use std::fmt;
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::watch;
use tokio::time::timeout;

#[cfg(test)]
use crate::RouteClaim;
use crate::ingress::AcceptedRouteIngress;
use crate::route::{RouteIngressGuard, RoutePermit};
use crate::{
    DnsResolution, InspectedSocketAddr, MonotonicMillis, ProxyProtocolError, ProxyProtocolLimits,
    ProxyRequest, ProxyRequestKind, RouteError, RouteRegistry,
};

pub trait EgressIo: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> EgressIo for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

pub type BoxedEgressIo = Box<dyn EgressIo>;

#[async_trait]
pub trait Resolver: Send + Sync + 'static {
    async fn resolve(&self, host: &str) -> Result<DnsResolution, DataPlaneError>;
}

#[async_trait]
pub trait Connector: Send + Sync + 'static {
    async fn connect(&self, target: InspectedSocketAddr) -> Result<BoxedEgressIo, DataPlaneError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct TokioResolver;

#[async_trait]
impl Resolver for TokioResolver {
    async fn resolve(&self, host: &str) -> Result<DnsResolution, DataPlaneError> {
        let addresses = tokio::net::lookup_host((host, 0))
            .await
            .map_err(|error| DataPlaneError::Resolve(error.to_string()))?
            .map(|address| address.ip())
            .collect::<Vec<_>>();
        Ok(DnsResolution::new(host, addresses))
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct TcpConnector;

#[async_trait]
impl Connector for TcpConnector {
    async fn connect(&self, target: InspectedSocketAddr) -> Result<BoxedEgressIo, DataPlaneError> {
        tokio::net::TcpStream::connect(target.as_socket_addr())
            .await
            .map(|stream| Box::new(stream) as BoxedEgressIo)
            .map_err(|error| DataPlaneError::Connect(error.to_string()))
    }
}

/// A route source can only be created by the ingress attribution boundary.
///
/// ```compile_fail
/// use browserd_core::ShardId;
/// use browserd_egress::{RouteEndpoint, VerifiedRouteSource};
///
/// let endpoint = RouteEndpoint::new(7).expect("nonzero endpoint");
/// let forged = VerifiedRouteSource::new(endpoint, ShardId::new());
/// # let _ = forged;
/// ```
#[derive(Debug, Eq, PartialEq)]
#[cfg(test)]
pub(crate) struct VerifiedRouteSource {
    claim: RouteClaim,
}

#[cfg(test)]
impl VerifiedRouteSource {
    #[must_use]
    pub(crate) const fn new(claim: RouteClaim) -> Self {
        Self { claim }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DataPlaneLimits {
    pub protocol: ProxyProtocolLimits,
    pub header_timeout: Duration,
    pub dns_timeout: Duration,
    pub connect_timeout: Duration,
    pub read_timeout: Duration,
    pub idle_timeout: Duration,
    pub write_timeout: Duration,
    pub max_request_body_bytes: u64,
    pub io_buffer_bytes: usize,
}

impl Default for DataPlaneLimits {
    fn default() -> Self {
        Self {
            protocol: ProxyProtocolLimits::default(),
            header_timeout: Duration::from_secs(5),
            dns_timeout: Duration::from_secs(5),
            connect_timeout: Duration::from_secs(10),
            read_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(30),
            write_timeout: Duration::from_secs(10),
            max_request_body_bytes: 16 * 1024 * 1024,
            io_buffer_bytes: 16 * 1024,
        }
    }
}

#[derive(Debug)]
pub enum DataPlaneError {
    InvalidLimits,
    Request(ProxyProtocolError),
    Route(RouteError),
    RouteRevoked,
    Resolve(String),
    Connect(String),
    Timeout(&'static str),
    RequestBodyTooLarge,
    UpstreamResponseHeaderTooLarge,
    UnexpectedEof,
    Io(std::io::Error),
}

impl fmt::Display for DataPlaneError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "egress data plane failed: {self:?}")
    }
}

impl std::error::Error for DataPlaneError {}

impl From<RouteError> for DataPlaneError {
    fn from(error: RouteError) -> Self {
        Self::Route(error)
    }
}

impl From<ProxyProtocolError> for DataPlaneError {
    fn from(error: ProxyProtocolError) -> Self {
        Self::Request(error)
    }
}

impl From<std::io::Error> for DataPlaneError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Clone)]
pub struct DataPlane<R, C> {
    #[cfg(test)]
    registry: RouteRegistry,
    resolver: R,
    connector: C,
    limits: DataPlaneLimits,
}

#[derive(Clone, Copy)]
enum TunnelDirection {
    Request,
    Response,
}

#[derive(Clone, Copy)]
struct TunnelRelay<'a> {
    permit: &'a Mutex<RoutePermit>,
    activity: &'a watch::Sender<tokio::time::Instant>,
    baseline: MonotonicMillis,
    started_at: tokio::time::Instant,
}

impl<R, C> DataPlane<R, C>
where
    R: Resolver,
    C: Connector,
{
    pub fn new(
        registry: RouteRegistry,
        resolver: R,
        connector: C,
        limits: DataPlaneLimits,
    ) -> Result<Self, DataPlaneError> {
        if limits.protocol.max_header_bytes == 0
            || limits.protocol.max_header_count == 0
            || limits.protocol.max_request_target_bytes == 0
            || limits.header_timeout.is_zero()
            || limits.dns_timeout.is_zero()
            || limits.connect_timeout.is_zero()
            || limits.read_timeout.is_zero()
            || limits.idle_timeout.is_zero()
            || limits.write_timeout.is_zero()
            || limits.max_request_body_bytes == 0
            || limits.io_buffer_bytes == 0
        {
            return Err(DataPlaneError::InvalidLimits);
        }
        #[cfg(not(test))]
        let _ = registry;
        Ok(Self {
            #[cfg(test)]
            registry,
            resolver,
            connector,
            limits,
        })
    }

    #[cfg(test)]
    pub(crate) async fn serve_verified_connection<S>(
        &self,
        source: VerifiedRouteSource,
        client: S,
        now: MonotonicMillis,
    ) -> Result<(), DataPlaneError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let ingress = self.registry.begin_ingress(&source.claim, now)?;
        self.serve_attributed_connection(ingress, client, now).await
    }

    pub async fn serve_accepted_connection(
        &self,
        accepted: AcceptedRouteIngress,
    ) -> Result<(), DataPlaneError> {
        let (client, ingress, accepted_at) = accepted.into_parts();
        self.serve_attributed_connection(ingress, client, accepted_at)
            .await
    }

    async fn serve_attributed_connection<S>(
        &self,
        ingress: RouteIngressGuard,
        client: S,
        now: MonotonicMillis,
    ) -> Result<(), DataPlaneError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let Some(cache) = ingress.runtime_safety() else {
            return self
                .serve_attributed_connection_inner(ingress, client, now)
                .await;
        };
        let mut generation = cache
            .generation()
            .map_err(|_| DataPlaneError::Route(RouteError::RuntimeSafetyUnavailable))?;
        let cancellation = generation.cancellation_token();
        let work = self.serve_attributed_connection_inner(ingress, client, now);
        tokio::pin!(work);
        loop {
            tokio::select! {
                biased;
                () = cancellation.cancelled() => {
                    return Err(DataPlaneError::Route(RouteError::RuntimeSafetyUnavailable));
                }
                () = tokio::time::sleep_until(generation.expires_at().into()) => {
                    let current = cache.generation().map_err(|_| {
                        DataPlaneError::Route(RouteError::RuntimeSafetyUnavailable)
                    })?;
                    if cancellation.is_cancelled()
                        || current.namespace_id() != generation.namespace_id()
                        || current.version() != generation.version()
                    {
                        return Err(DataPlaneError::Route(RouteError::RuntimeSafetyUnavailable));
                    }
                    // Exact polls extend freshness without replacing this flow's generation.
                    generation = current;
                }
                result = &mut work => return result,
            }
        }
    }

    async fn serve_attributed_connection_inner<S>(
        &self,
        ingress: RouteIngressGuard,
        mut client: S,
        now: MonotonicMillis,
    ) -> Result<(), DataPlaneError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let started_at = tokio::time::Instant::now();
        let cancellation = ingress.cancellation_token();
        let request = tokio::select! {
            biased;
            () = cancellation.cancelled() => return Err(DataPlaneError::RouteRevoked),
            result = timeout(self.limits.header_timeout, async {
                let mut buffered = Vec::new();
                loop {
                    match ProxyRequest::parse(&buffered, self.limits.protocol) {
                        Ok(request) => return Ok(request),
                        Err(ProxyProtocolError::IncompleteHeader) => {}
                        Err(error) => return Err(DataPlaneError::Request(error)),
                    }
                    let remaining = self
                        .limits
                        .protocol
                        .max_header_bytes
                        .saturating_add(1)
                        .saturating_sub(buffered.len());
                    if remaining == 0 {
                        return Err(DataPlaneError::Request(ProxyProtocolError::HeaderTooLarge));
                    }
                    let mut chunk = vec![0_u8; remaining.min(self.limits.io_buffer_bytes)];
                    let read = client.read(&mut chunk).await?;
                    if read == 0 {
                        return Err(DataPlaneError::UnexpectedEof);
                    }
                    buffered.extend_from_slice(&chunk[..read]);
                }
            }) => result.map_err(|_| DataPlaneError::Timeout("header"))??,
        };
        let websocket_upgrade_requested =
            request.kind() == ProxyRequestKind::ForwardHttp && request.url().scheme() == "ws" && {
                let head = String::from_utf8_lossy(request.upstream_head());
                let mut connection_upgrade = false;
                let mut websocket_upgrade = false;
                for line in head.split("\r\n").skip(1) {
                    let Some((name, value)) = line.split_once(':') else {
                        continue;
                    };
                    if name.eq_ignore_ascii_case("connection") {
                        connection_upgrade = value
                            .split(',')
                            .any(|token| token.trim().eq_ignore_ascii_case("upgrade"));
                    } else if name.eq_ignore_ascii_case("upgrade") {
                        websocket_upgrade = value.trim().eq_ignore_ascii_case("websocket");
                    }
                }
                connection_upgrade && websocket_upgrade
            };

        let pre_dns = ingress.authorize_dns(
            request.url(),
            MonotonicMillis::new(now.value().saturating_add(
                u64::try_from(started_at.elapsed().as_millis()).unwrap_or(u64::MAX),
            )),
        )?;
        let cancellation = pre_dns.cancellation_token();
        let resolution = tokio::select! {
            biased;
            () = cancellation.cancelled() => return Err(DataPlaneError::RouteRevoked),
            result = timeout(self.limits.dns_timeout, self.resolver.resolve(request.url().host())) => {
                result.map_err(|_| DataPlaneError::Timeout("dns"))??
            }
        };
        let mut permit = pre_dns.finish(
            resolution,
            MonotonicMillis::new(now.value().saturating_add(
                u64::try_from(started_at.elapsed().as_millis()).unwrap_or(u64::MAX),
            )),
        )?;
        let target = permit.plan().inspected_socket_addr();
        permit.authorize_connect()?;
        let cancellation = permit.cancellation_token();
        let mut upstream = tokio::select! {
            biased;
            () = cancellation.cancelled() => return Err(DataPlaneError::RouteRevoked),
            result = timeout(self.limits.connect_timeout, self.connector.connect(target)) => {
                result.map_err(|_| DataPlaneError::Timeout("connect"))??
            }
        };

        tokio::select! {
            biased;
            () = cancellation.cancelled() => return Err(DataPlaneError::RouteRevoked),
            result = async {
                match request.kind() {
                    ProxyRequestKind::ConnectTunnel => {
                        if request.content_length().is_some() {
                            return Err(DataPlaneError::Request(
                                ProxyProtocolError::AmbiguousBodyFraming,
                            ));
                        }
                        if !request.buffered_after_head().is_empty() {
                            permit.record_request_bytes(
                                u64::try_from(request.buffered_after_head().len())
                                    .map_err(|_| DataPlaneError::RequestBodyTooLarge)?,
                                MonotonicMillis::new(now.value().saturating_add(
                                    u64::try_from(started_at.elapsed().as_millis())
                                        .unwrap_or(u64::MAX),
                                )),
                            )?;
                            timeout(
                                self.limits.write_timeout,
                                upstream.write_all(request.buffered_after_head()),
                            )
                            .await
                            .map_err(|_| DataPlaneError::Timeout("upstream write"))??;
                        }
                        timeout(
                            self.limits.write_timeout,
                            client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n"),
                        )
                        .await
                        .map_err(|_| DataPlaneError::Timeout("client write"))??;
                    }
                    ProxyRequestKind::ForwardHttp => {
                        let content_length = request.content_length().unwrap_or(0);
                        if content_length > self.limits.max_request_body_bytes {
                            return Err(DataPlaneError::RequestBodyTooLarge);
                        }
                        permit.record_request_bytes(
                            u64::try_from(request.upstream_head().len()).map_err(|_| {
                                DataPlaneError::Request(ProxyProtocolError::HeaderTooLarge)
                            })?,
                            MonotonicMillis::new(now.value().saturating_add(
                                u64::try_from(started_at.elapsed().as_millis())
                                    .unwrap_or(u64::MAX),
                            )),
                        )?;
                        timeout(
                            self.limits.write_timeout,
                            upstream.write_all(request.upstream_head()),
                        )
                        .await
                        .map_err(|_| DataPlaneError::Timeout("upstream write"))??;
                        let buffered = u64::try_from(request.buffered_after_head().len())
                            .map_err(|_| DataPlaneError::RequestBodyTooLarge)?;
                        if !request.buffered_after_head().is_empty() {
                            permit.record_request_bytes(
                                buffered,
                                MonotonicMillis::new(now.value().saturating_add(
                                    u64::try_from(started_at.elapsed().as_millis())
                                        .unwrap_or(u64::MAX),
                                )),
                            )?;
                            timeout(
                                self.limits.write_timeout,
                                upstream.write_all(request.buffered_after_head()),
                            )
                            .await
                            .map_err(|_| DataPlaneError::Timeout("upstream write"))??;
                        }
                        let mut remaining = content_length.saturating_sub(buffered);
                        let mut chunk = vec![0_u8; self.limits.io_buffer_bytes];
                        while remaining != 0 {
                            let limit = usize::try_from(remaining)
                                .unwrap_or(usize::MAX)
                                .min(chunk.len());
                            let read =
                                timeout(self.limits.read_timeout, client.read(&mut chunk[..limit]))
                                    .await
                                    .map_err(|_| DataPlaneError::Timeout("request body read"))??;
                            if read == 0 {
                                return Err(DataPlaneError::UnexpectedEof);
                            }
                            permit.record_request_bytes(
                                u64::try_from(read)
                                    .map_err(|_| DataPlaneError::RequestBodyTooLarge)?,
                                MonotonicMillis::new(now.value().saturating_add(
                                    u64::try_from(started_at.elapsed().as_millis())
                                        .unwrap_or(u64::MAX),
                                )),
                            )?;
                            timeout(
                                self.limits.write_timeout,
                                upstream.write_all(&chunk[..read]),
                            )
                            .await
                            .map_err(|_| DataPlaneError::Timeout("upstream write"))??;
                            remaining = remaining.saturating_sub(read as u64);
                        }
                    }
                }
                Ok::<(), DataPlaneError>(())
            } => result?,
        }

        let mut tunnel_established = request.kind() == ProxyRequestKind::ConnectTunnel;
        if request.kind() == ProxyRequestKind::ForwardHttp && !websocket_upgrade_requested {
            tokio::select! {
                biased;
                () = cancellation.cancelled() => return Err(DataPlaneError::RouteRevoked),
                result = timeout(self.limits.write_timeout, upstream.shutdown()) => {
                    result.map_err(|_| DataPlaneError::Timeout("upstream shutdown"))??;
                }
            }
        } else if websocket_upgrade_requested {
            let mut response = Vec::new();
            let head_end = tokio::select! {
                biased;
                () = cancellation.cancelled() => return Err(DataPlaneError::RouteRevoked),
                result = timeout(self.limits.header_timeout, async {
                    loop {
                        if let Some(position) = response
                            .windows(4)
                            .position(|window| window == b"\r\n\r\n")
                        {
                            return Ok(position);
                        }
                        let remaining = self
                            .limits
                            .protocol
                            .max_header_bytes
                            .saturating_add(1)
                            .saturating_sub(response.len());
                        if remaining == 0 {
                            return Err(DataPlaneError::UpstreamResponseHeaderTooLarge);
                        }
                        let mut chunk = vec![0_u8; remaining.min(self.limits.io_buffer_bytes)];
                        let read = upstream.read(&mut chunk).await?;
                        if read == 0 {
                            return Err(DataPlaneError::UnexpectedEof);
                        }
                        response.extend_from_slice(&chunk[..read]);
                    }
                }) => {
                    result.map_err(|_| DataPlaneError::Timeout("upstream response header"))??
                }
            };
            let consumed_head = head_end
                .checked_add(4)
                .ok_or(DataPlaneError::UpstreamResponseHeaderTooLarge)?;
            if consumed_head > self.limits.protocol.max_header_bytes {
                return Err(DataPlaneError::UpstreamResponseHeaderTooLarge);
            }
            let response_head = &response[..head_end];
            let mut valid_response_bytes = response_head.iter().all(|byte| {
                byte.is_ascii()
                    && *byte != 0
                    && (*byte >= 0x20 || matches!(*byte, b'\r' | b'\n' | b'\t'))
                    && *byte != 0x7f
            });
            let response_head = String::from_utf8_lossy(response_head);
            let mut lines = response_head.split("\r\n");
            let status = lines.next().unwrap_or_default();
            let status_parts = status.split(' ').collect::<Vec<_>>();
            valid_response_bytes &= status_parts.len() >= 2
                && status_parts[0] == "HTTP/1.1"
                && status_parts[1] == "101";
            let mut connection_upgrade = false;
            let mut websocket_upgrade = false;
            for line in lines {
                let Some((name, value)) = line.split_once(':') else {
                    valid_response_bytes = false;
                    continue;
                };
                connection_upgrade |= name.eq_ignore_ascii_case("connection")
                    && value
                        .split(',')
                        .any(|token| token.trim().eq_ignore_ascii_case("upgrade"));
                websocket_upgrade |= name.eq_ignore_ascii_case("upgrade")
                    && value.trim().eq_ignore_ascii_case("websocket");
            }
            tunnel_established = valid_response_bytes && connection_upgrade && websocket_upgrade;
            permit.record_egress_bytes(
                response.len() as u64,
                MonotonicMillis::new(now.value().saturating_add(
                    u64::try_from(started_at.elapsed().as_millis()).unwrap_or(u64::MAX),
                )),
            )?;
            tokio::select! {
                biased;
                () = cancellation.cancelled() => return Err(DataPlaneError::RouteRevoked),
                result = timeout(self.limits.write_timeout, client.write_all(&response)) => {
                    result.map_err(|_| DataPlaneError::Timeout("client write"))??;
                }
            }
            if !tunnel_established {
                tokio::select! {
                    biased;
                    () = cancellation.cancelled() => return Err(DataPlaneError::RouteRevoked),
                    result = timeout(self.limits.write_timeout, upstream.shutdown()) => {
                        result.map_err(|_| DataPlaneError::Timeout("upstream shutdown"))??;
                    }
                }
            }
        }

        let (client_reader, mut client_writer) = tokio::io::split(client);
        let (mut upstream_reader, upstream_writer) = tokio::io::split(upstream);
        let mut upstream_chunk = vec![0_u8; self.limits.io_buffer_bytes];
        if !tunnel_established {
            loop {
                tokio::select! {
                    biased;
                    () = cancellation.cancelled() => return Err(DataPlaneError::RouteRevoked),
                    () = tokio::time::sleep(self.limits.idle_timeout) => {
                        return Err(DataPlaneError::Timeout("response idle"));
                    }
                    result = upstream_reader.read(&mut upstream_chunk) => {
                        let read = result?;
                        if read == 0 {
                            tokio::select! {
                                biased;
                                () = cancellation.cancelled() => {
                                    return Err(DataPlaneError::RouteRevoked);
                                }
                                result = timeout(
                                    self.limits.write_timeout,
                                    client_writer.shutdown(),
                                ) => {
                                    result
                                        .map_err(|_| DataPlaneError::Timeout("client shutdown"))??;
                                }
                            }
                            return Ok(());
                        }
                        permit.record_egress_bytes(
                            read as u64,
                            MonotonicMillis::new(
                                now.value().saturating_add(
                                    u64::try_from(started_at.elapsed().as_millis())
                                        .unwrap_or(u64::MAX),
                                ),
                            ),
                        )?;
                        tokio::select! {
                            biased;
                            () = cancellation.cancelled() => {
                                return Err(DataPlaneError::RouteRevoked);
                            }
                            result = timeout(
                                self.limits.write_timeout,
                                client_writer.write_all(&upstream_chunk[..read]),
                            ) => {
                                result.map_err(|_| DataPlaneError::Timeout("client write"))??;
                            }
                        }
                    }
                }
            }
        }

        let permit = Mutex::new(permit);
        let (activity, mut observed_activity) = watch::channel(tokio::time::Instant::now());
        let relay = TunnelRelay {
            permit: &permit,
            activity: &activity,
            baseline: now,
            started_at,
        };
        let relay_both = async {
            tokio::try_join!(
                self.relay_tunnel_direction(
                    client_reader,
                    upstream_writer,
                    relay,
                    TunnelDirection::Request
                ),
                self.relay_tunnel_direction(
                    upstream_reader,
                    client_writer,
                    relay,
                    TunnelDirection::Response
                ),
            )?;
            Ok::<(), DataPlaneError>(())
        };
        let idle = async {
            loop {
                let deadline = *observed_activity.borrow_and_update() + self.limits.idle_timeout;
                tokio::select! {
                    biased;
                    changed = observed_activity.changed() => {
                        if changed.is_err() {
                            return Err(DataPlaneError::Timeout("tunnel idle"));
                        }
                    }
                    () = tokio::time::sleep_until(deadline) => {
                        // A progress notification and timer can become ready together.
                        if tokio::time::Instant::now() >= *observed_activity.borrow() + self.limits.idle_timeout {
                            return Err(DataPlaneError::Timeout("tunnel idle"));
                        }
                    }
                }
            }
        };
        tokio::select! {
            biased;
            () = cancellation.cancelled() => Err(DataPlaneError::RouteRevoked),
            result = relay_both => result,
            result = idle => result,
        }
    }

    async fn relay_tunnel_direction<A, B>(
        &self,
        mut reader: A,
        mut writer: B,
        relay: TunnelRelay<'_>,
        direction: TunnelDirection,
    ) -> Result<(), DataPlaneError>
    where
        A: AsyncRead + Unpin,
        B: AsyncWrite + Unpin,
    {
        let (write_stage, shutdown_stage) = match direction {
            TunnelDirection::Request => ("upstream write", "upstream shutdown"),
            TunnelDirection::Response => ("client write", "client shutdown"),
        };
        let mut buffer = vec![0_u8; self.limits.io_buffer_bytes];
        let mut start = 0;
        let mut end = 0;
        let mut eof = false;
        let mut write_deadline = tokio::time::Instant::now() + self.limits.write_timeout;
        loop {
            if start != 0 {
                buffer.copy_within(start..end, 0);
                end -= start;
                start = 0;
            }
            if eof && end == 0 {
                timeout(self.limits.write_timeout, writer.shutdown())
                    .await
                    .map_err(|_| DataPlaneError::Timeout(shutdown_stage))??;
                return Ok(());
            }
            let capacity = buffer.len();
            let (pending, available) = buffer.split_at_mut(end);
            tokio::select! {
                () = tokio::time::sleep_until(write_deadline), if end != 0 => {
                    return Err(DataPlaneError::Timeout(write_stage));
                }
                result = writer.write(pending), if end != 0 => {
                    let written = result?;
                    if written == 0 {
                        return Err(std::io::Error::from(std::io::ErrorKind::WriteZero).into());
                    }
                    start = written;
                    // Partial writes do not extend the oldest pending batch's bound.
                    if written == end {
                        write_deadline = tokio::time::Instant::now() + self.limits.write_timeout;
                    }
                    let _ = relay.activity.send_replace(tokio::time::Instant::now());
                }
                result = reader.read(available), if !eof && end < capacity => {
                    let read = result?;
                    if read == 0 {
                        eof = true;
                        continue;
                    }
                    let bytes = u64::try_from(read).map_err(|_| DataPlaneError::RequestBodyTooLarge)?;
                    let now = MonotonicMillis::new(relay.baseline.value().saturating_add(
                        u64::try_from(relay.started_at.elapsed().as_millis()).unwrap_or(u64::MAX),
                    ));
                    {
                        let mut permit = relay.permit.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                        match direction {
                            TunnelDirection::Request => permit.record_request_bytes(bytes, now)?,
                            TunnelDirection::Response => permit.record_egress_bytes(bytes, now)?,
                        }
                    }
                    if end == 0 {
                        write_deadline = tokio::time::Instant::now() + self.limits.write_timeout;
                    }
                    end += read;
                    let _ = relay.activity.send_replace(tokio::time::Instant::now());
                }
            }
        }
    }
}
