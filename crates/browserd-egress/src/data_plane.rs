use std::fmt;
use std::time::Duration;

use async_trait::async_trait;
use browserd_core::ShardId;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

use crate::{
    DnsResolution, InspectedSocketAddr, MonotonicMillis, ProxyProtocolError, ProxyProtocolLimits,
    ProxyRequest, ProxyRequestKind, RouteEndpoint, RouteError, RouteRegistry,
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedRouteSource {
    endpoint: RouteEndpoint,
    source_shard: ShardId,
}

impl VerifiedRouteSource {
    /// Constructs identity already established by a dedicated route listener or a
    /// source-shard resolver at the network-namespace boundary. Proxy credentials
    /// are deliberately not an input to this type.
    #[must_use]
    pub const fn new(endpoint: RouteEndpoint, source_shard: ShardId) -> Self {
        Self {
            endpoint,
            source_shard,
        }
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
    registry: RouteRegistry,
    resolver: R,
    connector: C,
    limits: DataPlaneLimits,
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
        Ok(Self {
            registry,
            resolver,
            connector,
            limits,
        })
    }

    pub async fn serve_connection<S>(
        &self,
        source: VerifiedRouteSource,
        mut client: S,
        now: MonotonicMillis,
    ) -> Result<(), DataPlaneError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let started_at = tokio::time::Instant::now();
        let request = timeout(self.limits.header_timeout, async {
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
        })
        .await
        .map_err(|_| DataPlaneError::Timeout("header"))??;

        let pre_dns = self.registry.authorize_dns(
            source.endpoint,
            &source.source_shard,
            request.url(),
            now,
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
        let cancellation = permit.cancellation_token();
        let mut upstream = tokio::select! {
            biased;
            () = cancellation.cancelled() => return Err(DataPlaneError::RouteRevoked),
            result = timeout(self.limits.connect_timeout, self.connector.connect(target)) => {
                result.map_err(|_| DataPlaneError::Timeout("connect"))??
            }
        };

        match request.kind() {
            ProxyRequestKind::ConnectTunnel => {
                if request.content_length().is_some() {
                    return Err(DataPlaneError::Request(
                        ProxyProtocolError::AmbiguousBodyFraming,
                    ));
                }
                if !request.buffered_after_head().is_empty() {
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
                timeout(
                    self.limits.write_timeout,
                    upstream.write_all(request.upstream_head()),
                )
                .await
                .map_err(|_| DataPlaneError::Timeout("upstream write"))??;
                if !request.buffered_after_head().is_empty() {
                    timeout(
                        self.limits.write_timeout,
                        upstream.write_all(request.buffered_after_head()),
                    )
                    .await
                    .map_err(|_| DataPlaneError::Timeout("upstream write"))??;
                }
                let buffered = u64::try_from(request.buffered_after_head().len())
                    .map_err(|_| DataPlaneError::RequestBodyTooLarge)?;
                let mut remaining = content_length.saturating_sub(buffered);
                let mut chunk = vec![0_u8; self.limits.io_buffer_bytes];
                while remaining != 0 {
                    let limit = usize::try_from(remaining)
                        .unwrap_or(usize::MAX)
                        .min(chunk.len());
                    let read = timeout(self.limits.read_timeout, client.read(&mut chunk[..limit]))
                        .await
                        .map_err(|_| DataPlaneError::Timeout("request body read"))??;
                    if read == 0 {
                        return Err(DataPlaneError::UnexpectedEof);
                    }
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

        let (mut client_reader, mut client_writer) = tokio::io::split(client);
        let (mut upstream_reader, mut upstream_writer) = tokio::io::split(upstream);
        let mut client_chunk = vec![0_u8; self.limits.io_buffer_bytes];
        let mut upstream_chunk = vec![0_u8; self.limits.io_buffer_bytes];
        loop {
            tokio::select! {
                biased;
                () = cancellation.cancelled() => return Err(DataPlaneError::RouteRevoked),
                () = tokio::time::sleep(self.limits.idle_timeout) => {
                    return Err(DataPlaneError::Timeout("tunnel idle"));
                }
                result = client_reader.read(&mut client_chunk) => {
                    let read = result?;
                    if read == 0 {
                        upstream_writer.shutdown().await?;
                        return Ok(());
                    }
                    timeout(
                        self.limits.write_timeout,
                        upstream_writer.write_all(&client_chunk[..read]),
                    )
                    .await
                    .map_err(|_| DataPlaneError::Timeout("upstream write"))??;
                }
                result = upstream_reader.read(&mut upstream_chunk) => {
                    let read = result?;
                    if read == 0 {
                        client_writer.shutdown().await?;
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
                    timeout(
                        self.limits.write_timeout,
                        client_writer.write_all(&upstream_chunk[..read]),
                    )
                    .await
                    .map_err(|_| DataPlaneError::Timeout("client write"))??;
                }
            }
        }
    }
}
