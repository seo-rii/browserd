use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, Instant};

use anyhow::{Context, bail};
use axum::extract::{DefaultBodyLimit, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::routing::{get, post};
use axum::{Json, Router};
use browserd_core::{SessionId, ShardId, TenantId, WorkerId};
use browserd_egress::{
    DataPlane, DataPlaneLimits, EgressPolicy, MonotonicMillis, QuotaLimits, RouteBinding,
    RouteEndpoint, RouteRegistry, TcpConnector, TokioResolver, VerifiedRouteSource,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;
use tokio::time::Sleep;
use tokio_util::sync::CancellationToken;
use tower_http::timeout::TimeoutLayer;

#[derive(Clone, Debug)]
struct DataListenerConfig {
    endpoint: RouteEndpoint,
    address: SocketAddr,
    source_shard: ShardId,
}

#[derive(Debug)]
struct DaemonConfig {
    control_address: SocketAddr,
    data_listeners: Vec<DataListenerConfig>,
    max_data_connections_per_listener: usize,
}

struct LimitedControlListener {
    inner: TcpListener,
    permits: Arc<Semaphore>,
    read_timeout: Duration,
}

impl LimitedControlListener {
    fn new(
        inner: TcpListener,
        max_connections: usize,
        read_timeout: Duration,
    ) -> anyhow::Result<Self> {
        if max_connections == 0 || max_connections > 65_536 {
            bail!("control connection limit must be between 1 and 65536");
        }
        if read_timeout.is_zero() || read_timeout > Duration::from_secs(300) {
            bail!("control connection read timeout must be between 1ms and 300s");
        }
        Ok(Self {
            inner,
            permits: Arc::new(Semaphore::new(max_connections)),
            read_timeout,
        })
    }
}

struct LimitedControlStream {
    inner: TcpStream,
    _permit: OwnedSemaphorePermit,
    read_deadline: Pin<Box<Sleep>>,
}

impl AsyncRead for LimitedControlStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        if this.read_deadline.as_mut().poll(context).is_ready() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "control connection read deadline exceeded",
            )));
        }
        Pin::new(&mut this.inner).poll_read(context, buffer)
    }
}

impl AsyncWrite for LimitedControlStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
        buffers: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(context, buffers)
    }
}

impl axum::serve::Listener for LimitedControlListener {
    type Io = LimitedControlStream;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        let permit = match Arc::clone(&self.permits).acquire_owned().await {
            Ok(permit) => permit,
            Err(_) => std::future::pending::<OwnedSemaphorePermit>().await,
        };
        let (inner, address) = axum::serve::Listener::accept(&mut self.inner).await;
        (
            LimitedControlStream {
                inner,
                _permit: permit,
                read_deadline: Box::pin(tokio::time::sleep(self.read_timeout)),
            },
            address,
        )
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}

#[derive(Clone)]
struct ControlToken {
    digest: [u8; 32],
}

impl ControlToken {
    fn new(secret: &str) -> anyhow::Result<Self> {
        if secret.len() < 32
            || secret.len() > 4 * 1024
            || !secret.as_bytes().iter().all(u8::is_ascii_graphic)
        {
            bail!("control token must contain 32 to 4096 visible ASCII bytes");
        }
        Ok(Self {
            digest: Sha256::digest(secret.as_bytes()).into(),
        })
    }

    fn authorizes(&self, authorization: &str) -> bool {
        let Some(candidate) = authorization.strip_prefix("Bearer ") else {
            return false;
        };
        let candidate_digest: [u8; 32] = Sha256::digest(candidate.as_bytes()).into();
        bool::from(self.digest.ct_eq(&candidate_digest))
    }

    fn same_secret(&self, other: &Self) -> bool {
        bool::from(self.digest.ct_eq(&other.digest))
    }
}

#[derive(Clone)]
struct ControlCredentials {
    supervisor: ControlToken,
    worker: WorkerControlCredential,
}

#[derive(Clone)]
struct WorkerControlCredential {
    token: ControlToken,
    worker_id: WorkerId,
    worker_epoch: u64,
}

impl WorkerControlCredential {
    fn derive_bearer(
        worker_secret: &str,
        process_nonce: &str,
        worker_id: &WorkerId,
        worker_epoch: u64,
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"browserd-egress-worker-capability-v1");
        for field in [
            worker_secret.as_bytes(),
            process_nonce.as_bytes(),
            worker_id.as_str().as_bytes(),
        ] {
            hasher.update(u64::try_from(field.len()).unwrap_or(u64::MAX).to_be_bytes());
            hasher.update(field);
        }
        hasher.update(worker_epoch.to_be_bytes());
        let digest = hasher.finalize();
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut bearer = String::with_capacity(64);
        for byte in digest {
            bearer.push(char::from(HEX[usize::from(byte >> 4)]));
            bearer.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        bearer
    }

    fn owns(&self, worker_id: &WorkerId, worker_epoch: u64) -> bool {
        &self.worker_id == worker_id && self.worker_epoch == worker_epoch
    }
}

impl ControlCredentials {
    fn new(
        supervisor_secret: &str,
        worker_secret: &str,
        process_nonce: &str,
        worker_id: WorkerId,
        worker_epoch: u64,
    ) -> anyhow::Result<Self> {
        if worker_epoch == 0 {
            bail!("worker epoch must be positive");
        }
        let supervisor = ControlToken::new(supervisor_secret)?;
        let worker_secret_token = ControlToken::new(worker_secret)?;
        let process_nonce_token = ControlToken::new(process_nonce)?;
        if supervisor.same_secret(&worker_secret_token)
            || supervisor.same_secret(&process_nonce_token)
            || worker_secret_token.same_secret(&process_nonce_token)
        {
            bail!(
                "supervisor token, per-process worker token, and capability nonce must be distinct"
            );
        }
        let bearer = WorkerControlCredential::derive_bearer(
            worker_secret,
            process_nonce,
            &worker_id,
            worker_epoch,
        );
        let worker_token = ControlToken::new(&bearer)?;
        if supervisor.same_secret(&worker_token) {
            bail!("supervisor token must differ from the derived worker capability");
        }
        let worker = WorkerControlCredential {
            token: worker_token,
            worker_id,
            worker_epoch,
        };
        Ok(Self { supervisor, worker })
    }
}

impl DaemonConfig {
    fn from_parts(
        control: &str,
        listeners: &str,
        max_data_connections_per_listener: usize,
    ) -> anyhow::Result<Self> {
        if max_data_connections_per_listener == 0 || max_data_connections_per_listener > 65_536 {
            bail!("data connection limit must be between 1 and 65536");
        }
        let control_address = control
            .parse::<SocketAddr>()
            .context("control listener must be an IP socket address")?;
        if !control_address.ip().is_loopback() {
            bail!("control listener must be loopback; public unauthenticated admin is forbidden");
        }
        let mut data_listeners = Vec::new();
        for encoded in listeners.split(',').filter(|value| !value.is_empty()) {
            let mut parts = encoded.split('@');
            let endpoint = parts
                .next()
                .context("data listener endpoint is missing")?
                .parse::<u64>()
                .context("data listener endpoint must be an integer")?;
            let address = parts
                .next()
                .context("data listener address is missing")?
                .parse::<SocketAddr>()
                .context("data listener address must be an IP socket address")?;
            if !address.ip().is_loopback() {
                bail!(
                    "data listener must be an explicit loopback address when peer source authentication is unavailable"
                );
            }
            let source_shard = parts
                .next()
                .context("data listener source shard is missing")?
                .parse::<ShardId>()
                .context("data listener source shard is invalid")?;
            if parts.next().is_some() {
                bail!("data listener must be endpoint@address@source_shard");
            }
            data_listeners.push(DataListenerConfig {
                endpoint: RouteEndpoint::new(endpoint)
                    .map_err(|error| anyhow::anyhow!("invalid route endpoint: {error:?}"))?,
                address,
                source_shard,
            });
        }
        if data_listeners.is_empty() {
            bail!("at least one explicit data listener is required");
        }
        let mut seen = HashMap::new();
        for listener in &data_listeners {
            if seen.insert(listener.endpoint, ()).is_some() {
                bail!("route endpoint has more than one data listener");
            }
        }
        Ok(Self {
            control_address,
            data_listeners,
            max_data_connections_per_listener,
        })
    }
}

#[derive(Clone)]
struct ControlState {
    registry: RouteRegistry,
    listeners: Arc<HashMap<RouteEndpoint, ShardId>>,
    started: Instant,
    ready: Arc<AtomicBool>,
    credentials: ControlCredentials,
}

fn require_control(headers: &HeaderMap, token: &ControlToken) -> Result<(), StatusCode> {
    let authorized = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| token.authorizes(value));
    if authorized {
        Ok(())
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

fn require_worker_control(
    headers: &HeaderMap,
    credential: &WorkerControlCredential,
    worker_id: &WorkerId,
    worker_epoch: u64,
) -> Result<(), StatusCode> {
    require_control(headers, &credential.token)?;
    if credential.owns(worker_id, worker_epoch) {
        Ok(())
    } else {
        Err(StatusCode::CONFLICT)
    }
}

fn require_supervisor_control(
    headers: &HeaderMap,
    credentials: &ControlCredentials,
    worker_id: &WorkerId,
    worker_epoch: u64,
) -> Result<(), StatusCode> {
    require_control(headers, &credentials.supervisor)?;
    if credentials.worker.owns(worker_id, worker_epoch) {
        Ok(())
    } else {
        Err(StatusCode::CONFLICT)
    }
}

fn control_error(status: StatusCode) -> (StatusCode, String) {
    let message = if status == StatusCode::UNAUTHORIZED {
        "control authorization failed"
    } else {
        "worker ownership mismatch"
    };
    (status, message.to_owned())
}

fn route_conflict(error: browserd_egress::RouteError) -> (StatusCode, String) {
    if error == browserd_egress::RouteError::ShardNotDrained {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "shard connections are still draining; retry".to_owned(),
        )
    } else {
        (StatusCode::CONFLICT, "route state conflict".to_owned())
    }
}

fn route_not_found(_: browserd_egress::RouteError) -> (StatusCode, String) {
    (StatusCode::NOT_FOUND, "route is not active".to_owned())
}

impl ControlState {
    fn now(&self) -> MonotonicMillis {
        MonotonicMillis::new(u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX))
    }
}

async fn wait_for_shutdown_trigger<F>(
    tasks: &mut JoinSet<anyhow::Result<()>>,
    shutdown_signal: F,
) -> anyhow::Result<()>
where
    F: Future<Output = anyhow::Result<()>>,
{
    tokio::pin!(shutdown_signal);
    tokio::select! {
        signal = &mut shutdown_signal => signal,
        joined = tasks.join_next() => {
            match joined {
                Some(result) => {
                    result.context("egress daemon task panicked")??;
                    bail!("egress daemon task exited unexpectedly")
                }
                None => bail!("egress daemon has no supervised tasks"),
            }
        }
    }
}

#[derive(Deserialize)]
struct BindRequest {
    endpoint: u64,
    tenant_id: TenantId,
    session_id: SessionId,
    source_shard: ShardId,
    worker_id: WorkerId,
    worker_epoch: u64,
    lease_millis: u64,
}

#[derive(Deserialize)]
struct LeaseRequest {
    endpoint: u64,
    source_shard: ShardId,
    worker_id: WorkerId,
    worker_epoch: u64,
    lease_millis: u64,
}

#[derive(Deserialize)]
struct RevokeRequest {
    endpoint: u64,
    source_shard: ShardId,
    worker_id: WorkerId,
    worker_epoch: u64,
}

#[derive(Deserialize)]
struct ShardControlRequest {
    source_shard: ShardId,
    worker_id: WorkerId,
    worker_epoch: u64,
}

#[derive(Deserialize)]
struct RouteStatusRequest {
    endpoint: u64,
    source_shard: ShardId,
    worker_id: WorkerId,
    worker_epoch: u64,
}

#[derive(Serialize)]
struct RouteStatusResponse {
    active: bool,
}

async fn health() -> StatusCode {
    StatusCode::OK
}

async fn readiness(State(state): State<ControlState>) -> StatusCode {
    if state.ready.load(Ordering::Acquire) {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

async fn bind_route(
    State(state): State<ControlState>,
    headers: HeaderMap,
    Json(request): Json<BindRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    require_worker_control(
        &headers,
        &state.credentials.worker,
        &request.worker_id,
        request.worker_epoch,
    )
    .map_err(control_error)?;
    let endpoint = RouteEndpoint::new(request.endpoint)
        .map_err(|error| (StatusCode::BAD_REQUEST, format!("{error:?}")))?;
    if state.listeners.get(&endpoint) != Some(&request.source_shard) {
        return Err((
            StatusCode::FORBIDDEN,
            "source shard does not match the dedicated listener".into(),
        ));
    }
    let now = state.now();
    let expires_at = MonotonicMillis::new(now.value().saturating_add(request.lease_millis));
    state
        .registry
        .bind(
            endpoint,
            RouteBinding::new(
                request.tenant_id,
                request.session_id,
                request.source_shard,
                request.worker_epoch,
                EgressPolicy::public_web_default(),
                QuotaLimits {
                    max_concurrent_connections: 64,
                    max_connection_starts_per_window: 256,
                    max_dns_queries_per_window: 256,
                    max_egress_bytes_per_window: 64 * 1024 * 1024,
                    max_total_egress_bytes: 512 * 1024 * 1024,
                    max_response_bytes: Some(128 * 1024 * 1024),
                    accounting_window: Duration::from_secs(60),
                    idle_connection_timeout: Duration::from_secs(30),
                },
                expires_at,
            ),
            now,
        )
        .map_err(route_conflict)?;
    Ok(StatusCode::CREATED)
}

async fn renew_route(
    State(state): State<ControlState>,
    headers: HeaderMap,
    Json(request): Json<LeaseRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    require_worker_control(
        &headers,
        &state.credentials.worker,
        &request.worker_id,
        request.worker_epoch,
    )
    .map_err(control_error)?;
    let endpoint = RouteEndpoint::new(request.endpoint)
        .map_err(|error| (StatusCode::BAD_REQUEST, format!("{error:?}")))?;
    let now = state.now();
    state
        .registry
        .renew(
            endpoint,
            &request.source_shard,
            request.worker_epoch,
            now,
            MonotonicMillis::new(now.value().saturating_add(request.lease_millis)),
        )
        .map_err(route_conflict)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn revoke_route(
    State(state): State<ControlState>,
    headers: HeaderMap,
    Json(request): Json<RevokeRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    require_worker_control(
        &headers,
        &state.credentials.worker,
        &request.worker_id,
        request.worker_epoch,
    )
    .map_err(control_error)?;
    let endpoint = RouteEndpoint::new(request.endpoint)
        .map_err(|error| (StatusCode::BAD_REQUEST, format!("{error:?}")))?;
    state
        .registry
        .revoke(endpoint, &request.source_shard, request.worker_epoch)
        .map_err(route_conflict)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn revoke_shard(
    State(state): State<ControlState>,
    headers: HeaderMap,
    Json(request): Json<ShardControlRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    require_supervisor_control(
        &headers,
        &state.credentials,
        &request.worker_id,
        request.worker_epoch,
    )
    .map_err(control_error)?;
    state
        .registry
        .revoke_shard(&request.source_shard, request.worker_epoch)
        .map_err(route_conflict)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn prepare_shard(
    State(state): State<ControlState>,
    headers: HeaderMap,
    Json(request): Json<ShardControlRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    require_supervisor_control(
        &headers,
        &state.credentials,
        &request.worker_id,
        request.worker_epoch,
    )
    .map_err(control_error)?;
    state
        .registry
        .prepare_shard(&request.source_shard, request.worker_epoch)
        .map_err(route_conflict)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn release_shard(
    State(state): State<ControlState>,
    headers: HeaderMap,
    Json(request): Json<ShardControlRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    require_supervisor_control(
        &headers,
        &state.credentials,
        &request.worker_id,
        request.worker_epoch,
    )
    .map_err(control_error)?;
    state
        .registry
        .release_shard(&request.source_shard, request.worker_epoch)
        .map_err(route_conflict)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn route_status(
    State(state): State<ControlState>,
    headers: HeaderMap,
    Query(request): Query<RouteStatusRequest>,
) -> Result<Json<RouteStatusResponse>, (StatusCode, String)> {
    require_worker_control(
        &headers,
        &state.credentials.worker,
        &request.worker_id,
        request.worker_epoch,
    )
    .map_err(control_error)?;
    let endpoint = RouteEndpoint::new(request.endpoint)
        .map_err(|error| (StatusCode::BAD_REQUEST, format!("{error:?}")))?;
    let identity = state
        .registry
        .binding(endpoint, &request.source_shard, state.now())
        .map_err(route_not_found)?;
    if identity.worker_epoch() != request.worker_epoch {
        return Err((
            StatusCode::CONFLICT,
            "worker epoch does not own the route".to_owned(),
        ));
    }
    Ok(Json(RouteStatusResponse { active: true }))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let control =
        std::env::var("BROWSER_EGRESS_CONTROL_BIND").unwrap_or_else(|_| "127.0.0.1:9901".into());
    let data = std::env::var("BROWSER_EGRESS_DATA_LISTENERS")
        .context("BROWSER_EGRESS_DATA_LISTENERS must explicitly configure listeners")?;
    let max_data_connections = std::env::var("BROWSER_EGRESS_MAX_DATA_CONNECTIONS")
        .unwrap_or_else(|_| "1024".to_owned())
        .parse::<usize>()
        .context("BROWSER_EGRESS_MAX_DATA_CONNECTIONS must be an integer")?;
    let max_control_connections = std::env::var("BROWSER_EGRESS_MAX_CONTROL_CONNECTIONS")
        .unwrap_or_else(|_| "128".to_owned())
        .parse::<usize>()
        .context("BROWSER_EGRESS_MAX_CONTROL_CONNECTIONS must be an integer")?;
    let control_read_timeout = Duration::from_millis(
        std::env::var("BROWSER_EGRESS_CONTROL_READ_TIMEOUT_MILLIS")
            .unwrap_or_else(|_| "5000".to_owned())
            .parse::<u64>()
            .context("BROWSER_EGRESS_CONTROL_READ_TIMEOUT_MILLIS must be an integer")?,
    );
    let supervisor_token = std::env::var("BROWSER_EGRESS_SUPERVISOR_TOKEN")
        .context("BROWSER_EGRESS_SUPERVISOR_TOKEN must be explicitly configured")?;
    let worker_token = std::env::var("BROWSER_EGRESS_WORKER_TOKEN")
        .context("BROWSER_EGRESS_WORKER_TOKEN must be a unique per-process secret")?;
    let worker_capability_nonce = std::env::var("BROWSER_EGRESS_WORKER_CAPABILITY_NONCE")
        .context("BROWSER_EGRESS_WORKER_CAPABILITY_NONCE must be freshly generated per process")?;
    let worker_id = std::env::var("BROWSER_EGRESS_WORKER_ID")
        .context("BROWSER_EGRESS_WORKER_ID must be explicitly configured")?
        .parse::<WorkerId>()
        .context("BROWSER_EGRESS_WORKER_ID is invalid")?;
    let worker_epoch = std::env::var("BROWSER_EGRESS_WORKER_EPOCH")
        .context("BROWSER_EGRESS_WORKER_EPOCH must be explicitly configured")?
        .parse::<u64>()
        .context("BROWSER_EGRESS_WORKER_EPOCH must be a positive integer")?;
    let credentials = ControlCredentials::new(
        &supervisor_token,
        &worker_token,
        &worker_capability_nonce,
        worker_id,
        worker_epoch,
    )?;
    drop(supervisor_token);
    drop(worker_token);
    drop(worker_capability_nonce);
    let config = DaemonConfig::from_parts(&control, &data, max_data_connections)?;
    let registry = RouteRegistry::new(Duration::from_secs(30));
    let ready = Arc::new(AtomicBool::new(false));
    let shutdown = CancellationToken::new();
    let started = Instant::now();
    let listeners_by_endpoint = Arc::new(
        config
            .data_listeners
            .iter()
            .map(|listener| (listener.endpoint, listener.source_shard.clone()))
            .collect::<HashMap<_, _>>(),
    );

    let control_listener = TcpListener::bind(config.control_address)
        .await
        .context("failed to bind loopback control listener")?;
    let control_listener = LimitedControlListener::new(
        control_listener,
        max_control_connections,
        control_read_timeout,
    )?;
    let mut bound_data = Vec::new();
    let max_data_connections_per_listener = config.max_data_connections_per_listener;
    for listener in config.data_listeners {
        let socket = TcpListener::bind(listener.address)
            .await
            .with_context(|| format!("failed to bind data listener {}", listener.address))?;
        bound_data.push((listener, socket));
    }
    ready.store(true, Ordering::Release);

    let state = ControlState {
        registry: registry.clone(),
        listeners: listeners_by_endpoint,
        started,
        ready: ready.clone(),
        credentials,
    };
    let app = Router::new()
        .route("/healthz", get(health))
        .route("/readyz", get(readiness))
        .route("/v1/routes/bind", post(bind_route))
        .route("/v1/routes/renew", post(renew_route))
        .route("/v1/routes/revoke", post(revoke_route))
        .route("/v1/routes/prepare-shard", post(prepare_shard))
        .route("/v1/routes/revoke-shard", post(revoke_shard))
        .route("/v1/routes/release-shard", post(release_shard))
        .route("/v1/routes/status", get(route_status))
        .layer(DefaultBodyLimit::max(16 * 1024))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(5),
        ))
        .with_state(state.clone());
    let control_shutdown = shutdown.clone();
    let mut tasks = JoinSet::new();
    tasks.spawn(async move {
        axum::serve(control_listener, app)
            .with_graceful_shutdown(control_shutdown.cancelled_owned())
            .await
            .map_err(anyhow::Error::from)
    });

    for (listener, socket) in bound_data {
        let data_shutdown = shutdown.clone();
        let connection_permits = Arc::new(Semaphore::new(max_data_connections_per_listener));
        let data_plane = DataPlane::new(
            registry.clone(),
            TokioResolver,
            TcpConnector,
            DataPlaneLimits::default(),
        )?;
        let clock = state.clone();
        tasks.spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    () = data_shutdown.cancelled() => break,
                    accepted = socket.accept() => {
                        let (stream, _) = accepted.context("data listener accept failed")?;
                        let Ok(connection_permit) = Arc::clone(&connection_permits)
                            .try_acquire_owned()
                        else {
                            continue;
                        };
                        let plane = data_plane.clone();
                        let source = VerifiedRouteSource::new(
                            listener.endpoint,
                            listener.source_shard.clone(),
                        );
                        let now = clock.now();
                        connections.spawn(async move {
                            let _connection_permit = connection_permit;
                            let _ = plane.serve_connection(source, stream, now).await;
                        });
                    }
                    joined = connections.join_next(), if !connections.is_empty() => {
                        joined.context("data connection task disappeared")?
                            .context("data connection task panicked")?;
                    }
                }
            }
            while let Some(joined) = connections.join_next().await {
                joined.context("data connection task panicked")?;
            }
            Ok(())
        });
    }

    let expiry_shutdown = shutdown.clone();
    let expiry_registry = registry.clone();
    tasks.spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_millis(25));
        loop {
            tokio::select! {
                () = expiry_shutdown.cancelled() => return Ok(()),
                _ = interval.tick() => {
                    expiry_registry.expire_routes(MonotonicMillis::new(
                        u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                    ));
                }
            }
        }
    });

    let termination = wait_for_shutdown_trigger(&mut tasks, async {
        tokio::signal::ctrl_c()
            .await
            .context("failed to install shutdown signal")
    })
    .await;
    ready.store(false, Ordering::Release);
    registry.expire_routes(MonotonicMillis::new(u64::MAX));
    shutdown.cancel();
    let mut drain_result = Ok(());
    while let Some(result) = tasks.join_next().await {
        let result = result
            .context("egress daemon task panicked")
            .and_then(|result| result);
        if drain_result.is_ok() {
            drain_result = result;
        }
    }
    termination.and(drain_result)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    use std::time::{Duration, Instant};

    use super::{
        BindRequest, ControlCredentials, ControlState, ControlToken, DaemonConfig, LeaseRequest,
        LimitedControlListener, RevokeRequest, RouteStatusRequest, ShardControlRequest,
        WorkerControlCredential, bind_route, prepare_shard, release_shard, renew_route,
        require_control, require_supervisor_control, require_worker_control, revoke_route,
        revoke_shard, route_conflict, route_status, wait_for_shutdown_trigger,
    };
    use axum::Json;
    use axum::extract::{Query, State};
    use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
    use browserd_core::{SessionId, ShardId, TenantId, WorkerId};
    use browserd_egress::{
        EgressPolicy, MonotonicMillis, QuotaLimits, RouteBinding, RouteEndpoint, RouteError,
        RouteRegistry,
    };
    use tokio::io::AsyncReadExt;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::task::JoinSet;

    fn worker(value: &str) -> WorkerId {
        WorkerId::new(value).expect("worker ID is valid")
    }

    fn worker_control_headers(
        secret: &str,
        nonce: &str,
        worker_id: &WorkerId,
        worker_epoch: u64,
    ) -> HeaderMap {
        let bearer = WorkerControlCredential::derive_bearer(secret, nonce, worker_id, worker_epoch);
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {bearer}"))
                .expect("derived bearer is an HTTP header value"),
        );
        headers
    }

    #[test]
    fn control_plane_is_loopback_only_and_data_listeners_are_explicit() {
        let shard = ShardId::new();
        assert!(DaemonConfig::from_parts("0.0.0.0:9901", "", 128).is_err());
        assert!(DaemonConfig::from_parts("127.0.0.1:9901", "", 128).is_err());
        assert!(DaemonConfig::from_parts("127.0.0.1:9901", "ignored", 0).is_err());
        assert!(
            DaemonConfig::from_parts("127.0.0.1:9901", &format!("71@0.0.0.0:3128@{shard}"), 128,)
                .is_err()
        );
        assert!(
            DaemonConfig::from_parts(
                "127.0.0.1:9901",
                &format!("71@192.0.2.10:3128@{shard}"),
                128,
            )
            .is_err()
        );
        assert!(
            DaemonConfig::from_parts("127.0.0.1:9901", &format!("71@127.0.0.2:3128@{shard}"), 128,)
                .is_ok()
        );
    }

    #[test]
    fn duplicate_route_endpoints_are_rejected() {
        let shard = ShardId::new();
        let listeners = format!("71@127.0.0.1:3128@{shard},71@127.0.0.1:3129@{shard}");
        assert!(DaemonConfig::from_parts("127.0.0.1:9901", &listeners, 128).is_err());
    }

    #[test]
    fn control_token_is_mandatory_strong_and_compared_without_plaintext_storage() {
        assert!(ControlToken::new("").is_err());
        assert!(ControlToken::new("short").is_err());
        assert!(ControlToken::new(&"a".repeat(32)).is_ok());
        let token = ControlToken::new(&"a".repeat(32)).expect("token is strong enough");
        assert!(token.authorizes("Bearer aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
        assert!(!token.authorizes("Bearer aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab"));
        assert!(!token.authorizes("Basic aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
    }

    #[test]
    fn control_tokens_are_ascii_bearer_safe_and_cannot_alias_derived_credentials() {
        let worker_id = worker("worker-token-domain");
        let worker_secret = "w".repeat(32);
        let nonce = "n".repeat(32);
        let derived =
            WorkerControlCredential::derive_bearer(&worker_secret, &nonce, &worker_id, 17);

        assert!(ControlToken::new(&"é".repeat(32)).is_err());
        assert!(ControlToken::new(&format!("{} {}", "a".repeat(16), "b".repeat(16))).is_err());
        assert!(ControlCredentials::new(&derived, &worker_secret, &nonce, worker_id, 17).is_err());
    }

    #[test]
    fn a_draining_shard_is_reported_as_retryable_without_fence_details() {
        assert_eq!(
            route_conflict(RouteError::ShardNotDrained),
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "shard connections are still draining; retry".to_owned(),
            )
        );
        let fenced = route_conflict(RouteError::WorkerEpochMismatch {
            expected: 918_273,
            actual: 17,
        });
        assert_eq!(
            fenced,
            (StatusCode::CONFLICT, "route state conflict".to_owned())
        );
        assert!(!fenced.1.contains("918273"));
        assert!(!fenced.1.contains("17"));
    }

    #[tokio::test]
    async fn daemon_task_failure_wins_over_a_pending_shutdown_signal() {
        let mut tasks = JoinSet::new();
        tasks.spawn(async { Err(anyhow::anyhow!("control listener failed")) });

        let error =
            wait_for_shutdown_trigger(&mut tasks, std::future::pending::<anyhow::Result<()>>())
                .await
                .expect_err("a daemon task failure must trigger shutdown");

        assert!(error.to_string().contains("control listener failed"));
    }

    #[tokio::test]
    async fn control_listener_caps_connections_and_expires_slow_readers() {
        let socket = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test listener binds");
        let address = socket.local_addr().expect("test listener has an address");
        let mut listener = LimitedControlListener::new(socket, 1, Duration::from_millis(40))
            .expect("positive connection limit is valid");

        let _first_client = TcpStream::connect(address)
            .await
            .expect("first client connects");
        let (mut first_server, _) = axum::serve::Listener::accept(&mut listener).await;
        let _second_client = TcpStream::connect(address)
            .await
            .expect("second client reaches the kernel backlog");
        assert!(
            tokio::time::timeout(
                Duration::from_millis(20),
                axum::serve::Listener::accept(&mut listener),
            )
            .await
            .is_err()
        );

        let mut byte = [0_u8; 1];
        let read_error = first_server
            .read(&mut byte)
            .await
            .expect_err("an idle control connection expires");
        assert_eq!(read_error.kind(), std::io::ErrorKind::TimedOut);
        drop(first_server);
        assert!(
            tokio::time::timeout(
                Duration::from_secs(1),
                axum::serve::Listener::accept(&mut listener),
            )
            .await
            .is_ok()
        );
    }

    #[test]
    fn every_control_mutation_requires_the_configured_bearer_token() {
        let token = ControlToken::new(&"b".repeat(32)).expect("token is strong enough");
        let mut headers = HeaderMap::new();
        assert_eq!(
            require_control(&headers, &token),
            Err(StatusCode::UNAUTHORIZED)
        );
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
        );
        assert_eq!(require_control(&headers, &token), Ok(()));
    }

    #[tokio::test]
    async fn route_status_is_authenticated_and_fenced_by_source_and_worker_epoch() {
        let registry = RouteRegistry::new(Duration::from_secs(30));
        let endpoint = RouteEndpoint::new(71).expect("endpoint is valid");
        let shard = ShardId::new();
        let worker_id = worker("worker-status");
        registry.prepare_shard(&shard, 7).expect("shard prepares");
        registry
            .bind(
                endpoint,
                RouteBinding::new(
                    TenantId::new(),
                    SessionId::new(),
                    shard.clone(),
                    7,
                    EgressPolicy::public_web_default(),
                    QuotaLimits {
                        max_concurrent_connections: 4,
                        max_connection_starts_per_window: 8,
                        max_dns_queries_per_window: 8,
                        max_egress_bytes_per_window: 4_096,
                        max_total_egress_bytes: 8_192,
                        max_response_bytes: Some(2_048),
                        accounting_window: Duration::from_secs(60),
                        idle_connection_timeout: Duration::from_secs(2),
                    },
                    MonotonicMillis::new(20_000),
                ),
                MonotonicMillis::new(1_000),
            )
            .expect("route binds");
        let credentials = ControlCredentials::new(
            &"d".repeat(32),
            &"c".repeat(32),
            &"n".repeat(32),
            worker_id.clone(),
            7,
        )
        .expect("tokens are strong and distinct");
        let state = ControlState {
            registry,
            listeners: Arc::new(HashMap::from([(endpoint, shard.clone())])),
            started: Instant::now(),
            ready: Arc::new(AtomicBool::new(true)),
            credentials,
        };
        let headers = worker_control_headers(&"c".repeat(32), &"n".repeat(32), &worker_id, 7);

        let active = route_status(
            State(state.clone()),
            headers.clone(),
            Query(RouteStatusRequest {
                endpoint: 71,
                source_shard: shard.clone(),
                worker_id: worker_id.clone(),
                worker_epoch: 7,
            }),
        )
        .await;
        assert!(matches!(active, Ok(Json(response)) if response.active));
        let stale = route_status(
            State(state),
            headers,
            Query(RouteStatusRequest {
                endpoint: 71,
                source_shard: shard,
                worker_id,
                worker_epoch: 6,
            }),
        )
        .await;
        assert!(matches!(stale, Err((StatusCode::CONFLICT, _))));
    }

    #[tokio::test]
    async fn shard_revoke_is_authenticated_epoch_fenced_and_idempotent() {
        let registry = RouteRegistry::new(Duration::from_secs(30));
        let shard = ShardId::new();
        let worker_id = worker("worker-revoke");
        let first = RouteEndpoint::new(81).expect("endpoint is valid");
        let second = RouteEndpoint::new(82).expect("endpoint is valid");
        registry.prepare_shard(&shard, 9).expect("shard prepares");
        for endpoint in [first, second] {
            registry
                .bind(
                    endpoint,
                    RouteBinding::new(
                        TenantId::new(),
                        SessionId::new(),
                        shard.clone(),
                        9,
                        EgressPolicy::public_web_default(),
                        QuotaLimits {
                            max_concurrent_connections: 4,
                            max_connection_starts_per_window: 8,
                            max_dns_queries_per_window: 8,
                            max_egress_bytes_per_window: 4_096,
                            max_total_egress_bytes: 8_192,
                            max_response_bytes: Some(2_048),
                            accounting_window: Duration::from_secs(60),
                            idle_connection_timeout: Duration::from_secs(2),
                        },
                        MonotonicMillis::new(20_000),
                    ),
                    MonotonicMillis::new(1_000),
                )
                .expect("route binds");
        }
        let state = ControlState {
            registry: registry.clone(),
            listeners: Arc::new(HashMap::from([
                (first, shard.clone()),
                (second, shard.clone()),
            ])),
            started: Instant::now(),
            ready: Arc::new(AtomicBool::new(true)),
            credentials: ControlCredentials::new(
                &"d".repeat(32),
                &"f".repeat(32),
                &"n".repeat(32),
                worker_id.clone(),
                9,
            )
            .expect("tokens are strong and distinct"),
        };
        let request = || ShardControlRequest {
            source_shard: shard.clone(),
            worker_id: worker_id.clone(),
            worker_epoch: 9,
        };

        let missing = revoke_shard(State(state.clone()), HeaderMap::new(), Json(request())).await;
        assert!(matches!(missing, Err((StatusCode::UNAUTHORIZED, _))));
        let mut wrong_headers = HeaderMap::new();
        wrong_headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"),
        );
        let wrong = revoke_shard(State(state.clone()), wrong_headers, Json(request())).await;
        assert!(matches!(wrong, Err((StatusCode::UNAUTHORIZED, _))));

        let mut authorized = HeaderMap::new();
        authorized.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer dddddddddddddddddddddddddddddddd"),
        );
        let stale = revoke_shard(
            State(state.clone()),
            authorized.clone(),
            Json(ShardControlRequest {
                source_shard: shard.clone(),
                worker_id: worker_id.clone(),
                worker_epoch: 8,
            }),
        )
        .await;
        assert!(matches!(stale, Err((StatusCode::CONFLICT, _))));
        for endpoint in [first, second] {
            assert!(
                registry
                    .binding(endpoint, &shard, MonotonicMillis::new(1_001))
                    .is_ok()
            );
        }

        assert_eq!(
            revoke_shard(State(state.clone()), authorized.clone(), Json(request())).await,
            Ok(StatusCode::NO_CONTENT)
        );
        for endpoint in [first, second] {
            assert_eq!(
                registry.binding(endpoint, &shard, MonotonicMillis::new(1_002)),
                Err(browserd_egress::RouteError::RouteRevoked)
            );
        }
        assert_eq!(
            revoke_shard(State(state), authorized, Json(request())).await,
            Ok(StatusCode::NO_CONTENT)
        );
    }

    #[test]
    fn supervisor_and_worker_credentials_must_be_distinct() {
        let worker_id = worker("worker-credentials");
        assert!(
            ControlCredentials::new(
                &"s".repeat(32),
                &"w".repeat(32),
                &"n".repeat(32),
                worker_id.clone(),
                1,
            )
            .is_ok()
        );
        assert!(
            ControlCredentials::new(
                &"s".repeat(32),
                &"s".repeat(32),
                &"n".repeat(32),
                worker_id,
                1,
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn only_supervisor_credentials_can_transition_shard_lifecycle() {
        let registry = RouteRegistry::new(Duration::from_secs(30));
        let shard = ShardId::new();
        let endpoint = RouteEndpoint::new(91).expect("endpoint is valid");
        let worker_id = worker("worker-roles");
        let credentials = ControlCredentials::new(
            &"s".repeat(32),
            &"w".repeat(32),
            &"n".repeat(32),
            worker_id.clone(),
            11,
        )
        .expect("tokens differ");
        let state = ControlState {
            registry: registry.clone(),
            listeners: Arc::new(HashMap::from([(endpoint, shard.clone())])),
            started: Instant::now(),
            ready: Arc::new(AtomicBool::new(true)),
            credentials,
        };
        let mut supervisor_headers = HeaderMap::new();
        supervisor_headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer ssssssssssssssssssssssssssssssss"),
        );
        let worker_headers =
            worker_control_headers(&"w".repeat(32), &"n".repeat(32), &worker_id, 11);
        let shard_request = || ShardControlRequest {
            source_shard: shard.clone(),
            worker_id: worker_id.clone(),
            worker_epoch: 11,
        };
        let bind_request = || BindRequest {
            endpoint: 91,
            tenant_id: TenantId::new(),
            session_id: SessionId::new(),
            source_shard: shard.clone(),
            worker_id: worker_id.clone(),
            worker_epoch: 11,
            lease_millis: 10_000,
        };

        assert!(matches!(
            prepare_shard(
                State(state.clone()),
                worker_headers.clone(),
                Json(shard_request()),
            )
            .await,
            Err((StatusCode::UNAUTHORIZED, _))
        ));
        assert!(matches!(
            bind_route(
                State(state.clone()),
                worker_headers.clone(),
                Json(bind_request()),
            )
            .await,
            Err((StatusCode::CONFLICT, _))
        ));
        assert_eq!(
            prepare_shard(
                State(state.clone()),
                supervisor_headers.clone(),
                Json(shard_request()),
            )
            .await,
            Ok(StatusCode::NO_CONTENT)
        );
        assert_eq!(
            prepare_shard(
                State(state.clone()),
                supervisor_headers.clone(),
                Json(shard_request()),
            )
            .await,
            Ok(StatusCode::NO_CONTENT)
        );
        assert!(matches!(
            prepare_shard(
                State(state.clone()),
                supervisor_headers.clone(),
                Json(ShardControlRequest {
                    source_shard: shard.clone(),
                    worker_id: worker_id.clone(),
                    worker_epoch: 10,
                }),
            )
            .await,
            Err((StatusCode::CONFLICT, _))
        ));
        assert!(matches!(
            bind_route(
                State(state.clone()),
                supervisor_headers.clone(),
                Json(bind_request()),
            )
            .await,
            Err((StatusCode::UNAUTHORIZED, _))
        ));
        assert_eq!(
            bind_route(
                State(state.clone()),
                worker_headers.clone(),
                Json(bind_request()),
            )
            .await,
            Ok(StatusCode::CREATED)
        );
        assert!(matches!(
            revoke_shard(
                State(state.clone()),
                worker_headers.clone(),
                Json(shard_request()),
            )
            .await,
            Err((StatusCode::UNAUTHORIZED, _))
        ));
        assert_eq!(
            revoke_shard(
                State(state.clone()),
                supervisor_headers.clone(),
                Json(shard_request()),
            )
            .await,
            Ok(StatusCode::NO_CONTENT)
        );
        assert!(matches!(
            release_shard(State(state.clone()), worker_headers, Json(shard_request())).await,
            Err((StatusCode::UNAUTHORIZED, _))
        ));
        assert_eq!(
            release_shard(
                State(state.clone()),
                supervisor_headers.clone(),
                Json(shard_request()),
            )
            .await,
            Ok(StatusCode::NO_CONTENT)
        );
        assert_eq!(
            release_shard(State(state), supervisor_headers, Json(shard_request())).await,
            Ok(StatusCode::NO_CONTENT)
        );
    }

    #[test]
    fn worker_capability_is_bound_to_worker_process_identity_epoch_and_nonce() {
        let worker_id = WorkerId::new("worker-a").expect("worker ID is valid");
        let other_worker_id = WorkerId::new("worker-b").expect("worker ID is valid");
        let supervisor_secret = "s".repeat(32);
        let current_secret = "c".repeat(32);
        let current_nonce = "n".repeat(32);
        let stale_secret = "o".repeat(32);
        let stale_nonce = "p".repeat(32);
        let credentials = ControlCredentials::new(
            &supervisor_secret,
            &current_secret,
            &current_nonce,
            worker_id.clone(),
            11,
        )
        .expect("process-scoped credentials are valid");

        let current_bearer =
            WorkerControlCredential::derive_bearer(&current_secret, &current_nonce, &worker_id, 11);
        let stale_bearer =
            WorkerControlCredential::derive_bearer(&stale_secret, &stale_nonce, &worker_id, 10);
        assert_ne!(current_bearer, stale_bearer);
        assert_ne!(
            current_bearer,
            WorkerControlCredential::derive_bearer(&current_secret, &current_nonce, &worker_id, 10,)
        );
        assert_ne!(
            current_bearer,
            WorkerControlCredential::derive_bearer(
                &current_secret,
                &current_nonce,
                &other_worker_id,
                11,
            )
        );
        assert_ne!(
            current_bearer,
            WorkerControlCredential::derive_bearer(&current_secret, &stale_nonce, &worker_id, 11,)
        );
        let mut current_headers = HeaderMap::new();
        current_headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {current_bearer}"))
                .expect("derived bearer is an HTTP header value"),
        );
        let mut stale_headers = HeaderMap::new();
        stale_headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {stale_bearer}"))
                .expect("derived bearer is an HTTP header value"),
        );
        let mut unscoped_token_headers = HeaderMap::new();
        unscoped_token_headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {current_secret}"))
                .expect("worker secret is an HTTP header value"),
        );

        assert_eq!(
            require_worker_control(&current_headers, &credentials.worker, &worker_id, 11),
            Ok(())
        );
        assert_eq!(
            require_worker_control(&unscoped_token_headers, &credentials.worker, &worker_id, 11,),
            Err(StatusCode::UNAUTHORIZED)
        );
        assert_eq!(
            require_worker_control(&stale_headers, &credentials.worker, &worker_id, 11),
            Err(StatusCode::UNAUTHORIZED)
        );
        assert_eq!(
            require_worker_control(&current_headers, &credentials.worker, &worker_id, 10),
            Err(StatusCode::CONFLICT)
        );
        assert_eq!(
            require_worker_control(&current_headers, &credentials.worker, &other_worker_id, 11,),
            Err(StatusCode::CONFLICT)
        );
    }

    #[test]
    fn worker_capability_configuration_rejects_weak_or_reused_process_material() {
        let worker_id = WorkerId::new("worker-a").expect("worker ID is valid");
        let supervisor_secret = "s".repeat(32);
        let worker_secret = "w".repeat(32);
        let nonce = "n".repeat(32);

        assert!(
            ControlCredentials::new(
                &supervisor_secret,
                &worker_secret,
                &nonce,
                worker_id.clone(),
                0,
            )
            .is_err()
        );
        assert!(
            ControlCredentials::new(
                &supervisor_secret,
                &worker_secret,
                "short",
                worker_id.clone(),
                11,
            )
            .is_err()
        );
        assert!(
            ControlCredentials::new(
                &supervisor_secret,
                &worker_secret,
                &worker_secret,
                worker_id.clone(),
                11,
            )
            .is_err()
        );
        assert!(
            ControlCredentials::new(&supervisor_secret, &worker_secret, &nonce, worker_id, 11,)
                .is_ok()
        );
    }

    #[tokio::test]
    async fn every_worker_route_handler_rejects_stale_capability_or_owner_claim_before_mutation() {
        let registry = RouteRegistry::new(Duration::from_secs(30));
        let worker_id = WorkerId::new("worker-current").expect("worker ID is valid");
        let other_worker_id = WorkerId::new("worker-other").expect("worker ID is valid");
        let shard = ShardId::new();
        let endpoint = RouteEndpoint::new(101).expect("endpoint is valid");
        registry.prepare_shard(&shard, 11).expect("shard prepares");
        let worker_secret = "w".repeat(32);
        let worker_nonce = "n".repeat(32);
        let credentials = ControlCredentials::new(
            &"s".repeat(32),
            &worker_secret,
            &worker_nonce,
            worker_id.clone(),
            11,
        )
        .expect("credentials are valid");
        let state = ControlState {
            registry: registry.clone(),
            listeners: Arc::new(HashMap::from([(endpoint, shard.clone())])),
            started: Instant::now(),
            ready: Arc::new(AtomicBool::new(true)),
            credentials,
        };
        let current_bearer =
            WorkerControlCredential::derive_bearer(&worker_secret, &worker_nonce, &worker_id, 11);
        let stale_bearer = WorkerControlCredential::derive_bearer(
            &"o".repeat(32),
            &"p".repeat(32),
            &worker_id,
            10,
        );
        let mut current_headers = HeaderMap::new();
        current_headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {current_bearer}"))
                .expect("derived bearer is an HTTP header value"),
        );
        let mut stale_headers = HeaderMap::new();
        stale_headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {stale_bearer}"))
                .expect("derived bearer is an HTTP header value"),
        );
        let bind_request = |worker_id: WorkerId, worker_epoch| BindRequest {
            endpoint: endpoint.get(),
            tenant_id: TenantId::new(),
            session_id: SessionId::new(),
            source_shard: shard.clone(),
            worker_id,
            worker_epoch,
            lease_millis: 10_000,
        };

        let stale = bind_route(
            State(state.clone()),
            stale_headers,
            Json(bind_request(worker_id.clone(), 11)),
        )
        .await;
        assert_eq!(
            stale,
            Err((
                StatusCode::UNAUTHORIZED,
                "control authorization failed".to_owned(),
            ))
        );
        assert!(matches!(
            registry.binding(endpoint, &shard, MonotonicMillis::new(0)),
            Err(browserd_egress::RouteError::RouteNotFound)
        ));
        let wrong_owner = bind_route(
            State(state.clone()),
            current_headers.clone(),
            Json(bind_request(other_worker_id.clone(), 11)),
        )
        .await;
        assert_eq!(
            wrong_owner,
            Err((StatusCode::CONFLICT, "worker ownership mismatch".to_owned(),))
        );
        assert_eq!(
            bind_route(
                State(state.clone()),
                current_headers.clone(),
                Json(bind_request(worker_id.clone(), 11)),
            )
            .await,
            Ok(StatusCode::CREATED)
        );

        let wrong_renew = renew_route(
            State(state.clone()),
            current_headers.clone(),
            Json(LeaseRequest {
                endpoint: endpoint.get(),
                source_shard: shard.clone(),
                worker_id: other_worker_id.clone(),
                worker_epoch: 11,
                lease_millis: 10_000,
            }),
        )
        .await;
        assert_eq!(
            wrong_renew,
            Err((StatusCode::CONFLICT, "worker ownership mismatch".to_owned(),))
        );
        let wrong_status = route_status(
            State(state.clone()),
            current_headers.clone(),
            Query(RouteStatusRequest {
                endpoint: endpoint.get(),
                source_shard: shard.clone(),
                worker_id: other_worker_id,
                worker_epoch: 11,
            }),
        )
        .await;
        assert!(matches!(wrong_status, Err((StatusCode::CONFLICT, _))));
        let wrong_revoke = revoke_route(
            State(state.clone()),
            current_headers.clone(),
            Json(RevokeRequest {
                endpoint: endpoint.get(),
                source_shard: shard.clone(),
                worker_id: worker_id.clone(),
                worker_epoch: 10,
            }),
        )
        .await;
        assert_eq!(
            wrong_revoke,
            Err((StatusCode::CONFLICT, "worker ownership mismatch".to_owned(),))
        );
        assert!(
            registry
                .binding(endpoint, &shard, MonotonicMillis::new(0))
                .is_ok()
        );
        assert_eq!(
            revoke_route(
                State(state),
                current_headers,
                Json(RevokeRequest {
                    endpoint: endpoint.get(),
                    source_shard: shard,
                    worker_id,
                    worker_epoch: 11,
                }),
            )
            .await,
            Ok(StatusCode::NO_CONTENT)
        );
    }

    #[tokio::test]
    async fn supervisor_lifecycle_claim_must_match_the_configured_worker_before_transition() {
        let registry = RouteRegistry::new(Duration::from_secs(30));
        let worker_id = WorkerId::new("worker-current").expect("worker ID is valid");
        let other_worker_id = WorkerId::new("worker-other").expect("worker ID is valid");
        let shard = ShardId::new();
        let credentials = ControlCredentials::new(
            &"s".repeat(32),
            &"w".repeat(32),
            &"n".repeat(32),
            worker_id.clone(),
            11,
        )
        .expect("credentials are valid");
        let state = ControlState {
            registry,
            listeners: Arc::new(HashMap::new()),
            started: Instant::now(),
            ready: Arc::new(AtomicBool::new(true)),
            credentials,
        };
        let mut supervisor_headers = HeaderMap::new();
        supervisor_headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer ssssssssssssssssssssssssssssssss"),
        );

        assert_eq!(
            require_supervisor_control(&supervisor_headers, &state.credentials, &worker_id, 11,),
            Ok(())
        );
        let wrong_worker = prepare_shard(
            State(state.clone()),
            supervisor_headers.clone(),
            Json(ShardControlRequest {
                source_shard: shard.clone(),
                worker_id: other_worker_id,
                worker_epoch: 11,
            }),
        )
        .await;
        assert_eq!(
            wrong_worker,
            Err((StatusCode::CONFLICT, "worker ownership mismatch".to_owned(),))
        );
        let stale_epoch = prepare_shard(
            State(state.clone()),
            supervisor_headers.clone(),
            Json(ShardControlRequest {
                source_shard: shard.clone(),
                worker_id: worker_id.clone(),
                worker_epoch: 10,
            }),
        )
        .await;
        assert_eq!(
            stale_epoch,
            Err((StatusCode::CONFLICT, "worker ownership mismatch".to_owned(),))
        );
        assert_eq!(
            prepare_shard(
                State(state.clone()),
                supervisor_headers.clone(),
                Json(ShardControlRequest {
                    source_shard: shard.clone(),
                    worker_id: worker_id.clone(),
                    worker_epoch: 11,
                }),
            )
            .await,
            Ok(StatusCode::NO_CONTENT)
        );
        let wrong_revoke = revoke_shard(
            State(state.clone()),
            supervisor_headers.clone(),
            Json(ShardControlRequest {
                source_shard: shard.clone(),
                worker_id: worker("worker-other-revoke"),
                worker_epoch: 11,
            }),
        )
        .await;
        assert!(matches!(wrong_revoke, Err((StatusCode::CONFLICT, _))));
        assert_eq!(
            prepare_shard(
                State(state.clone()),
                supervisor_headers.clone(),
                Json(ShardControlRequest {
                    source_shard: shard.clone(),
                    worker_id: worker_id.clone(),
                    worker_epoch: 11,
                }),
            )
            .await,
            Ok(StatusCode::NO_CONTENT)
        );
        assert_eq!(
            revoke_shard(
                State(state.clone()),
                supervisor_headers.clone(),
                Json(ShardControlRequest {
                    source_shard: shard.clone(),
                    worker_id: worker_id.clone(),
                    worker_epoch: 11,
                }),
            )
            .await,
            Ok(StatusCode::NO_CONTENT)
        );
        let wrong_release = release_shard(
            State(state.clone()),
            supervisor_headers.clone(),
            Json(ShardControlRequest {
                source_shard: shard.clone(),
                worker_id: worker_id.clone(),
                worker_epoch: 10,
            }),
        )
        .await;
        assert!(matches!(wrong_release, Err((StatusCode::CONFLICT, _))));
        assert_eq!(
            release_shard(
                State(state),
                supervisor_headers,
                Json(ShardControlRequest {
                    source_shard: shard,
                    worker_id,
                    worker_epoch: 11,
                }),
            )
            .await,
            Ok(StatusCode::NO_CONTENT)
        );
    }

    #[tokio::test]
    async fn registry_epoch_conflicts_do_not_disclose_internal_fence_values() {
        let registry = RouteRegistry::new(Duration::from_secs(30));
        let worker_id = worker("worker-conflict-redaction");
        let shard = ShardId::new();
        registry
            .prepare_shard(&shard, 12)
            .expect("newer shard epoch prepares");
        let state = ControlState {
            registry,
            listeners: Arc::new(HashMap::new()),
            started: Instant::now(),
            ready: Arc::new(AtomicBool::new(true)),
            credentials: ControlCredentials::new(
                &"s".repeat(32),
                &"w".repeat(32),
                &"n".repeat(32),
                worker_id.clone(),
                11,
            )
            .expect("credentials are valid"),
        };
        let mut supervisor_headers = HeaderMap::new();
        supervisor_headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer ssssssssssssssssssssssssssssssss"),
        );

        let conflict = revoke_shard(
            State(state),
            supervisor_headers,
            Json(ShardControlRequest {
                source_shard: shard,
                worker_id,
                worker_epoch: 11,
            }),
        )
        .await;
        assert_eq!(
            conflict,
            Err((StatusCode::CONFLICT, "route state conflict".to_owned(),))
        );
    }
}
