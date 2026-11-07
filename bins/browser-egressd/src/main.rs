#![forbid(unsafe_code)]

use std::io;
use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use browser_egressd::{
    DaemonControlError, DaemonLimits, EgressDaemon, PreparedRouteRequest, RenewRouteRequest,
    allocate_daemon_epoch,
};
use browserd_coordination::{
    RedisSafetyAuthority, RedisSafetyAuthorityConfig, SafetyAuthority, SafetyAuthorityConfig,
    SafetyObserver,
};
use browserd_core::{EgressFence, RuntimeSafetyCache, TenantId, WorkerId};
use browserd_egress::{AttachmentState, DataPlaneLimits, QuotaLimits};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::net::{TcpListener, UnixListener};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

const MAX_INSTALL_TASKS: usize = 1024;

#[derive(Clone)]
struct AppState {
    daemon: Arc<EgressDaemon>,
    credentials: Arc<ControlCredentials>,
    safety_cache: Arc<RuntimeSafetyCache>,
}

#[derive(Clone)]
struct ControlToken([u8; 32]);

impl ControlToken {
    fn new(secret: &str) -> anyhow::Result<Self> {
        if secret.len() < 32
            || secret.len() > 4096
            || !secret.as_bytes().iter().all(u8::is_ascii_graphic)
        {
            bail!("control tokens must contain 32 to 4096 visible ASCII bytes");
        }
        Ok(Self(Sha256::digest(secret.as_bytes()).into()))
    }

    fn authorizes(&self, headers: &HeaderMap) -> bool {
        let Some(candidate) = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
        else {
            return false;
        };
        let digest: [u8; 32] = Sha256::digest(candidate.as_bytes()).into();
        bool::from(self.0.ct_eq(&digest))
    }

    fn is_same(&self, other: &Self) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }
}

#[derive(Clone)]
struct ControlCredentials {
    supervisor: ControlToken,
    worker: ControlToken,
    worker_id: WorkerId,
    worker_epoch: u64,
}

impl ControlCredentials {
    fn new(
        supervisor_secret: &str,
        worker_secret: &str,
        worker_id: WorkerId,
        worker_epoch: u64,
    ) -> anyhow::Result<Self> {
        if worker_epoch == 0 {
            bail!("worker epoch must be nonzero");
        }
        let supervisor = ControlToken::new(supervisor_secret)?;
        let worker = ControlToken::new(worker_secret)?;
        if supervisor.is_same(&worker) {
            bail!("supervisor and worker tokens must be distinct");
        }
        Ok(Self {
            supervisor,
            worker,
            worker_id,
            worker_epoch,
        })
    }

    fn authorize_worker(&self, headers: &HeaderMap, fence: &EgressFence) -> Result<(), ApiError> {
        let owner = fence.shard().owner();
        if !self.worker.authorizes(headers)
            || owner.worker_id() != &self.worker_id
            || owner.worker_epoch().get() != self.worker_epoch
        {
            return Err(ApiError::unauthorized());
        }
        Ok(())
    }

    fn authorize_revoke(&self, headers: &HeaderMap, fence: &EgressFence) -> Result<(), ApiError> {
        if self.supervisor.authorizes(headers) {
            return Ok(());
        }
        self.authorize_worker(headers, fence)
    }

    fn authorize_prepare(
        &self,
        headers: &HeaderMap,
        fence: &EgressFence,
        shared_context: bool,
    ) -> Result<(), ApiError> {
        if shared_context {
            return if self.supervisor.authorizes(headers) {
                Ok(())
            } else {
                Err(ApiError::unauthorized())
            };
        }
        self.authorize_worker(headers, fence)
    }
}

struct Config {
    control_bind: SocketAddr,
    install_socket: PathBuf,
    epoch_state: PathBuf,
    expected_peer_uid: u32,
    max_control_connections: usize,
    limits: DaemonLimits,
    credentials: ControlCredentials,
}

impl Config {
    fn from_env() -> anyhow::Result<Self> {
        let control_bind = env_value("BROWSER_EGRESS_CONTROL_BIND")?
            .parse::<SocketAddr>()
            .context("BROWSER_EGRESS_CONTROL_BIND must be an IP socket address")?;
        if !control_bind.ip().is_loopback() {
            bail!("BROWSER_EGRESS_CONTROL_BIND must be loopback");
        }
        let install_socket = PathBuf::from(env_value("BROWSER_EGRESS_INSTALL_SOCKET")?);
        validate_socket_path(&install_socket)?;
        let epoch_state = PathBuf::from(env_value("BROWSER_EGRESS_DAEMON_EPOCH_STATE")?);
        let expected_peer_uid = parse_env("BROWSER_EGRESS_EXPECTED_PEER_UID")?;
        let max_control_connections = parse_env("BROWSER_EGRESS_MAX_CONTROL_CONNECTIONS")?;
        if max_control_connections == 0 || max_control_connections > MAX_INSTALL_TASKS {
            bail!("BROWSER_EGRESS_MAX_CONTROL_CONNECTIONS must be between 1 and 1024");
        }
        let max_lease = Duration::from_millis(parse_env("BROWSER_EGRESS_MAX_LEASE_MILLIS")?);
        let max_plans = parse_env("BROWSER_EGRESS_MAX_PLANS")?;
        let quotas = QuotaLimits {
            max_concurrent_connections: parse_env("BROWSER_EGRESS_MAX_CONNECTIONS_PER_ROUTE")?,
            max_connection_starts_per_window: parse_env(
                "BROWSER_EGRESS_MAX_CONNECTION_STARTS_PER_MINUTE",
            )?,
            max_dns_queries_per_window: parse_env("BROWSER_EGRESS_MAX_DNS_PER_MINUTE")?,
            max_egress_bytes_per_window: parse_env("BROWSER_EGRESS_MAX_BYTES_PER_MINUTE")?,
            max_total_egress_bytes: parse_env("BROWSER_EGRESS_MAX_TOTAL_BYTES")?,
            max_response_bytes: Some(parse_env("BROWSER_EGRESS_MAX_RESPONSE_BYTES")?),
            accounting_window: Duration::from_secs(60),
            idle_connection_timeout: Duration::from_millis(parse_env(
                "BROWSER_EGRESS_IDLE_TIMEOUT_MILLIS",
            )?),
        };
        let mut limits = DaemonLimits::new(max_lease, max_plans, quotas)
            .map_err(|error| anyhow::anyhow!(error))?;
        match std::env::var("BROWSER_EGRESS_MAX_PLAN_HISTORY") {
            Ok(value) => {
                let capacity = value
                    .parse()
                    .context("BROWSER_EGRESS_MAX_PLAN_HISTORY must be a positive capacity")?;
                limits = limits
                    .with_plan_history_capacity(capacity)
                    .map_err(|error| anyhow::anyhow!(error))?;
            }
            Err(std::env::VarError::NotPresent) => {}
            Err(error) => {
                return Err(error).context("BROWSER_EGRESS_MAX_PLAN_HISTORY must be Unicode");
            }
        }
        let worker_id = WorkerId::new(env_value("BROWSER_EGRESS_WORKER_ID")?)
            .context("BROWSER_EGRESS_WORKER_ID is invalid")?;
        let worker_epoch = parse_env("BROWSER_EGRESS_WORKER_EPOCH")?;
        let credentials = ControlCredentials::new(
            &env_value("BROWSER_EGRESS_SUPERVISOR_TOKEN")?,
            &env_value("BROWSER_EGRESS_WORKER_TOKEN")?,
            worker_id,
            worker_epoch,
        )?;
        Ok(Self {
            control_bind,
            install_socket,
            epoch_state,
            expected_peer_uid,
            max_control_connections,
            limits,
            credentials,
        })
    }
}

fn env_value(name: &'static str) -> anyhow::Result<String> {
    std::env::var(name).with_context(|| format!("{name} must be explicitly configured"))
}

fn parse_env<T>(name: &'static str) -> anyhow::Result<T>
where
    T: std::str::FromStr,
    T::Err: std::error::Error + Send + Sync + 'static,
{
    env_value(name)?
        .parse()
        .with_context(|| format!("{name} has an invalid value"))
}

fn validate_socket_path(path: &Path) -> anyhow::Result<()> {
    if !path.is_absolute()
        || path.file_name().is_none()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        bail!("BROWSER_EGRESS_INSTALL_SOCKET must be an absolute non-traversing file path");
    }
    let parent = path
        .parent()
        .context("BROWSER_EGRESS_INSTALL_SOCKET must have a parent")?;
    for ancestor in parent
        .ancestors()
        .filter(|entry| !entry.as_os_str().is_empty())
    {
        let metadata = std::fs::symlink_metadata(ancestor).with_context(|| {
            format!(
                "install socket parent is unavailable: {}",
                ancestor.display()
            )
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            bail!("install socket parent chain must contain only real directories");
        }
    }
    if std::fs::symlink_metadata(path).is_ok() {
        bail!("install socket path already exists");
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrepareApiRequest {
    daemon_epoch: u64,
    tenant_id: TenantId,
    egress_fence: EgressFence,
    binding_digest_hex: String,
    profile: String,
    lease_ttl_millis: u64,
    #[serde(default)]
    shared_context: bool,
}

#[derive(Serialize)]
struct PrepareApiResponse {
    daemon_epoch: u64,
    egress_fence: EgressFence,
    binding_digest_hex: String,
    prepare_revision: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FenceApiRequest {
    daemon_epoch: u64,
    egress_fence: EgressFence,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RenewApiRequest {
    renewal_sequence: u64,
    daemon_epoch: u64,
    egress_fence: EgressFence,
    attachment_id: u64,
    activation_revision: u64,
    lease_ttl_millis: u64,
}

#[derive(Serialize)]
struct RenewApiResponse {
    renewal_sequence: u64,
    daemon_epoch: u64,
    egress_fence: EgressFence,
    attachment_id: u64,
    activation_revision: u64,
    expires_at_millis: u64,
}

#[derive(Serialize)]
struct StatusApiResponse {
    daemon_epoch: u64,
    egress_fence: EgressFence,
    state: &'static str,
    active: Option<browserd_egress_control::ActiveInstallResponse>,
}

#[derive(Serialize)]
struct ErrorBody {
    code: &'static str,
    message: String,
}

struct ApiError {
    status: StatusCode,
    body: ErrorBody,
}

impl ApiError {
    fn unauthorized() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            body: ErrorBody {
                code: "unauthorized",
                message: "control capability is missing or does not own this fence".to_owned(),
            },
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        (self.status, Json(self.body)).into_response()
    }
}

async fn health() -> StatusCode {
    StatusCode::NO_CONTENT
}

async fn readiness(State(state): State<AppState>) -> StatusCode {
    if state.daemon.daemon_epoch().get() == 0
        || state.safety_cache.with_fresh_snapshot(|_| ()).is_err()
    {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::NO_CONTENT
    }
}

async fn prepare_route(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<PrepareApiRequest>,
) -> Result<(StatusCode, Json<PrepareApiResponse>), ApiError> {
    state
        .credentials
        .authorize_prepare(&headers, &request.egress_fence, request.shared_context)?;
    let digest = parse_digest(&request.binding_digest_hex)?;
    let prepared = PreparedRouteRequest::new(
        request.daemon_epoch,
        request.tenant_id,
        request.egress_fence,
        digest,
        request.profile,
        Duration::from_millis(request.lease_ttl_millis),
    )
    .map_err(ApiError::from)?;
    let prepared = if request.shared_context {
        prepared.with_shared_context()
    } else {
        prepared
    };
    let response = state.daemon.prepare(prepared).map_err(ApiError::from)?;
    Ok((
        StatusCode::CREATED,
        Json(PrepareApiResponse {
            daemon_epoch: response.daemon_epoch(),
            egress_fence: response.egress_fence().clone(),
            binding_digest_hex: hex::encode(response.binding_digest()),
            prepare_revision: response.prepare_revision(),
        }),
    ))
}

async fn route_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<FenceApiRequest>,
) -> Result<Json<StatusApiResponse>, ApiError> {
    state
        .credentials
        .authorize_revoke(&headers, &request.egress_fence)?;
    let status = state
        .daemon
        .status(request.daemon_epoch, &request.egress_fence)
        .map_err(ApiError::from)?;
    Ok(Json(status_response(status)))
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ShardRetireRequest {
    daemon_epoch: u64,
    shard_fence: browserd_core::ShardFence,
}

async fn retire_shard(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ShardRetireRequest>,
) -> Result<Json<ShardRetireRequest>, ApiError> {
    if !state.credentials.supervisor.authorizes(&headers) {
        return Err(ApiError::unauthorized());
    }
    state
        .daemon
        .retire_shard(request.daemon_epoch, &request.shard_fence)
        .map_err(ApiError::from)?;
    Ok(Json(request))
}

async fn revoke_route(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<FenceApiRequest>,
) -> Result<Json<StatusApiResponse>, ApiError> {
    state
        .credentials
        .authorize_revoke(&headers, &request.egress_fence)?;
    let status = state
        .daemon
        .revoke(request.daemon_epoch, &request.egress_fence)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(status_response(status)))
}

async fn renew_route(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<RenewApiRequest>,
) -> Result<Json<RenewApiResponse>, ApiError> {
    state
        .credentials
        .authorize_worker(&headers, &request.egress_fence)?;
    let renewed = state
        .daemon
        .renew(
            RenewRouteRequest::new(
                request.renewal_sequence,
                request.daemon_epoch,
                request.egress_fence,
                request.attachment_id,
                request.activation_revision,
                Duration::from_millis(request.lease_ttl_millis),
            )
            .map_err(ApiError::from)?,
        )
        .map_err(ApiError::from)?;
    Ok(Json(RenewApiResponse {
        renewal_sequence: renewed.renewal_sequence(),
        daemon_epoch: renewed.daemon_epoch(),
        egress_fence: renewed.egress_fence().clone(),
        attachment_id: renewed.attachment_id(),
        activation_revision: renewed.activation_revision(),
        expires_at_millis: renewed.expires_at_millis(),
    }))
}

fn status_response(status: browser_egressd::AttachmentStatusView) -> StatusApiResponse {
    StatusApiResponse {
        daemon_epoch: status.daemon_epoch(),
        egress_fence: status.egress_fence().clone(),
        state: attachment_state_name(status.state()),
        active: status.active().cloned(),
    }
}

const fn attachment_state_name(state: AttachmentState) -> &'static str {
    match state {
        AttachmentState::Absent => "absent",
        AttachmentState::Prepared => "prepared",
        AttachmentState::Installing => "installing",
        AttachmentState::Active => "active",
        AttachmentState::Revoking => "revoking",
        AttachmentState::Revoked => "revoked",
        AttachmentState::Drained => "drained",
        AttachmentState::Cancelled => "cancelled",
        AttachmentState::Released => "released",
    }
}

fn parse_digest(encoded: &str) -> Result<[u8; 32], ApiError> {
    let decoded = hex::decode(encoded).map_err(|_| ApiError {
        status: StatusCode::BAD_REQUEST,
        body: ErrorBody {
            code: "invalid_binding_digest",
            message: "binding digest must be exactly 32 bytes of hexadecimal".to_owned(),
        },
    })?;
    decoded.try_into().map_err(|_| ApiError {
        status: StatusCode::BAD_REQUEST,
        body: ErrorBody {
            code: "invalid_binding_digest",
            message: "binding digest must be exactly 32 bytes of hexadecimal".to_owned(),
        },
    })
}

impl From<DaemonControlError> for ApiError {
    fn from(error: DaemonControlError) -> Self {
        let (status, code) = match error {
            DaemonControlError::InvalidLimits
            | DaemonControlError::InvalidPrepareRequest
            | DaemonControlError::InvalidRenewRequest
            | DaemonControlError::UnsupportedPolicy => {
                (StatusCode::BAD_REQUEST, "invalid_route_request")
            }
            DaemonControlError::DaemonEpochMismatch { .. } => {
                (StatusCode::CONFLICT, "daemon_epoch_mismatch")
            }
            DaemonControlError::PlanConflict
            | DaemonControlError::InstallMetadataMismatch
            | DaemonControlError::RenewalConflict => (StatusCode::CONFLICT, "route_fence_conflict"),
            DaemonControlError::PlanCapacityExceeded => {
                (StatusCode::TOO_MANY_REQUESTS, "route_capacity_exceeded")
            }
            DaemonControlError::PlanHistoryCapacityExceeded => (
                StatusCode::TOO_MANY_REQUESTS,
                "route_history_capacity_exceeded",
            ),
            DaemonControlError::PlanNotFound => (StatusCode::NOT_FOUND, "route_not_found"),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, "egress_internal_error"),
        };
        Self {
            status,
            body: ErrorBody {
                code,
                message: error.to_string(),
            },
        }
    }
}

async fn run_install_server(
    listener: UnixListener,
    daemon: Arc<EgressDaemon>,
    expected_peer_uid: u32,
    max_tasks: usize,
    shutdown: CancellationToken,
) {
    let permits = Arc::new(tokio::sync::Semaphore::new(max_tasks));
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            () = shutdown.cancelled() => break,
            completed = tasks.join_next(), if !tasks.is_empty() => {
                let _ = completed;
            }
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else {
                    break;
                };
                let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                    drop(stream);
                    continue;
                };
                let daemon = Arc::clone(&daemon);
                tasks.spawn(async move {
                    let _permit = permit;
                    let _ = daemon
                        .handle_control_stream(stream, expected_peer_uid)
                        .await;
                });
            }
        }
    }
    while tasks.join_next().await.is_some() {}
}

async fn shutdown_signal() -> io::Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result,
            _ = terminate.recv() => Ok(()),
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await
}

async fn run_safety_observer(observer: Arc<SafetyObserver>, shutdown: CancellationToken) {
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            biased;
            () = shutdown.cancelled() => break,
            _ = ticker.tick() => {}
        }
        tokio::select! {
            biased;
            () = shutdown.cancelled() => break,
            result = observer.refresh() => {
                if result.is_err() {
                    eprintln!("runtime safety observer refresh unavailable");
                }
            }
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = Config::from_env()?;
    let safety_cache = Arc::new(RuntimeSafetyCache::new());
    let safety_config = RedisSafetyAuthorityConfig::new(
        env_value("BROWSERD_REDIS_URL")?,
        env_value("BROWSERD_REDIS_PREFIX")?,
        SafetyAuthorityConfig::default(),
        4,
        Duration::from_secs(5),
    )
    .context("runtime safety Redis configuration is invalid")?;
    let safety_authority: Arc<dyn SafetyAuthority> = Arc::new(
        RedisSafetyAuthority::connect(safety_config)
            .await
            .context("runtime safety authority connection unavailable")?,
    );
    let safety_path = std::env::var_os("BROWSERD_SAFETY_STATE_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| config.epoch_state.with_extension("safety-state"));
    let safety_observer = Arc::new(
        SafetyObserver::open(
            safety_path,
            safety_authority,
            Arc::clone(&safety_cache),
            Duration::from_secs(30),
        )
        .context("runtime safety observer durability unavailable")?,
    );
    // An uninitialized authority leaves readiness unavailable while authenticated control works.
    let _initial_safety = safety_observer.refresh().await;
    let daemon_epoch = allocate_daemon_epoch(&config.epoch_state)
        .context("durable daemon epoch allocation failed")?;
    let daemon = Arc::new(EgressDaemon::with_runtime_safety(
        daemon_epoch,
        config.limits,
        DataPlaneLimits::default(),
        Arc::clone(&safety_cache),
    )?);
    let control_listener = TcpListener::bind(config.control_bind)
        .await
        .context("control listener bind failed")?;
    let install_listener = UnixListener::bind(&config.install_socket)
        .context("listener installation socket bind failed")?;
    let shutdown = CancellationToken::new();
    let safety_task = tokio::spawn(run_safety_observer(safety_observer, shutdown.clone()));
    let install_task = tokio::spawn(run_install_server(
        install_listener,
        Arc::clone(&daemon),
        config.expected_peer_uid,
        config.max_control_connections,
        shutdown.clone(),
    ));
    let app = Router::new()
        .route("/healthz", get(health))
        .route("/readyz", get(readiness))
        .route("/v1/routes/prepare", post(prepare_route))
        .route("/v1/routes/renew", post(renew_route))
        .route("/v1/routes/status", post(route_status))
        .route("/v1/routes/revoke", post(revoke_route))
        .route("/v1/shards/retire", post(retire_shard))
        .with_state(AppState {
            daemon: Arc::clone(&daemon),
            credentials: Arc::new(config.credentials),
            safety_cache,
        });
    let control_result = axum::serve(control_listener, app)
        .with_graceful_shutdown(async {
            let _ = shutdown_signal().await;
        })
        .await;
    shutdown.cancel();
    let _ = safety_task.await;
    let _ = install_task.await;
    control_result.context("control server failed")?;
    daemon.shutdown().await?;
    remove_owned_socket(&config.install_socket)?;
    Ok(())
}

fn remove_owned_socket(path: &Path) -> anyhow::Result<()> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("could not inspect owned socket: {}", path.display()))?;
    if !std::os::unix::fs::FileTypeExt::is_socket(&metadata.file_type()) {
        bail!("refusing to remove a non-socket install path");
    }
    std::fs::remove_file(path).context("could not remove owned install socket")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::collections::HashSet;
    use std::os::unix::fs::DirBuilderExt;

    use browserd_coordination::{
        MemorySafetyAuthority, SafetyActorIdentity, SafetyAuthorityError, SafetyInitializeRequest,
    };
    use browserd_core::{
        LaunchGeneration, OwnerFence, RouteGeneration, SafetySwitchSnapshot, SessionId,
        SessionIncarnation, ShardFence, ShardId, WorkerEpoch,
    };
    use browserd_egress::DaemonEpoch;

    use super::*;

    struct PrivateDirectory(PathBuf);
    impl PrivateDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("egress-safety-{}", SessionId::new()));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&path)
                .expect("private observer directory");
            Self(path)
        }
    }
    impl Drop for PrivateDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn runtime_state(cache: Arc<RuntimeSafetyCache>) -> AppState {
        let limits = DaemonLimits::new(
            Duration::from_secs(30),
            8,
            QuotaLimits {
                max_concurrent_connections: 8,
                max_connection_starts_per_window: 32,
                max_dns_queries_per_window: 32,
                max_egress_bytes_per_window: 1024 * 1024,
                max_total_egress_bytes: 8 * 1024 * 1024,
                max_response_bytes: Some(1024 * 1024),
                accounting_window: Duration::from_secs(60),
                idle_connection_timeout: Duration::from_secs(15),
            },
        )
        .expect("limits");
        AppState {
            daemon: Arc::new(
                EgressDaemon::with_runtime_safety(
                    DaemonEpoch::new(41).expect("epoch"),
                    limits,
                    DataPlaneLimits::default(),
                    cache.clone(),
                )
                .expect("daemon"),
            ),
            credentials: Arc::new(
                ControlCredentials::new(
                    &"s".repeat(32),
                    &"w".repeat(32),
                    WorkerId::new("runtime-worker").expect("worker"),
                    7,
                )
                .expect("credentials"),
            ),
            safety_cache: cache,
        }
    }

    fn runtime_fence() -> EgressFence {
        EgressFence::new(
            ShardFence::new(
                OwnerFence::new(
                    WorkerId::new("runtime-worker").expect("worker"),
                    WorkerEpoch::new(7).expect("worker epoch"),
                ),
                ShardId::new(),
                LaunchGeneration::new(1).expect("launch"),
            ),
            RouteGeneration::new(1).expect("route"),
            SessionId::new(),
            SessionIncarnation::new(1).expect("incarnation"),
        )
    }

    fn worker_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {}", "w".repeat(32))
                .parse()
                .expect("header"),
        );
        headers
    }

    #[tokio::test]
    async fn readiness_requires_fresh_safety_but_health_remains_available() {
        let cache = Arc::new(RuntimeSafetyCache::new());
        let state = runtime_state(cache.clone());
        let namespace = *SessionId::new().as_uuid();
        assert_eq!(health().await, StatusCode::NO_CONTENT);
        assert_eq!(
            readiness(State(state.clone())).await,
            StatusCode::SERVICE_UNAVAILABLE
        );
        cache
            .install(
                namespace,
                SafetySwitchSnapshot::default(),
                Duration::from_secs(30),
            )
            .expect("observed initial authority");
        assert_eq!(
            readiness(State(state.clone())).await,
            StatusCode::NO_CONTENT
        );
        cache.invalidate().expect("invalidate");
        assert_eq!(
            readiness(State(state.clone())).await,
            StatusCode::SERVICE_UNAVAILABLE
        );
        cache
            .install(
                namespace,
                SafetySwitchSnapshot::default(),
                Duration::from_millis(1),
            )
            .expect("short fresh observation");
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(
            readiness(State(state)).await,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(health().await, StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn stale_safety_keeps_authenticated_route_cleanup_operational() {
        let cache = Arc::new(RuntimeSafetyCache::new());
        cache
            .install(
                *SessionId::new().as_uuid(),
                SafetySwitchSnapshot::default(),
                Duration::from_secs(30),
            )
            .expect("initialize");
        let state = runtime_state(cache.clone());
        let fence = runtime_fence();
        assert!(
            prepare_route(
                State(state.clone()),
                worker_headers(),
                Json(PrepareApiRequest {
                    daemon_epoch: 41,
                    tenant_id: TenantId::new(),
                    egress_fence: fence.clone(),
                    binding_digest_hex: "ab".repeat(32),
                    profile: "public-web".to_owned(),
                    lease_ttl_millis: 10_000,
                    shared_context: false,
                }),
            )
            .await
            .is_ok()
        );
        cache.invalidate().expect("authority unavailable");
        assert_eq!(
            readiness(State(state.clone())).await,
            StatusCode::SERVICE_UNAVAILABLE
        );
        let request = || FenceApiRequest {
            daemon_epoch: 41,
            egress_fence: fence.clone(),
        };
        assert!(matches!(
            revoke_route(State(state.clone()), HeaderMap::new(), Json(request())).await,
            Err(ApiError {
                status: StatusCode::UNAUTHORIZED,
                ..
            })
        ));
        let revoked = revoke_route(State(state.clone()), worker_headers(), Json(request())).await;
        assert!(matches!(
            revoked,
            Ok(Json(StatusApiResponse {
                state: "released",
                ..
            }))
        ));
        let status = route_status(State(state), worker_headers(), Json(request())).await;
        assert!(matches!(
            status,
            Ok(Json(StatusApiResponse {
                state: "released",
                ..
            }))
        ));
    }

    #[tokio::test]
    async fn independent_observer_polls_after_initialization_and_joins_on_shutdown() {
        let directory = PrivateDirectory::new();
        let authority = Arc::new(MemorySafetyAuthority::default());
        let cache = Arc::new(RuntimeSafetyCache::new());
        let pin = directory.0.join("safety-state");
        let observer = Arc::new(
            SafetyObserver::open(
                pin.clone(),
                authority.clone(),
                cache.clone(),
                Duration::from_secs(30),
            )
            .expect("open durable observer"),
        );
        assert_eq!(
            observer.refresh().await,
            Err(SafetyAuthorityError::MissingAuthority)
        );
        let state = runtime_state(cache.clone());
        assert_eq!(
            readiness(State(state.clone())).await,
            StatusCode::SERVICE_UNAVAILABLE
        );
        let shutdown = CancellationToken::new();
        let task = tokio::spawn(run_safety_observer(observer.clone(), shutdown.clone()));
        authority
            .initialize(
                SafetyInitializeRequest::new(
                    SafetyActorIdentity::new(TenantId::new(), "operator").expect("actor"),
                    *SessionId::new().as_uuid(),
                    "bootstrap runtime safety",
                )
                .expect("initialize command"),
            )
            .await
            .expect("explicit initialization");
        tokio::time::timeout(Duration::from_secs(3), async {
            while cache.generation().is_err() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("observer independently sees initialization");
        assert_eq!(readiness(State(state)).await, StatusCode::NO_CONTENT);
        assert!(pin.is_file());
        assert_eq!(
            observer
                .last_accepted()
                .expect("pin")
                .expect("accepted")
                .version(),
            0
        );
        shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("observer shutdown is prompt")
            .expect("observer task joins");
    }

    #[test]
    fn static_data_listener_configuration_is_not_part_of_the_daemon_contract() {
        let source = include_str!("main.rs");
        let forbidden = [
            ["EGRESS_DATA_", "LISTENERS"].concat(),
            ["DataListener", "Config"].concat(),
            ["VerifiedRoute", "Source"].concat(),
        ];
        assert!(forbidden.iter().all(|name| !source.contains(name)));
    }

    #[test]
    fn credentials_are_distinct_and_worker_fenced() {
        assert!(
            ControlCredentials::new(
                &"s".repeat(32),
                &"s".repeat(32),
                WorkerId::new("worker-a").expect("worker ID"),
                1,
            )
            .is_err()
        );
        assert!(
            ControlCredentials::new(
                &"s".repeat(32),
                &"w".repeat(32),
                WorkerId::new("worker-a").expect("worker ID"),
                0,
            )
            .is_err()
        );
    }

    #[test]
    fn digest_parser_requires_exact_nonempty_sha256_width() {
        assert!(parse_digest(&"ab".repeat(32)).is_ok());
        assert!(parse_digest(&"ab".repeat(31)).is_err());
        assert!(parse_digest("not-hex").is_err());
    }

    #[test]
    fn socket_path_rejects_relative_traversal_and_existing_targets() {
        assert!(validate_socket_path(Path::new("relative.sock")).is_err());
        assert!(validate_socket_path(Path::new("/tmp/../tmp/egress.sock")).is_err());
        assert!(validate_socket_path(Path::new("/dev/null")).is_err());
    }

    #[test]
    fn every_attachment_state_has_a_stable_wire_name() {
        let names = [
            AttachmentState::Absent,
            AttachmentState::Prepared,
            AttachmentState::Installing,
            AttachmentState::Active,
            AttachmentState::Revoking,
            AttachmentState::Revoked,
            AttachmentState::Drained,
            AttachmentState::Cancelled,
            AttachmentState::Released,
        ]
        .map(attachment_state_name)
        .into_iter()
        .collect::<HashSet<_>>();
        assert_eq!(names.len(), 9);
    }

    #[test]
    fn router_exposes_the_worker_fenced_route_renewal_endpoint() {
        let source = include_str!("main.rs");
        assert!(source.contains(".route(\"/v1/routes/renew\", post(renew_route))"));
        assert!(source.contains("authorize_worker(&headers, &request.egress_fence)"));
    }
    #[test]
    fn history_exhaustion_is_distinct_from_active_admission_exhaustion() {
        let active = ApiError::from(DaemonControlError::PlanCapacityExceeded);
        let history = ApiError::from(DaemonControlError::PlanHistoryCapacityExceeded);
        assert_eq!(active.status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(history.status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(active.body.code, "route_capacity_exceeded");
        assert_eq!(history.body.code, "route_history_capacity_exceeded");
    }

    #[test]
    fn coordinated_owner_credentials_reject_old_prepare_specs_and_old_supervisor_tokens() {
        let fence = runtime_fence();
        let owner = fence.shard().owner();
        let original = ControlCredentials::new(
            &"s".repeat(32),
            &"w".repeat(32),
            owner.worker_id().clone(),
            owner.worker_epoch().get(),
        )
        .expect("old authority");
        let worker = worker_headers();
        let mut supervisor = HeaderMap::new();
        supervisor.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {}", "s".repeat(32))
                .parse()
                .expect("old supervisor header"),
        );
        assert!(original.authorize_prepare(&worker, &fence, false).is_ok());
        assert!(
            original
                .authorize_prepare(&supervisor, &fence, true)
                .is_ok()
        );
        let coordinated = ControlCredentials::new(
            &"n".repeat(32),
            &"m".repeat(32),
            owner.worker_id().clone(),
            owner.worker_epoch().get() + 1,
        )
        .expect("new authority");
        assert!(
            coordinated
                .authorize_prepare(&worker, &fence, false)
                .is_err()
        );
        assert!(
            coordinated
                .authorize_prepare(&supervisor, &fence, true)
                .is_err()
        );
        let mut fresh_worker = HeaderMap::new();
        fresh_worker.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {}", "m".repeat(32))
                .parse()
                .expect("new worker header"),
        );
        assert!(
            coordinated
                .authorize_prepare(&fresh_worker, &fence, false)
                .is_err(),
            "a current worker credential cannot replay its retired ownership fence"
        );
        // Supervisor preparation trusts that authority's complete inventory.
        // The coordinated drain must retire its old specs as well as credentials.
    }

    #[test]
    fn shared_route_preparation_requires_supervisor_capability_and_legacy_remains_worker_fenced() {
        use browserd_core::{
            LaunchGeneration, OwnerFence, RouteGeneration, SessionId, SessionIncarnation,
            ShardFence, ShardId, WorkerEpoch,
        };
        let worker = WorkerId::new("shared-auth").expect("worker");
        let credentials =
            ControlCredentials::new(&"s".repeat(32), &"w".repeat(32), worker.clone(), 7)
                .expect("credentials");
        let fence = EgressFence::new(
            ShardFence::new(
                OwnerFence::new(worker, WorkerEpoch::new(7).expect("epoch")),
                ShardId::new(),
                LaunchGeneration::new(1).expect("launch"),
            ),
            RouteGeneration::new(1).expect("route"),
            SessionId::new(),
            SessionIncarnation::new(1).expect("incarnation"),
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {}", "w".repeat(32))
                .parse()
                .expect("header"),
        );
        assert!(
            credentials
                .authorize_prepare(&headers, &fence, false)
                .is_ok()
        );
        assert!(
            credentials
                .authorize_prepare(&headers, &fence, true)
                .is_err()
        );
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {}", "s".repeat(32))
                .parse()
                .expect("header"),
        );
        assert!(
            credentials
                .authorize_prepare(&headers, &fence, true)
                .is_ok()
        );
        assert!(
            credentials
                .authorize_prepare(&headers, &fence, false)
                .is_err()
        );
    }
}
