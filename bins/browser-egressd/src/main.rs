use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, bail};
use axum::extract::{DefaultBodyLimit, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::routing::{get, post};
use axum::{Json, Router};
use browserd_core::{SessionId, ShardId, TenantId};
use browserd_egress::{
    DataPlane, DataPlaneLimits, EgressPolicy, MonotonicMillis, QuotaLimits, RouteBinding,
    RouteEndpoint, RouteRegistry, TcpConnector, TokioResolver, VerifiedRouteSource,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
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

#[derive(Clone)]
struct ControlToken {
    digest: [u8; 32],
}

impl ControlToken {
    fn new(secret: &str) -> anyhow::Result<Self> {
        if secret.len() < 32
            || secret.len() > 4 * 1024
            || secret.trim() != secret
            || secret.chars().any(char::is_control)
        {
            bail!("control token must contain 32 to 4096 non-control bytes");
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
    token: ControlToken,
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

impl ControlState {
    fn now(&self) -> MonotonicMillis {
        MonotonicMillis::new(u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX))
    }
}

#[derive(Deserialize)]
struct BindRequest {
    endpoint: u64,
    tenant_id: TenantId,
    session_id: SessionId,
    source_shard: ShardId,
    worker_epoch: u64,
    lease_millis: u64,
}

#[derive(Deserialize)]
struct LeaseRequest {
    endpoint: u64,
    source_shard: ShardId,
    worker_epoch: u64,
    lease_millis: u64,
}

#[derive(Deserialize)]
struct RevokeRequest {
    endpoint: u64,
    source_shard: ShardId,
    worker_epoch: u64,
}

#[derive(Deserialize)]
struct RouteStatusRequest {
    endpoint: u64,
    source_shard: ShardId,
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
    require_control(&headers, &state.token)
        .map_err(|status| (status, "control authorization failed".to_owned()))?;
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
        .map_err(|error| (StatusCode::CONFLICT, format!("{error:?}")))?;
    Ok(StatusCode::CREATED)
}

async fn renew_route(
    State(state): State<ControlState>,
    headers: HeaderMap,
    Json(request): Json<LeaseRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    require_control(&headers, &state.token)
        .map_err(|status| (status, "control authorization failed".to_owned()))?;
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
        .map_err(|error| (StatusCode::CONFLICT, format!("{error:?}")))?;
    Ok(StatusCode::NO_CONTENT)
}

async fn revoke_route(
    State(state): State<ControlState>,
    headers: HeaderMap,
    Json(request): Json<RevokeRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    require_control(&headers, &state.token)
        .map_err(|status| (status, "control authorization failed".to_owned()))?;
    let endpoint = RouteEndpoint::new(request.endpoint)
        .map_err(|error| (StatusCode::BAD_REQUEST, format!("{error:?}")))?;
    state
        .registry
        .revoke(endpoint, &request.source_shard, request.worker_epoch)
        .map_err(|error| (StatusCode::CONFLICT, format!("{error:?}")))?;
    Ok(StatusCode::NO_CONTENT)
}

async fn route_status(
    State(state): State<ControlState>,
    headers: HeaderMap,
    Query(request): Query<RouteStatusRequest>,
) -> Result<Json<RouteStatusResponse>, (StatusCode, String)> {
    require_control(&headers, &state.token)
        .map_err(|status| (status, "control authorization failed".to_owned()))?;
    let endpoint = RouteEndpoint::new(request.endpoint)
        .map_err(|error| (StatusCode::BAD_REQUEST, format!("{error:?}")))?;
    let identity = state
        .registry
        .binding(endpoint, &request.source_shard, state.now())
        .map_err(|error| (StatusCode::NOT_FOUND, format!("{error:?}")))?;
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
    let token = ControlToken::new(
        &std::env::var("BROWSER_EGRESS_CONTROL_TOKEN")
            .context("BROWSER_EGRESS_CONTROL_TOKEN must be explicitly configured")?,
    )?;
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
        token,
    };
    let app = Router::new()
        .route("/healthz", get(health))
        .route("/readyz", get(readiness))
        .route("/v1/routes/bind", post(bind_route))
        .route("/v1/routes/renew", post(renew_route))
        .route("/v1/routes/revoke", post(revoke_route))
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

    tokio::signal::ctrl_c()
        .await
        .context("failed to install shutdown signal")?;
    ready.store(false, Ordering::Release);
    registry.expire_routes(MonotonicMillis::new(u64::MAX));
    shutdown.cancel();
    while let Some(result) = tasks.join_next().await {
        result.context("egress daemon task panicked")??;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    use std::time::{Duration, Instant};

    use super::{
        ControlState, ControlToken, DaemonConfig, RouteStatusRequest, require_control, route_status,
    };
    use axum::Json;
    use axum::extract::{Query, State};
    use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
    use browserd_core::{SessionId, ShardId, TenantId};
    use browserd_egress::{
        EgressPolicy, MonotonicMillis, QuotaLimits, RouteBinding, RouteEndpoint, RouteRegistry,
    };

    #[test]
    fn control_plane_is_loopback_only_and_data_listeners_are_explicit() {
        let shard = ShardId::new();
        assert!(DaemonConfig::from_parts("0.0.0.0:9901", "", 128).is_err());
        assert!(DaemonConfig::from_parts("127.0.0.1:9901", "", 128).is_err());
        assert!(DaemonConfig::from_parts("127.0.0.1:9901", "ignored", 0).is_err());
        let config =
            DaemonConfig::from_parts("127.0.0.1:9901", &format!("71@0.0.0.0:3128@{shard}"), 128);
        assert!(config.is_ok());
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
        let token = ControlToken::new(&"c".repeat(32)).expect("token is strong enough");
        let state = ControlState {
            registry,
            listeners: Arc::new(HashMap::from([(endpoint, shard.clone())])),
            started: Instant::now(),
            ready: Arc::new(AtomicBool::new(true)),
            token,
        };
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer cccccccccccccccccccccccccccccccc"),
        );

        let active = route_status(
            State(state.clone()),
            headers.clone(),
            Query(RouteStatusRequest {
                endpoint: 71,
                source_shard: shard.clone(),
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
                worker_epoch: 6,
            }),
        )
        .await;
        assert!(matches!(stale, Err((StatusCode::CONFLICT, _))));
    }
}
