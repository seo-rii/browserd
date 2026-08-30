use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use browser_gateway::config::GatewayProcessConfig;
use browser_gateway::{
    GatewayAuthenticator, GatewayReadiness, GatewayViewer, GatewayWorkerPlacement,
    GatewayWorkerRuntime,
};
use browserd_api::DurableApiRouter;
use browserd_coordination::{
    CoordinationActorConfig, CoordinationBlockingClient, PostgresCreateSessionStore,
    RedisGatewayActionConfig, RedisGatewayActionStore, StoreConfig,
};
use browserd_http::{HttpConfig, router};
use browserd_worker::WorkerRpcClient;

const WORKER_RPC_MAX_FRAME_BYTES: usize = 1024 * 1024;
const VIEWER_MAX_TTL: Duration = Duration::from_secs(5 * 60);
const VIEWER_MAX_OUTSTANDING_TICKETS: usize = 16_384;
const REDIS_COMMAND_TIMEOUT: Duration = Duration::from_secs(5);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = GatewayProcessConfig::from_lookup(|name| std::env::var(name).ok())?;

    let authenticator = GatewayAuthenticator::from_hmac_parts(
        config.auth_issuer(),
        config.auth_audience(),
        config.auth_key_id(),
        config.auth_hmac_secret(),
        30,
    )?;

    let worker_rpc = WorkerRpcClient::new(
        config.worker_socket(),
        WORKER_RPC_MAX_FRAME_BYTES,
        config.worker_rpc_timeout(),
        Some(config.worker_uid()),
    )?;
    let probe = worker_rpc
        .probe(config.worker_epoch())
        .await
        .context("worker readiness probe failed")?;
    let worker_client = Arc::new(
        worker_rpc
            .blocking_with_limits(config.worker_rpc_queue(), config.worker_rpc_in_flight())?,
    );

    let store_config = StoreConfig::default();
    let create_store = Arc::new(
        PostgresCreateSessionStore::connect(
            config.postgres_url(),
            config.postgres_max_connections(),
            store_config,
        )
        .await
        .context("PostgreSQL coordination connection failed")?,
    );
    create_store
        .migrate()
        .await
        .context("PostgreSQL coordination migration failed")?;
    let actor_config = CoordinationActorConfig::new(
        config.coordination_queue(),
        config.coordination_in_flight(),
        config.coordination_query_timeout(),
        config.coordination_mutation_timeout(),
    )?;
    let coordination = CoordinationBlockingClient::spawn(create_store, actor_config)?;

    let action_config = RedisGatewayActionConfig::new(
        config.redis_url(),
        config.redis_prefix(),
        store_config,
        config.coordination_in_flight(),
        REDIS_COMMAND_TIMEOUT,
    )?;
    let action_store = Arc::new(
        RedisGatewayActionStore::connect(action_config)
            .await
            .context("Redis action coordination connection failed")?,
    );

    let placement = GatewayWorkerPlacement::new(
        probe.worker_id,
        config.worker_epoch(),
        config.placement_version(),
        config.placement_version(),
    )?;
    let runtime = Arc::new(GatewayWorkerRuntime::with_action_coordination(
        worker_client,
        placement,
        action_store,
        actor_config,
    )?);
    let api = DurableApiRouter::with_dispatch_lease_duration(
        runtime,
        coordination,
        config.create_lease_duration(),
    )?;
    let viewer = GatewayViewer::new(
        VIEWER_MAX_TTL,
        config.viewer_origins().iter().cloned(),
        VIEWER_MAX_OUTSTANDING_TICKETS,
    )?;
    let readiness = Arc::new(GatewayReadiness::new());
    readiness.set_worker_ready(true);
    readiness.set_coordination_ready(true);

    let app = router(
        HttpConfig::default(),
        Arc::new(api),
        Arc::new(authenticator),
        Arc::new(viewer),
        readiness,
    );
    let listener = tokio::net::TcpListener::bind(config.bind_address())
        .await
        .context("failed to bind browser gateway")?;
    let shutdown = async {
        if tokio::signal::ctrl_c().await.is_err() {
            std::future::pending::<()>().await;
        }
    };
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
        .context("browser gateway server failed")
}
