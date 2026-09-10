use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use browser_gateway::config::GatewayProcessConfig;
use browser_gateway::{
    GatewayAuthenticator, GatewayReadiness, GatewayViewer, GatewayWorkerPlacement,
    GatewayWorkerRuntime,
};
use browserd_api::{ApiService, DurableApiRouter};
use browserd_coordination::{
    CoordinationActorConfig, CoordinationBlockingClient, PostgresCreateSessionStore,
    RedisGatewayActionConfig, RedisGatewayActionStore, StoreConfig,
};
use browserd_http::{HttpConfig, router};
use browserd_worker::WorkerRpcClient;
use tokio_util::sync::CancellationToken;

const WORKER_RPC_MAX_FRAME_BYTES: usize = 1024 * 1024;
const VIEWER_MAX_TTL: Duration = Duration::from_secs(5 * 60);
const VIEWER_MAX_OUTSTANDING_TICKETS: usize = 16_384;
/// How often the gateway drives an autonomous reconcile pass over pending create operations that
/// no client is polling, so they still terminalize (BRD-016).
const RECONCILE_INTERVAL: Duration = Duration::from_secs(30);
/// Maximum create operations reconciled per pass, bounding each pass's work.
const RECONCILE_SCAN_LIMIT: usize = 64;
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
    let api = Arc::new(DurableApiRouter::with_dispatch_lease_duration(
        runtime,
        coordination,
        config.create_lease_duration(),
    )?);
    let viewer = GatewayViewer::new(
        VIEWER_MAX_TTL,
        config.viewer_origins().iter().cloned(),
        VIEWER_MAX_OUTSTANDING_TICKETS,
    )?;
    let readiness = Arc::new(GatewayReadiness::new());
    readiness.set_worker_ready(true);
    readiness.set_coordination_ready(true);

    // Autonomously recover create operations that no client is polling: on a fixed interval, drive
    // a bounded reconcile pass so pending/creating operations still terminalize (BRD-016). The
    // loop stops when the shutdown token is cancelled, so it never outlives graceful drain.
    let shutdown_token = CancellationToken::new();
    let reconcile = {
        let api = Arc::clone(&api);
        let shutdown = shutdown_token.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(RECONCILE_INTERVAL);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            // The first tick fires immediately; skip it so startup isn't perturbed.
            ticker.tick().await;
            loop {
                tokio::select! {
                    () = shutdown.cancelled() => break,
                    _ = ticker.tick() => {
                        let api = Arc::clone(&api);
                        match tokio::task::spawn_blocking(move || {
                            api.reconcile_pending(RECONCILE_SCAN_LIMIT)
                        })
                        .await
                        {
                            Ok(Ok(_)) => {}
                            Ok(Err(error)) => {
                                eprintln!("browser gateway reconcile pass failed: {error:?}");
                            }
                            Err(_) => eprintln!("browser gateway reconcile task panicked"),
                        }
                    }
                }
            }
        })
    };

    let service: Arc<dyn ApiService> = api.clone();
    let app = router(
        HttpConfig::default(),
        service,
        Arc::new(authenticator),
        Arc::new(viewer),
        readiness,
    );
    let listener = tokio::net::TcpListener::bind(config.bind_address())
        .await
        .context("failed to bind browser gateway")?;
    // Drain gracefully on either an interactive interrupt (SIGINT) or a service manager's SIGTERM
    // (BRD-015); the worker already handles both. On any signal-registration error, wait forever
    // rather than triggering a spurious shutdown. On a real signal, also stop the reconcile loop.
    let shutdown = {
        let shutdown_token = shutdown_token.clone();
        async move {
            let mut sigterm =
                match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                    Ok(sigterm) => sigterm,
                    Err(_) => {
                        std::future::pending::<()>().await;
                        return;
                    }
                };
            tokio::select! {
                result = tokio::signal::ctrl_c() => {
                    if result.is_err() {
                        std::future::pending::<()>().await;
                    }
                }
                signal = sigterm.recv() => {
                    if signal.is_none() {
                        std::future::pending::<()>().await;
                    }
                }
            }
            shutdown_token.cancel();
        }
    };
    let served = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
        .context("browser gateway server failed");
    // Stop and drain the reconcile loop before returning, so a failed serve does not leak it.
    shutdown_token.cancel();
    let _ = reconcile.await;
    served
}
