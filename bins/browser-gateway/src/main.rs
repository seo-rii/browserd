use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use browser_gateway::config::GatewayProcessConfig;
use browser_gateway::{
    DependencyHealthGate, GatewayAuthenticator, GatewayReadiness, GatewayViewer,
    GatewayWorkerPlacement, GatewayWorkerRuntime,
};
use browserd_api::{ApiService, DurableApiRouter};
use browserd_coordination::{
    CoordinationActorConfig, CoordinationBlockingClient, EventOutbox, EventOutboxBlockingClient,
    PostgresCreateSessionStore, PostgresEventOutbox, RedisGatewayActionConfig,
    RedisGatewayActionStore, StoreConfig,
};
use browserd_http::{HttpConfig, router};
use browserd_worker::WorkerRpcClient;
use chrono::{Duration as ChronoDuration, Utc};
use tokio_util::sync::CancellationToken;

const WORKER_RPC_MAX_FRAME_BYTES: usize = 1024 * 1024;
const VIEWER_MAX_TTL: Duration = Duration::from_secs(5 * 60);
const VIEWER_MAX_OUTSTANDING_TICKETS: usize = 16_384;
/// How often the gateway probes its dependencies (worker liveness, coordination) and drives an
/// autonomous reconcile pass over pending create operations no client is polling (BRD-014,
/// BRD-016).
const MONITOR_INTERVAL: Duration = Duration::from_secs(15);
/// Maximum create operations reconciled per pass, bounding each pass's work.
const RECONCILE_SCAN_LIMIT: usize = 64;
/// Retention for terminal session-listing entries before the catalog reclaims them (BRD-018),
/// matching the durable retention floor so a recently-closed session stays listable that long.
const SESSION_CATALOG_RETENTION_HOURS: i64 = 24;
/// Consecutive healthy probes required to advertise a dependency ready again after an outage.
const HEALTHY_THRESHOLD: u32 = 2;
/// Consecutive failed probes required to fail a dependency closed, absorbing transient blips.
const UNHEALTHY_THRESHOLD: u32 = 2;
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

    // Durable event outbox (BRD-017, BRD-003): the same Postgres-backed store feeds both the
    // runtime (which records each terminal transition) and the router (which serves ResumeEvents
    // from it), so the at-least-once notification stream is connected to durable transitions and
    // inherits Postgres's commit and failover durability — the durable authority, not a cache.
    let event_outbox = PostgresEventOutbox::connect(
        config.postgres_url(),
        config.postgres_max_connections(),
        store_config,
    )
    .await
    .context("PostgreSQL event outbox connection failed")?;
    event_outbox
        .migrate()
        .await
        .context("PostgreSQL event outbox migration failed")?;
    let event_outbox: Arc<dyn EventOutbox> = Arc::new(event_outbox);
    let outbox_client =
        EventOutboxBlockingClient::spawn(event_outbox, config.coordination_in_flight().max(1))
            .context("event outbox blocking client failed to start")?;

    let placement = GatewayWorkerPlacement::new(
        probe.worker_id,
        config.worker_epoch(),
        config.placement_version(),
        config.placement_version(),
    )?;
    let runtime = Arc::new(
        GatewayWorkerRuntime::with_action_coordination(
            worker_client,
            placement,
            action_store,
            actor_config,
        )?
        .with_terminal_event_outbox(outbox_client.clone()),
    );
    let api = Arc::new(
        DurableApiRouter::with_dispatch_lease_duration(
            Arc::clone(&runtime),
            coordination,
            config.create_lease_duration(),
        )?
        .with_event_outbox(outbox_client),
    );
    let viewer = GatewayViewer::new(
        VIEWER_MAX_TTL,
        config.viewer_origins().iter().cloned(),
        VIEWER_MAX_OUTSTANDING_TICKETS,
    )?;
    let readiness = Arc::new(GatewayReadiness::new());
    readiness.set_worker_ready(true);
    readiness.set_coordination_ready(true);

    // Supervise dependencies and recover stranded work on a fixed interval (BRD-014, BRD-016):
    // probe the worker for liveness and drive a bounded reconcile pass whose success or failure
    // doubles as the coordination-health signal, then update advertised readiness through a
    // hysteresis gate so a dependency that dies after startup is reflected (failing closed on a
    // sustained outage) without flapping on a transient blip. The loop stops when the shutdown
    // token is cancelled, so it never outlives graceful drain.
    let shutdown_token = CancellationToken::new();
    let monitor = {
        let api = Arc::clone(&api);
        let runtime = Arc::clone(&runtime);
        let readiness = Arc::clone(&readiness);
        let shutdown = shutdown_token.clone();
        let worker_probe = worker_rpc.clone();
        let worker_epoch = config.worker_epoch();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(MONITOR_INTERVAL);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            // The first tick fires immediately; skip it so startup isn't perturbed.
            ticker.tick().await;
            let mut worker_gate =
                DependencyHealthGate::new(HEALTHY_THRESHOLD, UNHEALTHY_THRESHOLD, true);
            let mut coordination_gate =
                DependencyHealthGate::new(HEALTHY_THRESHOLD, UNHEALTHY_THRESHOLD, true);
            loop {
                tokio::select! {
                    () = shutdown.cancelled() => break,
                    _ = ticker.tick() => {
                        let worker_healthy = worker_probe.probe(worker_epoch).await.is_ok();
                        readiness.set_worker_ready(worker_gate.record(worker_healthy));

                        let api = Arc::clone(&api);
                        let reconcile = tokio::task::spawn_blocking(move || {
                            api.reconcile_pending(RECONCILE_SCAN_LIMIT)
                        })
                        .await;
                        let coordination_healthy = matches!(reconcile, Ok(Ok(_)));
                        readiness.set_coordination_ready(coordination_gate.record(coordination_healthy));
                        match reconcile {
                            Ok(Ok(_)) => {}
                            Ok(Err(error)) => {
                                eprintln!("browser gateway reconcile pass failed: {error:?}");
                            }
                            Err(_) => eprintln!("browser gateway reconcile task panicked"),
                        }

                        // Reclaim terminal session-listing entries past their retention window so
                        // the catalog stays bounded under churn (BRD-018). Best-effort and off the
                        // async worker, so a large sweep never blocks the reactor.
                        let runtime = Arc::clone(&runtime);
                        if tokio::task::spawn_blocking(move || {
                            runtime.reclaim_retired_sessions(
                                Utc::now(),
                                ChronoDuration::hours(SESSION_CATALOG_RETENTION_HOURS),
                            )
                        })
                        .await
                        .is_err()
                        {
                            eprintln!("browser gateway session reclamation task panicked");
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
    // Stop and drain the monitor loop before returning, so a failed serve does not leak it.
    shutdown_token.cancel();
    let _ = monitor.await;
    served
}
