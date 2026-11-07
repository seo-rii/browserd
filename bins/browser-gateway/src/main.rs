use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use browser_gateway::config::GatewayProcessConfig;
use browser_gateway::{
    DependencyHealthGate, GatewayAuthenticator, GatewayFleetConfig, GatewayReadiness,
    GatewayViewer, GatewayWebhookDelivery, GatewayWorkerPlacement, GatewayWorkerRuntime,
    ReqwestWebhookTransport, action_retention_limits_from_lookup, load_webhook_signing_keys,
};
use browserd_api::{
    ApiService, DurableApiRouter, SafetyApi, WebhookApi, WebhookSigningKeyProvider,
};
use browserd_coordination::{
    CoordinationActorConfig, CoordinationBlockingClient, EventOutbox, EventOutboxBlockingClient,
    PostgresCreateSessionStore, PostgresEventOutbox, PostgresWebhookStore,
    RedisGatewayActionConfig, RedisGatewayActionStore, StoreConfig, WebhookBlockingClient,
    WebhookStoreConfig,
};
use browserd_http::{HttpConfig, router_with_artifacts};
use browserd_worker::WorkerRpcClient;
use chrono::{Duration as ChronoDuration, Utc};
use tokio_util::sync::CancellationToken;

const WORKER_RPC_MAX_FRAME_BYTES: usize = browserd_worker::MAX_WORKER_ACTION_RPC_FRAME_BYTES;
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
    let webhook_key_path =
        std::env::var_os("BROWSERD_WEBHOOK_SIGNING_KEY_FILE").map(std::path::PathBuf::from);
    let webhook_keys = load_webhook_signing_keys(webhook_key_path.as_deref())?;
    let fleet_config = std::env::var_os("BROWSERD_FLEET_GATEWAY_CONFIG_FILE")
        .map(std::path::PathBuf::from)
        .map(|path| GatewayFleetConfig::load(&path))
        .transpose()?;
    let config = GatewayProcessConfig::from_lookup(|name| {
        std::env::var(name).ok().or_else(|| {
            let peer = fleet_config.as_ref()?.peers().first()?;
            match name {
                "BROWSERD_WORKER_SOCKET" => peer.socket_path().to_str().map(str::to_owned),
                "BROWSERD_WORKER_UID" => Some(peer.peer_uid().to_string()),
                "BROWSERD_WORKER_EPOCH" => Some(peer.expected_worker_epoch().to_string()),
                "BROWSERD_PLACEMENT_VERSION" => Some("1".to_owned()),
                "BROWSERD_WORKER_RPC_TIMEOUT_MS" => Some("30000".to_owned()),
                "BROWSERD_CREATE_LEASE_MS" => Some("60000".to_owned()),
                _ => None,
            }
        })
    })?;
    let action_retention_limits =
        action_retention_limits_from_lookup(|name| std::env::var(name).ok())?;

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
    let (initial_worker_id, initially_worker_ready) = if let Some(fleet) = &fleet_config {
        let peer = fleet.peers().first().context("empty fleet inventory")?;
        (peer.worker_id().clone(), false)
    } else {
        let response = worker_rpc
            .exchange(browserd_worker::WorkerRpcRequest::Probe {
                expected_worker_epoch: config.worker_epoch(),
            })
            .await
            .context("worker metadata probe failed")?;
        let browserd_worker::WorkerRpcResponse::Probe(receipt) = response else {
            anyhow::bail!("worker metadata probe returned an unexpected response");
        };
        if receipt.worker_epoch != config.worker_epoch() {
            anyhow::bail!("worker metadata probe returned a mismatched epoch");
        }
        (receipt.worker_id, receipt.ready)
    };
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
    let safety_config = browserd_coordination::RedisSafetyAuthorityConfig::new(
        config.redis_url(),
        config.redis_prefix(),
        browserd_coordination::SafetyAuthorityConfig::default(),
        config.coordination_in_flight(),
        REDIS_COMMAND_TIMEOUT,
    )?;
    let safety_authority = Arc::new(
        browserd_coordination::RedisSafetyAuthority::connect(safety_config)
            .await
            .context("Redis runtime safety authority connection failed")?,
    );
    let safety = browserd_coordination::SafetyAuthorityBlockingClient::spawn(
        safety_authority,
        actor_config,
    )?;
    let coordination = CoordinationBlockingClient::spawn(create_store, actor_config)?;

    let mut action_config = RedisGatewayActionConfig::new(
        config.redis_url(),
        config.redis_prefix(),
        store_config,
        config.coordination_in_flight(),
        REDIS_COMMAND_TIMEOUT,
    )?
    .with_retention_limits(action_retention_limits);
    if let Some(fleet) = &fleet_config {
        action_config = action_config.with_fleet_admission(fleet.admission().clone());
    }
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
    let webhooks = if let Some(keys) = webhook_keys {
        let store = PostgresWebhookStore::new(event_outbox.clone(), WebhookStoreConfig::default())?;
        store
            .migrate()
            .await
            .context("PostgreSQL webhook migration failed")?;
        let client = WebhookBlockingClient::spawn(Arc::new(store), actor_config)?;
        let keys: Arc<dyn WebhookSigningKeyProvider> = keys;
        Some((
            WebhookApi::new(client.clone(), Arc::clone(&keys)),
            GatewayWebhookDelivery::new(client, keys, Arc::new(ReqwestWebhookTransport::new())),
        ))
    } else {
        None
    };
    let event_outbox: Arc<dyn EventOutbox> = Arc::new(event_outbox);
    let outbox_client =
        EventOutboxBlockingClient::spawn(event_outbox, config.coordination_in_flight().max(1))
            .context("event outbox blocking client failed to start")?;

    let placement = GatewayWorkerPlacement::new(
        initial_worker_id,
        config.worker_epoch(),
        config.placement_version(),
        config.placement_version(),
    )?;
    let viewer = GatewayViewer::new(
        VIEWER_MAX_TTL,
        config.viewer_origins().iter().cloned(),
        VIEWER_MAX_OUTSTANDING_TICKETS,
    )?;
    let viewer = Arc::new(if fleet_config.is_none() {
        viewer.with_worker_client(Arc::clone(&worker_client))
    } else {
        viewer
    });
    let mut runtime = GatewayWorkerRuntime::with_action_coordination(
        worker_client,
        placement,
        action_store,
        actor_config,
    )?
    .with_durable_session_directory()
    .with_runtime_safety(safety.clone())
    .with_terminal_event_outbox(outbox_client.clone())
    .with_viewer(Arc::clone(&viewer));
    if let Some(fleet) = &fleet_config {
        let mut clients = Vec::with_capacity(fleet.peers().len());
        for peer in fleet.peers() {
            clients.push(Arc::new(
                WorkerRpcClient::new(
                    peer.socket_path(),
                    WORKER_RPC_MAX_FRAME_BYTES,
                    config.worker_rpc_timeout(),
                    Some(peer.peer_uid()),
                )?
                .blocking_with_limits(config.worker_rpc_queue(), config.worker_rpc_in_flight())?,
            ));
        }
        runtime = runtime.with_fleet(fleet.inventory(clients)?, coordination.clone());
    }
    let runtime = Arc::new(runtime);
    let recovery_runtime = Arc::clone(&runtime);
    let managed_fleet = fleet_config.is_some();
    tokio::task::spawn_blocking(move || {
        recovery_runtime.reconcile_pending_actions(RECONCILE_SCAN_LIMIT)?;
        recovery_runtime.reconcile_terminal_events(RECONCILE_SCAN_LIMIT)?;
        let controls =
            recovery_runtime.reconcile_viewer_control_events(RECONCILE_SCAN_LIMIT.min(128));
        if managed_fleet { Ok(0usize) } else { controls }
    })
    .await
    .context("initial event recovery task failed")?
    .context("initial durable event recovery failed")?;
    let mut api = DurableApiRouter::with_dispatch_lease_duration(
        Arc::clone(&runtime),
        coordination.clone(),
        config.create_lease_duration(),
    )?
    .with_event_outbox(outbox_client)
    .with_safety(SafetyApi::new(safety));
    if let Some((webhook_api, _)) = &webhooks {
        api = api.with_webhooks(webhook_api.clone());
    }
    let api = Arc::new(api);
    let readiness = Arc::new(GatewayReadiness::new());
    readiness.set_worker_ready(initially_worker_ready);
    readiness.set_coordination_ready(true);

    // Supervise dependencies and recover stranded work on a fixed interval (BRD-014, BRD-016):
    // probe the worker for liveness and drive a bounded reconcile pass whose success or failure
    // doubles as the coordination-health signal, then update advertised readiness through a
    // hysteresis gate so a dependency that dies after startup is reflected (failing closed on a
    // sustained outage) without flapping on a transient blip. The loop stops when the shutdown
    // token is cancelled, so it never outlives graceful drain.
    let shutdown_token = CancellationToken::new();
    let webhook_monitor =
        webhooks.map(|(_, sender)| tokio::spawn(sender.run(shutdown_token.clone())));
    let notification_monitor = {
        let runtime = Arc::clone(&runtime);
        let shutdown = shutdown_token.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(1));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {biased;()=shutdown.cancelled()=>break,_=ticker.tick()=>{}}
                let runtime = Arc::clone(&runtime);
                let pass =
                    tokio::task::spawn_blocking(move || runtime.reconcile_worker_notifications(16));
                tokio::select! {biased;()=shutdown.cancelled()=>break,result=pass=>{
                    if !matches!(result,Ok(Ok(_))) {eprintln!("browser gateway worker notification recovery remains pending");}
                }}
            }
        })
    };
    // Lease maintenance is separate from slow worker discovery/outbox work. A started pass
    // retains its runtime through cancellation; Skip plus awaiting the pass prevents overlap.
    let fleet_monitor = {
        let runtime = Arc::clone(&runtime);
        let shutdown = shutdown_token.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(3));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {biased;()=shutdown.cancelled()=>break,_=ticker.tick()=>{}}
                let runtime = Arc::clone(&runtime);
                let pass = tokio::task::spawn_blocking(move || runtime.maintain_fleet_leases(16));
                tokio::select! {biased;()=shutdown.cancelled()=>break,result=pass=>{
                    if !matches!(result,Ok(Ok(_))){eprintln!("browser gateway fleet lease maintenance remains pending");}
                }}
            }
        })
    };
    let fleet_observer = {
        let runtime = Arc::clone(&runtime);
        let shutdown = shutdown_token.clone();
        let readiness = Arc::clone(&readiness);
        let enabled = fleet_config.is_some();
        tokio::spawn(async move {
            if !enabled {
                return;
            }
            let mut ticker = tokio::time::interval(Duration::from_secs(2));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {biased;()=shutdown.cancelled()=>break,_=ticker.tick()=>{}}
                let runtime = Arc::clone(&runtime);
                let pass = tokio::task::spawn_blocking(move || runtime.refresh_fleet_workers(32));
                tokio::select! {biased;()=shutdown.cancelled()=>break,result=pass=>{readiness.set_worker_ready(matches!(result,Ok(Ok(count)) if count>0));}}
            }
        })
    };
    // Run immediately at startup and independently of readiness/outbox delivery thereafter.
    // A started blocking RPC retains the runtime if shutdown detaches it; no overlapping
    // pass is started, and the durable obligation survives any unsuccessful response.
    let custody_catchup_monitor = {
        let runtime = Arc::clone(&runtime);
        let shutdown = shutdown_token.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(MONITOR_INTERVAL);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    biased;
                    () = shutdown.cancelled() => break,
                    _ = ticker.tick() => {}
                }
                let runtime = Arc::clone(&runtime);
                let pass = tokio::task::spawn_blocking(move || {
                    runtime.reconcile_terminal_custody_catchup(16)
                });
                tokio::select! {
                    biased;
                    () = shutdown.cancelled() => break,
                    result = pass => match result {
                        Ok(Ok(_)) => {},
                        Ok(Err(_)) => eprintln!("browser gateway terminal custody catch-up remains pending"),
                        Err(_) => eprintln!("browser gateway terminal custody catch-up task panicked"),
                    }
                }
            }
        })
    };
    let custody_monitor = {
        let runtime = Arc::clone(&runtime);
        let shutdown = shutdown_token.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(MONITOR_INTERVAL);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    biased;
                    () = shutdown.cancelled() => break,
                    _ = ticker.tick() => {}
                }
                let runtime = Arc::clone(&runtime);
                let pass =
                    tokio::task::spawn_blocking(move || runtime.reconcile_terminal_custody(16));
                tokio::select! {
                    biased;
                    () = shutdown.cancelled() => break,
                    result = pass => match result {
                        Ok(Ok(_)) => {},
                        Ok(Err(_)) => eprintln!("browser gateway terminal custody remains pending"),
                        Err(_) => eprintln!("browser gateway terminal custody task panicked"),
                    }
                }
            }
        })
    };
    // Reclaim durable action records independently of worker health and source delivery.
    // A started store call owns its runtime through cancellation; future ticks cannot overlap.
    let retention_monitor = {
        let runtime = Arc::clone(&runtime);
        let shutdown = shutdown_token.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(MONITOR_INTERVAL);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    biased;
                    () = shutdown.cancelled() => break,
                    _ = ticker.tick() => {}
                }
                let runtime = Arc::clone(&runtime);
                let pass =
                    tokio::task::spawn_blocking(move || runtime.maintain_action_retention(32));
                tokio::select! {
                    biased;
                    () = shutdown.cancelled() => break,
                    result = pass => match result {
                        Ok(Ok(_)) => {},
                        Ok(Err(_)) => eprintln!("browser gateway action retention remains pending"),
                        Err(_) => eprintln!("browser gateway action retention task panicked"),
                    }
                }
            }
        })
    };
    // Expired terminal creates have their own indexed, 32-candidate store pass. Pending creates
    // and their outbox recovery run independently; the store retains ownership through timeouts.
    let create_retention_monitor = {
        let shutdown = shutdown_token.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(MONITOR_INTERVAL);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! { biased; ()=shutdown.cancelled()=>break, _=ticker.tick()=>{} }
                let coordination = coordination.clone();
                let pass =
                    tokio::task::spawn_blocking(move || coordination.purge_expired(Utc::now()));
                tokio::select! { biased; ()=shutdown.cancelled()=>break, result=pass=>match result {
                    Ok(Ok(_))=>{},
                    Ok(Err(_))=>eprintln!("browser gateway create-operation retention remains pending"),
                    Err(_)=>eprintln!("browser gateway create-operation retention task panicked"),
                } }
            }
        })
    };
    let monitor = {
        let api = Arc::clone(&api);
        let runtime = Arc::clone(&runtime);
        let readiness = Arc::clone(&readiness);
        let shutdown = shutdown_token.clone();
        let worker_probe = worker_rpc.clone();
        let worker_epoch = config.worker_epoch();
        let fleet_enabled = fleet_config.is_some();
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
                        if !fleet_enabled {
                            let worker_healthy = worker_probe.probe(worker_epoch).await.is_ok();
                            readiness.set_worker_ready(worker_gate.record(worker_healthy));
                        }

                        let api = Arc::clone(&api);
                        let reconcile = tokio::task::spawn_blocking(move || {
                            api.reconcile_pending(RECONCILE_SCAN_LIMIT)
                        })
                        .await;
                        let event_runtime = Arc::clone(&runtime);
                        let events = tokio::task::spawn_blocking(move || {
                            event_runtime.reconcile_pending_actions(RECONCILE_SCAN_LIMIT)?;
                            event_runtime.reconcile_terminal_events(RECONCILE_SCAN_LIMIT)?;
                            event_runtime.reconcile_viewer_control_events(RECONCILE_SCAN_LIMIT.min(128))
                        })
                        .await;
                        let coordination_healthy = matches!(reconcile, Ok(Ok(_)))
                            && matches!(events, Ok(Ok(_)));
                        readiness.set_coordination_ready(coordination_gate.record(coordination_healthy));
                        match reconcile {
                            Ok(Ok(_)) => {}
                            Ok(Err(error)) => {
                                eprintln!("browser gateway reconcile pass failed: {error:?}");
                            }
                            Err(_) => eprintln!("browser gateway reconcile task panicked"),
                        }
                        match events {
                            Ok(Ok(_)) => {}
                            Ok(Err(error)) => eprintln!("browser gateway event recovery failed: {error:?}"),
                            Err(_) => eprintln!("browser gateway event recovery task panicked"),
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
    let app = router_with_artifacts(
        HttpConfig::new(1_048_576)?,
        service,
        Arc::new(authenticator),
        viewer,
        readiness,
        Some(runtime.clone()),
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
    let _ = notification_monitor.await;
    let _ = custody_catchup_monitor.await;
    let _ = custody_monitor.await;
    let _ = retention_monitor.await;
    let _ = create_retention_monitor.await;
    let _ = fleet_monitor.await;
    let _ = fleet_observer.await;
    if let Some(monitor) = webhook_monitor {
        let _ = monitor.await;
    }
    served
}
