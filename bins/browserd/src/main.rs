mod development_runtime;

use std::env;
use std::future::IntoFuture;
use std::net::SocketAddr;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use browser_gateway::{
    GatewayAuthenticator, GatewayReadiness, GatewayViewer, GatewayWorkerPlacement,
    GatewayWorkerRuntime,
};
use browser_worker::{LifecycleBounds, ProductionWorkerRuntime, SessionShardRouter};
use browserd_api::DurableApiRouter;
use browserd_coordination::{
    CoordinationActorConfig, CoordinationBlockingClient, MemoryCoordinationDatabase,
    MemoryCreateSessionStore, MemoryGatewayActionStore, StoreConfig,
};
use browserd_core::WorkerId;
use browserd_http::{HttpConfig, router};
use browserd_session::{LeasePolicy, SessionTimeoutPolicy};
use browserd_worker::{
    ActionJournalConfig, AuthenticatedPeer, DurableWorkerEpoch, InternalEndpoint, WorkerConfig,
    WorkerControlPlane, WorkerRpcClient, WorkerRpcConfig,
};
use development_runtime::{DevelopmentShardFactory, RejectDevelopmentArtifacts};
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if env::var("BROWSERD_ALL_IN_ONE_DEV").as_deref() != Ok("true") {
        bail!("BROWSERD_ALL_IN_ONE_DEV=true is required");
    }
    let bind_address = env::var("BROWSERD_BIND")
        .context("BROWSERD_BIND is required")?
        .parse::<SocketAddr>()
        .context("BROWSERD_BIND is invalid")?;
    if !bind_address.ip().is_loopback() || bind_address.port() == 0 {
        bail!("all-in-one bind must be loopback with a nonzero port");
    }
    let runtime_directory = env::var_os("BROWSERD_RUNTIME_DIR")
        .map(PathBuf::from)
        .context("BROWSERD_RUNTIME_DIR is required")?;
    if !runtime_directory.is_absolute() {
        bail!("runtime directory must be absolute");
    }
    let runtime_metadata = std::fs::symlink_metadata(&runtime_directory)
        .context("runtime directory is unavailable")?;
    let current_uid = std::fs::metadata("/proc/self")
        .context("current process identity is unavailable")?
        .uid();
    if !runtime_metadata.is_dir()
        || runtime_metadata.file_type().is_symlink()
        || runtime_metadata.uid() != current_uid
        || runtime_metadata.permissions().mode() & 0o077 != 0
    {
        bail!("runtime directory must be an owned private real directory");
    }
    let runtime_directory = runtime_directory
        .canonicalize()
        .context("runtime directory cannot be resolved")?;

    let worker_id =
        WorkerId::new(env::var("BROWSERD_WORKER_ID").context("BROWSERD_WORKER_ID is required")?)
            .map_err(|_| anyhow!("BROWSERD_WORKER_ID is invalid"))?;
    let worker_epoch_path = env::var_os("BROWSERD_WORKER_EPOCH_FILE")
        .map(PathBuf::from)
        .context("BROWSERD_WORKER_EPOCH_FILE is required")?;
    if !worker_epoch_path.is_absolute()
        || worker_epoch_path
            .parent()
            .and_then(|parent| parent.canonicalize().ok())
            .as_ref()
            != Some(&runtime_directory)
    {
        bail!("worker epoch file must be inside the runtime directory");
    }
    let worker_socket = env::var_os("BROWSERD_WORKER_SOCKET")
        .map(PathBuf::from)
        .context("BROWSERD_WORKER_SOCKET is required")?;
    if !worker_socket.is_absolute()
        || worker_socket
            .parent()
            .and_then(|parent| parent.canonicalize().ok())
            .as_ref()
            != Some(&runtime_directory)
    {
        bail!("worker socket must be inside the runtime directory");
    }
    let expected_endpoint = format!("unix:{}", worker_socket.display());
    if env::var("BROWSERD_INTERNAL_ENDPOINT").as_deref() != Ok(expected_endpoint.as_str()) {
        bail!("BROWSERD_INTERNAL_ENDPOINT must match BROWSERD_WORKER_SOCKET");
    }
    let trusted_peer = AuthenticatedPeer::new(
        env::var("BROWSERD_INTERNAL_PEER").context("BROWSERD_INTERNAL_PEER is required")?,
    )
    .map_err(|_| anyhow!("BROWSERD_INTERNAL_PEER is invalid"))?;
    let configured_uid = env::var("BROWSERD_WORKER_UID")
        .context("BROWSERD_WORKER_UID is required")?
        .parse::<u32>()
        .context("BROWSERD_WORKER_UID is invalid")?;
    if configured_uid != current_uid {
        bail!("BROWSERD_WORKER_UID does not match the process uid");
    }
    let expected_worker_epoch = env::var("BROWSERD_WORKER_EPOCH")
        .context("BROWSERD_WORKER_EPOCH is required")?
        .parse::<u64>()
        .context("BROWSERD_WORKER_EPOCH is invalid")?;
    if expected_worker_epoch == 0 {
        bail!("BROWSERD_WORKER_EPOCH must be nonzero");
    }
    let placement_version = env::var("BROWSERD_PLACEMENT_VERSION")
        .context("BROWSERD_PLACEMENT_VERSION is required")?
        .parse::<u64>()
        .context("BROWSERD_PLACEMENT_VERSION is invalid")?;
    if placement_version == 0 {
        bail!("BROWSERD_PLACEMENT_VERSION must be nonzero");
    }
    if env::var("BROWSERD_COORDINATION_MODE").as_deref() != Ok("memory") {
        bail!("all-in-one coordination mode must be memory");
    }
    let action_journal_directory = env::var_os("BROWSERD_ACTION_JOURNAL_DIR")
        .map(PathBuf::from)
        .context("BROWSERD_ACTION_JOURNAL_DIR is required")?;
    if !action_journal_directory.is_absolute()
        || !action_journal_directory
            .canonicalize()
            .is_ok_and(|path| path.starts_with(&runtime_directory))
    {
        bail!("action journal directory must be inside the runtime directory");
    }
    let action_journal = ActionJournalConfig::with_default_limits(action_journal_directory)
        .map_err(|error| anyhow!("action journal is unavailable: {error:?}"))?;

    let auth_issuer =
        env::var("BROWSERD_AUTH_ISSUER").context("BROWSERD_AUTH_ISSUER is required")?;
    let auth_audience =
        env::var("BROWSERD_AUTH_AUDIENCE").context("BROWSERD_AUTH_AUDIENCE is required")?;
    let auth_key_id =
        env::var("BROWSERD_AUTH_KEY_ID").context("BROWSERD_AUTH_KEY_ID is required")?;
    let auth_secret =
        env::var("BROWSERD_AUTH_HMAC_SECRET").context("BROWSERD_AUTH_HMAC_SECRET is required")?;
    let viewer_origins = env::var("BROWSERD_VIEWER_ORIGINS")
        .context("BROWSERD_VIEWER_ORIGINS is required")?
        .split(',')
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if viewer_origins.is_empty() || viewer_origins.iter().any(|origin| origin.is_empty()) {
        bail!("BROWSERD_VIEWER_ORIGINS is invalid");
    }

    let worker_epoch = DurableWorkerEpoch::increment(&worker_epoch_path)
        .map_err(|error| anyhow!("durable worker epoch unavailable: {error:?}"))?;
    if worker_epoch != expected_worker_epoch {
        bail!("durable worker epoch does not match BROWSERD_WORKER_EPOCH");
    }
    let max_sessions = 128;
    let factory = Arc::new(DevelopmentShardFactory {
        worker_id: worker_id.clone(),
        worker_epoch,
    });
    let shard_router = Arc::new(
        SessionShardRouter::new(
            worker_id.clone(),
            worker_epoch,
            factory,
            Arc::new(RejectDevelopmentArtifacts),
            max_sessions,
        )
        .map_err(|error| anyhow!("development shard router is invalid: {error:?}"))?,
    );
    let internal_endpoint = InternalEndpoint::unix(&worker_socket)
        .map_err(|error| anyhow!("worker endpoint is invalid: {error:?}"))?;
    let lease_policy = LeasePolicy::new(Duration::from_secs(15), Duration::from_secs(3))
        .map_err(|error| anyhow!("ownership lease policy is invalid: {error:?}"))?;
    let timeout_policy =
        SessionTimeoutPolicy::new(Duration::from_secs(30 * 60), Duration::from_secs(10 * 60))
            .map_err(|error| anyhow!("session timeout policy is invalid: {error:?}"))?;
    let worker_config = WorkerConfig::new(
        worker_id.clone(),
        worker_epoch,
        internal_endpoint,
        trusted_peer.clone(),
        max_sessions,
        128,
        lease_policy,
        timeout_policy,
        Duration::from_secs(5 * 60),
        action_journal,
    )
    .map_err(|error| anyhow!("worker configuration is invalid: {error:?}"))?;
    let worker = Arc::new(WorkerControlPlane::new(
        worker_config,
        Arc::clone(&shard_router),
        Arc::clone(&shard_router),
    ));
    let rpc_config = WorkerRpcConfig::new(
        &worker_socket,
        1024 * 1024,
        128,
        Duration::from_secs(5),
        Some(current_uid),
    )?;
    let lifecycle_bounds = LifecycleBounds::new(
        Duration::from_secs(3),
        Duration::from_secs(3),
        Duration::from_secs(15),
        Duration::from_secs(5),
    )
    .map_err(|error| anyhow!("worker lifecycle bounds are invalid: {error:?}"))?;
    let worker_runtime =
        ProductionWorkerRuntime::new(worker, trusted_peer, rpc_config, lifecycle_bounds)?;
    let worker_shutdown = CancellationToken::new();
    let runtime_shutdown = worker_shutdown.clone();
    let mut worker_task = tokio::spawn(async move { worker_runtime.serve(runtime_shutdown).await });

    let worker_rpc = WorkerRpcClient::new(
        &worker_socket,
        1024 * 1024,
        Duration::from_secs(5),
        Some(current_uid),
    )?;
    let probe = match tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(probe) = worker_rpc.probe(worker_epoch).await {
                break probe;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    {
        Ok(probe) => probe,
        Err(_) => {
            worker_shutdown.cancel();
            let _ = worker_task.await;
            bail!("local worker readiness probe timed out");
        }
    };
    if probe.worker_id != worker_id || probe.worker_epoch != worker_epoch || !probe.ready {
        worker_shutdown.cancel();
        let _ = worker_task.await;
        bail!("local worker readiness identity mismatch");
    }

    let database = MemoryCoordinationDatabase::default();
    let store_config = StoreConfig::default();
    let actor_config = CoordinationActorConfig::default();
    let coordination = CoordinationBlockingClient::spawn(
        Arc::new(MemoryCreateSessionStore::attach(
            database.clone(),
            store_config,
        )),
        actor_config,
    )?;
    let worker_client = Arc::new(worker_rpc.blocking_with_limits(256, 128)?);
    let placement = GatewayWorkerPlacement::new(
        worker_id,
        worker_epoch,
        placement_version,
        placement_version,
    )?;
    let gateway_runtime = Arc::new(GatewayWorkerRuntime::with_action_coordination(
        worker_client,
        placement,
        Arc::new(MemoryGatewayActionStore::attach(database, store_config)),
        actor_config,
    )?);
    let api = DurableApiRouter::with_dispatch_lease_duration(
        gateway_runtime,
        coordination.clone(),
        Duration::from_secs(30),
    )?;
    let authenticator = GatewayAuthenticator::from_hmac_parts(
        &auth_issuer,
        &auth_audience,
        &auth_key_id,
        auth_secret.as_bytes(),
        30,
    )?;
    let viewer = GatewayViewer::new(Duration::from_secs(5 * 60), viewer_origins, 16_384)?;
    let readiness = Arc::new(GatewayReadiness::new());
    let readiness_gate: Arc<dyn browserd_http::Readiness> = readiness.clone();
    let app = router(
        HttpConfig::default(),
        Arc::new(api),
        Arc::new(authenticator),
        Arc::new(viewer),
        readiness_gate,
    );
    let listener = tokio::net::TcpListener::bind(bind_address)
        .await
        .context("failed to bind all-in-one HTTP listener")?;
    readiness.set_worker_ready(true);
    readiness.set_coordination_ready(true);

    let http_shutdown = CancellationToken::new();
    let http_shutdown_signal = http_shutdown.clone();
    let server = axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            http_shutdown_signal.cancelled().await;
        })
        .into_future();
    tokio::pin!(server);
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("failed to install SIGTERM handler")?;
    let shutdown_signal = async {
        tokio::select! {
            result = tokio::signal::ctrl_c() => result.context("Ctrl-C handler failed"),
            signal = terminate.recv() => signal.map(|_| ()).context("SIGTERM handler closed"),
        }
    };
    tokio::pin!(shutdown_signal);
    let mut worker_finished = false;
    let mut server_finished = false;
    let mut exit_error = tokio::select! {
        result = &mut shutdown_signal => result.err(),
        result = &mut worker_task => {
            worker_finished = true;
            Some(match result {
                Ok(Ok(())) => anyhow!("local worker stopped unexpectedly"),
                Ok(Err(error)) => anyhow!(error).context("local worker failed"),
                Err(error) => anyhow!(error).context("local worker task failed"),
            })
        }
        result = &mut server => {
            server_finished = true;
            Some(match result {
                Ok(()) => anyhow!("HTTP server stopped unexpectedly"),
                Err(error) => anyhow!(error).context("HTTP server failed"),
            })
        }
    };

    readiness.set_worker_ready(false);
    readiness.set_coordination_ready(false);
    http_shutdown.cancel();
    if !server_finished {
        match tokio::time::timeout(Duration::from_secs(5), &mut server).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                if exit_error.is_none() {
                    exit_error = Some(anyhow!(error).context("HTTP drain failed"));
                }
            }
            Err(_) => {
                if exit_error.is_none() {
                    exit_error = Some(anyhow!("HTTP drain timed out"));
                }
            }
        }
    }
    let coordination_drain = tokio::task::spawn_blocking(move || coordination.drain()).await;
    match coordination_drain {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            if exit_error.is_none() {
                exit_error = Some(anyhow!(error).context("coordination drain failed"));
            }
        }
        Err(error) => {
            if exit_error.is_none() {
                exit_error = Some(anyhow!(error).context("coordination drain task failed"));
            }
        }
    }
    worker_shutdown.cancel();
    if !worker_finished {
        match tokio::time::timeout(Duration::from_secs(5), worker_task).await {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(error))) => {
                if exit_error.is_none() {
                    exit_error = Some(anyhow!(error).context("worker drain failed"));
                }
            }
            Ok(Err(error)) => {
                if exit_error.is_none() {
                    exit_error = Some(anyhow!(error).context("worker drain task failed"));
                }
            }
            Err(_) => {
                if exit_error.is_none() {
                    exit_error = Some(anyhow!("worker drain timed out"));
                }
            }
        }
    }
    if let Some(error) = exit_error {
        return Err(error);
    }
    Ok(())
}
