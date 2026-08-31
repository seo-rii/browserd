use std::env;
use std::fs;
use std::net::SocketAddr;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use browser_worker::{
    LifecycleBounds, ProductionSessionShardConfig, ProductionSessionShardFactory,
    ProductionWorkerRuntime, RoutedArtifactStore, SessionShardRouter,
};
use browserd_chromium::CompatibilityArtifact;
use browserd_core::WorkerId;
use browserd_sandbox::{EgressPolicyBinding, SandboxRpcClient};
use browserd_session::{LeasePolicy, SessionTimeoutPolicy};
use browserd_worker::{
    ActionJournalConfig, ArtifactStoreReceipt, ArtifactStoreRequest, AuthenticatedPeer,
    DependencyError, DurableWorkerEpoch, InternalEndpoint, WorkerConfig, WorkerControlPlane,
    WorkerRpcConfig,
};
use tokio_util::sync::CancellationToken;

const COMPATIBILITY_MANIFEST: &str = "compatibility.json";
const MAX_COMPATIBILITY_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_SANDBOX_RPC_FRAME_BYTES: usize = 4 * 1024 * 1024;
const MAX_WORKER_RPC_FRAME_BYTES: usize = 4 * 1024 * 1024;

fn main() -> ExitCode {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|_| "Tokio runtime unavailable".to_owned());
    let result = runtime.and_then(|runtime| run(&runtime));
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("browser-worker startup refused: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run(runtime: &tokio::runtime::Runtime) -> Result<(), String> {
    let worker_id = env::var("BROWSERD_WORKER_ID")
        .map_err(|_| "BROWSERD_WORKER_ID is required".to_owned())
        .and_then(|value| WorkerId::new(value).map_err(|_| "invalid worker identity".to_owned()))?;
    let epoch_path = env::var_os("BROWSERD_WORKER_EPOCH_FILE")
        .map(PathBuf::from)
        .ok_or_else(|| "BROWSERD_WORKER_EPOCH_FILE is required".to_owned())?;
    if !epoch_path.is_absolute() {
        return Err("epoch file must be absolute".to_owned());
    }
    let endpoint = parse_endpoint(
        &env::var("BROWSERD_INTERNAL_ENDPOINT")
            .map_err(|_| "BROWSERD_INTERNAL_ENDPOINT is required".to_owned())?,
    )?;
    let trusted_peer = env::var("BROWSERD_INTERNAL_PEER")
        .map_err(|_| "BROWSERD_INTERNAL_PEER is required".to_owned())
        .and_then(|value| {
            AuthenticatedPeer::new(value)
                .map_err(|_| "invalid authenticated peer identity".to_owned())
        })?;
    let action_journal_directory = env::var_os("BROWSERD_ACTION_JOURNAL_DIR")
        .map(PathBuf::from)
        .ok_or_else(|| "BROWSERD_ACTION_JOURNAL_DIR is required".to_owned())?;
    let action_journal = ActionJournalConfig::with_default_limits(action_journal_directory)
        .map_err(|_| "action journal directory must be absolute".to_owned())?;
    let worker_socket = match &endpoint {
        InternalEndpoint::Unix(path) => path.clone(),
        InternalEndpoint::Loopback(_) => {
            return Err("worker RPC endpoint must be unix".to_owned());
        }
    };
    let sandbox_socket = env::var_os("BROWSERD_SANDBOX_SOCKET")
        .map(PathBuf::from)
        .ok_or_else(|| "BROWSERD_SANDBOX_SOCKET is required".to_owned())?;
    if !sandbox_socket.is_absolute() || sandbox_socket.as_os_str().is_empty() {
        return Err("BROWSERD_SANDBOX_SOCKET must be absolute".to_owned());
    }
    let sandbox_uid = env::var("BROWSERD_SANDBOX_EXPECTED_SERVER_UID")
        .map_err(|_| "BROWSERD_SANDBOX_EXPECTED_SERVER_UID is required".to_owned())?
        .parse::<u32>()
        .map_err(|_| "BROWSERD_SANDBOX_EXPECTED_SERVER_UID is invalid".to_owned())?;
    let sandbox_epoch = env::var("BROWSERD_SANDBOXD_EPOCH")
        .map_err(|_| "BROWSERD_SANDBOXD_EPOCH is required".to_owned())?
        .parse::<u64>()
        .map_err(|_| "BROWSERD_SANDBOXD_EPOCH is invalid".to_owned())?;
    if sandbox_epoch == 0 {
        return Err("BROWSERD_SANDBOXD_EPOCH is invalid".to_owned());
    }
    let artifact_root = env::var_os("BROWSERD_CHROMIUM_ARTIFACT_ROOT")
        .map(PathBuf::from)
        .ok_or_else(|| "BROWSERD_CHROMIUM_ARTIFACT_ROOT is required".to_owned())?;
    let chromium_artifact = load_compatibility_artifact(&artifact_root)?;
    let egress_profile = env::var("BROWSERD_EGRESS_POLICY_PROFILE")
        .map_err(|_| "BROWSERD_EGRESS_POLICY_PROFILE is required".to_owned())?;
    let egress_digest = env::var("BROWSERD_EGRESS_POLICY_DIGEST")
        .map_err(|_| "BROWSERD_EGRESS_POLICY_DIGEST is required".to_owned())
        .and_then(|value| {
            hex::decode(value)
                .ok()
                .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
                .ok_or_else(|| "BROWSERD_EGRESS_POLICY_DIGEST is invalid".to_owned())
        })?;
    let egress_policy = EgressPolicyBinding::new(egress_profile, egress_digest)
        .map_err(|_| "egress policy binding is invalid".to_owned())?;
    let process_uid = fs::metadata("/proc/self")
        .map_err(|_| "process credentials unavailable".to_owned())?
        .uid();
    let sandbox = Arc::new(
        SandboxRpcClient::new(
            sandbox_socket,
            MAX_SANDBOX_RPC_FRAME_BYTES,
            Duration::from_secs(5),
            sandbox_uid,
            sandbox_epoch,
        )
        .map_err(|_| "sandbox RPC configuration is invalid".to_owned())?,
    );
    let rpc_config = WorkerRpcConfig::new(
        worker_socket,
        MAX_WORKER_RPC_FRAME_BYTES,
        256,
        Duration::from_secs(30),
        Some(process_uid),
    )
    .map_err(|_| "worker RPC configuration is invalid".to_owned())?;
    let worker_epoch = DurableWorkerEpoch::increment(epoch_path)
        .map_err(|_| "durable worker epoch unavailable".to_owned())?;
    let lease_policy = LeasePolicy::new(Duration::from_secs(15), Duration::from_secs(3))
        .map_err(|_| "invalid ownership lease policy".to_owned())?;
    let timeout_policy =
        SessionTimeoutPolicy::new(Duration::from_secs(30 * 60), Duration::from_secs(10 * 60))
            .map_err(|_| "invalid session timeout policy".to_owned())?;
    let worker_config = WorkerConfig::new(
        worker_id.clone(),
        worker_epoch,
        endpoint,
        trusted_peer.clone(),
        256,
        128,
        lease_policy,
        timeout_policy,
        Duration::from_secs(5 * 60),
        action_journal,
    )
    .map_err(|_| "invalid worker configuration".to_owned())?;
    let shard_config = ProductionSessionShardConfig::new(
        worker_id.clone(),
        worker_epoch,
        sandbox_epoch,
        chromium_artifact.identity,
        browserd_chromium::ChromiumConnectionConfig::default(),
        egress_policy,
        Duration::from_secs(30),
    )
    .map_err(|_| "production shard configuration is invalid".to_owned())?;
    let factory = Arc::new(ProductionSessionShardFactory::new(
        shard_config,
        sandbox,
        runtime.handle().clone(),
    ));
    let router = Arc::new(
        SessionShardRouter::new(
            worker_id,
            worker_epoch,
            factory,
            Arc::new(RejectArtifacts),
            256,
        )
        .map_err(|_| "session shard router configuration is invalid".to_owned())?,
    );
    let worker = Arc::new(WorkerControlPlane::new(
        worker_config,
        Arc::clone(&router),
        Arc::clone(&router),
    ));
    let lifecycle_bounds = LifecycleBounds::new(
        Duration::from_secs(3),
        Duration::from_secs(1),
        Duration::from_secs(15),
        Duration::from_secs(30),
    )
    .map_err(|_| "worker lifecycle bounds are invalid".to_owned())?;
    let service = ProductionWorkerRuntime::new(worker, trusted_peer, rpc_config, lifecycle_bounds)
        .map_err(|_| "readiness qualification unavailable".to_owned())?;

    runtime.block_on(async move {
        let shutdown = CancellationToken::new();
        let signal_shutdown = shutdown.clone();
        let signal = tokio::spawn(async move {
            let mut sigterm =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .map_err(|_| ())?;
            tokio::select! {
                result = tokio::signal::ctrl_c() => result.map_err(|_| ())?,
                signal = sigterm.recv() => {
                    if signal.is_none() {
                        return Err(());
                    }
                }
            }
            signal_shutdown.cancel();
            Ok::<(), ()>(())
        });
        let result = service.serve(shutdown).await;
        signal.abort();
        result.map_err(|error| format!("production worker runtime failed: {error}"))
    })
}

struct RejectArtifacts;

impl RoutedArtifactStore for RejectArtifacts {
    fn store(
        &self,
        _request: &ArtifactStoreRequest,
    ) -> Result<ArtifactStoreReceipt, DependencyError> {
        Err(DependencyError::Rejected)
    }
}

fn load_compatibility_artifact(root: &Path) -> Result<CompatibilityArtifact, String> {
    if !root.is_absolute() || root.as_os_str().is_empty() {
        return Err("BROWSERD_CHROMIUM_ARTIFACT_ROOT must be absolute".to_owned());
    }
    let root_metadata = fs::symlink_metadata(root)
        .map_err(|_| "Chromium artifact root is unavailable".to_owned())?;
    if !root_metadata.is_dir()
        || root_metadata.file_type().is_symlink()
        || root_metadata.mode() & 0o022 != 0
    {
        return Err("Chromium artifact root is not trusted".to_owned());
    }
    let manifest_path = root.join(COMPATIBILITY_MANIFEST);
    let manifest_metadata = fs::symlink_metadata(&manifest_path)
        .map_err(|_| "Chromium compatibility manifest is unavailable".to_owned())?;
    if !manifest_metadata.is_file()
        || manifest_metadata.file_type().is_symlink()
        || manifest_metadata.len() > MAX_COMPATIBILITY_MANIFEST_BYTES
        || manifest_metadata.mode() & 0o022 != 0
    {
        return Err("Chromium compatibility manifest is not trusted".to_owned());
    }
    let manifest = fs::read(&manifest_path)
        .map_err(|_| "Chromium compatibility manifest is unreadable".to_owned())?;
    let artifact: CompatibilityArtifact = serde_json::from_slice(&manifest)
        .map_err(|_| "Chromium compatibility manifest is invalid".to_owned())?;
    artifact
        .verify(root)
        .map_err(|_| "Chromium compatibility artifact verification failed".to_owned())?;
    Ok(artifact)
}

fn parse_endpoint(value: &str) -> Result<InternalEndpoint, String> {
    if let Some(path) = value.strip_prefix("unix:") {
        return InternalEndpoint::unix(path).map_err(|_| "invalid internal endpoint".to_owned());
    }
    let address = value
        .parse::<SocketAddr>()
        .map_err(|_| "invalid internal endpoint".to_owned())?;
    InternalEndpoint::loopback(address).map_err(|_| "invalid internal endpoint".to_owned())
}
