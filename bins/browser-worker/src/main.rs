use std::env;
use std::fs;
use std::net::SocketAddr;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use browser_worker::{
    ArtifactQuarantineConfig, ArtifactRetentionConfig, ArtifactScanner, ArtifactStoreConfig,
    ClamAvFreshnessPolicy, LifecycleBounds, ProductionArtifactStore, ProductionSessionShardConfig,
    ProductionSessionShardFactory, ProductionWorkerRuntime, SessionShardRouter, UnixClamAvScanner,
    load_shared_context_policy, load_worker_admission_policy,
};
use browserd_chromium::CompatibilityArtifact;
use browserd_core::WorkerId;
use browserd_observability::{AuditWal, AuditWalPolicy};
use browserd_policy::ActionApprovalPolicy;
use browserd_sandbox::{EgressPolicyBinding, SandboxRpcClient};
use browserd_session::{LeasePolicy, SessionTimeoutPolicy};
use browserd_worker::{
    ActionJournalConfig, ActionJournalPool, ActionJournalPoolConfig, ActionJournalPoolLimits,
    AuthenticatedPeer, ControlEventJournal, DurableWorkerEpoch, InternalEndpoint,
    PrivilegedEvaluatePolicy, SessionOptionSupport, SystemWorkerClock, WorkerArtifactLimits,
    WorkerConfig, WorkerControlPlane, WorkerRpcConfig,
};
use tokio_util::sync::CancellationToken;

const COMPATIBILITY_MANIFEST: &str = "compatibility.json";
const MAX_COMPATIBILITY_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_SANDBOX_RPC_FRAME_BYTES: usize = 4 * 1024 * 1024;
const MAX_WORKER_RPC_FRAME_BYTES: usize = browserd_worker::MAX_WORKER_ACTION_RPC_FRAME_BYTES;

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
    let action_journal = ActionJournalConfig::with_default_limits(action_journal_directory.clone())
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
    let audit_wal_path = env::var_os("BROWSERD_AUDIT_WAL_FILE")
        .map(PathBuf::from)
        .ok_or_else(|| "BROWSERD_AUDIT_WAL_FILE is required".to_owned())?;
    if !audit_wal_path.is_absolute() {
        return Err("BROWSERD_AUDIT_WAL_FILE must be absolute".to_owned());
    }
    let secret_config_path = env::var_os("BROWSERD_SECRET_CONFIG_FILE")
        .map(PathBuf::from)
        .map(|path| {
            if path.is_absolute() {
                Ok(path)
            } else {
                Err("BROWSERD_SECRET_CONFIG_FILE must be absolute".to_owned())
            }
        })
        .transpose()?;
    let privileged_evaluate_policy = match env::var_os("BROWSERD_PRIVILEGED_EVALUATE_POLICY_FILE") {
        None => PrivilegedEvaluatePolicy::default(),
        Some(path) => {
            let path = PathBuf::from(path);
            if !path.is_absolute() {
                return Err("BROWSERD_PRIVILEGED_EVALUATE_POLICY_FILE must be absolute".to_owned());
            }
            PrivilegedEvaluatePolicy::open(&path)
                .map_err(|_| "privileged evaluate policy could not be opened".to_owned())?
        }
    };
    let privileged_evaluate_enabled = privileged_evaluate_policy.is_enabled();
    let action_approval_policy = match env::var_os("BROWSERD_ACTION_APPROVAL_POLICY_FILE") {
        None => ActionApprovalPolicy::default(),
        Some(path) => {
            let path = PathBuf::from(path);
            if !path.is_absolute() {
                return Err("BROWSERD_ACTION_APPROVAL_POLICY_FILE must be absolute".to_owned());
            }
            ActionApprovalPolicy::open(&path)
                .map_err(|_| "action approval policy could not be opened".to_owned())?
        }
    };
    let checkpoint_configuration = match (
        env::var_os("BROWSERD_CHECKPOINT_ROOT"),
        env::var_os("BROWSERD_CHECKPOINT_KEY_FILE"),
    ) {
        (None, None) => None,
        (Some(root), Some(key)) => {
            let (root, key) = (PathBuf::from(root), PathBuf::from(key));
            if !root.is_absolute() || !key.is_absolute() {
                return Err("checkpoint storage paths must be absolute".to_owned());
            }
            Some((root, key))
        }
        _ => return Err("checkpoint storage requires both root and key file".to_owned()),
    };
    let control_event_path = env::var_os("BROWSERD_CONTROL_EVENT_JOURNAL_FILE")
        .map(PathBuf::from)
        .ok_or_else(|| "BROWSERD_CONTROL_EVENT_JOURNAL_FILE is required".to_owned())?;
    if !control_event_path.is_absolute() {
        return Err("BROWSERD_CONTROL_EVENT_JOURNAL_FILE must be absolute".to_owned());
    }
    let artifact_root = env::var_os("BROWSERD_CHROMIUM_ARTIFACT_ROOT")
        .map(PathBuf::from)
        .ok_or_else(|| "BROWSERD_CHROMIUM_ARTIFACT_ROOT is required".to_owned())?;
    let chromium_artifact = load_compatibility_artifact(&artifact_root)?;
    let native_profiles =
        browserd_chromium::VerifiedNativeProfileCatalog::load(&artifact_root, &chromium_artifact)
            .map_err(|_| "Chromium native process profile catalog is invalid".to_owned())?;
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
    // Production cannot admit effects without durable audit intent. Open the sink before
    // advancing the worker incarnation or creating any shard/RPC resources.
    let audit_policy = AuditWalPolicy::new(64 * 1024 * 1024, 64 * 1024)
        .map_err(|_| "audit WAL policy is invalid".to_owned())?;
    let audit_wal = Arc::new(
        AuditWal::open(&audit_wal_path, audit_policy)
            .map_err(|_| "audit WAL could not be opened".to_owned())?,
    );
    let journal_defaults = ActionJournalPoolLimits::default();
    let journal_limits = ActionJournalPoolLimits::new(
        optional_u64_env(
            "BROWSERD_ACTION_JOURNAL_MAX_WORKER_BYTES",
            journal_defaults.worker_bytes(),
        )?,
        optional_u64_env(
            "BROWSERD_ACTION_JOURNAL_MAX_TENANT_BYTES",
            journal_defaults.tenant_bytes(),
        )?,
        usize::try_from(optional_u64_env(
            "BROWSERD_ACTION_JOURNAL_MAX_WORKER_INODES",
            journal_defaults.worker_inodes() as u64,
        )?)
        .map_err(|_| "action journal inode limit exceeds platform bounds".to_owned())?,
        usize::try_from(optional_u64_env(
            "BROWSERD_ACTION_JOURNAL_MAX_TENANT_INODES",
            journal_defaults.tenant_inodes() as u64,
        )?)
        .map_err(|_| "action journal inode limit exceeds platform bounds".to_owned())?,
        optional_u64_env(
            "BROWSERD_ACTION_JOURNAL_RETENTION_MILLIS",
            journal_defaults.retention_millis(),
        )?,
    )
    .map_err(|_| "action journal pool limits are invalid".to_owned())?;
    let journal_pool_config =
        ActionJournalPoolConfig::new(action_journal_directory, Default::default())
            .and_then(|config| config.with_limits(journal_limits))
            .map_err(|_| "action journal pool configuration is invalid".to_owned())?;
    // Acquire and inventory the durable pool before advancing the worker incarnation.
    let action_journal_pool = ActionJournalPool::open(journal_pool_config, worker_id.clone())
        .map_err(|_| "action journal pool could not be opened".to_owned())?;
    let secret_resolver = secret_config_path
        .map(|path| {
            browserd_worker::FileSecretResolver::open(&path)
                .map(|resolver| Arc::new(resolver) as Arc<dyn browserd_worker::SecretResolver>)
                .map_err(|_| "secret provider configuration is invalid".to_owned())
        })
        .transpose()?;
    let checkpoint_store = checkpoint_configuration
        .map(|(root, key)| {
            browserd_worker::FileCheckpointStore::open(&root, &key)
                .map(|store| Arc::new(store) as Arc<dyn browserd_worker::CheckpointStore>)
                .map_err(|_| "checkpoint storage configuration is invalid".to_owned())
        })
        .transpose()?;
    let (artifact_store, artifact_limits, browser_downloads) =
        open_artifact_store(runtime.handle().clone())?;
    let artifact_store = Arc::new(artifact_store);
    let control_event_journal = Arc::new(
        ControlEventJournal::open(&control_event_path, 1024, 65_536, 8 * 1024 * 1024)
            .map_err(|_| "control event journal could not be opened".to_owned())?,
    );
    control_event_journal
        .enable_notifications(&worker_id)
        .map_err(|_| "control event journal belongs to another worker".to_owned())?;
    let session_event_path = env::var_os("BROWSERD_SESSION_EVENT_JOURNAL_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| control_event_path.with_extension("session-events.journal"));
    let session_event_journal = Arc::new(
        browserd_worker::SessionEventJournal::open(
            &session_event_path,
            4096,
            16_384,
            32 * 1024 * 1024,
        )
        .map_err(|_| "session event journal could not be opened".to_owned())?,
    );
    session_event_journal
        .bind_worker(&worker_id)
        .map_err(|_| "session event journal belongs to another worker".to_owned())?;
    let shared_policy_path = env::var_os("BROWSERD_SHARED_CONTEXT_POLICY_FILE").map(PathBuf::from);
    let shared_policy =
        load_shared_context_policy(shared_policy_path.as_deref(), &chromium_artifact.identity)
            .map_err(|_| "shared context policy could not be loaded".to_owned())?;
    let admission_policy = env::var_os("BROWSERD_FLEET_WORKER_POLICY_FILE")
        .map(PathBuf::from)
        .map(|path| {
            load_worker_admission_policy(
                &path,
                &worker_id,
                &chromium_artifact.identity,
                &egress_policy,
            )
        })
        .transpose()?;
    let tenant_assignment = admission_policy
        .as_ref()
        .and_then(|policy| policy.exclusive_assignment().cloned());
    let safety_cache = Arc::new(browserd_core::RuntimeSafetyCache::new());
    let safety_config = browserd_coordination::RedisSafetyAuthorityConfig::new(
        env::var("BROWSERD_REDIS_URL").map_err(|_| "BROWSERD_REDIS_URL is required".to_owned())?,
        env::var("BROWSERD_REDIS_PREFIX")
            .map_err(|_| "BROWSERD_REDIS_PREFIX is required".to_owned())?,
        browserd_coordination::SafetyAuthorityConfig::default(),
        4,
        Duration::from_secs(5),
    )
    .map_err(|_| "runtime safety Redis configuration is invalid".to_owned())?;
    let safety_authority: Arc<dyn browserd_coordination::SafetyAuthority> = Arc::new(
        runtime
            .block_on(browserd_coordination::RedisSafetyAuthority::connect(
                safety_config,
            ))
            .map_err(|_| "runtime safety authority connection unavailable".to_owned())?,
    );
    let safety_path = env::var_os("BROWSERD_SAFETY_STATE_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| control_event_path.with_extension("safety-state"));
    let safety_observer = Arc::new(
        browserd_coordination::SafetyObserver::open(
            safety_path,
            safety_authority,
            Arc::clone(&safety_cache),
            Duration::from_secs(30),
        )
        .map_err(|_| "runtime safety observer durability unavailable".to_owned())?,
    );
    // Missing initial authority leaves admission unavailable while metadata RPC can bootstrap it.
    let _initial_safety = runtime.block_on(safety_observer.refresh());
    let chromium_safety_digest = chromium_artifact.identity.binary_digest.to_string();
    let worker_epoch = DurableWorkerEpoch::increment(epoch_path)
        .map_err(|_| "durable worker epoch unavailable".to_owned())?;
    let ownership_ttl_secs = if admission_policy.is_some() { 60 } else { 15 };
    let lease_policy = LeasePolicy::new(
        Duration::from_secs(ownership_ttl_secs),
        Duration::from_secs(3),
    )
    .map_err(|_| "invalid ownership lease policy".to_owned())?;
    let timeout_policy =
        SessionTimeoutPolicy::new(Duration::from_secs(30 * 60), Duration::from_secs(10 * 60))
            .map_err(|_| "invalid session timeout policy".to_owned())?;
    let mut worker_config = WorkerConfig::new(
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
    .map_err(|_| "invalid worker configuration".to_owned())?
    .with_session_option_support(SessionOptionSupport::single_host_default())
    .with_artifact_limits(artifact_limits);
    if let Some(policy) = admission_policy {
        worker_config = worker_config
            .with_fleet_admission_policy(policy)
            .map_err(|_| "worker admission policy does not match capacity".to_owned())?;
    }
    let mut shard_config = ProductionSessionShardConfig::new(
        worker_id.clone(),
        worker_epoch,
        sandbox_epoch,
        chromium_artifact.identity,
        browserd_chromium::ChromiumConnectionConfig::default(),
        egress_policy,
        Duration::from_secs(30),
    )
    .map_err(|_| "production shard configuration is invalid".to_owned())?
    .with_native_profiles(native_profiles)
    .map_err(|_| "Chromium native process profile binding is invalid".to_owned())?
    .with_browser_downloads(browser_downloads)
    .with_privileged_evaluate(privileged_evaluate_enabled);
    if let Some(assignment) = tenant_assignment {
        shard_config = shard_config
            .with_worker_tenant_assignment(assignment)
            .map_err(|_| "worker tenant assignment does not match this worker".to_owned())?;
    }
    if let Some(policy) = shared_policy {
        shard_config = shard_config
            .with_shared_context_policy(policy)
            .map_err(|_| "shared context policy does not match the Chromium artifact".to_owned())?;
    }
    let factory = Arc::new(
        ProductionSessionShardFactory::new(shard_config, sandbox, runtime.handle().clone())
            .map_err(|_| "production shard runtime is unsupported".to_owned())?
            .with_runtime_safety(Arc::clone(&safety_cache)),
    );
    let router = Arc::new(
        SessionShardRouter::new(
            worker_id,
            worker_epoch,
            factory,
            Arc::clone(&artifact_store),
            256,
        )
        .map_err(|_| "session shard router configuration is invalid".to_owned())?,
    );
    let mut worker =
        WorkerControlPlane::new(worker_config, Arc::clone(&router), Arc::clone(&router))
            .with_audit_wal(audit_wal)
            .with_privileged_evaluate_policy(privileged_evaluate_policy)
            .with_action_approval_policy(action_approval_policy)
            .with_action_journal_pool(action_journal_pool)
            .with_control_event_journal(control_event_journal)
            .with_session_event_journal(session_event_journal)
            .with_runtime_safety_cache(Arc::clone(&safety_cache), chromium_safety_digest)
            .map_err(|_| "runtime safety cache configuration invalid".to_owned())?;
    if let Some(resolver) = secret_resolver {
        worker = worker.with_secret_resolver(resolver);
    }
    if let Some(store) = checkpoint_store {
        worker = worker.with_checkpoint_store(store);
    }
    let worker = Arc::new(worker);
    let lifecycle_bounds = LifecycleBounds::new(
        Duration::from_secs(3),
        Duration::from_secs(1),
        Duration::from_secs(15),
        Duration::from_secs(30),
    )
    .map_err(|_| "worker lifecycle bounds are invalid".to_owned())?;
    let service = ProductionWorkerRuntime::new(worker, trusted_peer, rpc_config, lifecycle_bounds)
        .map_err(|_| "readiness qualification unavailable".to_owned())?
        .with_artifact_maintenance(artifact_store);

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
        let safety_shutdown = shutdown.clone();
        let safety_task = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(1));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {biased; ()=safety_shutdown.cancelled()=>break,_=ticker.tick()=>{}}
                tokio::select! {biased; ()=safety_shutdown.cancelled()=>break,result=safety_observer.refresh()=>{
                    if result.is_err() { eprintln!("worker runtime safety verification remains pending"); }
                }}
            }
        });
        let result = service.serve(shutdown.clone()).await;
        shutdown.cancel();
        let _ = safety_task.await;
        signal.abort();
        result.map_err(|error| format!("production worker runtime failed: {error}"))
    })
}

fn positive_env(name: &str) -> Result<u64, String> {
    env::var(name)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| format!("{name} must be a positive integer"))
}

fn count_env(name: &str) -> Result<usize, String> {
    usize::try_from(positive_env(name)?).map_err(|_| format!("{name} exceeds platform bounds"))
}

fn optional_u64_env(name: &str, default: u64) -> Result<u64, String> {
    match env::var(name) {
        Ok(value) => value.parse().map_err(|_| format!("{name} is invalid")),
        Err(env::VarError::NotPresent) => Ok(default),
        Err(env::VarError::NotUnicode(_)) => Err(format!("{name} is invalid")),
    }
}

fn open_artifact_store(
    runtime: tokio::runtime::Handle,
) -> Result<(ProductionArtifactStore, WorkerArtifactLimits, bool), String> {
    let root = env::var_os("BROWSERD_ARTIFACT_ROOT")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or_else(|| "BROWSERD_ARTIFACT_ROOT must be absolute".to_owned())?;
    let config = ArtifactStoreConfig {
        root,
        max_file_bytes: positive_env("BROWSERD_ARTIFACT_MAX_FILE_BYTES")?,
        max_worker_bytes: positive_env("BROWSERD_ARTIFACT_MAX_WORKER_BYTES")?,
        max_worker_in_flight_bytes: positive_env("BROWSERD_ARTIFACT_MAX_WORKER_IN_FLIGHT_BYTES")?,
        max_session_bytes: positive_env("BROWSERD_ARTIFACT_MAX_SESSION_BYTES")?,
        max_session_in_flight_bytes: positive_env("BROWSERD_ARTIFACT_MAX_SESSION_IN_FLIGHT_BYTES")?,
        max_retained_artifacts: count_env("BROWSERD_ARTIFACT_MAX_RETAINED_ARTIFACTS")?,
        max_operations: count_env("BROWSERD_ARTIFACT_MAX_OPERATIONS")?,
        chunk_bytes: count_env("BROWSERD_ARTIFACT_CHUNK_BYTES")?,
        operation_timeout: Duration::from_millis(positive_env(
            "BROWSERD_ARTIFACT_OPERATION_TIMEOUT_MS",
        )?),
    };
    let limits = WorkerArtifactLimits::new(
        config.max_file_bytes,
        config.max_session_bytes.min(config.max_worker_bytes),
        config
            .max_session_in_flight_bytes
            .min(config.max_worker_in_flight_bytes),
    )
    .map_err(|_| "artifact file limit exceeds aggregate quota".to_owned())?;
    let scanner: Option<Arc<dyn ArtifactScanner>> = match (
        env::var_os("BROWSERD_ARTIFACT_SCANNER_SOCKET"),
        env::var_os("BROWSERD_ARTIFACT_SCANNER_UID"),
        env::var_os("BROWSERD_ARTIFACT_SCANNER_TIMESTAMP_TIMEZONE"),
    ) {
        (None, None, None) => None,
        (Some(path), Some(uid), Some(timezone)) if timezone.to_str() == Some("UTC") => {
            Some(Arc::new(
                UnixClamAvScanner::new(
                    PathBuf::from(path),
                    uid.into_string()
                        .map_err(|_| "BROWSERD_ARTIFACT_SCANNER_UID is invalid".to_owned())?
                        .parse()
                        .map_err(|_| "BROWSERD_ARTIFACT_SCANNER_UID is invalid".to_owned())?,
                    config.max_file_bytes,
                    config.operation_timeout,
                    ClamAvFreshnessPolicy::new_utc(
                        Duration::from_millis(optional_u64_env(
                            "BROWSERD_ARTIFACT_SCANNER_MAX_DATABASE_AGE_MS",
                            48 * 60 * 60 * 1000,
                        )?),
                        Duration::from_millis(optional_u64_env(
                            "BROWSERD_ARTIFACT_SCANNER_MAX_FUTURE_SKEW_MS",
                            5 * 60 * 1000,
                        )?),
                    )
                    .map_err(|_| "artifact scanner freshness policy is invalid".to_owned())?,
                    Arc::new(SystemWorkerClock),
                )
                .map_err(|_| "artifact scanner configuration is invalid".to_owned())?,
            ))
        }
        _ => {
            return Err(
                "artifact scanner requires socket, UID and timestamp timezone UTC together"
                    .to_owned(),
            );
        }
    };
    let browser_downloads = scanner.is_some();
    let quarantine = artifact_quarantine_from_lookup(|name| match env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(env::VarError::NotUnicode(_)) => Err(format!("{name} must be UTF-8")),
    })?;
    let store = ProductionArtifactStore::open_with_quarantine(
        config,
        runtime,
        scanner,
        ArtifactRetentionConfig::default(),
        Arc::new(SystemWorkerClock),
        quarantine,
    )
    .map_err(|_| "artifact storage could not be opened".to_owned())?;
    store
        .reconcile_pending()
        .map_err(|_| "artifact recovery failed".to_owned())?;
    Ok((store, limits, browser_downloads))
}

fn artifact_quarantine_from_lookup(
    mut lookup: impl FnMut(&str) -> Result<Option<String>, String>,
) -> Result<Option<ArtifactQuarantineConfig>, String> {
    const ENABLED: &str = "BROWSERD_ARTIFACT_QUARANTINE_ENABLED";
    const LIMITS: [&str; 5] = [
        "BROWSERD_ARTIFACT_QUARANTINE_RETENTION_MS",
        "BROWSERD_ARTIFACT_QUARANTINE_MAX_FILE_BYTES",
        "BROWSERD_ARTIFACT_QUARANTINE_MAX_WORKER_BYTES",
        "BROWSERD_ARTIFACT_QUARANTINE_MAX_SESSION_BYTES",
        "BROWSERD_ARTIFACT_QUARANTINE_MAX_RETAINED_ARTIFACTS",
    ];
    let enabled = lookup(ENABLED)?;
    let mut values = Vec::with_capacity(LIMITS.len());
    for name in LIMITS {
        values.push(lookup(name)?);
    }
    match enabled.as_deref() {
        None | Some("false") if values.iter().all(Option::is_none) => return Ok(None),
        None | Some("false") => {
            return Err(
                "quarantine limits require BROWSERD_ARTIFACT_QUARANTINE_ENABLED=true".to_owned(),
            );
        }
        Some("true") => {}
        Some(_) => return Err(format!("{ENABLED} must be true or false")),
    }
    let positive = |index: usize| {
        values[index]
            .as_deref()
            .ok_or_else(|| format!("{} is required", LIMITS[index]))?
            .parse::<u64>()
            .ok()
            .filter(|value| *value > 0)
            .ok_or_else(|| format!("{} must be a positive integer", LIMITS[index]))
    };
    ArtifactQuarantineConfig::new(
        Duration::from_millis(positive(0)?),
        positive(1)?,
        positive(2)?,
        positive(3)?,
        usize::try_from(positive(4)?)
            .map_err(|_| "quarantine count exceeds platform bounds".to_owned())?,
    )
    .map(Some)
    .map_err(|_| "artifact quarantine policy is invalid".to_owned())
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

#[cfg(test)]
mod quarantine_configuration_tests {
    #![allow(clippy::expect_used)]
    use super::*;
    use std::collections::BTreeMap;

    fn configured() -> BTreeMap<&'static str, String> {
        BTreeMap::from([
            ("BROWSERD_ARTIFACT_QUARANTINE_ENABLED", "true".to_owned()),
            (
                "BROWSERD_ARTIFACT_QUARANTINE_RETENTION_MS",
                "3600000".to_owned(),
            ),
            (
                "BROWSERD_ARTIFACT_QUARANTINE_MAX_FILE_BYTES",
                "1048576".to_owned(),
            ),
            (
                "BROWSERD_ARTIFACT_QUARANTINE_MAX_WORKER_BYTES",
                "4194304".to_owned(),
            ),
            (
                "BROWSERD_ARTIFACT_QUARANTINE_MAX_SESSION_BYTES",
                "2097152".to_owned(),
            ),
            (
                "BROWSERD_ARTIFACT_QUARANTINE_MAX_RETAINED_ARTIFACTS",
                "8".to_owned(),
            ),
        ])
    }
    fn parse(values: &BTreeMap<&str, String>) -> Result<Option<ArtifactQuarantineConfig>, String> {
        artifact_quarantine_from_lookup(|name| Ok(values.get(name).cloned()))
    }
    #[test]
    fn retention_is_explicit_and_partial_disabled_configuration_is_rejected() {
        assert!(parse(&BTreeMap::new()).expect("default disabled").is_none());
        assert!(
            parse(&BTreeMap::from([(
                "BROWSERD_ARTIFACT_QUARANTINE_ENABLED",
                "false".to_owned()
            )]))
            .expect("explicit disabled")
            .is_none()
        );
        assert!(
            parse(&configured())
                .expect("complete bounded policy")
                .is_some()
        );
        let mut values = configured();
        values.remove("BROWSERD_ARTIFACT_QUARANTINE_ENABLED");
        assert!(parse(&values).is_err());
        values.insert("BROWSERD_ARTIFACT_QUARANTINE_ENABLED", "false".to_owned());
        assert!(parse(&values).is_err());
        for key in configured()
            .keys()
            .filter(|key| **key != "BROWSERD_ARTIFACT_QUARANTINE_ENABLED")
        {
            let mut values = configured();
            values.remove(key);
            assert!(parse(&values).is_err(), "{key}");
        }
    }
    #[test]
    fn invalid_policy_cannot_silently_enable_or_relax_retention() {
        for (key, value) in [
            ("BROWSERD_ARTIFACT_QUARANTINE_ENABLED", "TRUE"),
            ("BROWSERD_ARTIFACT_QUARANTINE_ENABLED", "1"),
            ("BROWSERD_ARTIFACT_QUARANTINE_RETENTION_MS", "86400001"),
            ("BROWSERD_ARTIFACT_QUARANTINE_RETENTION_MS", "0"),
            ("BROWSERD_ARTIFACT_QUARANTINE_MAX_FILE_BYTES", "invalid"),
            ("BROWSERD_ARTIFACT_QUARANTINE_MAX_FILE_BYTES", "0"),
            ("BROWSERD_ARTIFACT_QUARANTINE_MAX_RETAINED_ARTIFACTS", "0"),
        ] {
            let mut values = configured();
            values.insert(key, value.to_owned());
            assert!(parse(&values).is_err(), "{key}");
        }
        assert!(artifact_quarantine_from_lookup(|_| Err("invalid UTF-8".to_owned())).is_err());
    }
}
