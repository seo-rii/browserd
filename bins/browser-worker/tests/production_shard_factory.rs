#![allow(clippy::expect_used, clippy::panic)]

use std::collections::VecDeque;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex, mpsc};
use std::thread::ThreadId;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use browser_worker::{
    ProductionQualificationBounds, ProductionSandboxControl, ProductionSessionShardConfig,
    ProductionSessionShardFactory, ProvisionedSessionShard, RoutedArtifactStore,
    SessionShardFactory, SessionShardRouter,
};
use browserd_cdp::CdpTransportConfig;
use browserd_chromium::{ChromiumArtifactIdentity, ChromiumConnectionConfig, Sha256Digest};
use browserd_core::{LaunchGeneration, SessionId, ShardId, TenantId, WorkerId};
use browserd_sandbox::{
    ChromiumBinaryDigest, ChromiumCdpPipes, CleanupReason, CleanupResult, CreateShardOutcome,
    EgressPolicyBinding, KillShardOutcome, LaunchSpec,
};
use browserd_session::OwnershipFence;
use browserd_worker::{
    ArtifactStoreReceipt, ArtifactStoreRequest, ChromiumDriver, DependencyError, SandboxClient,
    SandboxShardRpc, ShardRuntimeError, WorkerSessionOptionsV1, WorkerViewport,
};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::unix::pipe::{Receiver, Sender};
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

struct FailingSandbox {
    daemon_epoch: u64,
    launches: Mutex<Vec<LaunchSpec>>,
    cancelled_specs: Mutex<Vec<LaunchSpec>>,
    claims: AtomicUsize,
    kills: AtomicUsize,
}

#[async_trait]
impl SandboxShardRpc for FailingSandbox {
    async fn create_shard(
        &self,
        spec: LaunchSpec,
        _lease_ttl: Duration,
    ) -> Result<CreateShardOutcome, ShardRuntimeError> {
        self.launches
            .lock()
            .expect("launch log should remain available")
            .push(spec);
        Ok(CreateShardOutcome::Created)
    }

    async fn cancel_or_kill_shard(
        &self,
        spec: &LaunchSpec,
        _reason: CleanupReason,
    ) -> Result<KillShardOutcome, ShardRuntimeError> {
        self.cancelled_specs
            .lock()
            .expect("cancel log should remain available")
            .push(spec.clone());
        self.kills.fetch_add(1, Ordering::SeqCst);
        Ok(KillShardOutcome::Terminated(CleanupResult {
            route_revoked: true,
            cgroup_killed: true,
            namespaces_cleaned: true,
        }))
    }

    async fn claim_cdp_pipes(
        &self,
        _shard_id: &ShardId,
        _worker_id: &WorkerId,
        _worker_epoch: u64,
        _launch_generation: LaunchGeneration,
    ) -> Result<ChromiumCdpPipes, ShardRuntimeError> {
        self.claims.fetch_add(1, Ordering::SeqCst);
        Err(ShardRuntimeError::Unavailable)
    }

    async fn renew_owner_lease(
        &self,
        _shard_id: &ShardId,
        _worker_epoch: u64,
        _launch_generation: LaunchGeneration,
        _lease_ttl: Duration,
    ) -> Result<(), ShardRuntimeError> {
        Ok(())
    }

    async fn kill_shard(
        &self,
        _shard_id: &ShardId,
        _worker_epoch: u64,
        _launch_generation: LaunchGeneration,
        _reason: CleanupReason,
    ) -> Result<KillShardOutcome, ShardRuntimeError> {
        self.kills.fetch_add(1, Ordering::SeqCst);
        Ok(KillShardOutcome::Terminated(CleanupResult {
            route_revoked: true,
            cgroup_killed: true,
            namespaces_cleaned: true,
        }))
    }
}

#[async_trait]
impl ProductionSandboxControl for FailingSandbox {
    async fn probe_daemon_epoch(
        &self,
        _worker_id: &WorkerId,
        _worker_epoch: u64,
    ) -> Result<u64, ShardRuntimeError> {
        Ok(self.daemon_epoch)
    }
}

struct DelayedCreateSandbox {
    daemon_epoch: u64,
    daemon_delay: Duration,
    create_delay: Duration,
    block_create: bool,
    probe_threads: Mutex<Vec<ThreadId>>,
    launches: Mutex<Vec<LaunchSpec>>,
    cancelled_specs: Mutex<Vec<LaunchSpec>>,
    claims: AtomicUsize,
    kills: AtomicUsize,
}

#[async_trait]
impl SandboxShardRpc for DelayedCreateSandbox {
    async fn create_shard(
        &self,
        spec: LaunchSpec,
        _lease_ttl: Duration,
    ) -> Result<CreateShardOutcome, ShardRuntimeError> {
        self.launches
            .lock()
            .map_err(|_| ShardRuntimeError::Unavailable)?
            .push(spec);
        if self.block_create {
            std::future::pending::<()>().await;
        }
        tokio::time::sleep(self.create_delay).await;
        Ok(CreateShardOutcome::Created)
    }

    async fn cancel_or_kill_shard(
        &self,
        spec: &LaunchSpec,
        _reason: CleanupReason,
    ) -> Result<KillShardOutcome, ShardRuntimeError> {
        self.cancelled_specs
            .lock()
            .map_err(|_| ShardRuntimeError::Unavailable)?
            .push(spec.clone());
        self.kills.fetch_add(1, Ordering::SeqCst);
        Ok(KillShardOutcome::Terminated(CleanupResult {
            route_revoked: true,
            cgroup_killed: true,
            namespaces_cleaned: true,
        }))
    }

    async fn claim_cdp_pipes(
        &self,
        _shard_id: &ShardId,
        _worker_id: &WorkerId,
        _worker_epoch: u64,
        _launch_generation: LaunchGeneration,
    ) -> Result<ChromiumCdpPipes, ShardRuntimeError> {
        self.claims.fetch_add(1, Ordering::SeqCst);
        Err(ShardRuntimeError::Unavailable)
    }

    async fn renew_owner_lease(
        &self,
        _shard_id: &ShardId,
        _worker_epoch: u64,
        _launch_generation: LaunchGeneration,
        _lease_ttl: Duration,
    ) -> Result<(), ShardRuntimeError> {
        Ok(())
    }

    async fn kill_shard(
        &self,
        _shard_id: &ShardId,
        _worker_epoch: u64,
        _launch_generation: LaunchGeneration,
        _reason: CleanupReason,
    ) -> Result<KillShardOutcome, ShardRuntimeError> {
        self.kills.fetch_add(1, Ordering::SeqCst);
        Ok(KillShardOutcome::Terminated(CleanupResult {
            route_revoked: true,
            cgroup_killed: true,
            namespaces_cleaned: true,
        }))
    }
}

#[async_trait]
impl ProductionSandboxControl for DelayedCreateSandbox {
    async fn probe_daemon_epoch(
        &self,
        _worker_id: &WorkerId,
        _worker_epoch: u64,
    ) -> Result<u64, ShardRuntimeError> {
        self.probe_threads
            .lock()
            .map_err(|_| ShardRuntimeError::Unavailable)?
            .push(std::thread::current().id());
        tokio::time::sleep(self.daemon_delay).await;
        Ok(self.daemon_epoch)
    }
}

struct ScriptedSandbox {
    daemon_epoch: u64,
    cancel_delay: Mutex<Duration>,
    peer_termination: Option<PeerTermination>,
    panic_next_cancel: AtomicBool,
    peers: Mutex<VecDeque<oneshot::Sender<(Receiver, Sender)>>>,
    launches: AtomicUsize,
    claims: AtomicUsize,
    renewals: AtomicUsize,
    kills: AtomicUsize,
    cancelled_specs: Mutex<Vec<LaunchSpec>>,
}

#[derive(Clone)]
struct PeerTermination {
    kill: CancellationToken,
    closed: CancellationToken,
}

#[async_trait]
impl SandboxShardRpc for ScriptedSandbox {
    async fn create_shard(
        &self,
        _spec: LaunchSpec,
        _lease_ttl: Duration,
    ) -> Result<CreateShardOutcome, ShardRuntimeError> {
        self.launches.fetch_add(1, Ordering::SeqCst);
        Ok(CreateShardOutcome::Created)
    }

    async fn cancel_or_kill_shard(
        &self,
        spec: &LaunchSpec,
        _reason: CleanupReason,
    ) -> Result<KillShardOutcome, ShardRuntimeError> {
        if self.panic_next_cancel.swap(false, Ordering::AcqRel) {
            panic!("scripted exact cleanup panic");
        }
        self.cancelled_specs
            .lock()
            .map_err(|_| ShardRuntimeError::Unavailable)?
            .push(spec.clone());
        if let Some(termination) = self.peer_termination.as_ref() {
            termination.kill.cancel();
            termination.closed.cancelled().await;
        }
        let cancel_delay = *self
            .cancel_delay
            .lock()
            .map_err(|_| ShardRuntimeError::Unavailable)?;
        if !cancel_delay.is_zero() {
            tokio::time::sleep(cancel_delay).await;
        }
        self.kills.fetch_add(1, Ordering::SeqCst);
        Ok(KillShardOutcome::Terminated(CleanupResult {
            route_revoked: true,
            cgroup_killed: true,
            namespaces_cleaned: true,
        }))
    }

    async fn claim_cdp_pipes(
        &self,
        _shard_id: &ShardId,
        _worker_id: &WorkerId,
        _worker_epoch: u64,
        _launch_generation: LaunchGeneration,
    ) -> Result<ChromiumCdpPipes, ShardRuntimeError> {
        self.claims.fetch_add(1, Ordering::SeqCst);
        let (command_reader, command_writer) = nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC)
            .map_err(|_| ShardRuntimeError::Unavailable)?;
        let (event_reader, event_writer) = nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC)
            .map_err(|_| ShardRuntimeError::Unavailable)?;
        let pipes = ChromiumCdpPipes::from_owned_fds(command_writer, event_reader)
            .map_err(|_| ShardRuntimeError::Unavailable)?;
        let reader =
            Receiver::from_owned_fd(command_reader).map_err(|_| ShardRuntimeError::Unavailable)?;
        let writer =
            Sender::from_owned_fd(event_writer).map_err(|_| ShardRuntimeError::Unavailable)?;
        self.peers
            .lock()
            .map_err(|_| ShardRuntimeError::Unavailable)?
            .pop_front()
            .ok_or(ShardRuntimeError::Rejected)?
            .send((reader, writer))
            .map_err(|_| ShardRuntimeError::Cancelled)?;
        Ok(pipes)
    }

    async fn renew_owner_lease(
        &self,
        _shard_id: &ShardId,
        _worker_epoch: u64,
        _launch_generation: LaunchGeneration,
        _lease_ttl: Duration,
    ) -> Result<(), ShardRuntimeError> {
        self.renewals.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn kill_shard(
        &self,
        _shard_id: &ShardId,
        _worker_epoch: u64,
        _launch_generation: LaunchGeneration,
        _reason: CleanupReason,
    ) -> Result<KillShardOutcome, ShardRuntimeError> {
        self.kills.fetch_add(1, Ordering::SeqCst);
        Ok(KillShardOutcome::Terminated(CleanupResult {
            route_revoked: true,
            cgroup_killed: true,
            namespaces_cleaned: true,
        }))
    }
}

#[async_trait]
impl ProductionSandboxControl for ScriptedSandbox {
    async fn probe_daemon_epoch(
        &self,
        _worker_id: &WorkerId,
        _worker_epoch: u64,
    ) -> Result<u64, ShardRuntimeError> {
        Ok(self.daemon_epoch)
    }
}

struct RejectArtifacts;

struct FixedShardFactory {
    shard: ProvisionedSessionShard,
}

impl SessionShardFactory for FixedShardFactory {
    fn qualify_daemon(&self) -> Result<(), DependencyError> {
        Ok(())
    }

    fn heartbeat_daemon(
        &self,
        _worker_id: &WorkerId,
        _worker_epoch: u64,
    ) -> Result<(), DependencyError> {
        Ok(())
    }

    fn create(
        &self,
        _tenant_id: &TenantId,
        _session_id: &SessionId,
        _fence: &OwnershipFence,
    ) -> Result<ProvisionedSessionShard, DependencyError> {
        Ok(self.shard.clone())
    }
}

impl RoutedArtifactStore for RejectArtifacts {
    fn store(
        &self,
        _request: &ArtifactStoreRequest,
    ) -> Result<ArtifactStoreReceipt, DependencyError> {
        Err(DependencyError::Rejected)
    }
}

async fn read_command(reader: &mut Receiver) -> Value {
    let mut bytes = Vec::new();
    loop {
        let mut byte = [0_u8; 1];
        let read = reader
            .read(&mut byte)
            .await
            .expect("CDP command should be readable");
        assert_ne!(read, 0, "CDP owner closed before the expected command");
        if byte[0] == 0 {
            break;
        }
        bytes.push(byte[0]);
    }
    serde_json::from_slice(&bytes).expect("CDP command should be valid JSON")
}

async fn respond(writer: &mut Sender, command: &Value, result: Value) {
    let method = command["method"].as_str().unwrap_or("unknown");
    let response = serde_json::to_vec(&json!({
        "id": command["id"]
            .as_u64()
            .expect("CDP command ID should be present"),
        "result": result,
    }))
    .expect("CDP response should encode");
    writer
        .write_all(&response)
        .await
        .unwrap_or_else(|error| panic!("CDP {method} response should be writable: {error}"));
    writer.write_all(&[0]).await.unwrap_or_else(|error| {
        panic!("CDP {method} response terminator should be writable: {error}")
    });
}

async fn qualify_protocol(reader: &mut Receiver, writer: &mut Sender) {
    let version = read_command(reader).await;
    assert_eq!(version["method"], "Browser.getVersion");
    respond(
        writer,
        &version,
        json!({
            "protocolVersion": "1.3",
            "product": "HeadlessChrome/149.0.7827.55",
            "revision": "r1234567",
            "userAgent": "browserd-production-factory-test",
            "jsVersion": "14.9",
        }),
    )
    .await;
}

#[derive(Clone, Copy)]
enum CleanupProbe {
    ForcedClose,
    DisposeOnly,
    Clean,
    OrphanTarget,
    DelayedDispose(Duration),
    DelayedVerify(Duration),
}

async fn run_scripted_protocol(
    peer_rx: oneshot::Receiver<(Receiver, Sender)>,
    cleanup_probe: CleanupProbe,
) {
    let (reader, writer) = peer_rx.await.expect("CDP peer should be transferred");
    run_scripted_protocol_with_pipes(reader, writer, cleanup_probe).await;
}

async fn run_killable_scripted_protocol(
    peer_rx: oneshot::Receiver<(Receiver, Sender)>,
    cleanup_probe: CleanupProbe,
    termination: PeerTermination,
) {
    let (reader, writer) = peer_rx.await.expect("CDP peer should be transferred");
    {
        let protocol = run_scripted_protocol_with_pipes(reader, writer, cleanup_probe);
        tokio::pin!(protocol);
        tokio::select! {
            biased;
            () = termination.kill.cancelled() => {}
            () = &mut protocol => {}
        }
    }
    termination.closed.cancel();
}

async fn run_scripted_protocol_with_pipes(
    mut reader: Receiver,
    mut writer: Sender,
    cleanup_probe: CleanupProbe,
) {
    qualify_protocol(&mut reader, &mut writer).await;

    for method in [
        "Target.setAutoAttach",
        "Target.setDiscoverTargets",
        "Target.getTargets",
    ] {
        let command = read_command(&mut reader).await;
        assert_eq!(command["method"], method);
        let result = if method == "Target.getTargets" {
            json!({"targetInfos": []})
        } else {
            json!({})
        };
        respond(&mut writer, &command, result).await;
    }

    let context = read_command(&mut reader).await;
    assert_eq!(context["method"], "Target.createBrowserContext");
    respond(
        &mut writer,
        &context,
        json!({"browserContextId": "context-production"}),
    )
    .await;
    let target = read_command(&mut reader).await;
    assert_eq!(target["method"], "Target.createTarget");
    let attached = serde_json::to_vec(&json!({
        "method": "Target.attachedToTarget",
        "params": {
            "sessionId": "flat-production",
            "waitingForDebugger": true,
            "targetInfo": {
                "targetId": "target-production",
                "browserContextId": "context-production",
                "type": "page",
            }
        }
    }))
    .expect("CDP attached event should encode");
    writer
        .write_all(&attached)
        .await
        .expect("CDP attached event should be writable");
    writer
        .write_all(&[0])
        .await
        .expect("CDP attached event terminator should be writable");
    respond(
        &mut writer,
        &target,
        json!({"targetId": "target-production"}),
    )
    .await;
    for method in [
        "Target.setAutoAttach",
        "Network.enable",
        "Runtime.enable",
        "Page.enable",
        "Page.setInterceptFileChooserDialog",
        "Runtime.runIfWaitingForDebugger",
    ] {
        let command = read_command(&mut reader).await;
        assert_eq!(command["method"], method);
        respond(&mut writer, &command, json!({})).await;
    }

    if !matches!(cleanup_probe, CleanupProbe::ForcedClose) {
        let dispose = read_command(&mut reader).await;
        assert_eq!(dispose["method"], "Target.disposeBrowserContext");
        if matches!(
            cleanup_probe,
            CleanupProbe::DisposeOnly
                | CleanupProbe::Clean
                | CleanupProbe::DelayedDispose(_)
                | CleanupProbe::DelayedVerify(_)
        ) {
            let destroyed = serde_json::to_vec(&json!({
                "method": "Target.targetDestroyed",
                "params": {"targetId": "target-production"}
            }))
            .expect("CDP target-destroyed event should encode");
            writer
                .write_all(&destroyed)
                .await
                .expect("CDP target-destroyed event should be writable");
            writer
                .write_all(&[0])
                .await
                .expect("CDP target-destroyed terminator should be writable");
        }
        if let CleanupProbe::DelayedDispose(delay) = cleanup_probe {
            tokio::time::sleep(delay).await;
        }
        respond(&mut writer, &dispose, json!({})).await;
        if matches!(cleanup_probe, CleanupProbe::DisposeOnly) {
            let mut byte = [0_u8; 1];
            let closed = tokio::time::timeout(Duration::from_secs(1), reader.read(&mut byte))
                .await
                .expect("CDP writer should close during bounded shutdown")
                .expect("CDP EOF read should succeed");
            assert_eq!(closed, 0);
            return;
        }
        let targets = read_command(&mut reader).await;
        assert_eq!(targets["method"], "Target.getTargets");
        if let CleanupProbe::DelayedVerify(delay) = cleanup_probe {
            tokio::time::sleep(delay).await;
        }
        let target_infos = match cleanup_probe {
            CleanupProbe::OrphanTarget => json!([{
                "targetId": "target-production",
                "browserContextId": "context-production",
                "type": "page",
            }]),
            CleanupProbe::Clean
            | CleanupProbe::DelayedDispose(_)
            | CleanupProbe::DelayedVerify(_) => json!([]),
            CleanupProbe::ForcedClose | CleanupProbe::DisposeOnly => {
                unreachable!("this cleanup mode skips context verification")
            }
        };
        respond(&mut writer, &targets, json!({"targetInfos": target_infos})).await;
        if matches!(
            cleanup_probe,
            CleanupProbe::Clean | CleanupProbe::DelayedDispose(_) | CleanupProbe::DelayedVerify(_)
        ) {
            let contexts = read_command(&mut reader).await;
            assert_eq!(contexts["method"], "Target.getBrowserContexts");
            respond(&mut writer, &contexts, json!({"browserContextIds": []})).await;
        }
    }
    let mut byte = [0_u8; 1];
    let closed = tokio::time::timeout(Duration::from_secs(1), reader.read(&mut byte))
        .await
        .expect("CDP writer should close during bounded shutdown")
        .expect("CDP EOF read should succeed");
    assert_eq!(closed, 0);
}

fn identity() -> ChromiumArtifactIdentity {
    let digest =
        Sha256Digest::from_hex(&"11".repeat(32)).expect("test Chromium digest should be valid");
    ChromiumArtifactIdentity {
        binary_digest: digest,
        product_version: "149.0.7827.55".to_owned(),
        chromium_revision: "r1234567".to_owned(),
        browser_protocol_schema_digest: digest,
        js_protocol_schema_digest: digest,
        launch_profile_digest: digest,
        extension_bundle_digest: digest,
        font_bundle_digest: digest,
        certificate_runtime_bundle_digest: digest,
    }
}

fn wait_protocol(
    runtime: &tokio::runtime::Runtime,
    protocol: tokio::task::JoinHandle<()>,
) -> Result<(), tokio::task::JoinError> {
    runtime
        .block_on(async { tokio::time::timeout(Duration::from_secs(2), protocol).await })
        .expect("scripted CDP protocol must finish within the test bound")
}

#[test]
fn production_qualification_bounds_reject_unbounded_phases() {
    assert_eq!(
        ProductionQualificationBounds::new(Duration::ZERO, Duration::from_secs(1)),
        Err(DependencyError::Rejected),
    );
    assert_eq!(
        ProductionQualificationBounds::new(Duration::from_secs(1), Duration::ZERO),
        Err(DependencyError::Rejected),
    );
    assert_eq!(
        ProductionQualificationBounds::new(Duration::from_secs(301), Duration::from_secs(1),),
        Err(DependencyError::Rejected),
    );
    assert_eq!(
        ProductionQualificationBounds::new(Duration::from_secs(1), Duration::from_secs(301),),
        Err(DependencyError::Rejected),
    );
    assert!(
        ProductionQualificationBounds::new(Duration::from_secs(300), Duration::from_secs(300),)
            .is_ok()
    );
}

#[test]
fn readiness_uses_one_absolute_deadline_across_daemon_and_shard_stages() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("test runtime should build");
    let worker_id = WorkerId::new("production-absolute-readiness-deadline")
        .expect("worker identity should be valid");
    let worker_epoch = 43;
    let daemon_epoch = 29;
    let sandbox = Arc::new(DelayedCreateSandbox {
        daemon_epoch,
        daemon_delay: Duration::from_millis(80),
        create_delay: Duration::from_millis(80),
        block_create: false,
        probe_threads: Mutex::new(Vec::new()),
        launches: Mutex::new(Vec::new()),
        cancelled_specs: Mutex::new(Vec::new()),
        claims: AtomicUsize::new(0),
        kills: AtomicUsize::new(0),
    });
    let bounds =
        ProductionQualificationBounds::new(Duration::from_millis(120), Duration::from_millis(200))
            .expect("qualification bounds should be valid");
    let config = ProductionSessionShardConfig::new(
        worker_id,
        worker_epoch,
        daemon_epoch,
        identity(),
        ChromiumConnectionConfig::default(),
        EgressPolicyBinding::new("strict", [12; 32]).expect("egress policy should be valid"),
        Duration::from_secs(30),
    )
    .expect("production shard configuration should be valid")
    .with_qualification_bounds(bounds);
    let factory =
        ProductionSessionShardFactory::new(config, Arc::clone(&sandbox), runtime.handle().clone())
            .expect("multi-thread runtime should be supported");

    let started = Instant::now();
    assert_eq!(factory.qualify_daemon(), Err(DependencyError::Unavailable));
    assert!(
        started.elapsed() < Duration::from_millis(300),
        "the absolute qualification and cleanup bounds must cap the call"
    );
    assert_eq!(sandbox.claims.load(Ordering::SeqCst), 0);
    let launches = sandbox
        .launches
        .lock()
        .expect("launch log should remain available");
    assert_eq!(launches.len(), 1);
    let cancelled_specs = sandbox
        .cancelled_specs
        .lock()
        .expect("cancel log should remain available");
    assert!(!cancelled_specs.is_empty());
    assert!(cancelled_specs.iter().all(|spec| spec == &launches[0]));
}

#[test]
fn readiness_probe_is_owned_outside_the_calling_thread() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("test runtime should build");
    let worker_id = WorkerId::new("production-owned-readiness-flight")
        .expect("worker identity should be valid");
    let worker_epoch = 53;
    let daemon_epoch = 37;
    let sandbox = Arc::new(DelayedCreateSandbox {
        daemon_epoch,
        daemon_delay: Duration::ZERO,
        create_delay: Duration::ZERO,
        block_create: false,
        probe_threads: Mutex::new(Vec::new()),
        launches: Mutex::new(Vec::new()),
        cancelled_specs: Mutex::new(Vec::new()),
        claims: AtomicUsize::new(0),
        kills: AtomicUsize::new(0),
    });
    let config = ProductionSessionShardConfig::new(
        worker_id,
        worker_epoch,
        daemon_epoch,
        identity(),
        ChromiumConnectionConfig::default(),
        EgressPolicyBinding::new("strict", [14; 32]).expect("egress policy should be valid"),
        Duration::from_secs(30),
    )
    .expect("production shard configuration should be valid");
    let factory =
        ProductionSessionShardFactory::new(config, Arc::clone(&sandbox), runtime.handle().clone())
            .expect("multi-thread runtime should be supported");
    let caller_thread = std::thread::current().id();

    assert_eq!(factory.qualify_daemon(), Err(DependencyError::Unavailable));
    let probe_threads = sandbox
        .probe_threads
        .lock()
        .expect("probe thread log should remain available");
    assert_eq!(probe_threads.len(), 1);
    assert_ne!(probe_threads[0], caller_thread);
}

#[test]
fn readiness_timeout_tombstones_a_create_that_never_acknowledges_cancellation() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("test runtime should build");
    let worker_id = WorkerId::new("production-readiness-create-tombstone")
        .expect("worker identity should be valid");
    let worker_epoch = 61;
    let daemon_epoch = 43;
    let sandbox = Arc::new(DelayedCreateSandbox {
        daemon_epoch,
        daemon_delay: Duration::ZERO,
        create_delay: Duration::ZERO,
        block_create: true,
        probe_threads: Mutex::new(Vec::new()),
        launches: Mutex::new(Vec::new()),
        cancelled_specs: Mutex::new(Vec::new()),
        claims: AtomicUsize::new(0),
        kills: AtomicUsize::new(0),
    });
    let bounds =
        ProductionQualificationBounds::new(Duration::from_millis(50), Duration::from_millis(80))
            .expect("qualification bounds should be valid");
    let config = ProductionSessionShardConfig::new(
        worker_id,
        worker_epoch,
        daemon_epoch,
        identity(),
        ChromiumConnectionConfig::default(),
        EgressPolicyBinding::new("strict", [16; 32]).expect("egress policy should be valid"),
        Duration::from_secs(30),
    )
    .expect("production shard configuration should be valid")
    .with_qualification_bounds(bounds);
    let factory =
        ProductionSessionShardFactory::new(config, Arc::clone(&sandbox), runtime.handle().clone())
            .expect("multi-thread runtime should be supported");

    assert_eq!(factory.qualify_daemon(), Err(DependencyError::Unavailable));
    assert_eq!(sandbox.claims.load(Ordering::SeqCst), 0);
    let launches = sandbox
        .launches
        .lock()
        .expect("launch log should remain available");
    assert_eq!(launches.len(), 1);
    let cancelled_specs = sandbox
        .cancelled_specs
        .lock()
        .expect("cancel log should remain available");
    assert!(!cancelled_specs.is_empty());
    assert!(cancelled_specs.iter().all(|spec| spec == &launches[0]));
}

#[test]
fn readiness_deadline_also_bounds_context_disposal() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("test runtime should build");
    let worker_id = WorkerId::new("production-readiness-dispose-deadline")
        .expect("worker identity should be valid");
    let worker_epoch = 47;
    let daemon_epoch = 31;
    let (peer_tx, peer_rx) = oneshot::channel();
    let sandbox = Arc::new(ScriptedSandbox {
        daemon_epoch,
        cancel_delay: Mutex::new(Duration::ZERO),
        peer_termination: None,
        panic_next_cancel: AtomicBool::new(false),
        peers: Mutex::new(VecDeque::from([peer_tx])),
        launches: AtomicUsize::new(0),
        claims: AtomicUsize::new(0),
        renewals: AtomicUsize::new(0),
        kills: AtomicUsize::new(0),
        cancelled_specs: Mutex::new(Vec::new()),
    });
    let bounds =
        ProductionQualificationBounds::new(Duration::from_millis(150), Duration::from_millis(200))
            .expect("qualification bounds should be valid");
    let config = ProductionSessionShardConfig::new(
        worker_id,
        worker_epoch,
        daemon_epoch,
        identity(),
        ChromiumConnectionConfig::default(),
        EgressPolicyBinding::new("strict", [13; 32]).expect("egress policy should be valid"),
        Duration::from_secs(30),
    )
    .expect("production shard configuration should be valid")
    .with_qualification_bounds(bounds);
    let factory =
        ProductionSessionShardFactory::new(config, Arc::clone(&sandbox), runtime.handle().clone())
            .expect("multi-thread runtime should be supported");
    let protocol = runtime.spawn(run_scripted_protocol(
        peer_rx,
        CleanupProbe::DelayedDispose(Duration::from_millis(500)),
    ));

    let started = Instant::now();
    assert_eq!(
        factory.qualify_daemon(),
        Err(DependencyError::OutcomeUncertain)
    );
    assert!(
        started.elapsed() < Duration::from_millis(400),
        "context disposal must share the original qualification deadline"
    );
    assert_eq!(sandbox.launches.load(Ordering::SeqCst), 1);
    assert_eq!(sandbox.claims.load(Ordering::SeqCst), 1);
    assert!(sandbox.kills.load(Ordering::SeqCst) >= 1);
    protocol.abort();
    let _ = wait_protocol(&runtime, protocol);
}

#[test]
fn readiness_deadline_also_bounds_orphan_verification() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("test runtime should build");
    let worker_id = WorkerId::new("production-readiness-verification-deadline")
        .expect("worker identity should be valid");
    let worker_epoch = 59;
    let daemon_epoch = 41;
    let (peer_tx, peer_rx) = oneshot::channel();
    let sandbox = Arc::new(ScriptedSandbox {
        daemon_epoch,
        cancel_delay: Mutex::new(Duration::ZERO),
        peer_termination: None,
        panic_next_cancel: AtomicBool::new(false),
        peers: Mutex::new(VecDeque::from([peer_tx])),
        launches: AtomicUsize::new(0),
        claims: AtomicUsize::new(0),
        renewals: AtomicUsize::new(0),
        kills: AtomicUsize::new(0),
        cancelled_specs: Mutex::new(Vec::new()),
    });
    let bounds =
        ProductionQualificationBounds::new(Duration::from_millis(150), Duration::from_millis(200))
            .expect("qualification bounds should be valid");
    let config = ProductionSessionShardConfig::new(
        worker_id,
        worker_epoch,
        daemon_epoch,
        identity(),
        ChromiumConnectionConfig::default(),
        EgressPolicyBinding::new("strict", [15; 32]).expect("egress policy should be valid"),
        Duration::from_secs(30),
    )
    .expect("production shard configuration should be valid")
    .with_qualification_bounds(bounds);
    let factory =
        ProductionSessionShardFactory::new(config, Arc::clone(&sandbox), runtime.handle().clone())
            .expect("multi-thread runtime should be supported");
    let protocol = runtime.spawn(run_scripted_protocol(
        peer_rx,
        CleanupProbe::DelayedVerify(Duration::from_millis(500)),
    ));

    let started = Instant::now();
    assert_eq!(
        factory.qualify_daemon(),
        Err(DependencyError::OutcomeUncertain)
    );
    assert!(
        started.elapsed() < Duration::from_millis(400),
        "orphan verification must share the original qualification deadline"
    );
    assert_eq!(sandbox.launches.load(Ordering::SeqCst), 1);
    assert_eq!(sandbox.claims.load(Ordering::SeqCst), 1);
    assert!(sandbox.kills.load(Ordering::SeqCst) >= 1);
    protocol.abort();
    let _ = wait_protocol(&runtime, protocol);
}

#[test]
fn failed_readiness_connection_claim_cleans_the_exact_probe_shard() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("test runtime should build");
    let worker_id =
        WorkerId::new("production-shard-factory-worker").expect("worker identity should be valid");
    let worker_epoch = 19;
    let daemon_epoch = 7;
    let sandbox = Arc::new(FailingSandbox {
        daemon_epoch,
        launches: Mutex::new(Vec::new()),
        cancelled_specs: Mutex::new(Vec::new()),
        claims: AtomicUsize::new(0),
        kills: AtomicUsize::new(0),
    });
    let config = ProductionSessionShardConfig::new(
        worker_id.clone(),
        worker_epoch,
        daemon_epoch,
        identity(),
        ChromiumConnectionConfig::default(),
        EgressPolicyBinding::new("strict", [9; 32]).expect("egress policy should be valid"),
        Duration::from_secs(30),
    )
    .expect("production shard configuration should be valid");
    let factory =
        ProductionSessionShardFactory::new(config, Arc::clone(&sandbox), runtime.handle().clone())
            .expect("multi-thread runtime should be supported");
    assert_eq!(factory.qualify_daemon(), Err(DependencyError::Unavailable));

    let launches = sandbox
        .launches
        .lock()
        .expect("launch log should remain available");
    assert_eq!(launches.len(), 1);
    let launch = launches[0].clone();
    assert_eq!(launch.worker_id(), &worker_id);
    assert_eq!(launch.worker_epoch(), worker_epoch);
    assert_eq!(
        launch.chromium_binary_digest(),
        ChromiumBinaryDigest::new([0x11; 32]),
    );
    assert_eq!(
        launch
            .dedicated_egress()
            .egress_fence()
            .session_incarnation()
            .get(),
        1
    );
    drop(launches);
    assert_eq!(
        sandbox
            .cancelled_specs
            .lock()
            .expect("cancel log should remain available")
            .as_slice(),
        [launch],
        "all cleanup owners must share the exact qualified launch proof"
    );
    assert_eq!(sandbox.claims.load(Ordering::SeqCst), 1);
    assert_eq!(
        sandbox.kills.load(Ordering::SeqCst),
        1,
        "failed activation cleanup and actor shutdown must share one exact cleanup flight"
    );
}

#[test]
fn production_admission_stays_closed_until_real_readiness_qualification_succeeds() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("test runtime should build");
    let worker_id =
        WorkerId::new("production-unqualified-factory").expect("worker identity should be valid");
    let worker_epoch = 29;
    let daemon_epoch = 13;
    let sandbox = Arc::new(FailingSandbox {
        daemon_epoch,
        launches: Mutex::new(Vec::new()),
        cancelled_specs: Mutex::new(Vec::new()),
        claims: AtomicUsize::new(0),
        kills: AtomicUsize::new(0),
    });
    let config = ProductionSessionShardConfig::new(
        worker_id.clone(),
        worker_epoch,
        daemon_epoch,
        identity(),
        ChromiumConnectionConfig::default(),
        EgressPolicyBinding::new("strict", [5; 32]).expect("egress policy should be valid"),
        Duration::from_secs(30),
    )
    .expect("production shard configuration should be valid");
    let factory =
        ProductionSessionShardFactory::new(config, Arc::clone(&sandbox), runtime.handle().clone())
            .expect("multi-thread runtime should be supported");
    let fence = OwnershipFence::new(worker_id, worker_epoch, 1, 1);

    assert!(matches!(
        factory.create(&TenantId::new(), &SessionId::new(), &fence),
        Err(DependencyError::Rejected)
    ));
    assert!(
        sandbox
            .launches
            .lock()
            .expect("launch log should remain available")
            .is_empty()
    );
    assert_eq!(sandbox.claims.load(Ordering::SeqCst), 0);
    assert_eq!(sandbox.kills.load(Ordering::SeqCst), 0);
}

#[test]
fn unsupported_session_options_are_rejected_before_sandbox_effect() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("test runtime should build");
    let worker_id = WorkerId::new("production-network-policy-binding")
        .expect("worker identity should be valid");
    let worker_epoch = 31;
    let daemon_epoch = 17;
    let (readiness_peer_tx, readiness_peer_rx) = oneshot::channel();
    let sandbox = Arc::new(ScriptedSandbox {
        daemon_epoch,
        cancel_delay: Mutex::new(Duration::ZERO),
        peer_termination: None,
        panic_next_cancel: AtomicBool::new(false),
        peers: Mutex::new(VecDeque::from([readiness_peer_tx])),
        launches: AtomicUsize::new(0),
        claims: AtomicUsize::new(0),
        renewals: AtomicUsize::new(0),
        kills: AtomicUsize::new(0),
        cancelled_specs: Mutex::new(Vec::new()),
    });
    let config = ProductionSessionShardConfig::new(
        worker_id.clone(),
        worker_epoch,
        daemon_epoch,
        identity(),
        ChromiumConnectionConfig::default(),
        EgressPolicyBinding::new("strict", [25; 32]).expect("egress policy should be valid"),
        Duration::from_secs(30),
    )
    .expect("production shard configuration should be valid");
    let factory =
        ProductionSessionShardFactory::new(config, Arc::clone(&sandbox), runtime.handle().clone())
            .expect("multi-thread runtime should be supported");
    let readiness_protocol = runtime.spawn(run_scripted_protocol(
        readiness_peer_rx,
        CleanupProbe::Clean,
    ));
    assert_eq!(factory.qualify_daemon(), Ok(()));
    wait_protocol(&runtime, readiness_protocol).expect("readiness peer should not panic");
    let effects_before = (
        sandbox.launches.load(Ordering::SeqCst),
        sandbox.claims.load(Ordering::SeqCst),
        sandbox.kills.load(Ordering::SeqCst),
    );
    let options = WorkerSessionOptionsV1 {
        workload_class_hint: "interactive".to_owned(),
        viewport: WorkerViewport {
            width: 1_280,
            height: 720,
            device_scale_factor: 1,
        },
        locale: "ko-KR".to_owned(),
        timezone: "Asia/Seoul".to_owned(),
        user_agent: None,
        network_policy_id: "strict".to_owned(),
        network_class: "public".to_owned(),
        checkpoint_ref: None,
        dialog_policy: "auto_dismiss".to_owned(),
        feature_profile: "standard".to_owned(),
        ttl_seconds: 1_800,
        idle_timeout_seconds: 600,
        metadata: Default::default(),
    };
    let mut policy_mismatch = options.clone();
    policy_mismatch.network_policy_id = "different-policy".to_owned();
    let mut unsupported_network_class = options.clone();
    unsupported_network_class.network_class = "private".to_owned();
    let mut unsupported_checkpoint = options.clone();
    unsupported_checkpoint.checkpoint_ref = Some("checkpoint-1".to_owned());
    let mut unsupported_dialog = options.clone();
    unsupported_dialog.dialog_policy = "hold".to_owned();
    let mut unsupported_feature = options.clone();
    unsupported_feature.feature_profile = "privileged".to_owned();
    let mut invalid = options;
    invalid.locale.clear();
    let fence = OwnershipFence::new(worker_id, worker_epoch, 3, 1);

    for (case, options) in [
        ("network policy mismatch", policy_mismatch),
        ("unsupported network class", unsupported_network_class),
        ("unsupported checkpoint", unsupported_checkpoint),
        ("unsupported dialog policy", unsupported_dialog),
        ("unsupported feature profile", unsupported_feature),
        ("invalid options", invalid),
    ] {
        assert!(
            matches!(
                factory.create_with_options(&TenantId::new(), &SessionId::new(), &fence, &options,),
                Err(DependencyError::Rejected)
            ),
            "{case} must be rejected"
        );
        assert_eq!(
            (
                sandbox.launches.load(Ordering::SeqCst),
                sandbox.claims.load(Ordering::SeqCst),
                sandbox.kills.load(Ordering::SeqCst),
            ),
            effects_before,
            "{case} must not launch, claim, or clean a sandbox"
        );
    }
}

#[test]
fn production_factory_rejects_a_current_thread_runtime_before_sandbox_effects() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("current-thread runtime should build");
    let worker_id =
        WorkerId::new("unsupported-current-thread").expect("worker identity should be valid");
    let sandbox = Arc::new(FailingSandbox {
        daemon_epoch: 5,
        launches: Mutex::new(Vec::new()),
        cancelled_specs: Mutex::new(Vec::new()),
        claims: AtomicUsize::new(0),
        kills: AtomicUsize::new(0),
    });
    let config = ProductionSessionShardConfig::new(
        worker_id,
        7,
        5,
        identity(),
        ChromiumConnectionConfig::default(),
        EgressPolicyBinding::new("strict", [31; 32]).expect("egress policy should be valid"),
        Duration::from_secs(30),
    )
    .expect("production shard configuration should be valid");

    let factory =
        ProductionSessionShardFactory::new(config, Arc::clone(&sandbox), runtime.handle().clone());

    assert!(matches!(factory, Err(DependencyError::Rejected)));
    assert!(
        sandbox
            .launches
            .lock()
            .expect("launch log should remain available")
            .is_empty()
    );
}

#[test]
fn readiness_qualification_runs_a_real_shard_and_caches_failure() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("test runtime should build");
    let worker_id =
        WorkerId::new("production-readiness-failure").expect("worker identity should be valid");
    let worker_epoch = 31;
    let daemon_epoch = 17;
    let sandbox = Arc::new(FailingSandbox {
        daemon_epoch,
        launches: Mutex::new(Vec::new()),
        cancelled_specs: Mutex::new(Vec::new()),
        claims: AtomicUsize::new(0),
        kills: AtomicUsize::new(0),
    });
    let config = ProductionSessionShardConfig::new(
        worker_id,
        worker_epoch,
        daemon_epoch,
        identity(),
        ChromiumConnectionConfig::default(),
        EgressPolicyBinding::new("strict", [6; 32]).expect("egress policy should be valid"),
        Duration::from_secs(30),
    )
    .expect("production shard configuration should be valid");
    let factory =
        ProductionSessionShardFactory::new(config, Arc::clone(&sandbox), runtime.handle().clone())
            .expect("multi-thread runtime should be supported");

    assert_eq!(factory.qualify_daemon(), Err(DependencyError::Unavailable));
    assert_eq!(factory.qualify_daemon(), Err(DependencyError::Unavailable));
    assert_eq!(
        sandbox
            .launches
            .lock()
            .expect("launch log should remain available")
            .len(),
        1,
    );
    assert_eq!(sandbox.claims.load(Ordering::SeqCst), 1);
    assert_eq!(sandbox.kills.load(Ordering::SeqCst), 1);
}

#[test]
fn concurrent_readiness_callers_share_one_probe_and_one_cleanup() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("test runtime should build");
    let worker_id =
        WorkerId::new("production-concurrent-readiness").expect("worker identity should be valid");
    let worker_epoch = 37;
    let daemon_epoch = 19;
    let (peer_tx, peer_rx) = oneshot::channel();
    let sandbox = Arc::new(ScriptedSandbox {
        daemon_epoch,
        cancel_delay: Mutex::new(Duration::ZERO),
        peer_termination: None,
        panic_next_cancel: AtomicBool::new(false),
        peers: Mutex::new(VecDeque::from([peer_tx])),
        launches: AtomicUsize::new(0),
        claims: AtomicUsize::new(0),
        renewals: AtomicUsize::new(0),
        kills: AtomicUsize::new(0),
        cancelled_specs: Mutex::new(Vec::new()),
    });
    let config = ProductionSessionShardConfig::new(
        worker_id,
        worker_epoch,
        daemon_epoch,
        identity(),
        ChromiumConnectionConfig::default(),
        EgressPolicyBinding::new("strict", [8; 32]).expect("egress policy should be valid"),
        Duration::from_secs(30),
    )
    .expect("production shard configuration should be valid");
    let factory = Arc::new(
        ProductionSessionShardFactory::new(config, Arc::clone(&sandbox), runtime.handle().clone())
            .expect("multi-thread runtime should be supported"),
    );
    let protocol = runtime.spawn(run_scripted_protocol(peer_rx, CleanupProbe::Clean));
    let barrier = Arc::new(Barrier::new(3));
    let callers = (0..2)
        .map(|_| {
            let factory = Arc::clone(&factory);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                factory.qualify_daemon()
            })
        })
        .collect::<Vec<_>>();
    barrier.wait();

    for caller in callers {
        assert_eq!(
            caller.join().expect("readiness caller should not panic"),
            Ok(())
        );
    }
    wait_protocol(&runtime, protocol).expect("readiness CDP peer should not panic");
    assert_eq!(sandbox.launches.load(Ordering::SeqCst), 1);
    assert_eq!(sandbox.claims.load(Ordering::SeqCst), 1);
    assert_eq!(
        sandbox.kills.load(Ordering::SeqCst),
        1,
        "lifecycle and runtime cleanup owners must share the probe shard terminal proof"
    );
}

#[test]
fn readiness_rejects_and_caches_an_orphaned_context_target() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("test runtime should build");
    let worker_id =
        WorkerId::new("production-orphan-readiness").expect("worker identity should be valid");
    let worker_epoch = 41;
    let daemon_epoch = 23;
    let (peer_tx, peer_rx) = oneshot::channel();
    let sandbox = Arc::new(ScriptedSandbox {
        daemon_epoch,
        cancel_delay: Mutex::new(Duration::ZERO),
        peer_termination: None,
        panic_next_cancel: AtomicBool::new(false),
        peers: Mutex::new(VecDeque::from([peer_tx])),
        launches: AtomicUsize::new(0),
        claims: AtomicUsize::new(0),
        renewals: AtomicUsize::new(0),
        kills: AtomicUsize::new(0),
        cancelled_specs: Mutex::new(Vec::new()),
    });
    let config = ProductionSessionShardConfig::new(
        worker_id,
        worker_epoch,
        daemon_epoch,
        identity(),
        ChromiumConnectionConfig::default(),
        EgressPolicyBinding::new("strict", [10; 32]).expect("egress policy should be valid"),
        Duration::from_secs(30),
    )
    .expect("production shard configuration should be valid");
    let factory =
        ProductionSessionShardFactory::new(config, Arc::clone(&sandbox), runtime.handle().clone())
            .expect("multi-thread runtime should be supported");
    let protocol = runtime.spawn(run_scripted_protocol(peer_rx, CleanupProbe::OrphanTarget));

    assert_eq!(
        factory.qualify_daemon(),
        Err(DependencyError::OutcomeUncertain)
    );
    assert_eq!(
        factory.qualify_daemon(),
        Err(DependencyError::OutcomeUncertain)
    );
    wait_protocol(&runtime, protocol).expect("orphaned cleanup CDP peer should not panic");
    assert_eq!(sandbox.launches.load(Ordering::SeqCst), 1);
    assert_eq!(sandbox.claims.load(Ordering::SeqCst), 1);
    assert_eq!(
        sandbox.kills.load(Ordering::SeqCst),
        1,
        "lifecycle and runtime cleanup owners must share the probe shard terminal proof"
    );
}

#[test]
fn cleanup_deadline_caches_uncertainty_without_aborting_owned_cleanup() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("test runtime should build");
    let worker_id = WorkerId::new("production-readiness-cleanup-deadline")
        .expect("worker identity should be valid");
    let worker_epoch = 67;
    let daemon_epoch = 47;
    let (peer_tx, peer_rx) = oneshot::channel();
    let sandbox = Arc::new(ScriptedSandbox {
        daemon_epoch,
        cancel_delay: Mutex::new(Duration::from_millis(250)),
        peer_termination: None,
        panic_next_cancel: AtomicBool::new(false),
        peers: Mutex::new(VecDeque::from([peer_tx])),
        launches: AtomicUsize::new(0),
        claims: AtomicUsize::new(0),
        renewals: AtomicUsize::new(0),
        kills: AtomicUsize::new(0),
        cancelled_specs: Mutex::new(Vec::new()),
    });
    let bounds =
        ProductionQualificationBounds::new(Duration::from_secs(1), Duration::from_millis(80))
            .expect("qualification bounds should be valid");
    let config = ProductionSessionShardConfig::new(
        worker_id,
        worker_epoch,
        daemon_epoch,
        identity(),
        ChromiumConnectionConfig::default(),
        EgressPolicyBinding::new("strict", [17; 32]).expect("egress policy should be valid"),
        Duration::from_secs(30),
    )
    .expect("production shard configuration should be valid")
    .with_qualification_bounds(bounds);
    let factory =
        ProductionSessionShardFactory::new(config, Arc::clone(&sandbox), runtime.handle().clone())
            .expect("multi-thread runtime should be supported");
    let protocol = runtime.spawn(run_scripted_protocol(peer_rx, CleanupProbe::Clean));

    assert_eq!(
        factory.qualify_daemon(),
        Err(DependencyError::OutcomeUncertain)
    );
    assert_eq!(
        sandbox.kills.load(Ordering::SeqCst),
        0,
        "the cleanup wait deadline must publish before the owned exact cleanup finishes",
    );
    assert_eq!(sandbox.launches.load(Ordering::SeqCst), 1);
    assert!(
        !sandbox
            .cancelled_specs
            .lock()
            .expect("cancel log should remain available")
            .is_empty(),
        "exact cleanup must start before the cleanup wait deadline"
    );
    assert_eq!(
        factory.qualify_daemon(),
        Err(DependencyError::OutcomeUncertain)
    );
    assert_eq!(sandbox.kills.load(Ordering::SeqCst), 0);
    assert_eq!(sandbox.launches.load(Ordering::SeqCst), 1);

    wait_protocol(&runtime, protocol)
        .expect("owned cleanup must eventually close the readiness CDP peer");
    assert_eq!(sandbox.kills.load(Ordering::SeqCst), 1);
    assert_eq!(
        factory.qualify_daemon(),
        Err(DependencyError::OutcomeUncertain),
        "late cleanup success must not upgrade the published terminal result"
    );
}

#[test]
fn readiness_cleanup_accepts_eof_after_exact_kill_closes_the_cdp_peer() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("test runtime should build");
    let worker_id = WorkerId::new("production-readiness-exact-kill-eof")
        .expect("worker identity should be valid");
    let worker_epoch = 71;
    let daemon_epoch = 53;
    let (peer_tx, peer_rx) = oneshot::channel();
    let peer_termination = PeerTermination {
        kill: CancellationToken::new(),
        closed: CancellationToken::new(),
    };
    let sandbox = Arc::new(ScriptedSandbox {
        daemon_epoch,
        cancel_delay: Mutex::new(Duration::from_millis(100)),
        peer_termination: Some(peer_termination.clone()),
        panic_next_cancel: AtomicBool::new(false),
        peers: Mutex::new(VecDeque::from([peer_tx])),
        launches: AtomicUsize::new(0),
        claims: AtomicUsize::new(0),
        renewals: AtomicUsize::new(0),
        kills: AtomicUsize::new(0),
        cancelled_specs: Mutex::new(Vec::new()),
    });
    let bounds = ProductionQualificationBounds::new(Duration::from_secs(1), Duration::from_secs(1))
        .expect("qualification bounds should be valid");
    let config = ProductionSessionShardConfig::new(
        worker_id,
        worker_epoch,
        daemon_epoch,
        identity(),
        ChromiumConnectionConfig::default(),
        EgressPolicyBinding::new("strict", [18; 32]).expect("egress policy should be valid"),
        Duration::from_secs(30),
    )
    .expect("production shard configuration should be valid")
    .with_qualification_bounds(bounds);
    let factory =
        ProductionSessionShardFactory::new(config, Arc::clone(&sandbox), runtime.handle().clone())
            .expect("multi-thread runtime should be supported");
    let protocol = runtime.spawn(run_killable_scripted_protocol(
        peer_rx,
        CleanupProbe::Clean,
        peer_termination,
    ));

    let started = Instant::now();
    assert_eq!(factory.qualify_daemon(), Ok(()));
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "exact shard termination must not wait for a dead CDP transport timeout"
    );
    wait_protocol(&runtime, protocol)
        .expect("the exact kill must close and join the scripted CDP peer");
    assert_eq!(sandbox.kills.load(Ordering::SeqCst), 1);
}

#[test]
fn owned_exact_cleanup_panic_releases_waiters_with_one_terminal_result() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("test runtime should build");
    let worker_id =
        WorkerId::new("production-lifecycle-panic").expect("worker identity should be valid");
    let worker_epoch = 73;
    let daemon_epoch = 59;
    let (readiness_peer_tx, readiness_peer_rx) = oneshot::channel();
    let (session_peer_tx, session_peer_rx) = oneshot::channel();
    let sandbox = Arc::new(ScriptedSandbox {
        daemon_epoch,
        cancel_delay: Mutex::new(Duration::ZERO),
        peer_termination: None,
        panic_next_cancel: AtomicBool::new(false),
        peers: Mutex::new(VecDeque::from([readiness_peer_tx, session_peer_tx])),
        launches: AtomicUsize::new(0),
        claims: AtomicUsize::new(0),
        renewals: AtomicUsize::new(0),
        kills: AtomicUsize::new(0),
        cancelled_specs: Mutex::new(Vec::new()),
    });
    let config = ProductionSessionShardConfig::new(
        worker_id.clone(),
        worker_epoch,
        daemon_epoch,
        identity(),
        ChromiumConnectionConfig::default(),
        EgressPolicyBinding::new("strict", [19; 32]).expect("egress policy should be valid"),
        Duration::from_secs(30),
    )
    .expect("production shard configuration should be valid");
    let production_factory = Arc::new(
        ProductionSessionShardFactory::new(config, Arc::clone(&sandbox), runtime.handle().clone())
            .expect("multi-thread runtime should be supported"),
    );
    let readiness_protocol = runtime.spawn(run_scripted_protocol(
        readiness_peer_rx,
        CleanupProbe::Clean,
    ));
    assert_eq!(production_factory.qualify_daemon(), Ok(()));
    wait_protocol(&runtime, readiness_protocol).expect("readiness CDP peer should not panic");

    let tenant_id = TenantId::new();
    let session_id = SessionId::new();
    let fence = OwnershipFence::new(worker_id.clone(), worker_epoch, 5, 7);
    let session_protocol = runtime.spawn(run_scripted_protocol(
        session_peer_rx,
        CleanupProbe::DisposeOnly,
    ));
    let shard = production_factory
        .create(&tenant_id, &session_id, &fence)
        .expect("production session shard should provision");
    let fixed_factory = Arc::new(FixedShardFactory { shard });
    let router_a = SessionShardRouter::new(
        worker_id.clone(),
        worker_epoch,
        Arc::clone(&fixed_factory),
        Arc::new(RejectArtifacts),
        1,
    )
    .expect("first router should be valid");
    let router_b = Arc::new(
        SessionShardRouter::new(
            worker_id.clone(),
            worker_epoch,
            fixed_factory,
            Arc::new(RejectArtifacts),
            1,
        )
        .expect("second router should be valid"),
    );
    assert!(
        router_a
            .create_context_owned(&tenant_id, &session_id, &fence)
            .is_ok()
    );
    assert!(
        router_b
            .create_context_owned(&tenant_id, &session_id, &fence)
            .is_ok()
    );
    sandbox.panic_next_cancel.store(true, Ordering::Release);

    let first = catch_unwind(AssertUnwindSafe(|| {
        router_a.close_context_fenced(&session_id, &fence)
    }));
    let (second_sender, second_receiver) = mpsc::sync_channel(1);
    let second_session = session_id.clone();
    let second_fence = fence.clone();
    let second = std::thread::spawn(move || {
        let result = router_b.close_context_fenced(&second_session, &second_fence);
        let _ = second_sender.send(result);
    });
    let second_result = second_receiver.recv_timeout(Duration::from_millis(500));
    if second_result.is_ok() {
        second.join().expect("late lifecycle waiter should join");
    }
    wait_protocol(&runtime, session_protocol).expect("session CDP peer should not panic");

    let first_result = first.expect("owned exact cleanup panic must not escape the lifecycle");
    assert!(matches!(
        first_result,
        Ok(()) | Err(DependencyError::OutcomeUncertain)
    ));
    assert_eq!(
        second_result,
        Ok(first_result),
        "a cleanup panic must publish one shared terminal result"
    );
}

#[test]
fn session_cleanup_deadline_publishes_before_an_owned_exact_rpc_finishes() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("test runtime should build");
    let worker_id = WorkerId::new("production-session-cleanup-deadline")
        .expect("worker identity should be valid");
    let worker_epoch = 79;
    let daemon_epoch = 61;
    let (readiness_peer_tx, readiness_peer_rx) = oneshot::channel();
    let (session_peer_tx, session_peer_rx) = oneshot::channel();
    let sandbox = Arc::new(ScriptedSandbox {
        daemon_epoch,
        cancel_delay: Mutex::new(Duration::ZERO),
        peer_termination: None,
        panic_next_cancel: AtomicBool::new(false),
        peers: Mutex::new(VecDeque::from([readiness_peer_tx, session_peer_tx])),
        launches: AtomicUsize::new(0),
        claims: AtomicUsize::new(0),
        renewals: AtomicUsize::new(0),
        kills: AtomicUsize::new(0),
        cancelled_specs: Mutex::new(Vec::new()),
    });
    let bounds =
        ProductionQualificationBounds::new(Duration::from_secs(1), Duration::from_millis(80))
            .expect("qualification bounds should be valid");
    let config = ProductionSessionShardConfig::new(
        worker_id.clone(),
        worker_epoch,
        daemon_epoch,
        identity(),
        ChromiumConnectionConfig::default(),
        EgressPolicyBinding::new("strict", [23; 32]).expect("egress policy should be valid"),
        Duration::from_secs(30),
    )
    .expect("production shard configuration should be valid")
    .with_qualification_bounds(bounds);
    let factory = Arc::new(
        ProductionSessionShardFactory::new(config, Arc::clone(&sandbox), runtime.handle().clone())
            .expect("multi-thread runtime should be supported"),
    );
    let readiness_protocol = runtime.spawn(run_scripted_protocol(
        readiness_peer_rx,
        CleanupProbe::Clean,
    ));
    assert_eq!(factory.qualify_daemon(), Ok(()));
    wait_protocol(&runtime, readiness_protocol).expect("readiness peer should not panic");
    assert_eq!(sandbox.kills.load(Ordering::SeqCst), 1);
    *sandbox
        .cancel_delay
        .lock()
        .expect("cancel delay should remain available") = Duration::from_millis(250);

    let router = Arc::new(
        SessionShardRouter::new(
            worker_id.clone(),
            worker_epoch,
            factory,
            Arc::new(RejectArtifacts),
            1,
        )
        .expect("session shard router should be valid"),
    );
    let session_protocol = runtime.spawn(run_scripted_protocol(
        session_peer_rx,
        CleanupProbe::ForcedClose,
    ));
    let tenant_id = TenantId::new();
    let session_id = SessionId::new();
    let fence = OwnershipFence::new(worker_id, worker_epoch, 8, 9);
    assert!(
        router
            .create_context_owned(&tenant_id, &session_id, &fence)
            .is_ok()
    );

    assert_eq!(
        router.close_context_fenced(&session_id, &fence),
        Err(DependencyError::OutcomeUncertain),
    );
    assert_eq!(
        sandbox.kills.load(Ordering::SeqCst),
        1,
        "the close deadline must publish while exact cleanup remains owned in the background",
    );
    assert_eq!(
        router.close_context_fenced(&session_id, &fence),
        Err(DependencyError::OutcomeUncertain),
    );
    wait_protocol(&runtime, session_protocol).expect("session peer should not panic");
    assert_eq!(sandbox.kills.load(Ordering::SeqCst), 2);
}

#[test]
fn runtime_owned_concurrent_closes_do_not_starve_cleanup() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("test runtime should build");
    let worker_id =
        WorkerId::new("production-runtime-close").expect("worker identity should be valid");
    let worker_epoch = 83;
    let daemon_epoch = 67;
    let (readiness_peer_tx, readiness_peer_rx) = oneshot::channel();
    let (first_peer_tx, first_peer_rx) = oneshot::channel();
    let (second_peer_tx, second_peer_rx) = oneshot::channel();
    let sandbox = Arc::new(ScriptedSandbox {
        daemon_epoch,
        cancel_delay: Mutex::new(Duration::ZERO),
        peer_termination: None,
        panic_next_cancel: AtomicBool::new(false),
        peers: Mutex::new(VecDeque::from([
            readiness_peer_tx,
            first_peer_tx,
            second_peer_tx,
        ])),
        launches: AtomicUsize::new(0),
        claims: AtomicUsize::new(0),
        renewals: AtomicUsize::new(0),
        kills: AtomicUsize::new(0),
        cancelled_specs: Mutex::new(Vec::new()),
    });
    let bounds = ProductionQualificationBounds::new(Duration::from_secs(1), Duration::from_secs(1))
        .expect("qualification bounds should be valid");
    let config = ProductionSessionShardConfig::new(
        worker_id.clone(),
        worker_epoch,
        daemon_epoch,
        identity(),
        ChromiumConnectionConfig::default(),
        EgressPolicyBinding::new("strict", [29; 32]).expect("egress policy should be valid"),
        Duration::from_secs(30),
    )
    .expect("production shard configuration should be valid")
    .with_qualification_bounds(bounds);
    let factory = Arc::new(
        ProductionSessionShardFactory::new(config, Arc::clone(&sandbox), runtime.handle().clone())
            .expect("multi-thread runtime should be supported"),
    );
    let readiness_protocol = runtime.spawn(run_scripted_protocol(
        readiness_peer_rx,
        CleanupProbe::Clean,
    ));
    assert_eq!(factory.qualify_daemon(), Ok(()));
    wait_protocol(&runtime, readiness_protocol).expect("readiness peer should not panic");
    *sandbox
        .cancel_delay
        .lock()
        .expect("cancel delay should remain available") = Duration::from_millis(100);

    let router = Arc::new(
        SessionShardRouter::new(
            worker_id.clone(),
            worker_epoch,
            factory,
            Arc::new(RejectArtifacts),
            2,
        )
        .expect("session shard router should be valid"),
    );
    let first_protocol = runtime.spawn(run_scripted_protocol(
        first_peer_rx,
        CleanupProbe::ForcedClose,
    ));
    let second_protocol = runtime.spawn(run_scripted_protocol(
        second_peer_rx,
        CleanupProbe::ForcedClose,
    ));
    let tenant_id = TenantId::new();
    let first_session = SessionId::new();
    let second_session = SessionId::new();
    let first_fence = OwnershipFence::new(worker_id.clone(), worker_epoch, 10, 11);
    let second_fence = OwnershipFence::new(worker_id, worker_epoch, 12, 13);
    assert!(
        router
            .create_context_owned(&tenant_id, &first_session, &first_fence)
            .is_ok()
    );
    assert!(
        router
            .create_context_owned(&tenant_id, &second_session, &second_fence)
            .is_ok()
    );

    let (close_sender, close_receiver) = mpsc::sync_channel(2);
    let first_router = Arc::clone(&router);
    let first_sender = close_sender.clone();
    let first_close = runtime.spawn(async move {
        let result = first_router.close_context_fenced(&first_session, &first_fence);
        let _ = first_sender.send(result);
    });
    let second_router = Arc::clone(&router);
    let second_close = runtime.spawn(async move {
        let result = second_router.close_context_fenced(&second_session, &second_fence);
        let _ = close_sender.send(result);
    });
    let first_result = match close_receiver.recv_timeout(Duration::from_secs(1)) {
        Ok(result) => result,
        Err(error) => {
            drop(first_close);
            drop(second_close);
            runtime.shutdown_background();
            panic!("runtime-owned closes must not starve cleanup: {error}");
        }
    };
    let second_result = match close_receiver.recv_timeout(Duration::from_secs(1)) {
        Ok(result) => result,
        Err(error) => {
            drop(first_close);
            drop(second_close);
            runtime.shutdown_background();
            panic!("runtime-owned closes must all finish cleanup: {error}");
        }
    };
    assert_eq!(first_result, Ok(()));
    assert_eq!(second_result, Ok(()));
    runtime
        .block_on(first_close)
        .expect("first runtime-owned close caller should not panic");
    runtime
        .block_on(second_close)
        .expect("second runtime-owned close caller should not panic");
    wait_protocol(&runtime, first_protocol).expect("first session peer should not panic");
    wait_protocol(&runtime, second_protocol).expect("second session peer should not panic");
    assert_eq!(sandbox.kills.load(Ordering::SeqCst), 3);
}

#[test]
fn successful_shard_owns_cdp_bootstrap_lease_and_bounded_shutdown() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("test runtime should build");
    let worker_id =
        WorkerId::new("production-shard-success").expect("worker identity should be valid");
    let worker_epoch = 23;
    let daemon_epoch = 11;
    let (readiness_peer_tx, readiness_peer_rx) = oneshot::channel();
    let (session_peer_tx, session_peer_rx) = oneshot::channel();
    let sandbox = Arc::new(ScriptedSandbox {
        daemon_epoch,
        cancel_delay: Mutex::new(Duration::ZERO),
        peer_termination: None,
        panic_next_cancel: AtomicBool::new(false),
        peers: Mutex::new(VecDeque::from([readiness_peer_tx, session_peer_tx])),
        launches: AtomicUsize::new(0),
        claims: AtomicUsize::new(0),
        renewals: AtomicUsize::new(0),
        kills: AtomicUsize::new(0),
        cancelled_specs: Mutex::new(Vec::new()),
    });
    let connection = ChromiumConnectionConfig {
        transport: CdpTransportConfig {
            max_frame_bytes: 64 * 1024,
            max_pending_commands: 16,
            command_queue_capacity: 16,
            event_queue_capacity: 16,
            write_timeout: Duration::from_millis(500),
            default_command_timeout: Duration::from_millis(500),
        },
        version_probe_timeout: Duration::from_millis(500),
        max_version_field_bytes: 1_024,
    };
    let config = ProductionSessionShardConfig::new(
        worker_id.clone(),
        worker_epoch,
        daemon_epoch,
        identity(),
        connection,
        EgressPolicyBinding::new("strict", [7; 32]).expect("egress policy should be valid"),
        Duration::from_secs(30),
    )
    .expect("production shard configuration should be valid");
    let factory = Arc::new(
        ProductionSessionShardFactory::new(config, Arc::clone(&sandbox), runtime.handle().clone())
            .expect("multi-thread runtime should be supported"),
    );
    let readiness_protocol = runtime.spawn(run_scripted_protocol(
        readiness_peer_rx,
        CleanupProbe::Clean,
    ));
    assert_eq!(factory.qualify_daemon(), Ok(()));
    assert_eq!(factory.qualify_daemon(), Ok(()));
    wait_protocol(&runtime, readiness_protocol).expect("readiness CDP peer should not panic");
    assert_eq!(sandbox.launches.load(Ordering::SeqCst), 1);
    assert_eq!(sandbox.claims.load(Ordering::SeqCst), 1);
    assert_eq!(
        sandbox.kills.load(Ordering::SeqCst),
        1,
        "lifecycle and runtime cleanup owners must share the probe shard terminal proof"
    );
    let router = Arc::new(
        SessionShardRouter::new(
            worker_id.clone(),
            worker_epoch,
            factory,
            Arc::new(RejectArtifacts),
            1,
        )
        .expect("session shard router should be valid"),
    );
    let protocol = runtime.spawn(run_scripted_protocol(
        session_peer_rx,
        CleanupProbe::ForcedClose,
    ));

    let tenant_id = TenantId::new();
    let session_id = SessionId::new();
    let fence = OwnershipFence::new(worker_id.clone(), worker_epoch, 4, 6);
    let primary = router
        .create_context_owned(&tenant_id, &session_id, &fence)
        .expect("production factory should create a bootstrapped primary page");
    assert!(!primary.to_string().is_empty());
    assert_eq!(router.heartbeat(&worker_id, worker_epoch), Ok(()));
    assert_eq!(sandbox.renewals.load(Ordering::SeqCst), 1);
    assert_eq!(router.close_context_fenced(&session_id, &fence), Ok(()));
    assert_eq!(router.close_context_fenced(&session_id, &fence), Ok(()));
    wait_protocol(&runtime, protocol).expect("scripted CDP peer should not panic");
    assert_eq!(sandbox.launches.load(Ordering::SeqCst), 2);
    assert_eq!(sandbox.claims.load(Ordering::SeqCst), 2);
    assert_eq!(
        sandbox.kills.load(Ordering::SeqCst),
        2,
        "readiness and session shards must each use one exact cleanup flight"
    );
}
