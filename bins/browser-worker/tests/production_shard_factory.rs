#![allow(clippy::expect_used)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use browser_worker::{
    ProductionSandboxControl, ProductionSessionShardConfig, ProductionSessionShardFactory,
    RoutedArtifactStore, SessionShardFactory, SessionShardRouter,
};
use browserd_cdp::CdpTransportConfig;
use browserd_chromium::{ChromiumArtifactIdentity, ChromiumConnectionConfig, Sha256Digest};
use browserd_core::{LaunchGeneration, SessionId, ShardId, TenantId, WorkerId};
use browserd_sandbox::{
    ChromiumCdpPipes, CleanupReason, CleanupResult, CreateShardOutcome, EgressPolicyBinding,
    KillShardOutcome, LaunchSpec,
};
use browserd_session::OwnershipFence;
use browserd_worker::{
    ArtifactStoreReceipt, ArtifactStoreRequest, ChromiumDriver, DependencyError, SandboxClient,
    SandboxShardRpc, ShardRuntimeError,
};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::unix::pipe::{Receiver, Sender};
use tokio::sync::oneshot;

struct FailingSandbox {
    daemon_epoch: u64,
    launches: Mutex<Vec<LaunchSpec>>,
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

struct ScriptedSandbox {
    daemon_epoch: u64,
    peer: Mutex<Option<oneshot::Sender<(Receiver, Sender)>>>,
    renewals: AtomicUsize,
    kills: AtomicUsize,
}

#[async_trait]
impl SandboxShardRpc for ScriptedSandbox {
    async fn create_shard(
        &self,
        _spec: LaunchSpec,
        _lease_ttl: Duration,
    ) -> Result<CreateShardOutcome, ShardRuntimeError> {
        Ok(CreateShardOutcome::Created)
    }

    async fn claim_cdp_pipes(
        &self,
        _shard_id: &ShardId,
        _worker_id: &WorkerId,
        _worker_epoch: u64,
        _launch_generation: LaunchGeneration,
    ) -> Result<ChromiumCdpPipes, ShardRuntimeError> {
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
        self.peer
            .lock()
            .map_err(|_| ShardRuntimeError::Unavailable)?
            .take()
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
        .expect("CDP response should be writable");
    writer
        .write_all(&[0])
        .await
        .expect("CDP response terminator should be writable");
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

async fn run_scripted_protocol(peer_rx: oneshot::Receiver<(Receiver, Sender)>) {
    let (mut reader, mut writer) = peer_rx.await.expect("CDP peer should be transferred");
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

    let dispose = read_command(&mut reader).await;
    assert_eq!(dispose["method"], "Target.disposeBrowserContext");
    respond(&mut writer, &dispose, json!({})).await;
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

#[test]
fn failed_connection_claim_cleans_the_exact_session_shard() {
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
        ProductionSessionShardFactory::new(config, Arc::clone(&sandbox), runtime.handle().clone());
    assert_eq!(factory.qualify_daemon(), Ok(()));

    let tenant_id = TenantId::new();
    let session_id = SessionId::new();
    let fence = OwnershipFence::new(worker_id.clone(), worker_epoch, 3, 5);
    assert!(matches!(
        factory.create(&tenant_id, &session_id, &fence),
        Err(DependencyError::Unavailable)
    ));

    let launches = sandbox
        .launches
        .lock()
        .expect("launch log should remain available");
    assert_eq!(launches.len(), 1);
    let launch = &launches[0];
    assert_eq!(launch.tenant_id(), &tenant_id);
    assert_eq!(launch.worker_id(), &worker_id);
    assert_eq!(launch.worker_epoch(), worker_epoch);
    assert_eq!(
        launch.dedicated_egress().egress_fence().session_id(),
        &session_id
    );
    assert_eq!(
        launch
            .dedicated_egress()
            .egress_fence()
            .session_incarnation()
            .get(),
        fence.session_incarnation()
    );
    drop(launches);
    assert_eq!(sandbox.claims.load(Ordering::SeqCst), 1);
    assert_eq!(
        sandbox.kills.load(Ordering::SeqCst),
        2,
        "failed activation cleanup and actor shutdown must both reconcile the exact shard"
    );
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
    let (peer_tx, peer_rx) = oneshot::channel();
    let sandbox = Arc::new(ScriptedSandbox {
        daemon_epoch,
        peer: Mutex::new(Some(peer_tx)),
        renewals: AtomicUsize::new(0),
        kills: AtomicUsize::new(0),
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
    let factory = Arc::new(ProductionSessionShardFactory::new(
        config,
        Arc::clone(&sandbox),
        runtime.handle().clone(),
    ));
    let router = SessionShardRouter::new(
        worker_id.clone(),
        worker_epoch,
        factory,
        Arc::new(RejectArtifacts),
        1,
    )
    .expect("session shard router should be valid");
    let protocol = runtime.spawn(run_scripted_protocol(peer_rx));

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
    runtime
        .block_on(protocol)
        .expect("scripted CDP peer should not panic");
    assert_eq!(sandbox.kills.load(Ordering::SeqCst), 1);
}
