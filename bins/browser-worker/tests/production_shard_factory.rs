#![allow(clippy::expect_used)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use browser_worker::{
    ProductionSandboxControl, ProductionSessionShardConfig, ProductionSessionShardFactory,
    SessionShardFactory,
};
use browserd_chromium::{ChromiumArtifactIdentity, ChromiumConnectionConfig, Sha256Digest};
use browserd_core::{LaunchGeneration, SessionId, ShardId, TenantId, WorkerId};
use browserd_sandbox::{
    ChromiumCdpPipes, CleanupReason, CleanupResult, CreateShardOutcome, EgressPolicyBinding,
    KillShardOutcome, LaunchSpec,
};
use browserd_session::OwnershipFence;
use browserd_worker::{DependencyError, SandboxShardRpc, ShardRuntimeError};

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
