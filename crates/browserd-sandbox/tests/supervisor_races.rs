#![allow(clippy::expect_used)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use browserd_core::{
    EgressFence, LaunchGeneration, OwnerFence, RouteGeneration, SessionId, SessionIncarnation,
    ShardFence, ShardId, TenantId, WorkerEpoch, WorkerId,
};
use browserd_sandbox::{
    ChromiumBinaryDigest, CleanupReason, CreateShardOutcome, DedicatedEgressSpec,
    EgressPolicyBinding, InspectResources, KillShardOutcome, LaunchSpec, RenewLeaseError,
    SandboxBackend, SandboxCapabilities, SandboxError, SandboxHandle, SandboxSupervisor,
    SupervisorConfig, WorkerOwnership,
};
use tokio::sync::Notify;
use tokio::time::Instant;

#[derive(Clone)]
struct GatedBackend {
    provision_started: Arc<Notify>,
    allow_provision: Arc<Notify>,
    events: Arc<Mutex<Vec<&'static str>>>,
    fail_provision: bool,
    fail_first_revoke: bool,
    fail_kill: bool,
    fail_cleanup: bool,
}

#[async_trait]
impl SandboxBackend for GatedBackend {
    fn capabilities(&self) -> SandboxCapabilities {
        SandboxCapabilities::production_required()
    }

    async fn provision(&self, spec: &LaunchSpec) -> Result<SandboxHandle, SandboxError> {
        self.events
            .lock()
            .expect("event lock should work")
            .push("provision");
        self.provision_started.notify_one();
        self.allow_provision.notified().await;
        if self.fail_provision {
            return Err(SandboxError::Backend(
                "injected provisioning rollback failure".into(),
            ));
        }
        Ok(SandboxHandle::new(spec.shard_id().clone(), "gated"))
    }

    async fn renew_egress(
        &self,
        _handle: &SandboxHandle,
        _lease_ttl: Duration,
    ) -> Result<(), SandboxError> {
        Ok(())
    }

    async fn revoke_egress(
        &self,
        _handle: &SandboxHandle,
        _reason: CleanupReason,
    ) -> Result<(), SandboxError> {
        let fail = {
            let mut events = self.events.lock().expect("event lock should work");
            let fail = self.fail_first_revoke && !events.contains(&"revoke");
            events.push("revoke");
            fail
        };
        if fail {
            return Err(SandboxError::Backend("injected revoke failure".into()));
        }
        Ok(())
    }

    async fn kill_cgroup(
        &self,
        _handle: &SandboxHandle,
        _reason: CleanupReason,
    ) -> Result<(), SandboxError> {
        self.events
            .lock()
            .expect("event lock should work")
            .push("kill");
        if self.fail_kill {
            return Err(SandboxError::Backend("injected kill failure".into()));
        }
        Ok(())
    }

    async fn cleanup_namespaces(&self, _handle: &SandboxHandle) -> Result<(), SandboxError> {
        self.events
            .lock()
            .expect("event lock should work")
            .push("cleanup");
        if self.fail_cleanup {
            return Err(SandboxError::Backend("injected cleanup failure".into()));
        }
        Ok(())
    }

    async fn inspect(&self, _handle: &SandboxHandle) -> Result<InspectResources, SandboxError> {
        Err(SandboxError::Backend("not used".into()))
    }
}

fn worker() -> WorkerId {
    WorkerId::new("race-worker").expect("worker should be valid")
}

fn launch_spec(shard_id: ShardId) -> LaunchSpec {
    launch_spec_for_generation(TenantId::new(), shard_id, 1)
}

fn launch_spec_for_generation(
    tenant_id: TenantId,
    shard_id: ShardId,
    launch_generation: u64,
) -> LaunchSpec {
    launch_spec_for_owner(tenant_id, shard_id, worker(), 7, launch_generation)
}

fn launch_spec_for_owner(
    tenant_id: TenantId,
    shard_id: ShardId,
    worker_id: WorkerId,
    worker_epoch: u64,
    launch_generation: u64,
) -> LaunchSpec {
    let worker_epoch = WorkerEpoch::new(worker_epoch).expect("worker epoch is positive");
    let egress_fence = EgressFence::new(
        ShardFence::new(
            OwnerFence::new(worker_id, worker_epoch),
            shard_id,
            LaunchGeneration::new(launch_generation).expect("launch generation is positive"),
        ),
        RouteGeneration::new(launch_generation).expect("route generation is positive"),
        SessionId::new(),
        SessionIncarnation::new(1).expect("session incarnation is positive"),
    );
    let policy_binding =
        EgressPolicyBinding::new("test-public-web", [1; 32]).expect("policy binding is valid");
    let dedicated_egress =
        DedicatedEgressSpec::new(egress_fence, policy_binding, Duration::from_secs(5))
            .expect("dedicated egress spec is valid");
    LaunchSpec::production(
        tenant_id,
        dedicated_egress,
        ChromiumBinaryDigest::new([0x3c; 32]),
    )
}

async fn publish_active_shard(
    supervisor: &Arc<SandboxSupervisor<GatedBackend>>,
    backend: &GatedBackend,
    spec: &LaunchSpec,
) {
    let create = tokio::spawn({
        let supervisor = Arc::clone(supervisor);
        let spec = spec.clone();
        async move {
            supervisor
                .create_shard(
                    spec,
                    WorkerOwnership::new(worker(), 7, Instant::now() + Duration::from_secs(5)),
                )
                .await
        }
    });
    backend.provision_started.notified().await;
    backend.allow_provision.notify_one();
    assert_eq!(
        create.await.expect("create task should not panic"),
        Ok(CreateShardOutcome::Created)
    );
}

#[tokio::test]
async fn kill_before_create_records_exact_tombstone_and_skips_provisioning() {
    let backend = GatedBackend {
        provision_started: Arc::new(Notify::new()),
        allow_provision: Arc::new(Notify::new()),
        events: Arc::new(Mutex::new(Vec::new())),
        fail_provision: false,
        fail_first_revoke: false,
        fail_kill: false,
        fail_cleanup: false,
    };
    let supervisor = SandboxSupervisor::new(
        SupervisorConfig::new(Duration::from_secs(10), Duration::from_secs(30))
            .expect("config should work"),
        backend.clone(),
    );
    let spec = launch_spec(ShardId::new());

    assert_eq!(
        supervisor
            .cancel_or_kill_shard(&spec, CleanupReason::Administrative)
            .await,
        Ok(KillShardOutcome::AlreadyTerminated)
    );
    assert_eq!(
        tokio::time::timeout(
            Duration::from_millis(100),
            supervisor.create_shard(
                spec,
                WorkerOwnership::new(worker(), 7, Instant::now() + Duration::from_secs(5)),
            ),
        )
        .await
        .expect("an exact pre-cancelled create must complete without provisioning"),
        Ok(CreateShardOutcome::Cancelled)
    );
    assert!(
        backend
            .events
            .lock()
            .expect("event lock should work")
            .is_empty(),
        "an exact pre-cancelled create must not reach the backend"
    );
}

#[tokio::test]
async fn exact_cancel_rejects_every_non_exact_binding_without_mutating_the_tombstone() {
    let backend = GatedBackend {
        provision_started: Arc::new(Notify::new()),
        allow_provision: Arc::new(Notify::new()),
        events: Arc::new(Mutex::new(Vec::new())),
        fail_provision: false,
        fail_first_revoke: false,
        fail_kill: false,
        fail_cleanup: false,
    };
    let supervisor = SandboxSupervisor::new(
        SupervisorConfig::new(Duration::from_secs(10), Duration::from_secs(30))
            .expect("config should work"),
        backend.clone(),
    );
    let spec = launch_spec(ShardId::new());
    assert_eq!(
        supervisor
            .cancel_or_kill_shard(&spec, CleanupReason::Administrative)
            .await,
        Ok(KillShardOutcome::AlreadyTerminated)
    );

    let wrong_worker = launch_spec_for_owner(
        spec.tenant_id().clone(),
        spec.shard_id().clone(),
        WorkerId::new("wrong-race-worker").expect("worker should be valid"),
        7,
        1,
    );
    let wrong_epoch = launch_spec_for_owner(
        spec.tenant_id().clone(),
        spec.shard_id().clone(),
        worker(),
        8,
        1,
    );
    let changed_fence =
        launch_spec_for_generation(spec.tenant_id().clone(), spec.shard_id().clone(), 1);
    let changed_tenant = LaunchSpec::production(
        TenantId::new(),
        spec.dedicated_egress().clone(),
        spec.chromium_binary_digest(),
    );
    let changed_digest = LaunchSpec::production(
        spec.tenant_id().clone(),
        spec.dedicated_egress().clone(),
        ChromiumBinaryDigest::new([0x4d; 32]),
    );
    let changed_policy = LaunchSpec::production(
        spec.tenant_id().clone(),
        DedicatedEgressSpec::new(
            spec.dedicated_egress().egress_fence().clone(),
            EgressPolicyBinding::new("different-policy", [2; 32]).expect("policy binding is valid"),
            spec.dedicated_egress().initial_lease_ttl(),
        )
        .expect("dedicated egress spec is valid"),
        spec.chromium_binary_digest(),
    );
    for (candidate, expected) in [
        (wrong_worker, SandboxError::OwnershipMismatch),
        (
            wrong_epoch,
            SandboxError::WorkerEpochMismatch {
                expected: 7,
                actual: 8,
            },
        ),
        (changed_fence, SandboxError::LaunchFenceMismatch),
        (changed_tenant, SandboxError::LaunchBindingMismatch),
        (changed_digest, SandboxError::LaunchBindingMismatch),
        (changed_policy, SandboxError::LaunchBindingMismatch),
    ] {
        assert_eq!(
            supervisor
                .cancel_or_kill_shard(&candidate, CleanupReason::Administrative)
                .await,
            Err(expected)
        );
    }
    assert_eq!(
        supervisor
            .create_shard(
                spec,
                WorkerOwnership::new(worker(), 7, Instant::now() + Duration::from_secs(5)),
            )
            .await,
        Ok(CreateShardOutcome::Cancelled)
    );
    assert!(
        backend
            .events
            .lock()
            .expect("event lock should work")
            .is_empty()
    );
}

#[tokio::test]
async fn cancel_during_provision_waits_for_cleanup_and_returns_only_a_terminal_outcome() {
    let backend = GatedBackend {
        provision_started: Arc::new(Notify::new()),
        allow_provision: Arc::new(Notify::new()),
        events: Arc::new(Mutex::new(Vec::new())),
        fail_provision: false,
        fail_first_revoke: false,
        fail_kill: false,
        fail_cleanup: false,
    };
    let supervisor = Arc::new(SandboxSupervisor::new(
        SupervisorConfig::new(Duration::from_secs(10), Duration::from_secs(30))
            .expect("config should work"),
        backend.clone(),
    ));
    let spec = launch_spec(ShardId::new());
    let create = tokio::spawn({
        let supervisor = Arc::clone(&supervisor);
        let spec = spec.clone();
        async move {
            supervisor
                .create_shard(
                    spec,
                    WorkerOwnership::new(worker(), 7, Instant::now() + Duration::from_secs(5)),
                )
                .await
        }
    });
    backend.provision_started.notified().await;

    let mut cancel =
        Box::pin(supervisor.cancel_or_kill_shard(&spec, CleanupReason::Administrative));
    assert!(
        futures::poll!(cancel.as_mut()).is_pending(),
        "a provisioning cancellation must wait for a terminal cleanup outcome"
    );
    backend.allow_provision.notify_one();

    assert_eq!(
        create.await.expect("create task should not panic"),
        Ok(CreateShardOutcome::Cancelled)
    );
    assert!(matches!(
        cancel.await,
        Ok(KillShardOutcome::Terminated(_)) | Ok(KillShardOutcome::AlreadyTerminated)
    ));
    assert_eq!(
        backend
            .events
            .lock()
            .expect("event lock should work")
            .as_slice(),
        ["provision", "revoke", "kill", "cleanup"]
    );
    assert_eq!(
        supervisor
            .cancel_or_kill_shard(&spec, CleanupReason::Administrative)
            .await,
        Ok(KillShardOutcome::AlreadyTerminated)
    );
}

#[tokio::test]
async fn exact_cancel_of_an_active_shard_tombstones_future_create_retries() {
    let backend = GatedBackend {
        provision_started: Arc::new(Notify::new()),
        allow_provision: Arc::new(Notify::new()),
        events: Arc::new(Mutex::new(Vec::new())),
        fail_provision: false,
        fail_first_revoke: false,
        fail_kill: false,
        fail_cleanup: false,
    };
    let supervisor = Arc::new(SandboxSupervisor::new(
        SupervisorConfig::new(Duration::from_secs(10), Duration::from_secs(30))
            .expect("config should work"),
        backend.clone(),
    ));
    let spec = launch_spec(ShardId::new());
    let create = tokio::spawn({
        let supervisor = Arc::clone(&supervisor);
        let spec = spec.clone();
        async move {
            supervisor
                .create_shard(
                    spec,
                    WorkerOwnership::new(worker(), 7, Instant::now() + Duration::from_secs(5)),
                )
                .await
        }
    });
    backend.provision_started.notified().await;
    backend.allow_provision.notify_one();
    assert_eq!(
        create.await.expect("create task should not panic"),
        Ok(CreateShardOutcome::Created)
    );

    assert!(matches!(
        supervisor
            .cancel_or_kill_shard(&spec, CleanupReason::Administrative)
            .await,
        Ok(KillShardOutcome::Terminated(_))
    ));
    assert_eq!(
        supervisor
            .create_shard(
                spec,
                WorkerOwnership::new(worker(), 7, Instant::now() + Duration::from_secs(5)),
            )
            .await,
        Ok(CreateShardOutcome::Cancelled)
    );
    assert_eq!(
        backend
            .events
            .lock()
            .expect("event lock should work")
            .as_slice(),
        ["provision", "revoke", "kill", "cleanup"]
    );
}

#[tokio::test]
async fn exact_cancel_upgrades_an_incomplete_legacy_kill_to_a_cancelled_tombstone() {
    let backend = GatedBackend {
        provision_started: Arc::new(Notify::new()),
        allow_provision: Arc::new(Notify::new()),
        events: Arc::new(Mutex::new(Vec::new())),
        fail_provision: false,
        fail_first_revoke: true,
        fail_kill: false,
        fail_cleanup: false,
    };
    let supervisor = Arc::new(SandboxSupervisor::new(
        SupervisorConfig::new(Duration::from_secs(10), Duration::from_secs(30))
            .expect("config should work"),
        backend.clone(),
    ));
    let spec = launch_spec(ShardId::new());
    publish_active_shard(&supervisor, &backend, &spec).await;

    assert!(matches!(
        supervisor
            .kill_shard(
                spec.shard_id(),
                spec.worker_epoch(),
                spec.launch_generation(),
                CleanupReason::Administrative,
            )
            .await,
        Ok(KillShardOutcome::CleanupIncomplete(_))
    ));
    assert!(matches!(
        supervisor
            .cancel_or_kill_shard(&spec, CleanupReason::Administrative)
            .await,
        Ok(KillShardOutcome::Terminated(_))
    ));
    assert_eq!(
        supervisor
            .create_shard(
                spec,
                WorkerOwnership::new(worker(), 7, Instant::now() + Duration::from_secs(5)),
            )
            .await,
        Ok(CreateShardOutcome::Cancelled)
    );
    assert_eq!(
        backend
            .events
            .lock()
            .expect("event lock should work")
            .as_slice(),
        ["provision", "revoke", "kill", "cleanup", "revoke"]
    );
}

#[tokio::test]
async fn exact_cancel_upgrades_a_legacy_terminal_kill_to_a_cancelled_tombstone() {
    let backend = GatedBackend {
        provision_started: Arc::new(Notify::new()),
        allow_provision: Arc::new(Notify::new()),
        events: Arc::new(Mutex::new(Vec::new())),
        fail_provision: false,
        fail_first_revoke: false,
        fail_kill: false,
        fail_cleanup: false,
    };
    let supervisor = Arc::new(SandboxSupervisor::new(
        SupervisorConfig::new(Duration::from_secs(10), Duration::from_secs(30))
            .expect("config should work"),
        backend.clone(),
    ));
    let spec = launch_spec(ShardId::new());
    publish_active_shard(&supervisor, &backend, &spec).await;

    assert!(matches!(
        supervisor
            .kill_shard(
                spec.shard_id(),
                spec.worker_epoch(),
                spec.launch_generation(),
                CleanupReason::Administrative,
            )
            .await,
        Ok(KillShardOutcome::Terminated(_))
    ));
    assert_eq!(
        supervisor
            .cancel_or_kill_shard(&spec, CleanupReason::Administrative)
            .await,
        Ok(KillShardOutcome::AlreadyTerminated)
    );
    assert_eq!(
        supervisor
            .create_shard(
                spec,
                WorkerOwnership::new(worker(), 7, Instant::now() + Duration::from_secs(5)),
            )
            .await,
        Ok(CreateShardOutcome::Cancelled)
    );
    assert_eq!(
        backend
            .events
            .lock()
            .expect("event lock should work")
            .as_slice(),
        ["provision", "revoke", "kill", "cleanup"]
    );
}

#[tokio::test]
async fn failed_provisioning_cleanup_is_never_promoted_to_terminal_cancellation() {
    let backend = GatedBackend {
        provision_started: Arc::new(Notify::new()),
        allow_provision: Arc::new(Notify::new()),
        events: Arc::new(Mutex::new(Vec::new())),
        fail_provision: true,
        fail_first_revoke: false,
        fail_kill: false,
        fail_cleanup: false,
    };
    let supervisor = Arc::new(SandboxSupervisor::new(
        SupervisorConfig::new(Duration::from_secs(10), Duration::from_secs(30))
            .expect("config should work"),
        backend.clone(),
    ));
    let spec = launch_spec(ShardId::new());
    let create = tokio::spawn({
        let supervisor = Arc::clone(&supervisor);
        let spec = spec.clone();
        async move {
            supervisor
                .create_shard(
                    spec,
                    WorkerOwnership::new(worker(), 7, Instant::now() + Duration::from_secs(5)),
                )
                .await
        }
    });
    backend.provision_started.notified().await;
    let mut cancel =
        Box::pin(supervisor.cancel_or_kill_shard(&spec, CleanupReason::Administrative));
    assert!(
        futures::poll!(cancel.as_mut()).is_pending(),
        "the cancellation marker must be installed before provisioning fails"
    );
    backend.allow_provision.notify_one();

    assert!(matches!(
        create.await.expect("create task should not panic"),
        Err(SandboxError::Backend(_))
    ));
    assert!(matches!(cancel.await, Err(SandboxError::Backend(_))));
    assert!(matches!(
        supervisor
            .create_shard(
                spec,
                WorkerOwnership::new(worker(), 7, Instant::now() + Duration::from_secs(5)),
            )
            .await,
        Err(SandboxError::Backend(_))
    ));
    assert_eq!(
        backend
            .events
            .lock()
            .expect("event lock should work")
            .as_slice(),
        ["provision"]
    );
}

#[tokio::test]
async fn exact_cancel_after_a_failed_create_preserves_the_cached_failure() {
    let backend = GatedBackend {
        provision_started: Arc::new(Notify::new()),
        allow_provision: Arc::new(Notify::new()),
        events: Arc::new(Mutex::new(Vec::new())),
        fail_provision: true,
        fail_first_revoke: false,
        fail_kill: false,
        fail_cleanup: false,
    };
    let supervisor = Arc::new(SandboxSupervisor::new(
        SupervisorConfig::new(Duration::from_secs(10), Duration::from_secs(30))
            .expect("config should work"),
        backend.clone(),
    ));
    let spec = launch_spec(ShardId::new());
    let create = tokio::spawn({
        let supervisor = Arc::clone(&supervisor);
        let spec = spec.clone();
        async move {
            supervisor
                .create_shard(
                    spec,
                    WorkerOwnership::new(worker(), 7, Instant::now() + Duration::from_secs(5)),
                )
                .await
        }
    });
    backend.provision_started.notified().await;
    backend.allow_provision.notify_one();
    assert!(matches!(
        create.await.expect("create task should not panic"),
        Err(SandboxError::Backend(_))
    ));

    assert!(matches!(
        supervisor
            .cancel_or_kill_shard(&spec, CleanupReason::Administrative)
            .await,
        Err(SandboxError::Backend(_))
    ));
    assert!(matches!(
        supervisor
            .create_shard(
                spec,
                WorkerOwnership::new(worker(), 7, Instant::now() + Duration::from_secs(5)),
            )
            .await,
        Err(SandboxError::Backend(_))
    ));
    assert_eq!(
        backend
            .events
            .lock()
            .expect("event lock should work")
            .as_slice(),
        ["provision"]
    );
}

#[tokio::test]
async fn newer_generation_cancel_supersedes_a_stale_failed_launch_before_create() {
    let backend = GatedBackend {
        provision_started: Arc::new(Notify::new()),
        allow_provision: Arc::new(Notify::new()),
        events: Arc::new(Mutex::new(Vec::new())),
        fail_provision: true,
        fail_first_revoke: false,
        fail_kill: false,
        fail_cleanup: false,
    };
    let supervisor = Arc::new(SandboxSupervisor::new(
        SupervisorConfig::new(Duration::from_secs(10), Duration::from_secs(30))
            .expect("config should work"),
        backend.clone(),
    ));
    let shard_id = ShardId::new();
    let tenant_id = TenantId::new();
    let failed_spec = launch_spec_for_generation(tenant_id.clone(), shard_id.clone(), 1);
    let create = tokio::spawn({
        let supervisor = Arc::clone(&supervisor);
        async move {
            supervisor
                .create_shard(
                    failed_spec,
                    WorkerOwnership::new(worker(), 7, Instant::now() + Duration::from_secs(5)),
                )
                .await
        }
    });
    backend.provision_started.notified().await;
    backend.allow_provision.notify_one();
    assert!(matches!(
        create.await.expect("create task should not panic"),
        Err(SandboxError::Backend(_))
    ));
    let cancelled_spec = launch_spec_for_generation(tenant_id, shard_id, 2);

    assert_eq!(
        supervisor
            .cancel_or_kill_shard(&cancelled_spec, CleanupReason::Administrative)
            .await,
        Ok(KillShardOutcome::AlreadyTerminated)
    );
    assert_eq!(
        supervisor
            .create_shard(
                cancelled_spec,
                WorkerOwnership::new(worker(), 7, Instant::now() + Duration::from_secs(5)),
            )
            .await,
        Ok(CreateShardOutcome::Cancelled)
    );
    assert_eq!(
        backend
            .events
            .lock()
            .expect("event lock should work")
            .as_slice(),
        ["provision"]
    );
}

#[tokio::test]
async fn incomplete_provision_cancellation_can_be_reconciled_to_terminal_by_exact_retry() {
    let backend = GatedBackend {
        provision_started: Arc::new(Notify::new()),
        allow_provision: Arc::new(Notify::new()),
        events: Arc::new(Mutex::new(Vec::new())),
        fail_provision: false,
        fail_first_revoke: true,
        fail_kill: false,
        fail_cleanup: false,
    };
    let supervisor = Arc::new(SandboxSupervisor::new(
        SupervisorConfig::new(Duration::from_secs(10), Duration::from_secs(30))
            .expect("config should work"),
        backend.clone(),
    ));
    let spec = launch_spec(ShardId::new());
    let create = tokio::spawn({
        let supervisor = Arc::clone(&supervisor);
        let spec = spec.clone();
        async move {
            supervisor
                .create_shard(
                    spec,
                    WorkerOwnership::new(worker(), 7, Instant::now() + Duration::from_secs(5)),
                )
                .await
        }
    });
    backend.provision_started.notified().await;

    let mut cancel =
        Box::pin(supervisor.cancel_or_kill_shard(&spec, CleanupReason::Administrative));
    assert!(futures::poll!(cancel.as_mut()).is_pending());
    backend.allow_provision.notify_one();

    assert!(matches!(
        create.await.expect("create task should not panic"),
        Err(SandboxError::IncompleteCleanup { .. })
    ));
    assert!(matches!(
        cancel.await,
        Ok(KillShardOutcome::CleanupIncomplete(_))
    ));
    assert!(matches!(
        supervisor
            .cancel_or_kill_shard(&spec, CleanupReason::Administrative)
            .await,
        Ok(KillShardOutcome::Terminated(_)) | Ok(KillShardOutcome::AlreadyTerminated)
    ));
    assert_eq!(
        backend
            .events
            .lock()
            .expect("event lock should work")
            .as_slice(),
        ["provision", "revoke", "kill", "cleanup", "revoke"]
    );
}

#[tokio::test]
async fn kill_and_renew_during_provision_are_fenced_and_cannot_resurrect_shard() {
    let backend = GatedBackend {
        provision_started: Arc::new(Notify::new()),
        allow_provision: Arc::new(Notify::new()),
        events: Arc::new(Mutex::new(Vec::new())),
        fail_provision: false,
        fail_first_revoke: false,
        fail_kill: false,
        fail_cleanup: false,
    };
    let supervisor = Arc::new(SandboxSupervisor::new(
        SupervisorConfig::new(Duration::from_secs(10), Duration::from_secs(30))
            .expect("config should work"),
        backend.clone(),
    ));
    let shard_id = ShardId::new();
    let now = Instant::now();
    let create = {
        let supervisor = supervisor.clone();
        let shard_id = shard_id.clone();
        tokio::spawn(async move {
            supervisor
                .create_shard(
                    launch_spec(shard_id),
                    WorkerOwnership::new(worker(), 7, now + Duration::from_secs(5)),
                )
                .await
        })
    };
    backend.provision_started.notified().await;

    supervisor
        .renew_owner_lease(
            &shard_id,
            7,
            LaunchGeneration::new(1).expect("launch generation is positive"),
            now + Duration::from_secs(1),
            now + Duration::from_secs(9),
        )
        .await
        .expect("provisioning lease should renew");
    assert_eq!(
        supervisor
            .kill_shard(
                &shard_id,
                7,
                LaunchGeneration::new(1).expect("launch generation is positive"),
                CleanupReason::Administrative,
            )
            .await,
        Ok(KillShardOutcome::CancellationRequested)
    );
    assert_eq!(
        supervisor
            .renew_owner_lease(
                &shard_id,
                7,
                LaunchGeneration::new(1).expect("launch generation is positive"),
                now + Duration::from_secs(2),
                now + Duration::from_secs(9),
            )
            .await,
        Err(RenewLeaseError::ShardNotFound)
    );
    backend.allow_provision.notify_one();
    assert_eq!(
        create
            .await
            .expect("create task should not panic")
            .expect("cancellation cleanup should complete"),
        CreateShardOutcome::Cancelled
    );
    assert_eq!(
        backend
            .events
            .lock()
            .expect("event lock should work")
            .as_slice(),
        ["provision", "revoke", "kill", "cleanup"]
    );
    assert_eq!(
        supervisor
            .kill_shard(
                &shard_id,
                7,
                LaunchGeneration::new(1).expect("launch generation is positive"),
                CleanupReason::Administrative,
            )
            .await,
        Ok(KillShardOutcome::AlreadyTerminated)
    );
}

#[tokio::test]
async fn provisioning_lease_renewal_survives_active_publication() {
    let backend = GatedBackend {
        provision_started: Arc::new(Notify::new()),
        allow_provision: Arc::new(Notify::new()),
        events: Arc::new(Mutex::new(Vec::new())),
        fail_provision: false,
        fail_first_revoke: false,
        fail_kill: false,
        fail_cleanup: false,
    };
    let supervisor = Arc::new(SandboxSupervisor::new(
        SupervisorConfig::new(Duration::from_secs(10), Duration::from_secs(30))
            .expect("config should work"),
        backend.clone(),
    ));
    let shard_id = ShardId::new();
    let now = Instant::now();
    let create = {
        let supervisor = Arc::clone(&supervisor);
        let shard_id = shard_id.clone();
        tokio::spawn(async move {
            supervisor
                .create_shard(
                    launch_spec(shard_id),
                    WorkerOwnership::new(worker(), 7, now + Duration::from_secs(5)),
                )
                .await
        })
    };
    backend.provision_started.notified().await;

    supervisor
        .renew_owner_lease(
            &shard_id,
            7,
            LaunchGeneration::new(1).expect("launch generation is positive"),
            now + Duration::from_secs(1),
            now + Duration::from_secs(10),
        )
        .await
        .expect("provisioning lease should renew");
    backend.allow_provision.notify_one();
    assert_eq!(
        create
            .await
            .expect("create task should not panic")
            .expect("renewed provision should complete"),
        CreateShardOutcome::Created
    );

    assert_eq!(
        supervisor
            .renew_owner_lease(
                &shard_id,
                7,
                LaunchGeneration::new(1).expect("launch generation is positive"),
                now + Duration::from_secs(6),
                now + Duration::from_secs(11),
            )
            .await,
        Ok(())
    );
}

#[tokio::test]
async fn cancellation_or_expiry_during_provision_surfaces_incomplete_cleanup() {
    for expire in [false, true] {
        let backend = GatedBackend {
            provision_started: Arc::new(Notify::new()),
            allow_provision: Arc::new(Notify::new()),
            events: Arc::new(Mutex::new(Vec::new())),
            fail_provision: false,
            fail_first_revoke: true,
            fail_kill: false,
            fail_cleanup: false,
        };
        let supervisor = Arc::new(SandboxSupervisor::new(
            SupervisorConfig::new(Duration::from_secs(10), Duration::from_secs(30))
                .expect("config should work"),
            backend.clone(),
        ));
        let shard_id = ShardId::new();
        let now = Instant::now();
        let create = {
            let supervisor = supervisor.clone();
            let shard_id = shard_id.clone();
            tokio::spawn(async move {
                supervisor
                    .create_shard(
                        launch_spec(shard_id),
                        WorkerOwnership::new(worker(), 7, now + Duration::from_secs(10)),
                    )
                    .await
            })
        };
        backend.provision_started.notified().await;

        if expire {
            assert!(
                supervisor
                    .expire_leases(now + Duration::from_secs(11))
                    .await
                    .is_empty()
            );
        } else {
            assert_eq!(
                supervisor
                    .kill_shard(
                        &shard_id,
                        7,
                        LaunchGeneration::new(1).expect("launch generation is positive"),
                        CleanupReason::Administrative,
                    )
                    .await,
                Ok(KillShardOutcome::CancellationRequested)
            );
        }
        backend.allow_provision.notify_one();
        let error = create
            .await
            .expect("create task should not panic")
            .expect_err("incomplete cancellation cleanup must be surfaced");
        assert!(error.to_string().contains("incomplete cleanup"));
        assert_eq!(
            backend
                .events
                .lock()
                .expect("event lock should work")
                .as_slice(),
            ["provision", "revoke", "kill", "cleanup"]
        );
    }
}

#[tokio::test]
async fn concurrent_renew_and_duplicate_kill_have_one_cleanup_owner() {
    let backend = GatedBackend {
        provision_started: Arc::new(Notify::new()),
        allow_provision: Arc::new(Notify::new()),
        events: Arc::new(Mutex::new(Vec::new())),
        fail_provision: false,
        fail_first_revoke: false,
        fail_kill: false,
        fail_cleanup: false,
    };
    backend.allow_provision.notify_one();
    let supervisor = Arc::new(SandboxSupervisor::new(
        SupervisorConfig::new(Duration::from_secs(10), Duration::from_secs(30))
            .expect("config should work"),
        backend.clone(),
    ));
    let shard_id = ShardId::new();
    let now = Instant::now();
    supervisor
        .create_shard(
            launch_spec(shard_id.clone()),
            WorkerOwnership::new(worker(), 7, now + Duration::from_secs(10)),
        )
        .await
        .expect("shard should provision");
    let start = Arc::new(tokio::sync::Barrier::new(4));
    let renew = {
        let supervisor = supervisor.clone();
        let shard_id = shard_id.clone();
        let start = start.clone();
        tokio::spawn(async move {
            start.wait().await;
            supervisor
                .renew_owner_lease(
                    &shard_id,
                    7,
                    LaunchGeneration::new(1).expect("launch generation is positive"),
                    now + Duration::from_secs(1),
                    now + Duration::from_secs(9),
                )
                .await
        })
    };
    let mut kills = Vec::new();
    for _ in 0..2 {
        let supervisor = supervisor.clone();
        let shard_id = shard_id.clone();
        let start = start.clone();
        kills.push(tokio::spawn(async move {
            start.wait().await;
            supervisor
                .kill_shard(
                    &shard_id,
                    7,
                    LaunchGeneration::new(1).expect("launch generation is positive"),
                    CleanupReason::Administrative,
                )
                .await
        }));
    }
    start.wait().await;

    let renew = renew.await.expect("renew task should not panic");
    assert!(
        renew.is_ok() || matches!(renew, Err(browserd_sandbox::RenewLeaseError::ShardNotFound))
    );
    let mut outcomes = Vec::new();
    for kill in kills {
        outcomes.push(
            kill.await
                .expect("kill task should not panic")
                .expect("kill should be fenced"),
        );
    }
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, KillShardOutcome::Terminated(_)))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == KillShardOutcome::AlreadyTerminated)
            .count(),
        1
    );
    let events = backend.events.lock().expect("event lock should work");
    assert_eq!(events.iter().filter(|event| **event == "revoke").count(), 1);
    assert_eq!(events.iter().filter(|event| **event == "kill").count(), 1);
    assert_eq!(
        events.iter().filter(|event| **event == "cleanup").count(),
        1
    );
}
