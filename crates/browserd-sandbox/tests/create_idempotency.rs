#![allow(clippy::expect_used)]

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use browserd_core::{
    EgressFence, LaunchGeneration, OwnerFence, RouteGeneration, SessionId, SessionIncarnation,
    ShardFence, ShardId, TenantId, WorkerEpoch, WorkerId,
};
use browserd_sandbox::{
    ChromiumBinaryDigest, CleanupReason, CreateShardOutcome, DedicatedEgressSpec,
    EgressPolicyBinding, InspectResources, LaunchSpec, SandboxBackend, SandboxCapabilities,
    SandboxError, SandboxHandle, SandboxSupervisor, SupervisorConfig, WorkerOwnership,
};
use tokio::sync::{Notify, Semaphore};
use tokio::time::Instant;

#[derive(Clone)]
struct GatedProvisionBackend {
    calls: Arc<AtomicUsize>,
    entered: Arc<Notify>,
    permits: Arc<Semaphore>,
    outcomes: Arc<Mutex<VecDeque<Result<&'static str, SandboxError>>>>,
}

impl GatedProvisionBackend {
    fn with_outcomes(
        outcomes: impl IntoIterator<Item = Result<&'static str, SandboxError>>,
    ) -> Self {
        Self {
            calls: Arc::new(AtomicUsize::new(0)),
            entered: Arc::new(Notify::new()),
            permits: Arc::new(Semaphore::new(0)),
            outcomes: Arc::new(Mutex::new(outcomes.into_iter().collect())),
        }
    }

    async fn wait_until_entered(&self, expected_calls: usize) {
        tokio::time::timeout(Duration::from_millis(200), async {
            loop {
                if self.calls.load(Ordering::Acquire) >= expected_calls {
                    return;
                }
                self.entered.notified().await;
            }
        })
        .await
        .expect("provision should reach its gated boundary");
    }

    fn release_one(&self) {
        self.permits.add_permits(1);
    }
}

#[async_trait]
impl SandboxBackend for GatedProvisionBackend {
    fn capabilities(&self) -> SandboxCapabilities {
        SandboxCapabilities::production_required()
    }

    async fn provision(&self, spec: &LaunchSpec) -> Result<SandboxHandle, SandboxError> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        self.entered.notify_waiters();
        self.permits
            .acquire()
            .await
            .expect("test provision gate should remain open")
            .forget();
        self.outcomes
            .lock()
            .expect("outcome lock should remain available")
            .pop_front()
            .expect("every provision call needs a scripted outcome")
            .map(|token| SandboxHandle::new(spec.shard_id().clone(), token))
    }

    async fn revoke_egress(
        &self,
        _handle: &SandboxHandle,
        _reason: CleanupReason,
    ) -> Result<(), SandboxError> {
        Ok(())
    }

    async fn kill_cgroup(
        &self,
        _handle: &SandboxHandle,
        _reason: CleanupReason,
    ) -> Result<(), SandboxError> {
        Ok(())
    }

    async fn cleanup_namespaces(&self, _handle: &SandboxHandle) -> Result<(), SandboxError> {
        Ok(())
    }

    async fn inspect(&self, _handle: &SandboxHandle) -> Result<InspectResources, SandboxError> {
        Err(SandboxError::Backend("not used".to_owned()))
    }
}

fn worker() -> WorkerId {
    WorkerId::new("create-idempotency-worker").expect("worker ID should be valid")
}

fn config() -> SupervisorConfig {
    SupervisorConfig::new(Duration::from_secs(10), Duration::from_secs(30))
        .expect("supervisor config should be valid")
}

fn launch_spec(
    tenant_id: TenantId,
    shard_id: ShardId,
    launch_generation: u64,
    profile: &str,
    digest: [u8; 32],
    lease_ttl: Duration,
) -> LaunchSpec {
    let fence = EgressFence::new(
        ShardFence::new(
            OwnerFence::new(
                worker(),
                WorkerEpoch::new(17).expect("worker epoch should be positive"),
            ),
            shard_id,
            LaunchGeneration::new(launch_generation).expect("launch generation should be positive"),
        ),
        RouteGeneration::new(1).expect("route generation should be positive"),
        SessionId::new(),
        SessionIncarnation::new(1).expect("session incarnation should be positive"),
    );
    let binding = EgressPolicyBinding::new(profile, digest).expect("binding should be valid");
    let egress = DedicatedEgressSpec::new(fence, binding, lease_ttl)
        .expect("dedicated egress spec should be valid");
    LaunchSpec::production(tenant_id, egress, ChromiumBinaryDigest::new([0x3c; 32]))
}

fn ownership() -> WorkerOwnership {
    WorkerOwnership::new(worker(), 17, Instant::now() + Duration::from_secs(5))
}

#[tokio::test]
async fn concurrent_exact_create_waits_for_active_publication_and_provisions_once() {
    let backend = GatedProvisionBackend::with_outcomes([Ok("created")]);
    let supervisor = Arc::new(SandboxSupervisor::new(config(), backend.clone()));
    let spec = launch_spec(
        TenantId::new(),
        ShardId::new(),
        1,
        "public-web",
        [1; 32],
        Duration::from_secs(5),
    );
    let leader = tokio::spawn({
        let supervisor = Arc::clone(&supervisor);
        let spec = spec.clone();
        async move { supervisor.create_shard(spec, ownership()).await }
    });
    backend.wait_until_entered(1).await;

    let mut waiter = Box::pin(supervisor.create_shard(spec.clone(), ownership()));
    assert!(
        futures::poll!(waiter.as_mut()).is_pending(),
        "an exact retry must not report success before the active shard is published"
    );
    backend.release_one();

    assert_eq!(
        leader.await.expect("leader task should finish"),
        Ok(CreateShardOutcome::Created)
    );
    assert_eq!(waiter.await, Ok(CreateShardOutcome::AlreadyExists));
    assert_eq!(backend.calls.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn provision_failure_is_cloned_to_waiters_and_exact_later_retries() {
    let failure = SandboxError::Backend("stable provision failure".to_owned());
    let backend = GatedProvisionBackend::with_outcomes([Err(failure.clone())]);
    let supervisor = Arc::new(SandboxSupervisor::new(config(), backend.clone()));
    let spec = launch_spec(
        TenantId::new(),
        ShardId::new(),
        1,
        "public-web",
        [2; 32],
        Duration::from_secs(5),
    );
    let leader = tokio::spawn({
        let supervisor = Arc::clone(&supervisor);
        let spec = spec.clone();
        async move { supervisor.create_shard(spec, ownership()).await }
    });
    backend.wait_until_entered(1).await;

    let mut waiter = Box::pin(supervisor.create_shard(spec.clone(), ownership()));
    assert!(futures::poll!(waiter.as_mut()).is_pending());
    backend.release_one();

    assert_eq!(
        leader.await.expect("leader task should finish"),
        Err(failure.clone())
    );
    assert_eq!(waiter.await, Err(failure.clone()));
    assert_eq!(
        supervisor.create_shard(spec, ownership()).await,
        Err(failure)
    );
    assert_eq!(backend.calls.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn cancelling_an_exact_waiter_does_not_cancel_the_provision_owner() {
    let backend = GatedProvisionBackend::with_outcomes([Ok("created")]);
    let supervisor = Arc::new(SandboxSupervisor::new(config(), backend.clone()));
    let spec = launch_spec(
        TenantId::new(),
        ShardId::new(),
        1,
        "public-web",
        [3; 32],
        Duration::from_secs(5),
    );
    let leader = tokio::spawn({
        let supervisor = Arc::clone(&supervisor);
        let spec = spec.clone();
        async move { supervisor.create_shard(spec, ownership()).await }
    });
    backend.wait_until_entered(1).await;

    let mut cancelled_waiter = Box::pin(supervisor.create_shard(spec.clone(), ownership()));
    assert!(futures::poll!(cancelled_waiter.as_mut()).is_pending());
    drop(cancelled_waiter);
    backend.release_one();

    assert_eq!(
        leader.await.expect("leader task should finish"),
        Ok(CreateShardOutcome::Created)
    );
    assert_eq!(
        supervisor.create_shard(spec, ownership()).await,
        Ok(CreateShardOutcome::AlreadyExists)
    );
    assert_eq!(backend.calls.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn disconnecting_the_first_create_waiter_does_not_cancel_the_provision_owner() {
    let backend = GatedProvisionBackend::with_outcomes([Ok("created")]);
    let supervisor = SandboxSupervisor::new(config(), backend.clone());
    let spec = launch_spec(
        TenantId::new(),
        ShardId::new(),
        1,
        "public-web",
        [31; 32],
        Duration::from_secs(5),
    );

    let mut disconnected = Box::pin(supervisor.create_shard(spec.clone(), ownership()));
    assert!(futures::poll!(disconnected.as_mut()).is_pending());
    backend.wait_until_entered(1).await;
    drop(disconnected);
    backend.release_one();

    assert_eq!(
        tokio::time::timeout(
            Duration::from_millis(200),
            supervisor.create_shard(spec, ownership()),
        )
        .await
        .expect("the supervisor-owned create must finish after its RPC waiter disconnects"),
        Ok(CreateShardOutcome::AlreadyExists)
    );
    assert_eq!(backend.calls.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn in_flight_binding_conflicts_are_typed_without_a_second_backend_effect() {
    let backend = GatedProvisionBackend::with_outcomes([Ok("created")]);
    let supervisor = Arc::new(SandboxSupervisor::new(config(), backend.clone()));
    let tenant_id = TenantId::new();
    let shard_id = ShardId::new();
    let spec = launch_spec(
        tenant_id.clone(),
        shard_id.clone(),
        1,
        "public-web",
        [4; 32],
        Duration::from_secs(5),
    );
    let different_binding = DedicatedEgressSpec::new(
        spec.dedicated_egress().egress_fence().clone(),
        EgressPolicyBinding::new("restricted-web", [5; 32]).expect("binding should be valid"),
        Duration::from_secs(5),
    )
    .expect("egress spec should be valid");
    let different_ttl = DedicatedEgressSpec::new(
        spec.dedicated_egress().egress_fence().clone(),
        spec.dedicated_egress().policy_binding().clone(),
        Duration::from_secs(6),
    )
    .expect("egress spec should be valid");
    let leader = tokio::spawn({
        let supervisor = Arc::clone(&supervisor);
        let spec = spec.clone();
        async move { supervisor.create_shard(spec, ownership()).await }
    });
    backend.wait_until_entered(1).await;

    assert_eq!(
        supervisor
            .create_shard(
                LaunchSpec::production(
                    tenant_id.clone(),
                    different_binding,
                    ChromiumBinaryDigest::new([0x3c; 32]),
                ),
                ownership(),
            )
            .await,
        Err(SandboxError::LaunchBindingMismatch)
    );
    assert_eq!(
        supervisor
            .create_shard(
                LaunchSpec::production(
                    tenant_id,
                    different_ttl,
                    ChromiumBinaryDigest::new([0x3c; 32]),
                ),
                ownership()
            )
            .await,
        Err(SandboxError::LaunchBindingMismatch)
    );
    assert_eq!(backend.calls.load(Ordering::Acquire), 1);

    backend.release_one();
    assert_eq!(
        leader.await.expect("leader task should finish"),
        Ok(CreateShardOutcome::Created)
    );
}

#[tokio::test]
async fn a_waiting_retry_never_holds_the_supervisor_mutex() {
    let backend = GatedProvisionBackend::with_outcomes([Ok("created")]);
    let supervisor = Arc::new(SandboxSupervisor::new(config(), backend.clone()));
    let spec = launch_spec(
        TenantId::new(),
        ShardId::new(),
        1,
        "public-web",
        [6; 32],
        Duration::from_secs(5),
    );
    let shard_id = spec.shard_id().clone();
    let leader = tokio::spawn({
        let supervisor = Arc::clone(&supervisor);
        let spec = spec.clone();
        async move { supervisor.create_shard(spec, ownership()).await }
    });
    backend.wait_until_entered(1).await;
    let mut waiter = Box::pin(supervisor.create_shard(spec, ownership()));
    assert!(futures::poll!(waiter.as_mut()).is_pending());

    let now = Instant::now();
    tokio::time::timeout(
        Duration::from_millis(100),
        supervisor.renew_owner_lease(
            &shard_id,
            17,
            LaunchGeneration::new(1).expect("launch generation should be positive"),
            now,
            now + Duration::from_secs(5),
        ),
    )
    .await
    .expect("a waiting create retry must not hold the supervisor mutex")
    .expect("the provisioning owner lease should renew");

    backend.release_one();
    assert_eq!(
        leader.await.expect("leader task should finish"),
        Ok(CreateShardOutcome::Created)
    );
    assert_eq!(waiter.await, Ok(CreateShardOutcome::AlreadyExists));
}

#[tokio::test]
async fn only_a_newer_launch_generation_supersedes_a_failed_tombstone() {
    let failure = SandboxError::Backend("first launch failed".to_owned());
    let backend = GatedProvisionBackend::with_outcomes([Err(failure.clone()), Ok("new-launch")]);
    let supervisor = SandboxSupervisor::new(config(), backend.clone());
    let tenant_id = TenantId::new();
    let shard_id = ShardId::new();
    let first = launch_spec(
        tenant_id.clone(),
        shard_id.clone(),
        1,
        "public-web",
        [7; 32],
        Duration::from_secs(5),
    );
    let first_create = tokio::spawn({
        let supervisor = supervisor.clone();
        let first = first.clone();
        async move { supervisor.create_shard(first, ownership()).await }
    });
    backend.wait_until_entered(1).await;
    backend.release_one();
    assert_eq!(
        first_create.await.expect("first create should finish"),
        Err(failure.clone())
    );

    let changed_binding = DedicatedEgressSpec::new(
        first.dedicated_egress().egress_fence().clone(),
        EgressPolicyBinding::new("other-policy", [8; 32]).expect("binding should be valid"),
        Duration::from_secs(5),
    )
    .expect("egress spec should be valid");
    assert_eq!(
        supervisor
            .create_shard(
                LaunchSpec::production(
                    tenant_id.clone(),
                    changed_binding,
                    ChromiumBinaryDigest::new([0x3c; 32]),
                ),
                ownership(),
            )
            .await,
        Err(SandboxError::LaunchBindingMismatch)
    );

    let newer = launch_spec(
        tenant_id,
        shard_id,
        2,
        "public-web-v2",
        [9; 32],
        Duration::from_secs(5),
    );
    let newer_create = tokio::spawn({
        let supervisor = supervisor.clone();
        async move { supervisor.create_shard(newer, ownership()).await }
    });
    backend.wait_until_entered(2).await;
    backend.release_one();

    assert_eq!(
        newer_create.await.expect("newer create should finish"),
        Ok(CreateShardOutcome::Created)
    );
    assert_eq!(backend.calls.load(Ordering::Acquire), 2);
}
