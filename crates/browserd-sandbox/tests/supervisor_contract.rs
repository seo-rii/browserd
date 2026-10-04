#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::os::fd::OwnedFd;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use browserd_core::{
    EgressFence, LaunchGeneration, OwnerFence, RouteGeneration, SessionId, SessionIncarnation,
    ShardFence, ShardId, TenantId, WorkerEpoch, WorkerId,
};
use browserd_sandbox::{
    ChromiumBinaryDigest, ChromiumCdpPipes, CleanupReason, CleanupResult, CreateShardOutcome,
    DedicatedEgressSpec, EgressPolicyBinding, InspectResources, KillShardOutcome, LaunchSpec,
    RenewLeaseError, SandboxBackend, SandboxCapabilities, SandboxError, SandboxHandle,
    SandboxSupervisor, SupervisorConfig, WorkerOwnership,
};
use tokio::sync::Notify;
use tokio::time::Instant;

#[derive(Clone)]
struct RecordingBackend {
    capabilities: SandboxCapabilities,
    events: Arc<Mutex<Vec<String>>>,
    renew_gate: Option<(Arc<Notify>, Arc<Notify>)>,
    fail_renew: bool,
    fail_revoke: bool,
}

impl RecordingBackend {
    fn production_capable() -> Self {
        Self {
            capabilities: SandboxCapabilities::production_required(),
            events: Arc::new(Mutex::new(Vec::new())),
            renew_gate: None,
            fail_renew: false,
            fail_revoke: false,
        }
    }

    fn events(&self) -> Vec<String> {
        self.events.lock().unwrap().clone()
    }

    fn record(&self, event: &str) {
        self.events.lock().unwrap().push(event.to_owned());
    }
}

#[async_trait]
impl SandboxBackend for RecordingBackend {
    fn capabilities(&self) -> SandboxCapabilities {
        self.capabilities
    }

    async fn provision(&self, spec: &LaunchSpec) -> Result<SandboxHandle, SandboxError> {
        self.record("provision");
        Ok(SandboxHandle::new(
            spec.shard_id().clone(),
            "backend-handle",
        ))
    }

    async fn renew_egress(
        &self,
        _handle: &SandboxHandle,
        _lease_ttl: Duration,
    ) -> Result<(), SandboxError> {
        self.record("renew_egress");
        if let Some((entered, proceed)) = &self.renew_gate {
            entered.notify_one();
            proceed.notified().await;
        }
        if self.fail_renew {
            Err(SandboxError::Backend("route renewal failed".to_owned()))
        } else {
            Ok(())
        }
    }

    async fn revoke_egress(
        &self,
        _handle: &SandboxHandle,
        _reason: CleanupReason,
    ) -> Result<(), SandboxError> {
        self.record("revoke_egress");
        if self.fail_revoke {
            Err(SandboxError::Backend("route revoke failed".to_owned()))
        } else {
            Ok(())
        }
    }

    async fn kill_cgroup(
        &self,
        _handle: &SandboxHandle,
        _reason: CleanupReason,
    ) -> Result<(), SandboxError> {
        self.record("kill_cgroup");
        Ok(())
    }

    async fn cleanup_namespaces(&self, _handle: &SandboxHandle) -> Result<(), SandboxError> {
        self.record("cleanup_namespaces");
        Ok(())
    }

    async fn inspect(&self, _handle: &SandboxHandle) -> Result<InspectResources, SandboxError> {
        Ok(InspectResources {
            memory_current_bytes: 123,
            memory_peak_bytes: 456,
            process_count: 7,
            egress_route_active: true,
        })
    }
}

fn worker() -> WorkerId {
    WorkerId::new("worker-apne2-a-001").expect("test worker ID must be valid")
}

fn launch_generation() -> LaunchGeneration {
    LaunchGeneration::new(1).expect("launch generation is positive")
}

fn config() -> SupervisorConfig {
    SupervisorConfig::new(Duration::from_secs(10), Duration::from_secs(30))
        .expect("lease ordering must be valid")
}

fn launch_spec(shard_id: ShardId) -> LaunchSpec {
    let worker_epoch = WorkerEpoch::new(17).expect("worker epoch is positive");
    let egress_fence = EgressFence::new(
        ShardFence::new(
            OwnerFence::new(worker(), worker_epoch),
            shard_id,
            launch_generation(),
        ),
        RouteGeneration::new(1).expect("route generation is positive"),
        SessionId::new(),
        SessionIncarnation::new(1).expect("session incarnation is positive"),
    );
    let policy_binding =
        EgressPolicyBinding::new("test-public-web", [1; 32]).expect("policy binding is valid");
    let dedicated_egress =
        DedicatedEgressSpec::new(egress_fence, policy_binding, Duration::from_secs(5))
            .expect("dedicated egress spec is valid");
    LaunchSpec::production(
        TenantId::new(),
        dedicated_egress,
        ChromiumBinaryDigest::new([0x3c; 32]),
    )
}

#[derive(Clone)]
struct ClaimingBackend {
    pipes: Arc<Mutex<Option<ChromiumCdpPipes>>>,
    claim_calls: Arc<AtomicUsize>,
    claim_gate: Option<(Arc<Notify>, Arc<Notify>)>,
    revoke_calls: Arc<AtomicUsize>,
    revoke_called: Arc<Notify>,
    fail_first_revoke: bool,
    kill_reasons: Arc<Mutex<Vec<CleanupReason>>>,
    kill_called: Arc<Notify>,
    claim_completed: Arc<Notify>,
    panic_on_claim: bool,
}

impl ClaimingBackend {
    fn new() -> Self {
        let (backend, command_reader) = Self::with_gate(None);
        drop(command_reader);
        backend
    }

    fn blocked() -> (Self, Arc<Notify>, Arc<Notify>, OwnedFd) {
        let entered = Arc::new(Notify::new());
        let proceed = Arc::new(Notify::new());
        let (backend, command_reader) =
            Self::with_gate(Some((Arc::clone(&entered), Arc::clone(&proceed))));
        (backend, entered, proceed, command_reader)
    }

    fn blocked_with_transient_revoke_failure() -> (Self, Arc<Notify>, Arc<Notify>, OwnedFd) {
        let (mut backend, entered, proceed, command_reader) = Self::blocked();
        backend.fail_first_revoke = true;
        (backend, entered, proceed, command_reader)
    }

    fn panicking() -> Self {
        let mut backend = Self::new();
        backend.panic_on_claim = true;
        backend
    }

    fn with_gate(gate: Option<(Arc<Notify>, Arc<Notify>)>) -> (Self, OwnedFd) {
        let (command_reader, command_writer) = nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC)
            .expect("command pipe should be created");
        let (event_reader, event_writer) =
            nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).expect("event pipe should be created");
        drop(event_writer);
        (
            Self {
                pipes: Arc::new(Mutex::new(Some(
                    ChromiumCdpPipes::from_owned_fds(command_writer, event_reader)
                        .expect("directional CDP capabilities should be valid"),
                ))),
                claim_calls: Arc::new(AtomicUsize::new(0)),
                claim_gate: gate,
                revoke_calls: Arc::new(AtomicUsize::new(0)),
                revoke_called: Arc::new(Notify::new()),
                fail_first_revoke: false,
                kill_reasons: Arc::new(Mutex::new(Vec::new())),
                kill_called: Arc::new(Notify::new()),
                claim_completed: Arc::new(Notify::new()),
                panic_on_claim: false,
            },
            command_reader,
        )
    }
}

#[async_trait]
impl SandboxBackend for ClaimingBackend {
    fn capabilities(&self) -> SandboxCapabilities {
        SandboxCapabilities::production_required()
    }

    async fn provision(&self, spec: &LaunchSpec) -> Result<SandboxHandle, SandboxError> {
        Ok(SandboxHandle::new(spec.shard_id().clone(), "claiming"))
    }

    async fn claim_cdp_pipes(
        &self,
        _handle: &SandboxHandle,
    ) -> Result<ChromiumCdpPipes, SandboxError> {
        self.claim_calls.fetch_add(1, Ordering::AcqRel);
        if let Some((entered, proceed)) = &self.claim_gate {
            entered.notify_one();
            proceed.notified().await;
        }
        if self.panic_on_claim {
            panic!("simulated CDP claim panic");
        }
        let result = self
            .pipes
            .lock()
            .unwrap()
            .take()
            .ok_or_else(|| SandboxError::Backend("CDP pipes already claimed".to_owned()));
        if result.is_ok() {
            self.claim_completed.notify_one();
        }
        result
    }

    async fn revoke_egress(
        &self,
        _handle: &SandboxHandle,
        _reason: CleanupReason,
    ) -> Result<(), SandboxError> {
        let call = self.revoke_calls.fetch_add(1, Ordering::AcqRel);
        self.revoke_called.notify_one();
        if self.fail_first_revoke && call == 0 {
            Err(SandboxError::Backend(
                "transient route revoke failure".to_owned(),
            ))
        } else {
            Ok(())
        }
    }

    async fn kill_cgroup(
        &self,
        _handle: &SandboxHandle,
        reason: CleanupReason,
    ) -> Result<(), SandboxError> {
        self.kill_reasons.lock().unwrap().push(reason);
        self.kill_called.notify_one();
        Ok(())
    }

    async fn cleanup_namespaces(&self, _handle: &SandboxHandle) -> Result<(), SandboxError> {
        Ok(())
    }

    async fn inspect(&self, _handle: &SandboxHandle) -> Result<InspectResources, SandboxError> {
        Err(SandboxError::Backend("not used".to_owned()))
    }
}

#[tokio::test]
async fn cdp_capability_claim_is_epoch_fenced_and_one_shot() {
    let backend = ClaimingBackend::new();
    let supervisor = SandboxSupervisor::new(config(), backend.clone());
    let shard_id = ShardId::new();
    supervisor
        .create_shard(
            launch_spec(shard_id.clone()),
            WorkerOwnership::new(worker(), 17, Instant::now() + Duration::from_secs(10)),
        )
        .await
        .expect("sandbox creation should succeed");

    assert!(matches!(
        supervisor
            .claim_cdp_pipes(&shard_id, &worker(), 16, launch_generation())
            .await,
        Err(SandboxError::WorkerEpochMismatch {
            expected: 17,
            actual: 16,
        })
    ));
    assert_eq!(backend.claim_calls.load(Ordering::Acquire), 0);
    let other_worker = WorkerId::new("worker-apne2-a-002").expect("test worker ID must be valid");
    assert!(matches!(
        supervisor
            .claim_cdp_pipes(&shard_id, &other_worker, 17, launch_generation())
            .await,
        Err(SandboxError::OwnershipMismatch)
    ));
    assert_eq!(backend.claim_calls.load(Ordering::Acquire), 0);
    let claimed = supervisor
        .claim_cdp_pipes(&shard_id, &worker(), 17, launch_generation())
        .await;
    assert!(claimed.is_ok());
    assert_eq!(backend.claim_calls.load(Ordering::Acquire), 1);
    let duplicate = supervisor
        .claim_cdp_pipes(&shard_id, &worker(), 17, launch_generation())
        .await;
    assert!(matches!(
        duplicate,
        Err(SandboxError::CdpPipesAlreadyClaimed)
    ));
}

#[tokio::test]
async fn expired_owner_cannot_claim_cdp_capabilities_before_the_sweeper_runs() {
    let backend = ClaimingBackend::new();
    let short_config =
        SupervisorConfig::new(Duration::from_millis(100), Duration::from_millis(300))
            .expect("short lease ordering should be valid");
    let supervisor = SandboxSupervisor::new(short_config, backend.clone());
    let shard_id = ShardId::new();
    supervisor
        .create_shard(
            launch_spec(shard_id.clone()),
            WorkerOwnership::new(worker(), 17, Instant::now() + Duration::from_millis(50)),
        )
        .await
        .expect("sandbox creation should succeed");
    tokio::time::sleep(Duration::from_millis(75)).await;

    assert!(matches!(
        supervisor
            .claim_cdp_pipes(&shard_id, &worker(), 17, launch_generation())
            .await,
        Err(SandboxError::InvalidOwnerLease)
    ));
    assert_eq!(backend.claim_calls.load(Ordering::Acquire), 0);
}

#[tokio::test]
async fn concurrent_cdp_claim_is_rejected_before_a_second_backend_effect() {
    let (backend, claim_entered, release_claim, _command_reader) = ClaimingBackend::blocked();
    let supervisor = Arc::new(SandboxSupervisor::new(config(), backend.clone()));
    let shard_id = ShardId::new();
    supervisor
        .create_shard(
            launch_spec(shard_id.clone()),
            WorkerOwnership::new(worker(), 17, Instant::now() + Duration::from_secs(10)),
        )
        .await
        .expect("sandbox creation should succeed");

    let first_supervisor = Arc::clone(&supervisor);
    let first_shard_id = shard_id.clone();
    let first = tokio::spawn(async move {
        first_supervisor
            .claim_cdp_pipes(&first_shard_id, &worker(), 17, launch_generation())
            .await
    });
    claim_entered.notified().await;

    let concurrent = tokio::time::timeout(
        Duration::from_millis(100),
        supervisor.claim_cdp_pipes(&shard_id, &worker(), 17, launch_generation()),
    )
    .await;
    release_claim.notify_one();
    let first_result = first.await.expect("first claim task should finish");

    assert!(matches!(
        concurrent,
        Ok(Err(SandboxError::CdpClaimInProgress))
    ));
    assert!(first_result.is_ok());
    assert_eq!(backend.claim_calls.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn kill_linearized_during_cdp_claim_prevents_stale_capability_handoff() {
    let (backend, claim_entered, release_claim, _command_reader) = ClaimingBackend::blocked();
    let supervisor = Arc::new(SandboxSupervisor::new(config(), backend.clone()));
    let shard_id = ShardId::new();
    supervisor
        .create_shard(
            launch_spec(shard_id.clone()),
            WorkerOwnership::new(worker(), 17, Instant::now() + Duration::from_secs(10)),
        )
        .await
        .expect("sandbox creation should succeed");

    let claim_supervisor = Arc::clone(&supervisor);
    let claim_shard_id = shard_id.clone();
    let claim = tokio::spawn(async move {
        claim_supervisor
            .claim_cdp_pipes(&claim_shard_id, &worker(), 17, launch_generation())
            .await
    });
    claim_entered.notified().await;
    let killed = supervisor
        .kill_shard(
            &shard_id,
            17,
            launch_generation(),
            CleanupReason::SecurityViolation,
        )
        .await;
    assert!(matches!(killed, Ok(KillShardOutcome::Terminated(_))));

    release_claim.notify_one();
    assert!(matches!(
        claim.await.expect("claim task should finish"),
        Err(SandboxError::ShardNotFound)
    ));
    assert_eq!(
        backend.kill_reasons.lock().unwrap().as_slice(),
        [CleanupReason::SecurityViolation]
    );
}

#[tokio::test]
async fn lease_expiry_during_cdp_claim_drops_capabilities_and_starts_cleanup() {
    let (backend, claim_entered, release_claim, _command_reader) = ClaimingBackend::blocked();
    let short_config =
        SupervisorConfig::new(Duration::from_millis(100), Duration::from_millis(300))
            .expect("short lease ordering should be valid");
    let supervisor = Arc::new(SandboxSupervisor::new(short_config, backend.clone()));
    let shard_id = ShardId::new();
    supervisor
        .create_shard(
            launch_spec(shard_id.clone()),
            WorkerOwnership::new(worker(), 17, Instant::now() + Duration::from_millis(50)),
        )
        .await
        .expect("sandbox creation should succeed");

    let claim_supervisor = Arc::clone(&supervisor);
    let claim_shard_id = shard_id.clone();
    let claim = tokio::spawn(async move {
        claim_supervisor
            .claim_cdp_pipes(&claim_shard_id, &worker(), 17, launch_generation())
            .await
    });
    claim_entered.notified().await;
    tokio::time::sleep(Duration::from_millis(75)).await;
    release_claim.notify_one();

    assert!(matches!(
        claim.await.expect("claim task should finish"),
        Err(SandboxError::InvalidOwnerLease)
    ));
    assert_eq!(
        backend.kill_reasons.lock().unwrap().as_slice(),
        [CleanupReason::WorkerLeaseExpired]
    );
}

#[tokio::test]
async fn cancelling_cdp_claim_caller_drops_returned_fds_and_fails_closed() {
    let (backend, claim_entered, release_claim, command_reader) = ClaimingBackend::blocked();
    nix::fcntl::fcntl(
        &command_reader,
        nix::fcntl::FcntlArg::F_SETFL(nix::fcntl::OFlag::O_NONBLOCK),
    )
    .expect("test command reader should become nonblocking");
    let supervisor = Arc::new(SandboxSupervisor::new(config(), backend.clone()));
    let shard_id = ShardId::new();
    supervisor
        .create_shard(
            launch_spec(shard_id.clone()),
            WorkerOwnership::new(worker(), 17, Instant::now() + Duration::from_secs(10)),
        )
        .await
        .expect("sandbox creation should succeed");

    let claim_supervisor = Arc::clone(&supervisor);
    let claim_shard_id = shard_id.clone();
    let claim = tokio::spawn(async move {
        claim_supervisor
            .claim_cdp_pipes(&claim_shard_id, &worker(), 17, launch_generation())
            .await
    });
    claim_entered.notified().await;
    claim.abort();
    assert!(
        claim
            .await
            .expect_err("claim caller should be cancelled")
            .is_cancelled()
    );
    release_claim.notify_one();

    tokio::time::timeout(Duration::from_millis(200), backend.kill_called.notified())
        .await
        .expect("cancelled handoff should start cleanup");
    assert_eq!(
        backend.kill_reasons.lock().unwrap().as_slice(),
        [CleanupReason::BrowserFailure]
    );
    let mut byte = [0_u8; 1];
    assert_eq!(nix::unistd::read(&command_reader, &mut byte), Ok(0));
}

#[tokio::test]
async fn cancelling_claim_during_backend_retries_incomplete_cleanup_to_terminal() {
    let (backend, claim_entered, release_claim, command_reader) =
        ClaimingBackend::blocked_with_transient_revoke_failure();
    nix::fcntl::fcntl(
        &command_reader,
        nix::fcntl::FcntlArg::F_SETFL(nix::fcntl::OFlag::O_NONBLOCK),
    )
    .expect("test command reader should become nonblocking");
    let bounded_config = config()
        .with_cleanup_stage_timeout(Duration::from_millis(20))
        .expect("cleanup timeout should be valid");
    let supervisor = Arc::new(SandboxSupervisor::new(bounded_config, backend.clone()));
    let shard_id = ShardId::new();
    supervisor
        .create_shard(
            launch_spec(shard_id.clone()),
            WorkerOwnership::new(worker(), 17, Instant::now() + Duration::from_secs(10)),
        )
        .await
        .expect("sandbox creation should succeed");

    let claim_supervisor = Arc::clone(&supervisor);
    let claim_shard_id = shard_id.clone();
    let claim = tokio::spawn(async move {
        claim_supervisor
            .claim_cdp_pipes(&claim_shard_id, &worker(), 17, launch_generation())
            .await
    });
    tokio::time::timeout(Duration::from_millis(200), claim_entered.notified())
        .await
        .expect("claim backend must reach its blocking boundary");
    claim.abort();
    assert!(
        claim
            .await
            .expect_err("claim caller should be cancelled while the backend is blocked")
            .is_cancelled()
    );
    release_claim.notify_one();

    let cleanup_retried = tokio::time::timeout(Duration::from_millis(200), async {
        loop {
            if backend.revoke_calls.load(Ordering::Acquire) >= 2 {
                break;
            }
            backend.revoke_called.notified().await;
        }
    })
    .await;
    assert!(
        cleanup_retried.is_ok(),
        "an incomplete cancellation cleanup must retry its failed stage"
    );
    assert_eq!(backend.revoke_calls.load(Ordering::Acquire), 2);
    assert!(matches!(
        supervisor
            .kill_shard(
                &shard_id,
                17,
                launch_generation(),
                CleanupReason::BrowserFailure,
            )
            .await,
        Ok(KillShardOutcome::AlreadyTerminated)
    ));
    assert_eq!(
        backend.kill_reasons.lock().unwrap().as_slice(),
        [CleanupReason::BrowserFailure]
    );
    let mut byte = [0_u8; 1];
    assert_eq!(nix::unistd::read(&command_reader, &mut byte), Ok(0));
}

#[tokio::test]
async fn dropping_cdp_claim_after_delivery_but_before_receipt_fails_closed() {
    let (backend, claim_entered, release_claim, command_reader) = ClaimingBackend::blocked();
    nix::fcntl::fcntl(
        &command_reader,
        nix::fcntl::FcntlArg::F_SETFL(nix::fcntl::OFlag::O_NONBLOCK),
    )
    .expect("test command reader should become nonblocking");
    let supervisor = SandboxSupervisor::new(config(), backend.clone());
    let shard_id = ShardId::new();
    let owner = worker();
    supervisor
        .create_shard(
            launch_spec(shard_id.clone()),
            WorkerOwnership::new(owner.clone(), 17, Instant::now() + Duration::from_secs(10)),
        )
        .await
        .expect("sandbox creation should succeed");

    let mut claim =
        Box::pin(supervisor.claim_cdp_pipes(&shard_id, &owner, 17, launch_generation()));
    assert!(futures::poll!(claim.as_mut()).is_pending());
    claim_entered.notified().await;
    release_claim.notify_one();
    backend.claim_completed.notified().await;
    tokio::task::yield_now().await;
    drop(claim);

    tokio::time::timeout(Duration::from_millis(200), backend.kill_called.notified())
        .await
        .expect("an unacknowledged delivered capability should start cleanup");
    assert_eq!(
        backend.kill_reasons.lock().unwrap().as_slice(),
        [CleanupReason::BrowserFailure]
    );
    let mut byte = [0_u8; 1];
    assert_eq!(nix::unistd::read(&command_reader, &mut byte), Ok(0));
}

#[tokio::test]
async fn kill_after_backend_delivery_is_revalidated_before_caller_receipt() {
    let (backend, claim_entered, release_claim, _command_reader) = ClaimingBackend::blocked();
    let supervisor = SandboxSupervisor::new(config(), backend.clone());
    let shard_id = ShardId::new();
    let owner = worker();
    supervisor
        .create_shard(
            launch_spec(shard_id.clone()),
            WorkerOwnership::new(owner.clone(), 17, Instant::now() + Duration::from_secs(10)),
        )
        .await
        .expect("sandbox creation should succeed");

    let mut claim =
        Box::pin(supervisor.claim_cdp_pipes(&shard_id, &owner, 17, launch_generation()));
    assert!(futures::poll!(claim.as_mut()).is_pending());
    claim_entered.notified().await;
    release_claim.notify_one();
    backend.claim_completed.notified().await;
    tokio::task::yield_now().await;
    assert!(matches!(
        supervisor
            .kill_shard(
                &shard_id,
                17,
                launch_generation(),
                CleanupReason::SecurityViolation,
            )
            .await,
        Ok(KillShardOutcome::Terminated(_))
    ));

    assert!(matches!(claim.await, Err(SandboxError::ShardNotFound)));
}

#[tokio::test]
async fn hung_cdp_backend_claim_is_bounded_and_fails_closed() {
    let (backend, claim_entered, release_claim, _command_reader) = ClaimingBackend::blocked();
    let bounded_config = config()
        .with_cleanup_stage_timeout(Duration::from_millis(20))
        .expect("claim timeout should be valid");
    let supervisor = Arc::new(SandboxSupervisor::new(bounded_config, backend.clone()));
    let shard_id = ShardId::new();
    supervisor
        .create_shard(
            launch_spec(shard_id.clone()),
            WorkerOwnership::new(worker(), 17, Instant::now() + Duration::from_secs(10)),
        )
        .await
        .expect("sandbox creation should succeed");

    let claim_supervisor = Arc::clone(&supervisor);
    let claim_shard_id = shard_id.clone();
    let claim = tokio::spawn(async move {
        claim_supervisor
            .claim_cdp_pipes(&claim_shard_id, &worker(), 17, launch_generation())
            .await
    });
    claim_entered.notified().await;
    let bounded = tokio::time::timeout(Duration::from_millis(200), claim).await;
    release_claim.notify_one();

    assert!(matches!(
        bounded,
        Ok(Ok(Err(SandboxError::Backend(message)))) if message.contains("timed out")
    ));
    assert_eq!(
        backend.kill_reasons.lock().unwrap().as_slice(),
        [CleanupReason::BrowserFailure]
    );
}

#[tokio::test]
async fn panicking_cdp_backend_claim_is_caught_and_fails_closed() {
    let backend = ClaimingBackend::panicking();
    let supervisor = SandboxSupervisor::new(config(), backend.clone());
    let shard_id = ShardId::new();
    supervisor
        .create_shard(
            launch_spec(shard_id.clone()),
            WorkerOwnership::new(worker(), 17, Instant::now() + Duration::from_secs(10)),
        )
        .await
        .expect("sandbox creation should succeed");

    let result = supervisor
        .claim_cdp_pipes(&shard_id, &worker(), 17, launch_generation())
        .await;

    assert!(matches!(
        result,
        Err(SandboxError::Backend(message)) if message.contains("panicked")
    ));
    assert_eq!(
        backend.kill_reasons.lock().unwrap().as_slice(),
        [CleanupReason::BrowserFailure]
    );
}

#[test]
fn supervisor_lease_must_not_outlive_directory_lease() {
    assert!(SupervisorConfig::new(Duration::from_secs(10), Duration::from_secs(30)).is_ok());
    assert!(SupervisorConfig::new(Duration::from_secs(30), Duration::from_secs(30)).is_ok());
    assert!(matches!(
        SupervisorConfig::new(Duration::from_secs(31), Duration::from_secs(30)),
        Err(SandboxError::InvalidLeaseOrdering)
    ));
    assert!(matches!(
        SupervisorConfig::new(Duration::ZERO, Duration::from_secs(30)),
        Err(SandboxError::ZeroLeaseTtl)
    ));
}

#[tokio::test]
async fn production_creation_fails_closed_when_any_required_capability_is_missing() {
    for capability in SandboxCapabilities::REQUIRED_NAMES {
        let mut capabilities = SandboxCapabilities::production_required();
        capabilities.disable(capability);
        let backend = RecordingBackend {
            capabilities,
            events: Arc::new(Mutex::new(Vec::new())),
            renew_gate: None,
            fail_renew: false,
            fail_revoke: false,
        };
        let supervisor = SandboxSupervisor::new(config(), backend.clone());
        let shard_id = ShardId::new();
        let result = supervisor
            .create_shard(
                launch_spec(shard_id),
                WorkerOwnership::new(worker(), 17, Instant::now() + Duration::from_secs(10)),
            )
            .await;

        assert!(matches!(
            result,
            Err(SandboxError::MissingCapability { name }) if name == capability
        ));
        assert!(backend.events().is_empty());
    }
}

#[tokio::test]
async fn creation_rejects_expired_or_overlong_owner_leases_before_provisioning() {
    let backend = RecordingBackend::production_capable();
    let supervisor = SandboxSupervisor::new(config(), backend.clone());
    let now = Instant::now();

    for expires_at in [
        now.checked_sub(Duration::from_millis(1)).unwrap(),
        now + Duration::from_secs(11),
    ] {
        let outcome = supervisor
            .create_shard(
                launch_spec(ShardId::new()),
                WorkerOwnership::new(worker(), 17, expires_at),
            )
            .await;
        assert_eq!(outcome, Err(SandboxError::InvalidOwnerLease));
    }
    assert!(backend.events().is_empty());
}

#[tokio::test]
async fn stale_worker_epoch_cannot_renew_or_control_a_shard() {
    let backend = RecordingBackend::production_capable();
    let supervisor = SandboxSupervisor::new(config(), backend);
    let shard_id = ShardId::new();
    let now = Instant::now();
    supervisor
        .create_shard(
            launch_spec(shard_id.clone()),
            WorkerOwnership::new(worker(), 17, now + Duration::from_secs(10)),
        )
        .await
        .expect("sandbox creation must succeed");

    assert_eq!(
        supervisor
            .renew_owner_lease(
                &shard_id,
                16,
                launch_generation(),
                now + Duration::from_secs(5),
                now + Duration::from_secs(15)
            )
            .await,
        Err(RenewLeaseError::WorkerEpochMismatch {
            expected: 17,
            actual: 16,
        })
    );
    assert!(
        supervisor
            .renew_owner_lease(
                &shard_id,
                17,
                launch_generation(),
                now + Duration::from_secs(5),
                now + Duration::from_secs(15)
            )
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn owner_lease_renewal_extends_egress_before_committing_local_ownership() {
    let backend = RecordingBackend::production_capable();
    let supervisor = SandboxSupervisor::new(config(), backend.clone());
    let shard_id = ShardId::new();
    let now = Instant::now();
    supervisor
        .create_shard(
            launch_spec(shard_id.clone()),
            WorkerOwnership::new(worker(), 17, now + Duration::from_secs(5)),
        )
        .await
        .expect("sandbox creation must succeed");

    supervisor
        .renew_owner_lease(
            &shard_id,
            17,
            launch_generation(),
            now + Duration::from_secs(1),
            now + Duration::from_secs(9),
        )
        .await
        .expect("owner and egress leases should renew together");

    assert_eq!(backend.events(), ["provision", "renew_egress"]);
    assert!(
        supervisor
            .expire_leases(now + Duration::from_secs(6))
            .await
            .is_empty(),
        "local ownership must remain live only after egress renewal succeeds"
    );
}

#[tokio::test]
async fn failed_egress_renewal_does_not_extend_local_ownership() {
    let mut backend = RecordingBackend::production_capable();
    backend.fail_renew = true;
    let supervisor = SandboxSupervisor::new(config(), backend.clone());
    let shard_id = ShardId::new();
    let now = Instant::now();
    supervisor
        .create_shard(
            launch_spec(shard_id.clone()),
            WorkerOwnership::new(worker(), 17, now + Duration::from_secs(5)),
        )
        .await
        .expect("sandbox creation must succeed");

    assert_eq!(
        supervisor
            .renew_owner_lease(
                &shard_id,
                17,
                launch_generation(),
                now + Duration::from_secs(1),
                now + Duration::from_secs(9),
            )
            .await,
        Err(RenewLeaseError::EgressRenewalFailed)
    );

    assert_eq!(backend.events(), ["provision", "renew_egress"]);
    assert_eq!(
        supervisor
            .expire_leases(now + Duration::from_secs(6))
            .await
            .len(),
        1,
        "failed route renewal must leave the original owner expiry intact"
    );
}

#[tokio::test]
async fn owner_lease_renewal_cannot_shorten_an_active_lease() {
    let backend = RecordingBackend::production_capable();
    let supervisor = SandboxSupervisor::new(config(), backend.clone());
    let shard_id = ShardId::new();
    let now = Instant::now();
    supervisor
        .create_shard(
            launch_spec(shard_id.clone()),
            WorkerOwnership::new(worker(), 17, now + Duration::from_secs(8)),
        )
        .await
        .expect("sandbox creation must succeed");

    assert_eq!(
        supervisor
            .renew_owner_lease(
                &shard_id,
                17,
                launch_generation(),
                now + Duration::from_secs(1),
                now + Duration::from_secs(7),
            )
            .await,
        Err(RenewLeaseError::InvalidNewExpiry)
    );
    assert_eq!(backend.events(), ["provision"]);
}

#[tokio::test]
async fn concurrent_owner_renewals_are_serialized_without_expiry_regression() {
    let entered = Arc::new(Notify::new());
    let proceed = Arc::new(Notify::new());
    let mut backend = RecordingBackend::production_capable();
    backend.renew_gate = Some((Arc::clone(&entered), Arc::clone(&proceed)));
    let supervisor = Arc::new(SandboxSupervisor::new(config(), backend.clone()));
    let shard_id = ShardId::new();
    let now = Instant::now();
    supervisor
        .create_shard(
            launch_spec(shard_id.clone()),
            WorkerOwnership::new(worker(), 17, now + Duration::from_secs(5)),
        )
        .await
        .expect("sandbox creation must succeed");

    let longer = tokio::spawn({
        let supervisor = Arc::clone(&supervisor);
        let shard_id = shard_id.clone();
        async move {
            supervisor
                .renew_owner_lease(
                    &shard_id,
                    17,
                    launch_generation(),
                    now + Duration::from_secs(1),
                    now + Duration::from_secs(9),
                )
                .await
        }
    });
    tokio::time::timeout(Duration::from_secs(1), entered.notified())
        .await
        .expect("the first route renewal should enter its backend");

    let shorter = tokio::spawn({
        let supervisor = Arc::clone(&supervisor);
        let shard_id = shard_id.clone();
        async move {
            supervisor
                .renew_owner_lease(
                    &shard_id,
                    17,
                    launch_generation(),
                    now + Duration::from_secs(1),
                    now + Duration::from_secs(7),
                )
                .await
        }
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(50), entered.notified())
            .await
            .is_err(),
        "one shard must never have two route renewals in flight"
    );

    proceed.notify_one();
    assert_eq!(longer.await.expect("longer renew task should join"), Ok(()));
    assert_eq!(
        shorter.await.expect("shorter renew task should join"),
        Err(RenewLeaseError::InvalidNewExpiry)
    );
    assert_eq!(backend.events(), ["provision", "renew_egress"]);
    assert!(
        supervisor
            .expire_leases(now + Duration::from_secs(8))
            .await
            .is_empty(),
        "the rejected shorter renewal must not regress local ownership"
    );
}

#[tokio::test]
async fn lease_expiry_revokes_egress_before_killing_and_cleaning_the_shard() {
    let backend = RecordingBackend::production_capable();
    let supervisor = SandboxSupervisor::new(config(), backend.clone());
    let shard_id = ShardId::new();
    let now = Instant::now();
    assert_eq!(
        supervisor
            .create_shard(
                launch_spec(shard_id.clone()),
                WorkerOwnership::new(worker(), 17, now + Duration::from_secs(10)),
            )
            .await,
        Ok(CreateShardOutcome::Created)
    );

    let before = supervisor.expire_leases(now + Duration::from_secs(9)).await;
    assert!(before.is_empty());
    let expired = supervisor
        .expire_leases(now + Duration::from_secs(10))
        .await;
    assert_eq!(
        expired,
        vec![(
            shard_id,
            CleanupResult {
                route_revoked: true,
                cgroup_killed: true,
                namespaces_cleaned: true,
            }
        )]
    );
    assert_eq!(
        backend.events(),
        [
            "provision",
            "revoke_egress",
            "kill_cgroup",
            "cleanup_namespaces"
        ]
    );
}

#[tokio::test]
async fn cleanup_continues_to_kill_when_route_revocation_reports_failure() {
    let backend = RecordingBackend {
        fail_revoke: true,
        ..RecordingBackend::production_capable()
    };
    let supervisor = SandboxSupervisor::new(config(), backend.clone());
    let shard_id = ShardId::new();
    let now = Instant::now();
    supervisor
        .create_shard(
            launch_spec(shard_id.clone()),
            WorkerOwnership::new(worker(), 17, now + Duration::from_secs(10)),
        )
        .await
        .expect("sandbox creation must succeed");

    assert_eq!(
        supervisor
            .kill_shard(
                &shard_id,
                17,
                launch_generation(),
                CleanupReason::SecurityViolation,
            )
            .await
            .expect("cleanup must return its partial result"),
        KillShardOutcome::CleanupIncomplete(CleanupResult {
            route_revoked: false,
            cgroup_killed: true,
            namespaces_cleaned: true,
        })
    );
    assert_eq!(
        backend.events(),
        [
            "provision",
            "revoke_egress",
            "kill_cgroup",
            "cleanup_namespaces"
        ]
    );
}

#[tokio::test]
async fn explicit_kill_is_idempotent_and_resource_inspection_is_fenced() {
    let backend = RecordingBackend::production_capable();
    let supervisor = SandboxSupervisor::new(config(), backend.clone());
    let shard_id = ShardId::new();
    let now = Instant::now();
    supervisor
        .create_shard(
            launch_spec(shard_id.clone()),
            WorkerOwnership::new(worker(), 17, now + Duration::from_secs(10)),
        )
        .await
        .expect("sandbox creation must succeed");

    assert_eq!(
        supervisor
            .inspect_resources(&shard_id, 17, launch_generation())
            .await,
        Ok(InspectResources {
            memory_current_bytes: 123,
            memory_peak_bytes: 456,
            process_count: 7,
            egress_route_active: true,
        })
    );
    assert!(matches!(
        supervisor
            .inspect_resources(&shard_id, 18, launch_generation())
            .await,
        Err(SandboxError::WorkerEpochMismatch { .. })
    ));

    let first = supervisor
        .kill_shard(
            &shard_id,
            17,
            launch_generation(),
            CleanupReason::Administrative,
        )
        .await;
    assert!(matches!(first, Ok(KillShardOutcome::Terminated(_))));
    let second = supervisor
        .kill_shard(
            &shard_id,
            17,
            launch_generation(),
            CleanupReason::Administrative,
        )
        .await;
    assert_eq!(second, Ok(KillShardOutcome::AlreadyTerminated));
    assert_eq!(
        backend
            .events()
            .iter()
            .filter(|event| event.as_str() == "kill_cgroup")
            .count(),
        1
    );
}

#[derive(Clone)]
struct RetryCleanupBackend {
    revoke_failures_remaining: Arc<AtomicUsize>,
    events: Arc<Mutex<Vec<&'static str>>>,
}

#[async_trait]
impl SandboxBackend for RetryCleanupBackend {
    fn capabilities(&self) -> SandboxCapabilities {
        SandboxCapabilities::production_required()
    }

    async fn provision(&self, spec: &LaunchSpec) -> Result<SandboxHandle, SandboxError> {
        Ok(SandboxHandle::new(spec.shard_id().clone(), "retry"))
    }

    async fn revoke_egress(
        &self,
        _handle: &SandboxHandle,
        _reason: CleanupReason,
    ) -> Result<(), SandboxError> {
        self.events.lock().unwrap().push("revoke");
        if self
            .revoke_failures_remaining
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
        {
            Err(SandboxError::Backend("first revoke fails".to_owned()))
        } else {
            Ok(())
        }
    }

    async fn kill_cgroup(
        &self,
        _handle: &SandboxHandle,
        _reason: CleanupReason,
    ) -> Result<(), SandboxError> {
        self.events.lock().unwrap().push("kill");
        Ok(())
    }

    async fn cleanup_namespaces(&self, _handle: &SandboxHandle) -> Result<(), SandboxError> {
        self.events.lock().unwrap().push("namespaces");
        Ok(())
    }

    async fn inspect(&self, _handle: &SandboxHandle) -> Result<InspectResources, SandboxError> {
        Err(SandboxError::Backend("not used".to_owned()))
    }
}

#[tokio::test]
async fn partial_cleanup_retries_only_failed_stages_before_claiming_termination() {
    let backend = RetryCleanupBackend {
        revoke_failures_remaining: Arc::new(AtomicUsize::new(1)),
        events: Arc::new(Mutex::new(Vec::new())),
    };
    let supervisor = SandboxSupervisor::new(config(), backend.clone());
    let shard_id = ShardId::new();
    let now = Instant::now();
    assert_eq!(
        supervisor
            .create_shard(
                launch_spec(shard_id.clone()),
                WorkerOwnership::new(worker(), 17, now + Duration::from_secs(10)),
            )
            .await,
        Ok(CreateShardOutcome::Created)
    );

    assert_eq!(
        supervisor
            .kill_shard(
                &shard_id,
                17,
                launch_generation(),
                CleanupReason::SecurityViolation,
            )
            .await,
        Ok(KillShardOutcome::CleanupIncomplete(CleanupResult {
            route_revoked: false,
            cgroup_killed: true,
            namespaces_cleaned: true,
        }))
    );
    assert_eq!(
        supervisor
            .kill_shard(
                &shard_id,
                17,
                launch_generation(),
                CleanupReason::SecurityViolation,
            )
            .await,
        Ok(KillShardOutcome::Terminated(CleanupResult {
            route_revoked: true,
            cgroup_killed: true,
            namespaces_cleaned: true,
        }))
    );
    assert_eq!(
        supervisor
            .kill_shard(
                &shard_id,
                17,
                launch_generation(),
                CleanupReason::SecurityViolation,
            )
            .await,
        Ok(KillShardOutcome::AlreadyTerminated)
    );
    assert_eq!(
        backend.events.lock().unwrap().as_slice(),
        ["revoke", "kill", "namespaces", "revoke"]
    );
}

#[tokio::test]
async fn lease_sweeper_retries_incomplete_cleanup_without_a_live_worker() {
    let backend = RetryCleanupBackend {
        revoke_failures_remaining: Arc::new(AtomicUsize::new(1)),
        events: Arc::new(Mutex::new(Vec::new())),
    };
    let supervisor = SandboxSupervisor::new(config(), backend.clone());
    let shard_id = ShardId::new();
    let now = Instant::now();
    assert_eq!(
        supervisor
            .create_shard(
                launch_spec(shard_id.clone()),
                WorkerOwnership::new(worker(), 17, now + Duration::from_secs(10)),
            )
            .await,
        Ok(CreateShardOutcome::Created)
    );

    assert_eq!(
        supervisor
            .expire_leases(now + Duration::from_secs(10))
            .await,
        vec![(
            shard_id.clone(),
            CleanupResult {
                route_revoked: false,
                cgroup_killed: true,
                namespaces_cleaned: true,
            }
        )]
    );
    assert_eq!(
        supervisor
            .expire_leases(now + Duration::from_secs(11))
            .await,
        vec![(
            shard_id.clone(),
            CleanupResult {
                route_revoked: true,
                cgroup_killed: true,
                namespaces_cleaned: true,
            }
        )]
    );
    assert!(
        supervisor
            .expire_leases(now + Duration::from_secs(12))
            .await
            .is_empty()
    );
    assert_eq!(
        backend.events.lock().unwrap().as_slice(),
        ["revoke", "kill", "namespaces", "revoke"]
    );
}

#[derive(Clone)]
struct PanickingFirstRevokeBackend {
    revoke_calls: Arc<AtomicUsize>,
    revoke_started: Arc<Notify>,
    release_revoke: Arc<Notify>,
    events: Arc<Mutex<Vec<&'static str>>>,
}

#[async_trait]
impl SandboxBackend for PanickingFirstRevokeBackend {
    fn capabilities(&self) -> SandboxCapabilities {
        SandboxCapabilities::production_required()
    }

    async fn provision(&self, spec: &LaunchSpec) -> Result<SandboxHandle, SandboxError> {
        Ok(SandboxHandle::new(
            spec.shard_id().clone(),
            "panic-retry-cleanup",
        ))
    }

    async fn revoke_egress(
        &self,
        _handle: &SandboxHandle,
        _reason: CleanupReason,
    ) -> Result<(), SandboxError> {
        let call = self.revoke_calls.fetch_add(1, Ordering::AcqRel);
        self.events.lock().unwrap().push("revoke");
        if call == 0 {
            self.revoke_started.notify_one();
            self.release_revoke.notified().await;
            panic!("simulated first revoke panic");
        }
        Ok(())
    }

    async fn kill_cgroup(
        &self,
        _handle: &SandboxHandle,
        _reason: CleanupReason,
    ) -> Result<(), SandboxError> {
        self.events.lock().unwrap().push("kill");
        Ok(())
    }

    async fn cleanup_namespaces(&self, _handle: &SandboxHandle) -> Result<(), SandboxError> {
        self.events.lock().unwrap().push("namespaces");
        Ok(())
    }

    async fn inspect(&self, _handle: &SandboxHandle) -> Result<InspectResources, SandboxError> {
        Err(SandboxError::Backend("not used".to_owned()))
    }
}

#[tokio::test(flavor = "current_thread")]
async fn cleanup_stage_panic_is_bounded_retryable_and_wakes_a_concurrent_waiter() {
    let backend = PanickingFirstRevokeBackend {
        revoke_calls: Arc::new(AtomicUsize::new(0)),
        revoke_started: Arc::new(Notify::new()),
        release_revoke: Arc::new(Notify::new()),
        events: Arc::new(Mutex::new(Vec::new())),
    };
    let supervisor_config = config()
        .with_cleanup_stage_timeout(Duration::from_millis(50))
        .expect("cleanup timeout should be valid");
    let supervisor = Arc::new(SandboxSupervisor::new(supervisor_config, backend.clone()));
    let shard_id = ShardId::new();
    supervisor
        .create_shard(
            launch_spec(shard_id.clone()),
            WorkerOwnership::new(worker(), 17, Instant::now() + Duration::from_secs(10)),
        )
        .await
        .expect("sandbox creation should succeed");

    let owner_supervisor = Arc::clone(&supervisor);
    let owner_shard_id = shard_id.clone();
    let owner = tokio::spawn(async move {
        owner_supervisor
            .kill_shard(
                &owner_shard_id,
                17,
                launch_generation(),
                CleanupReason::SecurityViolation,
            )
            .await
    });
    backend.revoke_started.notified().await;

    let waiter_supervisor = Arc::clone(&supervisor);
    let waiter_shard_id = shard_id.clone();
    let waiter = tokio::spawn(async move {
        waiter_supervisor
            .kill_shard(
                &waiter_shard_id,
                17,
                launch_generation(),
                CleanupReason::SecurityViolation,
            )
            .await
    });
    tokio::task::yield_now().await;
    backend.release_revoke.notify_one();

    let (owner_outcome, waiter_outcome) = tokio::time::timeout(Duration::from_millis(500), async {
        (
            owner.await.expect("cleanup owner task should finish"),
            waiter
                .await
                .expect("concurrent cleanup waiter should finish"),
        )
    })
    .await
    .expect("a panicking cleanup stage must not strand its concurrent waiter");
    assert_eq!(
        owner_outcome,
        Ok(KillShardOutcome::CleanupIncomplete(CleanupResult {
            route_revoked: false,
            cgroup_killed: true,
            namespaces_cleaned: true,
        }))
    );
    assert_eq!(
        waiter_outcome,
        Ok(KillShardOutcome::Terminated(CleanupResult {
            route_revoked: true,
            cgroup_killed: true,
            namespaces_cleaned: true,
        }))
    );
    assert_eq!(
        supervisor
            .kill_shard(
                &shard_id,
                17,
                launch_generation(),
                CleanupReason::SecurityViolation,
            )
            .await,
        Ok(KillShardOutcome::AlreadyTerminated)
    );
    assert_eq!(
        backend.events.lock().unwrap().as_slice(),
        ["revoke", "kill", "namespaces", "revoke"]
    );
}

#[derive(Clone)]
struct HangingRevokeBackend {
    never_revoke: Arc<Notify>,
    kill_started: Arc<Notify>,
    events: Arc<Mutex<Vec<&'static str>>>,
}

#[async_trait]
impl SandboxBackend for HangingRevokeBackend {
    fn capabilities(&self) -> SandboxCapabilities {
        SandboxCapabilities::production_required()
    }

    async fn provision(&self, spec: &LaunchSpec) -> Result<SandboxHandle, SandboxError> {
        Ok(SandboxHandle::new(
            spec.shard_id().clone(),
            "hanging-revoke",
        ))
    }

    async fn revoke_egress(
        &self,
        _handle: &SandboxHandle,
        _reason: CleanupReason,
    ) -> Result<(), SandboxError> {
        self.events.lock().unwrap().push("revoke-started");
        self.never_revoke.notified().await;
        Ok(())
    }

    async fn kill_cgroup(
        &self,
        _handle: &SandboxHandle,
        _reason: CleanupReason,
    ) -> Result<(), SandboxError> {
        self.events.lock().unwrap().push("kill");
        self.kill_started.notify_one();
        Ok(())
    }

    async fn cleanup_namespaces(&self, _handle: &SandboxHandle) -> Result<(), SandboxError> {
        self.events.lock().unwrap().push("namespaces");
        Ok(())
    }

    async fn inspect(&self, _handle: &SandboxHandle) -> Result<InspectResources, SandboxError> {
        Err(SandboxError::Backend("not used".to_owned()))
    }
}

#[tokio::test]
async fn hung_revoke_is_bounded_and_never_prevents_security_cgroup_kill() {
    let backend = HangingRevokeBackend {
        never_revoke: Arc::new(Notify::new()),
        kill_started: Arc::new(Notify::new()),
        events: Arc::new(Mutex::new(Vec::new())),
    };
    let supervisor_config = config()
        .with_cleanup_stage_timeout(Duration::from_millis(20))
        .expect("cleanup timeout should be valid");
    let supervisor = SandboxSupervisor::new(supervisor_config, backend.clone());
    let shard_id = ShardId::new();
    let now = Instant::now();
    assert!(
        supervisor
            .create_shard(
                launch_spec(shard_id.clone()),
                WorkerOwnership::new(worker(), 17, now + Duration::from_secs(10)),
            )
            .await
            .is_ok()
    );

    let outcome = tokio::time::timeout(
        Duration::from_millis(200),
        supervisor.kill_shard(
            &shard_id,
            17,
            launch_generation(),
            CleanupReason::SecurityViolation,
        ),
    )
    .await;
    assert!(outcome.is_ok());
    assert!(matches!(
        outcome.ok().and_then(Result::ok),
        Some(KillShardOutcome::CleanupIncomplete(CleanupResult {
            route_revoked: false,
            cgroup_killed: true,
            namespaces_cleaned: true,
        }))
    ));
    assert_eq!(
        backend.events.lock().unwrap().as_slice(),
        ["revoke-started", "kill", "namespaces"]
    );
}

#[tokio::test]
async fn blocked_revoke_cannot_delay_the_independently_journaled_kill_intent() {
    let backend = HangingRevokeBackend {
        never_revoke: Arc::new(Notify::new()),
        kill_started: Arc::new(Notify::new()),
        events: Arc::new(Mutex::new(Vec::new())),
    };
    let supervisor_config = config()
        .with_cleanup_stage_timeout(Duration::from_secs(30))
        .expect("cleanup timeout should be valid");
    let supervisor = Arc::new(SandboxSupervisor::new(supervisor_config, backend.clone()));
    let shard_id = ShardId::new();
    let now = Instant::now();
    supervisor
        .create_shard(
            launch_spec(shard_id.clone()),
            WorkerOwnership::new(worker(), 17, now + Duration::from_secs(10)),
        )
        .await
        .expect("sandbox creation must succeed");

    let cleanup = {
        let supervisor = Arc::clone(&supervisor);
        tokio::spawn(async move {
            supervisor
                .kill_shard(
                    &shard_id,
                    17,
                    launch_generation(),
                    CleanupReason::SecurityViolation,
                )
                .await
        })
    };
    tokio::time::timeout(Duration::from_millis(100), backend.kill_started.notified())
        .await
        .expect("the cgroup kill must start without waiting for route revoke timeout");
    backend.never_revoke.notify_one();
    assert!(matches!(
        cleanup.await.expect("cleanup task should not panic"),
        Ok(KillShardOutcome::Terminated(_))
    ));
}

#[derive(Clone)]
struct CancelSafeCleanupBackend {
    revoke_started: Arc<Notify>,
    release_revoke: Arc<Notify>,
}

#[async_trait]
impl SandboxBackend for CancelSafeCleanupBackend {
    fn capabilities(&self) -> SandboxCapabilities {
        SandboxCapabilities::production_required()
    }

    async fn provision(&self, spec: &LaunchSpec) -> Result<SandboxHandle, SandboxError> {
        Ok(SandboxHandle::new(
            spec.shard_id().clone(),
            "cancel-safe-cleanup",
        ))
    }

    async fn revoke_egress(
        &self,
        _handle: &SandboxHandle,
        _reason: CleanupReason,
    ) -> Result<(), SandboxError> {
        self.revoke_started.notify_one();
        self.release_revoke.notified().await;
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

#[tokio::test]
async fn cancelling_cleanup_caller_never_strands_the_cleanup_owner() {
    let backend = CancelSafeCleanupBackend {
        revoke_started: Arc::new(Notify::new()),
        release_revoke: Arc::new(Notify::new()),
    };
    let supervisor = Arc::new(SandboxSupervisor::new(config(), backend.clone()));
    let shard_id = ShardId::new();
    let now = Instant::now();
    assert_eq!(
        supervisor
            .create_shard(
                launch_spec(shard_id.clone()),
                WorkerOwnership::new(worker(), 17, now + Duration::from_secs(10)),
            )
            .await,
        Ok(CreateShardOutcome::Created)
    );

    let cleanup_supervisor = Arc::clone(&supervisor);
    let cleanup_shard_id = shard_id.clone();
    let cleanup = tokio::spawn(async move {
        cleanup_supervisor
            .kill_shard(
                &cleanup_shard_id,
                17,
                launch_generation(),
                CleanupReason::SecurityViolation,
            )
            .await
    });
    backend.revoke_started.notified().await;
    cleanup.abort();
    assert!(
        cleanup
            .await
            .expect_err("caller must be cancelled")
            .is_cancelled()
    );

    backend.release_revoke.notify_waiters();
    let retry = tokio::time::timeout(
        Duration::from_millis(200),
        supervisor.kill_shard(
            &shard_id,
            17,
            launch_generation(),
            CleanupReason::SecurityViolation,
        ),
    )
    .await;
    assert!(
        retry.is_ok(),
        "cleanup ownership must survive caller cancellation"
    );
    assert!(matches!(
        retry.expect("retry must be bounded"),
        Ok(KillShardOutcome::Terminated(_) | KillShardOutcome::AlreadyTerminated)
    ));
}

#[tokio::test]
async fn supervisor_shutdown_closes_admission_and_cleans_every_active_shard() {
    let backend = RecordingBackend::production_capable();
    let supervisor = SandboxSupervisor::new(config(), backend.clone());
    let first = ShardId::new();
    let second = ShardId::new();
    for shard_id in [&first, &second] {
        supervisor
            .create_shard(
                launch_spec(shard_id.clone()),
                WorkerOwnership::new(worker(), 17, Instant::now() + Duration::from_secs(10)),
            )
            .await
            .expect("test shard should be created");
    }

    let report = supervisor.shutdown_fail_closed().await;
    assert!(
        report.is_complete(),
        "shutdown must prove cleanup of every shard"
    );
    assert_eq!(report.cleaned_shards(), 2);
    assert_eq!(
        backend.events(),
        [
            "provision",
            "provision",
            "revoke_egress",
            "kill_cgroup",
            "cleanup_namespaces",
            "revoke_egress",
            "kill_cgroup",
            "cleanup_namespaces",
        ]
    );

    assert!(matches!(
        supervisor
            .create_shard(
                launch_spec(ShardId::new()),
                WorkerOwnership::new(worker(), 17, Instant::now() + Duration::from_secs(10)),
            )
            .await,
        Err(SandboxError::AdmissionClosed)
    ));
}

#[tokio::test]
async fn terminated_replay_guards_are_reclaimed_after_their_retention() {
    let backend = RecordingBackend::production_capable();
    let retention = Duration::from_secs(3600);
    let config = SupervisorConfig::new(Duration::from_secs(10), Duration::from_secs(30))
        .expect("lease ordering must be valid")
        .with_terminated_retention(retention)
        .expect("terminated retention must be valid");
    let supervisor = SandboxSupervisor::new(config, backend.clone());
    let shard_id = ShardId::new();
    // The replay guard only matches an exact binding, and `launch_spec` randomizes its tenant and
    // session identity per call, so the whole scenario must reuse one spec instance.
    let spec = launch_spec(shard_id.clone());
    // `expire_leases` compares its argument against the real-time `terminated_at` stamp, so the
    // sweep watermarks ride a synthetic timeline anchored here while every ownership lease stays
    // real-time-relative (`create_shard` validates it against `Instant::now()`).
    let sweep_base = Instant::now();

    let provisions = |backend: &RecordingBackend| {
        backend
            .events()
            .iter()
            .filter(|event| event.as_str() == "provision")
            .count()
    };

    supervisor
        .create_shard(
            spec.clone(),
            WorkerOwnership::new(worker(), 17, Instant::now() + Duration::from_secs(10)),
        )
        .await
        .expect("the first create must provision the shard");
    assert!(matches!(
        supervisor
            .kill_shard(
                &shard_id,
                17,
                launch_generation(),
                CleanupReason::Administrative,
            )
            .await,
        Ok(KillShardOutcome::Terminated(_))
    ));
    assert_eq!(provisions(&backend), 1);

    // While the guard is live an exact retry replays the terminal outcome, and an intervening sweep
    // that has not reached the watermark leaves the guard in place — neither re-enters the backend.
    let replayed = supervisor
        .create_shard(
            spec.clone(),
            WorkerOwnership::new(worker(), 17, Instant::now() + Duration::from_secs(10)),
        )
        .await
        .expect("an exact retry of a terminated shard must replay its outcome");
    assert!(
        supervisor
            .expire_leases(sweep_base + Duration::from_secs(60))
            .await
            .is_empty()
    );
    assert_eq!(
        supervisor
            .create_shard(
                spec.clone(),
                WorkerOwnership::new(worker(), 17, Instant::now() + Duration::from_secs(10)),
            )
            .await,
        Ok(replayed)
    );
    assert_eq!(provisions(&backend), 1);

    // Once a sweep crosses the retention watermark the guard is reclaimed, so the next exact create
    // provisions a fresh shard rather than replaying the now-stale terminal outcome.
    assert!(
        supervisor
            .expire_leases(sweep_base + retention + Duration::from_secs(1))
            .await
            .is_empty()
    );
    assert_eq!(
        supervisor
            .create_shard(
                spec,
                WorkerOwnership::new(worker(), 17, Instant::now() + Duration::from_secs(10)),
            )
            .await,
        Ok(CreateShardOutcome::Created)
    );
    assert_eq!(provisions(&backend), 2);
}
