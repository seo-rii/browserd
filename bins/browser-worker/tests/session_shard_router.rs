use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::time::{Duration, Instant};

use browser_worker::{
    ProvisionedSessionShard, RoutedArtifactStore, SessionShardFactory, SessionShardLifecycle,
    SessionShardRouter,
};
use browserd_core::{ActionId, ArtifactId, PageId, SessionId, TenantId, WorkerId};
use browserd_policy::CanonicalActionProposal;
use browserd_session::OwnershipFence;
use browserd_worker::{
    ActionExecutionResult, ApprovedActionError, ArtifactStoreReceipt, ArtifactStoreRequest,
    ChromiumDriver, DependencyError, LiveApprovalContext, SandboxClient, UnavailableChromiumDriver,
};

const TEST_TIMEOUT: Duration = Duration::from_secs(2);

struct CallGate {
    entered: mpsc::Sender<()>,
    released: Mutex<bool>,
    wake: Condvar,
}

impl CallGate {
    fn new() -> (Arc<Self>, mpsc::Receiver<()>) {
        let (entered, receiver) = mpsc::channel();
        (
            Arc::new(Self {
                entered,
                released: Mutex::new(false),
                wake: Condvar::new(),
            }),
            receiver,
        )
    }

    fn block(&self) -> Result<(), DependencyError> {
        self.entered
            .send(())
            .map_err(|_| DependencyError::Unavailable)?;
        let mut released = self
            .released
            .lock()
            .map_err(|_| DependencyError::Unavailable)?;
        while !*released {
            released = self
                .wake
                .wait(released)
                .map_err(|_| DependencyError::Unavailable)?;
        }
        Ok(())
    }

    fn release(&self) {
        if let Ok(mut released) = self.released.lock() {
            *released = true;
            self.wake.notify_all();
        }
    }
}

#[derive(Default)]
struct Lifecycle {
    qualifications: AtomicUsize,
    heartbeats: AtomicUsize,
    terminations: AtomicUsize,
}

impl SessionShardLifecycle for Lifecycle {
    fn qualify(&self) -> Result<(), DependencyError> {
        self.qualifications.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn heartbeat(&self) -> Result<(), DependencyError> {
        self.heartbeats.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn terminate(&self, _fence: &OwnershipFence) -> Result<(), DependencyError> {
        self.terminations.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[derive(Default)]
struct Factory {
    creations: AtomicUsize,
    daemon_qualifications: AtomicUsize,
    daemon_heartbeats: AtomicUsize,
    lifecycles: Mutex<Vec<Arc<Lifecycle>>>,
}

impl Factory {
    fn lifecycles(&self) -> Option<Vec<Arc<Lifecycle>>> {
        self.lifecycles.lock().ok().map(|items| items.clone())
    }
}

impl SessionShardFactory for Factory {
    fn qualify_daemon(&self) -> Result<(), DependencyError> {
        self.daemon_qualifications.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn heartbeat_daemon(
        &self,
        _worker_id: &WorkerId,
        _worker_epoch: u64,
    ) -> Result<(), DependencyError> {
        self.daemon_heartbeats.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn create(
        &self,
        _tenant_id: &TenantId,
        _session_id: &SessionId,
        _fence: &OwnershipFence,
    ) -> Result<ProvisionedSessionShard, DependencyError> {
        self.creations.fetch_add(1, Ordering::SeqCst);
        let lifecycle = Arc::new(Lifecycle::default());
        self.lifecycles
            .lock()
            .map_err(|_| DependencyError::Unavailable)?
            .push(Arc::clone(&lifecycle));
        Ok(ProvisionedSessionShard::new(
            PageId::new(),
            Arc::new(UnavailableChromiumDriver),
            lifecycle,
        ))
    }
}

struct BlockingFactory {
    creations: AtomicUsize,
    gate: Arc<CallGate>,
    lifecycle: Arc<Lifecycle>,
}

impl BlockingFactory {
    fn new(gate: Arc<CallGate>) -> Self {
        Self {
            creations: AtomicUsize::new(0),
            gate,
            lifecycle: Arc::new(Lifecycle::default()),
        }
    }
}

impl SessionShardFactory for BlockingFactory {
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
        self.creations.fetch_add(1, Ordering::SeqCst);
        self.gate.block()?;
        Ok(ProvisionedSessionShard::new(
            PageId::new(),
            Arc::new(UnavailableChromiumDriver),
            self.lifecycle.clone(),
        ))
    }
}

struct BlockingLifecycle {
    qualification_gate: Arc<CallGate>,
    heartbeat_gate: Arc<CallGate>,
    terminations: AtomicUsize,
}

impl SessionShardLifecycle for BlockingLifecycle {
    fn qualify(&self) -> Result<(), DependencyError> {
        self.qualification_gate.block()
    }

    fn heartbeat(&self) -> Result<(), DependencyError> {
        self.heartbeat_gate.block()
    }

    fn terminate(&self, _fence: &OwnershipFence) -> Result<(), DependencyError> {
        self.terminations.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

struct LockProbeFactory {
    creations: AtomicUsize,
    blocking_lifecycle: Arc<BlockingLifecycle>,
}

impl SessionShardFactory for LockProbeFactory {
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
        let creation = self.creations.fetch_add(1, Ordering::SeqCst);
        let lifecycle: Arc<dyn SessionShardLifecycle> = if creation == 0 {
            self.blocking_lifecycle.clone()
        } else {
            Arc::new(Lifecycle::default())
        };
        Ok(ProvisionedSessionShard::new(
            PageId::new(),
            Arc::new(UnavailableChromiumDriver),
            lifecycle,
        ))
    }
}

struct RejectArtifacts;

#[derive(Default)]
struct DeadlineDriver {
    observed_deadline: Mutex<Option<Instant>>,
}

impl ChromiumDriver for DeadlineDriver {
    fn qualify(&self) -> Result<(), DependencyError> {
        Ok(())
    }

    fn create_context(&self, _session_id: &SessionId) -> Result<PageId, DependencyError> {
        Err(DependencyError::Rejected)
    }

    fn close_context(&self, _session_id: &SessionId) -> Result<(), DependencyError> {
        Err(DependencyError::Rejected)
    }

    fn create_page(&self, _session_id: &SessionId) -> Result<PageId, DependencyError> {
        Err(DependencyError::Rejected)
    }

    fn close_page(
        &self,
        _session_id: &SessionId,
        _page_id: &PageId,
    ) -> Result<(), DependencyError> {
        Err(DependencyError::Rejected)
    }

    fn activate_page(
        &self,
        _session_id: &SessionId,
        _page_id: &PageId,
    ) -> Result<(), DependencyError> {
        Err(DependencyError::Rejected)
    }

    fn execute_action(
        &self,
        _session_id: &SessionId,
        _page_id: Option<&PageId>,
        _payload: &[u8],
    ) -> ActionExecutionResult {
        ActionExecutionResult::FailedKnown("legacy_execution".to_owned())
    }

    fn execute_action_until(
        &self,
        _session_id: &SessionId,
        _page_id: Option<&PageId>,
        _payload: &[u8],
        deadline: Instant,
    ) -> ActionExecutionResult {
        if let Ok(mut observed) = self.observed_deadline.lock() {
            *observed = Some(deadline);
        }
        ActionExecutionResult::Succeeded(vec![9])
    }

    fn inspect_approval_context(
        &self,
        _session_id: &SessionId,
        _page_id: &PageId,
        _proposal: &CanonicalActionProposal,
    ) -> Result<LiveApprovalContext, DependencyError> {
        Err(DependencyError::Rejected)
    }

    fn execute_approved_action(
        &self,
        _session_id: &SessionId,
        _page_id: &PageId,
        _payload: &[u8],
        _proposal: &CanonicalActionProposal,
        _inspected: &LiveApprovalContext,
        _authorize_and_commit: &mut dyn FnMut(
            &LiveApprovalContext,
        ) -> Result<(), ApprovedActionError>,
    ) -> Result<ActionExecutionResult, ApprovedActionError> {
        Err(ApprovedActionError::Unavailable)
    }

    fn cancel_action(
        &self,
        _session_id: &SessionId,
        _action_id: &ActionId,
    ) -> Result<bool, DependencyError> {
        Err(DependencyError::Rejected)
    }
}

struct DeadlineFactory {
    driver: Arc<DeadlineDriver>,
    lifecycle: Arc<Lifecycle>,
}

impl SessionShardFactory for DeadlineFactory {
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
        Ok(ProvisionedSessionShard::new(
            PageId::new(),
            self.driver.clone(),
            self.lifecycle.clone(),
        ))
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

#[derive(Clone, Debug, Eq, PartialEq)]
struct ArtifactEffect {
    tenant_id: TenantId,
    session_id: SessionId,
    artifact_id: ArtifactId,
    fence: OwnershipFence,
}

#[derive(Default)]
struct RecordingArtifacts {
    calls: AtomicUsize,
    effects: Mutex<Vec<ArtifactEffect>>,
}

impl RecordingArtifacts {
    fn effects(&self) -> Option<Vec<ArtifactEffect>> {
        self.effects.lock().ok().map(|effects| effects.clone())
    }
}

impl RoutedArtifactStore for RecordingArtifacts {
    fn store(
        &self,
        request: &ArtifactStoreRequest,
    ) -> Result<ArtifactStoreReceipt, DependencyError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.effects
            .lock()
            .map_err(|_| DependencyError::Unavailable)?
            .push(ArtifactEffect {
                tenant_id: request.key().tenant_id().clone(),
                session_id: request.key().session_id().clone(),
                artifact_id: request.key().artifact_id().clone(),
                fence: request.fence().clone(),
            });
        Err(DependencyError::Rejected)
    }
}

fn worker() -> Option<WorkerId> {
    let worker = WorkerId::new("router-worker");
    assert!(worker.is_ok());
    worker.ok()
}

fn fence(worker: &WorkerId, placement_version: u64) -> OwnershipFence {
    OwnershipFence::new(worker.clone(), 7, placement_version, 1)
}

fn router<F, A>(
    factory: Arc<F>,
    artifacts: Arc<A>,
    max_sessions: usize,
) -> Option<SessionShardRouter<F, A>>
where
    F: SessionShardFactory,
    A: RoutedArtifactStore,
{
    let worker = worker()?;
    let router = SessionShardRouter::new(worker, 7, factory, artifacts, max_sessions);
    assert!(router.is_ok());
    router.ok()
}

fn artifact_request(
    tenant_id: &TenantId,
    session_id: &SessionId,
    fence: &OwnershipFence,
) -> Option<ArtifactStoreRequest> {
    let request = ArtifactStoreRequest::new(
        tenant_id.clone(),
        session_id.clone(),
        ArtifactId::new(),
        fence.clone(),
        b"routed artifact".to_vec(),
        "application/octet-stream",
        64,
    );
    assert!(request.is_ok());
    request.ok()
}

#[test]
fn exact_create_retry_publishes_one_session_shard() {
    let factory = Arc::new(Factory::default());
    let Some(router) = router(Arc::clone(&factory), Arc::new(RejectArtifacts), 8) else {
        return;
    };
    let Some(worker) = worker() else {
        return;
    };
    let tenant = TenantId::new();
    let session = SessionId::new();
    let ownership = fence(&worker, 11);

    let first = router.create_context_owned(&tenant, &session, &ownership);
    let second = router.create_context_owned(&tenant, &session, &ownership);

    assert!(first.is_ok());
    assert_eq!(second, first);
    assert_eq!(factory.creations.load(Ordering::SeqCst), 1);
    assert!(router.shard_managed_contexts());
}

#[test]
fn action_deadline_is_delegated_to_the_routed_driver() {
    let driver = Arc::new(DeadlineDriver::default());
    let factory = Arc::new(DeadlineFactory {
        driver: Arc::clone(&driver),
        lifecycle: Arc::new(Lifecycle::default()),
    });
    let Some(router) = router(factory, Arc::new(RejectArtifacts), 8) else {
        return;
    };
    let Some(worker) = worker() else {
        return;
    };
    let tenant_id = TenantId::new();
    let session_id = SessionId::new();
    let ownership = fence(&worker, 11);
    assert!(
        router
            .create_context_owned(&tenant_id, &session_id, &ownership)
            .is_ok()
    );
    let deadline = Instant::now() + Duration::from_secs(1);
    assert_eq!(
        router.execute_action_until(&session_id, None, b"deadline", deadline),
        ActionExecutionResult::Succeeded(vec![9])
    );
    assert_eq!(
        driver
            .observed_deadline
            .lock()
            .ok()
            .and_then(|observed| *observed),
        Some(deadline)
    );
}

#[test]
fn concurrent_exact_create_is_linearized_to_one_factory_effect() {
    let factory = Arc::new(Factory::default());
    let Some(router) = router(Arc::clone(&factory), Arc::new(RejectArtifacts), 8).map(Arc::new)
    else {
        return;
    };
    let Some(worker) = worker() else {
        return;
    };
    let tenant = TenantId::new();
    let session = SessionId::new();
    let ownership = fence(&worker, 12);
    let other_router = Arc::clone(&router);
    let other_tenant = tenant.clone();
    let other_session = session.clone();
    let other_ownership = ownership.clone();
    let other = std::thread::spawn(move || {
        other_router.create_context_owned(&other_tenant, &other_session, &other_ownership)
    });

    let first = router.create_context_owned(&tenant, &session, &ownership);
    let second = other.join();

    assert!(first.is_ok());
    assert!(second.is_ok());
    assert_eq!(second.ok(), Some(first));
    assert_eq!(factory.creations.load(Ordering::SeqCst), 1);
}

#[test]
fn provisioning_reserves_capacity_before_the_factory_create_completes() {
    let (gate, entered) = CallGate::new();
    let factory = Arc::new(BlockingFactory::new(Arc::clone(&gate)));
    let Some(router) = router(Arc::clone(&factory), Arc::new(RejectArtifacts), 1).map(Arc::new)
    else {
        return;
    };
    let Some(worker) = worker() else {
        return;
    };
    let first_tenant = TenantId::new();
    let first_session = SessionId::new();
    let first_fence = fence(&worker, 30);
    let first_router = Arc::clone(&router);
    let first = std::thread::spawn(move || {
        first_router.create_context_owned(&first_tenant, &first_session, &first_fence)
    });
    let first_entered = entered.recv_timeout(TEST_TIMEOUT);

    let second_tenant = TenantId::new();
    let second_session = SessionId::new();
    let second_fence = fence(&worker, 31);
    let second_router = Arc::clone(&router);
    let (second_sender, second_receiver) = mpsc::channel();
    let second = std::thread::spawn(move || {
        let result =
            second_router.create_context_owned(&second_tenant, &second_session, &second_fence);
        let _ = second_sender.send(result);
    });
    let second_before_release = second_receiver.recv_timeout(TEST_TIMEOUT);
    let factory_effects_before_release = factory.creations.load(Ordering::SeqCst);

    gate.release();
    let first_result = first.join();
    let second_join = second.join();

    assert!(first_entered.is_ok());
    assert!(matches!(second_before_release, Ok(Err(_))));
    assert_eq!(factory_effects_before_release, 1);
    assert!(matches!(first_result, Ok(Ok(_))));
    assert!(second_join.is_ok());
    assert_eq!(factory.creations.load(Ordering::SeqCst), 1);
}

#[test]
fn close_waits_for_same_session_create_publish_then_terminalizes_exactly_once() {
    let (gate, entered) = CallGate::new();
    let factory = Arc::new(BlockingFactory::new(Arc::clone(&gate)));
    let Some(router) = router(Arc::clone(&factory), Arc::new(RejectArtifacts), 8).map(Arc::new)
    else {
        return;
    };
    let Some(worker) = worker() else {
        return;
    };
    let tenant = TenantId::new();
    let session = SessionId::new();
    let ownership = fence(&worker, 32);
    let create_router = Arc::clone(&router);
    let create_tenant = tenant.clone();
    let create_session = session.clone();
    let create_fence = ownership.clone();
    let create = std::thread::spawn(move || {
        create_router.create_context_owned(&create_tenant, &create_session, &create_fence)
    });
    let create_entered = entered.recv_timeout(TEST_TIMEOUT);

    let close_router = Arc::clone(&router);
    let close_session = session.clone();
    let close_fence = ownership.clone();
    let (close_started_sender, close_started_receiver) = mpsc::channel();
    let (close_result_sender, close_result_receiver) = mpsc::channel();
    let close = std::thread::spawn(move || {
        let _ = close_started_sender.send(());
        let result = close_router.close_context_fenced(&close_session, &close_fence);
        let _ = close_result_sender.send(result);
    });
    let close_started = close_started_receiver.recv_timeout(TEST_TIMEOUT);
    let close_before_publish = close_result_receiver.recv_timeout(TEST_TIMEOUT);

    gate.release();
    let create_result = create.join();
    let close_result = close.join();
    let published_close_result = close_result_receiver.recv_timeout(TEST_TIMEOUT);

    assert!(create_entered.is_ok());
    assert!(close_started.is_ok());
    assert!(matches!(
        close_before_publish,
        Err(mpsc::RecvTimeoutError::Timeout)
    ));
    assert!(matches!(create_result, Ok(Ok(_))));
    assert!(close_result.is_ok());
    assert_eq!(published_close_result, Ok(Ok(())));
    assert_eq!(factory.lifecycle.terminations.load(Ordering::SeqCst), 1);
    assert_eq!(router.close_context_fenced(&session, &ownership), Ok(()));
    assert_eq!(factory.lifecycle.terminations.load(Ordering::SeqCst), 1);
    assert_eq!(
        router.create_context_owned(&tenant, &session, &ownership),
        Err(DependencyError::Rejected)
    );
    assert_eq!(factory.creations.load(Ordering::SeqCst), 1);
}

#[test]
fn cross_tenant_or_stale_fence_is_rejected_before_factory_effect() {
    let factory = Arc::new(Factory::default());
    let Some(router) = router(Arc::clone(&factory), Arc::new(RejectArtifacts), 8) else {
        return;
    };
    let Some(worker) = worker() else {
        return;
    };
    let tenant = TenantId::new();
    let other_tenant = TenantId::new();
    let session = SessionId::new();
    let ownership = fence(&worker, 13);
    assert!(
        router
            .create_context_owned(&tenant, &session, &ownership)
            .is_ok()
    );

    assert_eq!(
        router.create_context_owned(&other_tenant, &session, &ownership),
        Err(DependencyError::Rejected)
    );
    assert_eq!(
        router.create_context_owned(&tenant, &session, &fence(&worker, 14)),
        Err(DependencyError::Rejected)
    );
    assert_eq!(factory.creations.load(Ordering::SeqCst), 1);
}

#[test]
fn artifact_route_validates_active_namespace_and_full_fence_before_store_effect() {
    let factory = Arc::new(Factory::default());
    let artifacts = Arc::new(RecordingArtifacts::default());
    let Some(router) = router(Arc::clone(&factory), Arc::clone(&artifacts), 8) else {
        return;
    };
    let Some(worker) = worker() else {
        return;
    };
    let tenant = TenantId::new();
    let session = SessionId::new();
    let ownership = fence(&worker, 33);
    assert!(
        router
            .create_context_owned(&tenant, &session, &ownership)
            .is_ok()
    );

    let Some(valid) = artifact_request(&tenant, &session, &ownership) else {
        return;
    };
    let expected_effect = ArtifactEffect {
        tenant_id: tenant.clone(),
        session_id: session.clone(),
        artifact_id: valid.key().artifact_id().clone(),
        fence: ownership.clone(),
    };
    assert_eq!(
        SandboxClient::store_artifact(&router, &valid),
        Err(DependencyError::Rejected),
        "the active exact route must forward the underlying store result"
    );
    assert_eq!(artifacts.effects(), Some(vec![expected_effect]));

    let Some(cross_tenant) = artifact_request(&TenantId::new(), &session, &ownership) else {
        return;
    };
    assert_eq!(
        SandboxClient::store_artifact(&router, &cross_tenant),
        Err(DependencyError::Rejected)
    );

    let Some(unknown_session) = artifact_request(&tenant, &SessionId::new(), &ownership) else {
        return;
    };
    assert_eq!(
        SandboxClient::store_artifact(&router, &unknown_session),
        Err(DependencyError::Rejected)
    );

    let other_worker = WorkerId::new("other-router-worker");
    assert!(other_worker.is_ok());
    let Some(other_worker) = other_worker.ok() else {
        return;
    };
    let stale_fences = [
        OwnershipFence::new(other_worker, 7, 33, 1),
        OwnershipFence::new(worker.clone(), 8, 33, 1),
        OwnershipFence::new(worker.clone(), 7, 34, 1),
        OwnershipFence::new(worker, 7, 33, 2),
    ];
    for stale_fence in stale_fences {
        let Some(stale) = artifact_request(&tenant, &session, &stale_fence) else {
            return;
        };
        assert_eq!(
            SandboxClient::store_artifact(&router, &stale),
            Err(DependencyError::Rejected)
        );
    }
    assert_eq!(artifacts.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn exact_close_terminalizes_once_and_tombstones_the_session_identity() {
    let factory = Arc::new(Factory::default());
    let Some(router) = router(Arc::clone(&factory), Arc::new(RejectArtifacts), 8) else {
        return;
    };
    let Some(worker) = worker() else {
        return;
    };
    let tenant = TenantId::new();
    let session = SessionId::new();
    let ownership = fence(&worker, 15);
    assert!(
        router
            .create_context_owned(&tenant, &session, &ownership)
            .is_ok()
    );
    let Some(lifecycles) = factory.lifecycles() else {
        return;
    };
    let Some(lifecycle) = lifecycles.first() else {
        return;
    };

    assert_eq!(
        router.close_context_fenced(&session, &fence(&worker, 16)),
        Err(DependencyError::Rejected)
    );
    assert_eq!(lifecycle.terminations.load(Ordering::SeqCst), 0);
    assert_eq!(router.close_context_fenced(&session, &ownership), Ok(()));
    assert_eq!(router.close_context_fenced(&session, &ownership), Ok(()));
    assert_eq!(lifecycle.terminations.load(Ordering::SeqCst), 1);
    assert_eq!(
        router.create_context_owned(&tenant, &session, &ownership),
        Err(DependencyError::Rejected)
    );
    assert_eq!(factory.creations.load(Ordering::SeqCst), 1);
}

#[test]
fn heartbeat_and_qualification_cover_daemon_and_every_active_shard() {
    let factory = Arc::new(Factory::default());
    let Some(router) = router(Arc::clone(&factory), Arc::new(RejectArtifacts), 8) else {
        return;
    };
    let Some(worker) = worker() else {
        return;
    };
    for placement in [20, 21] {
        assert!(
            router
                .create_context_owned(
                    &TenantId::new(),
                    &SessionId::new(),
                    &fence(&worker, placement),
                )
                .is_ok()
        );
    }

    assert_eq!(ChromiumDriver::qualify(&router), Ok(()));
    assert_eq!(SandboxClient::heartbeat(&router, &worker, 7), Ok(()));
    assert_eq!(factory.daemon_qualifications.load(Ordering::SeqCst), 1);
    assert_eq!(factory.daemon_heartbeats.load(Ordering::SeqCst), 1);
    let Some(lifecycles) = factory.lifecycles() else {
        return;
    };
    assert_eq!(lifecycles.len(), 2);
    assert!(lifecycles.iter().all(|lifecycle| {
        lifecycle.qualifications.load(Ordering::SeqCst) == 1
            && lifecycle.heartbeats.load(Ordering::SeqCst) == 1
    }));
}

#[test]
fn blocking_external_health_calls_do_not_hold_the_global_router_lock() {
    let (qualification_gate, qualification_entered) = CallGate::new();
    let (heartbeat_gate, heartbeat_entered) = CallGate::new();
    let blocking_lifecycle = Arc::new(BlockingLifecycle {
        qualification_gate: Arc::clone(&qualification_gate),
        heartbeat_gate: Arc::clone(&heartbeat_gate),
        terminations: AtomicUsize::new(0),
    });
    let factory = Arc::new(LockProbeFactory {
        creations: AtomicUsize::new(0),
        blocking_lifecycle,
    });
    let Some(router) = router(Arc::clone(&factory), Arc::new(RejectArtifacts), 8).map(Arc::new)
    else {
        return;
    };
    let Some(worker) = worker() else {
        return;
    };
    let first_tenant = TenantId::new();
    let first_session = SessionId::new();
    let first_fence = fence(&worker, 40);
    let second_tenant = TenantId::new();
    let second_session = SessionId::new();
    let second_fence = fence(&worker, 41);
    assert!(
        router
            .create_context_owned(&first_tenant, &first_session, &first_fence)
            .is_ok()
    );
    assert!(
        router
            .create_context_owned(&second_tenant, &second_session, &second_fence)
            .is_ok()
    );

    let qualification_router = Arc::clone(&router);
    let qualification =
        std::thread::spawn(move || ChromiumDriver::qualify(qualification_router.as_ref()));
    let qualification_was_entered = qualification_entered.recv_timeout(TEST_TIMEOUT);

    let close_router = Arc::clone(&router);
    let close_session = second_session.clone();
    let close_fence = second_fence.clone();
    let (close_sender, close_receiver) = mpsc::channel();
    let close = std::thread::spawn(move || {
        let result = close_router.close_context_fenced(&close_session, &close_fence);
        let _ = close_sender.send(result);
    });
    let third_tenant = TenantId::new();
    let third_session = SessionId::new();
    let third_fence = fence(&worker, 42);
    let create_router = Arc::clone(&router);
    let create_tenant = third_tenant.clone();
    let create_session = third_session.clone();
    let create_fence = third_fence.clone();
    let (create_sender, create_receiver) = mpsc::channel();
    let create = std::thread::spawn(move || {
        let result =
            create_router.create_context_owned(&create_tenant, &create_session, &create_fence);
        let _ = create_sender.send(result);
    });
    let close_during_qualification = close_receiver.recv_timeout(TEST_TIMEOUT);
    let create_during_qualification = create_receiver.recv_timeout(TEST_TIMEOUT);

    qualification_gate.release();
    let qualification_result = qualification.join();
    let close_join = close.join();
    let create_join = create.join();

    assert!(qualification_was_entered.is_ok());
    assert_eq!(close_during_qualification, Ok(Ok(())));
    assert!(matches!(create_during_qualification, Ok(Ok(_))));
    assert!(matches!(qualification_result, Ok(Ok(()))));
    assert!(close_join.is_ok());
    assert!(create_join.is_ok());

    let heartbeat_router = Arc::clone(&router);
    let heartbeat_worker = worker.clone();
    let heartbeat = std::thread::spawn(move || {
        SandboxClient::heartbeat(heartbeat_router.as_ref(), &heartbeat_worker, 7)
    });
    let heartbeat_was_entered = heartbeat_entered.recv_timeout(TEST_TIMEOUT);

    let close_router = Arc::clone(&router);
    let close_session = third_session;
    let close_fence = third_fence;
    let (close_sender, close_receiver) = mpsc::channel();
    let close = std::thread::spawn(move || {
        let result = close_router.close_context_fenced(&close_session, &close_fence);
        let _ = close_sender.send(result);
    });
    let fourth_tenant = TenantId::new();
    let fourth_session = SessionId::new();
    let fourth_fence = fence(&worker, 43);
    let create_router = Arc::clone(&router);
    let (create_sender, create_receiver) = mpsc::channel();
    let create = std::thread::spawn(move || {
        let result =
            create_router.create_context_owned(&fourth_tenant, &fourth_session, &fourth_fence);
        let _ = create_sender.send(result);
    });
    let close_during_heartbeat = close_receiver.recv_timeout(TEST_TIMEOUT);
    let create_during_heartbeat = create_receiver.recv_timeout(TEST_TIMEOUT);

    heartbeat_gate.release();
    let heartbeat_result = heartbeat.join();
    let close_join = close.join();
    let create_join = create.join();

    assert!(heartbeat_was_entered.is_ok());
    assert_eq!(close_during_heartbeat, Ok(Ok(())));
    assert!(matches!(create_during_heartbeat, Ok(Ok(_))));
    assert!(matches!(heartbeat_result, Ok(Ok(()))));
    assert!(close_join.is_ok());
    assert!(create_join.is_ok());
}
