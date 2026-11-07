#![allow(clippy::expect_used)]

use super::*;
use browserd_core::{LaunchGeneration, OwnerFence, ShardFence, ShardId, WorkerEpoch};
use browserd_worker::WorkerIsolationProfile;

struct SharedLifecycle {
    shard: ShardFence,
    health: Arc<Lifecycle>,
    closes: AtomicUsize,
}
impl SessionShardLifecycle for SharedLifecycle {
    fn shard_fence(&self) -> Option<ShardFence> {
        Some(self.shard.clone())
    }
    fn qualify(&self) -> Result<(), DependencyError> {
        self.health.qualify()
    }
    fn heartbeat(&self) -> Result<(), DependencyError> {
        self.health.heartbeat()
    }
    fn terminate(&self, _: &OwnershipFence) -> Result<(), DependencyError> {
        self.closes.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}
struct PlacementFactory {
    actual: WorkerIsolationProfile,
    shard: ShardFence,
    health: Arc<Lifecycle>,
    requested: Mutex<Vec<WorkerIsolationProfile>>,
    contexts: Mutex<Vec<Arc<SharedLifecycle>>>,
}
impl PlacementFactory {
    fn new(actual: WorkerIsolationProfile) -> Self {
        Self {
            actual,
            shard: ShardFence::new(
                OwnerFence::new(
                    worker().expect("worker"),
                    WorkerEpoch::new(7).expect("epoch"),
                ),
                ShardId::new(),
                LaunchGeneration::new(1).expect("generation"),
            ),
            health: Arc::new(Lifecycle::default()),
            requested: Mutex::new(Vec::new()),
            contexts: Mutex::new(Vec::new()),
        }
    }
}
impl SessionShardFactory for PlacementFactory {
    fn qualify_daemon(&self) -> Result<(), DependencyError> {
        Ok(())
    }
    fn heartbeat_daemon(&self, _: &WorkerId, _: u64) -> Result<(), DependencyError> {
        Ok(())
    }
    fn create(
        &self,
        _: &TenantId,
        _: &SessionId,
        _: &OwnershipFence,
    ) -> Result<ProvisionedSessionShard, DependencyError> {
        Err(DependencyError::Rejected)
    }
    fn create_with_placement(
        &self,
        _: &TenantId,
        _: &SessionId,
        _: &OwnershipFence,
        options: Option<&WorkerSessionOptionsV1>,
        requested: WorkerIsolationProfile,
    ) -> Result<ProvisionedSessionShard, DependencyError> {
        assert_eq!(options, Some(&session_options("standard")));
        self.requested.lock().expect("requested").push(requested);
        let lifecycle = Arc::new(SharedLifecycle {
            shard: self.shard.clone(),
            health: Arc::clone(&self.health),
            closes: AtomicUsize::new(0),
        });
        self.contexts
            .lock()
            .expect("contexts")
            .push(Arc::clone(&lifecycle));
        Ok(ProvisionedSessionShard::with_isolation(
            PageId::new(),
            Arc::new(UnavailableChromiumDriver),
            lifecycle,
            self.actual,
        ))
    }
}

#[test]
fn shared_placement_is_per_session_and_health_is_once_per_shard() {
    let factory = Arc::new(PlacementFactory::new(WorkerIsolationProfile::SharedContext));
    let router = router(Arc::clone(&factory), Arc::new(RejectArtifacts), 8).expect("router");
    let worker = worker().expect("worker");
    let tenant = TenantId::new();
    let options = session_options("standard");
    let a = SessionId::new();
    let b = SessionId::new();
    let fa = fence(&worker, 11);
    let fb = fence(&worker, 12);
    let first = router
        .create_context_owned_with_placement(
            &tenant,
            &a,
            &fa,
            Some(&options),
            WorkerIsolationProfile::SharedContext,
        )
        .expect("first");
    let repeat = router
        .create_context_owned_with_placement(
            &tenant,
            &a,
            &fa,
            Some(&options),
            WorkerIsolationProfile::SharedContext,
        )
        .expect("retry");
    assert_eq!(first, repeat);
    assert_eq!(
        first.effective_isolation,
        WorkerIsolationProfile::SharedContext
    );
    router
        .create_context_owned_with_placement(
            &TenantId::new(),
            &b,
            &fb,
            Some(&options),
            WorkerIsolationProfile::SharedContext,
        )
        .expect("sibling");
    assert!(
        router
            .create_context_owned_with_placement(
                &tenant,
                &a,
                &fa,
                Some(&options),
                WorkerIsolationProfile::TenantDedicatedShard
            )
            .is_err()
    );
    assert_eq!(factory.requested.lock().expect("requested").len(), 2);
    assert_eq!(ChromiumDriver::qualify(&router), Ok(()));
    assert_eq!(SandboxClient::heartbeat(&router, &worker, 7), Ok(()));
    assert_eq!(factory.health.qualifications.load(Ordering::SeqCst), 1);
    assert_eq!(factory.health.heartbeats.load(Ordering::SeqCst), 1);
    assert_eq!(router.close_context_fenced(&a, &fa), Ok(()));
    let contexts = factory.contexts.lock().expect("contexts");
    assert_eq!(contexts[0].closes.load(Ordering::SeqCst), 1);
    assert_eq!(contexts[1].closes.load(Ordering::SeqCst), 0);
    drop(contexts);
    assert_eq!(SandboxClient::heartbeat(&router, &worker, 7), Ok(()));
    assert_eq!(factory.health.heartbeats.load(Ordering::SeqCst), 2);
    assert_eq!(router.close_context_fenced(&b, &fb), Ok(()));
}

#[test]
fn weaker_factory_receipt_is_cleaned_without_publishing_a_route() {
    let factory = Arc::new(PlacementFactory::new(WorkerIsolationProfile::SharedContext));
    let router = router(Arc::clone(&factory), Arc::new(RejectArtifacts), 8).expect("router");
    let tenant = TenantId::new();
    let session = SessionId::new();
    let fence = fence(&worker().expect("worker"), 11);
    let options = session_options("standard");
    assert!(
        router
            .create_context_owned_with_placement(
                &tenant,
                &session,
                &fence,
                Some(&options),
                WorkerIsolationProfile::DedicatedProcess
            )
            .is_err()
    );
    assert_eq!(
        factory.contexts.lock().expect("contexts")[0]
            .closes
            .load(Ordering::SeqCst),
        1
    );
    assert!(router.create_page(&session).is_err());
}
