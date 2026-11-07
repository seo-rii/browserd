#![allow(clippy::expect_used, clippy::unwrap_used)]

use super::*;
use std::os::unix::fs::MetadataExt;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex};

use browserd_core::{ActionId, PageId, SessionId, TenantId, WorkerId};
use browserd_policy::CanonicalActionProposal;
use browserd_sandbox::CleanupReason;
use browserd_session::{LeasePolicy, OwnershipFence, SessionTimeoutPolicy};
use browserd_worker::{
    ActionExecutionResult, ActionJournalConfig, ApprovedActionError, ArtifactStoreReceipt,
    ArtifactStoreRequest, BrowserDownloadCompletion, CreateSessionCommand, InternalEndpoint,
    LiveApprovalContext, WorkerConfig, WorkerRpcClient,
};

const OBSERVATION_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Default)]
struct Gate {
    entered: AtomicBool,
    released: Mutex<bool>,
    condition: Condvar,
    timed_out: AtomicBool,
}
impl Gate {
    fn release(&self) {
        *self.released.lock().expect("gate") = true;
        self.condition.notify_all();
    }
    fn wait(&self) {
        self.entered.store(true, Ordering::SeqCst);
        let (_guard, result) = self
            .condition
            .wait_timeout_while(
                self.released.lock().expect("gate"),
                Duration::from_secs(5),
                |released| !*released,
            )
            .expect("gate wait");
        self.timed_out
            .fetch_or(result.timed_out(), Ordering::SeqCst);
    }
}
struct ReleaseOnDrop(Arc<Gate>);
impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        self.0.release();
    }
}

#[derive(Default)]
struct Observations {
    calls: AtomicUsize,
    active: AtomicUsize,
    maximum_active: AtomicUsize,
    limits_and_deadlines: Mutex<Vec<(usize, Instant, Instant)>>,
}
struct Sweep {
    observations: Arc<Observations>,
    gate: Option<Arc<Gate>>,
    fail: bool,
}
impl ArtifactMaintenance for Sweep {
    fn sweep_expired(&self, limit: usize, deadline: Instant) -> Result<usize, DependencyError> {
        self.observations
            .limits_and_deadlines
            .lock()
            .expect("observations")
            .push((limit, Instant::now(), deadline));
        self.observations.calls.fetch_add(1, Ordering::SeqCst);
        let active = self.observations.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.observations
            .maximum_active
            .fetch_max(active, Ordering::SeqCst);
        if let Some(gate) = &self.gate {
            gate.wait();
        }
        self.observations.active.fetch_sub(1, Ordering::SeqCst);
        if self.fail {
            Err(DependencyError::Unavailable)
        } else {
            Ok(0)
        }
    }
}

async fn observe(description: &str, condition: impl Fn() -> bool) {
    tokio::time::timeout(OBSERVATION_TIMEOUT, async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .expect(description);
}

#[tokio::test]
async fn a_started_sweep_stays_single_in_flight_past_its_deadline() {
    let observations = Arc::new(Observations::default());
    let gate = Arc::new(Gate::default());
    let _release = ReleaseOnDrop(gate.clone());
    let sweep = Arc::new(Sweep {
        observations: observations.clone(),
        gate: Some(gate.clone()),
        fail: false,
    });
    let shutdown = CancellationToken::new();
    let task = tokio::spawn(run_artifact_maintenance(
        Some(sweep),
        shutdown.clone(),
        Duration::from_millis(10),
        Duration::from_millis(100),
    ));
    observe("sweep started", || gate.entered.load(Ordering::SeqCst)).await;
    tokio::time::sleep(Duration::from_millis(180)).await;
    assert_eq!(observations.calls.load(Ordering::SeqCst), 1);
    assert_eq!(observations.active.load(Ordering::SeqCst), 1);
    let observed = observations
        .limits_and_deadlines
        .lock()
        .expect("observations")[0];
    assert_eq!(observed.0, 32);
    assert!(observed.1 < observed.2);
    assert!(observed.2.duration_since(observed.1) <= Duration::from_millis(100));
    assert!(Instant::now() > observed.2);
    gate.release();
    observe("later tick retries after completed sweep", || {
        observations.calls.load(Ordering::SeqCst) >= 2
    })
    .await;
    shutdown.cancel();
    task.await.expect("maintenance task");
    observe("all callbacks settled", || {
        observations.active.load(Ordering::SeqCst) == 0
    })
    .await;
    assert_eq!(observations.maximum_active.load(Ordering::SeqCst), 1);
    assert!(!gate.timed_out.load(Ordering::SeqCst));
}

#[tokio::test(flavor = "current_thread")]
async fn errors_retry_on_scheduled_ticks_without_a_catch_up_burst() {
    let observations = Arc::new(Observations::default());
    let sweep = Arc::new(Sweep {
        observations: observations.clone(),
        gate: None,
        fail: true,
    });
    let shutdown = CancellationToken::new();
    let task = tokio::spawn(run_artifact_maintenance(
        Some(sweep),
        shutdown.clone(),
        Duration::from_millis(200),
        Duration::from_secs(1),
    ));
    observe("first error returned", || {
        observations.calls.load(Ordering::SeqCst) == 1
            && observations.active.load(Ordering::SeqCst) == 0
    })
    .await;
    // Deliberately stall this test's single-thread executor across several timer ticks.
    // Skip produces one overdue tick; Burst would immediately replay the missed interval.
    std::thread::sleep(Duration::from_millis(1100));
    observe("error retried after scheduler resumes", || {
        observations.calls.load(Ordering::SeqCst) >= 2
    })
    .await;
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert_eq!(observations.calls.load(Ordering::SeqCst), 2);
    observe("subsequent scheduled tick continues retries", || {
        observations.calls.load(Ordering::SeqCst) >= 3
    })
    .await;
    shutdown.cancel();
    task.await.expect("maintenance task");
    assert_eq!(observations.maximum_active.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn absent_or_cancelled_maintenance_never_invokes_a_callback() {
    run_artifact_maintenance(
        None,
        CancellationToken::new(),
        Duration::from_millis(1),
        Duration::from_secs(1),
    )
    .await;
    let observations = Arc::new(Observations::default());
    let sweep = Arc::new(Sweep {
        observations: observations.clone(),
        gate: None,
        fail: false,
    });
    let shutdown = CancellationToken::new();
    shutdown.cancel();
    run_artifact_maintenance(
        Some(sweep),
        shutdown,
        Duration::from_millis(1),
        Duration::from_secs(1),
    )
    .await;
    assert_eq!(observations.calls.load(Ordering::SeqCst), 0);
}

#[derive(Default)]
struct Driver {
    download_polls: AtomicUsize,
    creates: AtomicUsize,
}
impl ChromiumDriver for Driver {
    fn qualify(&self) -> Result<(), DependencyError> {
        Ok(())
    }
    fn create_context(&self, _: &SessionId) -> Result<PageId, DependencyError> {
        self.creates.fetch_add(1, Ordering::SeqCst);
        Ok(PageId::new())
    }
    fn close_context(&self, _: &SessionId) -> Result<(), DependencyError> {
        Ok(())
    }
    fn create_page(&self, _: &SessionId) -> Result<PageId, DependencyError> {
        Err(DependencyError::Rejected)
    }
    fn close_page(&self, _: &SessionId, _: &PageId) -> Result<(), DependencyError> {
        Err(DependencyError::Rejected)
    }
    fn activate_page(&self, _: &SessionId, _: &PageId) -> Result<(), DependencyError> {
        Err(DependencyError::Rejected)
    }
    fn execute_action(&self, _: &SessionId, _: Option<&PageId>, _: &[u8]) -> ActionExecutionResult {
        ActionExecutionResult::FailedKnown("unused".to_owned())
    }
    fn inspect_approval_context(
        &self,
        _: &SessionId,
        _: &PageId,
        _: &CanonicalActionProposal,
    ) -> Result<LiveApprovalContext, DependencyError> {
        Err(DependencyError::Rejected)
    }
    fn execute_approved_action(
        &self,
        _: &SessionId,
        _: &PageId,
        _: &[u8],
        _: &CanonicalActionProposal,
        _: &LiveApprovalContext,
        _: &mut dyn FnMut(&LiveApprovalContext) -> Result<(), ApprovedActionError>,
    ) -> Result<ActionExecutionResult, ApprovedActionError> {
        Err(ApprovedActionError::Unavailable)
    }
    fn cancel_action(&self, _: &SessionId, _: &ActionId) -> Result<bool, DependencyError> {
        Err(DependencyError::Rejected)
    }
    fn pending_browser_downloads(
        &self,
        _: &SessionId,
        _: &OwnershipFence,
        _: usize,
    ) -> Result<Vec<BrowserDownloadCompletion>, DependencyError> {
        self.download_polls.fetch_add(1, Ordering::SeqCst);
        Ok(Vec::new())
    }
}
#[derive(Default)]
struct Sandbox {
    heartbeats: AtomicUsize,
    provisions: AtomicUsize,
}
impl SandboxClient for Sandbox {
    fn qualify(&self) -> Result<(), DependencyError> {
        Ok(())
    }
    fn provision(&self, _: &SessionId, _: &OwnershipFence) -> Result<(), DependencyError> {
        self.provisions.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn cleanup(&self, _: &SessionId, _: CleanupReason) -> Result<(), DependencyError> {
        Ok(())
    }
    fn heartbeat(&self, _: &WorkerId, _: u64) -> Result<(), DependencyError> {
        self.heartbeats.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn store_artifact(
        &self,
        _: &ArtifactStoreRequest,
    ) -> Result<ArtifactStoreReceipt, DependencyError> {
        Err(DependencyError::Rejected)
    }
}

#[tokio::test]
async fn blocked_sweep_keeps_rpc_heartbeat_ready_and_shutdown_detaches_owned_callback() {
    let directory = tempfile::tempdir().expect("runtime directory");
    let journal = directory.path().join("actions");
    std::fs::create_dir(&journal).expect("journal");
    let socket = directory.path().join("worker.sock");
    let peer = AuthenticatedPeer::new("artifact-maintenance-gateway").expect("peer");
    let config = WorkerConfig::new(
        WorkerId::new("artifact-maintenance-worker").expect("worker"),
        7,
        InternalEndpoint::unix(&socket).expect("endpoint"),
        peer.clone(),
        2,
        2,
        LeasePolicy::new(Duration::from_secs(15), Duration::from_secs(3)).expect("lease"),
        SessionTimeoutPolicy::new(Duration::from_secs(60), Duration::from_secs(30))
            .expect("timeouts"),
        Duration::from_secs(5),
        ActionJournalConfig::with_default_limits(journal).expect("journal"),
    )
    .expect("config");
    let sandbox = Arc::new(Sandbox::default());
    let driver = Arc::new(Driver::default());
    let worker = Arc::new(WorkerControlPlane::new(
        config,
        driver.clone(),
        sandbox.clone(),
    ));
    worker
        .create_session(
            &peer,
            CreateSessionCommand {
                tenant_id: TenantId::new(),
                idempotency_key: "maintenance-session".to_owned(),
                canonical_request_hash: [9; 32],
                placement_version: 1,
                session_incarnation: 1,
            },
            current_session_time().expect("trusted UTC"),
        )
        .expect("session for independent download maintenance");
    let uid = std::fs::metadata("/proc/self").expect("process").uid();
    let rpc = WorkerRpcConfig::new(
        &socket,
        128 * 1024,
        16,
        Duration::from_millis(500),
        Some(uid),
    )
    .expect("rpc");
    let bounds = LifecycleBounds::new(
        Duration::from_millis(10),
        Duration::from_millis(20),
        Duration::from_secs(15),
        Duration::from_secs(1),
    )
    .expect("bounds");
    let observations = Arc::new(Observations::default());
    let gate = Arc::new(Gate::default());
    let _release = ReleaseOnDrop(gate.clone());
    let sweep = Arc::new(Sweep {
        observations: observations.clone(),
        gate: Some(gate.clone()),
        fail: false,
    });
    let weak = Arc::downgrade(&sweep);
    let runtime = ProductionWorkerRuntime::new(worker.clone(), peer, rpc, bounds)
        .expect("runtime")
        .with_artifact_maintenance(sweep);
    let shutdown = CancellationToken::new();
    let task = tokio::spawn(runtime.serve(shutdown.clone()));
    observe("maintenance blocked inside callback", || {
        gate.entered.load(Ordering::SeqCst)
    })
    .await;
    let before = sandbox.heartbeats.load(Ordering::SeqCst);
    observe("heartbeat advances independently", || {
        sandbox.heartbeats.load(Ordering::SeqCst) >= before + 3
    })
    .await;
    let before_downloads = driver.download_polls.load(Ordering::SeqCst);
    observe(
        "browser download maintenance advances independently",
        || driver.download_polls.load(Ordering::SeqCst) > before_downloads,
    )
    .await;
    let client = WorkerRpcClient::new(&socket, 128 * 1024, Duration::from_millis(500), Some(uid))
        .expect("client");
    let probe = client.probe(7).await.expect("RPC remains responsive");
    assert!(probe.ready);
    assert!(worker.is_ready());
    assert_eq!(observations.calls.load(Ordering::SeqCst), 1);
    let observed = observations
        .limits_and_deadlines
        .lock()
        .expect("observations")[0];
    assert_eq!(observed.0, 32);
    assert!(observed.1 < observed.2);
    assert!(observed.2.duration_since(observed.1) <= Duration::from_secs(5));
    shutdown.cancel();
    tokio::time::timeout(Duration::from_millis(500), task)
        .await
        .expect("shutdown must not wait on blocking cleanup")
        .expect("runtime task")
        .expect("clean shutdown");
    assert!(
        weak.upgrade().is_some(),
        "started callback retains maintenance owner"
    );
    assert_eq!(observations.active.load(Ordering::SeqCst), 1);
    gate.release();
    observe(
        "detached callback releases its owned capability only when finished",
        || weak.upgrade().is_none(),
    )
    .await;
    assert_eq!(observations.active.load(Ordering::SeqCst), 0);
    assert!(!gate.timed_out.load(Ordering::SeqCst));
}

#[tokio::test]
async fn production_transport_bootstraps_metadata_while_safety_admission_is_closed() {
    use browserd_core::{RuntimeSafetyCache, SafetySwitchSnapshot};
    use browserd_worker::{WorkerRpcRequest, WorkerRpcResponse};
    let directory = tempfile::tempdir().expect("runtime directory");
    let journal = directory.path().join("actions");
    std::fs::create_dir(&journal).expect("journal");
    let socket = directory.path().join("worker.sock");
    let peer = AuthenticatedPeer::new("safety-bootstrap-gateway").expect("peer");
    let config = WorkerConfig::new(
        WorkerId::new("safety-bootstrap-worker").expect("worker"),
        7,
        InternalEndpoint::unix(&socket).expect("endpoint"),
        peer.clone(),
        2,
        2,
        LeasePolicy::new(Duration::from_secs(15), Duration::from_secs(3)).expect("lease"),
        SessionTimeoutPolicy::new(Duration::from_secs(60), Duration::from_secs(30))
            .expect("timeouts"),
        Duration::from_secs(5),
        ActionJournalConfig::with_default_limits(journal).expect("journal"),
    )
    .expect("config");
    let driver = Arc::new(Driver::default());
    let sandbox = Arc::new(Sandbox::default());
    let cache = Arc::new(RuntimeSafetyCache::new());
    let worker = Arc::new(
        WorkerControlPlane::new(config, driver.clone(), sandbox.clone())
            .with_runtime_safety_cache(cache.clone(), "19".repeat(32))
            .expect("runtime safety"),
    );
    assert!(worker.control_plane_qualified());
    assert!(!worker.is_ready());
    let uid = std::fs::metadata("/proc/self").expect("process").uid();
    let rpc = WorkerRpcConfig::new(
        &socket,
        128 * 1024,
        16,
        Duration::from_millis(500),
        Some(uid),
    )
    .expect("rpc");
    let bounds = LifecycleBounds::new(
        Duration::from_millis(10),
        Duration::from_millis(20),
        Duration::from_secs(15),
        Duration::from_secs(1),
    )
    .expect("bounds");
    let runtime = ProductionWorkerRuntime::new(worker.clone(), peer.clone(), rpc, bounds)
        .expect("transport bootstrap");
    let shutdown = CancellationToken::new();
    let task = tokio::spawn(runtime.serve(shutdown.clone()));
    observe("RPC listener available before safety init", || {
        socket.exists()
    })
    .await;
    let client = WorkerRpcClient::new(&socket, 128 * 1024, Duration::from_millis(500), Some(uid))
        .expect("client");
    let metadata = client
        .exchange(WorkerRpcRequest::Probe {
            expected_worker_epoch: 7,
        })
        .await
        .expect("metadata");
    assert!(
        matches!(metadata, WorkerRpcResponse::Probe(receipt) if receipt.worker_epoch == 7 && !receipt.ready)
    );
    assert!(client.probe(7).await.is_err());
    assert!(
        worker
            .create_session(
                &peer,
                CreateSessionCommand {
                    tenant_id: TenantId::new(),
                    idempotency_key: "uninitialized-create".to_owned(),
                    canonical_request_hash: [9; 32],
                    placement_version: 1,
                    session_incarnation: 1,
                },
                current_session_time().expect("trusted UTC")
            )
            .is_err()
    );
    assert_eq!(driver.creates.load(Ordering::SeqCst), 0);
    assert_eq!(sandbox.provisions.load(Ordering::SeqCst), 0);
    cache
        .install(
            uuid::Uuid::new_v4(),
            SafetySwitchSnapshot::default(),
            Duration::from_secs(30),
        )
        .expect("observed initialized authority");
    assert!(
        client
            .probe(7)
            .await
            .expect("ready after observation")
            .ready
    );
    cache.invalidate().expect("lost continuity");
    let metadata = client
        .exchange(WorkerRpcRequest::Probe {
            expected_worker_epoch: 7,
        })
        .await
        .expect("metadata after invalidation");
    assert!(matches!(metadata, WorkerRpcResponse::Probe(receipt) if !receipt.ready));
    assert!(client.probe(7).await.is_err());
    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .expect("shutdown")
        .expect("runtime task")
        .expect("runtime drain");
}
