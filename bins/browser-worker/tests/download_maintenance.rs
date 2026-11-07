#![allow(clippy::expect_used)]

use std::collections::BTreeMap;
use std::os::unix::fs::MetadataExt;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use browser_worker::{LifecycleBounds, ProductionWorkerRuntime, ProductionWorkerRuntimeError};
use browserd_core::{ActionId, ArtifactId, PageId, SessionId, TenantId, WorkerId};
use browserd_policy::CanonicalActionProposal;
use browserd_sandbox::CleanupReason;
use browserd_session::{
    LeasePolicy, OwnershipFence, SessionLifecycle, SessionTime, SessionTimeoutPolicy,
};
use browserd_worker::{
    ActionExecutionResult, ActionJournalConfig, ApprovedActionError, ArtifactStoreReceipt,
    ArtifactStoreRequest, AuthenticatedPeer, BrowserDownloadCompletion, BrowserDownloadFile,
    ChromiumDriver, CreateSessionCommand, CreateSessionOutcome, DependencyError, InternalEndpoint,
    LiveApprovalContext, SandboxClient, WorkerConfig, WorkerControlPlane, WorkerRpcConfig,
    WorkerSessionOptionsV1, WorkerViewport,
};
use tokio_util::sync::CancellationToken;

const OBSERVATION_TIMEOUT: Duration = Duration::from_secs(3);

/// A test failure cannot leave a production blocking task waiting forever.
struct DownloadGate {
    entered: AtomicBool,
    timed_out: AtomicBool,
    released: Mutex<bool>,
    wake: Condvar,
}

impl DownloadGate {
    fn new() -> Self {
        Self {
            entered: AtomicBool::new(false),
            timed_out: AtomicBool::new(false),
            released: Mutex::new(false),
            wake: Condvar::new(),
        }
    }

    fn wait(&self) -> Result<(), DependencyError> {
        self.entered.store(true, Ordering::SeqCst);
        let released = self
            .released
            .lock()
            .map_err(|_| DependencyError::Unavailable)?;
        let (released, timeout) = self
            .wake
            .wait_timeout_while(released, Duration::from_secs(8), |released| !*released)
            .map_err(|_| DependencyError::Unavailable)?;
        if timeout.timed_out() && !*released {
            self.timed_out.store(true, Ordering::SeqCst);
            return Err(DependencyError::Unavailable);
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

struct DownloadsDriver {
    created_contexts: AtomicUsize,
    completion: Mutex<Option<BrowserDownloadCompletion>>,
    pending_calls: AtomicUsize,
    opens: AtomicUsize,
    rejected: AtomicUsize,
    gate: Option<Arc<DownloadGate>>,
}

impl ChromiumDriver for DownloadsDriver {
    fn qualify(&self) -> Result<(), DependencyError> {
        Ok(())
    }
    fn create_context(&self, _: &SessionId) -> Result<PageId, DependencyError> {
        Err(DependencyError::Rejected)
    }
    fn create_context_owned(
        &self,
        tenant: &TenantId,
        session: &SessionId,
        fence: &OwnershipFence,
    ) -> Result<PageId, DependencyError> {
        let page = PageId::new();
        if self.created_contexts.fetch_add(1, Ordering::SeqCst) == 0 {
            *self.completion.lock().expect("completion") = Some(BrowserDownloadCompletion {
                guid: "01234567-89ab-4cde-8fab-0123456789ab".to_owned(),
                artifact_id: ArtifactId::new(),
                tenant_id: tenant.clone(),
                session_id: session.clone(),
                fence: fence.clone(),
                page_id: page.clone(),
                expected_size_bytes: 17,
            });
        }
        Ok(page)
    }
    fn create_context_owned_with_options(
        &self,
        tenant: &TenantId,
        session: &SessionId,
        fence: &OwnershipFence,
        _: &WorkerSessionOptionsV1,
    ) -> Result<PageId, DependencyError> {
        self.create_context_owned(tenant, session, fence)
    }
    fn close_context(&self, _: &SessionId) -> Result<(), DependencyError> {
        Ok(())
    }
    fn create_page(&self, _: &SessionId) -> Result<PageId, DependencyError> {
        Ok(PageId::new())
    }
    fn close_page(&self, _: &SessionId, _: &PageId) -> Result<(), DependencyError> {
        Ok(())
    }
    fn activate_page(&self, _: &SessionId, _: &PageId) -> Result<(), DependencyError> {
        Ok(())
    }
    fn execute_action(&self, _: &SessionId, _: Option<&PageId>, _: &[u8]) -> ActionExecutionResult {
        ActionExecutionResult::OutcomeUnknown
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
        Ok(false)
    }

    fn pending_browser_downloads(
        &self,
        session: &SessionId,
        fence: &OwnershipFence,
        limit: usize,
    ) -> Result<Vec<BrowserDownloadCompletion>, DependencyError> {
        assert!((1..=4).contains(&limit));
        self.pending_calls.fetch_add(1, Ordering::SeqCst);
        let pending = self
            .completion
            .lock()
            .expect("completion")
            .as_ref()
            .filter(|completion| &completion.session_id == session && &completion.fence == fence)
            .cloned();
        if pending.is_some()
            && let Some(gate) = &self.gate
        {
            gate.wait()?;
        }
        Ok(pending.into_iter().collect())
    }

    fn open_browser_download(
        &self,
        completion: &BrowserDownloadCompletion,
    ) -> Result<BrowserDownloadFile, DependencyError> {
        assert_eq!(
            self.completion.lock().expect("completion").as_ref(),
            Some(completion)
        );
        self.opens.fetch_add(1, Ordering::SeqCst);
        // An integration fake has no owner-minted filesystem capability. The real
        // maintenance path must safely reject and retire this unreadable completion.
        Err(DependencyError::Rejected)
    }

    fn reject_browser_download(
        &self,
        completion: &BrowserDownloadCompletion,
    ) -> Result<(), DependencyError> {
        let mut pending = self.completion.lock().expect("completion");
        assert_eq!(pending.as_ref(), Some(completion));
        *pending = None;
        self.rejected.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[derive(Default)]
struct Sandbox {
    heartbeats: AtomicUsize,
    cleaned: Mutex<Vec<SessionId>>,
    stores: AtomicUsize,
}

impl SandboxClient for Sandbox {
    fn qualify(&self) -> Result<(), DependencyError> {
        Ok(())
    }
    fn provision(&self, _: &SessionId, _: &OwnershipFence) -> Result<(), DependencyError> {
        Ok(())
    }
    fn cleanup(&self, session: &SessionId, _: CleanupReason) -> Result<(), DependencyError> {
        self.cleaned
            .lock()
            .expect("cleaned sessions")
            .push(session.clone());
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
        self.stores.fetch_add(1, Ordering::SeqCst);
        Err(DependencyError::Rejected)
    }
}

struct Fixture {
    worker: Arc<WorkerControlPlane<DownloadsDriver, Sandbox>>,
    driver: Arc<DownloadsDriver>,
    sandbox: Arc<Sandbox>,
    peer: AuthenticatedPeer,
    download_session: CreateSessionOutcome,
    expiring_session: Option<CreateSessionOutcome>,
    shutdown: CancellationToken,
    task: Option<tokio::task::JoinHandle<Result<(), ProductionWorkerRuntimeError>>>,
    _directory: tempfile::TempDir,
}

impl Fixture {
    fn new(block_downloads: bool) -> Self {
        let directory = tempfile::tempdir().expect("runtime directory");
        let journal = directory.path().join("actions");
        std::fs::create_dir(&journal).expect("journal directory");
        let socket = directory.path().join("worker.sock");
        let peer = AuthenticatedPeer::new("download-maintenance-gateway").expect("peer");
        let config = WorkerConfig::new(
            WorkerId::new("download-maintenance-worker").expect("worker"),
            7,
            InternalEndpoint::unix(&socket).expect("endpoint"),
            peer.clone(),
            4,
            16,
            LeasePolicy::new(Duration::from_secs(15), Duration::from_secs(3)).expect("lease"),
            SessionTimeoutPolicy::new(Duration::from_secs(60), Duration::from_secs(60))
                .expect("timeouts"),
            Duration::from_secs(5),
            ActionJournalConfig::with_default_limits(&journal).expect("journal"),
        )
        .expect("worker config");
        let driver = Arc::new(DownloadsDriver {
            created_contexts: AtomicUsize::new(0),
            completion: Mutex::new(None),
            pending_calls: AtomicUsize::new(0),
            opens: AtomicUsize::new(0),
            rejected: AtomicUsize::new(0),
            gate: block_downloads.then(|| Arc::new(DownloadGate::new())),
        });
        let sandbox = Arc::new(Sandbox::default());
        let worker = Arc::new(WorkerControlPlane::new(
            config,
            driver.clone(),
            sandbox.clone(),
        ));
        let now = SessionTime::new(
            u64::try_from(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("system time")
                    .as_millis(),
            )
            .expect("current milliseconds"),
        );
        let command = |key: &str| CreateSessionCommand {
            tenant_id: TenantId::new(),
            idempotency_key: key.to_owned(),
            canonical_request_hash: [1; 32],
            placement_version: 1,
            session_incarnation: 1,
        };
        let download_session = worker
            .create_session(&peer, command("download-maintenance"), now)
            .expect("download session");
        let expiring_session = block_downloads.then(|| {
            let options = WorkerSessionOptionsV1 {
                workload_class_hint: "interactive".to_owned(),
                viewport: WorkerViewport {
                    width: 640,
                    height: 480,
                    device_scale_factor: 1,
                },
                locale: "en-US".to_owned(),
                timezone: "UTC".to_owned(),
                user_agent: None,
                network_policy_id: "public-web-default".to_owned(),
                network_class: "public".to_owned(),
                checkpoint_ref: None,
                dialog_policy: "auto_dismiss".to_owned(),
                feature_profile: "standard".to_owned(),
                ttl_seconds: 1,
                idle_timeout_seconds: 1,
                metadata: BTreeMap::new(),
            };
            worker
                .create_session_with_options(&peer, command("expiring-maintenance"), &options, now)
                .expect("independent expiring session")
        });
        let uid = std::fs::metadata("/proc/self")
            .expect("current process")
            .uid();
        let rpc = WorkerRpcConfig::new(
            &socket,
            128 * 1024,
            16,
            Duration::from_millis(500),
            Some(uid),
        )
        .expect("RPC config");
        let bounds = LifecycleBounds::new(
            Duration::from_millis(100),
            Duration::from_millis(50),
            Duration::from_secs(15),
            Duration::from_secs(2),
        )
        .expect("lifecycle bounds");
        let runtime = ProductionWorkerRuntime::new(worker.clone(), peer.clone(), rpc, bounds)
            .expect("qualified runtime");
        let shutdown = CancellationToken::new();
        let runtime_shutdown = shutdown.clone();
        let task = tokio::spawn(async move { runtime.serve(runtime_shutdown).await });
        Self {
            worker,
            driver,
            sandbox,
            peer,
            download_session,
            expiring_session,
            shutdown,
            task: Some(task),
            _directory: directory,
        }
    }

    async fn finish(mut self) {
        if let Some(gate) = &self.driver.gate {
            gate.release();
        }
        self.shutdown.cancel();
        tokio::time::timeout(OBSERVATION_TIMEOUT, self.task.take().expect("runtime task"))
            .await
            .expect("runtime shutdown is bounded")
            .expect("runtime task does not panic")
            .expect("runtime shutdown succeeds");
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(gate) = &self.driver.gate {
            gate.release();
        }
        self.shutdown.cancel();
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

async fn observe(message: &str, condition: impl Fn() -> bool) {
    tokio::time::timeout(OBSERVATION_TIMEOUT, async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect(message);
}

#[tokio::test]
async fn production_timer_reconciles_completed_download_without_artifact_http_or_rpc_polling() {
    let fixture = Fixture::new(false);
    // No client, artifact route, or manual reconcile call drives this completion.
    observe(
        "production timer retires the owned unreadable completion",
        || fixture.driver.rejected.load(Ordering::SeqCst) == 1,
    )
    .await;
    assert!(fixture.driver.pending_calls.load(Ordering::SeqCst) >= 1);
    assert_eq!(fixture.driver.opens.load(Ordering::SeqCst), 1);
    assert!(
        fixture
            .driver
            .completion
            .lock()
            .expect("completion")
            .is_none()
    );
    assert_eq!(fixture.sandbox.stores.load(Ordering::SeqCst), 0);
    assert_eq!(
        fixture
            .worker
            .get_session(
                &fixture.peer,
                &fixture.download_session.session_id,
                &fixture.download_session.fence
            )
            .expect("session remains live")
            .lifecycle,
        SessionLifecycle::Ready
    );
    assert!(
        fixture
            .sandbox
            .cleaned
            .lock()
            .expect("cleaned sessions")
            .is_empty()
    );
    fixture.finish().await;
}

#[tokio::test]
async fn blocked_download_maintenance_keeps_heartbeat_and_unrelated_session_expiration_running() {
    let fixture = Fixture::new(true);
    let gate = fixture.driver.gate.as_ref().expect("download gate");
    observe(
        "download maintenance enters its blocking dependency",
        || gate.entered.load(Ordering::SeqCst),
    )
    .await;
    let before = fixture.sandbox.heartbeats.load(Ordering::SeqCst);
    let expiring = fixture.expiring_session.as_ref().expect("expiring session");
    let progress = tokio::time::timeout(OBSERVATION_TIMEOUT, async {
        loop {
            if fixture.sandbox.heartbeats.load(Ordering::SeqCst) >= before + 3
                && fixture
                    .sandbox
                    .cleaned
                    .lock()
                    .expect("cleaned sessions")
                    .contains(&expiring.session_id)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    if progress.is_err() {
        let cleaned_sessions = fixture
            .sandbox
            .cleaned
            .lock()
            .expect("cleaned sessions")
            .clone();
        let gate_released = *gate.released.lock().expect("gate");
        assert!(
            progress.is_ok(),
            "heartbeat/TTL progress stalled: heartbeats_before={before}, heartbeats_current={}, cleaned_sessions={cleaned_sessions:?}, expiring_session={}, download_session={}, runtime_finished={}, gate_released={gate_released}, gate_timed_out={}, pending_calls={}, opens={}, rejected={}",
            fixture.sandbox.heartbeats.load(Ordering::SeqCst),
            expiring.session_id,
            fixture.download_session.session_id,
            fixture.task.as_ref().is_some_and(|task| task.is_finished()),
            gate.timed_out.load(Ordering::SeqCst),
            fixture.driver.pending_calls.load(Ordering::SeqCst),
            fixture.driver.opens.load(Ordering::SeqCst),
            fixture.driver.rejected.load(Ordering::SeqCst),
        );
    }
    assert!(!gate.timed_out.load(Ordering::SeqCst));
    assert!(!*gate.released.lock().expect("gate"));
    assert_eq!(fixture.driver.opens.load(Ordering::SeqCst), 0);
    assert!(
        fixture
            .driver
            .completion
            .lock()
            .expect("completion")
            .is_some()
    );
    assert_eq!(
        fixture
            .worker
            .get_session(&fixture.peer, &expiring.session_id, &expiring.fence)
            .expect("expired session")
            .lifecycle,
        SessionLifecycle::Closed
    );
    gate.release();
    observe("released maintenance safely retires its completion", || {
        fixture.driver.rejected.load(Ordering::SeqCst) == 1
    })
    .await;
    let sandbox = fixture.sandbox.clone();
    let expired_id = expiring.session_id.clone();
    let download_id = fixture.download_session.session_id.clone();
    fixture.finish().await;
    let cleaned = sandbox.cleaned.lock().expect("cleaned sessions");
    assert_eq!(cleaned.iter().filter(|id| **id == expired_id).count(), 1);
    assert_eq!(cleaned.iter().filter(|id| **id == download_id).count(), 1);
}
