#![allow(clippy::expect_used, clippy::panic)]

use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use browserd_actions::{
    ActionJournalLimits, ActionJournalPool, ActionJournalPoolConfig, ActionKind, FileActionJournal,
    ReplayableActionJournal,
};
use browserd_core::{
    ActionId, IsolationProfile, NotificationAck, NotificationCommit,
    NotificationSessionExecutionState, NotificationSessionLifecycleState, NotificationSourceFamily,
    PageId, PrincipalId, SessionId, TenantId, WorkerId, WorkerNotificationEvent,
};
use browserd_policy::{
    ActionArgumentsHash, ActionType, CanonicalActionProposal, CredentialRefsHash, Origin,
};
use browserd_sandbox::CleanupReason;
use browserd_session::{LeasePolicy, OwnershipFence, SessionTime, SessionTimeoutPolicy};
use browserd_worker::{
    ActionApprovalRequirement, ActionExecutionResult, ActionJournalConfig, ApprovedActionError,
    ArtifactStoreReceipt, ArtifactStoreRequest, AuthenticatedPeer, ChromiumDriver,
    CreateSessionCommand, CreateSessionOutcome, DependencyError, InternalEndpoint,
    LiveApprovalContext, SandboxClient, SessionEventJournal, WorkerClock, WorkerConfig,
    WorkerControlPlane, WorkerControlPlaneRpcHandler, WorkerError, WorkerNotificationPage,
    WorkerRpcFailureCode, WorkerRpcHandler, WorkerRpcRequest, WorkerRpcResponse,
};

struct FrozenClock;
impl WorkerClock for FrozenClock {
    fn now(&self) -> Result<SessionTime, WorkerError> {
        Ok(SessionTime::new(0))
    }
}

#[derive(Default)]
struct Driver {
    executions: AtomicUsize,
    gate: Mutex<Option<EffectGate>>,
}
type EffectGate = (mpsc::Sender<()>, mpsc::Receiver<()>);
impl ChromiumDriver for Driver {
    fn qualify(&self) -> Result<(), DependencyError> {
        Ok(())
    }
    fn create_context(&self, _session_id: &SessionId) -> Result<PageId, DependencyError> {
        Ok(PageId::new())
    }
    fn close_context(&self, _session_id: &SessionId) -> Result<(), DependencyError> {
        Ok(())
    }
    fn create_page(&self, _session_id: &SessionId) -> Result<PageId, DependencyError> {
        Ok(PageId::new())
    }
    fn close_page(
        &self,
        _session_id: &SessionId,
        _page_id: &PageId,
    ) -> Result<(), DependencyError> {
        Ok(())
    }
    fn activate_page(
        &self,
        _session_id: &SessionId,
        _page_id: &PageId,
    ) -> Result<(), DependencyError> {
        Ok(())
    }
    fn execute_action(
        &self,
        _session_id: &SessionId,
        _page_id: Option<&PageId>,
        payload: &[u8],
    ) -> ActionExecutionResult {
        self.executions.fetch_add(1, Ordering::AcqRel);
        if let Some((started, release)) = self.gate.lock().expect("gate").take() {
            started.send(()).expect("effect observed");
            release
                .recv_timeout(Duration::from_secs(10))
                .expect("bounded effect release");
        }
        ActionExecutionResult::Succeeded(payload.to_vec())
    }
    fn inspect_approval_context(
        &self,
        _session_id: &SessionId,
        _page_id: &PageId,
        _proposal: &CanonicalActionProposal,
    ) -> Result<LiveApprovalContext, DependencyError> {
        Ok(LiveApprovalContext {
            target_incarnation: 1,
            frame_document_epoch: 1,
            current_origin: Origin::parse("https://example.test/")
                .map_err(|_| DependencyError::Rejected)?,
            url_revision: 1,
            node_ref: None,
            node_valid: true,
            resolved_ips: Vec::new(),
            credential_refs: Vec::new(),
            chromium_build: "sha256:notification-rpc-test".to_owned(),
            effective_isolation: IsolationProfile::DedicatedProcess,
        })
    }
    fn execute_approved_action(
        &self,
        session_id: &SessionId,
        page_id: &PageId,
        payload: &[u8],
        proposal: &CanonicalActionProposal,
        inspected: &LiveApprovalContext,
        authorize_and_commit: &mut dyn FnMut(
            &LiveApprovalContext,
        ) -> Result<(), ApprovedActionError>,
    ) -> Result<ActionExecutionResult, ApprovedActionError> {
        let observed = self
            .inspect_approval_context(session_id, page_id, proposal)
            .map_err(|_| ApprovedActionError::Unavailable)?;
        if let Some(reason) = inspected.stale_reason(&observed) {
            return Err(ApprovedActionError::ApprovalStale(reason));
        }
        authorize_and_commit(&observed)?;
        Ok(self.execute_action(session_id, Some(page_id), payload))
    }
    fn cancel_action(
        &self,
        _session_id: &SessionId,
        _action_id: &ActionId,
    ) -> Result<bool, DependencyError> {
        Ok(true)
    }
}

struct Sandbox {
    fail_provision: bool,
}
impl SandboxClient for Sandbox {
    fn qualify(&self) -> Result<(), DependencyError> {
        Ok(())
    }
    fn provision(
        &self,
        _session_id: &SessionId,
        _fence: &OwnershipFence,
    ) -> Result<(), DependencyError> {
        if self.fail_provision {
            Err(DependencyError::Unavailable)
        } else {
            Ok(())
        }
    }
    fn cleanup(
        &self,
        _session_id: &SessionId,
        _reason: CleanupReason,
    ) -> Result<(), DependencyError> {
        Ok(())
    }
    fn heartbeat(&self, _worker_id: &WorkerId, _worker_epoch: u64) -> Result<(), DependencyError> {
        Ok(())
    }
    fn store_artifact(
        &self,
        _request: &ArtifactStoreRequest,
    ) -> Result<ArtifactStoreReceipt, DependencyError> {
        Err(DependencyError::Unavailable)
    }
}

type TestWorker = WorkerControlPlane<Driver, Sandbox>;
type TestHandler = WorkerControlPlaneRpcHandler<Driver, Sandbox>;
struct Fixture {
    worker: Arc<TestWorker>,
    handler: Arc<TestHandler>,
    driver: Arc<Driver>,
    peer: AuthenticatedPeer,
    worker_id: WorkerId,
    epoch: u64,
}
fn fixture(root: &Path, epoch: u64, fail_provision: bool) -> Fixture {
    let actions = root.join("actions");
    fs::create_dir_all(&actions).expect("action root");
    fs::set_permissions(&actions, fs::Permissions::from_mode(0o700)).expect("private action root");
    let limits = ActionJournalLimits::new(8192, 128, 1024 * 1024);
    let worker_id = WorkerId::new("notification-rpc-worker").expect("worker");
    let peer = AuthenticatedPeer::new("notification-rpc-gateway").expect("peer");
    let config = WorkerConfig::new(
        worker_id.clone(),
        epoch,
        InternalEndpoint::Loopback(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9123)),
        peer.clone(),
        4,
        8,
        LeasePolicy::new(Duration::from_secs(30), Duration::from_secs(1)).expect("lease"),
        SessionTimeoutPolicy::new(Duration::from_secs(60), Duration::from_secs(30))
            .expect("timeout"),
        Duration::from_secs(10),
        ActionJournalConfig::new(&actions, limits).expect("journal config"),
    )
    .expect("worker config");
    let pool = ActionJournalPool::open(
        ActionJournalPoolConfig::new(actions, limits).expect("pool config"),
        worker_id.clone(),
    )
    .expect("pool");
    let journal = SessionEventJournal::open(
        &root.join("session-events.json"),
        4096,
        16384,
        32 * 1024 * 1024,
    )
    .expect("session authority");
    let driver = Arc::new(Driver::default());
    let worker = Arc::new(
        WorkerControlPlane::new_with_clock(
            config,
            Arc::clone(&driver),
            Arc::new(Sandbox { fail_provision }),
            Arc::new(FrozenClock),
        )
        .with_action_journal_pool(pool)
        .with_session_event_journal(Arc::new(journal)),
    );
    let handler = Arc::new(TestHandler::new(Arc::clone(&worker), peer.clone()));
    Fixture {
        worker,
        handler,
        driver,
        peer,
        worker_id,
        epoch,
    }
}
fn create(f: &Fixture, tenant: TenantId) -> Result<CreateSessionOutcome, WorkerError> {
    f.worker.create_session(
        &f.peer,
        CreateSessionCommand {
            tenant_id: tenant,
            idempotency_key: "create-notification-session".to_owned(),
            canonical_request_hash: [17; 32],
            placement_version: 2,
            session_incarnation: 3,
        },
        SessionTime::new(0),
    )
}
fn pending_request(f: &Fixture, family: NotificationSourceFamily) -> WorkerRpcRequest {
    WorkerRpcRequest::PendingNotifications {
        expected_worker_id: f.worker_id.clone(),
        expected_worker_epoch: f.epoch,
        family,
        cursor: None,
        limit: 32,
    }
}
async fn pending(f: &Fixture, family: NotificationSourceFamily) -> WorkerNotificationPage {
    let request = serde_json::from_slice(
        &serde_json::to_vec(&pending_request(f, family)).expect("encode request"),
    )
    .expect("decode request");
    let response = f.handler.handle(request).await;
    let response = serde_json::from_slice(&serde_json::to_vec(&response).expect("encode response"))
        .expect("decode response");
    let WorkerRpcResponse::Notifications {
        worker_id,
        worker_epoch,
        page,
    } = response
    else {
        panic!("notification RPC failed: {response:?}");
    };
    assert_eq!(worker_id, f.worker_id);
    assert_eq!(worker_epoch, f.epoch);
    page.validate(&f.worker_id, f.epoch, family, 32)
        .expect("scope/page validation");
    *page
}
async fn ack(f: &Fixture, ack: NotificationAck) {
    let expected = ack.clone();
    let response = f
        .handler
        .handle(WorkerRpcRequest::AckNotification {
            expected_worker_id: f.worker_id.clone(),
            expected_worker_epoch: f.epoch,
            ack: Box::new(ack),
        })
        .await;
    let WorkerRpcResponse::NotificationAck {
        worker_id,
        worker_epoch,
        ack,
    } = response
    else {
        panic!("ack RPC failed: {response:?}");
    };
    assert_eq!(worker_id, f.worker_id);
    assert_eq!(worker_epoch, f.epoch);
    assert_eq!(*ack, expected);
}
async fn drain(f: &Fixture, family: NotificationSourceFamily) -> Vec<NotificationCommit> {
    let mut commits = Vec::new();
    for _ in 0..32 {
        let page = pending(f, family).await;
        if page.commits.is_empty() {
            return commits;
        }
        for commit in page.commits {
            ack(f, commit.ack()).await;
            commits.push(commit);
        }
    }
    panic!("bounded fixture notification stream did not drain");
}

#[tokio::test]
async fn historical_closed_session_metadata_keeps_original_scope_and_needs_no_live_ready_session() {
    let dir = tempfile::tempdir().expect("private root");
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).expect("private");
    let f = fixture(dir.path(), 9, false);
    let tenant = TenantId::new();
    let created = create(&f, tenant.clone()).expect("create");
    f.worker
        .close_session(
            &f.peer,
            &created.session_id,
            &created.fence,
            SessionTime::new(1),
        )
        .expect("positive cleanup");
    let first = pending(&f, NotificationSourceFamily::SessionLifecycle).await;
    assert_eq!(first.commits.len(), 1);
    let immutable = first.commits[0].clone();
    assert_eq!(f.driver.executions.load(Ordering::Acquire), 0);
    drop(f);
    let restarted = fixture(dir.path(), 10, false);
    assert!(
        restarted
            .worker
            .get_session(&restarted.peer, &created.session_id, &created.fence)
            .is_err(),
        "source transfer does not reconstruct a live session"
    );
    assert_eq!(
        pending(&restarted, NotificationSourceFamily::SessionLifecycle)
            .await
            .commits,
        vec![immutable]
    );
    let commits = drain(&restarted, NotificationSourceFamily::SessionLifecycle).await;
    assert!(
        commits
            .iter()
            .flat_map(|c| c.descriptors())
            .any(|d| matches!(
                d.event(),
                WorkerNotificationEvent::SessionLifecycleChanged {
                    state: NotificationSessionLifecycleState::Closed
                }
            ))
    );
    for commit in &commits {
        assert_eq!(commit.scope().tenant_id(), &tenant);
        assert_eq!(commit.scope().original_worker_id(), &restarted.worker_id);
        for descriptor in commit.descriptors() {
            assert_eq!(descriptor.session_scope().session_id(), &created.session_id);
            assert_eq!(
                descriptor.session_scope().fence(),
                created.fence.as_placement_fence()
            );
        }
    }
    assert_eq!(restarted.driver.executions.load(Ordering::Acquire), 0);
}

#[tokio::test]
async fn failed_session_creation_without_actions_has_durable_failed_lifecycle_metadata() {
    let dir = tempfile::tempdir().expect("private root");
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).expect("private");
    let f = fixture(dir.path(), 9, true);
    let tenant = TenantId::new();
    assert!(create(&f, tenant.clone()).is_err());
    let commits = drain(&f, NotificationSourceFamily::SessionLifecycle).await;
    assert!(
        commits
            .iter()
            .flat_map(|c| c.descriptors())
            .any(|d| matches!(
                d.event(),
                WorkerNotificationEvent::SessionLifecycleChanged {
                    state: NotificationSessionLifecycleState::Failed
                }
            ))
    );
    assert!(commits.iter().all(|c| c.scope().tenant_id() == &tenant));
    assert!(
        pending(&f, NotificationSourceFamily::ActionJournal)
            .await
            .commits
            .is_empty()
    );
    assert_eq!(f.driver.executions.load(Ordering::Acquire), 0);
}

#[tokio::test]
async fn wrong_peer_worker_epoch_and_ack_digest_are_rejected_before_source_ack() {
    let dir = tempfile::tempdir().expect("private root");
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).expect("private");
    let f = fixture(dir.path(), 9, false);
    create(&f, TenantId::new()).expect("create");
    let original = pending(&f, NotificationSourceFamily::SessionLifecycle)
        .await
        .commits[0]
        .clone();
    let foreign = TestHandler::new(
        Arc::clone(&f.worker),
        AuthenticatedPeer::new("foreign-gateway").expect("foreign peer"),
    );
    assert!(
        matches!(foreign.handle(pending_request(&f, NotificationSourceFamily::SessionLifecycle)).await, WorkerRpcResponse::Failure(error) if error.code == WorkerRpcFailureCode::Unauthorized)
    );
    assert!(
        matches!(foreign.handle(WorkerRpcRequest::AckNotification { expected_worker_id:f.worker_id.clone(), expected_worker_epoch:f.epoch, ack:Box::new(original.ack()) }).await, WorkerRpcResponse::Failure(error) if error.code == WorkerRpcFailureCode::Unauthorized)
    );
    for (worker, epoch) in [
        (f.worker_id.clone(), 8),
        (WorkerId::new("foreign-worker").expect("worker"), 9),
    ] {
        assert!(matches!(
            f.handler
                .handle(WorkerRpcRequest::PendingNotifications {
                    expected_worker_id: worker.clone(),
                    expected_worker_epoch: epoch,
                    family: NotificationSourceFamily::SessionLifecycle,
                    cursor: None,
                    limit: 32
                })
                .await,
            WorkerRpcResponse::Failure(_)
        ));
        assert!(matches!(
            f.handler
                .handle(WorkerRpcRequest::AckNotification {
                    expected_worker_id: worker,
                    expected_worker_epoch: epoch,
                    ack: Box::new(original.ack())
                })
                .await,
            WorkerRpcResponse::Failure(_)
        ));
    }
    let mut wire = serde_json::to_value(original.ack()).expect("ack wire");
    wire["digest"][0] = serde_json::json!(if original.digest()[0] == 1 { 2 } else { 1 });
    let wrong = serde_json::from_value(wire).expect("typed syntactically valid forged digest");
    assert!(matches!(
        f.handler
            .handle(WorkerRpcRequest::AckNotification {
                expected_worker_id: f.worker_id.clone(),
                expected_worker_epoch: f.epoch,
                ack: Box::new(wrong)
            })
            .await,
        WorkerRpcResponse::Failure(_)
    ));
    assert_eq!(
        pending(&f, NotificationSourceFamily::SessionLifecycle)
            .await
            .commits,
        vec![original.clone()]
    );
    ack(&f, original.ack()).await;
    assert_ne!(
        pending(&f, NotificationSourceFamily::SessionLifecycle)
            .await
            .commits
            .first(),
        Some(&original)
    );
}

#[tokio::test]
async fn approval_required_rpc_identity_matches_ram_and_original_wal() {
    let dir = tempfile::tempdir().expect("private root");
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).expect("private");
    let f = fixture(dir.path(), 9, false);
    let tenant = TenantId::new();
    let created = create(&f, tenant.clone()).expect("create");
    let principal = PrincipalId::new();
    let payload = b"manual-action";
    let proposal = CanonicalActionProposal::new(
        tenant,
        principal.clone(),
        created.session_id.clone(),
        created.fence.session_incarnation(),
        created.primary_page_id.clone(),
        1,
        1,
        Origin::parse("https://example.test/").expect("origin"),
        1,
        ActionType::Click,
        ActionArgumentsHash::digest(payload),
        None,
        CredentialRefsHash::digest(std::iter::empty()),
        10_000,
    );
    let action = f
        .worker
        .submit_action(
            &f.peer,
            principal,
            &created.session_id,
            &created.fence,
            "manual-action",
            [33; 32],
            ActionKind::Mutating,
            None,
            Some(created.primary_page_id.clone()),
            payload.to_vec(),
            Some(ActionApprovalRequirement::new(
                proposal,
                ActionType::Click,
                true,
            )),
            SessionTime::new(0),
        )
        .expect("identified approval requirement");
    let id = f
        .worker
        .approval_for_action(&f.peer, &created.session_id, &action, &created.fence)
        .expect("ram identity");
    assert_eq!(
        f.worker
            .get_approval(&f.peer, &created.session_id, &id, &created.fence)
            .expect("approval")
            .action_id,
        action
    );
    let commits = drain(&f, NotificationSourceFamily::ActionJournal).await;
    let required = commits.iter().find(|c| c.descriptors().iter().any(|d| matches!(d.event(), WorkerNotificationEvent::ActionApprovalRequired { action_id, approval_id } if action_id == &action && approval_id == &id))).expect("required production notification");
    assert_eq!(
        required.descriptors().len(),
        2,
        "pending state and requirement share one authority commit"
    );
    let copy = dir.path().join("original-authority-copy.wal");
    fs::copy(
        dir.path()
            .join("actions")
            .join(format!("{}.wal", created.session_id)),
        &copy,
    )
    .expect("copy immutable committed prefix");
    let wal = FileActionJournal::open(copy, ActionJournalLimits::new(8192, 128, 1024 * 1024))
        .expect("validate original frame checksums");
    let entries = wal.replay().expect("original metadata");
    let record = entries
        .iter()
        .find(|entry| entry.notifications() == Some(required))
        .expect("same commit inside original authority WAL");
    assert_eq!(record.approval_id(), Some(&id));
    assert_eq!(f.driver.executions.load(Ordering::Acquire), 0);
}

#[tokio::test]
async fn cancelling_queued_b_during_running_a_emits_no_false_idle_execution() {
    let dir = tempfile::tempdir().expect("private root");
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).expect("private");
    let f = fixture(dir.path(), 9, false);
    let created = create(&f, TenantId::new()).expect("create");
    drain(&f, NotificationSourceFamily::SessionLifecycle).await;
    let (started_tx, started_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    *f.driver.gate.lock().expect("gate") = Some((started_tx, release_rx));
    struct ReleaseOnDrop(Option<mpsc::Sender<()>>);
    impl Drop for ReleaseOnDrop {
        fn drop(&mut self) {
            if let Some(sender) = self.0.take() {
                let _ = sender.send(());
            }
        }
    }
    let mut release = ReleaseOnDrop(Some(release_tx));
    let a = f
        .worker
        .submit_action(
            &f.peer,
            PrincipalId::new(),
            &created.session_id,
            &created.fence,
            "running-a",
            [41; 32],
            ActionKind::Mutating,
            None,
            None,
            b"A".to_vec(),
            None,
            SessionTime::new(0),
        )
        .expect("a");
    let worker = Arc::clone(&f.worker);
    let peer = f.peer.clone();
    let session = created.session_id.clone();
    let fence = created.fence.clone();
    let running = std::thread::spawn(move || {
        worker.run_next_action(&peer, &session, &fence, SessionTime::new(0))
    });
    started_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("a effect started");
    let b = f
        .worker
        .submit_action(
            &f.peer,
            PrincipalId::new(),
            &created.session_id,
            &created.fence,
            "queued-b",
            [42; 32],
            ActionKind::Mutating,
            None,
            None,
            b"B".to_vec(),
            None,
            SessionTime::new(0),
        )
        .expect("b");
    f.worker
        .cancel_action(
            &f.peer,
            &created.session_id,
            &b,
            &created.fence,
            SessionTime::new(0),
        )
        .expect("b known cancelled");
    assert_eq!(
        f.worker
            .get_session(&f.peer, &created.session_id, &created.fence)
            .expect("current execution")
            .execution,
        browserd_session::SessionExecution::Running(a.clone())
    );
    let commits = drain(&f, NotificationSourceFamily::SessionLifecycle).await;
    assert!(commits.iter().flat_map(|c| c.descriptors()).any(|d| matches!(d.event(), WorkerNotificationEvent::SessionExecutionChanged { state:NotificationSessionExecutionState::Running, action_id:Some(id) } if id == &a)));
    assert!(
        !commits
            .iter()
            .flat_map(|c| c.descriptors())
            .any(|d| matches!(
                d.event(),
                WorkerNotificationEvent::SessionExecutionChanged {
                    state: NotificationSessionExecutionState::Idle,
                    ..
                }
            ))
    );
    release
        .0
        .take()
        .expect("release sender")
        .send(())
        .expect("finish a");
    running
        .join()
        .expect("action owner exited")
        .expect("a completed");
    assert_eq!(f.driver.executions.load(Ordering::Acquire), 1);
}
