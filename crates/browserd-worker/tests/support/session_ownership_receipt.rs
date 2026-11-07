#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use browserd_actions::ActionJournalLimits;
use browserd_core::{ActionId, PageId, SessionId, TenantId, WorkerId};
use browserd_policy::CanonicalActionProposal;
use browserd_sandbox::CleanupReason;
use browserd_session::{LeasePolicy, OwnershipFence, SessionTime, SessionTimeoutPolicy};
use browserd_worker::{
    ActionExecutionResult, ActionJournalConfig, ApprovedActionError, ArtifactStoreReceipt,
    ArtifactStoreRequest, AuthenticatedPeer, ChromiumDriver, CreateSessionCommand, DependencyError,
    InternalEndpoint, LiveApprovalContext, SandboxClient, WorkerClock, WorkerConfig,
    WorkerControlPlane, WorkerControlPlaneRpcHandler, WorkerError, WorkerRpcClient,
    WorkerRpcConfig, WorkerRpcFailureCode, WorkerRpcHandler, WorkerRpcRequest, WorkerRpcResponse,
    WorkerRpcServer, WorkerSessionFence, WorkerSessionLifecycle, WorkerSessionOwnershipReceipt,
    WorkerSessionReceipt,
};
use tokio_util::sync::CancellationToken;

struct FrozenClock;

impl WorkerClock for FrozenClock {
    fn now(&self) -> Result<SessionTime, WorkerError> {
        Ok(SessionTime::new(0))
    }
}

type CloseGate = (mpsc::Sender<()>, mpsc::Receiver<()>);

#[derive(Default)]
struct InspectionDriver {
    effects: AtomicUsize,
    qualifications: AtomicUsize,
    close_gate: Mutex<Option<CloseGate>>,
}

impl ChromiumDriver for InspectionDriver {
    fn qualify(&self) -> Result<(), DependencyError> {
        self.qualifications.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn create_context(&self, _: &SessionId) -> Result<PageId, DependencyError> {
        self.effects.fetch_add(1, Ordering::SeqCst);
        Ok(PageId::new())
    }

    fn close_context(&self, _: &SessionId) -> Result<(), DependencyError> {
        self.effects.fetch_add(1, Ordering::SeqCst);
        let gate = self.close_gate.lock().expect("close gate").take();
        if let Some((entered, released)) = gate {
            entered.send(()).map_err(|_| DependencyError::Unavailable)?;
            released
                .recv_timeout(Duration::from_secs(5))
                .map_err(|_| DependencyError::Unavailable)?;
        }
        Ok(())
    }

    fn create_page(&self, _: &SessionId) -> Result<PageId, DependencyError> {
        self.effects.fetch_add(1, Ordering::SeqCst);
        Ok(PageId::new())
    }

    fn close_page(&self, _: &SessionId, _: &PageId) -> Result<(), DependencyError> {
        self.effects.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn activate_page(&self, _: &SessionId, _: &PageId) -> Result<(), DependencyError> {
        self.effects.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn execute_action(&self, _: &SessionId, _: Option<&PageId>, _: &[u8]) -> ActionExecutionResult {
        self.effects.fetch_add(1, Ordering::SeqCst);
        ActionExecutionResult::Succeeded(Vec::new())
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
        Err(ApprovedActionError::DispatchRevoked)
    }

    fn cancel_action(&self, _: &SessionId, _: &ActionId) -> Result<bool, DependencyError> {
        self.effects.fetch_add(1, Ordering::SeqCst);
        Ok(true)
    }
}

#[derive(Default)]
struct InspectionSandbox {
    effects: AtomicUsize,
    qualifications: AtomicUsize,
}

impl SandboxClient for InspectionSandbox {
    fn qualify(&self) -> Result<(), DependencyError> {
        self.qualifications.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn provision(&self, _: &SessionId, _: &OwnershipFence) -> Result<(), DependencyError> {
        self.effects.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn cleanup(&self, _: &SessionId, _: CleanupReason) -> Result<(), DependencyError> {
        self.effects.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn heartbeat(&self, _: &WorkerId, _: u64) -> Result<(), DependencyError> {
        self.effects.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn store_artifact(
        &self,
        _: &ArtifactStoreRequest,
    ) -> Result<ArtifactStoreReceipt, DependencyError> {
        self.effects.fetch_add(1, Ordering::SeqCst);
        Err(DependencyError::Unavailable)
    }
}

struct Fixture {
    directory: tempfile::TempDir,
    worker: Arc<WorkerControlPlane<InspectionDriver, InspectionSandbox>>,
    handler: Arc<WorkerControlPlaneRpcHandler<InspectionDriver, InspectionSandbox>>,
    driver: Arc<InspectionDriver>,
    sandbox: Arc<InspectionSandbox>,
    peer: AuthenticatedPeer,
    worker_id: WorkerId,
    fence: WorkerSessionFence,
    ownership: OwnershipFence,
    page: PageId,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("journal directory");
        let driver = Arc::new(InspectionDriver::default());
        let sandbox = Arc::new(InspectionSandbox::default());
        let peer = AuthenticatedPeer::new("inspection-gateway").expect("peer");
        let worker_id = WorkerId::new("inspection-worker").expect("worker");
        let config = WorkerConfig::new(
            worker_id.clone(),
            7,
            InternalEndpoint::Loopback(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 19731)),
            peer.clone(),
            1,
            8,
            LeasePolicy::new(Duration::from_secs(1), Duration::from_millis(200)).expect("lease"),
            SessionTimeoutPolicy::new(Duration::from_secs(60), Duration::from_secs(30))
                .expect("timeout"),
            Duration::from_secs(10),
            ActionJournalConfig::new(directory.path(), ActionJournalLimits::default())
                .expect("journal"),
        )
        .expect("config");
        let worker = Arc::new(WorkerControlPlane::new_with_clock(
            config,
            driver.clone(),
            sandbox.clone(),
            Arc::new(FrozenClock),
        ));
        let tenant = TenantId::new();
        let created = worker
            .create_session(
                &peer,
                CreateSessionCommand {
                    tenant_id: tenant.clone(),
                    idempotency_key: "owned-session".to_owned(),
                    canonical_request_hash: [19; 32],
                    placement_version: 11,
                    session_incarnation: 13,
                },
                SessionTime::new(0),
            )
            .expect("session");
        let fence = WorkerSessionFence {
            tenant_id: tenant,
            session_id: created.session_id,
            worker_epoch: 7,
            placement_version: 11,
            session_incarnation: 13,
        };
        let handler = Arc::new(WorkerControlPlaneRpcHandler::new(
            worker.clone(),
            peer.clone(),
        ));
        Self {
            directory,
            worker,
            handler,
            driver,
            sandbox,
            peer,
            worker_id,
            fence,
            ownership: created.fence,
            page: created.primary_page_id,
        }
    }

    fn request(&self) -> WorkerRpcRequest {
        WorkerRpcRequest::InspectSession {
            expected_worker_id: self.worker_id.clone(),
            fence: self.fence.clone(),
        }
    }

    fn counters(&self) -> [usize; 4] {
        [
            self.driver.effects.load(Ordering::SeqCst),
            self.sandbox.effects.load(Ordering::SeqCst),
            self.driver.qualifications.load(Ordering::SeqCst),
            self.sandbox.qualifications.load(Ordering::SeqCst),
        ]
    }

    fn wal(&self) -> Vec<u8> {
        std::fs::read(
            self.directory
                .path()
                .join(format!("{}.wal", self.fence.session_id)),
        )
        .expect("WAL")
    }

    fn expected(&self, lifecycle: WorkerSessionLifecycle) -> WorkerSessionOwnershipReceipt {
        WorkerSessionOwnershipReceipt {
            worker_id: self.worker_id.clone(),
            session: WorkerSessionReceipt {
                fence: self.fence.clone(),
                lifecycle,
                primary_page_id: self.page.clone(),
            },
        }
    }
}

#[tokio::test]
async fn inspection_reads_ready_session_during_drain_without_qualifying_or_mutating() {
    let fixture = Fixture::new();
    fixture.worker.begin_drain(&fixture.peer).expect("drain");
    assert!(!fixture.worker.is_ready());
    let before = fixture.counters();
    let wal = fixture.wal();
    for _ in 0..3 {
        assert_eq!(
            fixture.handler.handle(fixture.request()).await,
            WorkerRpcResponse::SessionOwnership(fixture.expected(WorkerSessionLifecycle::Ready))
        );
    }
    assert_eq!(fixture.counters(), before);
    assert_eq!(fixture.wal(), wal);
    let response = fixture
        .handler
        .handle(WorkerRpcRequest::Probe {
            expected_worker_epoch: 7,
        })
        .await;
    assert!(
        matches!(response, WorkerRpcResponse::Failure(failure) if failure.code == WorkerRpcFailureCode::NotReady)
    );
    assert_eq!(fixture.counters(), before);
}

#[tokio::test]
async fn inspection_reads_failed_owned_session_when_probe_readiness_denies() {
    let fixture = Fixture::new();
    assert_eq!(
        fixture
            .worker
            .expire_due(&fixture.peer, SessionTime::new(1_000))
            .expect("expire"),
        1
    );
    assert!(!fixture.worker.is_ready());
    let before = fixture.counters();
    let wal = fixture.wal();
    assert_eq!(
        fixture.handler.handle(fixture.request()).await,
        WorkerRpcResponse::SessionOwnership(fixture.expected(WorkerSessionLifecycle::Failed))
    );
    assert_eq!(fixture.counters(), before);
    assert_eq!(fixture.wal(), wal);
    assert_eq!(
        fixture
            .handler
            .handle(WorkerRpcRequest::GetSession {
                fence: fixture.fence.clone()
            })
            .await,
        WorkerRpcResponse::Session(fixture.expected(WorkerSessionLifecycle::Failed).session)
    );
    assert!(
        matches!(fixture.handler.handle(WorkerRpcRequest::Probe {expected_worker_epoch:7}).await,
        WorkerRpcResponse::Failure(failure) if failure.code == WorkerRpcFailureCode::NotReady)
    );
}

#[tokio::test]
async fn inspection_reads_closed_owned_session_without_reopening_admission() {
    let fixture = Fixture::new();
    fixture
        .worker
        .close_session(
            &fixture.peer,
            &fixture.fence.session_id,
            &fixture.ownership,
            SessionTime::new(1),
        )
        .expect("close");
    fixture.worker.begin_drain(&fixture.peer).expect("drain");
    assert!(!fixture.worker.is_ready());
    let before = fixture.counters();
    let wal = fixture.wal();
    assert_eq!(
        fixture.handler.handle(fixture.request()).await,
        WorkerRpcResponse::SessionOwnership(fixture.expected(WorkerSessionLifecycle::Closed))
    );
    assert_eq!(fixture.counters(), before);
    assert_eq!(fixture.wal(), wal);
    assert_eq!(
        fixture
            .worker
            .get_session(&fixture.peer, &fixture.fence.session_id, &fixture.ownership)
            .expect("session")
            .lifecycle,
        browserd_session::SessionLifecycle::Closed
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inspection_observes_closing_while_cleanup_is_in_flight() {
    let fixture = Fixture::new();
    let (entered_tx, entered_rx) = mpsc::channel();
    let (released_tx, released_rx) = mpsc::channel();
    *fixture.driver.close_gate.lock().expect("gate") = Some((entered_tx, released_rx));
    let worker = fixture.worker.clone();
    let peer = fixture.peer.clone();
    let session = fixture.fence.session_id.clone();
    let ownership = fixture.ownership.clone();
    let close = std::thread::spawn(move || {
        worker.close_session(&peer, &session, &ownership, SessionTime::new(1))
    });
    entered_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("cleanup started");
    let observed = fixture.handler.handle(fixture.request()).await;
    released_tx.send(()).expect("release cleanup");
    close.join().expect("close thread").expect("close");
    assert_eq!(
        observed,
        WorkerRpcResponse::SessionOwnership(fixture.expected(WorkerSessionLifecycle::Closing))
    );
}

#[tokio::test]
async fn inspection_rejects_other_worker_tenant_session_and_every_fence_component() {
    let fixture = Fixture::new();
    let before = fixture.counters();
    let wal = fixture.wal();
    for field in 0..10 {
        let mut worker_id = fixture.worker_id.clone();
        let mut fence = fixture.fence.clone();
        match field {
            0 => worker_id = WorkerId::new("other-worker").expect("worker"),
            1 => fence.tenant_id = TenantId::new(),
            2 => fence.session_id = SessionId::new(),
            3 => fence.worker_epoch += 1,
            4 => fence.placement_version += 1,
            5 => fence.session_incarnation += 1,
            6 => fence.worker_epoch = 0,
            7 => fence.placement_version = 0,
            8 => fence.session_incarnation = 0,
            _ => {
                worker_id = WorkerId::new("other-worker").expect("worker");
                fence.session_id = SessionId::new();
            }
        }
        let response = fixture
            .handler
            .handle(WorkerRpcRequest::InspectSession {
                expected_worker_id: worker_id,
                fence,
            })
            .await;
        assert!(
            matches!(response, WorkerRpcResponse::Failure(failure)
            if failure.code == if field == 2 {WorkerRpcFailureCode::NotFound} else {WorkerRpcFailureCode::FenceMismatch}),
            "invalid field {field}"
        );
    }
    let untrusted = WorkerControlPlaneRpcHandler::new(
        fixture.worker.clone(),
        AuthenticatedPeer::new("untrusted").expect("peer"),
    );
    assert!(matches!(untrusted.handle(fixture.request()).await,
        WorkerRpcResponse::Failure(failure) if failure.code == WorkerRpcFailureCode::Unauthorized));
    assert_eq!(fixture.counters(), before);
    assert_eq!(fixture.wal(), wal);
}

#[test]
fn inspection_wire_requires_exact_known_fields_and_roundtrips_every_lifecycle() {
    let fixture = Fixture::new();
    let request = serde_json::to_value(fixture.request()).expect("request JSON");
    assert_eq!(
        serde_json::from_value::<WorkerRpcRequest>(request.clone()).expect("request"),
        fixture.request()
    );
    for field in 0..6 {
        let mut invalid = request.clone();
        match field {
            0 => invalid["unexpected"] = serde_json::json!(true),
            1 => invalid["params"]["unexpected"] = serde_json::json!(true),
            2 => invalid["params"]["fence"]["unexpected"] = serde_json::json!(true),
            3 => {
                invalid["params"]
                    .as_object_mut()
                    .expect("params")
                    .remove("expected_worker_id");
            }
            4 => invalid["params"]["expected_worker_id"] = serde_json::Value::Null,
            _ => invalid["method"] = serde_json::json!("inspect_session_future"),
        }
        assert!(
            serde_json::from_value::<WorkerRpcRequest>(invalid).is_err(),
            "invalid request {field}"
        );
    }
    for lifecycle in [
        WorkerSessionLifecycle::Creating,
        WorkerSessionLifecycle::Ready,
        WorkerSessionLifecycle::Closing,
        WorkerSessionLifecycle::Closed,
        WorkerSessionLifecycle::Failed,
    ] {
        let response = WorkerRpcResponse::SessionOwnership(fixture.expected(lifecycle));
        let encoded = serde_json::to_value(&response).expect("response JSON");
        assert_eq!(
            serde_json::from_value::<WorkerRpcResponse>(encoded.clone()).expect("response"),
            response
        );
        for field in 0..5 {
            let mut invalid = encoded.clone();
            match field {
                0 => invalid["value"]["unexpected"] = serde_json::json!(true),
                1 => invalid["value"]["session"]["unexpected"] = serde_json::json!(true),
                2 => invalid["value"]["session"]["fence"]["unexpected"] = serde_json::json!(true),
                3 => invalid["value"]["session"]["lifecycle"] = serde_json::json!("ready_future"),
                _ => {
                    invalid["value"]
                        .as_object_mut()
                        .expect("value")
                        .remove("worker_id");
                }
            }
            assert!(
                serde_json::from_value::<WorkerRpcResponse>(invalid).is_err(),
                "invalid response {field}"
            );
        }
    }
}

#[tokio::test]
async fn inspection_roundtrips_actual_failed_owner_handler_over_authenticated_unix_transport() {
    let fixture = Fixture::new();
    fixture
        .worker
        .expire_due(&fixture.peer, SessionTime::new(1_000))
        .expect("expire");
    let uid = super::current_uid().expect("effective UID");
    let socket_path = fixture.directory.path().join("ownership.sock");
    let config = WorkerRpcConfig::new(&socket_path, 65_536, 4, Duration::from_secs(2), Some(uid))
        .expect("config");
    let server = WorkerRpcServer::bind(config, fixture.handler.clone())
        .await
        .expect("server");
    let shutdown = CancellationToken::new();
    let task = tokio::spawn(server.serve(shutdown.clone()));
    let client = WorkerRpcClient::new(&socket_path, 65_536, Duration::from_secs(2), Some(uid))
        .expect("client");
    let before = fixture.counters();
    let wal = fixture.wal();
    let owned = client.exchange(fixture.request()).await;
    let wrong = client
        .exchange(WorkerRpcRequest::InspectSession {
            expected_worker_id: WorkerId::new("wrong-worker").expect("worker"),
            fence: fixture.fence.clone(),
        })
        .await;
    let probe = client.probe(fixture.fence.worker_epoch).await;
    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(3), task)
        .await
        .expect("server shutdown")
        .expect("join")
        .expect("serve");
    assert_eq!(
        owned.expect("ownership response"),
        WorkerRpcResponse::SessionOwnership(fixture.expected(WorkerSessionLifecycle::Failed))
    );
    assert!(
        matches!(wrong.expect("denied response"), WorkerRpcResponse::Failure(failure)
        if failure.code == WorkerRpcFailureCode::FenceMismatch)
    );
    assert!(
        matches!(probe, Err(browserd_worker::WorkerRpcError::Remote(failure))
        if failure.code == WorkerRpcFailureCode::NotReady)
    );
    assert_eq!(fixture.counters(), before);
    assert_eq!(fixture.wal(), wal);
}
