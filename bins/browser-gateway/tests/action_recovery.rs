#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use browser_gateway::{
    GatewayWorkerClient, GatewayWorkerPending, GatewayWorkerPlacement, GatewayWorkerRuntime,
};
use browserd_actions::{
    ActionDeliveryEvidence, ActionKind, ActionSequence, CanonicalRequestHash, DispatchId,
    KnownFailureReason, OutcomeUnknownReason, ResultDigest, TerminalDetail,
};
use browserd_api::{ActionGetRequest, ApiRequest, ApiResponse, ApiRouter, ApiService};
use browserd_auth::{
    AuthConfig, AuthenticatedPrincipal, RevocationRegistry, ServiceClaims, ServiceTokenSigner,
    ServiceTokenVerifier, VerificationKeySet,
};
use browserd_coordination::{
    ClaimGatewayAction, CoordinationActorConfig, DirectoryFence, GatewayActionBlockingClient,
    GatewayActionCoordination, GatewayActionCoordinationError, GatewayActionPlacement,
    GatewayActionSnapshot, GatewayActionSubmissionLease, MemoryGatewayActionStore, OutboxEventKind,
};
use browserd_core::{
    ActionId, ActionState, ErrorCode, PageId, PrincipalId, SessionId, TenantId, WorkerId,
};
use browserd_worker::{
    WorkerActionReceipt, WorkerActionStatus, WorkerCreateSessionReceipt,
    WorkerCreateSessionRequest, WorkerProbeReceipt, WorkerRpcCompletionError,
    WorkerRpcEnqueueError, WorkerRpcError, WorkerRpcFailure, WorkerRpcFailureCode,
    WorkerRpcRequest, WorkerRpcResponse, WorkerSessionFence, WorkerSessionLifecycle,
    WorkerSessionOwnershipReceipt, WorkerSessionReceipt,
};
use chrono::{DateTime, Utc};
use jsonwebtoken::Algorithm;
use sha2::{Digest, Sha256};
use uuid::Uuid;

const BODY: &[u8] = br#"{"recovered":true}"#;

#[derive(Clone, Copy, Debug)]
enum Fault {
    None,
    InspectWorker,
    InspectEpoch,
    InspectProtocol,
    InspectTimeout,
    InspectTenant,
    InspectSession,
    InspectPlacement,
    SessionFence,
    SessionNotFound,
    ActionNotFound,
    ActionTimeout,
    ActionFenceFailure,
    ReceiptTenant,
    ReceiptSession,
    ReceiptEpoch,
    ReceiptPlacement,
    ReceiptIncarnation,
    ReceiptAction,
    ReceiptSequence,
    ReceiptKey,
    ReceiptHash,
    ReceiptKind,
    ReceiptDigest,
}

struct NeverPending;

impl GatewayWorkerPending for NeverPending {
    fn wait(self) -> Result<WorkerRpcResponse, WorkerRpcCompletionError> {
        panic!("recovery must never enqueue or wait for a new submission")
    }
}

struct RecoveryWorker {
    id: WorkerId,
    fault: Mutex<Fault>,
    lifecycle: Mutex<WorkerSessionLifecycle>,
    ready: AtomicBool,
    receipts: Mutex<HashMap<ActionId, WorkerActionReceipt>>,
    requests: Mutex<Vec<&'static str>>,
    mutations: AtomicUsize,
    before_action: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl GatewayWorkerClient for RecoveryWorker {
    type PendingAction = NeverPending;

    fn create_session(
        &self,
        _: WorkerCreateSessionRequest,
    ) -> Result<WorkerCreateSessionReceipt, WorkerRpcError> {
        self.mutations.fetch_add(1, Ordering::SeqCst);
        panic!("recovery must never create a session")
    }

    fn enqueue_action(
        &self,
        _: WorkerRpcRequest,
    ) -> Result<Self::PendingAction, WorkerRpcEnqueueError> {
        self.mutations.fetch_add(1, Ordering::SeqCst);
        panic!("recovery must never submit an action")
    }

    fn request(&self, request: WorkerRpcRequest) -> Result<WorkerRpcResponse, WorkerRpcError> {
        let fault = *self.fault.lock().expect("fault lock");
        match request {
            WorkerRpcRequest::Probe {
                expected_worker_epoch,
            } => {
                self.requests.lock().expect("requests").push("probe");
                Ok(WorkerRpcResponse::Probe(WorkerProbeReceipt {
                    worker_id: self.id.clone(),
                    worker_epoch: expected_worker_epoch,
                    ready: self.ready.load(Ordering::Acquire),
                }))
            }
            WorkerRpcRequest::InspectSession {
                expected_worker_id,
                mut fence,
            } => {
                self.requests.lock().expect("requests").push("inspect");
                assert_eq!(expected_worker_id, self.id);
                if matches!(fault, Fault::InspectTimeout) {
                    return Err(WorkerRpcError::Timeout);
                }
                if matches!(fault, Fault::InspectProtocol) {
                    return Ok(WorkerRpcResponse::Empty);
                }
                if matches!(fault, Fault::SessionNotFound) {
                    return Ok(WorkerRpcResponse::Failure(WorkerRpcFailure::new(
                        WorkerRpcFailureCode::NotFound,
                        "session unavailable",
                    )));
                }
                match fault {
                    Fault::SessionFence => fence.session_incarnation += 1,
                    Fault::InspectEpoch => fence.worker_epoch += 1,
                    Fault::InspectTenant => fence.tenant_id = TenantId::new(),
                    Fault::InspectSession => fence.session_id = SessionId::new(),
                    Fault::InspectPlacement => fence.placement_version += 1,
                    _ => {}
                }
                Ok(WorkerRpcResponse::SessionOwnership(
                    WorkerSessionOwnershipReceipt {
                        worker_id: if matches!(fault, Fault::InspectWorker) {
                            WorkerId::new("foreign-worker").expect("worker")
                        } else {
                            self.id.clone()
                        },
                        session: WorkerSessionReceipt {
                            fence,
                            lifecycle: *self.lifecycle.lock().expect("lifecycle"),
                            primary_page_id: PageId::new(),
                        },
                    },
                ))
            }
            WorkerRpcRequest::GetAction { action_id, .. } => {
                self.requests.lock().expect("requests").push("action");
                let hook = self.before_action.lock().expect("hook").take();
                if let Some(hook) = hook {
                    hook();
                }
                match fault {
                    Fault::ActionTimeout => return Err(WorkerRpcError::Timeout),
                    Fault::ActionNotFound | Fault::ActionFenceFailure => {
                        return Ok(WorkerRpcResponse::Failure(WorkerRpcFailure::new(
                            if matches!(fault, Fault::ActionNotFound) {
                                WorkerRpcFailureCode::NotFound
                            } else {
                                WorkerRpcFailureCode::FenceMismatch
                            },
                            "action unavailable",
                        )));
                    }
                    _ => {}
                }
                let mut receipt = self
                    .receipts
                    .lock()
                    .expect("receipts")
                    .get(&action_id)
                    .expect("seeded receipt")
                    .clone();
                match fault {
                    Fault::ReceiptTenant => receipt.fence.tenant_id = TenantId::new(),
                    Fault::ReceiptSession => receipt.fence.session_id = SessionId::new(),
                    Fault::ReceiptEpoch => receipt.fence.worker_epoch += 1,
                    Fault::ReceiptPlacement => receipt.fence.placement_version += 1,
                    Fault::ReceiptIncarnation => receipt.fence.session_incarnation += 1,
                    Fault::ReceiptAction => receipt.action_id = ActionId::new(),
                    Fault::ReceiptSequence => {
                        receipt.action_sequence =
                            ActionSequence::new(receipt.action_sequence.get() + 1)
                    }
                    Fault::ReceiptKey => receipt.idempotency_key.push('x'),
                    Fault::ReceiptHash => receipt.canonical_request_hash[0] ^= 1,
                    Fault::ReceiptKind => receipt.kind = ActionKind::Mutating,
                    Fault::ReceiptDigest => receipt.result = Some(b"different result".to_vec()),
                    _ => {}
                }
                Ok(WorkerRpcResponse::Action(receipt))
            }
            _ => panic!("recovery sent a mutation or unrelated worker RPC"),
        }
    }
}

struct Fixture {
    executor: tokio::runtime::Runtime,
    store: Arc<MemoryGatewayActionStore>,
    worker: Arc<RecoveryWorker>,
    tenant: TenantId,
}

impl Fixture {
    fn new() -> Self {
        Self {
            executor: tokio::runtime::Runtime::new().expect("runtime"),
            store: Arc::new(MemoryGatewayActionStore::default()),
            worker: Arc::new(RecoveryWorker {
                id: WorkerId::new("action-recovery-test").expect("worker"),
                fault: Mutex::new(Fault::None),
                lifecycle: Mutex::new(WorkerSessionLifecycle::Ready),
                ready: AtomicBool::new(true),
                receipts: Mutex::new(HashMap::new()),
                requests: Mutex::new(Vec::new()),
                mutations: AtomicUsize::new(0),
                before_action: Mutex::new(None),
            }),
            tenant: TenantId::new(),
        }
    }

    fn placement(&self) -> GatewayActionPlacement {
        GatewayActionPlacement::new(
            DirectoryFence::new(self.worker.id.clone(), 3, 4, 5).expect("directory fence"),
            6,
        )
        .expect("placement")
    }

    fn gateway(&self) -> GatewayWorkerRuntime<RecoveryWorker> {
        GatewayWorkerRuntime::with_action_coordination(
            self.worker.clone(),
            GatewayWorkerPlacement::new(self.worker.id.clone(), 3, 4, 6).expect("placement"),
            self.store.clone(),
            CoordinationActorConfig::default(),
        )
        .expect("gateway")
    }

    fn seed(
        &self,
        placement: GatewayActionPlacement,
        lease: Option<GatewayActionSubmissionLease>,
        now: DateTime<Utc>,
        armed: bool,
    ) -> GatewayActionSnapshot {
        let session = SessionId::new();
        let id = ActionId::new();
        self.executor.block_on(async {
            let mut claim = ClaimGatewayAction::new(
                self.tenant.clone(),
                session.clone(),
                id.clone(),
                id.to_string(),
                CanonicalRequestHash::new([17; 32]),
                ActionKind::ReadOnly,
                placement.clone(),
            )
            .expect("claim");
            if let Some(lease) = &lease {
                claim = claim.with_submission_lease(lease.clone());
            }
            let claimed = self
                .store
                .claim_action(claim, now)
                .await
                .expect("claim")
                .into_snapshot();
            let durable = if armed {
                let dispatch = DispatchId::new();
                if let Some(lease) = &lease {
                    self.store
                        .arm_dispatch_owned(
                            &self.tenant,
                            &session,
                            &id,
                            claimed.revision(),
                            &placement,
                            dispatch,
                            lease,
                            now,
                        )
                        .await
                        .expect("owned arm")
                } else {
                    self.store
                        .arm_dispatch(
                            &self.tenant,
                            &session,
                            &id,
                            claimed.revision(),
                            &placement,
                            dispatch,
                            now,
                        )
                        .await
                        .expect("arm")
                }
            } else {
                claimed
            };
            let directory = placement.directory_fence();
            self.worker.receipts.lock().expect("receipts").insert(
                id.clone(),
                WorkerActionReceipt {
                    fence: WorkerSessionFence {
                        tenant_id: self.tenant.clone(),
                        session_id: session,
                        worker_epoch: directory.worker_epoch(),
                        placement_version: directory.placement_version(),
                        session_incarnation: directory.session_incarnation(),
                    },
                    action_id: id,
                    action_sequence: durable.action_sequence(),
                    idempotency_key: durable.idempotency_key().to_owned(),
                    canonical_request_hash: *durable.request_hash().as_bytes(),
                    kind: durable.kind(),
                    status: WorkerActionStatus::Succeeded,
                    dispatch_acknowledged: true,
                    approval_decision: None,
                    terminal_detail: Some(TerminalDetail::Succeeded(ResultDigest::new(
                        Sha256::digest(BODY).into(),
                    ))),
                    result: Some(BODY.to_vec()),
                    resolution: None,
                    custody: None,
                    custody_requirement: None,
                },
            );
            durable
        })
    }

    fn stored(&self, action: &GatewayActionSnapshot) -> GatewayActionSnapshot {
        self.executor
            .block_on(self.store.get_effective_action(
                action.tenant_id(),
                action.session_id(),
                action.action_id(),
            ))
            .expect("read")
            .expect("action")
    }
}

fn principal(tenant: TenantId) -> AuthenticatedPrincipal {
    let secret = [31; 32];
    let mut keys = VerificationKeySet::new();
    keys.insert_hmac("recovery-test", Algorithm::HS256, &secret)
        .expect("key");
    let verifier = ServiceTokenVerifier::new(
        AuthConfig::new("issuer", "audience", [Algorithm::HS256], 0, false),
        keys,
        RevocationRegistry::new(),
    );
    let token = ServiceTokenSigner::new("recovery-test", Algorithm::HS256, &secret)
        .sign(&ServiceClaims::new(
            "issuer",
            "audience",
            PrincipalId::new(),
            tenant,
            BTreeSet::from(["session:read".to_owned()]),
            "recovery-test",
            1,
            100,
            None,
        ))
        .expect("token");
    verifier.verify_at(&token, None, 10).expect("principal")
}

#[test]
fn restart_get_recovers_body_without_hydrating_or_replaying_session() {
    let fixture = Fixture::new();
    let action = fixture.seed(fixture.placement(), None, Utc::now(), true);
    let router = ApiRouter::new(Arc::new(fixture.gateway()));
    let user = principal(fixture.tenant.clone());
    let ApiResponse::Action(receipt) = router
        .execute(
            &user,
            ApiRequest::GetAction(ActionGetRequest {
                session_id: action.session_id().clone(),
                action_id: action.action_id().clone(),
            }),
        )
        .expect("restart get")
    else {
        panic!("action response")
    };
    assert_eq!(receipt.data().state(), ActionState::Succeeded);
    assert_eq!(receipt.data().result_content(), Some(BODY));
    assert_eq!(fixture.stored(&action).result_content(), Some(BODY));
    assert_eq!(
        router
            .execute(&user, ApiRequest::GetSession(action.session_id().clone()))
            .expect_err("recovery must not create a Ready session")
            .code(),
        ErrorCode::SessionNotFound
    );
    assert_eq!(
        *fixture.worker.requests.lock().expect("requests"),
        ["inspect", "action"]
    );
    assert_eq!(fixture.worker.mutations.load(Ordering::SeqCst), 0);
}

#[test]
fn autonomous_recovery_persists_success_without_client_polling() {
    let fixture = Fixture::new();
    let action = fixture.seed(fixture.placement(), None, Utc::now(), true);
    assert_eq!(
        fixture
            .gateway()
            .reconcile_pending_actions(256)
            .expect("pass"),
        1
    );
    let stored = fixture.stored(&action);
    assert_eq!(stored.state(), ActionState::Succeeded);
    assert_eq!(stored.result_content(), Some(BODY));
    assert!(stored.terminal_outbox_append().is_some());
    assert_eq!(fixture.worker.mutations.load(Ordering::SeqCst), 0);
}

#[test]
fn restart_get_unavailable_worker_returns_existing_pending_receipt() {
    let fixture = Fixture::new();
    let action = fixture.seed(fixture.placement(), None, Utc::now(), true);
    *fixture.worker.fault.lock().expect("fault") = Fault::ActionNotFound;
    let router = ApiRouter::new(Arc::new(fixture.gateway()));
    let ApiResponse::Action(receipt) = router
        .execute(
            &principal(fixture.tenant.clone()),
            ApiRequest::GetAction(ActionGetRequest {
                session_id: action.session_id().clone(),
                action_id: action.action_id().clone(),
            }),
        )
        .expect("durable pending response")
    else {
        panic!("action response")
    };
    assert_eq!(receipt.data().state(), ActionState::MayHaveExecuted);
    assert!(receipt.data().result_content().is_none());
    assert_eq!(fixture.stored(&action), action);
    assert_eq!(fixture.worker.mutations.load(Ordering::SeqCst), 0);
}

#[test]
fn worker_unknown_is_positive_terminal_evidence_but_query_failure_is_not() {
    let fixture = Fixture::new();
    let action = fixture.seed(fixture.placement(), None, Utc::now(), true);
    let mut receipts = fixture.worker.receipts.lock().expect("receipts");
    let receipt = receipts.get_mut(action.action_id()).expect("receipt");
    receipt.status = WorkerActionStatus::OutcomeUnknown;
    receipt.terminal_detail = Some(TerminalDetail::OutcomeUnknown(
        OutcomeUnknownReason::WorkerLost,
    ));
    receipt.result = None;
    drop(receipts);
    assert_eq!(
        fixture
            .gateway()
            .reconcile_pending_actions(7)
            .expect("pass"),
        1
    );
    assert_eq!(fixture.stored(&action).state(), ActionState::OutcomeUnknown);
}

#[test]
fn all_identity_protocol_and_unavailability_faults_preserve_pending() {
    for fault in [
        Fault::InspectWorker,
        Fault::InspectEpoch,
        Fault::InspectProtocol,
        Fault::InspectTimeout,
        Fault::InspectTenant,
        Fault::InspectSession,
        Fault::InspectPlacement,
        Fault::SessionFence,
        Fault::SessionNotFound,
        Fault::ActionNotFound,
        Fault::ActionTimeout,
        Fault::ActionFenceFailure,
        Fault::ReceiptTenant,
        Fault::ReceiptSession,
        Fault::ReceiptEpoch,
        Fault::ReceiptPlacement,
        Fault::ReceiptIncarnation,
        Fault::ReceiptAction,
        Fault::ReceiptSequence,
        Fault::ReceiptKey,
        Fault::ReceiptHash,
        Fault::ReceiptKind,
        Fault::ReceiptDigest,
    ] {
        let fixture = Fixture::new();
        let action = fixture.seed(fixture.placement(), None, Utc::now(), true);
        *fixture.worker.fault.lock().expect("fault") = fault;
        assert_eq!(
            fixture
                .gateway()
                .reconcile_pending_actions(256)
                .expect("pass"),
            0,
            "{fault:?}"
        );
        assert_eq!(fixture.stored(&action), action, "{fault:?}");
        assert_eq!(fixture.worker.mutations.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn foreign_durable_placement_never_contacts_configured_worker() {
    let fixture = Fixture::new();
    for (worker, epoch, version, revision) in [
        (WorkerId::new("foreign").expect("worker"), 3, 4, 6),
        (fixture.worker.id.clone(), 9, 4, 6),
        (fixture.worker.id.clone(), 3, 9, 6),
        (fixture.worker.id.clone(), 3, 4, 9),
    ] {
        let placement = GatewayActionPlacement::new(
            DirectoryFence::new(worker, epoch, version, 5).expect("fence"),
            revision,
        )
        .expect("placement");
        let action = fixture.seed(placement, None, Utc::now(), true);
        assert_eq!(
            fixture
                .gateway()
                .reconcile_pending_actions(256)
                .expect("pass"),
            0
        );
        assert_eq!(fixture.stored(&action), action);
    }
    assert!(fixture.worker.requests.lock().expect("requests").is_empty());
}

#[test]
fn expired_unattempted_lease_is_known_not_dispatched_without_querying_an_action() {
    let fixture = Fixture::new();
    let now = Utc::now() - chrono::Duration::minutes(2);
    let lease = GatewayActionSubmissionLease::new(
        Uuid::now_v7(),
        1,
        now + chrono::Duration::seconds(10),
        now + chrono::Duration::seconds(10),
    )
    .expect("lease");
    let action = fixture.seed(fixture.placement(), Some(lease), now, false);
    assert_eq!(
        fixture
            .gateway()
            .reconcile_pending_actions(256)
            .expect("pass"),
        1
    );
    let stored = fixture.stored(&action);
    assert_eq!(stored.state(), ActionState::FailedKnown);
    assert_eq!(
        stored.terminal().expect("terminal").detail(),
        TerminalDetail::FailedKnown(KnownFailureReason::NotDispatched)
    );
    assert!(matches!(
        stored.delivery(),
        ActionDeliveryEvidence::NotAttempted
    ));
    assert_eq!(
        *fixture.worker.requests.lock().expect("requests"),
        ["inspect"]
    );
}

#[test]
fn live_lease_and_legacy_unleased_claim_never_expire_by_age() {
    let fixture = Fixture::new();
    let now = Utc::now();
    let lease = GatewayActionSubmissionLease::new(
        Uuid::now_v7(),
        1,
        now + chrono::Duration::minutes(1),
        now + chrono::Duration::minutes(1),
    )
    .expect("lease");
    let live = fixture.seed(fixture.placement(), Some(lease), now, false);
    let legacy = fixture.seed(
        fixture.placement(),
        None,
        now - chrono::Duration::minutes(2),
        false,
    );
    assert_eq!(
        fixture
            .gateway()
            .reconcile_pending_actions(256)
            .expect("pass"),
        0
    );
    assert_eq!(fixture.stored(&live), live);
    assert_eq!(fixture.stored(&legacy), legacy);
    assert_eq!(
        *fixture.worker.requests.lock().expect("requests"),
        ["inspect", "inspect"]
    );
}

#[test]
fn bounded_page_cursor_eventually_visits_every_action_and_caps_all_worker_rpcs() {
    let fixture = Fixture::new();
    let actions: Vec<_> = (0..25)
        .map(|_| fixture.seed(fixture.placement(), None, Utc::now(), true))
        .collect();
    let gateway = fixture.gateway();
    let mut total = 0;
    for _ in 0..4 {
        fixture.worker.requests.lock().expect("requests").clear();
        total += gateway.reconcile_pending_actions(256).expect("pass");
        let calls = fixture.worker.requests.lock().expect("requests");
        assert!(calls.len() <= 14);
        assert!(!calls.contains(&"probe"));
        assert_eq!(
            calls.iter().filter(|call| **call == "inspect").count(),
            calls.iter().filter(|call| **call == "action").count()
        );
    }
    assert_eq!(total, 25);
    assert!(
        actions
            .iter()
            .all(|action| fixture.stored(action).state() == ActionState::Succeeded)
    );
    assert_eq!(
        gateway.reconcile_pending_actions(256).expect("empty pass"),
        0
    );
    assert_eq!(fixture.worker.mutations.load(Ordering::SeqCst), 0);
}

#[test]
fn concurrent_pass_returns_immediately_and_capacity_is_released_after_completion() {
    let fixture = Fixture::new();
    fixture.seed(fixture.placement(), None, Utc::now(), true);
    let gateway = Arc::new(fixture.gateway());
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    *fixture.worker.before_action.lock().expect("hook") = Some(Box::new(move || {
        entered_tx.send(()).expect("entered");
        release_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("release");
    }));
    let running = gateway.clone();
    let pass = std::thread::spawn(move || running.reconcile_pending_actions(256));
    entered_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("entered pass");
    assert_eq!(gateway.reconcile_pending_actions(256).expect("overlap"), 0);
    assert_eq!(fixture.worker.requests.lock().expect("requests").len(), 2);
    release_tx.send(()).expect("release pass");
    assert_eq!(pass.join().expect("join").expect("pass"), 1);
    assert_eq!(
        gateway.reconcile_pending_actions(256).expect("next pass"),
        0
    );
}

#[test]
fn concurrent_exposure_revision_preserves_positive_worker_completion() {
    let fixture = Fixture::new();
    let action = fixture.seed(fixture.placement(), None, Utc::now(), true);
    let client = GatewayActionBlockingClient::spawn(
        fixture.store.clone(),
        CoordinationActorConfig::default(),
    )
    .expect("client");
    let original = action.clone();
    *fixture.worker.before_action.lock().expect("hook") = Some(Box::new(move || {
        let ActionDeliveryEvidence::DispatchArmed(dispatch) = original.delivery() else {
            panic!("armed")
        };
        client
            .mark_exposure_possible(
                original.tenant_id(),
                original.session_id(),
                original.action_id(),
                original.revision(),
                original.placement(),
                dispatch,
                Utc::now(),
            )
            .expect("concurrent exposure");
    }));
    assert_eq!(
        fixture
            .gateway()
            .reconcile_pending_actions(256)
            .expect("pass"),
        1
    );
    assert_eq!(fixture.stored(&action).state(), ActionState::Succeeded);
    assert_eq!(fixture.stored(&action).result_content(), Some(BODY));
}

#[test]
fn two_gateways_query_the_same_worker_and_converge_without_a_recovery_lease() {
    let fixture = Fixture::new();
    let action = fixture.seed(fixture.placement(), None, Utc::now(), true);
    let first = fixture.gateway();
    let second = fixture.gateway();
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    *fixture.worker.before_action.lock().expect("hook") = Some(Box::new(move || {
        entered_tx.send(()).expect("entered");
        release_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("release");
    }));
    let first_pass = std::thread::spawn(move || first.reconcile_pending_actions(256));
    entered_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("first query");
    assert_eq!(second.reconcile_pending_actions(256).expect("second"), 1);
    release_tx.send(()).expect("release first");
    assert_eq!(first_pass.join().expect("join").expect("first"), 1);
    assert_eq!(fixture.stored(&action).state(), ActionState::Succeeded);
    assert_eq!(fixture.stored(&action).result_content(), Some(BODY));
    assert_eq!(fixture.worker.requests.lock().expect("requests").len(), 4);
    assert_eq!(fixture.worker.mutations.load(Ordering::SeqCst), 0);
}

#[test]
fn concurrent_durable_terminal_winner_is_never_overwritten_by_late_success() {
    let fixture = Fixture::new();
    let action = fixture.seed(fixture.placement(), None, Utc::now(), true);
    let client = GatewayActionBlockingClient::spawn(
        fixture.store.clone(),
        CoordinationActorConfig::default(),
    )
    .expect("client");
    let original = action.clone();
    *fixture.worker.before_action.lock().expect("hook") = Some(Box::new(move || {
        let ActionDeliveryEvidence::DispatchArmed(dispatch) = original.delivery() else {
            panic!("armed")
        };
        client
            .record_transport_loss(
                original.tenant_id(),
                original.session_id(),
                original.action_id(),
                original.revision(),
                original.placement(),
                dispatch,
                browserd_actions::TransportLoss::Ambiguous(
                    OutcomeUnknownReason::AmbiguousTransportLoss,
                ),
                Utc::now(),
            )
            .expect("concurrent terminal");
    }));
    assert_eq!(
        fixture
            .gateway()
            .reconcile_pending_actions(256)
            .expect("pass"),
        1
    );
    let stored = fixture.stored(&action);
    assert_eq!(stored.state(), ActionState::OutcomeUnknown);
    assert!(stored.result_content().is_none());
    assert_eq!(
        stored.terminal().expect("terminal").detail(),
        TerminalDetail::OutcomeUnknown(OutcomeUnknownReason::AmbiguousTransportLoss)
    );
}

#[test]
fn recovery_limits_and_other_tenant_reads_do_not_touch_worker() {
    let fixture = Fixture::new();
    let action = fixture.seed(fixture.placement(), None, Utc::now(), true);
    let gateway = fixture.gateway();
    assert!(gateway.reconcile_pending_actions(0).is_err());
    assert!(gateway.reconcile_pending_actions(257).is_err());
    let router = ApiRouter::new(Arc::new(gateway));
    assert!(
        router
            .execute(
                &principal(TenantId::new()),
                ApiRequest::GetAction(ActionGetRequest {
                    session_id: action.session_id().clone(),
                    action_id: action.action_id().clone(),
                })
            )
            .is_err()
    );
    assert_eq!(fixture.stored(&action), action);
    assert!(fixture.worker.requests.lock().expect("requests").is_empty());
}

#[test]
fn failed_unready_worker_supplies_positive_loss_proof_without_a_readiness_probe() {
    let fixture = Fixture::new();
    let action = fixture.seed(fixture.placement(), None, Utc::now(), true);
    fixture.worker.ready.store(false, Ordering::Release);
    *fixture.worker.lifecycle.lock().expect("lifecycle") = WorkerSessionLifecycle::Failed;
    *fixture.worker.fault.lock().expect("fault") = Fault::ActionNotFound;
    assert_eq!(
        fixture
            .gateway()
            .reconcile_pending_actions(7)
            .expect("pass"),
        1
    );
    assert_eq!(
        fixture
            .stored(&action)
            .terminal()
            .expect("terminal")
            .detail(),
        TerminalDetail::OutcomeUnknown(OutcomeUnknownReason::WorkerLost)
    );
    assert_eq!(
        *fixture.worker.requests.lock().expect("requests"),
        ["inspect", "action"]
    );
    assert_eq!(fixture.worker.mutations.load(Ordering::Acquire), 0);
}

#[test]
fn terminal_session_proof_derives_loss_when_the_action_is_absent_unreadable_or_corrupt() {
    for lifecycle in [
        WorkerSessionLifecycle::Closed,
        WorkerSessionLifecycle::Failed,
    ] {
        for fault in [
            Fault::ActionNotFound,
            Fault::ActionTimeout,
            Fault::ReceiptHash,
            Fault::ReceiptDigest,
        ] {
            let fixture = Fixture::new();
            let action = fixture.seed(fixture.placement(), None, Utc::now(), true);
            *fixture.worker.lifecycle.lock().expect("lifecycle") = lifecycle;
            *fixture.worker.fault.lock().expect("fault") = fault;
            let router = ApiRouter::new(Arc::new(fixture.gateway()));
            let user = principal(fixture.tenant.clone());
            let ApiResponse::Action(receipt) = router
                .execute(
                    &user,
                    ApiRequest::GetAction(ActionGetRequest {
                        session_id: action.session_id().clone(),
                        action_id: action.action_id().clone(),
                    }),
                )
                .expect("loss receipt")
            else {
                panic!("action response")
            };
            assert_eq!(
                receipt.data().terminal_detail(),
                Some(TerminalDetail::OutcomeUnknown(
                    OutcomeUnknownReason::WorkerLost
                )),
                "{lifecycle:?}/{fault:?}"
            );
            assert_eq!(fixture.stored(&action).state(), ActionState::OutcomeUnknown);
            assert_eq!(
                router
                    .execute(&user, ApiRequest::GetSession(action.session_id().clone()))
                    .expect_err("no session hydration")
                    .code(),
                ErrorCode::SessionNotFound
            );
            assert_eq!(
                *fixture.worker.requests.lock().expect("requests"),
                ["inspect", "action"]
            );
            assert_eq!(fixture.worker.mutations.load(Ordering::Acquire), 0);
        }
    }
}

#[test]
fn available_success_is_committed_before_the_terminal_session_loss_fence() {
    let fixture = Fixture::new();
    let action = fixture.seed(fixture.placement(), None, Utc::now(), true);
    *fixture.worker.lifecycle.lock().expect("lifecycle") = WorkerSessionLifecycle::Closed;
    assert_eq!(
        fixture
            .gateway()
            .reconcile_pending_actions(7)
            .expect("pass"),
        1
    );
    let stored = fixture.stored(&action);
    assert_eq!(stored.state(), ActionState::Succeeded);
    assert_eq!(stored.result_content(), Some(BODY));
    fixture.executor.block_on(async {
        let first = fixture
            .store
            .peek_event_projection(action.tenant_id(), action.session_id())
            .await
            .expect("first projection")
            .expect("success");
        assert_eq!(first.append().kind(), OutboxEventKind::ActionTerminal);
        fixture
            .store
            .ack_event_projection(&first)
            .await
            .expect("ack success");
        let second = fixture
            .store
            .peek_event_projection(action.tenant_id(), action.session_id())
            .await
            .expect("second projection")
            .expect("loss");
        assert_eq!(second.append().kind(), OutboxEventKind::SessionLost);
        fixture
            .store
            .ack_event_projection(&second)
            .await
            .expect("ack loss");
        assert!(
            fixture
                .store
                .peek_event_projection(action.tenant_id(), action.session_id())
                .await
                .expect("no duplicate")
                .is_none()
        );
        let new_action = ClaimGatewayAction::new(
            action.tenant_id().clone(),
            action.session_id().clone(),
            ActionId::new(),
            "after-positive-close",
            CanonicalRequestHash::new([3; 32]),
            ActionKind::ReadOnly,
            action.placement().clone(),
        )
        .expect("claim");
        assert!(matches!(
            fixture.store.claim_action(new_action, Utc::now()).await,
            Err(GatewayActionCoordinationError::SessionLost)
        ));
    });
    assert_eq!(fixture.stored(&action), stored);
}

#[test]
fn terminal_session_proof_settles_not_attempted_claims_without_querying_or_replaying_them() {
    for leased in [false, true] {
        let fixture = Fixture::new();
        let now = Utc::now();
        let lease = leased.then(|| {
            GatewayActionSubmissionLease::new(
                Uuid::now_v7(),
                1,
                now + chrono::Duration::minutes(1),
                now + chrono::Duration::minutes(1),
            )
            .expect("live lease")
        });
        let action = fixture.seed(fixture.placement(), lease, now, false);
        *fixture.worker.lifecycle.lock().expect("lifecycle") = WorkerSessionLifecycle::Closed;
        let router = ApiRouter::new(Arc::new(fixture.gateway()));
        let ApiResponse::Action(receipt) = router
            .execute(
                &principal(fixture.tenant.clone()),
                ApiRequest::GetAction(ActionGetRequest {
                    session_id: action.session_id().clone(),
                    action_id: action.action_id().clone(),
                }),
            )
            .expect("known non-delivery")
        else {
            panic!("action response")
        };
        assert_eq!(
            receipt.data().terminal_detail(),
            Some(TerminalDetail::FailedKnown(
                KnownFailureReason::NotDispatched
            ))
        );
        let stored = fixture.stored(&action);
        assert_eq!(
            stored.terminal().expect("terminal").source(),
            browserd_actions::ActionTerminalSource::WorkerLoss
        );
        assert!(matches!(
            stored.delivery(),
            ActionDeliveryEvidence::NotAttempted
        ));
        assert_eq!(
            *fixture.worker.requests.lock().expect("requests"),
            ["inspect"]
        );
        assert_eq!(fixture.worker.mutations.load(Ordering::Acquire), 0);
    }
}

#[test]
fn terminal_proof_replaces_a_nonterminal_worker_receipt_with_loss_evidence() {
    let fixture = Fixture::new();
    let action = fixture.seed(fixture.placement(), None, Utc::now(), true);
    *fixture.worker.lifecycle.lock().expect("lifecycle") = WorkerSessionLifecycle::Failed;
    {
        let mut receipts = fixture.worker.receipts.lock().expect("receipts");
        let receipt = receipts.get_mut(action.action_id()).expect("receipt");
        receipt.status = WorkerActionStatus::Queued;
        receipt.dispatch_acknowledged = false;
        receipt.terminal_detail = None;
        receipt.result = None;
    }
    assert_eq!(
        fixture
            .gateway()
            .reconcile_pending_actions(7)
            .expect("pass"),
        1
    );
    assert_eq!(
        fixture
            .stored(&action)
            .terminal()
            .expect("terminal")
            .detail(),
        TerminalDetail::OutcomeUnknown(OutcomeUnknownReason::WorkerLost)
    );
}

#[test]
fn a_terminal_lifecycle_never_overrides_an_invalid_or_missing_ownership_inspection() {
    for fault in [
        Fault::InspectWorker,
        Fault::InspectEpoch,
        Fault::InspectProtocol,
        Fault::InspectTimeout,
        Fault::InspectTenant,
        Fault::InspectSession,
        Fault::InspectPlacement,
        Fault::SessionFence,
        Fault::SessionNotFound,
    ] {
        let fixture = Fixture::new();
        let action = fixture.seed(fixture.placement(), None, Utc::now(), true);
        *fixture.worker.lifecycle.lock().expect("lifecycle") = WorkerSessionLifecycle::Failed;
        *fixture.worker.fault.lock().expect("fault") = fault;
        assert_eq!(
            fixture
                .gateway()
                .reconcile_pending_actions(7)
                .expect("pass"),
            0,
            "{fault:?}"
        );
        assert_eq!(fixture.stored(&action), action, "{fault:?}");
        assert_eq!(
            *fixture.worker.requests.lock().expect("requests"),
            ["inspect"]
        );
    }
}

#[test]
fn nonterminal_session_lifecycle_and_missing_action_never_imply_loss() {
    for lifecycle in [
        WorkerSessionLifecycle::Creating,
        WorkerSessionLifecycle::Ready,
        WorkerSessionLifecycle::Closing,
    ] {
        let fixture = Fixture::new();
        let action = fixture.seed(fixture.placement(), None, Utc::now(), true);
        *fixture.worker.lifecycle.lock().expect("lifecycle") = lifecycle;
        *fixture.worker.fault.lock().expect("fault") = Fault::ActionNotFound;
        assert_eq!(
            fixture
                .gateway()
                .reconcile_pending_actions(7)
                .expect("pass"),
            0
        );
        assert_eq!(fixture.stored(&action), action);
        assert_eq!(
            *fixture.worker.requests.lock().expect("requests"),
            ["inspect", "action"]
        );
    }
}
