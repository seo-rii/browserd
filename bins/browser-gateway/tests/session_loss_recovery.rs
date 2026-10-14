#![allow(clippy::expect_used, clippy::panic, clippy::too_many_arguments)]

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use async_trait::async_trait;
use browser_gateway::{
    GatewayWorkerClient, GatewayWorkerPending, GatewayWorkerPlacement, GatewayWorkerRuntime,
};
use browserd_actions::{
    ActionKind, ActionSequence, BrowserResult, CanonicalRequestHash, DispatchId,
    KnownFailureReason, OutcomeUnknownReason, ResolutionAnnotation, TerminalDetail, TransportLoss,
};
use browserd_api::{
    ActionPayload, ActionSubmitCommand, ActionSubmitRequest, ApiRequest, ApiResponse, ApiRouter,
    ApiService, decode_session_create,
};
use browserd_auth::{
    AuthConfig, AuthenticatedPrincipal, RevocationRegistry, ServiceClaims, ServiceTokenSigner,
    ServiceTokenVerifier, VerificationKeySet,
};
use browserd_coordination::{
    ClaimGatewayAction, CoordinationActorConfig, DirectoryFence, EventCursor, EventOutbox,
    EventOutboxBlockingClient, EventOutboxError, GatewayActionClaimOutcome,
    GatewayActionCoordination, GatewayActionCoordinationError, GatewayActionPlacement,
    GatewayActionRecoveryCursor, GatewayActionSnapshot, GatewayEventProjection,
    GatewayEventScanCursor, GatewayEventScanPage, MemoryEventOutbox, MemoryGatewayActionStore,
    OutboxAppend, OutboxEvent, OutboxEventKind, OutboxPage, SessionLossClaim, SessionLossOutcome,
    SessionLossReceipt,
};
use browserd_core::{
    ActionId, ErrorCode, PageId, PrincipalId, SessionId, SessionLifecycle, TenantId, WorkerId,
};
use browserd_worker::{
    WorkerCreateSessionReceipt, WorkerCreateSessionRequest, WorkerIsolationProfile,
    WorkerRpcCompletionError, WorkerRpcEnqueueError, WorkerRpcError, WorkerRpcFailure,
    WorkerRpcFailureCode, WorkerRpcRequest, WorkerRpcResponse, WorkerSessionFence,
    WorkerSessionLifecycle, WorkerSessionOwnershipReceipt, WorkerSessionReceipt,
};
use chrono::{DateTime, Utc};
use jsonwebtoken::Algorithm;
use uuid::Uuid;

const CREATE_JSON: &str = r#"{"isolation":"shared_context","workload_class_hint":"interactive","viewport":{"width":1280,"height":720,"device_scale_factor":1},"locale":"ko-KR","timezone":"Asia/Seoul","user_agent":null,"network_policy_id":"public-web-default","network_class":"public","checkpoint_ref":null,"dialog_policy":"auto_dismiss","feature_profile":"standard","ttl_seconds":1800,"idle_timeout_seconds":600,"metadata":{}}"#;

#[derive(Clone, Copy, Debug)]
enum ReadMode {
    Lifecycle(WorkerSessionLifecycle),
    Timeout,
    NotFound,
}
#[derive(Clone, Copy, Debug)]
enum InspectFault {
    None,
    Worker,
    Tenant,
    Session,
    Epoch,
    Placement,
    Incarnation,
    Lifecycle,
    NotFound,
    Timeout,
}

struct NeverPending;
impl GatewayWorkerPending for NeverPending {
    fn wait(self) -> Result<WorkerRpcResponse, WorkerRpcCompletionError> {
        panic!("closed admission must not wait for a new effect")
    }
}

struct Worker {
    id: WorkerId,
    session: SessionId,
    page: PageId,
    created: Mutex<Option<WorkerCreateSessionRequest>>,
    mode: Mutex<ReadMode>,
    inspect_fault: Mutex<InspectFault>,
    inspected: AtomicUsize,
    closed: AtomicUsize,
    enqueued: AtomicUsize,
}
impl Worker {
    fn receipt(&self, fence: WorkerSessionFence) -> Result<WorkerSessionReceipt, WorkerRpcError> {
        match *self.mode.lock().expect("mode") {
            ReadMode::Timeout => Err(WorkerRpcError::Timeout),
            ReadMode::NotFound => Err(WorkerRpcError::Remote(WorkerRpcFailure::new(
                WorkerRpcFailureCode::NotFound,
                "not retained",
            ))),
            ReadMode::Lifecycle(lifecycle) => Ok(WorkerSessionReceipt {
                fence,
                lifecycle,
                primary_page_id: self.page.clone(),
            }),
        }
    }
}
impl GatewayWorkerClient for Worker {
    type PendingAction = NeverPending;
    fn create_session(
        &self,
        request: WorkerCreateSessionRequest,
    ) -> Result<WorkerCreateSessionReceipt, WorkerRpcError> {
        *self.created.lock().expect("created") = Some(request.clone());
        Ok(WorkerCreateSessionReceipt {
            operation_id: request.operation_id,
            tenant_id: request.tenant_id,
            session_id: self.session.clone(),
            session_incarnation: request.session_incarnation,
            effective_isolation: WorkerIsolationProfile::SharedContext,
            primary_page_id: self.page.clone(),
            worker_epoch: request.expected_worker_epoch,
            placement_version: request.placement_version,
            existing: false,
            restored_checkpoint: None,
        })
    }
    fn request(&self, request: WorkerRpcRequest) -> Result<WorkerRpcResponse, WorkerRpcError> {
        match request {
            WorkerRpcRequest::GetSession { fence } => {
                self.receipt(fence).map(WorkerRpcResponse::Session)
            }
            WorkerRpcRequest::CloseSession { fence, .. } => {
                self.closed.fetch_add(1, Ordering::SeqCst);
                self.receipt(fence).map(WorkerRpcResponse::SessionClosed)
            }
            WorkerRpcRequest::InspectSession {
                expected_worker_id,
                fence,
            } => {
                self.inspected.fetch_add(1, Ordering::SeqCst);
                assert_eq!(expected_worker_id, self.id);
                let mut receipt = self.receipt(fence)?;
                let mut worker_id = self.id.clone();
                match *self.inspect_fault.lock().expect("inspect fault") {
                    InspectFault::None => {}
                    InspectFault::Worker => {
                        worker_id = WorkerId::new("foreign-worker").expect("id")
                    }
                    InspectFault::Tenant => receipt.fence.tenant_id = TenantId::new(),
                    InspectFault::Session => receipt.fence.session_id = SessionId::new(),
                    InspectFault::Epoch => receipt.fence.worker_epoch += 1,
                    InspectFault::Placement => receipt.fence.placement_version += 1,
                    InspectFault::Incarnation => receipt.fence.session_incarnation += 1,
                    InspectFault::Lifecycle => receipt.lifecycle = WorkerSessionLifecycle::Ready,
                    InspectFault::NotFound => {
                        return Ok(WorkerRpcResponse::Failure(WorkerRpcFailure::new(
                            WorkerRpcFailureCode::NotFound,
                            "unavailable",
                        )));
                    }
                    InspectFault::Timeout => return Err(WorkerRpcError::Timeout),
                }
                Ok(WorkerRpcResponse::SessionOwnership(
                    WorkerSessionOwnershipReceipt {
                        worker_id,
                        session: receipt,
                    },
                ))
            }
            _ => panic!(
                "session loss recovery must not infer loss from a probe or issue action RPCs"
            ),
        }
    }
    fn enqueue_action(
        &self,
        request: WorkerRpcRequest,
    ) -> Result<Self::PendingAction, WorkerRpcEnqueueError> {
        self.enqueued.fetch_add(1, Ordering::SeqCst);
        Err(WorkerRpcEnqueueError::Closed(Box::new(request)))
    }
}

#[derive(Default)]
struct FaultStore {
    inner: MemoryGatewayActionStore,
    claim_calls: AtomicUsize,
    lose_ensure_reply: AtomicBool,
    proposals: Mutex<Vec<Uuid>>,
    committed: Mutex<Vec<SessionLossClaim>>,
    materialize_limits: Mutex<Vec<usize>>,
}

#[async_trait]
impl GatewayActionCoordination for FaultStore {
    async fn claim_action(
        &self,
        claim: ClaimGatewayAction,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionClaimOutcome, GatewayActionCoordinationError> {
        self.claim_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.claim_action(claim, now).await
    }
    async fn get_effective_action(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
    ) -> Result<Option<GatewayActionSnapshot>, GatewayActionCoordinationError> {
        self.inner
            .get_effective_action(tenant_id, session_id, action_id)
            .await
    }
    async fn arm_dispatch(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        dispatch_id: DispatchId,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        self.inner
            .arm_dispatch(
                tenant_id,
                session_id,
                action_id,
                expected_revision,
                placement,
                dispatch_id,
                now,
            )
            .await
    }
    async fn mark_exposure_possible(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        dispatch_id: &DispatchId,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        self.inner
            .mark_exposure_possible(
                tenant_id,
                session_id,
                action_id,
                expected_revision,
                placement,
                dispatch_id,
                now,
            )
            .await
    }
    async fn record_worker_result(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        dispatch_id: &DispatchId,
        action_sequence: ActionSequence,
        result: BrowserResult,
        result_body: Option<Vec<u8>>,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        self.inner
            .record_worker_result(
                tenant_id,
                session_id,
                action_id,
                expected_revision,
                placement,
                dispatch_id,
                action_sequence,
                result,
                result_body,
                now,
            )
            .await
    }

    async fn record_worker_result_with_custody(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        dispatch_id: &DispatchId,
        action_sequence: ActionSequence,
        result: BrowserResult,
        result_body: Option<Vec<u8>>,
        custody: Option<browserd_actions::TerminalCustodyReceipt>,
        custody_requirement: Option<browserd_actions::TerminalCustodyRequirement>,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        self.inner
            .record_worker_result_with_custody(
                tenant_id,
                session_id,
                action_id,
                expected_revision,
                placement,
                dispatch_id,
                action_sequence,
                result,
                result_body,
                custody,
                custody_requirement,
                now,
            )
            .await
    }
    async fn record_worker_terminal(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        dispatch_id: &DispatchId,
        action_sequence: ActionSequence,
        detail: TerminalDetail,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        self.inner
            .record_worker_terminal(
                tenant_id,
                session_id,
                action_id,
                expected_revision,
                placement,
                dispatch_id,
                action_sequence,
                detail,
                now,
            )
            .await
    }

    async fn record_worker_terminal_with_custody(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        dispatch_id: &DispatchId,
        action_sequence: ActionSequence,
        detail: TerminalDetail,
        custody: Option<browserd_actions::TerminalCustodyReceipt>,
        custody_requirement: Option<browserd_actions::TerminalCustodyRequirement>,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        self.inner
            .record_worker_terminal_with_custody(
                tenant_id,
                session_id,
                action_id,
                expected_revision,
                placement,
                dispatch_id,
                action_sequence,
                detail,
                custody,
                custody_requirement,
                now,
            )
            .await
    }
    async fn record_transport_loss(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        dispatch_id: &DispatchId,
        loss: TransportLoss,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        self.inner
            .record_transport_loss(
                tenant_id,
                session_id,
                action_id,
                expected_revision,
                placement,
                dispatch_id,
                loss,
                now,
            )
            .await
    }
    async fn cancel_before_dispatch(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        self.inner
            .cancel_before_dispatch(
                tenant_id,
                session_id,
                action_id,
                expected_revision,
                placement,
                now,
            )
            .await
    }
    async fn resolve_unknown(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        annotation: ResolutionAnnotation,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        self.inner
            .resolve_unknown(
                tenant_id,
                session_id,
                action_id,
                expected_revision,
                placement,
                annotation,
                now,
            )
            .await
    }

    async fn resolve_unknown_with_custody(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        annotation: ResolutionAnnotation,
        custody: Option<browserd_actions::TerminalCustodyReceipt>,
        custody_requirement: Option<browserd_actions::TerminalCustodyRequirement>,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        self.inner
            .resolve_unknown_with_custody(
                tenant_id,
                session_id,
                action_id,
                expected_revision,
                placement,
                annotation,
                custody,
                custody_requirement,
                now,
            )
            .await
    }
    async fn mark_session_lost(
        &self,
        claim: &SessionLossClaim,
        now: DateTime<Utc>,
    ) -> Result<SessionLossOutcome, GatewayActionCoordinationError> {
        self.inner.mark_session_lost(claim, now).await
    }
    async fn materialize_session_loss(
        &self,
        claim: &SessionLossClaim,
        limit: usize,
        now: DateTime<Utc>,
    ) -> Result<usize, GatewayActionCoordinationError> {
        self.materialize_limits.lock().expect("limits").push(limit);
        self.inner.materialize_session_loss(claim, limit, now).await
    }
    async fn scan_event_sessions(
        &self,
        cursor: GatewayEventScanCursor,
        limit: usize,
    ) -> Result<GatewayEventScanPage, GatewayActionCoordinationError> {
        self.inner.scan_event_sessions(cursor, limit).await
    }
    async fn peek_event_projection(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
    ) -> Result<Option<GatewayEventProjection>, GatewayActionCoordinationError> {
        self.inner
            .peek_event_projection(tenant_id, session_id)
            .await
    }
    async fn ack_event_projection(
        &self,
        projection: &GatewayEventProjection,
    ) -> Result<(), GatewayActionCoordinationError> {
        self.inner.ack_event_projection(projection).await
    }
    async fn ensure_session_lost(
        &self,
        proposed: &SessionLossClaim,
        now: DateTime<Utc>,
    ) -> Result<SessionLossReceipt, GatewayActionCoordinationError> {
        self.proposals
            .lock()
            .expect("proposals")
            .push(*proposed.loss_id());
        let receipt = self.inner.ensure_session_lost(proposed, now).await?;
        self.committed
            .lock()
            .expect("commits")
            .push(receipt.claim().clone());
        if self.lose_ensure_reply.swap(false, Ordering::SeqCst) {
            return Err(GatewayActionCoordinationError::ActorMutationTimedOut);
        }
        Ok(receipt)
    }
}

#[derive(Default)]
struct FaultSink {
    inner: MemoryEventOutbox,
    unavailable: AtomicBool,
}
#[async_trait]
impl EventOutbox for FaultSink {
    async fn append(
        &self,
        event: OutboxAppend,
        now: DateTime<Utc>,
    ) -> Result<OutboxEvent, EventOutboxError> {
        self.inner.append(event, now).await
    }
    async fn append_projection(
        &self,
        projection: GatewayEventProjection,
        now: DateTime<Utc>,
    ) -> Result<(), EventOutboxError> {
        if self.unavailable.load(Ordering::SeqCst) {
            return Err(EventOutboxError::PostgresUnavailable);
        }
        self.inner.append_projection(projection, now).await
    }
    async fn read_from(
        &self,
        tenant: &TenantId,
        after: EventCursor,
        limit: usize,
        now: DateTime<Utc>,
    ) -> Result<OutboxPage, EventOutboxError> {
        self.inner.read_from(tenant, after, limit, now).await
    }
    async fn read_after_event_id(
        &self,
        tenant: &TenantId,
        after: Option<Uuid>,
        limit: usize,
        now: DateTime<Utc>,
    ) -> Result<OutboxPage, EventOutboxError> {
        self.inner
            .read_after_event_id(tenant, after, limit, now)
            .await
    }
    async fn mark_delivered(
        &self,
        tenant: &TenantId,
        cursor: EventCursor,
    ) -> Result<(), EventOutboxError> {
        self.inner.mark_delivered(tenant, cursor).await
    }
    async fn delivered_cursor(&self, tenant: &TenantId) -> Result<EventCursor, EventOutboxError> {
        self.inner.delivered_cursor(tenant).await
    }
}

struct Fixture {
    executor: tokio::runtime::Runtime,
    store: Arc<FaultStore>,
    sink: Arc<FaultSink>,
    worker: Arc<Worker>,
    gateway: Arc<GatewayWorkerRuntime<Worker>>,
    router: ApiRouter<GatewayWorkerRuntime<Worker>>,
    principal: AuthenticatedPrincipal,
}
impl Fixture {
    fn new() -> Self {
        let tenant = TenantId::new();
        let secret = [31_u8; 32];
        let mut keys = VerificationKeySet::new();
        keys.insert_hmac("loss-tests", Algorithm::HS256, &secret)
            .expect("test key");
        let verifier = ServiceTokenVerifier::new(
            AuthConfig::new("issuer", "audience", [Algorithm::HS256], 0, false),
            keys,
            RevocationRegistry::new(),
        );
        let signer = ServiceTokenSigner::new("loss-tests", Algorithm::HS256, &secret);
        let token = signer
            .sign(&ServiceClaims::new(
                "issuer",
                "audience",
                PrincipalId::new(),
                tenant,
                BTreeSet::from([
                    "session:create".to_owned(),
                    "session:read".to_owned(),
                    "session:close".to_owned(),
                    "browser:act".to_owned(),
                ]),
                "session-loss-test",
                1,
                100,
                None,
            ))
            .expect("sign");
        let principal = verifier.verify_at(&token, None, 10).expect("principal");
        let worker = Arc::new(Worker {
            id: WorkerId::new("session-loss-worker").expect("worker"),
            session: SessionId::new(),
            page: PageId::new(),
            created: Mutex::new(None),
            mode: Mutex::new(ReadMode::Lifecycle(WorkerSessionLifecycle::Ready)),
            inspect_fault: Mutex::new(InspectFault::None),
            inspected: AtomicUsize::new(0),
            closed: AtomicUsize::new(0),
            enqueued: AtomicUsize::new(0),
        });
        let store = Arc::new(FaultStore::default());
        let sink = Arc::new(FaultSink::default());
        let outbox: Arc<dyn EventOutbox> = sink.clone();
        let gateway = Arc::new(
            GatewayWorkerRuntime::with_action_coordination(
                worker.clone(),
                GatewayWorkerPlacement::new(worker.id.clone(), 41, 7, 11).expect("placement"),
                store.clone(),
                CoordinationActorConfig::default(),
            )
            .expect("gateway")
            .with_terminal_event_outbox(
                EventOutboxBlockingClient::spawn(outbox, 2).expect("outbox actor"),
            ),
        );
        let router = ApiRouter::new(gateway.clone());
        let created = router
            .execute(
                &principal,
                ApiRequest::CreateSession {
                    body: decode_session_create(CREATE_JSON).expect("create options"),
                    idempotency_key: Uuid::new_v4().to_string(),
                    received_at: Instant::now(),
                },
            )
            .expect("public create");
        let ApiResponse::SessionCreate(created) = created else {
            panic!("create receipt");
        };
        let resource = created
            .data()
            .operation()
            .session()
            .expect("created session");
        assert_eq!(resource.id, worker.session);
        assert_eq!(resource.lifecycle, SessionLifecycle::Ready);
        Self {
            executor: tokio::runtime::Runtime::new().expect("runtime"),
            store,
            sink,
            worker,
            gateway,
            router,
            principal,
        }
    }
    fn placement(&self) -> GatewayActionPlacement {
        let guard = self.worker.created.lock().expect("create request");
        let request = guard.as_ref().expect("created");
        GatewayActionPlacement::new(
            DirectoryFence::new(
                self.worker.id.clone(),
                request.expected_worker_epoch,
                request.placement_version,
                request.session_incarnation,
            )
            .expect("fence"),
            11,
        )
        .expect("placement")
    }
    fn mode(&self, mode: ReadMode) {
        *self.worker.mode.lock().expect("mode") = mode;
    }
    fn get(&self) -> Result<ApiResponse, browserd_api::ApiError> {
        self.router.execute(
            &self.principal,
            ApiRequest::GetSession(self.worker.session.clone()),
        )
    }
    fn close(&self) -> Result<ApiResponse, browserd_api::ApiError> {
        self.router.execute(
            &self.principal,
            ApiRequest::DeleteSession(self.worker.session.clone()),
        )
    }
    fn seed(&self, key: &str, armed: bool, terminal: bool) -> GatewayActionSnapshot {
        self.executor.block_on(async {
            let claim = ClaimGatewayAction::new(
                self.principal.tenant_id().clone(),
                self.worker.session.clone(),
                ActionId::new(),
                key,
                CanonicalRequestHash::new([key.as_bytes()[0]; 32]),
                ActionKind::Mutating,
                self.placement(),
            )
            .expect("claim");
            let mut row = self
                .store
                .inner
                .claim_action(claim, Utc::now())
                .await
                .expect("durable claim")
                .into_snapshot();
            if armed {
                row = self
                    .store
                    .inner
                    .arm_dispatch(
                        row.tenant_id(),
                        row.session_id(),
                        row.action_id(),
                        row.revision(),
                        row.placement(),
                        DispatchId::new(),
                        Utc::now(),
                    )
                    .await
                    .expect("armed");
            }
            if terminal {
                row = self
                    .store
                    .inner
                    .cancel_before_dispatch(
                        row.tenant_id(),
                        row.session_id(),
                        row.action_id(),
                        row.revision(),
                        row.placement(),
                        Utc::now(),
                    )
                    .await
                    .expect("terminal winner");
            }
            row
        })
    }
    fn row(&self, original: &GatewayActionSnapshot) -> GatewayActionSnapshot {
        self.executor
            .block_on(self.store.inner.get_effective_action(
                original.tenant_id(),
                original.session_id(),
                original.action_id(),
            ))
            .expect("read")
            .expect("preserved identity")
    }
    fn events(&self) -> OutboxPage {
        self.executor
            .block_on(self.sink.read_from(
                self.principal.tenant_id(),
                EventCursor::start(),
                64,
                Utc::now(),
            ))
            .expect("sink events")
    }
    fn drain(&self) {
        for _ in 0..16 {
            self.gateway
                .reconcile_terminal_events(1)
                .expect("bounded reconciliation");
        }
        assert!(
            self.executor
                .block_on(
                    self.store
                        .inner
                        .peek_event_projection(self.principal.tenant_id(), &self.worker.session)
                )
                .expect("source peek")
                .is_none()
        );
        assert!(
            self.executor
                .block_on(
                    self.store
                        .inner
                        .scan_pending_actions(GatewayActionRecoveryCursor::default(), 256)
                )
                .expect("pending scan")
                .actions()
                .is_empty()
        );
        assert!(
            self.store
                .materialize_limits
                .lock()
                .expect("limits")
                .iter()
                .all(|limit| *limit == 1)
        );
    }
    fn assert_admission_closed(&self) {
        let incarnation = self
            .worker
            .created
            .lock()
            .expect("created")
            .as_ref()
            .expect("request")
            .session_incarnation;
        let result = self.router.execute(
            &self.principal,
            ApiRequest::SubmitAction(ActionSubmitCommand {
                session_id: self.worker.session.clone(),
                idempotency_key: Uuid::new_v4(),
                body: ActionSubmitRequest {
                    page_id: self.worker.page.clone(),
                    if_session_incarnation: incarnation,
                    execution_timeout_ms: 1000,
                    action: ActionPayload::GetTitle,
                },
            }),
        );
        assert_eq!(
            result.expect_err("closed admission").code(),
            ErrorCode::SessionNotFound
        );
        assert_eq!(self.store.claim_calls.load(Ordering::SeqCst), 0);
        assert_eq!(self.worker.enqueued.load(Ordering::SeqCst), 0);
    }
}

fn lifecycle(response: ApiResponse) -> SessionLifecycle {
    match response {
        ApiResponse::Session(value) | ApiResponse::SessionClosed(value) => value.data().lifecycle,
        _ => panic!("session resource expected"),
    }
}

#[test]
fn confirmed_closed_and_failed_sessions_classify_pending_work_and_preserve_terminal_winner() {
    for (worker_lifecycle, expected) in [
        (WorkerSessionLifecycle::Closed, SessionLifecycle::Closed),
        (WorkerSessionLifecycle::Failed, SessionLifecycle::Failed),
    ] {
        let fixture = Fixture::new();
        let terminal = fixture.seed("terminal", false, true);
        let unattempted = fixture.seed("unattempted", false, false);
        let armed = fixture.seed("armed", true, false);
        fixture.mode(ReadMode::Lifecycle(worker_lifecycle));
        assert_eq!(
            lifecycle(fixture.get().expect("confirmed terminal session")),
            expected
        );
        fixture.assert_admission_closed();
        fixture.drain();
        assert_eq!(fixture.row(&terminal), terminal);
        for (before, detail) in [
            (
                &unattempted,
                TerminalDetail::FailedKnown(KnownFailureReason::NotDispatched),
            ),
            (
                &armed,
                TerminalDetail::OutcomeUnknown(OutcomeUnknownReason::WorkerLost),
            ),
        ] {
            let after = fixture.row(before);
            assert_eq!(after.action_id(), before.action_id());
            assert_eq!(after.request_hash(), before.request_hash());
            assert_eq!(after.idempotency_key(), before.idempotency_key());
            assert_eq!(after.action_sequence(), before.action_sequence());
            assert_eq!(after.terminal().expect("terminal").detail(), detail);
        }
        assert_eq!(
            lifecycle(fixture.get().expect("same terminal retry")),
            expected
        );
        fixture.drain();
        let events = fixture.events();
        assert_eq!(events.events().len(), 4);
        assert_eq!(
            events
                .events()
                .iter()
                .filter(|event| event.kind() == OutboxEventKind::SessionLost)
                .count(),
            1
        );
        assert_eq!(fixture.worker.enqueued.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn mismatched_or_missing_inspector_proof_never_records_loss_and_keeps_admission_closed() {
    for fault in [
        InspectFault::Worker,
        InspectFault::Tenant,
        InspectFault::Session,
        InspectFault::Epoch,
        InspectFault::Placement,
        InspectFault::Incarnation,
        InspectFault::Lifecycle,
        InspectFault::NotFound,
        InspectFault::Timeout,
    ] {
        let fixture = Fixture::new();
        let action = fixture.seed("pending", false, false);
        fixture.mode(ReadMode::Lifecycle(WorkerSessionLifecycle::Closed));
        *fixture.worker.inspect_fault.lock().expect("fault") = fault;
        assert!(fixture.get().is_err(), "{fault:?}");
        assert_eq!(fixture.worker.inspected.load(Ordering::SeqCst), 1);
        assert!(
            fixture
                .store
                .proposals
                .lock()
                .expect("proposals")
                .is_empty()
        );
        assert_eq!(fixture.row(&action), action);
        assert!(fixture.events().events().is_empty());
        fixture.mode(ReadMode::Lifecycle(WorkerSessionLifecycle::Ready));
        assert_eq!(
            lifecycle(fixture.get().expect("stale Ready receipt")),
            SessionLifecycle::Closing
        );
        fixture.assert_admission_closed();
    }
}

#[test]
fn nonterminal_receipts_and_transient_get_failures_do_not_produce_loss() {
    for mode in [
        ReadMode::Lifecycle(WorkerSessionLifecycle::Ready),
        ReadMode::Lifecycle(WorkerSessionLifecycle::Creating),
        ReadMode::Lifecycle(WorkerSessionLifecycle::Closing),
        ReadMode::Timeout,
        ReadMode::NotFound,
    ] {
        let fixture = Fixture::new();
        let action = fixture.seed("pending", false, false);
        fixture.mode(mode);
        let result = fixture.get();
        assert_eq!(
            result.is_err(),
            matches!(mode, ReadMode::Timeout | ReadMode::NotFound)
        );
        assert_eq!(fixture.worker.inspected.load(Ordering::SeqCst), 0);
        assert!(
            fixture
                .store
                .proposals
                .lock()
                .expect("proposals")
                .is_empty()
        );
        assert_eq!(fixture.row(&action), action);
        assert!(fixture.events().events().is_empty());
    }
}

#[test]
fn committed_loss_with_lost_reply_keeps_admission_closed_and_retry_adopts_canonical_id() {
    let fixture = Fixture::new();
    fixture.mode(ReadMode::Lifecycle(WorkerSessionLifecycle::Closed));
    fixture
        .store
        .lose_ensure_reply
        .store(true, Ordering::SeqCst);
    assert!(fixture.get().is_err());
    assert!(
        fixture
            .store
            .materialize_limits
            .lock()
            .expect("limits")
            .is_empty()
    );
    let canonical = fixture.store.committed.lock().expect("committed")[0].clone();
    fixture.mode(ReadMode::Lifecycle(WorkerSessionLifecycle::Ready));
    assert_eq!(
        lifecycle(fixture.get().expect("stale Ready response")),
        SessionLifecycle::Closing
    );
    fixture.assert_admission_closed();
    fixture.mode(ReadMode::Lifecycle(WorkerSessionLifecycle::Closed));
    assert_eq!(
        lifecycle(fixture.get().expect("canonical retry")),
        SessionLifecycle::Closed
    );
    let proposals = fixture.store.proposals.lock().expect("proposals");
    assert_eq!(proposals.len(), 2);
    assert_ne!(proposals[0], proposals[1]);
    assert!(
        fixture
            .store
            .committed
            .lock()
            .expect("committed")
            .iter()
            .all(|claim| claim == &canonical)
    );
    drop(proposals);
    fixture.drain();
    assert_eq!(fixture.events().events().len(), 1);
}

#[test]
fn failed_outbox_is_recovered_in_bounded_batches_without_overwriting_existing_terminal() {
    let fixture = Fixture::new();
    let terminal = fixture.seed("winner", false, true);
    let mut pending = Vec::new();
    for index in 0..5 {
        pending.push(fixture.seed(&format!("pending-{index}"), false, false));
    }
    fixture.sink.unavailable.store(true, Ordering::SeqCst);
    fixture.mode(ReadMode::Lifecycle(WorkerSessionLifecycle::Failed));
    assert_eq!(
        lifecycle(
            fixture
                .get()
                .expect("sink outage cannot erase committed loss")
        ),
        SessionLifecycle::Failed
    );
    assert_eq!(
        *fixture.store.materialize_limits.lock().expect("limits"),
        vec![1]
    );
    assert!(fixture.events().events().is_empty());
    assert!(fixture.gateway.reconcile_terminal_events(1).is_err());
    fixture.assert_admission_closed();
    fixture.sink.unavailable.store(false, Ordering::SeqCst);
    fixture.drain();
    assert_eq!(fixture.row(&terminal), terminal);
    for action in pending {
        assert_eq!(
            fixture.row(&action).terminal().expect("known").detail(),
            TerminalDetail::FailedKnown(KnownFailureReason::NotDispatched)
        );
    }
    let events = fixture.events();
    assert_eq!(events.events().len(), 7);
    assert_eq!(
        events
            .events()
            .iter()
            .filter(|event| event.kind() == OutboxEventKind::SessionLost)
            .count(),
        1
    );
}

#[test]
fn repeated_close_and_get_of_an_empty_session_emit_one_loss_and_do_not_repeat_close_rpc() {
    let fixture = Fixture::new();
    fixture.mode(ReadMode::Lifecycle(WorkerSessionLifecycle::Closed));
    assert_eq!(
        lifecycle(fixture.close().expect("close")),
        SessionLifecycle::Closed
    );
    assert_eq!(
        lifecycle(fixture.close().expect("repeat close")),
        SessionLifecycle::Closed
    );
    assert_eq!(
        lifecycle(fixture.get().expect("get after close")),
        SessionLifecycle::Closed
    );
    assert_eq!(fixture.worker.closed.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.worker.inspected.load(Ordering::SeqCst), 2);
    fixture.assert_admission_closed();
    fixture.drain();
    assert_eq!(fixture.events().events().len(), 1);
    let commits = fixture.store.committed.lock().expect("committed");
    assert_eq!(commits.len(), 2);
    assert_eq!(commits[0], commits[1]);
}
