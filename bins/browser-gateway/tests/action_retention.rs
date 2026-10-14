#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use async_trait::async_trait;
use browser_gateway::{
    GatewayWorkerClient, GatewayWorkerPending, GatewayWorkerPlacement, GatewayWorkerRuntime,
};
use browserd_actions::{
    ActionKind, ActionSequence, BrowserResult, CanonicalRequestHash, DispatchId,
    JournalSessionScope, KnownFailureReason, ResolutionAnnotation, TerminalCustodyReceipt,
    TerminalDetail, TransportLoss,
};
use browserd_api::{ActionGetRequest, ApiRequest, ApiResponse, ApiRouter, ApiService};
use browserd_auth::{
    AuthConfig, AuthenticatedPrincipal, RevocationRegistry, ServiceClaims, ServiceTokenSigner,
    ServiceTokenVerifier, VerificationKeySet,
};
use browserd_coordination::{
    ClaimGatewayAction, CoordinationActorConfig, DirectoryFence, GatewayActionClaimOutcome,
    GatewayActionCoordination, GatewayActionCoordinationError, GatewayActionPlacement,
    GatewayActionRetentionClock, GatewayActionRetentionCursor, GatewayActionRetentionPage,
    GatewayActionSnapshot, GatewayCustodyCursor, MemoryGatewayActionStore, SessionLossClaim,
    SessionLossOutcome,
};
use browserd_core::{
    ActionId, ActionState, ErrorCode, PlacementFence, PrincipalId, SessionId, TenantId, WorkerId,
};
use browserd_worker::{
    WorkerCreateSessionReceipt, WorkerCreateSessionRequest, WorkerRpcCompletionError,
    WorkerRpcEnqueueError, WorkerRpcError, WorkerRpcRequest, WorkerRpcResponse,
};
use chrono::{DateTime, Utc};
use jsonwebtoken::Algorithm;
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

struct Clock(AtomicI64);
impl Clock {
    fn new() -> Self {
        Self(AtomicI64::new(1_700_000_000_000))
    }
    fn advance(&self, millis: i64) {
        self.0.fetch_add(millis, Ordering::AcqRel);
    }
}
impl GatewayActionRetentionClock for Clock {
    fn now(&self) -> DateTime<Utc> {
        DateTime::from_timestamp_millis(self.0.load(Ordering::Acquire)).unwrap()
    }
}

struct NeverPending;
impl GatewayWorkerPending for NeverPending {
    fn wait(self) -> Result<WorkerRpcResponse, WorkerRpcCompletionError> {
        panic!("retention never submits browser work")
    }
}
#[derive(Default)]
struct UnavailableWorker(AtomicUsize);
impl GatewayWorkerClient for UnavailableWorker {
    type PendingAction = NeverPending;
    fn create_session(
        &self,
        _: WorkerCreateSessionRequest,
    ) -> Result<WorkerCreateSessionReceipt, WorkerRpcError> {
        self.0.fetch_add(1, Ordering::AcqRel);
        panic!("retention never creates a session")
    }
    fn enqueue_action(
        &self,
        _: WorkerRpcRequest,
    ) -> Result<Self::PendingAction, WorkerRpcEnqueueError> {
        self.0.fetch_add(1, Ordering::AcqRel);
        panic!("retention never enqueues an action")
    }
    fn request(&self, _: WorkerRpcRequest) -> Result<WorkerRpcResponse, WorkerRpcError> {
        self.0.fetch_add(1, Ordering::AcqRel);
        Err(WorkerRpcError::Timeout)
    }
}
struct Fixture {
    executor: tokio::runtime::Runtime,
    store: Arc<MemoryGatewayActionStore>,
    clock: Arc<Clock>,
    worker: Arc<UnavailableWorker>,
    tenant: TenantId,
    worker_id: WorkerId,
}
impl Fixture {
    fn new() -> Self {
        let clock = Arc::new(Clock::new());
        Self {
            executor: tokio::runtime::Runtime::new().unwrap(),
            store: Arc::new(
                MemoryGatewayActionStore::default().with_retention_clock(clock.clone()),
            ),
            clock,
            worker: Arc::new(UnavailableWorker::default()),
            tenant: TenantId::new(),
            worker_id: WorkerId::new("retention-worker").unwrap(),
        }
    }
    fn placement(&self) -> GatewayActionPlacement {
        GatewayActionPlacement::new(
            DirectoryFence::new(self.worker_id.clone(), 3, 4, 5).unwrap(),
            6,
        )
        .unwrap()
    }
    fn gateway(&self) -> GatewayWorkerRuntime<UnavailableWorker> {
        self.gateway_store(self.store.clone())
    }
    fn gateway_store<S: GatewayActionCoordination + 'static>(
        &self,
        store: Arc<S>,
    ) -> GatewayWorkerRuntime<UnavailableWorker> {
        GatewayWorkerRuntime::with_action_coordination(
            self.worker.clone(),
            GatewayWorkerPlacement::new(self.worker_id.clone(), 3, 4, 6).unwrap(),
            store,
            CoordinationActorConfig::default(),
        )
        .unwrap()
    }
    fn claim(&self, session: &SessionId, key: &str) -> GatewayActionSnapshot {
        self.executor
            .block_on(
                self.store.claim_action(
                    ClaimGatewayAction::new(
                        self.tenant.clone(),
                        session.clone(),
                        ActionId::new(),
                        key,
                        CanonicalRequestHash::new([31; 32]),
                        ActionKind::ReadOnly,
                        self.placement(),
                    )
                    .unwrap(),
                    self.clock.now(),
                ),
            )
            .unwrap()
            .into_snapshot()
    }
    fn terminal(&self, session: SessionId, key: &str, custody: bool) -> GatewayActionSnapshot {
        let claimed = self.claim(&session, key);
        let dispatch = DispatchId::new();
        self.executor.block_on(async {
            let armed = self
                .store
                .arm_dispatch(
                    &self.tenant,
                    &session,
                    claimed.action_id(),
                    claimed.revision(),
                    claimed.placement(),
                    dispatch.clone(),
                    self.clock.now(),
                )
                .await
                .unwrap();
            let detail = TerminalDetail::FailedKnown(KnownFailureReason::BrowserRejected);
            let receipt = if custody {
                Some(
                    TerminalCustodyReceipt::new(
                        JournalSessionScope::new(
                            self.tenant.clone(),
                            session.clone(),
                            self.worker_id.clone(),
                            PlacementFence::new(3, 4, 5),
                        )
                        .unwrap(),
                        armed.action_id().clone(),
                        armed.action_sequence(),
                        armed.kind(),
                        CanonicalRequestHash::new([71; 32]),
                        Some(DispatchId::new()),
                        detail,
                        None,
                    )
                    .unwrap(),
                )
            } else {
                None
            };
            self.store
                .record_worker_terminal_with_custody(
                    &self.tenant,
                    &session,
                    armed.action_id(),
                    armed.revision(),
                    armed.placement(),
                    &dispatch,
                    armed.action_sequence(),
                    detail,
                    receipt,
                    Some(if custody {
                        browserd_actions::TerminalCustodyRequirement::Required
                    } else {
                        browserd_actions::TerminalCustodyRequirement::Unsupported
                    }),
                    self.clock.now(),
                )
                .await
                .unwrap()
        })
    }
    fn ack_source(&self, action: &GatewayActionSnapshot) {
        self.executor.block_on(async {
            let event = self
                .store
                .peek_event_projection(action.tenant_id(), action.session_id())
                .await
                .unwrap()
                .expect("source event");
            self.store.ack_event_projection(&event).await.unwrap();
        });
    }
    fn exists(&self, action: &GatewayActionSnapshot) -> bool {
        self.executor
            .block_on(self.store.get_effective_action(
                action.tenant_id(),
                action.session_id(),
                action.action_id(),
            ))
            .unwrap()
            .is_some()
    }
    fn expire(&self) {
        self.clock
            .advance(chrono::Duration::days(3).num_milliseconds());
    }
}

#[test]
fn pinned_oldest_source_does_not_starve_later_records_with_bounded_cursor_progress() {
    let f = Fixture::new();
    let pinned = f.terminal(SessionId::new(), "pinned", false);
    f.clock.advance(1_000);
    let mut collectible = Vec::new();
    for _ in 0..34 {
        let action = f.terminal(SessionId::new(), "eligible", false);
        f.ack_source(&action);
        collectible.push(action);
    }
    f.expire();
    let gateway = f.gateway();
    assert!(gateway.maintain_action_retention(0).is_err());
    assert!(gateway.maintain_action_retention(257).is_err());
    assert_eq!(gateway.maintain_action_retention(256).unwrap(), 31);
    assert!(f.exists(&pinned));
    assert_eq!(gateway.maintain_action_retention(256).unwrap(), 3);
    assert!(collectible.iter().all(|action| !f.exists(action)));
    assert_eq!(gateway.maintain_action_retention(256).unwrap(), 0);
    f.ack_source(&pinned);
    assert_eq!(gateway.maintain_action_retention(256).unwrap(), 1);
    assert!(!f.exists(&pinned));
    assert_eq!(f.worker.0.load(Ordering::Acquire), 0);
}

#[test]
fn both_custody_phases_pin_expired_action_until_positive_final_release() {
    let f = Fixture::new();
    let action = f.terminal(SessionId::new(), "custody", true);
    f.ack_source(&action);
    f.expire();
    let gateway = f.gateway();
    assert_eq!(gateway.maintain_action_retention(32).unwrap(), 0);
    assert!(f.exists(&action));
    let copy = f
        .executor
        .block_on(
            f.store
                .scan_pending_custody(GatewayCustodyCursor::default(), 1),
        )
        .unwrap()
        .entries()[0]
        .clone();
    assert!(!copy.is_release());
    f.executor
        .block_on(f.store.ack_pending_custody(&copy, f.clock.now()))
        .unwrap();
    assert_eq!(gateway.maintain_action_retention(32).unwrap(), 0);
    assert!(f.exists(&action));
    let release = f
        .executor
        .block_on(
            f.store
                .scan_pending_custody(GatewayCustodyCursor::default(), 1),
        )
        .unwrap()
        .entries()[0]
        .clone();
    assert!(release.is_release());
    f.executor
        .block_on(f.store.complete_custody_release(&release, f.clock.now()))
        .unwrap();
    assert_eq!(gateway.maintain_action_retention(32).unwrap(), 1);
    assert!(!f.exists(&action));
    assert_eq!(f.worker.0.load(Ordering::Acquire), 0);
}

fn principal(tenant: TenantId) -> AuthenticatedPrincipal {
    let secret = [49; 32];
    let mut keys = VerificationKeySet::new();
    keys.insert_hmac("retention", Algorithm::HS256, &secret)
        .unwrap();
    let verifier = ServiceTokenVerifier::new(
        AuthConfig::new("issuer", "audience", [Algorithm::HS256], 0, false),
        keys,
        RevocationRegistry::new(),
    );
    let token = ServiceTokenSigner::new("retention", Algorithm::HS256, &secret)
        .sign(&ServiceClaims::new(
            "issuer",
            "audience",
            PrincipalId::new(),
            tenant,
            BTreeSet::from(["session:read".to_owned()]),
            "retention",
            1,
            100,
            None,
        ))
        .unwrap();
    verifier.verify_at(&token, None, 10).unwrap()
}

#[test]
fn public_get_expires_only_after_safe_gc_and_same_key_reuse_cannot_alias_old_action() {
    let f = Fixture::new();
    let session = SessionId::new();
    let old = f.terminal(session.clone(), "same-key", true);
    let runtime = Arc::new(f.gateway());
    let router = ApiRouter::new(runtime.clone());
    let user = principal(f.tenant.clone());
    let request = || {
        ApiRequest::GetAction(ActionGetRequest {
            session_id: session.clone(),
            action_id: old.action_id().clone(),
        })
    };
    let ApiResponse::Action(response) = router.execute(&user, request()).unwrap() else {
        panic!("action")
    };
    assert_eq!(response.data().state(), ActionState::FailedKnown);
    assert_eq!(
        router
            .execute(&principal(TenantId::new()), request())
            .unwrap_err()
            .code(),
        ErrorCode::OperationNotFound
    );
    f.expire();
    assert!(router.execute(&user, request()).is_ok());
    assert_eq!(runtime.maintain_action_retention(32).unwrap(), 0);
    f.ack_source(&old);
    let copy = f
        .executor
        .block_on(
            f.store
                .scan_pending_custody(GatewayCustodyCursor::default(), 1),
        )
        .unwrap()
        .entries()[0]
        .clone();
    f.executor
        .block_on(f.store.ack_pending_custody(&copy, f.clock.now()))
        .unwrap();
    let release = f
        .executor
        .block_on(
            f.store
                .scan_pending_custody(GatewayCustodyCursor::default(), 1),
        )
        .unwrap()
        .entries()[0]
        .clone();
    f.executor
        .block_on(f.store.complete_custody_release(&release, f.clock.now()))
        .unwrap();
    assert_eq!(runtime.maintain_action_retention(32).unwrap(), 1);
    assert_eq!(
        router.execute(&user, request()).unwrap_err().code(),
        ErrorCode::OperationNotFound
    );
    let new = f.claim(&session, "same-key");
    assert_ne!(new.action_id(), old.action_id());
    assert_eq!(new.action_sequence().get(), old.action_sequence().get() + 1);
    assert_eq!(new.placement(), old.placement());
    assert_eq!(
        router.execute(&user, request()).unwrap_err().code(),
        ErrorCode::OperationNotFound
    );
    assert_eq!(f.worker.0.load(Ordering::Acquire), 0);
}

#[test]
fn old_and_new_records_have_independent_deadlines_and_old_retry_cannot_extend_retention() {
    let f = Fixture::new();
    let session = SessionId::new();
    let old = f.terminal(session.clone(), "old", false);
    let deadline = old.retain_until();
    f.ack_source(&old);
    f.expire();
    let retry = f.claim(&session, "old");
    assert_eq!(retry.action_id(), old.action_id());
    assert_eq!(retry.retain_until(), deadline);
    let fresh = f.terminal(session.clone(), "fresh", false);
    f.ack_source(&fresh);
    assert_eq!(f.gateway().maintain_action_retention(32).unwrap(), 1);
    assert!(!f.exists(&old));
    assert!(f.exists(&fresh));
    let new = f.claim(&session, "old");
    assert_eq!(
        new.action_sequence().get(),
        fresh.action_sequence().get() + 1
    );
    assert_ne!(new.action_id(), old.action_id());
    assert_eq!(f.worker.0.load(Ordering::Acquire), 0);
}

struct RetentionFaultStore {
    inner: Arc<MemoryGatewayActionStore>,
    fail_after: AtomicBool,
    calls: Mutex<Vec<(GatewayActionRetentionCursor, usize)>>,
    before: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}
impl RetentionFaultStore {
    fn new(inner: Arc<MemoryGatewayActionStore>) -> Self {
        Self {
            inner,
            fail_after: AtomicBool::new(false),
            calls: Mutex::new(Vec::new()),
            before: Mutex::new(None),
        }
    }
}
#[allow(clippy::too_many_arguments)]
#[async_trait]
impl GatewayActionCoordination for RetentionFaultStore {
    async fn claim_action(
        &self,
        claim: ClaimGatewayAction,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionClaimOutcome, GatewayActionCoordinationError> {
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
        self.inner.materialize_session_loss(claim, limit, now).await
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
    async fn maintain_action_retention(
        &self,
        cursor: GatewayActionRetentionCursor,
        limit: usize,
    ) -> Result<GatewayActionRetentionPage, GatewayActionCoordinationError> {
        self.calls.lock().unwrap().push((cursor.clone(), limit));
        let hook = self.before.lock().unwrap().take();
        if let Some(hook) = hook {
            hook();
        }
        let page = self.inner.maintain_action_retention(cursor, limit).await?;
        if self.fail_after.swap(false, Ordering::AcqRel) {
            return Err(GatewayActionCoordinationError::RedisUnavailable);
        }
        Ok(page)
    }
}

#[test]
fn lost_retention_response_retries_original_cursor_and_restart_reclaims_remaining_records() {
    let f = Fixture::new();
    let mut actions = Vec::new();
    for _ in 0..33 {
        let action = f.terminal(SessionId::new(), "eligible", false);
        f.ack_source(&action);
        actions.push(action);
    }
    f.expire();
    let store = Arc::new(RetentionFaultStore::new(f.store.clone()));
    store.fail_after.store(true, Ordering::Release);
    let runtime = f.gateway_store(store.clone());
    assert!(runtime.maintain_action_retention(256).is_err());
    assert_eq!(actions.iter().filter(|action| f.exists(action)).count(), 1);
    assert_eq!(runtime.maintain_action_retention(256).unwrap(), 1);
    let calls = store.calls.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].0, calls[1].0);
    assert_eq!(calls[0].1, 32);
    assert_eq!(calls[1].1, 32);
    drop(calls);
    drop(runtime);
    assert_eq!(
        f.gateway_store(store)
            .maintain_action_retention(256)
            .unwrap(),
        0
    );
    assert!(actions.iter().all(|action| !f.exists(action)));
    assert_eq!(f.worker.0.load(Ordering::Acquire), 0);
}

#[test]
fn overlapping_retention_ticks_do_not_start_a_second_store_mutation() {
    let f = Fixture::new();
    let action = f.terminal(SessionId::new(), "eligible", false);
    f.ack_source(&action);
    f.expire();
    let store = Arc::new(RetentionFaultStore::new(f.store.clone()));
    let (entered_send, entered) = std::sync::mpsc::channel();
    let (release_send, release) = std::sync::mpsc::channel();
    *store.before.lock().unwrap() = Some(Box::new(move || {
        entered_send.send(()).unwrap();
        release
            .recv_timeout(std::time::Duration::from_secs(3))
            .unwrap();
    }));
    let runtime = Arc::new(f.gateway_store(store.clone()));
    let running = runtime.clone();
    let pass = std::thread::spawn(move || running.maintain_action_retention(32));
    entered
        .recv_timeout(std::time::Duration::from_secs(3))
        .expect("retention entered");
    let overlapping = runtime.maintain_action_retention(32);
    release_send.send(()).unwrap();
    assert_eq!(overlapping.unwrap(), 0);
    assert_eq!(pass.join().unwrap().unwrap(), 1);
    assert_eq!(store.calls.lock().unwrap().len(), 1);
    assert!(!f.exists(&action));
    assert_eq!(f.worker.0.load(Ordering::Acquire), 0);
}

#[test]
fn shared_retention_config_preserves_defaults_and_allows_bounded_migration_capacity() {
    use browser_gateway::action_retention_limits_from_lookup;
    use browserd_coordination::GatewayActionRetentionLimits;
    assert_eq!(
        action_retention_limits_from_lookup(|_| None).unwrap(),
        GatewayActionRetentionLimits::default()
    );
    let explicit = action_retention_limits_from_lookup(|name| match name {
        "BROWSERD_ACTION_MAX_RETAINED_RECORDS" => Some("1048576".to_owned()),
        "BROWSERD_ACTION_MAX_RETAINED_RECORDS_PER_SESSION" => Some("65536".to_owned()),
        _ => panic!("unexpected lookup"),
    })
    .unwrap();
    assert_eq!(
        explicit,
        GatewayActionRetentionLimits::new(1_048_576, 65_536).unwrap()
    );
    let partial = action_retention_limits_from_lookup(|name| {
        (name == "BROWSERD_ACTION_MAX_RETAINED_RECORDS").then(|| "131072".to_owned())
    })
    .unwrap();
    assert_eq!(partial.namespace_records(), 131_072);
    assert_eq!(
        partial.session_records(),
        GatewayActionRetentionLimits::default().session_records()
    );
}

#[test]
fn retention_config_rejects_invalid_numbers_bounds_and_cross_field_overflow_without_values() {
    use browser_gateway::{GatewayConfigurationError, action_retention_limits_from_lookup};
    const NAMESPACE: &str = "BROWSERD_ACTION_MAX_RETAINED_RECORDS";
    const SESSION: &str = "BROWSERD_ACTION_MAX_RETAINED_RECORDS_PER_SESSION";
    for value in [
        "",
        "0",
        "-1",
        "+1",
        " 64",
        "64 ",
        "1048577",
        "18446744073709551616",
        "redis://private-credential",
    ] {
        let error = action_retention_limits_from_lookup(|name| {
            (name == NAMESPACE).then(|| value.to_owned())
        })
        .unwrap_err();
        assert_eq!(
            error,
            GatewayConfigurationError::InvalidActionRetention(NAMESPACE)
        );
        assert!(!error.to_string().contains("private-credential"));
        assert!(!format!("{error:?}").contains("private-credential"));
    }
    for (namespace, session) in [("8", "9"), ("65536", "0"), ("1048576", "65537")] {
        let error = action_retention_limits_from_lookup(|name| {
            Some(
                if name == NAMESPACE {
                    namespace
                } else {
                    session
                }
                .to_owned(),
            )
        })
        .unwrap_err();
        assert_eq!(
            error,
            GatewayConfigurationError::InvalidActionRetention(SESSION)
        );
    }
}
