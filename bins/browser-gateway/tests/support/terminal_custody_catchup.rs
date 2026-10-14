use super::*;
use browserd_actions::TerminalCustodyRequirement;
use browserd_api::ActionGetRequest;
use browserd_coordination::{GatewayActionRetentionClock, GatewayActionRetentionCursor};
use browserd_worker::WorkerTerminalCustodyReceipt;
use std::sync::atomic::AtomicI64;

#[derive(Clone, Copy, Debug)]
enum ProofFault {
    None,
    Timeout,
    NotFound,
    ServingWorker,
    ServingEpoch,
    Tenant,
    Session,
    OriginalWorker,
    OriginalEpoch,
    Placement,
    Incarnation,
    Action,
    Sequence,
    Kind,
    Terminal,
    Resolution,
}

struct CatchupWorker {
    base: Arc<CustodyWorker>,
    historical: Mutex<HashMap<ActionId, TerminalCustodyReceipt>>,
    fault: Mutex<ProofFault>,
    lookups: AtomicUsize,
    before_lookup: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}
impl GatewayWorkerClient for CatchupWorker {
    type PendingAction = NeverPending;
    fn create_session(
        &self,
        _: WorkerCreateSessionRequest,
    ) -> Result<WorkerCreateSessionReceipt, WorkerRpcError> {
        panic!("catch-up never creates a session")
    }
    fn enqueue_action(
        &self,
        _: WorkerRpcRequest,
    ) -> Result<Self::PendingAction, WorkerRpcEnqueueError> {
        panic!("catch-up never enqueues browser work")
    }
    fn request(&self, request: WorkerRpcRequest) -> Result<WorkerRpcResponse, WorkerRpcError> {
        match request {
            WorkerRpcRequest::GetTerminalCustody {
                expected_serving_worker_id,
                expected_serving_worker_epoch,
                scope,
                action_id,
                action_sequence,
                kind,
            } => {
                self.lookups.fetch_add(1, Ordering::AcqRel);
                assert_eq!(expected_serving_worker_id, self.base.id);
                assert_eq!(
                    expected_serving_worker_epoch,
                    self.base.epoch.load(Ordering::Acquire)
                );
                let receipt = self
                    .historical
                    .lock()
                    .unwrap()
                    .get(&action_id)
                    .unwrap()
                    .clone();
                assert_eq!(receipt.scope(), &scope);
                assert_eq!(receipt.action_sequence(), action_sequence);
                assert_eq!(receipt.kind(), kind);
                let hook = self.before_lookup.lock().unwrap().take();
                if let Some(hook) = hook {
                    hook();
                }
                let fault = *self.fault.lock().unwrap();
                if matches!(fault, ProofFault::Timeout) {
                    return Err(WorkerRpcError::Timeout);
                }
                if matches!(fault, ProofFault::NotFound) {
                    return Ok(WorkerRpcResponse::Failure(WorkerRpcFailure::new(
                        WorkerRpcFailureCode::NotFound,
                        "no historical proof",
                    )));
                }
                let original = scope.fence();
                let scope = JournalSessionScope::new(
                    if matches!(fault, ProofFault::Tenant) {
                        TenantId::new()
                    } else {
                        scope.tenant_id().clone()
                    },
                    if matches!(fault, ProofFault::Session) {
                        SessionId::new()
                    } else {
                        scope.session_id().clone()
                    },
                    if matches!(fault, ProofFault::OriginalWorker) {
                        WorkerId::new("foreign-original").unwrap()
                    } else {
                        scope.original_worker_id().clone()
                    },
                    PlacementFence::new(
                        original.worker_epoch
                            + u64::from(matches!(fault, ProofFault::OriginalEpoch)),
                        original.placement_version
                            + u64::from(matches!(fault, ProofFault::Placement)),
                        original.session_incarnation
                            + u64::from(matches!(fault, ProofFault::Incarnation)),
                    ),
                )
                .unwrap();
                let receipt = TerminalCustodyReceipt::new(
                    scope,
                    if matches!(fault, ProofFault::Action) {
                        ActionId::new()
                    } else {
                        action_id
                    },
                    ActionSequence::new(
                        action_sequence.get() + u64::from(matches!(fault, ProofFault::Sequence)),
                    ),
                    if matches!(fault, ProofFault::Kind) {
                        ActionKind::ReadOnly
                    } else {
                        kind
                    },
                    receipt.request_hash(),
                    receipt.dispatch_id().cloned(),
                    if matches!(fault, ProofFault::Terminal) {
                        TerminalDetail::OutcomeUnknown(OutcomeUnknownReason::AmbiguousTransportLoss)
                    } else {
                        receipt.terminal()
                    },
                    if matches!(fault, ProofFault::Resolution) {
                        Some(annotation())
                    } else {
                        receipt.resolution().cloned()
                    },
                )
                .unwrap();
                Ok(WorkerRpcResponse::TerminalCustody(
                    WorkerTerminalCustodyReceipt {
                        worker_id: if matches!(fault, ProofFault::ServingWorker) {
                            WorkerId::new("foreign-serving").unwrap()
                        } else {
                            self.base.id.clone()
                        },
                        worker_epoch: expected_serving_worker_epoch
                            + u64::from(matches!(fault, ProofFault::ServingEpoch)),
                        receipt: Box::new(receipt),
                    },
                ))
            }
            request @ (WorkerRpcRequest::AckTerminalCustody { .. }
            | WorkerRpcRequest::ReleaseTerminalCustody { .. }) => self.base.request(request),
            _ => panic!("catch-up must not inspect readiness, get actions, resolve, or replay"),
        }
    }
}

struct Clock(AtomicI64);
impl GatewayActionRetentionClock for Clock {
    fn now(&self) -> DateTime<Utc> {
        DateTime::from_timestamp_millis(self.0.load(Ordering::Acquire)).unwrap()
    }
}
struct CatchupFixture {
    base: Fixture,
    worker: Arc<CatchupWorker>,
    clock: Arc<Clock>,
}
impl CatchupFixture {
    fn new() -> Self {
        let mut base = Fixture::new();
        let clock = Arc::new(Clock(AtomicI64::new(Utc::now().timestamp_millis())));
        base.store =
            Arc::new(MemoryGatewayActionStore::default().with_retention_clock(clock.clone()));
        let worker = Arc::new(CatchupWorker {
            base: base.worker.clone(),
            historical: Mutex::new(HashMap::new()),
            fault: Mutex::new(ProofFault::None),
            lookups: AtomicUsize::new(0),
            before_lookup: Mutex::new(None),
        });
        Self {
            base,
            worker,
            clock,
        }
    }
    fn gateway(&self, epoch: u64) -> GatewayWorkerRuntime<CatchupWorker> {
        self.gateway_store(epoch, self.base.store.clone())
    }
    fn gateway_store<S: GatewayActionCoordination + 'static>(
        &self,
        epoch: u64,
        store: Arc<S>,
    ) -> GatewayWorkerRuntime<CatchupWorker> {
        self.base.worker.epoch.store(epoch, Ordering::Release);
        GatewayWorkerRuntime::with_action_coordination(
            self.worker.clone(),
            GatewayWorkerPlacement::new(self.base.worker.id.clone(), epoch, 4, 6).unwrap(),
            store,
            CoordinationActorConfig::default(),
        )
        .unwrap()
    }
    fn missing(
        &self,
        unknown: bool,
        requirement: Option<TerminalCustodyRequirement>,
    ) -> GatewayActionSnapshot {
        self.missing_in_session(unknown, requirement, SessionId::new())
    }
    fn missing_in_session(
        &self,
        unknown: bool,
        requirement: Option<TerminalCustodyRequirement>,
        session: SessionId,
    ) -> GatewayActionSnapshot {
        let action = self.base.seed_session(unknown, session, 5);
        {
            let mut receipts = self.base.worker.receipts.lock().unwrap();
            let receipt = receipts.get_mut(action.action_id()).unwrap();
            self.worker
                .historical
                .lock()
                .unwrap()
                .insert(action.action_id().clone(), *receipt.custody.take().unwrap());
            receipt.custody_requirement = requirement;
        }
        self.base.recover();
        self.base.worker.calls.lock().unwrap().clear();
        let saved = self.base.stored(&action);
        assert_eq!(saved.custody_requirement(), requirement);
        saved
    }
    fn fault_store(&self, fault: usize) -> Arc<LostCommitStore> {
        Arc::new(LostCommitStore {
            inner: self.base.store.clone(),
            lose_response: AtomicBool::new(false),
            commits: AtomicUsize::new(0),
            ack_fault: AtomicUsize::new(0),
            catchup_fault: AtomicUsize::new(fault),
            catchup_scans: Mutex::new(Vec::new()),
        })
    }
    fn ack_source(&self, action: &GatewayActionSnapshot) {
        self.base.executor.block_on(async {
            while let Some(event) = self
                .base
                .store
                .peek_event_projection(action.tenant_id(), action.session_id())
                .await
                .unwrap()
            {
                self.base.store.ack_event_projection(&event).await.unwrap();
            }
        });
    }
    fn expire(&self) {
        self.clock.0.fetch_add(3 * 86_400_000, Ordering::AcqRel);
    }
    fn reclaimed(&self) -> usize {
        self.base
            .executor
            .block_on(
                self.base
                    .store
                    .maintain_action_retention(GatewayActionRetentionCursor::default(), 256),
            )
            .unwrap()
            .reclaimed()
    }
}
fn annotation() -> ResolutionAnnotation {
    ResolutionAnnotation::new(
        ResolutionKind::ConfirmedNotExecuted,
        PrincipalId::new(),
        1000,
        "external state verified".to_owned(),
    )
}
fn assert_preserved(before: &GatewayActionSnapshot, after: &GatewayActionSnapshot) {
    assert_eq!(before.revision(), after.revision());
    assert_eq!(before.terminal(), after.terminal());
    assert_eq!(before.result_content(), after.result_content());
    assert_eq!(before.resolution(), after.resolution());
    assert_eq!(before.retain_until(), after.retain_until());
    assert_eq!(
        before.last_source_event_sequence(),
        after.last_source_event_sequence()
    );
    assert_eq!(before.placement(), after.placement());
}

#[test]
fn required_projection_failure_preserves_known_result_then_restart_reads_old_epoch_without_browser_calls()
 {
    let f = CatchupFixture::new();
    let before = f.missing(false, Some(TerminalCustodyRequirement::Required));
    assert_eq!(before.result_content(), Some(BODY));
    assert!(before.requires_terminal_custody_catchup());
    assert!(f.base.pending().entries().is_empty());
    *f.worker.fault.lock().unwrap() = ProofFault::Timeout;
    assert_eq!(
        f.gateway(3).reconcile_terminal_custody_catchup(16).unwrap(),
        0
    );
    assert_preserved(&before, &f.base.stored(&before));
    *f.worker.fault.lock().unwrap() = ProofFault::None;
    let gateway = Arc::new(f.gateway(5));
    let router = ApiRouter::new(gateway.clone());
    let request = ApiRequest::GetAction(ActionGetRequest {
        session_id: before.session_id().clone(),
        action_id: before.action_id().clone(),
    });
    let ApiResponse::Action(response) = router
        .execute(&principal(f.base.tenant.clone()), request)
        .unwrap()
    else {
        panic!("action");
    };
    assert_eq!(response.data().result_content(), Some(BODY));
    assert_eq!(gateway.reconcile_terminal_custody_catchup(16).unwrap(), 1);
    assert_preserved(&before, &f.base.stored(&before));
    assert!(!f.base.stored(&before).requires_terminal_custody_catchup());
    assert_eq!(
        f.base.pending().entries()[0].receipt().fence().worker_epoch,
        3
    );
    assert_eq!(gateway.reconcile_terminal_custody(16).unwrap(), 1);
    assert_eq!(gateway.reconcile_terminal_custody(16).unwrap(), 1);
    assert!(f.base.pending().entries().is_empty());
    assert_eq!(*f.base.worker.calls.lock().unwrap(), ["ack", "release"]);
    assert_eq!(f.worker.lookups.load(Ordering::Acquire), 2);
    // The source event remains queued: catch-up and both custody phases do not wait for delivery.
    assert!(
        f.base
            .executor
            .block_on(
                f.base
                    .store
                    .peek_event_projection(before.tenant_id(), before.session_id())
            )
            .unwrap()
            .is_some()
    );
}

#[test]
fn explicit_unsupported_is_skipped_but_legacy_absence_is_recovered() {
    let f = CatchupFixture::new();
    let unsupported = f.missing(false, Some(TerminalCustodyRequirement::Unsupported));
    let legacy = f.missing(false, None);
    assert!(!unsupported.requires_terminal_custody_catchup());
    assert!(legacy.requires_terminal_custody_catchup());
    assert_eq!(
        f.gateway(5).reconcile_terminal_custody_catchup(16).unwrap(),
        1
    );
    assert_eq!(f.worker.lookups.load(Ordering::Acquire), 1);
    assert_eq!(
        f.base.pending().entries()[0].receipt().action_id(),
        legacy.action_id()
    );
    assert_preserved(&unsupported, &f.base.stored(&unsupported));
    f.ack_source(&unsupported);
    f.ack_source(&legacy);
    f.expire();
    assert_eq!(
        f.reclaimed(),
        1,
        "only the positively unsupported origin is reclaimable"
    );
}

#[test]
fn absent_and_mismatched_historical_proofs_preserve_known_terminal_and_pending_discovery() {
    let f = CatchupFixture::new();
    let before = f.missing(true, Some(TerminalCustodyRequirement::Required));
    for fault in [
        ProofFault::Timeout,
        ProofFault::NotFound,
        ProofFault::ServingWorker,
        ProofFault::ServingEpoch,
        ProofFault::Tenant,
        ProofFault::Session,
        ProofFault::OriginalWorker,
        ProofFault::OriginalEpoch,
        ProofFault::Placement,
        ProofFault::Incarnation,
        ProofFault::Action,
        ProofFault::Sequence,
        ProofFault::Kind,
        ProofFault::Terminal,
    ] {
        *f.worker.fault.lock().unwrap() = fault;
        assert_eq!(
            f.gateway(5).reconcile_terminal_custody_catchup(16).unwrap(),
            0,
            "{fault:?}"
        );
        assert_preserved(&before, &f.base.stored(&before));
        assert!(f.base.stored(&before).requires_terminal_custody_catchup());
        assert!(f.base.pending().entries().is_empty());
    }
    assert!(f.base.worker.calls.lock().unwrap().is_empty());
}

#[test]
fn historical_lookup_never_routes_an_original_newer_epoch_to_an_older_serving_process() {
    let f = CatchupFixture::new();
    let before = f.missing(false, Some(TerminalCustodyRequirement::Required));
    assert_eq!(
        f.gateway(2).reconcile_terminal_custody_catchup(16).unwrap(),
        0
    );
    assert_eq!(f.worker.lookups.load(Ordering::Acquire), 0);
    assert!(f.base.stored(&before).requires_terminal_custody_catchup());
}

#[test]
fn missing_proof_and_both_transfer_phases_pin_expired_action_before_final_release() {
    let f = CatchupFixture::new();
    let before = f.missing(false, Some(TerminalCustodyRequirement::Required));
    f.ack_source(&before);
    f.expire();
    assert_eq!(f.reclaimed(), 0);
    let gateway = f.gateway(5);
    assert_eq!(gateway.reconcile_terminal_custody_catchup(16).unwrap(), 1);
    assert_eq!(f.reclaimed(), 0);
    assert_eq!(gateway.reconcile_terminal_custody(16).unwrap(), 1);
    assert_eq!(f.reclaimed(), 0);
    assert_eq!(gateway.reconcile_terminal_custody(16).unwrap(), 1);
    assert_eq!(f.reclaimed(), 1);
    assert_eq!(gateway.reconcile_terminal_custody_catchup(16).unwrap(), 0);
}

#[test]
fn attachment_failure_and_lost_commit_response_retry_without_changing_result_or_source() {
    for fault in [1, 2] {
        let f = CatchupFixture::new();
        let before = f.missing(false, Some(TerminalCustodyRequirement::Required));
        let store = f.fault_store(fault);
        let gateway = f.gateway_store(5, store.clone());
        assert!(gateway.reconcile_terminal_custody_catchup(16).is_err());
        assert_preserved(&before, &f.base.stored(&before));
        assert_eq!(f.base.pending().entries().len(), usize::from(fault == 2));
        assert_eq!(
            gateway.reconcile_terminal_custody_catchup(16).unwrap(),
            usize::from(fault == 1)
        );
        let scans = store.catchup_scans.lock().unwrap();
        assert_eq!(scans.len(), 2);
        assert_eq!(scans[0], scans[1]);
        drop(scans);
        assert_eq!(
            f.gateway(6).reconcile_terminal_custody_catchup(16).unwrap(),
            0
        );
        assert_eq!(f.gateway(6).reconcile_terminal_custody(16).unwrap(), 1);
        assert_eq!(f.gateway(6).reconcile_terminal_custody(16).unwrap(), 1);
        assert!(f.base.pending().entries().is_empty());
        assert_preserved(&before, &f.base.stored(&before));
    }
}

#[test]
fn gateway_only_resolution_racing_lookup_preserves_annotation_and_attaches_original_worker_proof() {
    let f = CatchupFixture::new();
    let before = f.missing(true, Some(TerminalCustodyRequirement::Required));
    let note = annotation();
    let store = f.base.store.clone();
    let action = before.clone();
    let annotation = note.clone();
    *f.worker.before_lookup.lock().unwrap() = Some(Box::new(move || {
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(store.resolve_unknown(
                action.tenant_id(),
                action.session_id(),
                action.action_id(),
                action.revision(),
                action.placement(),
                annotation,
                Utc::now(),
            ))
            .unwrap();
    }));
    assert_eq!(
        f.gateway(5).reconcile_terminal_custody_catchup(16).unwrap(),
        1
    );
    let current = f.base.stored(&before);
    assert_eq!(current.resolution(), Some(&note));
    assert_eq!(current.revision(), before.revision() + 1);
    assert_eq!(
        current.last_source_event_sequence(),
        Some(before.last_source_event_sequence().unwrap() + 1)
    );
    assert_eq!(
        f.base.pending().entries()[0].action_revision(),
        before.revision()
    );
    assert!(
        f.base.pending().entries()[0]
            .receipt()
            .resolution()
            .is_none()
    );
    assert_eq!(f.worker.lookups.load(Ordering::Acquire), 1);
    assert_eq!(f.gateway(5).reconcile_terminal_custody(16).unwrap(), 1);
    assert_eq!(f.gateway(5).reconcile_terminal_custody(16).unwrap(), 1);
    assert_eq!(f.base.stored(&before).resolution(), Some(&note));
}

#[test]
fn actual_newer_worker_resolution_is_transferred_once_without_worker_resolve_or_terminal_rewrite() {
    let f = CatchupFixture::new();
    let before = f.missing(true, Some(TerminalCustodyRequirement::Required));
    let old = f
        .worker
        .historical
        .lock()
        .unwrap()
        .get(before.action_id())
        .unwrap()
        .clone();
    let annotation = annotation();
    let resolved = TerminalCustodyReceipt::new(
        old.scope().clone(),
        old.action_id().clone(),
        old.action_sequence(),
        old.kind(),
        old.request_hash(),
        old.dispatch_id().cloned(),
        old.terminal(),
        Some(annotation.clone()),
    )
    .unwrap();
    f.worker
        .historical
        .lock()
        .unwrap()
        .insert(before.action_id().clone(), resolved.clone());
    let gateway = f.gateway(5);
    assert_eq!(gateway.reconcile_terminal_custody_catchup(16).unwrap(), 1);
    let after = f.base.stored(&before);
    assert_eq!(after.resolution(), Some(&annotation));
    assert_eq!(after.terminal(), before.terminal());
    assert_eq!(after.revision(), before.revision() + 1);
    assert_eq!(
        after.last_source_event_sequence(),
        Some(before.last_source_event_sequence().unwrap() + 1)
    );
    assert_eq!(f.base.pending().entries()[0].receipt(), &resolved);
    assert_eq!(gateway.reconcile_terminal_custody_catchup(16).unwrap(), 0);
    assert_eq!(f.base.stored(&before).revision(), after.revision());
    assert_eq!(f.worker.lookups.load(Ordering::Acquire), 1);
    assert!(f.base.worker.calls.lock().unwrap().is_empty());
}

#[test]
fn conflicting_worker_resolution_remains_pinned_without_overwriting_gateway_evidence() {
    let f = CatchupFixture::new();
    let before = f.missing(true, Some(TerminalCustodyRequirement::Required));
    let resolved = f
        .base
        .executor
        .block_on(f.base.store.resolve_unknown(
            before.tenant_id(),
            before.session_id(),
            before.action_id(),
            before.revision(),
            before.placement(),
            annotation(),
            Utc::now(),
        ))
        .unwrap();
    *f.worker.fault.lock().unwrap() = ProofFault::Resolution;
    assert_eq!(
        f.gateway(5).reconcile_terminal_custody_catchup(16).unwrap(),
        0
    );
    assert_preserved(&resolved, &f.base.stored(&before));
    assert!(f.base.stored(&before).requires_terminal_custody_catchup());
    assert!(f.base.pending().entries().is_empty());
    f.ack_source(&before);
    f.expire();
    assert_eq!(f.reclaimed(), 0);
}

#[test]
fn bounded_catalog_cursor_advances_past_irrelevant_and_temporarily_unavailable_rows() {
    let f = CatchupFixture::new();
    let mut sessions = (0..18).map(|_| SessionId::new()).collect::<Vec<_>>();
    sessions.sort();
    for (index, session) in sessions.into_iter().enumerate() {
        f.missing_in_session(
            false,
            Some(if index < 16 {
                TerminalCustodyRequirement::Unsupported
            } else {
                TerminalCustodyRequirement::Required
            }),
            session,
        );
    }
    *f.worker.fault.lock().unwrap() = ProofFault::NotFound;
    let gateway = f.gateway(5);
    // All identities share one tenant and use explicitly sorted sessions.
    assert_eq!(gateway.reconcile_terminal_custody_catchup(256).unwrap(), 0);
    assert_eq!(f.worker.lookups.load(Ordering::Acquire), 0);
    assert_eq!(gateway.reconcile_terminal_custody_catchup(256).unwrap(), 0);
    assert_eq!(f.worker.lookups.load(Ordering::Acquire), 2);
    *f.worker.fault.lock().unwrap() = ProofFault::None;
    assert_eq!(gateway.reconcile_terminal_custody_catchup(256).unwrap(), 0);
    assert_eq!(gateway.reconcile_terminal_custody_catchup(256).unwrap(), 2);
    assert_eq!(f.base.pending().entries().len(), 2);
    assert!(gateway.reconcile_terminal_custody_catchup(0).is_err());
    assert!(gateway.reconcile_terminal_custody_catchup(257).is_err());
}

#[test]
fn concurrent_catchup_pass_keeps_only_one_historical_lookup_in_flight() {
    let f = CatchupFixture::new();
    f.missing(false, Some(TerminalCustodyRequirement::Required));
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    *f.worker.before_lookup.lock().unwrap() = Some(Box::new(move || {
        entered_tx.send(()).unwrap();
        release_rx
            .recv_timeout(std::time::Duration::from_secs(3))
            .unwrap();
    }));
    let gateway = Arc::new(f.gateway(5));
    let active = gateway.clone();
    let thread = std::thread::spawn(move || active.reconcile_terminal_custody_catchup(16));
    entered_rx
        .recv_timeout(std::time::Duration::from_secs(3))
        .unwrap();
    assert_eq!(gateway.reconcile_terminal_custody_catchup(16).unwrap(), 0);
    assert_eq!(f.worker.lookups.load(Ordering::Acquire), 1);
    release_tx.send(()).unwrap();
    assert_eq!(thread.join().unwrap().unwrap(), 1);
}
