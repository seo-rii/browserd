use super::*;

use async_trait::async_trait;
use browserd_actions::{BrowserResult, DispatchId, TransportLoss};
use browserd_coordination::{
    ClaimGatewayAction, GatewayActionClaimOutcome, GatewayActionCoordinationError,
    GatewayActionPlacement, GatewayActionRecoveryCursor, GatewayActionRecoveryPage,
    GatewayActionSubmissionLease, GatewayEventProjection, GatewayEventScanCursor,
    GatewayEventScanPage, SessionLossClaim, SessionLossOutcome,
};
use chrono::DateTime;

#[derive(Clone, Copy)]
enum ExposureFault {
    StoreUnavailable,
    CommitThenUnavailable,
    TerminalWonRace,
}

struct ExposureFaultStore {
    inner: Arc<MemoryGatewayActionStore>,
    worker: Arc<ActionWorker>,
    fault: ExposureFault,
    calls: AtomicUsize,
    result_calls: AtomicUsize,
}

#[allow(clippy::too_many_arguments)]
#[async_trait]
impl GatewayActionCoordination for ExposureFaultStore {
    async fn scan_pending_actions(
        &self,
        cursor: GatewayActionRecoveryCursor,
        limit: usize,
    ) -> Result<GatewayActionRecoveryPage, GatewayActionCoordinationError> {
        self.inner.scan_pending_actions(cursor, limit).await
    }

    async fn arm_dispatch_owned(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        dispatch_id: DispatchId,
        lease: &GatewayActionSubmissionLease,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        self.inner
            .arm_dispatch_owned(
                tenant_id,
                session_id,
                action_id,
                expected_revision,
                placement,
                dispatch_id,
                lease,
                now,
            )
            .await
    }

    async fn expire_unattempted_action(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        lease: &GatewayActionSubmissionLease,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        self.inner
            .expire_unattempted_action(
                tenant_id,
                session_id,
                action_id,
                expected_revision,
                placement,
                lease,
                now,
            )
            .await
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
        self.result_calls.fetch_add(1, Ordering::AcqRel);
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
        self.result_calls.fetch_add(1, Ordering::AcqRel);
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
        assert_eq!(
            self.worker.enqueue_count.load(Ordering::Acquire),
            1,
            "the injected persistence failure must occur after enqueue"
        );
        if self.calls.fetch_add(1, Ordering::AcqRel) != 0 {
            return self
                .inner
                .mark_exposure_possible(
                    tenant_id,
                    session_id,
                    action_id,
                    expected_revision,
                    placement,
                    dispatch_id,
                    now,
                )
                .await;
        }
        match self.fault {
            ExposureFault::StoreUnavailable => {
                Err(GatewayActionCoordinationError::RedisUnavailable)
            }
            ExposureFault::CommitThenUnavailable => {
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
                    .await?;
                Err(GatewayActionCoordinationError::RedisUnavailable)
            }
            ExposureFault::TerminalWonRace => {
                let winner = self
                    .inner
                    .record_transport_loss(
                        tenant_id,
                        session_id,
                        action_id,
                        expected_revision,
                        placement,
                        dispatch_id,
                        TransportLoss::Ambiguous(OutcomeUnknownReason::TimeoutAfterDispatch),
                        now,
                    )
                    .await?;
                Err(GatewayActionCoordinationError::StaleWrite(Box::new(winner)))
            }
        }
    }
}

struct ReleasePendingOnDrop(Arc<ReleaseGate>);
impl Drop for ReleasePendingOnDrop {
    fn drop(&mut self) {
        let _ = self.0.release();
    }
}

fn fault_fixture(
    fault: ExposureFault,
) -> Result<(Fixture, Arc<ExposureFaultStore>), Box<dyn Error>> {
    let tenant_id = TenantId::new();
    let principal = authenticated_principal(tenant_id.clone())?;
    let (pending_sender, pending_entered) = mpsc::channel();
    let worker = Arc::new(ActionWorker {
        tenant_id,
        session_id: SessionId::new(),
        page_id: PageId::new(),
        mode: EnqueueMode::Succeed,
        enqueue_count: AtomicUsize::new(0),
        request_count: AtomicUsize::new(0),
        enqueued: Mutex::new(Vec::new()),
        pending_entered: pending_sender,
        pending_gate: Arc::new(ReleaseGate::default()),
    });
    let store = Arc::new(MemoryGatewayActionStore::default());
    let fault_store = Arc::new(ExposureFaultStore {
        inner: store.clone(),
        worker: worker.clone(),
        fault,
        calls: AtomicUsize::new(0),
        result_calls: AtomicUsize::new(0),
    });
    let runtime = Arc::new(GatewayWorkerRuntime::with_action_coordination(
        worker.clone(),
        GatewayWorkerPlacement::new(WorkerId::new("durable-action-worker")?, 41, 7, 29)?,
        fault_store.clone(),
        CoordinationActorConfig::new(256, 32, Duration::from_secs(2), Duration::from_secs(5))?,
    )?);
    let router = Arc::new(ApiRouter::new(runtime));
    let created = router.execute(
        &principal,
        ApiRequest::CreateSession {
            body: decode_session_create(CREATE_JSON)?,
            idempotency_key: Uuid::new_v4().to_string(),
            received_at: Instant::now(),
        },
    )?;
    assert!(matches!(created, ApiResponse::SessionCreate(_)));
    let session_id = worker.session_id.clone();
    Ok((
        Fixture {
            principal,
            worker,
            router,
            store,
            outbox: None,
            session_id,
            pending_entered,
        },
        fault_store,
    ))
}

fn exercise_exposure_failure(fault: ExposureFault) -> Result<(), Box<dyn Error>> {
    let (fixture, fault_store) = fault_fixture(fault)?;
    let _release_on_exit = ReleasePendingOnDrop(fixture.worker.pending_gate.clone());
    let router = fixture.router.clone();
    let principal = fixture.principal.clone();
    let key = Uuid::new_v4();
    let command = fixture.command(key);
    let (accepted_tx, accepted_rx) = mpsc::sync_channel(1);
    let (result_tx, result_rx) = mpsc::sync_channel(1);
    let caller = thread::spawn(move || {
        let result = router
            .execute_with_action_acceptance(
                &principal,
                ApiRequest::SubmitAction(command),
                &mut |accepted| {
                    accepted_tx.try_send(accepted).expect("one acceptance");
                },
            )
            .map_err(|error| error.to_string())
            .and_then(action_snapshot);
        let _ = result_tx.send(result);
    });
    let accepted = accepted_rx.recv_timeout(Duration::from_secs(5))?;
    fixture
        .pending_entered
        .recv_timeout(Duration::from_secs(5))
        .map_err(
            |_| "the original pending completion was abandoned after exposure persistence failed",
        )?;
    assert_eq!(fault_store.calls.load(Ordering::Acquire), 1);
    assert_eq!(fixture.worker.enqueue_count.load(Ordering::Acquire), 1);
    assert!(
        matches!(result_rx.try_recv(), Err(mpsc::TryRecvError::Empty)),
        "even a terminal CAS winner must not abandon the original pending completion"
    );
    let before_completion = stored_action(
        fixture.store.as_ref(),
        fixture.principal.tenant_id(),
        &fixture.session_id,
        accepted.data().action_id(),
    )?;
    match fault {
        ExposureFault::StoreUnavailable => {
            assert!(before_completion.terminal().is_none());
            assert!(matches!(
                before_completion.delivery(),
                browserd_actions::ActionDeliveryEvidence::DispatchArmed(_)
            ));
        }
        ExposureFault::CommitThenUnavailable => {
            assert!(before_completion.terminal().is_none());
            assert!(matches!(
                before_completion.delivery(),
                browserd_actions::ActionDeliveryEvidence::ExposurePossible(_)
            ));
        }
        ExposureFault::TerminalWonRace => assert_eq!(
            before_completion
                .terminal()
                .map(|terminal| terminal.detail()),
            Some(TerminalDetail::OutcomeUnknown(
                OutcomeUnknownReason::TimeoutAfterDispatch
            ))
        ),
    }
    fixture.worker.pending_gate.release()?;
    let completed = result_rx.recv_timeout(Duration::from_secs(5))??;
    caller
        .join()
        .map_err(|_| "exposure recovery submit thread panicked")?;
    assert!(
        matches!(
            fixture.pending_entered.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ),
        "the pending operation must be consumed exactly once"
    );
    assert_eq!(completed.action_id(), accepted.data().action_id());
    assert_eq!(
        completed.action_sequence(),
        accepted.data().action_sequence()
    );
    let durable = stored_action(
        fixture.store.as_ref(),
        fixture.principal.tenant_id(),
        &fixture.session_id,
        completed.action_id(),
    )?;
    match fault {
        ExposureFault::StoreUnavailable | ExposureFault::CommitThenUnavailable => {
            assert_eq!(completed.state(), ActionState::Succeeded);
            assert_eq!(completed.result_content(), Some(SUCCEEDED_RESULT_BODY));
            assert_eq!(durable.result_content(), Some(SUCCEEDED_RESULT_BODY));
            assert_eq!(
                durable.terminal().map(|terminal| terminal.detail()),
                completed.terminal_detail()
            );
        }
        ExposureFault::TerminalWonRace => {
            assert_eq!(
                completed.terminal_detail(),
                Some(TerminalDetail::OutcomeUnknown(
                    OutcomeUnknownReason::TimeoutAfterDispatch
                ))
            );
            assert_eq!(
                durable, before_completion,
                "the late successful receipt cannot replace a winning durable terminal"
            );
            assert!(completed.result_content().is_none());
        }
    }
    let replay = action_snapshot(fixture.router.execute(
        &fixture.principal,
        ApiRequest::SubmitAction(fixture.command(key)),
    )?)?;
    assert_eq!(replay, completed);
    if matches!(fault, ExposureFault::CommitThenUnavailable) {
        assert_eq!(
            fault_store.result_calls.load(Ordering::Acquire),
            2,
            "the original successful receipt must converge after one stale revision CAS"
        );
    }
    assert_eq!(fixture.worker.enqueue_count.load(Ordering::Acquire), 1);
    assert_eq!(
        fixture.worker.request_count.load(Ordering::Acquire),
        0,
        "the original completion alone must suffice; no recovery re-dispatch or worker query"
    );
    Ok(())
}

#[test]
fn exposure_persistence_unavailable_still_consumes_the_original_completion_once()
-> Result<(), Box<dyn Error>> {
    exercise_exposure_failure(ExposureFault::StoreUnavailable)
}

#[test]
fn exposure_stale_cas_terminal_winner_is_preserved_after_draining_original_completion()
-> Result<(), Box<dyn Error>> {
    exercise_exposure_failure(ExposureFault::TerminalWonRace)
}

#[test]
fn committed_exposure_with_lost_reply_persists_original_success_after_one_cas_retry()
-> Result<(), Box<dyn Error>> {
    exercise_exposure_failure(ExposureFault::CommitThenUnavailable)
}
