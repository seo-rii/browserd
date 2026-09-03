use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use browserd_core::{ActionId, ActionState, LeaseId, PlacementFence};

use crate::{
    AcceptDecision, ActionLedgerError, ActionRequest, ActionSequence, ActionSnapshot,
    ApprovalDecision, BrowserResult, DispatchDecision, DispatchId, DispatchPermit,
    DurableActionJournal, IdempotencyKey, JournalEntry, JournalEntryKind, JournalError,
    KnownFailureReason, LedgerSession, OutcomeUnknownReason, RecordOutcome,
    ReplayableActionJournal, ResolutionAnnotation, ResolutionKind, ResolutionOutcome,
    ResolutionPolicy, TerminalDetail, TransportLoss,
};

#[derive(Default)]
struct LedgerState {
    last_sequence: u64,
    idempotency: HashMap<IdempotencyKey, ActionId>,
    actions: HashMap<ActionId, ActionSnapshot>,
}

pub struct ActionLedger<J> {
    session: LedgerSession,
    journal: Arc<J>,
    state: Mutex<LedgerState>,
}

impl<J> ActionLedger<J>
where
    J: DurableActionJournal,
{
    #[must_use]
    pub fn new(session: LedgerSession, journal: Arc<J>) -> Self {
        Self {
            session,
            journal,
            state: Mutex::new(LedgerState::default()),
        }
    }

    pub fn recover(session: LedgerSession, journal: Arc<J>) -> Result<Self, ActionLedgerError>
    where
        J: ReplayableActionJournal,
    {
        let entries = journal
            .replay()
            .map_err(ActionLedgerError::JournalUnavailable)?;
        let mut state = LedgerState::default();

        for (index, entry) in entries.into_iter().enumerate() {
            let invalid = |reason: &str| {
                ActionLedgerError::RecoveryInvalid(JournalError::new(format!(
                    "invalid action journal record {}: {reason}",
                    index + 1
                )))
            };
            if entry.tenant_id() != session.tenant_id()
                || entry.session_id() != session.session_id()
                || entry.fence() != session.fence()
            {
                return Err(invalid("ledger session scope does not match"));
            }

            let action_id = entry.action_id().clone();
            let action_sequence = entry.action_sequence();
            match entry.kind().clone() {
                JournalEntryKind::Accepted {
                    idempotency_key,
                    canonical_request_hash,
                    action_kind,
                } => {
                    let expected_sequence = state
                        .last_sequence
                        .checked_add(1)
                        .ok_or(ActionLedgerError::SequenceExhausted)?;
                    if action_sequence.get() < expected_sequence {
                        return Err(invalid("accepted action sequence is not monotonic"));
                    }
                    if state.actions.contains_key(&action_id)
                        || state.idempotency.contains_key(&idempotency_key)
                    {
                        return Err(invalid("duplicate action or idempotency key"));
                    }
                    let request = ActionRequest::new(
                        idempotency_key.clone(),
                        canonical_request_hash,
                        action_kind,
                    );
                    let snapshot = ActionSnapshot {
                        action_id: action_id.clone(),
                        action_sequence,
                        request,
                        state: ActionState::Accepted,
                        dispatch_permit: None,
                        dispatch_acknowledged: false,
                        approval_decision: None,
                        terminal_detail: None,
                        resolution: None,
                        result_content: None,
                    };
                    state.last_sequence = action_sequence.get();
                    state.idempotency.insert(idempotency_key, action_id.clone());
                    state.actions.insert(action_id, snapshot);
                }
                kind => {
                    let snapshot = state
                        .actions
                        .get_mut(&action_id)
                        .ok_or_else(|| invalid("record references an unknown action"))?;
                    if snapshot.action_sequence() != action_sequence {
                        return Err(invalid("record action sequence does not match acceptance"));
                    }
                    match kind {
                        JournalEntryKind::Enqueued => {
                            if snapshot.state() != ActionState::Accepted {
                                return Err(invalid("enqueue transition is not valid"));
                            }
                            snapshot.state = ActionState::Queued;
                        }
                        JournalEntryKind::ApprovalRequired => {
                            if snapshot.state() != ActionState::Queued
                                || snapshot.approval_decision().is_some()
                            {
                                return Err(invalid(
                                    "approval requirement transition is not valid",
                                ));
                            }
                            snapshot.state = ActionState::PendingApproval;
                        }
                        JournalEntryKind::ApprovalGranted => {
                            if snapshot.state() != ActionState::PendingApproval
                                || snapshot.approval_decision().is_some()
                            {
                                return Err(invalid("approval grant transition is not valid"));
                            }
                            snapshot.state = ActionState::ReadyToDispatch;
                            snapshot.approval_decision = Some(ApprovalDecision::Granted);
                        }
                        JournalEntryKind::ReadyToDispatch => {
                            if snapshot.state() != ActionState::Queued {
                                return Err(invalid("ready transition is not valid"));
                            }
                            snapshot.state = ActionState::ReadyToDispatch;
                        }
                        JournalEntryKind::DispatchIntent { dispatch_id } => {
                            if snapshot.state() != ActionState::ReadyToDispatch
                                || snapshot.dispatch_permit().is_some()
                            {
                                return Err(invalid("dispatch intent transition is not valid"));
                            }
                            snapshot.state = ActionState::MayHaveExecuted;
                            snapshot.dispatch_permit = Some(DispatchPermit {
                                action_id,
                                action_sequence,
                                dispatch_id,
                            });
                        }
                        JournalEntryKind::DispatchAcknowledged { dispatch_id } => {
                            let Some(permit) = snapshot.dispatch_permit() else {
                                return Err(invalid("dispatch acknowledgement has no intent"));
                            };
                            if snapshot.state() != ActionState::MayHaveExecuted
                                || snapshot.dispatch_acknowledged()
                                || permit.dispatch_id() != &dispatch_id
                            {
                                return Err(invalid(
                                    "dispatch acknowledgement does not match its intent",
                                ));
                            }
                            snapshot.dispatch_acknowledged = true;
                        }
                        JournalEntryKind::Terminal { detail } => {
                            if snapshot.terminal_detail().is_some() {
                                return Err(invalid("action has more than one terminal record"));
                            }
                            let attempted_approval = match detail {
                                TerminalDetail::FailedKnown(KnownFailureReason::ApprovalDenied) => {
                                    Some(ApprovalDecision::Denied)
                                }
                                TerminalDetail::FailedKnown(
                                    KnownFailureReason::ApprovalTimedOut,
                                ) => Some(ApprovalDecision::TimedOut),
                                _ => None,
                            };
                            let approval_decision = (snapshot.state()
                                == ActionState::PendingApproval)
                                .then_some(attempted_approval)
                                .flatten();
                            if detail == TerminalDetail::CancelledBeforeDispatch {
                                if !matches!(
                                    snapshot.state(),
                                    ActionState::Accepted
                                        | ActionState::Queued
                                        | ActionState::PendingApproval
                                        | ActionState::ReadyToDispatch
                                ) {
                                    return Err(invalid(
                                        "pre-dispatch cancellation follows a dispatch intent",
                                    ));
                                }
                            } else if approval_decision.is_some() {
                                if snapshot.approval_decision().is_some() {
                                    return Err(invalid(
                                        "approval decision transition is not valid",
                                    ));
                                }
                            } else if attempted_approval.is_some() {
                                return Err(invalid(
                                    "approval failure does not follow a pending approval",
                                ));
                            } else if snapshot.state() != ActionState::MayHaveExecuted {
                                return Err(invalid("terminal result has no dispatch intent"));
                            }
                            if detail
                                == TerminalDetail::FailedKnown(KnownFailureReason::NotDispatched)
                                && snapshot.dispatch_acknowledged()
                            {
                                return Err(invalid(
                                    "not-dispatched result contradicts dispatch acknowledgement",
                                ));
                            }
                            snapshot.state = detail.state();
                            if approval_decision.is_some() {
                                snapshot.approval_decision = approval_decision;
                            }
                            snapshot.terminal_detail = Some(detail);
                        }
                        JournalEntryKind::Resolved { annotation } => {
                            if snapshot.state() != ActionState::OutcomeUnknown
                                || snapshot.resolution().is_some()
                            {
                                return Err(invalid("resolution is not valid for action state"));
                            }
                            snapshot.resolution = Some(annotation);
                        }
                        JournalEntryKind::Accepted { .. } => {
                            return Err(invalid("accepted record dispatch is inconsistent"));
                        }
                    }
                }
            }
        }

        let interrupted_dispatches = state
            .actions
            .values()
            .filter(|snapshot| snapshot.state() == ActionState::MayHaveExecuted)
            .map(|snapshot| (snapshot.action_id().clone(), snapshot.action_sequence()))
            .collect::<Vec<_>>();
        let detail = TerminalDetail::OutcomeUnknown(OutcomeUnknownReason::WorkerLost);
        for (action_id, action_sequence) in interrupted_dispatches {
            journal
                .append(&JournalEntry::new(
                    &session,
                    action_id.clone(),
                    action_sequence,
                    JournalEntryKind::Terminal { detail },
                ))
                .map_err(ActionLedgerError::JournalUnavailable)?;
            let snapshot = state
                .actions
                .get_mut(&action_id)
                .ok_or(ActionLedgerError::StateUnavailable)?;
            snapshot.state = detail.state();
            snapshot.terminal_detail = Some(detail);
        }

        Ok(Self {
            session,
            journal,
            state: Mutex::new(state),
        })
    }

    #[must_use]
    pub const fn session(&self) -> &LedgerSession {
        &self.session
    }

    pub fn accept(
        &self,
        fence: PlacementFence,
        request: ActionRequest,
    ) -> Result<AcceptDecision, ActionLedgerError> {
        self.check_fence(fence)?;
        let mut state = self.lock_state()?;
        self.accept_locked(&mut state, ActionId::new(), None, request)
    }

    pub fn accept_with_identity(
        &self,
        fence: PlacementFence,
        proposed_action_id: ActionId,
        proposed_action_sequence: ActionSequence,
        request: ActionRequest,
    ) -> Result<AcceptDecision, ActionLedgerError> {
        self.check_fence(fence)?;
        let mut state = self.lock_state()?;
        self.accept_locked(
            &mut state,
            proposed_action_id,
            Some(proposed_action_sequence),
            request,
        )
    }

    fn accept_locked(
        &self,
        state: &mut LedgerState,
        proposed_action_id: ActionId,
        proposed_action_sequence: Option<ActionSequence>,
        request: ActionRequest,
    ) -> Result<AcceptDecision, ActionLedgerError> {
        if let Some(action_id) = state.idempotency.get(request.idempotency_key()) {
            let snapshot = state
                .actions
                .get(action_id)
                .ok_or(ActionLedgerError::StateUnavailable)?;
            if snapshot.request().canonical_request_hash() != request.canonical_request_hash()
                || snapshot.request().kind() != request.kind()
            {
                return Err(ActionLedgerError::IdempotencyConflict {
                    existing_action_id: action_id.clone(),
                });
            }
            if proposed_action_sequence.is_some_and(|proposed_action_sequence| {
                action_id != &proposed_action_id
                    || snapshot.action_sequence() != proposed_action_sequence
            }) {
                return Err(ActionLedgerError::ActionIdentityConflict {
                    existing_action_id: action_id.clone(),
                });
            }
            return Ok(AcceptDecision::Existing(snapshot.clone()));
        }
        if state.actions.contains_key(&proposed_action_id) {
            return Err(ActionLedgerError::ActionIdentityConflict {
                existing_action_id: proposed_action_id,
            });
        }

        let expected_sequence = state
            .last_sequence
            .checked_add(1)
            .ok_or(ActionLedgerError::SequenceExhausted)?;
        let proposed_action_sequence =
            proposed_action_sequence.unwrap_or_else(|| ActionSequence::new(expected_sequence));
        if proposed_action_sequence.get() < expected_sequence {
            return Err(ActionLedgerError::ActionSequenceConflict {
                expected: ActionSequence::new(expected_sequence),
                received: proposed_action_sequence,
            });
        }
        let action_id = proposed_action_id;
        let snapshot = ActionSnapshot {
            action_id: action_id.clone(),
            action_sequence: proposed_action_sequence,
            request: request.clone(),
            state: ActionState::Accepted,
            dispatch_permit: None,
            dispatch_acknowledged: false,
            approval_decision: None,
            terminal_detail: None,
            resolution: None,
            result_content: None,
        };
        self.append(JournalEntry::new(
            &self.session,
            action_id.clone(),
            snapshot.action_sequence(),
            JournalEntryKind::Accepted {
                idempotency_key: request.idempotency_key().clone(),
                canonical_request_hash: request.canonical_request_hash(),
                action_kind: request.kind(),
            },
        ))?;

        state.last_sequence = proposed_action_sequence.get();
        state
            .idempotency
            .insert(request.idempotency_key().clone(), action_id.clone());
        state.actions.insert(action_id, snapshot.clone());
        Ok(AcceptDecision::Created(snapshot))
    }

    pub fn enqueue(
        &self,
        fence: PlacementFence,
        action_id: &ActionId,
    ) -> Result<ActionSnapshot, ActionLedgerError> {
        self.transition_action(
            fence,
            action_id,
            ActionState::Accepted,
            ActionState::Queued,
            JournalEntryKind::Enqueued,
        )
    }

    pub fn require_approval(
        &self,
        fence: PlacementFence,
        action_id: &ActionId,
    ) -> Result<ActionSnapshot, ActionLedgerError> {
        self.transition_action(
            fence,
            action_id,
            ActionState::Queued,
            ActionState::PendingApproval,
            JournalEntryKind::ApprovalRequired,
        )
    }

    pub fn grant_approval(
        &self,
        fence: PlacementFence,
        action_id: &ActionId,
    ) -> Result<ActionSnapshot, ActionLedgerError> {
        self.check_fence(fence)?;
        let mut state = self.lock_state()?;
        let snapshot = state
            .actions
            .get(action_id)
            .cloned()
            .ok_or(ActionLedgerError::ActionNotFound)?;
        if let Some(current) = snapshot.approval_decision() {
            return if current == ApprovalDecision::Granted {
                Ok(snapshot)
            } else {
                Err(ActionLedgerError::ApprovalDecisionConflict {
                    current,
                    attempted: ApprovalDecision::Granted,
                })
            };
        }
        if snapshot.state() != ActionState::PendingApproval {
            return Err(ActionLedgerError::InvalidTransition {
                state: snapshot.state(),
            });
        }

        self.append(JournalEntry::new(
            &self.session,
            action_id.clone(),
            snapshot.action_sequence(),
            JournalEntryKind::ApprovalGranted,
        ))?;
        let stored = state
            .actions
            .get_mut(action_id)
            .ok_or(ActionLedgerError::StateUnavailable)?;
        stored.state = ActionState::ReadyToDispatch;
        stored.approval_decision = Some(ApprovalDecision::Granted);
        Ok(stored.clone())
    }

    pub fn deny_approval(
        &self,
        fence: PlacementFence,
        action_id: &ActionId,
    ) -> Result<RecordOutcome, ActionLedgerError> {
        self.record_approval_failure(fence, action_id, ApprovalDecision::Denied)
    }

    pub fn expire_approval(
        &self,
        fence: PlacementFence,
        action_id: &ActionId,
    ) -> Result<RecordOutcome, ActionLedgerError> {
        self.record_approval_failure(fence, action_id, ApprovalDecision::TimedOut)
    }

    pub fn mark_ready(
        &self,
        fence: PlacementFence,
        action_id: &ActionId,
    ) -> Result<ActionSnapshot, ActionLedgerError> {
        self.transition_action(
            fence,
            action_id,
            ActionState::Queued,
            ActionState::ReadyToDispatch,
            JournalEntryKind::ReadyToDispatch,
        )
    }

    pub fn snapshot(
        &self,
        fence: PlacementFence,
        action_id: &ActionId,
    ) -> Result<ActionSnapshot, ActionLedgerError> {
        self.check_fence(fence)?;
        self.lock_state()?
            .actions
            .get(action_id)
            .cloned()
            .ok_or(ActionLedgerError::ActionNotFound)
    }

    pub fn prepare_dispatch(
        &self,
        fence: PlacementFence,
        action_id: &ActionId,
    ) -> Result<DispatchDecision, ActionLedgerError> {
        self.check_fence(fence)?;
        let mut state = self.lock_state()?;
        let snapshot = state
            .actions
            .get(action_id)
            .cloned()
            .ok_or(ActionLedgerError::ActionNotFound)?;

        if snapshot.state() == ActionState::ReadyToDispatch {
            let permit = DispatchPermit {
                action_id: action_id.clone(),
                action_sequence: snapshot.action_sequence(),
                dispatch_id: DispatchId(LeaseId::new()),
            };
            self.append(JournalEntry::new(
                &self.session,
                action_id.clone(),
                snapshot.action_sequence(),
                JournalEntryKind::DispatchIntent {
                    dispatch_id: permit.dispatch_id().clone(),
                },
            ))?;

            let stored = state
                .actions
                .get_mut(action_id)
                .ok_or(ActionLedgerError::StateUnavailable)?;
            stored.state = ActionState::MayHaveExecuted;
            stored.dispatch_permit = Some(permit.clone());
            return Ok(DispatchDecision::Dispatch(permit));
        }

        if snapshot.dispatch_permit().is_some() || snapshot.state().is_terminal() {
            return Ok(DispatchDecision::DoNotReplay(Box::new(snapshot)));
        }

        Err(ActionLedgerError::InvalidTransition {
            state: snapshot.state(),
        })
    }

    pub fn record_ack(
        &self,
        fence: PlacementFence,
        permit: &DispatchPermit,
    ) -> Result<RecordOutcome, ActionLedgerError> {
        self.check_fence(fence)?;
        let mut state = self.lock_state()?;
        let snapshot = self.correlated_snapshot(&state, permit)?;
        if snapshot.dispatch_acknowledged() {
            return Ok(RecordOutcome::AlreadyRecorded);
        }
        if snapshot.state() != ActionState::MayHaveExecuted {
            return Err(ActionLedgerError::InvalidTransition {
                state: snapshot.state(),
            });
        }

        self.append(JournalEntry::new(
            &self.session,
            permit.action_id().clone(),
            permit.action_sequence(),
            JournalEntryKind::DispatchAcknowledged {
                dispatch_id: permit.dispatch_id().clone(),
            },
        ))?;
        state
            .actions
            .get_mut(permit.action_id())
            .ok_or(ActionLedgerError::StateUnavailable)?
            .dispatch_acknowledged = true;
        Ok(RecordOutcome::Recorded)
    }

    pub fn record_result(
        &self,
        fence: PlacementFence,
        permit: &DispatchPermit,
        result: BrowserResult,
    ) -> Result<RecordOutcome, ActionLedgerError> {
        let detail = match result {
            BrowserResult::Succeeded(digest) => TerminalDetail::Succeeded(digest),
            BrowserResult::FailedKnown(reason) => TerminalDetail::FailedKnown(reason),
            BrowserResult::CancellationConfirmed => TerminalDetail::CancelledConfirmed,
        };
        self.record_terminal(fence, permit, detail)
    }

    pub fn record_transport_loss(
        &self,
        fence: PlacementFence,
        permit: &DispatchPermit,
        loss: TransportLoss,
    ) -> Result<RecordOutcome, ActionLedgerError> {
        let detail = match loss {
            TransportLoss::ConfirmedNotWritten => {
                TerminalDetail::FailedKnown(KnownFailureReason::NotDispatched)
            }
            TransportLoss::Ambiguous(reason) => TerminalDetail::OutcomeUnknown(reason),
        };
        self.record_terminal(fence, permit, detail)
    }

    pub fn cancel_before_dispatch(
        &self,
        fence: PlacementFence,
        action_id: &ActionId,
    ) -> Result<RecordOutcome, ActionLedgerError> {
        self.check_fence(fence)?;
        let mut state = self.lock_state()?;
        let snapshot = state
            .actions
            .get(action_id)
            .cloned()
            .ok_or(ActionLedgerError::ActionNotFound)?;
        let attempted = TerminalDetail::CancelledBeforeDispatch;

        if let Some(current) = snapshot.terminal_detail() {
            return if current == attempted {
                Ok(RecordOutcome::AlreadyRecorded)
            } else {
                Err(ActionLedgerError::TerminalStateConflict { current, attempted })
            };
        }
        if !matches!(
            snapshot.state(),
            ActionState::Accepted
                | ActionState::Queued
                | ActionState::PendingApproval
                | ActionState::ReadyToDispatch
        ) {
            return Err(ActionLedgerError::InvalidTransition {
                state: snapshot.state(),
            });
        }

        self.append(JournalEntry::new(
            &self.session,
            action_id.clone(),
            snapshot.action_sequence(),
            JournalEntryKind::Terminal { detail: attempted },
        ))?;
        let stored = state
            .actions
            .get_mut(action_id)
            .ok_or(ActionLedgerError::StateUnavailable)?;
        stored.state = attempted.state();
        stored.terminal_detail = Some(attempted);
        Ok(RecordOutcome::Recorded)
    }

    pub fn resolve(
        &self,
        fence: PlacementFence,
        action_id: &ActionId,
        annotation: ResolutionAnnotation,
        policy: ResolutionPolicy,
    ) -> Result<ResolutionOutcome, ActionLedgerError> {
        self.check_fence(fence)?;
        let mut state = self.lock_state()?;
        let snapshot = state
            .actions
            .get(action_id)
            .cloned()
            .ok_or(ActionLedgerError::ActionNotFound)?;

        if snapshot.state() != ActionState::OutcomeUnknown {
            return Err(ActionLedgerError::ResolutionInvalid);
        }
        if let Some(existing) = snapshot.resolution() {
            return if existing == &annotation {
                Ok(ResolutionOutcome::AlreadyRecorded(snapshot))
            } else {
                Err(ActionLedgerError::ResolutionConflict)
            };
        }
        if annotation.kind() == ResolutionKind::Abandoned && !policy.allow_abandoned() {
            return Err(ActionLedgerError::AbandonedResolutionDenied);
        }

        self.append(JournalEntry::new(
            &self.session,
            action_id.clone(),
            snapshot.action_sequence(),
            JournalEntryKind::Resolved {
                annotation: annotation.clone(),
            },
        ))?;
        let stored = state
            .actions
            .get_mut(action_id)
            .ok_or(ActionLedgerError::StateUnavailable)?;
        stored.resolution = Some(annotation);
        Ok(ResolutionOutcome::Recorded(stored.clone()))
    }

    fn check_fence(&self, received: PlacementFence) -> Result<(), ActionLedgerError> {
        let expected = self.session.fence();
        if received == expected {
            Ok(())
        } else {
            Err(ActionLedgerError::StaleFence { expected, received })
        }
    }

    fn lock_state(&self) -> Result<MutexGuard<'_, LedgerState>, ActionLedgerError> {
        self.state
            .lock()
            .map_err(|_| ActionLedgerError::StateUnavailable)
    }

    fn append(&self, entry: JournalEntry) -> Result<(), ActionLedgerError> {
        self.journal
            .append(&entry)
            .map_err(ActionLedgerError::JournalUnavailable)
    }

    fn transition_action(
        &self,
        fence: PlacementFence,
        action_id: &ActionId,
        from: ActionState,
        to: ActionState,
        journal_kind: JournalEntryKind,
    ) -> Result<ActionSnapshot, ActionLedgerError> {
        self.check_fence(fence)?;
        let mut state = self.lock_state()?;
        let snapshot = state
            .actions
            .get(action_id)
            .cloned()
            .ok_or(ActionLedgerError::ActionNotFound)?;
        if snapshot.state() == to {
            return Ok(snapshot);
        }
        if snapshot.state() != from {
            return Err(ActionLedgerError::InvalidTransition {
                state: snapshot.state(),
            });
        }
        self.append(JournalEntry::new(
            &self.session,
            action_id.clone(),
            snapshot.action_sequence(),
            journal_kind,
        ))?;
        let stored = state
            .actions
            .get_mut(action_id)
            .ok_or(ActionLedgerError::StateUnavailable)?;
        stored.state = to;
        Ok(stored.clone())
    }

    fn correlated_snapshot(
        &self,
        state: &LedgerState,
        permit: &DispatchPermit,
    ) -> Result<ActionSnapshot, ActionLedgerError> {
        let snapshot = state
            .actions
            .get(permit.action_id())
            .ok_or(ActionLedgerError::CorrelationMismatch)?;
        if snapshot.dispatch_permit() != Some(permit) {
            return Err(ActionLedgerError::CorrelationMismatch);
        }
        Ok(snapshot.clone())
    }

    fn record_terminal(
        &self,
        fence: PlacementFence,
        permit: &DispatchPermit,
        attempted: TerminalDetail,
    ) -> Result<RecordOutcome, ActionLedgerError> {
        self.check_fence(fence)?;
        let mut state = self.lock_state()?;
        let snapshot = self.correlated_snapshot(&state, permit)?;
        if matches!(
            attempted,
            TerminalDetail::FailedKnown(
                KnownFailureReason::ApprovalDenied | KnownFailureReason::ApprovalTimedOut
            )
        ) {
            return Err(ActionLedgerError::InvalidTransition {
                state: snapshot.state(),
            });
        }
        if attempted == TerminalDetail::FailedKnown(KnownFailureReason::NotDispatched)
            && snapshot.dispatch_acknowledged()
        {
            return Err(ActionLedgerError::DeliveryEvidenceConflict);
        }
        if let Some(current) = snapshot.terminal_detail() {
            return if current == attempted {
                Ok(RecordOutcome::AlreadyRecorded)
            } else {
                Err(ActionLedgerError::TerminalStateConflict { current, attempted })
            };
        }
        if snapshot.state() != ActionState::MayHaveExecuted {
            return Err(ActionLedgerError::InvalidTransition {
                state: snapshot.state(),
            });
        }

        self.append(JournalEntry::new(
            &self.session,
            permit.action_id().clone(),
            permit.action_sequence(),
            JournalEntryKind::Terminal { detail: attempted },
        ))?;
        let stored = state
            .actions
            .get_mut(permit.action_id())
            .ok_or(ActionLedgerError::StateUnavailable)?;
        stored.state = attempted.state();
        stored.terminal_detail = Some(attempted);
        Ok(RecordOutcome::Recorded)
    }

    fn record_approval_failure(
        &self,
        fence: PlacementFence,
        action_id: &ActionId,
        attempted: ApprovalDecision,
    ) -> Result<RecordOutcome, ActionLedgerError> {
        self.check_fence(fence)?;
        let mut state = self.lock_state()?;
        let snapshot = state
            .actions
            .get(action_id)
            .cloned()
            .ok_or(ActionLedgerError::ActionNotFound)?;
        if let Some(current) = snapshot.approval_decision() {
            return if current == attempted {
                Ok(RecordOutcome::AlreadyRecorded)
            } else {
                Err(ActionLedgerError::ApprovalDecisionConflict { current, attempted })
            };
        }
        if snapshot.state() != ActionState::PendingApproval {
            return Err(ActionLedgerError::InvalidTransition {
                state: snapshot.state(),
            });
        }
        let detail = match attempted {
            ApprovalDecision::Denied => {
                TerminalDetail::FailedKnown(KnownFailureReason::ApprovalDenied)
            }
            ApprovalDecision::TimedOut => {
                TerminalDetail::FailedKnown(KnownFailureReason::ApprovalTimedOut)
            }
            ApprovalDecision::Granted => {
                return Err(ActionLedgerError::InvalidTransition {
                    state: snapshot.state(),
                });
            }
        };

        self.append(JournalEntry::new(
            &self.session,
            action_id.clone(),
            snapshot.action_sequence(),
            JournalEntryKind::Terminal { detail },
        ))?;
        let stored = state
            .actions
            .get_mut(action_id)
            .ok_or(ActionLedgerError::StateUnavailable)?;
        stored.state = ActionState::FailedKnown;
        stored.approval_decision = Some(attempted);
        stored.terminal_detail = Some(detail);
        Ok(RecordOutcome::Recorded)
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use browserd_core::{PlacementFence, SessionId, TenantId};

    use super::*;
    use crate::{ActionKind, CanonicalRequestHash};

    struct NoopJournal;

    impl DurableActionJournal for NoopJournal {
        fn append(&self, _entry: &JournalEntry) -> Result<(), JournalError> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct ReplayJournal {
        entries: Mutex<Vec<JournalEntry>>,
    }

    impl DurableActionJournal for ReplayJournal {
        fn append(&self, entry: &JournalEntry) -> Result<(), JournalError> {
            self.entries
                .lock()
                .map_err(|_| JournalError::new("journal lock poisoned"))?
                .push(entry.clone());
            Ok(())
        }
    }

    impl ReplayableActionJournal for ReplayJournal {
        fn replay(&self) -> Result<Vec<JournalEntry>, JournalError> {
            self.entries
                .lock()
                .map_err(|_| JournalError::new("journal lock poisoned"))
                .map(|entries| entries.clone())
        }
    }

    #[test]
    fn exact_retry_precedes_sequence_exhaustion() -> Result<(), Box<dyn Error>> {
        let fence = PlacementFence::new(7, 11, 1);
        let ledger = ActionLedger::new(
            LedgerSession::new(TenantId::new(), SessionId::new(), fence),
            Arc::new(NoopJournal),
        );
        let request = ActionRequest::new(
            IdempotencyKey::new("sequence-exhausted-retry"),
            CanonicalRequestHash::new([9; 32]),
            ActionKind::Mutating,
        );
        let created = ledger.accept(fence, request.clone())?;
        {
            let mut state = ledger
                .state
                .lock()
                .map_err(|_| std::io::Error::other("ledger state lock poisoned"))?;
            state.last_sequence = u64::MAX;
        }

        let retried = ledger.accept(fence, request)?;
        assert!(matches!(retried, AcceptDecision::Existing(_)));
        assert_eq!(
            retried.snapshot().action_id(),
            created.snapshot().action_id()
        );
        Ok(())
    }

    #[test]
    fn gateway_sequence_gaps_survive_recovery() -> Result<(), Box<dyn Error>> {
        let fence = PlacementFence::new(7, 11, 1);
        let session = LedgerSession::new(TenantId::new(), SessionId::new(), fence);
        let journal = Arc::new(ReplayJournal::default());
        let ledger = ActionLedger::new(session.clone(), Arc::clone(&journal));
        let accepted = ledger.accept_with_identity(
            fence,
            ActionId::new(),
            ActionSequence::new(4),
            ActionRequest::new(
                IdempotencyKey::new("gateway-sequence-after-known-gap"),
                CanonicalRequestHash::new([7; 32]),
                ActionKind::Mutating,
            ),
        )?;
        assert_eq!(
            accepted.snapshot().action_sequence(),
            ActionSequence::new(4)
        );

        let recovered = ActionLedger::recover(session, journal)?;
        assert_eq!(
            recovered
                .snapshot(fence, accepted.snapshot().action_id())?
                .action_sequence(),
            ActionSequence::new(4)
        );
        Ok(())
    }
}
