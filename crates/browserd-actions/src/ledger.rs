use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use browserd_core::{ActionId, ActionState, LeaseId, PlacementFence};

use crate::{
    AcceptDecision, ActionLedgerError, ActionRequest, ActionSequence, ActionSnapshot,
    BrowserResult, DispatchDecision, DispatchId, DispatchPermit, DurableActionJournal,
    IdempotencyKey, JournalEntry, JournalEntryKind, KnownFailureReason, LedgerSession,
    RecordOutcome, ResolutionAnnotation, ResolutionKind, ResolutionOutcome, ResolutionPolicy,
    TerminalDetail, TransportLoss,
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

        if let Some(action_id) = state.idempotency.get(request.idempotency_key()) {
            let snapshot = state
                .actions
                .get(action_id)
                .ok_or(ActionLedgerError::StateUnavailable)?;
            if snapshot.request().canonical_request_hash() != request.canonical_request_hash() {
                return Err(ActionLedgerError::IdempotencyConflict {
                    existing_action_id: action_id.clone(),
                });
            }
            return Ok(AcceptDecision::Existing(snapshot.clone()));
        }

        let sequence = state
            .last_sequence
            .checked_add(1)
            .ok_or(ActionLedgerError::SequenceExhausted)?;
        let action_id = ActionId::new();
        let snapshot = ActionSnapshot {
            action_id: action_id.clone(),
            action_sequence: ActionSequence::new(sequence),
            request: request.clone(),
            state: ActionState::Accepted,
            dispatch_permit: None,
            dispatch_acknowledged: false,
            terminal_detail: None,
            resolution: None,
        };
        self.append(JournalEntry {
            session_id: self.session.session_id().clone(),
            action_id: action_id.clone(),
            action_sequence: snapshot.action_sequence(),
            kind: JournalEntryKind::Accepted {
                idempotency_key: request.idempotency_key().clone(),
                canonical_request_hash: request.canonical_request_hash(),
                action_kind: request.kind(),
            },
        })?;

        state.last_sequence = sequence;
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
            self.append(JournalEntry {
                session_id: self.session.session_id().clone(),
                action_id: action_id.clone(),
                action_sequence: snapshot.action_sequence(),
                kind: JournalEntryKind::DispatchIntent {
                    dispatch_id: permit.dispatch_id().clone(),
                },
            })?;

            let stored = state
                .actions
                .get_mut(action_id)
                .ok_or(ActionLedgerError::StateUnavailable)?;
            stored.state = ActionState::MayHaveExecuted;
            stored.dispatch_permit = Some(permit.clone());
            return Ok(DispatchDecision::Dispatch(permit));
        }

        if snapshot.dispatch_permit().is_some() || snapshot.state().is_terminal() {
            return Ok(DispatchDecision::DoNotReplay(snapshot));
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

        self.append(JournalEntry {
            session_id: self.session.session_id().clone(),
            action_id: permit.action_id().clone(),
            action_sequence: permit.action_sequence(),
            kind: JournalEntryKind::DispatchAcknowledged {
                dispatch_id: permit.dispatch_id().clone(),
            },
        })?;
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

        self.append(JournalEntry {
            session_id: self.session.session_id().clone(),
            action_id: action_id.clone(),
            action_sequence: snapshot.action_sequence(),
            kind: JournalEntryKind::Terminal { detail: attempted },
        })?;
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
            return if existing.kind() == annotation.kind() {
                Ok(ResolutionOutcome::AlreadyRecorded(snapshot))
            } else {
                Err(ActionLedgerError::ResolutionConflict)
            };
        }
        if annotation.kind() == ResolutionKind::Abandoned && !policy.allow_abandoned() {
            return Err(ActionLedgerError::AbandonedResolutionDenied);
        }

        self.append(JournalEntry {
            session_id: self.session.session_id().clone(),
            action_id: action_id.clone(),
            action_sequence: snapshot.action_sequence(),
            kind: JournalEntryKind::Resolved {
                annotation: annotation.clone(),
            },
        })?;
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
        self.append(JournalEntry {
            session_id: self.session.session_id().clone(),
            action_id: action_id.clone(),
            action_sequence: snapshot.action_sequence(),
            kind: journal_kind,
        })?;
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

        self.append(JournalEntry {
            session_id: self.session.session_id().clone(),
            action_id: permit.action_id().clone(),
            action_sequence: permit.action_sequence(),
            kind: JournalEntryKind::Terminal { detail: attempted },
        })?;
        let stored = state
            .actions
            .get_mut(permit.action_id())
            .ok_or(ActionLedgerError::StateUnavailable)?;
        stored.state = attempted.state();
        stored.terminal_detail = Some(attempted);
        Ok(RecordOutcome::Recorded)
    }
}
