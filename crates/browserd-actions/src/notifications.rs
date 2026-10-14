//! Notification metadata derived from the same durable action transition.
use browserd_core::{
    ActionState, ApprovalId, NotificationActionResolution, NotificationApprovalDecision,
    NotificationCommit, NotificationDescriptor, NotificationSessionScope, NotificationSourceFamily,
    NotificationSourceScope, WorkerNotificationEvent,
};

use crate::{
    JournalEntry, JournalEntryKind, JournalError, JournalSessionScope, KnownFailureReason,
    ResolutionKind, TerminalDetail,
};

pub(crate) fn source_scope(
    scope: &JournalSessionScope,
) -> Result<NotificationSourceScope, JournalError> {
    NotificationSourceScope::new(
        scope.tenant_id().clone(),
        scope.original_worker_id().clone(),
        *scope.session_id().as_uuid(),
        NotificationSourceFamily::ActionJournal,
    )
    .map_err(|_| JournalError::new("action notification source scope is invalid"))
}

pub(crate) fn events_for_entry(
    entry: &JournalEntry,
    approval_id: Option<&ApprovalId>,
    approval_decided: bool,
) -> Result<Vec<WorkerNotificationEvent>, JournalError> {
    let (state, resolution) = match entry.kind() {
        JournalEntryKind::Accepted { .. } => (ActionState::Accepted, None),
        JournalEntryKind::Enqueued => (ActionState::Queued, None),
        JournalEntryKind::ApprovalRequired => (ActionState::PendingApproval, None),
        JournalEntryKind::ApprovalGranted | JournalEntryKind::ReadyToDispatch => {
            (ActionState::ReadyToDispatch, None)
        }
        JournalEntryKind::DispatchIntent { .. } => (ActionState::MayHaveExecuted, None),
        JournalEntryKind::DispatchAcknowledged { .. } => return Ok(Vec::new()),
        JournalEntryKind::Terminal { detail } => (detail.state(), None),
        JournalEntryKind::Resolved { annotation } => (
            ActionState::OutcomeUnknown,
            Some(match annotation.kind() {
                ResolutionKind::ConfirmedExecuted => {
                    NotificationActionResolution::ConfirmedExecuted
                }
                ResolutionKind::ConfirmedNotExecuted => {
                    NotificationActionResolution::ConfirmedNotExecuted
                }
                ResolutionKind::Abandoned => NotificationActionResolution::Abandoned,
            }),
        ),
    };
    let mut events = vec![WorkerNotificationEvent::ActionStateChanged {
        action_id: entry.action_id().clone(),
        state: state.into(),
        resolution,
    }];
    if matches!(entry.kind(), JournalEntryKind::ApprovalRequired) {
        events.push(WorkerNotificationEvent::ActionApprovalRequired {
            action_id: entry.action_id().clone(),
            approval_id: approval_id.cloned().ok_or_else(|| {
                JournalError::new("notifying approval requirement has no durable identity")
            })?,
        });
    }
    let decision = match entry.kind() {
        JournalEntryKind::ApprovalGranted => Some(NotificationApprovalDecision::Approved),
        JournalEntryKind::Terminal {
            detail: TerminalDetail::FailedKnown(KnownFailureReason::ApprovalDenied),
        } => Some(NotificationApprovalDecision::Denied),
        JournalEntryKind::Terminal {
            detail: TerminalDetail::FailedKnown(KnownFailureReason::ApprovalTimedOut),
        } => Some(NotificationApprovalDecision::Expired),
        JournalEntryKind::Terminal {
            detail: TerminalDetail::CancelledBeforeDispatch,
        } if approval_id.is_some() && !approval_decided => {
            Some(NotificationApprovalDecision::Expired)
        }
        _ => None,
    };
    if let Some(state) = decision {
        events.push(WorkerNotificationEvent::ApprovalDecided {
            action_id: entry.action_id().clone(),
            approval_id: approval_id.cloned().ok_or_else(|| {
                JournalError::new("notifying approval decision has no original identity")
            })?,
            state,
        });
    }
    Ok(events)
}

pub(crate) fn commit_for_entry(
    source: &NotificationSourceScope,
    sequence: u64,
    occurred_at_ms: u64,
    entry: &JournalEntry,
    approval_id: Option<&ApprovalId>,
    approval_decided: bool,
) -> Result<Option<NotificationCommit>, JournalError> {
    if source.tenant_id() != entry.tenant_id()
        || source.source_id() != *entry.session_id().as_uuid()
        || source.family() != NotificationSourceFamily::ActionJournal
    {
        return Err(JournalError::new(
            "action notification source does not match original authority",
        ));
    }
    let events = events_for_entry(entry, approval_id, approval_decided)?;
    if events.is_empty() {
        return Ok(None);
    }
    let session = NotificationSessionScope::new(entry.session_id().clone(), entry.fence())
        .map_err(|_| JournalError::new("action notification session scope is invalid"))?;
    let descriptors = events
        .into_iter()
        .map(|event| NotificationDescriptor::fresh(session.clone(), event))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| JournalError::new("action notification descriptor is invalid"))?;
    NotificationCommit::new(source.clone(), sequence, occurred_at_ms, descriptors)
        .map(Some)
        .map_err(|_| JournalError::new("action notification commit is invalid"))
}

pub(crate) fn validate_entry_notification(
    entry: &JournalEntry,
    source: &NotificationSourceScope,
    sequence: u64,
    approval_id: Option<&ApprovalId>,
    approval_decided: bool,
) -> Result<(), JournalError> {
    if source.tenant_id() != entry.tenant_id()
        || source.source_id() != *entry.session_id().as_uuid()
        || source.family() != NotificationSourceFamily::ActionJournal
    {
        return Err(JournalError::new(
            "action notification metadata source contradicts original authority",
        ));
    }
    let expected = events_for_entry(entry, approval_id, approval_decided)?;
    if expected.is_empty() {
        if entry.notifications().is_some() {
            return Err(JournalError::new(
                "unchanged action transition carries a notification",
            ));
        }
        return Ok(());
    }
    let commit = entry.notifications().ok_or_else(|| {
        JournalError::new("notifying action transition lost its original metadata")
    })?;
    commit
        .validate()
        .map_err(|_| JournalError::new("action notification metadata is invalid"))?;
    if commit.scope() != source
        || commit.source_sequence() != sequence
        || commit.descriptors().len() != expected.len()
        || commit.descriptors().iter().zip(expected).any(|(d, event)| {
            d.session_scope().session_id() != entry.session_id()
                || d.session_scope().fence() != entry.fence()
                || d.event() != &event
        })
    {
        return Err(JournalError::new(
            "action notification metadata contradicts original authority",
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionNotificationPage {
    pub commits: Vec<NotificationCommit>,
    pub cursor: Option<browserd_core::SessionId>,
    pub examined: usize,
    pub is_complete: bool,
}

#[cfg(test)]
mod tests;
