#![allow(clippy::expect_used)]

use browserd_actions::{
    ActionDeliveryEvidence, ActionEvidence, ActionEvidenceError, ActionEvidenceMutation,
    ActionTerminalEvidence, ActionTerminalSource, BrowserResult, DispatchId, KnownFailureReason,
    OutcomeUnknownReason, ResultDigest, TerminalDetail, TransportLoss,
};

#[test]
fn worker_loss_derivation_uses_the_durable_dispatch_boundary() {
    let mut evidence = ActionEvidence::new();
    assert_eq!(
        evidence.effective_terminal(true),
        Some(ActionTerminalEvidence::new(
            TerminalDetail::FailedKnown(KnownFailureReason::NotDispatched),
            ActionTerminalSource::WorkerLoss,
        ))
    );

    let dispatch_id = DispatchId::new();
    assert_eq!(
        evidence.arm_dispatch(dispatch_id.clone()),
        Ok(ActionEvidenceMutation::Recorded)
    );
    assert_eq!(
        evidence.delivery(),
        &ActionDeliveryEvidence::DispatchArmed(dispatch_id.clone())
    );
    assert_eq!(
        evidence.effective_terminal(true),
        Some(ActionTerminalEvidence::new(
            TerminalDetail::OutcomeUnknown(OutcomeUnknownReason::WorkerLost),
            ActionTerminalSource::WorkerLoss,
        ))
    );

    assert_eq!(
        evidence.mark_exposure_possible(&dispatch_id),
        Ok(ActionEvidenceMutation::Recorded)
    );
    assert_eq!(
        evidence.effective_terminal(true),
        Some(ActionTerminalEvidence::new(
            TerminalDetail::OutcomeUnknown(OutcomeUnknownReason::WorkerLost),
            ActionTerminalSource::WorkerLoss,
        ))
    );
}

#[test]
fn dispatch_attempt_is_idempotent_but_never_regresses_or_changes_identity() {
    let mut evidence = ActionEvidence::new();
    let first = DispatchId::new();
    let conflicting = DispatchId::new();

    assert_eq!(
        evidence.mark_exposure_possible(&first),
        Err(ActionEvidenceError::DispatchNotArmed)
    );
    assert_eq!(
        evidence.arm_dispatch(first.clone()),
        Ok(ActionEvidenceMutation::Recorded)
    );
    assert_eq!(
        evidence.arm_dispatch(first.clone()),
        Ok(ActionEvidenceMutation::AlreadyRecorded)
    );
    assert_eq!(
        evidence.arm_dispatch(conflicting.clone()),
        Err(ActionEvidenceError::DispatchAttemptConflict {
            current: first.clone(),
            attempted: conflicting,
        })
    );
    assert_eq!(
        evidence.mark_exposure_possible(&first),
        Ok(ActionEvidenceMutation::Recorded)
    );
    assert_eq!(
        evidence.arm_dispatch(first.clone()),
        Ok(ActionEvidenceMutation::AlreadyRecorded)
    );
    assert_eq!(
        evidence.delivery(),
        &ActionDeliveryEvidence::ExposurePossible(first)
    );
}

#[test]
fn proven_non_delivery_requires_the_matching_armed_attempt() {
    let mut evidence = ActionEvidence::new();
    let dispatch_id = DispatchId::new();

    assert_eq!(
        evidence.record_transport_loss(&dispatch_id, TransportLoss::ConfirmedNotWritten),
        Err(ActionEvidenceError::DispatchNotArmed)
    );
    evidence
        .arm_dispatch(dispatch_id.clone())
        .expect("dispatch should arm");
    assert_eq!(
        evidence.record_transport_loss(&dispatch_id, TransportLoss::ConfirmedNotWritten),
        Ok(ActionEvidenceMutation::Recorded)
    );
    assert_eq!(
        evidence.terminal(),
        Some(&ActionTerminalEvidence::new(
            TerminalDetail::FailedKnown(KnownFailureReason::NotDispatched),
            ActionTerminalSource::ProvenNonDelivery,
        ))
    );
}

#[test]
fn terminal_evidence_is_idempotent_and_conflicting_results_are_rejected() {
    let mut evidence = ActionEvidence::new();
    let dispatch_id = DispatchId::new();
    evidence
        .arm_dispatch(dispatch_id.clone())
        .expect("dispatch should arm");
    let succeeded = BrowserResult::Succeeded(ResultDigest::new([3; 32]));

    assert_eq!(
        evidence.record_worker_result(&dispatch_id, succeeded),
        Ok(ActionEvidenceMutation::Recorded)
    );
    assert_eq!(
        evidence.record_worker_result(&dispatch_id, succeeded),
        Ok(ActionEvidenceMutation::AlreadyRecorded)
    );
    let attempted = ActionTerminalEvidence::new(
        TerminalDetail::FailedKnown(KnownFailureReason::BrowserRejected),
        ActionTerminalSource::Worker,
    );
    assert_eq!(
        evidence.record_worker_result(
            &dispatch_id,
            BrowserResult::FailedKnown(KnownFailureReason::BrowserRejected),
        ),
        Err(ActionEvidenceError::TerminalConflict {
            current: ActionTerminalEvidence::new(
                TerminalDetail::Succeeded(ResultDigest::new([3; 32])),
                ActionTerminalSource::Worker,
            ),
            attempted,
        })
    );
}

#[test]
fn materialized_loss_terminal_matches_query_time_derivation() {
    for armed in [false, true] {
        let mut evidence = ActionEvidence::new();
        if armed {
            evidence
                .arm_dispatch(DispatchId::new())
                .expect("dispatch should arm");
        }
        let derived = evidence
            .effective_terminal(true)
            .expect("worker loss should derive a terminal state");
        assert_eq!(
            evidence.materialize_worker_loss(),
            Ok(ActionEvidenceMutation::Recorded)
        );
        assert_eq!(evidence.terminal(), Some(&derived));
        assert_eq!(
            evidence.materialize_worker_loss(),
            Ok(ActionEvidenceMutation::AlreadyRecorded)
        );
    }
}
