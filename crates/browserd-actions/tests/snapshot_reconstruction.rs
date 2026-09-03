use browserd_actions::{
    ActionKind, ActionSequence, ActionSnapshot, ActionSnapshotFacts, ApprovalDecision,
    CanonicalRequestHash, IdempotencyKey, KnownFailureReason, MAX_ACTION_RESULT_CONTENT_BYTES,
    ResultDigest, TerminalDetail,
};
use browserd_core::{ActionId, ActionState};

fn succeeded_facts() -> ActionSnapshotFacts {
    ActionSnapshotFacts {
        action_id: ActionId::new(),
        action_sequence: ActionSequence::new(7),
        idempotency_key: IdempotencyKey::new("request-7"),
        canonical_request_hash: CanonicalRequestHash::new([3; 32]),
        kind: ActionKind::Mutating,
        state: ActionState::Succeeded,
        dispatch_acknowledged: true,
        approval_decision: None,
        terminal_detail: Some(TerminalDetail::Succeeded(ResultDigest::new([5; 32]))),
        resolution: None,
        result_content: None,
    }
}

#[test]
fn validated_worker_facts_reconstruct_a_complete_public_snapshot() {
    let facts = succeeded_facts();
    let snapshot = ActionSnapshot::from_facts(facts.clone());

    assert!(snapshot.is_ok());
    let Some(snapshot) = snapshot.ok() else {
        return;
    };
    assert_eq!(snapshot.action_id(), &facts.action_id);
    assert_eq!(snapshot.action_sequence(), facts.action_sequence);
    assert_eq!(snapshot.request().idempotency_key(), &facts.idempotency_key);
    assert_eq!(
        snapshot.request().canonical_request_hash(),
        facts.canonical_request_hash
    );
    assert_eq!(snapshot.request().kind(), facts.kind);
    assert_eq!(snapshot.state(), facts.state);
    assert!(snapshot.dispatch_acknowledged());
    assert_eq!(snapshot.terminal_detail(), facts.terminal_detail);
    assert_eq!(snapshot.result_content(), None);
}

#[test]
fn succeeded_facts_surface_bounded_result_content() {
    let facts = ActionSnapshotFacts {
        result_content: Some(br#"{"url":"https://example.test/"}"#.to_vec()),
        ..succeeded_facts()
    };
    let snapshot = ActionSnapshot::from_facts(facts);
    assert!(snapshot.is_ok());
    let Some(snapshot) = snapshot.ok() else {
        return;
    };
    assert_eq!(
        snapshot.result_content(),
        Some(&br#"{"url":"https://example.test/"}"#[..])
    );
}

#[test]
fn result_content_only_survives_on_a_succeeded_action() {
    // Content on a non-succeeded action is contradictory.
    let failed = ActionSnapshotFacts {
        state: ActionState::FailedKnown,
        terminal_detail: Some(TerminalDetail::FailedKnown(
            KnownFailureReason::BrowserRejected,
        )),
        result_content: Some(b"{}".to_vec()),
        ..succeeded_facts()
    };
    assert!(ActionSnapshot::from_facts(failed).is_err());

    // Empty and oversized content are out of bounds even when succeeded.
    let empty = ActionSnapshotFacts {
        result_content: Some(Vec::new()),
        ..succeeded_facts()
    };
    assert!(ActionSnapshot::from_facts(empty).is_err());
    let oversized = ActionSnapshotFacts {
        result_content: Some(vec![b'a'; MAX_ACTION_RESULT_CONTENT_BYTES + 1]),
        ..succeeded_facts()
    };
    assert!(ActionSnapshot::from_facts(oversized).is_err());
}

#[test]
fn contradictory_or_unbounded_worker_facts_are_rejected() {
    let mut mismatched_terminal = succeeded_facts();
    mismatched_terminal.state = ActionState::FailedKnown;
    assert!(ActionSnapshot::from_facts(mismatched_terminal).is_err());

    let mut missing_terminal = succeeded_facts();
    missing_terminal.terminal_detail = None;
    assert!(ActionSnapshot::from_facts(missing_terminal).is_err());

    let mut zero_sequence = succeeded_facts();
    zero_sequence.action_sequence = ActionSequence::new(0);
    assert!(ActionSnapshot::from_facts(zero_sequence).is_err());

    let mut unbounded_key = succeeded_facts();
    unbounded_key.idempotency_key = IdempotencyKey::new("x".repeat(256));
    assert!(ActionSnapshot::from_facts(unbounded_key).is_err());

    let mut missing_denial_evidence = succeeded_facts();
    missing_denial_evidence.state = ActionState::FailedKnown;
    missing_denial_evidence.terminal_detail = Some(TerminalDetail::FailedKnown(
        KnownFailureReason::ApprovalDenied,
    ));
    assert!(ActionSnapshot::from_facts(missing_denial_evidence).is_err());

    let mut contradictory_grant = succeeded_facts();
    contradictory_grant.state = ActionState::FailedKnown;
    contradictory_grant.approval_decision = Some(ApprovalDecision::Granted);
    contradictory_grant.terminal_detail = Some(TerminalDetail::FailedKnown(
        KnownFailureReason::ApprovalTimedOut,
    ));
    assert!(ActionSnapshot::from_facts(contradictory_grant).is_err());

    let mut grant_before_approval = succeeded_facts();
    grant_before_approval.state = ActionState::Accepted;
    grant_before_approval.approval_decision = Some(ApprovalDecision::Granted);
    grant_before_approval.terminal_detail = None;
    assert!(ActionSnapshot::from_facts(grant_before_approval).is_err());
}
