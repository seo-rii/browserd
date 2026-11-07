#![allow(clippy::expect_used)]

use browserd_actions::{
    ActionJournalLimits, ActionKind, ActionLedger, ActionLedgerError, ActionRequest,
    ActionResultBudget, ActionSequence, ActionSnapshot, ActionSnapshotFacts, BrowserResult,
    CanonicalRequestHash, DispatchDecision, FileActionJournal, IdempotencyKey, JournalEntry,
    LedgerSession, MAX_ACTION_RESULT_CONTENT_BYTES, MAX_SNAPSHOT_RESULT_CONTENT_BYTES,
    ReplayableActionJournal, ResultDigest, TerminalDetail,
};
use browserd_core::{ActionId, ActionState, PlacementFence, SessionId, TenantId};
use std::sync::Arc;

fn facts(bytes: usize, kind: ActionKind) -> ActionSnapshotFacts {
    ActionSnapshotFacts {
        action_id: ActionId::new(),
        action_sequence: ActionSequence::new(1),
        idempotency_key: IdempotencyKey::new("snapshot-result"),
        canonical_request_hash: CanonicalRequestHash::new([4; 32]),
        kind,
        state: ActionState::Succeeded,
        dispatch_acknowledged: true,
        approval_decision: None,
        terminal_detail: Some(TerminalDetail::Succeeded(ResultDigest::new([7; 32]))),
        resolution: None,
        result_content: Some(vec![b'x'; bytes]),
    }
}

#[test]
fn exact_result_boundaries_require_the_trusted_read_only_snapshot_profile() {
    for size in [
        MAX_ACTION_RESULT_CONTENT_BYTES,
        MAX_ACTION_RESULT_CONTENT_BYTES + 1,
        MAX_SNAPSHOT_RESULT_CONTENT_BYTES,
        MAX_SNAPSHOT_RESULT_CONTENT_BYTES + 1,
    ] {
        assert_eq!(
            ActionSnapshot::from_facts(facts(size, ActionKind::ReadOnly)).is_ok(),
            size <= MAX_ACTION_RESULT_CONTENT_BYTES
        );
        assert_eq!(
            ActionSnapshot::from_facts_with_result_budget(
                facts(size, ActionKind::ReadOnly),
                ActionResultBudget::Snapshot
            )
            .is_ok(),
            size <= MAX_SNAPSHOT_RESULT_CONTENT_BYTES
        );
    }
    assert!(
        ActionSnapshot::from_facts_with_result_budget(
            facts(1, ActionKind::Mutating),
            ActionResultBudget::Snapshot
        )
        .is_err()
    );
    let text = "가".repeat(MAX_ACTION_RESULT_CONTENT_BYTES / 3 + 1);
    assert!(text.chars().count() < MAX_ACTION_RESULT_CONTENT_BYTES);
    assert!(text.len() > MAX_ACTION_RESULT_CONTENT_BYTES);
    let mut value = facts(1, ActionKind::ReadOnly);
    value.result_content = Some(text.into_bytes());
    assert!(ActionSnapshot::from_facts(value.clone()).is_err());
    assert!(
        ActionSnapshot::from_facts_with_result_budget(value, ActionResultBudget::Snapshot).is_ok()
    );
}

#[test]
fn accepted_profile_survives_restart_without_reserving_a_four_megabyte_terminal_body() {
    let dir = tempfile::tempdir().expect("private journal");
    let path = dir.path().join("actions.wal");
    let fence = PlacementFence::new(3, 9, 2);
    let session = LedgerSession::new(TenantId::new(), SessionId::new(), fence);
    let limits = ActionJournalLimits::new(4096, 64, 8192);
    let request = ActionRequest::new(
        IdempotencyKey::new("snapshot"),
        CanonicalRequestHash::new([8; 32]),
        ActionKind::ReadOnly,
    )
    .with_result_budget(ActionResultBudget::Snapshot);
    let id = {
        let journal = Arc::new(FileActionJournal::open(&path, limits).expect("bounded WAL"));
        let ledger = ActionLedger::new(session.clone(), journal);
        let id = ledger
            .accept(fence, request.clone())
            .expect("snapshot uses only small digest terminal reservation")
            .snapshot()
            .action_id()
            .clone();
        ledger.enqueue(fence, &id).expect("enqueue");
        ledger.mark_ready(fence, &id).expect("ready");
        let dispatch = ledger.prepare_dispatch(fence, &id).expect("dispatch");
        assert!(matches!(&dispatch, DispatchDecision::Dispatch(_)));
        if let DispatchDecision::Dispatch(permit) = dispatch {
            ledger
                .record_result(
                    fence,
                    &permit,
                    BrowserResult::Succeeded(ResultDigest::new([1; 32])),
                )
                .expect("terminal digest");
        }
        id
    };
    assert!(std::fs::metadata(&path).expect("WAL bytes").len() < 8192);
    let journal = Arc::new(FileActionJournal::open(&path, limits).expect("reopen"));
    let entries = journal.replay().expect("durable accepted prefix");
    assert_eq!(entries[0].result_budget(), ActionResultBudget::Snapshot);
    let mut legacy = serde_json::to_value(&entries[0]).expect("accepted wire");
    legacy
        .as_object_mut()
        .expect("record object")
        .remove("result_budget");
    let old: JournalEntry = serde_json::from_value(legacy).expect("older record");
    assert_eq!(old.result_budget(), ActionResultBudget::Standard);
    let ledger = ActionLedger::recover(session, journal).expect("restart");
    let snapshot = ledger.snapshot(fence, &id).expect("owned action");
    assert_eq!(snapshot.state(), ActionState::Succeeded);
    assert_eq!(
        snapshot.request().result_budget(),
        ActionResultBudget::Snapshot
    );
    assert!(matches!(
        ledger.accept(
            fence,
            ActionRequest::new(
                IdempotencyKey::new("snapshot"),
                CanonicalRequestHash::new([8; 32]),
                ActionKind::ReadOnly
            )
        ),
        Err(ActionLedgerError::IdempotencyConflict { .. })
    ));
    assert!(matches!(
        ledger.accept(
            fence,
            ActionRequest::new(
                IdempotencyKey::new("mutating"),
                CanonicalRequestHash::new([9; 32]),
                ActionKind::Mutating
            )
            .with_result_budget(ActionResultBudget::Snapshot)
        ),
        Err(ActionLedgerError::InvalidResultBudget)
    ));
}
