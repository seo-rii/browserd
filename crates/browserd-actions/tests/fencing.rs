#![allow(clippy::expect_used)]
#![allow(clippy::panic)]

mod common;

use browserd_actions::{
    ActionLedgerError, BrowserResult, DispatchDecision, JournalEntryType, ResultDigest,
};
use browserd_core::{ActionState, PlacementFence};

use common::{ledger_fixture, request};

#[test]
fn stale_fences_are_rejected_before_sequence_or_journal_mutation() {
    let fixture = ledger_fixture();
    for stale in [
        PlacementFence::new(6, 11, 1),
        PlacementFence::new(7, 10, 1),
        PlacementFence::new(7, 11, 2),
    ] {
        assert!(matches!(
            fixture.ledger.accept(stale, request("stale", 1)),
            Err(ActionLedgerError::StaleFence { .. })
        ));
    }
    assert_eq!(fixture.journal.count(JournalEntryType::Accepted), 0);

    let accepted = fixture
        .ledger
        .accept(fixture.fence, request("fresh", 2))
        .expect("current fence should be accepted");
    assert_eq!(accepted.snapshot().action_sequence().get(), 1);
}

#[test]
fn stale_dispatch_and_result_calls_cannot_change_action_state() {
    let fixture = ledger_fixture();
    let accepted = fixture
        .ledger
        .accept(fixture.fence, request("fenced-action", 3))
        .expect("current action should be accepted");
    let action_id = accepted.snapshot().action_id().clone();
    fixture
        .ledger
        .enqueue(fixture.fence, &action_id)
        .expect("enqueue should succeed");
    fixture
        .ledger
        .mark_ready(fixture.fence, &action_id)
        .expect("ready transition should succeed");
    let stale = PlacementFence::new(8, 11, 1);

    assert!(matches!(
        fixture.ledger.prepare_dispatch(stale, &action_id),
        Err(ActionLedgerError::StaleFence { .. })
    ));
    assert_eq!(fixture.journal.count(JournalEntryType::DispatchIntent), 0);
    assert_eq!(
        fixture
            .ledger
            .snapshot(fixture.fence, &action_id)
            .expect("current fence should still read action")
            .state(),
        ActionState::ReadyToDispatch
    );

    let permit = match fixture
        .ledger
        .prepare_dispatch(fixture.fence, &action_id)
        .expect("current fence should prepare dispatch")
    {
        DispatchDecision::Dispatch(permit) => permit,
        DispatchDecision::DoNotReplay(_) => panic!("first intent must dispatch"),
    };
    assert!(matches!(
        fixture.ledger.record_result(
            stale,
            &permit,
            BrowserResult::Succeeded(ResultDigest::new([1; 32])),
        ),
        Err(ActionLedgerError::StaleFence { .. })
    ));
    assert_eq!(fixture.journal.count(JournalEntryType::Terminal), 0);
    assert_eq!(
        fixture
            .ledger
            .snapshot(fixture.fence, &action_id)
            .expect("stale result must preserve the action")
            .state(),
        ActionState::MayHaveExecuted
    );
}
