#![allow(clippy::expect_used)]
#![allow(clippy::panic)]

mod common;

use browserd_actions::{
    ActionLedgerError, BrowserResult, DispatchDecision, JournalEntryType, RecordOutcome,
    ResultDigest,
};
use browserd_core::ActionState;

use common::{ledger_fixture, ready_action, request};

#[test]
fn dispatch_permit_is_issued_only_after_durable_intent() {
    let fixture = ledger_fixture();
    let ready = ready_action(&fixture.ledger, fixture.fence, request("intent", 1));
    fixture.journal.fail_next(JournalEntryType::DispatchIntent);

    assert!(matches!(
        fixture
            .ledger
            .prepare_dispatch(fixture.fence, ready.action_id()),
        Err(ActionLedgerError::JournalUnavailable(_))
    ));
    assert_eq!(
        fixture
            .ledger
            .snapshot(fixture.fence, ready.action_id())
            .expect("failed intent append must preserve the action")
            .state(),
        ActionState::ReadyToDispatch
    );
    assert_eq!(fixture.journal.count(JournalEntryType::DispatchIntent), 0);

    let permit = match fixture
        .ledger
        .prepare_dispatch(fixture.fence, ready.action_id())
        .expect("retry after a failed append should persist one intent")
    {
        DispatchDecision::Dispatch(permit) => permit,
        DispatchDecision::DoNotReplay(_) => {
            panic!("no dispatch intent was durable, so the first permit is still safe")
        }
    };
    assert_eq!(fixture.journal.count(JournalEntryType::DispatchIntent), 1);

    assert_eq!(
        fixture
            .ledger
            .record_ack(fixture.fence, &permit)
            .expect("matching ack should be recorded"),
        RecordOutcome::Recorded
    );
    fixture
        .ledger
        .record_result(
            fixture.fence,
            &permit,
            BrowserResult::Succeeded(ResultDigest::new([9; 32])),
        )
        .expect("matching result should be recorded");

    let types: Vec<_> = fixture
        .journal
        .entries()
        .into_iter()
        .map(|entry| entry.kind().entry_type())
        .collect();
    let intent = types
        .iter()
        .position(|kind| *kind == JournalEntryType::DispatchIntent)
        .expect("intent entry should exist");
    let ack = types
        .iter()
        .position(|kind| *kind == JournalEntryType::DispatchAcknowledged)
        .expect("ack entry should exist");
    let terminal = types
        .iter()
        .position(|kind| *kind == JournalEntryType::Terminal)
        .expect("terminal entry should exist");
    assert!(intent < ack && ack < terminal);
}

#[test]
fn terminal_state_does_not_advance_when_its_journal_append_fails() {
    let fixture = ledger_fixture();
    let ready = ready_action(&fixture.ledger, fixture.fence, request("terminal", 2));
    let permit = match fixture
        .ledger
        .prepare_dispatch(fixture.fence, ready.action_id())
        .expect("dispatch preparation should succeed")
    {
        DispatchDecision::Dispatch(permit) => permit,
        DispatchDecision::DoNotReplay(_) => panic!("first preparation must dispatch"),
    };
    fixture.journal.fail_next(JournalEntryType::Terminal);

    assert!(matches!(
        fixture.ledger.record_result(
            fixture.fence,
            &permit,
            BrowserResult::Succeeded(ResultDigest::new([3; 32])),
        ),
        Err(ActionLedgerError::JournalUnavailable(_))
    ));
    assert_eq!(
        fixture
            .ledger
            .snapshot(fixture.fence, ready.action_id())
            .expect("action should remain queryable")
            .state(),
        ActionState::MayHaveExecuted
    );
}
