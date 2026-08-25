#![allow(clippy::expect_used)]
#![allow(clippy::panic)]

mod common;

use std::sync::{Arc, Barrier};
use std::thread;

use browserd_actions::{
    AcceptDecision, ActionLedgerError, BrowserResult, DispatchDecision, JournalEntryType,
    KnownFailureReason, OutcomeUnknownReason, RecordOutcome, ResultDigest, TerminalDetail,
    TransportLoss,
};
use browserd_core::ActionState;

use common::{ledger_fixture, ready_action, request};

fn dispatch_first(
    fixture: &common::LedgerFixture,
    key: &str,
) -> (
    browserd_actions::ActionRequest,
    browserd_actions::DispatchPermit,
) {
    let request = request(key, 5);
    let ready = ready_action(&fixture.ledger, fixture.fence, request.clone());
    let decision = fixture
        .ledger
        .prepare_dispatch(fixture.fence, ready.action_id())
        .expect("first dispatch preparation should succeed");
    match decision {
        DispatchDecision::Dispatch(permit) => (request, permit),
        DispatchDecision::DoNotReplay(_) => panic!("first intent must issue one permit"),
    }
}

#[test]
fn ack_and_result_must_match_the_ledger_dispatch_permit() {
    let first = ledger_fixture();
    let second = ledger_fixture();
    let (_, first_permit) = dispatch_first(&first, "first");
    let (_, second_permit) = dispatch_first(&second, "second");

    assert_eq!(
        first.ledger.record_ack(first.fence, &second_permit),
        Err(ActionLedgerError::CorrelationMismatch)
    );
    assert_eq!(
        first.ledger.record_result(
            first.fence,
            &second_permit,
            BrowserResult::Succeeded(ResultDigest::new([1; 32])),
        ),
        Err(ActionLedgerError::CorrelationMismatch)
    );

    assert_eq!(
        first
            .ledger
            .record_ack(first.fence, &first_permit)
            .expect("matching ack should succeed"),
        RecordOutcome::Recorded
    );
    assert_eq!(
        first
            .ledger
            .record_ack(first.fence, &first_permit)
            .expect("duplicate ack should be idempotent"),
        RecordOutcome::AlreadyRecorded
    );
}

#[test]
fn ambiguous_transport_loss_is_terminal_unknown_and_never_auto_replays() {
    let fixture = ledger_fixture();
    let (request, permit) = dispatch_first(&fixture, "unknown");

    fixture
        .ledger
        .record_transport_loss(
            fixture.fence,
            &permit,
            TransportLoss::Ambiguous(OutcomeUnknownReason::AmbiguousTransportLoss),
        )
        .expect("ambiguous loss should be recorded as unknown");
    let snapshot = fixture
        .ledger
        .snapshot(fixture.fence, permit.action_id())
        .expect("unknown action should remain queryable");
    assert_eq!(snapshot.state(), ActionState::OutcomeUnknown);
    assert_eq!(
        snapshot.terminal_detail(),
        Some(TerminalDetail::OutcomeUnknown(
            OutcomeUnknownReason::AmbiguousTransportLoss
        ))
    );
    assert!(!snapshot.automatic_replay_allowed());

    assert!(matches!(
        fixture
            .ledger
            .prepare_dispatch(fixture.fence, permit.action_id())
            .expect("repeated preparation should return a no-replay decision"),
        DispatchDecision::DoNotReplay(_)
    ));
    assert!(matches!(
        fixture
            .ledger
            .accept(fixture.fence, request)
            .expect("idempotent retry should return the existing action"),
        AcceptDecision::Existing(_)
    ));
    assert_eq!(fixture.journal.count(JournalEntryType::DispatchIntent), 1);
}

#[test]
fn confirmed_not_written_is_known_failure_but_is_not_replayed_under_the_same_key() {
    let fixture = ledger_fixture();
    let (request, permit) = dispatch_first(&fixture, "not-written");

    fixture
        .ledger
        .record_transport_loss(fixture.fence, &permit, TransportLoss::ConfirmedNotWritten)
        .expect("confirmed no-write should become known failure");
    let snapshot = fixture
        .ledger
        .snapshot(fixture.fence, permit.action_id())
        .expect("known failure should remain queryable");
    assert_eq!(snapshot.state(), ActionState::FailedKnown);
    assert_eq!(
        snapshot.terminal_detail(),
        Some(TerminalDetail::FailedKnown(
            KnownFailureReason::NotDispatched
        ))
    );
    assert!(matches!(
        fixture
            .ledger
            .accept(fixture.fence, request)
            .expect("same idempotency key should resolve to existing action"),
        AcceptDecision::Existing(_)
    ));
}

#[test]
fn confirmed_not_written_cannot_override_a_durable_dispatch_ack() {
    let fixture = ledger_fixture();
    let (_, permit) = dispatch_first(&fixture, "acked-before-loss");
    fixture
        .ledger
        .record_ack(fixture.fence, &permit)
        .expect("dispatch acknowledgement should be durable");

    assert_eq!(
        fixture.ledger.record_transport_loss(
            fixture.fence,
            &permit,
            TransportLoss::ConfirmedNotWritten,
        ),
        Err(ActionLedgerError::DeliveryEvidenceConflict)
    );
    let snapshot = fixture
        .ledger
        .snapshot(fixture.fence, permit.action_id())
        .expect("contradictory evidence must not mutate the action");
    assert_eq!(snapshot.state(), ActionState::MayHaveExecuted);
    assert!(snapshot.dispatch_acknowledged());
    assert_eq!(snapshot.terminal_detail(), None);
    assert_eq!(fixture.journal.count(JournalEntryType::Terminal), 0);
}

#[test]
fn concurrent_dispatch_preparation_issues_exactly_one_permit() {
    const CALLERS: usize = 24;

    let fixture = ledger_fixture();
    let ready = ready_action(&fixture.ledger, fixture.fence, request("dispatch-race", 8));
    let start = Arc::new(Barrier::new(CALLERS + 1));
    let mut tasks = Vec::with_capacity(CALLERS);

    for _ in 0..CALLERS {
        let ledger = fixture.ledger.clone();
        let action_id = ready.action_id().clone();
        let start = start.clone();
        let fence = fixture.fence;
        tasks.push(thread::spawn(move || {
            start.wait();
            ledger.prepare_dispatch(fence, &action_id)
        }));
    }
    start.wait();

    let decisions: Vec<_> = tasks
        .into_iter()
        .map(|task| {
            task.join()
                .expect("dispatch thread should not panic")
                .expect("dispatch preparation should return a decision")
        })
        .collect();
    assert_eq!(
        decisions
            .iter()
            .filter(|decision| matches!(decision, DispatchDecision::Dispatch(_)))
            .count(),
        1
    );
    assert_eq!(
        decisions
            .iter()
            .filter(|decision| matches!(decision, DispatchDecision::DoNotReplay(_)))
            .count(),
        CALLERS - 1
    );
    assert_eq!(fixture.journal.count(JournalEntryType::DispatchIntent), 1);
}
