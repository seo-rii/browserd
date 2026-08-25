#![allow(clippy::expect_used)]
#![allow(clippy::panic)]

mod common;

use std::sync::{Arc, Barrier};
use std::thread;

use browserd_actions::{
    ActionLedgerError, BrowserResult, DispatchDecision, JournalEntryType, KnownFailureReason,
    OutcomeUnknownReason, RecordOutcome, ResolutionAnnotation, ResolutionKind, ResolutionOutcome,
    ResolutionPolicy, ResultDigest, TerminalDetail, TransportLoss,
};
use browserd_core::{ActionState, PrincipalId};

use common::{ledger_fixture, ready_action, request};

fn unknown_action(fixture: &common::LedgerFixture, key: &str) -> browserd_actions::DispatchPermit {
    let ready = ready_action(&fixture.ledger, fixture.fence, request(key, 6));
    let permit = match fixture
        .ledger
        .prepare_dispatch(fixture.fence, ready.action_id())
        .expect("dispatch preparation should succeed")
    {
        DispatchDecision::Dispatch(permit) => permit,
        DispatchDecision::DoNotReplay(_) => panic!("first intent must dispatch"),
    };
    fixture
        .ledger
        .record_transport_loss(
            fixture.fence,
            &permit,
            TransportLoss::Ambiguous(OutcomeUnknownReason::WorkerLost),
        )
        .expect("worker loss should become outcome unknown");
    permit
}

#[test]
fn resolution_annotates_unknown_without_rewriting_its_terminal_outcome() {
    let fixture = ledger_fixture();
    let permit = unknown_action(&fixture, "resolve");
    let resolution = ResolutionAnnotation::new(
        ResolutionKind::ConfirmedExecuted,
        PrincipalId::new(),
        1234,
        "post-read verification",
    );

    assert!(matches!(
        fixture
            .ledger
            .resolve(
                fixture.fence,
                permit.action_id(),
                resolution.clone(),
                ResolutionPolicy::new(false),
            )
            .expect("first resolution should be recorded"),
        ResolutionOutcome::Recorded(_)
    ));
    let snapshot = fixture
        .ledger
        .snapshot(fixture.fence, permit.action_id())
        .expect("resolved action should remain queryable");
    assert_eq!(snapshot.state(), ActionState::OutcomeUnknown);
    assert_eq!(
        snapshot.terminal_detail(),
        Some(TerminalDetail::OutcomeUnknown(
            OutcomeUnknownReason::WorkerLost
        ))
    );
    assert_eq!(snapshot.resolution(), Some(&resolution));

    assert!(matches!(
        fixture
            .ledger
            .resolve(
                fixture.fence,
                permit.action_id(),
                resolution,
                ResolutionPolicy::new(false),
            )
            .expect("same resolution should be idempotent"),
        ResolutionOutcome::AlreadyRecorded(_)
    ));
    assert_eq!(fixture.journal.count(JournalEntryType::Resolved), 1);
}

#[test]
fn conflicting_or_disallowed_resolutions_are_rejected() {
    let fixture = ledger_fixture();
    let permit = unknown_action(&fixture, "resolve-conflict");
    fixture
        .ledger
        .resolve(
            fixture.fence,
            permit.action_id(),
            ResolutionAnnotation::new(
                ResolutionKind::ConfirmedExecuted,
                PrincipalId::new(),
                1,
                "verified",
            ),
            ResolutionPolicy::new(false),
        )
        .expect("first resolution should succeed");

    assert_eq!(
        fixture.ledger.resolve(
            fixture.fence,
            permit.action_id(),
            ResolutionAnnotation::new(
                ResolutionKind::ConfirmedNotExecuted,
                PrincipalId::new(),
                2,
                "different conclusion",
            ),
            ResolutionPolicy::new(false),
        ),
        Err(ActionLedgerError::ResolutionConflict)
    );

    let other = ledger_fixture();
    let other_permit = unknown_action(&other, "abandoned");
    assert_eq!(
        other.ledger.resolve(
            other.fence,
            other_permit.action_id(),
            ResolutionAnnotation::new(
                ResolutionKind::Abandoned,
                PrincipalId::new(),
                3,
                "caller chose to continue",
            ),
            ResolutionPolicy::new(false),
        ),
        Err(ActionLedgerError::AbandonedResolutionDenied)
    );
}

#[test]
fn same_resolution_kind_cannot_replace_its_audit_identity_or_basis() {
    let fixture = ledger_fixture();
    let permit = unknown_action(&fixture, "resolution-audit-conflict");
    let original = ResolutionAnnotation::new(
        ResolutionKind::ConfirmedExecuted,
        PrincipalId::new(),
        7,
        "original evidence",
    );
    fixture
        .ledger
        .resolve(
            fixture.fence,
            permit.action_id(),
            original,
            ResolutionPolicy::new(false),
        )
        .expect("first resolution should succeed");

    assert_eq!(
        fixture.ledger.resolve(
            fixture.fence,
            permit.action_id(),
            ResolutionAnnotation::new(
                ResolutionKind::ConfirmedExecuted,
                PrincipalId::new(),
                8,
                "replacement evidence",
            ),
            ResolutionPolicy::new(false),
        ),
        Err(ActionLedgerError::ResolutionConflict)
    );
}

#[test]
fn terminal_state_is_monotonic_and_conflicting_late_results_are_rejected() {
    let fixture = ledger_fixture();
    let ready = ready_action(&fixture.ledger, fixture.fence, request("terminal", 9));
    let permit = match fixture
        .ledger
        .prepare_dispatch(fixture.fence, ready.action_id())
        .expect("dispatch preparation should succeed")
    {
        DispatchDecision::Dispatch(permit) => permit,
        DispatchDecision::DoNotReplay(_) => panic!("first intent must dispatch"),
    };
    let success = BrowserResult::Succeeded(ResultDigest::new([4; 32]));
    assert_eq!(
        fixture
            .ledger
            .record_result(fixture.fence, &permit, success)
            .expect("success should become terminal"),
        RecordOutcome::Recorded
    );
    assert_eq!(
        fixture
            .ledger
            .record_result(fixture.fence, &permit, success)
            .expect("identical terminal result should be idempotent"),
        RecordOutcome::AlreadyRecorded
    );

    assert!(matches!(
        fixture.ledger.record_result(
            fixture.fence,
            &permit,
            BrowserResult::FailedKnown(KnownFailureReason::BrowserRejected),
        ),
        Err(ActionLedgerError::TerminalStateConflict { .. })
    ));
    assert!(matches!(
        fixture.ledger.record_transport_loss(
            fixture.fence,
            &permit,
            TransportLoss::Ambiguous(OutcomeUnknownReason::AmbiguousTransportLoss),
        ),
        Err(ActionLedgerError::TerminalStateConflict { .. })
    ));
    assert!(matches!(
        fixture
            .ledger
            .cancel_before_dispatch(fixture.fence, permit.action_id()),
        Err(ActionLedgerError::TerminalStateConflict { .. })
    ));
    assert_eq!(
        fixture
            .ledger
            .snapshot(fixture.fence, permit.action_id())
            .expect("terminal action should remain queryable")
            .terminal_detail(),
        Some(TerminalDetail::Succeeded(ResultDigest::new([4; 32])))
    );
    assert_eq!(fixture.journal.count(JournalEntryType::Terminal), 1);
}

#[test]
fn known_success_cannot_be_resolved() {
    let fixture = ledger_fixture();
    let ready = ready_action(&fixture.ledger, fixture.fence, request("no-resolve", 2));
    let permit = match fixture
        .ledger
        .prepare_dispatch(fixture.fence, ready.action_id())
        .expect("dispatch preparation should succeed")
    {
        DispatchDecision::Dispatch(permit) => permit,
        DispatchDecision::DoNotReplay(_) => panic!("first intent must dispatch"),
    };
    fixture
        .ledger
        .record_result(
            fixture.fence,
            &permit,
            BrowserResult::Succeeded(ResultDigest::new([7; 32])),
        )
        .expect("success should be recorded");

    assert_eq!(
        fixture.ledger.resolve(
            fixture.fence,
            permit.action_id(),
            ResolutionAnnotation::new(
                ResolutionKind::ConfirmedExecuted,
                PrincipalId::new(),
                5,
                "already known",
            ),
            ResolutionPolicy::new(false),
        ),
        Err(ActionLedgerError::ResolutionInvalid)
    );
}

#[test]
fn concurrent_identical_terminal_results_append_exactly_once() {
    const CALLERS: usize = 32;

    let fixture = ledger_fixture();
    let ready = ready_action(&fixture.ledger, fixture.fence, request("terminal-race", 3));
    let permit = match fixture
        .ledger
        .prepare_dispatch(fixture.fence, ready.action_id())
        .expect("dispatch preparation should succeed")
    {
        DispatchDecision::Dispatch(permit) => permit,
        DispatchDecision::DoNotReplay(_) => panic!("first intent must dispatch"),
    };
    let start = Arc::new(Barrier::new(CALLERS + 1));
    let mut tasks = Vec::with_capacity(CALLERS);
    for _ in 0..CALLERS {
        let ledger = fixture.ledger.clone();
        let permit = permit.clone();
        let start = start.clone();
        let fence = fixture.fence;
        tasks.push(thread::spawn(move || {
            start.wait();
            ledger.record_result(
                fence,
                &permit,
                BrowserResult::Succeeded(ResultDigest::new([8; 32])),
            )
        }));
    }
    start.wait();

    let outcomes: Vec<_> = tasks
        .into_iter()
        .map(|task| task.join().expect("result thread should not panic"))
        .collect();
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == Ok(RecordOutcome::Recorded))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == Ok(RecordOutcome::AlreadyRecorded))
            .count(),
        CALLERS - 1
    );
    assert_eq!(fixture.journal.count(JournalEntryType::Terminal), 1);
}

#[test]
fn concurrent_conflicting_terminal_results_choose_one_monotonic_outcome() {
    let fixture = ledger_fixture();
    let ready = ready_action(
        &fixture.ledger,
        fixture.fence,
        request("terminal-conflict-race", 4),
    );
    let permit = match fixture
        .ledger
        .prepare_dispatch(fixture.fence, ready.action_id())
        .expect("dispatch preparation should succeed")
    {
        DispatchDecision::Dispatch(permit) => permit,
        DispatchDecision::DoNotReplay(_) => panic!("first intent must dispatch"),
    };
    let start = Arc::new(Barrier::new(3));
    let success = {
        let ledger = fixture.ledger.clone();
        let permit = permit.clone();
        let start = start.clone();
        let fence = fixture.fence;
        thread::spawn(move || {
            start.wait();
            ledger.record_result(
                fence,
                &permit,
                BrowserResult::Succeeded(ResultDigest::new([9; 32])),
            )
        })
    };
    let unknown = {
        let ledger = fixture.ledger.clone();
        let permit = permit.clone();
        let start = start.clone();
        let fence = fixture.fence;
        thread::spawn(move || {
            start.wait();
            ledger.record_transport_loss(
                fence,
                &permit,
                TransportLoss::Ambiguous(OutcomeUnknownReason::WorkerLost),
            )
        })
    };
    start.wait();

    let outcomes = [
        success.join().expect("success thread should not panic"),
        unknown.join().expect("unknown thread should not panic"),
    ];
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == Ok(RecordOutcome::Recorded))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(
                outcome,
                Err(ActionLedgerError::TerminalStateConflict { .. })
            ))
            .count(),
        1
    );
    assert_eq!(fixture.journal.count(JournalEntryType::Terminal), 1);
    let snapshot = fixture
        .ledger
        .snapshot(fixture.fence, permit.action_id())
        .expect("winning terminal result should remain queryable");
    assert!(matches!(
        snapshot.terminal_detail(),
        Some(TerminalDetail::Succeeded(_))
            | Some(TerminalDetail::OutcomeUnknown(
                OutcomeUnknownReason::WorkerLost
            ))
    ));
}
