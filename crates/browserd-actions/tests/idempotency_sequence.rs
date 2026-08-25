#![allow(clippy::expect_used)]

mod common;

use std::sync::{Arc, Barrier};
use std::thread;

use browserd_actions::{AcceptDecision, ActionLedgerError, JournalEntryType};

use common::{ledger_fixture, request};

#[test]
fn concurrent_duplicate_accepts_share_one_action_and_sequence() {
    const CALLERS: usize = 32;

    let fixture = ledger_fixture();
    let start = Arc::new(Barrier::new(CALLERS + 1));
    let action_request = request("same-key", 1);
    let mut tasks = Vec::with_capacity(CALLERS);

    for _ in 0..CALLERS {
        let ledger = fixture.ledger.clone();
        let start = start.clone();
        let request = action_request.clone();
        let fence = fixture.fence;
        tasks.push(thread::spawn(move || {
            start.wait();
            ledger.accept(fence, request)
        }));
    }
    start.wait();

    let decisions: Vec<_> = tasks
        .into_iter()
        .map(|task| {
            task.join()
                .expect("accept thread should not panic")
                .expect("duplicate accept should succeed")
        })
        .collect();
    let created = decisions
        .iter()
        .filter(|decision| matches!(decision, AcceptDecision::Created(_)))
        .count();
    let first = decisions[0].snapshot();

    assert_eq!(created, 1);
    assert!(decisions.iter().all(|decision| {
        decision.snapshot().action_id() == first.action_id()
            && decision.snapshot().action_sequence() == first.action_sequence()
    }));
    assert_eq!(first.action_sequence().get(), 1);
    assert_eq!(fixture.journal.count(JournalEntryType::Accepted), 1);
}

#[test]
fn same_idempotency_key_with_a_different_body_conflicts() {
    let fixture = ledger_fixture();
    fixture
        .ledger
        .accept(fixture.fence, request("conflict", 1))
        .expect("first request should be accepted");

    assert!(matches!(
        fixture.ledger.accept(fixture.fence, request("conflict", 2)),
        Err(ActionLedgerError::IdempotencyConflict { .. })
    ));
    assert_eq!(fixture.journal.count(JournalEntryType::Accepted), 1);
}

#[test]
fn concurrent_distinct_actions_receive_gapless_session_monotonic_sequences() {
    const ACTIONS: usize = 64;

    let fixture = ledger_fixture();
    let start = Arc::new(Barrier::new(ACTIONS + 1));
    let mut tasks = Vec::with_capacity(ACTIONS);
    for index in 0..ACTIONS {
        let ledger = fixture.ledger.clone();
        let start = start.clone();
        let fence = fixture.fence;
        tasks.push(thread::spawn(move || {
            start.wait();
            ledger.accept(fence, request(format!("key-{index}"), index as u8))
        }));
    }
    start.wait();

    let mut sequences: Vec<_> = tasks
        .into_iter()
        .map(|task| {
            task.join()
                .expect("accept thread should not panic")
                .expect("distinct action should be accepted")
                .snapshot()
                .action_sequence()
                .get()
        })
        .collect();
    sequences.sort_unstable();
    assert_eq!(sequences, (1..=ACTIONS as u64).collect::<Vec<_>>());

    let journal_sequences: Vec<_> = fixture
        .journal
        .entries()
        .into_iter()
        .filter(|entry| entry.kind().entry_type() == JournalEntryType::Accepted)
        .map(|entry| entry.action_sequence().get())
        .collect();
    assert_eq!(journal_sequences, (1..=ACTIONS as u64).collect::<Vec<_>>());
}
