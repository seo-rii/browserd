#![allow(clippy::expect_used)]

mod common;

use std::sync::{Arc, Barrier};
use std::thread;

use browserd_actions::{AcceptDecision, ActionLedgerError, JournalEntryType};
use browserd_core::ActionId;

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
fn gateway_supplied_action_id_is_preserved_and_cannot_be_rebound() {
    let fixture = ledger_fixture();
    let proposed = ActionId::new();
    let created = fixture
        .ledger
        .accept_with_identity(
            fixture.fence,
            proposed.clone(),
            browserd_actions::ActionSequence::new(1),
            request("gateway-owned-action", 9),
        )
        .expect("gateway-owned action ID should be accepted");
    assert!(matches!(created, AcceptDecision::Created(_)));
    assert_eq!(created.snapshot().action_id(), &proposed);

    let retry = fixture
        .ledger
        .accept_with_identity(
            fixture.fence,
            proposed.clone(),
            browserd_actions::ActionSequence::new(1),
            request("gateway-owned-action", 9),
        )
        .expect("an exact idempotent retry should recover the original action");
    assert!(matches!(retry, AcceptDecision::Existing(_)));
    assert_eq!(retry.snapshot().action_id(), &proposed);

    let different = ActionId::new();
    assert_eq!(
        fixture.ledger.accept_with_identity(
            fixture.fence,
            different,
            browserd_actions::ActionSequence::new(1),
            request("gateway-owned-action", 9),
        ),
        Err(ActionLedgerError::ActionIdentityConflict {
            existing_action_id: proposed.clone(),
        })
    );
    assert_eq!(
        fixture.ledger.accept_with_identity(
            fixture.fence,
            proposed.clone(),
            browserd_actions::ActionSequence::new(2),
            request("different-gateway-action", 10),
        ),
        Err(ActionLedgerError::ActionIdentityConflict {
            existing_action_id: proposed,
        })
    );
    let after_known_gap = fixture
        .ledger
        .accept_with_identity(
            fixture.fence,
            ActionId::new(),
            browserd_actions::ActionSequence::new(3),
            request("skipped-gateway-sequence", 11),
        )
        .expect("a gateway sequence gap can represent an action never sent to this worker");
    assert_eq!(
        after_known_gap.snapshot().action_sequence(),
        browserd_actions::ActionSequence::new(3)
    );
    assert_eq!(
        fixture.ledger.accept_with_identity(
            fixture.fence,
            ActionId::new(),
            browserd_actions::ActionSequence::new(2),
            request("stale-gateway-sequence", 12),
        ),
        Err(ActionLedgerError::ActionSequenceConflict {
            expected: browserd_actions::ActionSequence::new(4),
            received: browserd_actions::ActionSequence::new(2),
        })
    );
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
