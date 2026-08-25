#![allow(clippy::expect_used)]
#![allow(clippy::panic)]

mod common;

use std::sync::{Arc, Barrier, Mutex};
use std::thread;

use browserd_actions::{
    ActionJournalLimits, ActionLedger, ActionLedgerError, ApprovalDecision, BrowserResult,
    DispatchDecision, DurableActionJournal, FileActionJournal, JournalEntry, JournalEntryType,
    JournalError, KnownFailureReason, RecordOutcome, ReplayableActionJournal,
};
use browserd_core::ActionState;
use tempfile::tempdir;

use common::{RecordingJournal, ledger_fixture, ready_action, request};

struct ReplayJournal {
    entries: Mutex<Vec<JournalEntry>>,
}

impl ReplayJournal {
    fn new(entries: Vec<JournalEntry>) -> Self {
        Self {
            entries: Mutex::new(entries),
        }
    }
}

impl DurableActionJournal for ReplayJournal {
    fn append(&self, entry: &JournalEntry) -> Result<(), JournalError> {
        self.entries
            .lock()
            .map_err(|_| JournalError::new("replay journal lock poisoned"))?
            .push(entry.clone());
        Ok(())
    }
}

impl ReplayableActionJournal for ReplayJournal {
    fn replay(&self) -> Result<Vec<JournalEntry>, JournalError> {
        self.entries
            .lock()
            .map_err(|_| JournalError::new("replay journal lock poisoned"))
            .map(|entries| entries.clone())
    }
}

fn pending_action(
    ledger: &ActionLedger<RecordingJournal>,
    fence: browserd_core::PlacementFence,
    key: &str,
) -> browserd_actions::ActionSnapshot {
    let accepted = ledger
        .accept(fence, request(key, 1))
        .expect("action should be accepted")
        .snapshot()
        .clone();
    ledger
        .enqueue(fence, accepted.action_id())
        .expect("action should be queued");
    ledger
        .require_approval(fence, accepted.action_id())
        .expect("action should wait for approval")
}

#[test]
fn granted_approval_recovers_ready_and_dispatches_once() {
    let fixture = ledger_fixture();
    let pending = pending_action(&fixture.ledger, fixture.fence, "grant-recover");
    assert_eq!(pending.state(), ActionState::PendingApproval);

    let granted = fixture
        .ledger
        .grant_approval(fixture.fence, pending.action_id())
        .expect("approval should make the action ready");
    assert_eq!(granted.state(), ActionState::ReadyToDispatch);
    assert_eq!(granted.approval_decision(), Some(ApprovalDecision::Granted));

    let recovered = ActionLedger::recover(
        fixture.ledger.session().clone(),
        Arc::new(ReplayJournal::new(fixture.journal.entries())),
    )
    .expect("valid approval records should recover");
    let snapshot = recovered
        .snapshot(fixture.fence, pending.action_id())
        .expect("approved action should recover");
    assert_eq!(snapshot.state(), ActionState::ReadyToDispatch);
    assert_eq!(
        snapshot.approval_decision(),
        Some(ApprovalDecision::Granted)
    );
    assert!(matches!(
        recovered
            .prepare_dispatch(fixture.fence, pending.action_id())
            .expect("recovered approved action should dispatch"),
        DispatchDecision::Dispatch(_)
    ));
}

#[test]
fn denial_and_timeout_recover_as_known_pre_dispatch_failures() {
    for (key, decision) in [
        ("denied", ApprovalDecision::Denied),
        ("timed-out", ApprovalDecision::TimedOut),
    ] {
        let fixture = ledger_fixture();
        let pending = pending_action(&fixture.ledger, fixture.fence, key);
        let outcome = match decision {
            ApprovalDecision::Denied => fixture
                .ledger
                .deny_approval(fixture.fence, pending.action_id()),
            ApprovalDecision::TimedOut => fixture
                .ledger
                .expire_approval(fixture.fence, pending.action_id()),
            ApprovalDecision::Granted => unreachable!(),
        }
        .expect("approval refusal should be durable");
        assert_eq!(outcome, RecordOutcome::Recorded);

        let recovered = ActionLedger::recover(
            fixture.ledger.session().clone(),
            Arc::new(ReplayJournal::new(fixture.journal.entries())),
        )
        .expect("known approval failure should recover");
        let snapshot = recovered
            .snapshot(fixture.fence, pending.action_id())
            .expect("failed action should recover");
        assert_eq!(snapshot.state(), ActionState::FailedKnown);
        assert_eq!(snapshot.approval_decision(), Some(decision));
        assert_eq!(fixture.journal.count(JournalEntryType::DispatchIntent), 0);
    }
}

#[test]
fn concurrent_opposite_decisions_persist_exactly_one_winner() {
    let fixture = ledger_fixture();
    let pending = pending_action(&fixture.ledger, fixture.fence, "decision-race");
    let action_id = pending.action_id().clone();
    let barrier = Arc::new(Barrier::new(3));

    let grant_ledger = fixture.ledger.clone();
    let grant_barrier = barrier.clone();
    let grant_action = action_id.clone();
    let fence = fixture.fence;
    let grant = thread::spawn(move || {
        grant_barrier.wait();
        grant_ledger.grant_approval(fence, &grant_action)
    });

    let deny_ledger = fixture.ledger.clone();
    let deny_barrier = barrier.clone();
    let deny_action = action_id.clone();
    let deny = thread::spawn(move || {
        deny_barrier.wait();
        deny_ledger.deny_approval(fence, &deny_action)
    });

    barrier.wait();
    let grant = grant.join().expect("grant thread should finish");
    let deny = deny.join().expect("deny thread should finish");
    assert_ne!(grant.is_ok(), deny.is_ok());
    assert_eq!(
        fixture.journal.count(JournalEntryType::ApprovalGranted)
            + fixture.journal.count(JournalEntryType::Terminal),
        1
    );
    assert!(matches!(
        grant.err().or_else(|| deny.err()),
        Some(ActionLedgerError::ApprovalDecisionConflict { .. })
    ));
}

#[test]
fn duplicate_decision_is_idempotent_and_opposite_decision_conflicts() {
    let fixture = ledger_fixture();
    let pending = pending_action(&fixture.ledger, fixture.fence, "duplicate-decision");
    assert_eq!(
        fixture
            .ledger
            .deny_approval(fixture.fence, pending.action_id())
            .expect("first denial should be recorded"),
        RecordOutcome::Recorded
    );
    assert_eq!(
        fixture
            .ledger
            .deny_approval(fixture.fence, pending.action_id())
            .expect("same denial should be idempotent"),
        RecordOutcome::AlreadyRecorded
    );
    assert!(matches!(
        fixture
            .ledger
            .grant_approval(fixture.fence, pending.action_id()),
        Err(ActionLedgerError::ApprovalDecisionConflict {
            current: ApprovalDecision::Denied,
            attempted: ApprovalDecision::Granted,
        })
    ));
    assert_eq!(fixture.journal.count(JournalEntryType::Terminal), 1);
}

#[test]
fn recovery_rejects_approval_grant_before_approval_requirement() {
    let fixture = ledger_fixture();
    let pending = pending_action(&fixture.ledger, fixture.fence, "malformed-order");
    fixture
        .ledger
        .grant_approval(fixture.fence, pending.action_id())
        .expect("fixture approval should succeed");
    let mut entries = fixture.journal.entries();
    let required = entries
        .iter()
        .position(|entry| entry.kind().entry_type() == JournalEntryType::ApprovalRequired)
        .expect("approval-required record should exist");
    let granted = entries
        .iter()
        .position(|entry| entry.kind().entry_type() == JournalEntryType::ApprovalGranted)
        .expect("approval-granted record should exist");
    entries.swap(required, granted);

    assert!(matches!(
        ActionLedger::recover(
            fixture.ledger.session().clone(),
            Arc::new(ReplayJournal::new(entries)),
        ),
        Err(ActionLedgerError::RecoveryInvalid(_))
    ));
}

#[test]
fn approval_state_changes_only_after_their_journal_records_are_durable() {
    let fixture = ledger_fixture();
    let accepted = fixture
        .ledger
        .accept(fixture.fence, request("approval-fsync", 2))
        .expect("action should be accepted")
        .snapshot()
        .clone();
    fixture
        .ledger
        .enqueue(fixture.fence, accepted.action_id())
        .expect("action should be queued");

    fixture
        .journal
        .fail_next(JournalEntryType::ApprovalRequired);
    assert!(matches!(
        fixture
            .ledger
            .require_approval(fixture.fence, accepted.action_id()),
        Err(ActionLedgerError::JournalUnavailable(_))
    ));
    assert_eq!(
        fixture
            .ledger
            .snapshot(fixture.fence, accepted.action_id())
            .expect("failed transition should remain queryable")
            .state(),
        ActionState::Queued
    );

    fixture
        .ledger
        .require_approval(fixture.fence, accepted.action_id())
        .expect("approval requirement retry should succeed");
    fixture.journal.fail_next(JournalEntryType::ApprovalGranted);
    assert!(matches!(
        fixture
            .ledger
            .grant_approval(fixture.fence, accepted.action_id()),
        Err(ActionLedgerError::JournalUnavailable(_))
    ));
    let snapshot = fixture
        .ledger
        .snapshot(fixture.fence, accepted.action_id())
        .expect("failed grant should remain queryable");
    assert_eq!(snapshot.state(), ActionState::PendingApproval);
    assert_eq!(snapshot.approval_decision(), None);
}

#[test]
fn stale_recovered_ledgers_cannot_persist_opposite_approval_decisions() {
    let directory = tempdir().expect("temporary journal directory should be created");
    let path = directory.path().join("actions.wal");
    let session = ledger_fixture().ledger.session().clone();
    let journal = Arc::new(
        FileActionJournal::open(&path, ActionJournalLimits::new(4 * 1024, 128, 1024 * 1024))
            .expect("file journal should open"),
    );
    let initial = ActionLedger::new(session.clone(), journal.clone());
    let accepted = initial
        .accept(session.fence(), request("stale-ledgers", 3))
        .expect("action should be accepted")
        .snapshot()
        .clone();
    initial
        .enqueue(session.fence(), accepted.action_id())
        .expect("action should be queued");
    initial
        .require_approval(session.fence(), accepted.action_id())
        .expect("action should await approval");

    let first = Arc::new(
        ActionLedger::recover(session.clone(), journal.clone())
            .expect("first stale ledger should recover"),
    );
    let second = Arc::new(
        ActionLedger::recover(session.clone(), journal.clone())
            .expect("second stale ledger should recover"),
    );
    let barrier = Arc::new(Barrier::new(3));
    let action_id = accepted.action_id().clone();

    let first_barrier = barrier.clone();
    let first_action = action_id.clone();
    let grant_session = session.clone();
    let recovery_session = session.clone();
    let grant = thread::spawn(move || {
        first_barrier.wait();
        first.grant_approval(grant_session.fence(), &first_action)
    });
    let second_barrier = barrier.clone();
    let second_action = action_id.clone();
    let deny = thread::spawn(move || {
        second_barrier.wait();
        second.deny_approval(session.fence(), &second_action)
    });

    barrier.wait();
    let grant = grant.join().expect("grant thread should finish");
    let deny = deny.join().expect("deny thread should finish");
    assert_ne!(grant.is_ok(), deny.is_ok());

    let recovered = ActionLedger::recover(recovery_session, journal)
        .expect("the single durable approval decision should recover");
    assert!(
        recovered
            .snapshot(recovered.session().fence(), &action_id)
            .expect("action should recover")
            .approval_decision()
            .is_some()
    );
}

#[test]
fn approval_failure_reasons_cannot_be_reported_after_dispatch() {
    for reason in [
        KnownFailureReason::ApprovalDenied,
        KnownFailureReason::ApprovalTimedOut,
    ] {
        let fixture = ledger_fixture();
        let ready = ready_action(
            &fixture.ledger,
            fixture.fence,
            request(format!("post-dispatch-{reason:?}"), 4),
        );
        let permit = match fixture
            .ledger
            .prepare_dispatch(fixture.fence, ready.action_id())
            .expect("dispatch intent should be durable")
        {
            DispatchDecision::Dispatch(permit) => permit,
            DispatchDecision::DoNotReplay(_) => panic!("first dispatch should issue a permit"),
        };

        assert!(matches!(
            fixture.ledger.record_result(
                fixture.fence,
                &permit,
                BrowserResult::FailedKnown(reason),
            ),
            Err(ActionLedgerError::InvalidTransition {
                state: ActionState::MayHaveExecuted,
            })
        ));
        assert_eq!(fixture.journal.count(JournalEntryType::Terminal), 0);
    }
}

#[test]
fn recovery_rejects_approval_failure_forged_after_dispatch() {
    let fixture = ledger_fixture();
    let ready = ready_action(
        &fixture.ledger,
        fixture.fence,
        request("forged-post-dispatch-approval", 5),
    );
    let permit = match fixture
        .ledger
        .prepare_dispatch(fixture.fence, ready.action_id())
        .expect("dispatch intent should be durable")
    {
        DispatchDecision::Dispatch(permit) => permit,
        DispatchDecision::DoNotReplay(_) => panic!("first dispatch should issue a permit"),
    };
    fixture
        .ledger
        .record_result(
            fixture.fence,
            &permit,
            BrowserResult::FailedKnown(KnownFailureReason::BrowserRejected),
        )
        .expect("fixture terminal should be durable");
    let mut entries = fixture.journal.entries();
    let terminal = entries
        .iter()
        .position(|entry| entry.kind().entry_type() == JournalEntryType::Terminal)
        .expect("terminal record should exist");
    let mut encoded = serde_json::to_value(&entries[terminal])
        .expect("terminal record should serialize for corruption fixture");
    encoded["kind"]["Terminal"]["detail"]["FailedKnown"] =
        serde_json::Value::String("ApprovalDenied".to_owned());
    entries[terminal] = serde_json::from_value(encoded)
        .expect("corrupted but structurally valid record should deserialize");

    assert!(matches!(
        ActionLedger::recover(
            fixture.ledger.session().clone(),
            Arc::new(ReplayJournal::new(entries)),
        ),
        Err(ActionLedgerError::RecoveryInvalid(_))
    ));
}

#[test]
fn stale_recovered_ledger_cannot_grant_after_durable_cancel() {
    let directory = tempdir().expect("temporary journal directory should be created");
    let path = directory.path().join("actions.wal");
    let session = ledger_fixture().ledger.session().clone();
    let journal = Arc::new(
        FileActionJournal::open(&path, ActionJournalLimits::new(4 * 1024, 128, 1024 * 1024))
            .expect("file journal should open"),
    );
    let initial = ActionLedger::new(session.clone(), journal.clone());
    let accepted = initial
        .accept(session.fence(), request("cancel-before-stale-grant", 6))
        .expect("action should be accepted")
        .snapshot()
        .clone();
    initial
        .enqueue(session.fence(), accepted.action_id())
        .expect("action should be queued");
    initial
        .require_approval(session.fence(), accepted.action_id())
        .expect("action should await approval");
    let cancelled_view = ActionLedger::recover(session.clone(), journal.clone())
        .expect("cancellation view should recover");
    let stale_grant_view =
        ActionLedger::recover(session.clone(), journal.clone()).expect("grant view should recover");

    assert_eq!(
        cancelled_view
            .cancel_before_dispatch(session.fence(), accepted.action_id())
            .expect("cancellation should become durable"),
        RecordOutcome::Recorded
    );
    assert!(matches!(
        stale_grant_view.grant_approval(session.fence(), accepted.action_id()),
        Err(ActionLedgerError::JournalUnavailable(_))
    ));

    let recovered = ActionLedger::recover(session, journal)
        .expect("cancelled approval journal should remain recoverable");
    let snapshot = recovered
        .snapshot(recovered.session().fence(), accepted.action_id())
        .expect("cancelled action should recover");
    assert_eq!(snapshot.state(), ActionState::CancelledBeforeDispatch);
    assert_eq!(snapshot.approval_decision(), None);
}

#[test]
fn recovery_preserves_grant_evidence_when_approved_action_is_cancelled() {
    let fixture = ledger_fixture();
    let pending = pending_action(&fixture.ledger, fixture.fence, "grant-then-cancel");
    fixture
        .ledger
        .grant_approval(fixture.fence, pending.action_id())
        .expect("approval should be durable");
    fixture
        .ledger
        .cancel_before_dispatch(fixture.fence, pending.action_id())
        .expect("approved action should still be cancellable before dispatch");

    let recovered = ActionLedger::recover(
        fixture.ledger.session().clone(),
        Arc::new(ReplayJournal::new(fixture.journal.entries())),
    )
    .expect("approved cancellation should recover");
    let snapshot = recovered
        .snapshot(fixture.fence, pending.action_id())
        .expect("cancelled action should recover");
    assert_eq!(snapshot.state(), ActionState::CancelledBeforeDispatch);
    assert_eq!(
        snapshot.approval_decision(),
        Some(ApprovalDecision::Granted)
    );
}
