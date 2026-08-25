#![allow(clippy::expect_used)]
#![allow(clippy::panic)]

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Barrier};
use std::thread;

use browserd_actions::{
    AcceptDecision, ActionJournalLimits, ActionKind, ActionLedger, ActionLedgerError,
    ActionRequest, CanonicalRequestHash, DispatchDecision, DurableActionJournal, FileActionJournal,
    IdempotencyKey, JournalEntry, JournalError, LedgerSession, OutcomeUnknownReason,
    ReplayableActionJournal, ResultDigest, TerminalDetail,
};
use browserd_core::{ActionState, PlacementFence, SessionId, TenantId};
use tempfile::tempdir;

const FENCE: PlacementFence = PlacementFence::new(3, 9, 2);

fn session() -> LedgerSession {
    LedgerSession::new(TenantId::new(), SessionId::new(), FENCE)
}

fn request(key: impl Into<String>, hash_byte: u8) -> ActionRequest {
    ActionRequest::new(
        IdempotencyKey::new(key),
        CanonicalRequestHash::new([hash_byte; 32]),
        ActionKind::Mutating,
    )
}

fn limits() -> ActionJournalLimits {
    ActionJournalLimits::new(4 * 1024, 1_024, 4 * 1024 * 1024)
}

#[test]
fn restart_recovers_terminal_state_idempotency_and_next_sequence() {
    let directory = tempdir().expect("temporary journal directory should be created");
    let path = directory.path().join("actions.wal");
    let session = session();
    let first_request = request("first", 1);
    let second_request = request("second", 2);

    let (first_action_id, second_action_id) = {
        let journal =
            Arc::new(FileActionJournal::open(&path, limits()).expect("journal should be created"));
        let ledger = ActionLedger::new(session.clone(), journal);
        let first = ledger
            .accept(FENCE, first_request.clone())
            .expect("first action should be accepted")
            .snapshot()
            .clone();
        ledger
            .enqueue(FENCE, first.action_id())
            .expect("first action should be enqueued");
        ledger
            .mark_ready(FENCE, first.action_id())
            .expect("first action should become ready");
        let permit = match ledger
            .prepare_dispatch(FENCE, first.action_id())
            .expect("dispatch intent should be durable")
        {
            DispatchDecision::Dispatch(permit) => permit,
            DispatchDecision::DoNotReplay(_) => panic!("first dispatch must issue a permit"),
        };
        ledger
            .record_ack(FENCE, &permit)
            .expect("dispatch acknowledgement should be durable");
        ledger
            .record_result(
                FENCE,
                &permit,
                browserd_actions::BrowserResult::Succeeded(ResultDigest::new([7; 32])),
            )
            .expect("terminal result should be durable");

        let second = ledger
            .accept(FENCE, second_request.clone())
            .expect("second action should be accepted")
            .snapshot()
            .clone();
        (first.action_id().clone(), second.action_id().clone())
    };

    let journal =
        Arc::new(FileActionJournal::open(&path, limits()).expect("durable journal should reopen"));
    let ledger = ActionLedger::recover(session, journal).expect("valid journal should recover");
    let first = ledger
        .snapshot(FENCE, &first_action_id)
        .expect("first action should be reconstructed");
    assert_eq!(first.state(), ActionState::Succeeded);
    assert!(first.dispatch_acknowledged());
    assert_eq!(
        ledger
            .snapshot(FENCE, &second_action_id)
            .expect("second action should be reconstructed")
            .state(),
        ActionState::Accepted
    );
    assert!(matches!(
        ledger
            .accept(FENCE, first_request)
            .expect("same idempotency request should resolve after restart"),
        AcceptDecision::Existing(_)
    ));
    let third = ledger
        .accept(FENCE, request("third", 3))
        .expect("sequence should continue after recovered actions");
    assert_eq!(third.snapshot().action_sequence().get(), 3);
}

#[test]
fn recovered_dispatch_intent_is_durably_terminalized_as_worker_loss() {
    let directory = tempdir().expect("temporary journal directory should be created");
    let path = directory.path().join("actions.wal");
    let session = session();
    let action_id = {
        let journal =
            Arc::new(FileActionJournal::open(&path, limits()).expect("journal should be created"));
        let ledger = ActionLedger::new(session.clone(), journal);
        let action = ledger
            .accept(FENCE, request("ambiguous", 4))
            .expect("action should be accepted")
            .snapshot()
            .clone();
        ledger
            .enqueue(FENCE, action.action_id())
            .expect("action should be enqueued");
        ledger
            .mark_ready(FENCE, action.action_id())
            .expect("action should become ready");
        assert!(matches!(
            ledger
                .prepare_dispatch(FENCE, action.action_id())
                .expect("dispatch intent should be persisted"),
            DispatchDecision::Dispatch(_)
        ));
        action.action_id().clone()
    };
    let size_before_recovery = fs::metadata(&path)
        .expect("journal metadata should be readable")
        .len();

    let journal =
        Arc::new(FileActionJournal::open(&path, limits()).expect("journal should reopen"));
    let ledger = ActionLedger::recover(session, journal).expect("journal should recover");
    let recovered = ledger
        .snapshot(FENCE, &action_id)
        .expect("dispatched action should be reconstructed");
    assert_eq!(recovered.state(), ActionState::OutcomeUnknown);
    assert_eq!(
        recovered.terminal_detail(),
        Some(TerminalDetail::OutcomeUnknown(
            OutcomeUnknownReason::WorkerLost
        ))
    );
    assert!(!recovered.automatic_replay_allowed());
    assert!(matches!(
        ledger
            .prepare_dispatch(FENCE, &action_id)
            .expect("recovered dispatch should yield a no-replay decision"),
        DispatchDecision::DoNotReplay(_)
    ));
    assert!(
        fs::metadata(&path)
            .expect("journal metadata should remain readable")
            .len()
            > size_before_recovery
    );
}

#[test]
fn truncated_or_corrupt_frame_fails_closed_at_open() {
    let directory = tempdir().expect("temporary journal directory should be created");
    let truncated_path = directory.path().join("truncated.wal");
    {
        let journal = Arc::new(
            FileActionJournal::open(&truncated_path, limits()).expect("journal should be created"),
        );
        let ledger = ActionLedger::new(session(), journal);
        ledger
            .accept(FENCE, request("persisted", 5))
            .expect("one valid record should be persisted");
    }
    let mut truncated = OpenOptions::new()
        .append(true)
        .open(&truncated_path)
        .expect("journal should be appendable by the corruption fixture");
    truncated
        .write_all(&[0, 0])
        .expect("partial frame should be written");
    truncated
        .sync_all()
        .expect("partial frame should reach storage");
    drop(truncated);
    let truncated_error = FileActionJournal::open(&truncated_path, limits())
        .expect_err("truncated journal must not be repaired automatically");
    assert!(truncated_error.to_string().contains("truncated"));

    let corrupt_path = directory.path().join("corrupt.wal");
    {
        let journal = Arc::new(
            FileActionJournal::open(&corrupt_path, limits()).expect("journal should be created"),
        );
        let ledger = ActionLedger::new(session(), journal);
        ledger
            .accept(FENCE, request("persisted", 6))
            .expect("one valid record should be persisted");
    }
    let mut bytes = fs::read(&corrupt_path).expect("journal bytes should be readable");
    let last = bytes
        .last_mut()
        .expect("non-empty journal should have a checksum byte");
    *last ^= 0xff;
    fs::write(&corrupt_path, bytes).expect("checksum should be corrupted");
    let corrupt_error = FileActionJournal::open(&corrupt_path, limits())
        .expect_err("checksum mismatch must fail closed");
    assert!(corrupt_error.to_string().contains("checksum"));
}

#[test]
fn configured_record_and_count_bounds_preserve_pre_append_state() {
    let directory = tempdir().expect("temporary journal directory should be created");
    let path = directory.path().join("bounded.wal");
    let session = session();
    let bounded = ActionJournalLimits::new(512, 1, 4 * 1024);
    let accepted_action_id = {
        let journal = Arc::new(
            FileActionJournal::open(&path, bounded).expect("bounded journal should be created"),
        );
        let ledger = ActionLedger::new(session.clone(), journal);
        assert!(matches!(
            ledger.accept(FENCE, request("x".repeat(2_048), 7)),
            Err(ActionLedgerError::JournalUnavailable(_))
        ));
        let accepted = ledger
            .accept(FENCE, request("small", 8))
            .expect("failed oversized append must not consume sequence one")
            .snapshot()
            .clone();
        assert_eq!(accepted.action_sequence().get(), 1);
        assert!(matches!(
            ledger.enqueue(FENCE, accepted.action_id()),
            Err(ActionLedgerError::JournalUnavailable(_))
        ));
        assert_eq!(
            ledger
                .snapshot(FENCE, accepted.action_id())
                .expect("failed enqueue must leave the action queryable")
                .state(),
            ActionState::Accepted
        );
        accepted.action_id().clone()
    };

    let journal =
        Arc::new(FileActionJournal::open(&path, bounded).expect("bounded journal should reopen"));
    let recovered = ActionLedger::recover(session, journal).expect("valid bounded record recovers");
    assert_eq!(
        recovered
            .snapshot(FENCE, &accepted_action_id)
            .expect("accepted record should recover")
            .state(),
        ActionState::Accepted
    );
}

#[test]
fn one_writer_owns_the_path_and_symlink_targets_are_rejected() {
    let directory = tempdir().expect("temporary journal directory should be created");
    let path = directory.path().join("owned.wal");
    let first = FileActionJournal::open(&path, limits()).expect("first writer should own path");
    assert!(FileActionJournal::open(&path, limits()).is_err());
    drop(first);
    FileActionJournal::open(&path, limits()).expect("path should unlock after writer drop");

    let target = directory.path().join("target.wal");
    FileActionJournal::open(&target, limits()).expect("target journal should be created");
    let symlink = directory.path().join("linked.wal");
    std::os::unix::fs::symlink(&target, &symlink).expect("test symlink should be created");
    assert!(FileActionJournal::open(&symlink, limits()).is_err());

    let real_parent = directory.path().join("real-parent");
    fs::create_dir(&real_parent).expect("real parent directory should be created");
    let linked_parent = directory.path().join("linked-parent");
    std::os::unix::fs::symlink(&real_parent, &linked_parent)
        .expect("parent symlink should be created");
    assert!(FileActionJournal::open(linked_parent.join("nested.wal"), limits()).is_err());
}

#[test]
fn writable_by_others_parent_directory_is_rejected() {
    let directory = tempdir().expect("temporary journal directory should be created");
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o777))
        .expect("test directory permissions should be widened");

    let error = FileActionJournal::open(directory.path().join("unsafe.wal"), limits())
        .expect_err("replaceable journal paths must be rejected");
    assert!(error.to_string().contains("parent permissions"));
}

#[test]
fn replaceable_intermediate_parent_component_is_rejected() {
    let directory = tempdir().expect("temporary journal directory should be created");
    let replaceable = directory.path().join("replaceable");
    fs::create_dir(&replaceable).expect("replaceable ancestor should be created");
    fs::set_permissions(&replaceable, fs::Permissions::from_mode(0o777))
        .expect("replaceable ancestor permissions should be widened");
    let private_parent = replaceable.join("private");
    fs::create_dir(&private_parent).expect("private final parent should be created");
    fs::set_permissions(&private_parent, fs::Permissions::from_mode(0o700))
        .expect("final parent should remain private");

    let error = FileActionJournal::open(private_parent.join("unsafe.wal"), limits())
        .expect_err("replaceable intermediate components must be rejected");
    assert!(error.to_string().contains("parent permissions"));
}

#[test]
fn nonempty_file_refuses_a_fresh_ledger_that_skips_recovery() {
    let directory = tempdir().expect("temporary journal directory should be created");
    let path = directory.path().join("must-recover.wal");
    let session = session();
    {
        let journal =
            Arc::new(FileActionJournal::open(&path, limits()).expect("journal should be created"));
        let ledger = ActionLedger::new(session.clone(), journal);
        ledger
            .accept(FENCE, request("before-restart", 41))
            .expect("first action should be durable");
    }

    let journal =
        Arc::new(FileActionJournal::open(&path, limits()).expect("journal should reopen"));
    let incorrectly_fresh = ActionLedger::new(session, journal);
    assert!(matches!(
        incorrectly_fresh.accept(FENCE, request("would-reuse-sequence-one", 42)),
        Err(ActionLedgerError::JournalUnavailable(_))
    ));
}

#[test]
fn concurrent_appends_recover_contiguous_sequences_and_idempotency() {
    const CALLERS: usize = 16;

    let directory = tempdir().expect("temporary journal directory should be created");
    let path = directory.path().join("concurrent.wal");
    let session = session();
    let journal =
        Arc::new(FileActionJournal::open(&path, limits()).expect("journal should be created"));
    let ledger = Arc::new(ActionLedger::new(session.clone(), journal));
    let start = Arc::new(Barrier::new(CALLERS + 1));
    let mut tasks = Vec::with_capacity(CALLERS);
    for index in 0..CALLERS {
        let ledger = ledger.clone();
        let start = start.clone();
        tasks.push(thread::spawn(move || {
            start.wait();
            ledger.accept(FENCE, request(format!("key-{index}"), index as u8))
        }));
    }
    start.wait();
    let mut sequences = tasks
        .into_iter()
        .map(|task| {
            task.join()
                .expect("accept thread should not panic")
                .expect("concurrent append should succeed")
                .snapshot()
                .action_sequence()
                .get()
        })
        .collect::<Vec<_>>();
    sequences.sort_unstable();
    assert_eq!(sequences, (1..=CALLERS as u64).collect::<Vec<_>>());
    drop(ledger);

    let journal =
        Arc::new(FileActionJournal::open(&path, limits()).expect("journal should reopen"));
    let recovered = ActionLedger::recover(session, journal).expect("journal should recover");
    for index in 0..CALLERS {
        assert!(matches!(
            recovered
                .accept(FENCE, request(format!("key-{index}"), index as u8))
                .expect("recovered key should remain idempotent"),
            AcceptDecision::Existing(_)
        ));
    }
    assert_eq!(
        recovered
            .accept(FENCE, request("next", 99))
            .expect("new action should continue the recovered sequence")
            .snapshot()
            .action_sequence()
            .get(),
        CALLERS as u64 + 1
    );
}

#[test]
fn stale_recovered_ledgers_cannot_persist_two_dispatch_intents() {
    let directory = tempdir().expect("temporary journal directory should be created");
    let path = directory.path().join("single-dispatch.wal");
    let session = session();
    let journal =
        Arc::new(FileActionJournal::open(&path, limits()).expect("journal should be created"));
    let action_id = {
        let ledger = ActionLedger::new(session.clone(), Arc::clone(&journal));
        let accepted = ledger
            .accept(FENCE, request("single-dispatch", 55))
            .expect("action should be accepted")
            .snapshot()
            .clone();
        ledger
            .enqueue(FENCE, accepted.action_id())
            .expect("action should be enqueued");
        ledger
            .mark_ready(FENCE, accepted.action_id())
            .expect("action should become ready");
        accepted.action_id().clone()
    };

    let first = Arc::new(
        ActionLedger::recover(session.clone(), Arc::clone(&journal))
            .expect("first ledger should recover"),
    );
    let second = Arc::new(
        ActionLedger::recover(session, Arc::clone(&journal))
            .expect("second stale ledger should recover before dispatch"),
    );
    let start = Arc::new(Barrier::new(3));
    let mut tasks = Vec::new();
    for ledger in [first, second] {
        let start = Arc::clone(&start);
        let action_id = action_id.clone();
        tasks.push(thread::spawn(move || {
            start.wait();
            ledger.prepare_dispatch(FENCE, &action_id)
        }));
    }
    start.wait();
    let outcomes = tasks
        .into_iter()
        .map(|task| task.join().expect("dispatch thread should not panic"))
        .collect::<Vec<_>>();
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, Ok(DispatchDecision::Dispatch(_))))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, Err(ActionLedgerError::JournalUnavailable(_))))
            .count(),
        1
    );
}

struct GatedReplayJournal {
    inner: Arc<FileActionJournal>,
    replay_barrier: Arc<Barrier>,
}

impl DurableActionJournal for GatedReplayJournal {
    fn append(&self, entry: &JournalEntry) -> Result<(), JournalError> {
        self.inner.append(entry)
    }
}

impl ReplayableActionJournal for GatedReplayJournal {
    fn replay(&self) -> Result<Vec<JournalEntry>, JournalError> {
        let entries = self.inner.replay()?;
        self.replay_barrier.wait();
        Ok(entries)
    }
}

#[test]
fn concurrent_recovery_persists_only_one_worker_loss_terminal() {
    let directory = tempdir().expect("temporary journal directory should be created");
    let path = directory.path().join("single-recovery-terminal.wal");
    let session = session();
    let inner =
        Arc::new(FileActionJournal::open(&path, limits()).expect("journal should be created"));
    {
        let ledger = ActionLedger::new(session.clone(), Arc::clone(&inner));
        let accepted = ledger
            .accept(FENCE, request("interrupted", 56))
            .expect("action should be accepted")
            .snapshot()
            .clone();
        ledger
            .enqueue(FENCE, accepted.action_id())
            .expect("action should be enqueued");
        ledger
            .mark_ready(FENCE, accepted.action_id())
            .expect("action should become ready");
        assert!(matches!(
            ledger.prepare_dispatch(FENCE, accepted.action_id()),
            Ok(DispatchDecision::Dispatch(_))
        ));
    }

    let replay_barrier = Arc::new(Barrier::new(3));
    let journal = Arc::new(GatedReplayJournal {
        inner,
        replay_barrier: Arc::clone(&replay_barrier),
    });
    let mut tasks = Vec::new();
    for _ in 0..2 {
        let journal = Arc::clone(&journal);
        let session = session.clone();
        tasks.push(thread::spawn(move || {
            ActionLedger::recover(session, journal)
        }));
    }
    replay_barrier.wait();
    let outcomes = tasks
        .into_iter()
        .map(|task| task.join().expect("recovery thread should not panic"))
        .collect::<Vec<_>>();
    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, Err(ActionLedgerError::JournalUnavailable(_))))
            .count(),
        1
    );
}
