#![allow(clippy::expect_used)]

use std::fs;
use std::sync::{Arc, Barrier};
use std::thread;

use browserd_actions::{
    AcceptDecision, ActionJournalLimits, ActionKind, ActionLedger, ActionRequest,
    CanonicalRequestHash, FileActionJournal, IdempotencyKey, LedgerSession,
    ReplayableActionJournal,
};
use browserd_core::{PlacementFence, SessionId, TenantId};
use tempfile::tempdir;

const FENCE: PlacementFence = PlacementFence::new(5, 8, 13);

fn limits() -> ActionJournalLimits {
    ActionJournalLimits::new(4 * 1024, 1_024, 4 * 1024 * 1024)
}

fn session() -> LedgerSession {
    LedgerSession::new(TenantId::new(), SessionId::new(), FENCE)
}

fn request(key: &str, hash_byte: u8) -> ActionRequest {
    ActionRequest::new(
        IdempotencyKey::new(key),
        CanonicalRequestHash::new([hash_byte; 32]),
        ActionKind::Mutating,
    )
}

#[test]
fn create_new_creates_and_durably_initializes_a_new_wal() {
    let directory = tempdir().expect("temporary journal directory should be created");
    let path = directory.path().join("new.wal");

    let journal = FileActionJournal::create_new(&path, limits())
        .expect("an absent journal path should be created");

    assert_eq!(journal.path(), path);
    assert!(
        fs::metadata(&path)
            .expect("created journal metadata should be readable")
            .len()
            > 0
    );
    assert!(
        journal
            .replay()
            .expect("new journal should contain a valid empty log")
            .is_empty()
    );
}

#[test]
fn create_new_rejects_every_existing_file_without_changing_its_bytes() {
    let directory = tempdir().expect("temporary journal directory should be created");
    let empty_path = directory.path().join("empty.wal");
    fs::write(&empty_path, []).expect("empty pre-existing file should be created");
    let empty_before = fs::read(&empty_path).expect("empty file should be readable");

    let empty_error = FileActionJournal::create_new(&empty_path, limits())
        .expect_err("even an empty existing file must not be reused");
    assert!(empty_error.to_string().contains("already exists"));
    assert_eq!(
        fs::read(&empty_path).expect("empty file should remain readable"),
        empty_before
    );

    let valid_path = directory.path().join("valid.wal");
    {
        let journal = Arc::new(
            FileActionJournal::create_new(&valid_path, limits())
                .expect("valid fixture WAL should be created"),
        );
        ActionLedger::new(session(), journal)
            .accept(FENCE, request("persisted", 1))
            .expect("valid fixture record should be persisted");
    }
    let valid_before = fs::read(&valid_path).expect("valid WAL should be readable");

    let valid_error = FileActionJournal::create_new(&valid_path, limits())
        .expect_err("a valid existing WAL must not be reused for a new session");
    assert!(valid_error.to_string().contains("already exists"));
    assert_eq!(
        fs::read(&valid_path).expect("valid WAL should remain readable"),
        valid_before
    );
}

#[test]
fn concurrent_create_new_has_exactly_one_winner() {
    const CALLERS: usize = 24;

    let directory = tempdir().expect("temporary journal directory should be created");
    let path = Arc::new(directory.path().join("contended.wal"));
    let start = Arc::new(Barrier::new(CALLERS + 1));
    let mut tasks = Vec::with_capacity(CALLERS);
    for _ in 0..CALLERS {
        let path = Arc::clone(&path);
        let start = Arc::clone(&start);
        tasks.push(thread::spawn(move || {
            start.wait();
            FileActionJournal::create_new(path.as_path(), limits())
        }));
    }
    start.wait();

    let results = tasks
        .into_iter()
        .map(|task| task.join().expect("create thread should not panic"))
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert!(
        results
            .iter()
            .filter_map(|result| result.as_ref().err())
            .all(|error| error.to_string().contains("already exists"))
    );
}

#[test]
fn create_new_wal_still_reopens_and_recovers_through_the_existing_path() {
    let directory = tempdir().expect("temporary journal directory should be created");
    let path = directory.path().join("recoverable.wal");
    let session = session();
    let action_request = request("recover", 2);
    let action_id = {
        let journal = Arc::new(
            FileActionJournal::create_new(&path, limits())
                .expect("new session WAL should be created"),
        );
        let ledger = ActionLedger::new(session.clone(), journal);
        ledger
            .accept(FENCE, action_request.clone())
            .expect("action should be durable")
            .snapshot()
            .action_id()
            .clone()
    };

    let reopened = Arc::new(
        FileActionJournal::open(&path, limits()).expect("existing WAL should still reopen"),
    );
    let recovered =
        ActionLedger::recover(session, reopened).expect("existing recovery should still work");
    assert_eq!(
        recovered
            .snapshot(FENCE, &action_id)
            .expect("created action should recover")
            .action_id(),
        &action_id
    );
    assert!(matches!(
        recovered
            .accept(FENCE, action_request)
            .expect("recovered idempotency should remain intact"),
        AcceptDecision::Existing(_)
    ));
}
