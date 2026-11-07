#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use browserd_core::{PlacementFence, SessionId, TenantId, WorkerId};
use std::os::unix::fs::PermissionsExt;

fn directory() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    dir
}
fn new_scope() -> JournalSessionScope {
    JournalSessionScope::new(
        TenantId::new(),
        SessionId::new(),
        WorkerId::new("notification-worker").unwrap(),
        PlacementFence::new(3, 7, 11),
    )
    .unwrap()
}
fn open(path: &Path) -> SessionEventJournal {
    SessionEventJournal::open(path, 8, 1, 128 * 1024).unwrap()
}

#[test]
fn durable_state_and_original_batch_reopen_without_notification_replay_or_identity_changes() {
    let dir = directory();
    let path = dir.path().join("session-events");
    let scope = new_scope();
    let journal = open(&path);
    journal
        .record(&scope, Lifecycle::Creating, Execution::Idle, None)
        .unwrap();
    let first = journal.pending(None, 32).unwrap().commits.remove(0);
    journal
        .record(&scope, Lifecycle::Ready, Execution::Idle, None)
        .unwrap();
    journal
        .record(&scope, Lifecycle::Ready, Execution::Idle, None)
        .unwrap();
    drop(journal);
    let journal = open(&path);
    assert_eq!(journal.pending(None, 32).unwrap().commits[0], first);
    journal.ack(&first.ack()).unwrap();
    journal.ack(&first.ack()).unwrap();
    let second = journal.pending(None, 32).unwrap().commits.remove(0);
    assert_eq!(second.source_sequence(), 2);
    assert_ne!(
        second.descriptors()[0].event_id(),
        first.descriptors()[0].event_id()
    );
    assert!(second.occurred_at_unix_ms() >= first.occurred_at_unix_ms());
    assert_eq!(
        second.descriptors()[0].session_scope().fence(),
        scope.fence()
    );
    drop(journal);
    let journal = open(&path);
    assert_eq!(journal.pending(None, 32).unwrap().commits[0], second);
    journal.ack(&second.ack()).unwrap();
    assert!(journal.ack(&first.ack()).is_err());
    drop(journal);
    let journal = open(&path);
    assert!(journal.pending(None, 32).unwrap().commits.is_empty());
    assert!(
        journal
            .record(&new_scope(), Lifecycle::Creating, Execution::Idle, None)
            .is_err(),
        "ACK cannot reopen permanent source capacity"
    );
}

#[test]
fn cleanup_and_reconciliation_reserved_capacity_survive_a_full_pending_source() {
    let dir = directory();
    let path = dir.path().join("session-events");
    let scope = new_scope();
    let journal = open(&path);
    let action = ActionId::new();
    journal
        .record(&scope, Lifecycle::Creating, Execution::Idle, None)
        .unwrap();
    journal
        .record(&scope, Lifecycle::Ready, Execution::Idle, None)
        .unwrap();
    journal
        .record(
            &scope,
            Lifecycle::Ready,
            Execution::Running,
            Some(action.clone()),
        )
        .unwrap();
    journal
        .record(
            &scope,
            Lifecycle::Ready,
            Execution::ReconciliationRequired,
            Some(action),
        )
        .unwrap();
    assert!(
        journal
            .record(&new_scope(), Lifecycle::Creating, Execution::Idle, None)
            .is_err()
    );
    journal
        .record(&scope, Lifecycle::Ready, Execution::Idle, None)
        .unwrap();
    journal
        .record(&scope, Lifecycle::Closing, Execution::Idle, None)
        .unwrap();
    journal
        .record(&scope, Lifecycle::Closed, Execution::Idle, None)
        .unwrap();
    drop(journal);
    let journal = open(&path);
    for sequence in 1..=7 {
        let commit = journal.pending(None, 32).unwrap().commits.remove(0);
        assert_eq!(commit.source_sequence(), sequence);
        journal.ack(&commit.ack()).unwrap();
    }
    assert!(journal.pending(None, 32).unwrap().commits.is_empty());
}

#[test]
fn future_or_foreign_ack_and_changed_original_fence_cannot_remove_pending_state() {
    let dir = directory();
    let path = dir.path().join("session-events");
    let scope = new_scope();
    let journal = open(&path);
    journal
        .record(&scope, Lifecycle::Creating, Execution::Idle, None)
        .unwrap();
    let first = journal.pending(None, 32).unwrap().commits.remove(0);
    journal
        .record(&scope, Lifecycle::Ready, Execution::Idle, None)
        .unwrap();
    let pending = journal
        .state
        .lock()
        .unwrap()
        .snapshot
        .entries
        .values()
        .next()
        .unwrap()
        .pending
        .clone();
    assert!(journal.ack(&pending[1].ack()).is_err());
    let mut foreign = serde_json::to_value(first.ack()).unwrap();
    foreign["scope"]["tenant_id"] = serde_json::to_value(TenantId::new()).unwrap();
    let foreign: NotificationAck = serde_json::from_value(foreign).unwrap();
    assert!(journal.ack(&foreign).is_err());
    let stale = JournalSessionScope::new(
        scope.tenant_id().clone(),
        scope.session_id().clone(),
        scope.original_worker_id().clone(),
        PlacementFence::new(3, 8, 11),
    )
    .unwrap();
    assert_eq!(
        journal.record(&stale, Lifecycle::Ready, Execution::Idle, None),
        Err(WorkerError::StaleFence)
    );
    assert_eq!(journal.pending(None, 32).unwrap().commits[0], first);
}

#[test]
fn snapshot_io_failure_poisoned_writer_never_exposes_uncommitted_state_or_ack() {
    let dir = directory();
    let path = dir.path().join("session-events");
    let scope = new_scope();
    let journal = open(&path);
    journal
        .record(&scope, Lifecycle::Creating, Execution::Idle, None)
        .unwrap();
    let first = journal.pending(None, 32).unwrap().commits.remove(0);
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap();
    assert_eq!(
        journal.record(&scope, Lifecycle::Ready, Execution::Idle, None),
        Err(WorkerError::DurabilityUnavailable)
    );
    assert!(journal.pending(None, 32).is_err());
    assert!(journal.ack(&first.ack()).is_err());
    assert!(!journal.qualify());
    assert_eq!(
        journal
            .state
            .lock()
            .unwrap()
            .snapshot
            .entries
            .values()
            .next()
            .unwrap()
            .lifecycle,
        Lifecycle::Creating
    );
}

#[test]
fn unsupported_configuration_and_worker_reassignment_fail_before_authority_changes() {
    let dir = directory();
    let path = dir.path().join("session-events");
    assert!(SessionEventJournal::open(&path, usize::MAX, 1, 128 * 1024).is_err());
    assert!(SessionEventJournal::open(&path, 8, usize::MAX, 128 * 1024).is_err());
    assert!(SessionEventJournal::open(&path, 8, 1, usize::MAX).is_err());
    let journal = open(&path);
    let scope = new_scope();
    journal.bind_worker(scope.original_worker_id()).unwrap();
    journal
        .record(&scope, Lifecycle::Creating, Execution::Idle, None)
        .unwrap();
    assert_eq!(
        journal.bind_worker(&WorkerId::new("foreign-worker").unwrap()),
        Err(WorkerError::StaleFence)
    );
    drop(journal);
    let journal = open(&path);
    assert_eq!(
        journal.bind_worker(&WorkerId::new("foreign-worker").unwrap()),
        Err(WorkerError::StaleFence)
    );
    assert_eq!(
        journal.pending(None, 32).unwrap().commits[0].source_sequence(),
        1
    );
}
