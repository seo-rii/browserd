#![allow(clippy::expect_used)]
use browserd_core::{PageId, SessionId, TenantId};
use browserd_worker::{ControlEventJournal, WorkerSessionFence};
use std::os::unix::fs::PermissionsExt;

fn fence() -> WorkerSessionFence {
    WorkerSessionFence {
        tenant_id: TenantId::new(),
        session_id: SessionId::new(),
        worker_epoch: 1,
        placement_version: 1,
        session_incarnation: 1,
    }
}

#[test]
fn journal_recovers_pending_and_sequences_after_restart_and_exact_ack() {
    let root = tempfile::tempdir().expect("root");
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
        .expect("private root");
    let path = root.path().join("control-events.json");
    let owner = fence();
    let first;
    {
        let journal = ControlEventJournal::open(&path, 4, 8, 65536).expect("open");
        assert!(ControlEventJournal::open(&path, 4, 8, 65536).is_err());
        first = journal
            .record(owner.clone(), 1, true, Some(PageId::new()))
            .expect("grant");
        assert_eq!(first.sequence, 1);
    }
    let journal = ControlEventJournal::open(&path, 4, 8, 65536).expect("restart");
    assert_eq!(journal.pending(1).expect("pending"), vec![first.clone()]);
    let mut wrong = first.clone();
    wrong.human = false;
    assert!(journal.ack(&wrong).is_err());
    assert_eq!(journal.pending(1).expect("pending"), vec![first.clone()]);
    journal.ack(&first).expect("exact ack");
    journal.ack(&first).expect("idempotent ack");
    drop(journal);
    let journal = ControlEventJournal::open(&path, 4, 8, 65536).expect("restart after ack");
    assert_eq!(
        journal
            .record(owner, 8, false, None)
            .expect("release")
            .sequence,
        2
    );
    assert_eq!(
        journal
            .record(fence(), 1, true, Some(PageId::new()))
            .expect("other session")
            .sequence,
        1
    );
}

#[test]
fn pending_capacity_cannot_discard_unacknowledged_control_events() {
    let root = tempfile::tempdir().expect("root");
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
        .expect("private root");
    let path = root.path().join("control-events.json");
    let journal = ControlEventJournal::open(&path, 1, 2, 65536).expect("open");
    let owner = fence();
    let first = journal
        .record(owner.clone(), 1, true, Some(PageId::new()))
        .expect("grant");
    assert!(journal.record(owner.clone(), 2, false, None).is_err());
    assert_eq!(journal.pending(128).expect("pending"), vec![first.clone()]);
    journal.ack(&first).expect("ack");
    assert_eq!(
        journal
            .record(owner, 2, false, None)
            .expect("retry")
            .sequence,
        2
    );
    assert!(journal.pending(0).is_err());
    assert!(journal.pending(129).is_err());
    drop(journal);
    let mut bytes = std::fs::read(&path).expect("snapshot");
    bytes.truncate(bytes.len() / 2);
    std::fs::write(&path, bytes).expect("crash fixture");
    assert!(ControlEventJournal::open(&path, 1, 2, 65536).is_err());
}
