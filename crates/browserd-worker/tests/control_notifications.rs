#![allow(clippy::expect_used)]

use std::os::unix::fs::PermissionsExt;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use browserd_core::{
    NotificationCommit, NotificationControlState, NotificationDescriptor, NotificationSessionScope,
    PageId, PlacementFence, SessionId, TenantId, WorkerId, WorkerNotificationEvent,
};
use browserd_session::SessionTime;
use browserd_worker::{ControlEventJournal, WorkerClock, WorkerError, WorkerSessionFence};
use sha2::{Digest, Sha256};

struct Clock(AtomicU64);
impl WorkerClock for Clock {
    fn now(&self) -> Result<SessionTime, WorkerError> {
        Ok(SessionTime::new(self.0.load(Ordering::SeqCst)))
    }
}
fn owner() -> WorkerSessionFence {
    WorkerSessionFence {
        tenant_id: TenantId::new(),
        session_id: SessionId::new(),
        worker_epoch: 7,
        placement_version: 11,
        session_incarnation: 13,
    }
}
fn root() -> tempfile::TempDir {
    let root = tempfile::tempdir().expect("root");
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
        .expect("private root");
    root
}
fn head(journal: &ControlEventJournal) -> NotificationCommit {
    let page = journal.pending_notifications(None, 32).expect("pending");
    assert_eq!(page.commits.len(), 1);
    page.commits[0].clone()
}

#[test]
fn general_control_source_preserves_stable_id_time_full_fence_and_exact_ack_on_reopen() {
    let root = root();
    let path = root.path().join("control.json");
    let worker = WorkerId::new("control-worker").expect("worker");
    let owner = owner();
    let clock = Arc::new(Clock(AtomicU64::new(1_700_000_000_000)));
    let first;
    {
        let journal = ControlEventJournal::open(&path, 4, 8, 65536)
            .expect("open")
            .with_clock(clock.clone());
        journal
            .enable_notifications(&worker)
            .expect("enable additive authority");
        journal
            .record(owner.clone(), 1, true, Some(PageId::new()))
            .expect("Human grant");
        assert!(
            journal
                .pending(8)
                .expect("no second legacy event")
                .is_empty()
        );
        first = head(&journal);
        assert_eq!(first.source_sequence(), 1);
        assert_eq!(first.occurred_at_unix_ms(), 1_700_000_000_000);
        assert_eq!(first.scope().original_worker_id(), &worker);
        assert_eq!(
            first.descriptors()[0].session_scope().fence(),
            PlacementFence::new(7, 11, 13)
        );
        assert_eq!(
            first.descriptors()[0].event(),
            &WorkerNotificationEvent::BrowserControlChanged {
                state: NotificationControlState::Human
            }
        );
    }
    let journal = ControlEventJournal::open(&path, 4, 8, 65536)
        .expect("reopen")
        .with_clock(clock.clone());
    journal
        .enable_notifications(&worker)
        .expect("same original worker");
    assert!(
        journal
            .enable_notifications(&WorkerId::new("foreign-worker").expect("worker"))
            .is_err()
    );
    assert_eq!(head(&journal), first);
    // A well-formed ACK for the same sequence and event ID with a changed original fence is wrong.
    let changed = NotificationCommit::new(
        first.scope().clone(),
        1,
        first.occurred_at_unix_ms(),
        vec![
            NotificationDescriptor::new(
                first.descriptors()[0].event_id(),
                NotificationSessionScope::new(
                    owner.session_id.clone(),
                    PlacementFence::new(8, 11, 13),
                )
                .expect("different boot"),
                first.descriptors()[0].event().clone(),
            )
            .expect("descriptor"),
        ],
    )
    .expect("changed scope commit");
    assert_eq!(
        journal.ack_notification(&changed.ack()),
        Err(WorkerError::StaleFence)
    );
    assert_eq!(head(&journal), first);
    journal
        .ack_notification(&first.ack())
        .expect("exact source ACK");
    journal
        .ack_notification(&first.ack())
        .expect("lost ACK response retry");
    drop(journal);
    // Reopening cannot reset the source sequence or original UTC floor, even with clock rollback.
    clock.0.store(1_600_000_000_000, Ordering::SeqCst);
    let journal = ControlEventJournal::open(&path, 4, 8, 65536)
        .expect("reopen after ACK")
        .with_clock(clock);
    journal
        .ack_notification(&first.ack())
        .expect("last exact ACK persisted");
    journal.record(owner, 2, false, None).expect("Agent return");
    let second = head(&journal);
    assert_eq!(second.source_sequence(), 2);
    assert_eq!(second.occurred_at_unix_ms(), first.occurred_at_unix_ms());
    assert_ne!(
        second.descriptors()[0].event_id(),
        first.descriptors()[0].event_id()
    );
    assert_eq!(
        second.descriptors()[0].event(),
        &WorkerNotificationEvent::BrowserControlChanged {
            state: NotificationControlState::Agent
        }
    );
    journal
        .ack_notification(&first.ack())
        .expect("duplicate prior exact ACK cannot remove current pending");
    assert_eq!(head(&journal), second);
    journal
        .ack_notification(&second.ack())
        .expect("next exact ACK");
    assert_eq!(
        journal.ack_notification(&first.ack()),
        Err(WorkerError::StaleFence)
    );
}

#[test]
fn human_grant_reserves_agent_return_while_other_backlog_consumes_all_unreserved_slots() {
    let root = root();
    let journal =
        ControlEventJournal::open(&root.path().join("control.json"), 2, 8, 65536).expect("open");
    journal
        .enable_notifications(&WorkerId::new("worker").expect("worker"))
        .expect("enable");
    let first = owner();
    journal
        .record(first.clone(), 1, true, Some(PageId::new()))
        .expect("pending grant plus return reserve");
    assert!(journal.record(owner(), 1, false, None).is_err());
    let grant = head(&journal);
    journal
        .ack_notification(&grant.ack())
        .expect("ACK grant; Human reserve remains");
    let other = owner();
    journal
        .record(other.clone(), 1, false, None)
        .expect("consume every unreserved slot");
    assert!(journal.record(owner(), 1, false, None).is_err());
    journal
        .record(first.clone(), 2, false, None)
        .expect("Agent return consumes held slot even at capacity");
    let page = journal
        .pending_notifications(None, 32)
        .expect("two pending sources");
    assert_eq!(page.commits.len(), 2);
    assert!(page.commits.iter().any(|commit| commit.scope().source_id()
        == *first.session_id.as_uuid()
        && commit.source_sequence() == 2));
    assert!(
        page.commits
            .iter()
            .any(|commit| commit.scope().source_id() == *other.session_id.as_uuid())
    );
}

#[test]
fn human_grant_cannot_spend_unavailable_return_slot_or_byte_reserve() {
    let root = root();
    let worker = WorkerId::new("w".repeat(255)).expect("full worker id");
    let journal =
        ControlEventJournal::open(&root.path().join("one-slot.json"), 1, 8, 65536).expect("open");
    journal.enable_notifications(&worker).expect("enable");
    assert!(
        journal
            .record(owner(), 1, true, Some(PageId::new()))
            .is_err()
    );
    assert!(
        journal
            .pending_notifications(None, 32)
            .expect("no half grant")
            .commits
            .is_empty()
    );
    let journal =
        ControlEventJournal::open(&root.path().join("byte-budget.json"), 8, 8, 4096).expect("open");
    journal.enable_notifications(&worker).expect("enable");
    assert!(
        journal
            .record(owner(), 1, true, Some(PageId::new()))
            .is_err()
    );
    assert!(
        journal
            .pending_notifications(None, 32)
            .expect("no byte-overcommitted grant")
            .commits
            .is_empty()
    );
    journal
        .record(owner(), 1, false, None)
        .expect("small Agent event remains possible");
}

#[test]
fn legacy_checksum_pending_and_sequence_survive_additive_notification_enablement() {
    let root = root();
    let path = root.path().join("legacy.json");
    let owner = owner();
    let first;
    {
        let journal = ControlEventJournal::open(&path, 8, 8, 65536).expect("legacy open");
        first = journal
            .record(owner.clone(), 1, true, Some(PageId::new()))
            .expect("legacy grant");
    }
    let legacy_bytes = std::fs::read(&path).expect("original legacy file");
    let legacy: serde_json::Value = serde_json::from_slice(&legacy_bytes).expect("legacy envelope");
    assert!(legacy["snapshot"].get("notifications").is_none());
    // Rebuild the old exact field layout/checksum rather than trusting a new serializer.
    #[derive(serde::Serialize)]
    struct OldSnapshot {
        sequences: std::collections::BTreeMap<String, u64>,
        pending: Vec<browserd_worker::WorkerControlEvent>,
    }
    let old = OldSnapshot {
        sequences: serde_json::from_value(legacy["snapshot"]["sequences"].clone())
            .expect("old sequence map"),
        pending: serde_json::from_value(legacy["snapshot"]["pending"].clone())
            .expect("old event layout"),
    };
    let checksum = Sha256::digest(serde_json::to_vec(&old).expect("old field layout"));
    assert_eq!(
        legacy["checksum"],
        serde_json::to_value(checksum.as_slice()).expect("legacy checksum")
    );
    {
        let journal = ControlEventJournal::open(&path, 8, 8, 65536).expect("old checksum reopened");
        assert_eq!(
            std::fs::read(&path).expect("unchanged legacy snapshot"),
            legacy_bytes
        );
        journal
            .enable_notifications(&WorkerId::new("worker").expect("worker"))
            .expect("additive opt-in");
        assert_eq!(
            journal.pending(8).expect("old event retained"),
            vec![first.clone()]
        );
        journal
            .record(owner.clone(), 2, false, None)
            .expect("new mode Agent transition");
        let notification = head(&journal);
        assert_eq!(notification.source_sequence(), 1);
        assert_eq!(
            journal
                .pending(8)
                .expect("new record has no legacy duplicate"),
            vec![first.clone()]
        );
        journal.ack(&first).expect("legacy ACK remains independent");
        assert_eq!(head(&journal), notification);
        let encoded: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).expect("snapshot")).expect("envelope");
        assert_eq!(
            encoded["snapshot"]["sequences"][format!("{}/{}", owner.tenant_id, owner.session_id)],
            1
        );
    }
    let journal = ControlEventJournal::open(&path, 8, 8, 65536).expect("new authority reopen");
    let notification = head(&journal);
    journal.ack(&first).expect("lost legacy ACK response retry");
    assert_eq!(head(&journal), notification);
}

#[test]
fn source_paging_bounds_and_full_fence_rejection_preserve_pending() {
    let root = root();
    let journal =
        ControlEventJournal::open(&root.path().join("control.json"), 16, 16, 131072).expect("open");
    journal
        .enable_notifications(&WorkerId::new("worker").expect("worker"))
        .expect("enable");
    let first = owner();
    journal
        .record(first.clone(), 1, false, None)
        .expect("initial source");
    let mut stale = first.clone();
    stale.worker_epoch += 1;
    assert_eq!(
        journal.record(stale, 2, true, Some(PageId::new())),
        Err(WorkerError::StaleFence)
    );
    for _ in 0..9 {
        journal
            .record(owner(), 1, false, None)
            .expect("other source");
    }
    let first_page = journal
        .pending_notifications(None, 32)
        .expect("bounded descriptors");
    assert_eq!(first_page.commits.len(), 8);
    assert_eq!(first_page.examined, 8);
    assert!(!first_page.is_complete);
    let second_page = journal
        .pending_notifications(first_page.cursor.as_deref(), 32)
        .expect("next bounded page");
    assert_eq!(second_page.commits.len(), 2);
    assert!(second_page.is_complete);
    assert!(journal.pending_notifications(None, 0).is_err());
    assert!(journal.pending_notifications(None, 33).is_err());
    assert!(journal.pending_notifications(Some(""), 32).is_err());
}

#[test]
fn journal_configuration_and_future_notification_clock_fail_without_panic_or_mutation() {
    let root = root();
    let path = root.path().join("control.json");
    assert!(ControlEventJournal::open(&path, usize::MAX, 1, 65536).is_err());
    assert!(ControlEventJournal::open(&path, 1, usize::MAX, 65536).is_err());
    assert!(ControlEventJournal::open(&path, 1, 1, usize::MAX).is_err());
    let journal = ControlEventJournal::open(&path, 4, 8, 65536)
        .expect("open")
        .with_clock(Arc::new(Clock(AtomicU64::new(u64::MAX))));
    journal
        .enable_notifications(&WorkerId::new("worker").expect("worker"))
        .expect("enable");
    assert!(journal.record(owner(), 1, false, None).is_err());
    assert!(
        journal
            .pending_notifications(None, 32)
            .expect("no invalid time event")
            .commits
            .is_empty()
    );
}
