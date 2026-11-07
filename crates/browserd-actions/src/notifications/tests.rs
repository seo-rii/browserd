#![allow(clippy::expect_used, clippy::panic)]
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use browserd_core::{
    ActionId, NotificationActionState, NotificationApprovalDecision, PlacementFence, TenantId,
    WorkerId,
};
use tempfile::TempDir;

use super::*;
use crate::{
    ActionJournalLimits, ActionJournalPool, ActionJournalPoolConfig, ActionLedger, ActionRequest,
    BrowserResult, CanonicalRequestHash, DispatchDecision, FileActionJournal, IdempotencyKey,
    ManagedActionJournal, ReplayableActionJournal, ResultDigest,
};

const NOW: u64 = 1_800_000_000_000;
const TTL: u64 = 24 * 60 * 60 * 1000;
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(2)
}
fn worker() -> WorkerId {
    WorkerId::new("notification-owner").expect("worker")
}
fn config(dir: &TempDir) -> ActionJournalPoolConfig {
    ActionJournalPoolConfig::new(
        dir.path().to_path_buf(),
        ActionJournalLimits::new(8192, 128, 1024 * 1024),
    )
    .expect("config")
}
fn scope() -> JournalSessionScope {
    JournalSessionScope::new(
        TenantId::new(),
        browserd_core::SessionId::new(),
        worker(),
        PlacementFence::new(3, 4, 5),
    )
    .expect("scope")
}
fn directory() -> TempDir {
    let d = TempDir::new().expect("directory");
    fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).expect("private");
    d
}
fn request(key: &str) -> ActionRequest {
    ActionRequest::new(
        IdempotencyKey::new(key),
        CanonicalRequestHash::new([17; 32]),
        crate::ActionKind::Mutating,
    )
}
fn pending(
    ledger: &ActionLedger<ManagedActionJournal>,
    s: &JournalSessionScope,
) -> (ActionId, ApprovalId) {
    let action = ledger
        .accept(s.fence(), request("approval"))
        .expect("accept")
        .snapshot()
        .action_id()
        .clone();
    ledger.enqueue(s.fence(), &action).expect("enqueue");
    let id = ApprovalId::new();
    ledger
        .require_approval_with_identity(s.fence(), &action, id.clone())
        .expect("require");
    (action, id)
}
fn success(ledger: &ActionLedger<ManagedActionJournal>, s: &JournalSessionScope) -> ActionId {
    let action = ledger
        .accept(s.fence(), request("success"))
        .expect("accept")
        .snapshot()
        .action_id()
        .clone();
    ledger.enqueue(s.fence(), &action).expect("enqueue");
    ledger.mark_ready(s.fence(), &action).expect("ready");
    let permit = match ledger.prepare_dispatch(s.fence(), &action).expect("intent") {
        DispatchDecision::Dispatch(p) => p,
        DispatchDecision::DoNotReplay(_) => panic!("first dispatch"),
    };
    ledger
        .record_result(
            s.fence(),
            &permit,
            BrowserResult::Succeeded(ResultDigest::new([23; 32])),
        )
        .expect("terminal");
    action
}

#[test]
fn notifying_approval_identity_and_decision_are_atomic_and_recoverable() {
    let dir = directory();
    let pool = ActionJournalPool::open(config(&dir), worker()).expect("pool");
    let s = scope();
    let journal = pool
        .create_notifying_session(&s)
        .expect("notifying journal");
    let ledger = ActionLedger::new(s.ledger_session(), Arc::clone(&journal));
    let (action, id) = pending(&ledger, &s);
    let original = journal.replay().expect("wal");
    let required = original.last().expect("require record");
    assert_eq!(required.approval_id(), Some(&id));
    let commit = required.notifications().expect("same frame metadata");
    assert_eq!(commit.descriptors().len(), 2);
    assert!(
        matches!(commit.descriptors()[1].event(), WorkerNotificationEvent::ActionApprovalRequired { approval_id, .. } if approval_id == &id)
    );
    ledger
        .require_approval_with_identity(s.fence(), &action, id.clone())
        .expect("same retry");
    assert!(
        ledger
            .require_approval_with_identity(s.fence(), &action, ApprovalId::new())
            .is_err()
    );
    assert_eq!(journal.replay().expect("after retry"), original);
    ledger.grant_approval(s.fence(), &action).expect("grant");
    let permit = match ledger
        .prepare_dispatch(s.fence(), &action)
        .expect("dispatch")
    {
        DispatchDecision::Dispatch(p) => p,
        DispatchDecision::DoNotReplay(_) => panic!("first dispatch"),
    };
    ledger
        .record_result(
            s.fence(),
            &permit,
            BrowserResult::Succeeded(ResultDigest::new([9; 32])),
        )
        .expect("terminal");
    let before = journal
        .replay()
        .expect("original authority")
        .iter()
        .filter_map(|entry| entry.notifications().cloned())
        .collect::<Vec<_>>();
    assert_eq!(
        pool.pending_notifications_all(None, 32, deadline())
            .expect("oldest only")
            .commits,
        vec![before[0].clone()]
    );
    assert_eq!(
        before.iter().map(|c| c.descriptors().len()).sum::<usize>(),
        8
    );
    assert_eq!(before.iter().filter(|c| c.descriptors().iter().any(|d| matches!(d.event(), WorkerNotificationEvent::ApprovalDecided { approval_id, state: NotificationApprovalDecision::Approved, .. } if approval_id == &id))).count(), 1);
    assert!(
        pool.receipt(&s, &action)
            .expect("receipt")
            .expect("terminal")
            .notification_source()
            .is_some()
    );
    drop(ledger);
    drop(journal);
    drop(pool);
    let reopened = ActionJournalPool::open(config(&dir), worker()).expect("reopen");
    assert_eq!(
        reopened
            .pending_notifications_all(None, 32, deadline())
            .expect("reopened oldest")
            .commits,
        vec![before[0].clone()]
    );
    let reopened_journal = FileActionJournal::open(
        dir.path().join(format!("{}.wal", s.session_id())),
        config(&dir).journal_limits(),
    )
    .expect("original retained authority");
    assert_eq!(
        reopened_journal
            .replay()
            .expect("stable metadata")
            .iter()
            .filter_map(|entry| entry.notifications().cloned())
            .collect::<Vec<_>>(),
        before
    );
}

#[test]
fn negative_approval_and_cancel_preserve_original_identity() {
    for choice in ["deny", "expire", "cancel"] {
        let dir = directory();
        let pool = ActionJournalPool::open(config(&dir), worker()).expect("pool");
        let s = scope();
        let journal = pool.create_notifying_session(&s).expect("journal");
        let ledger = ActionLedger::new(s.ledger_session(), Arc::clone(&journal));
        let (action, id) = pending(&ledger, &s);
        match choice {
            "deny" => ledger.deny_approval(s.fence(), &action),
            "expire" => ledger.expire_approval(s.fence(), &action),
            _ => ledger.cancel_before_dispatch(s.fence(), &action),
        }
        .expect("terminal");
        let entries = journal.replay().expect("original authority");
        let terminal = entries
            .last()
            .expect("terminal record")
            .notifications()
            .expect("terminal commit");
        assert_eq!(terminal.descriptors().len(), 2);
        let expected = if choice == "deny" {
            NotificationApprovalDecision::Denied
        } else {
            NotificationApprovalDecision::Expired
        };
        assert!(
            matches!(terminal.descriptors()[1].event(), WorkerNotificationEvent::ApprovalDecided { approval_id, state, .. } if approval_id == &id && *state == expected)
        );
    }
}

#[test]
fn independent_exact_source_ack_pins_wal_after_positive_custody_release() {
    let dir = directory();
    let pool = ActionJournalPool::open(config(&dir), worker()).expect("pool");
    let s = scope();
    let journal = pool.create_notifying_session(&s).expect("journal");
    let ledger = ActionLedger::new(s.ledger_session(), Arc::clone(&journal));
    let action = success(&ledger, &s);
    let commits = journal
        .replay()
        .expect("original authority")
        .iter()
        .filter_map(|entry| entry.notifications().cloned())
        .collect::<Vec<_>>();
    let receipt = pool
        .receipt(&s, &action)
        .expect("receipt")
        .expect("terminal");
    pool.ack_at(&receipt, NOW).expect("custody copied");
    pool.release_at(&receipt, NOW).expect("custody released");
    pool.seal(&s, NOW).expect("cleaned");
    drop(ledger);
    drop(journal);
    assert_eq!(
        pool.maintain(NOW + TTL + 1, 32, deadline())
            .expect("pending pins"),
        0
    );
    assert_eq!(
        pool.pending_notifications_all(None, 32, deadline())
            .expect("oldest source")
            .commits,
        vec![commits[0].clone()]
    );
    assert!(
        pool.ack_notification(&commits[1].ack(), NOW).is_err(),
        "cannot skip original commit"
    );
    let mut wrong = serde_json::to_value(commits[0].ack()).expect("wire");
    wrong["digest"][0] = serde_json::json!(if commits[0].digest()[0] == 1 { 2 } else { 1 });
    let wrong = serde_json::from_value(wrong).expect("syntactically valid wrong digest");
    assert!(pool.ack_notification(&wrong, NOW).is_err());
    for commit in &commits {
        assert_eq!(
            pool.pending_notifications_all(None, 32, deadline())
                .expect("next exact source head")
                .commits,
            vec![commit.clone()]
        );
        pool.ack_notification(&commit.ack(), NOW + TTL + 2)
            .expect("exact source ack");
    }
    pool.ack_notification(&commits[0].ack(), NOW)
        .expect("old exact duplicate does not regress floor");
    assert!(
        pool.pending_notifications_all(None, 32, deadline())
            .expect("empty")
            .commits
            .is_empty()
    );
    drop(pool);
    let pool = ActionJournalPool::open(config(&dir), worker()).expect("reopen ack");
    assert!(
        pool.pending_notifications_all(None, 32, deadline())
            .expect("still empty")
            .commits
            .is_empty()
    );
    assert_eq!(
        pool.maintain(NOW + 2 * TTL + 1, 32, deadline())
            .expect("ack retention"),
        0
    );
    assert_eq!(
        pool.maintain(NOW + 2 * TTL + 3, 32, deadline())
            .expect("safe release"),
        1
    );
}

#[test]
fn legacy_frames_and_receipt_digests_do_not_acquire_notification_authority() {
    let dir = directory();
    let pool = ActionJournalPool::open(config(&dir), worker()).expect("pool");
    let s = scope();
    let journal = pool.create_session(&s).expect("legacy journal");
    let ledger = ActionLedger::new(s.ledger_session(), Arc::clone(&journal));
    let action = success(&ledger, &s);
    assert!(ledger.notification_source().is_none());
    for entry in journal.replay().expect("legacy entries") {
        let wire = serde_json::to_value(&entry).expect("entry");
        assert!(wire.get("notifications").is_none());
        assert!(wire.get("approval_id").is_none());
    }
    let receipt = pool
        .receipt(&s, &action)
        .expect("receipt")
        .expect("terminal");
    assert!(receipt.notification_source().is_none());
    let legacy = serde_json::to_vec(&receipt).expect("old wire");
    assert!(
        !String::from_utf8(legacy.clone())
            .expect("json")
            .contains("notification_source")
    );
    assert_eq!(
        serde_json::from_slice::<crate::TerminalCustodyReceipt>(&legacy).expect("old receipt"),
        receipt
    );
    let mut h = sha2::Sha256::new();
    use sha2::Digest;
    let payload = serde_json::to_vec(&(
        1_u8,
        receipt.scope(),
        receipt.action_id(),
        receipt.action_sequence(),
        receipt.kind(),
        receipt.request_hash(),
        receipt.dispatch_id(),
        receipt.terminal(),
        receipt.resolution(),
    ))
    .expect("original tuple");
    h.update(b"browserd-terminal-custody-v1\0");
    h.update((payload.len() as u64).to_be_bytes());
    h.update(payload);
    assert_eq!(receipt.digest(), <[u8; 32]>::from(h.finalize()));
    let notifying = receipt
        .clone()
        .with_notification_source(source_scope(&s).expect("source"))
        .expect("bound");
    assert_ne!(notifying.digest(), receipt.digest());
    assert!(
        pool.ack_at(&notifying, NOW).is_err(),
        "fabricated capability cannot release legacy evidence"
    );
    let mut stripped = serde_json::to_value(&notifying).expect("new wire");
    stripped
        .as_object_mut()
        .expect("object")
        .remove("notification_source");
    assert!(serde_json::from_value::<crate::TerminalCustodyReceipt>(stripped).is_err());
}

#[test]
fn complete_uncertain_write_reopens_exact_metadata_without_browser_replay() {
    let dir = directory();
    let s = scope();
    let path = dir.path().join("fault.wal");
    let limits = ActionJournalLimits::new(8192, 64, 65536);
    let journal = Arc::new(
        FileActionJournal::create_new(&path, limits)
            .expect("file")
            .with_notification_source(source_scope(&s).expect("source"))
            .expect("bound"),
    );
    let ledger = ActionLedger::new(s.ledger_session(), Arc::clone(&journal));
    journal.inject_post_write_failure().expect("fault");
    assert!(ledger.accept(s.fence(), request("uncertain")).is_err());
    assert!(
        journal.replay().is_err(),
        "poison prevents publishing ambiguous RAM"
    );
    drop(ledger);
    drop(journal);
    let journal =
        Arc::new(FileActionJournal::open(&path, limits).expect("complete checksum frame recovers"));
    let before = journal.replay().expect("original prefix");
    assert_eq!(before.len(), 1);
    let commit = before[0]
        .notifications()
        .expect("same authority frame")
        .clone();
    assert_eq!(commit.source_sequence(), 1);
    let ledger = ActionLedger::recover(s.ledger_session(), Arc::clone(&journal))
        .expect("recover without effect");
    ledger
        .accept(s.fence(), request("uncertain"))
        .expect("exact same acceptance");
    assert_eq!(journal.replay().expect("no replay"), before);
    assert_eq!(
        journal.replay().expect("stable")[0].notifications(),
        Some(&commit)
    );
}

#[test]
fn terminal_reserve_includes_atomic_notifications_and_identity() {
    let dir = directory();
    let s = scope();
    let path = dir.path().join("reserve.wal");
    let limits = ActionJournalLimits::new(4096, 8, 16384);
    let journal = Arc::new(
        FileActionJournal::create_new(&path, limits)
            .expect("file")
            .with_notification_source(source_scope(&s).expect("source"))
            .expect("bound"),
    );
    let ledger = ActionLedger::new(s.ledger_session(), Arc::clone(&journal));
    let action = ledger
        .accept(s.fence(), request("reserve"))
        .expect("accept")
        .snapshot()
        .action_id()
        .clone();
    let reserved =
        journal.charged_bytes().expect("charge") - fs::metadata(&path).expect("bytes").len();
    ledger.enqueue(s.fence(), &action).expect("queued");
    assert!(
        ledger.require_approval(s.fence(), &action).is_err(),
        "no identity cannot commit notifying requirement"
    );
    ledger
        .require_approval_with_identity(s.fence(), &action, ApprovalId::new())
        .expect("identified");
    let before = fs::metadata(&path).expect("before terminal").len();
    ledger
        .cancel_before_dispatch(s.fence(), &action)
        .expect("reserved terminal commits");
    let growth = fs::metadata(&path).expect("after terminal").len() - before;
    assert!(growth <= reserved);
    let entries = journal.replay().expect("prefix");
    assert_eq!(
        entries
            .last()
            .expect("terminal")
            .notifications()
            .expect("metadata")
            .descriptors()
            .len(),
        2
    );
    assert!(matches!(
        entries
            .last()
            .expect("terminal")
            .notifications()
            .expect("metadata")
            .descriptors()[0]
            .event(),
        WorkerNotificationEvent::ActionStateChanged {
            state: NotificationActionState::CancelledBeforeDispatch,
            ..
        }
    ));
}

#[test]
fn bounded_source_pages_preserve_whole_commits_and_tenant_scope() {
    let dir = directory();
    let pool = ActionJournalPool::open(config(&dir), worker()).expect("pool");
    let s = scope();
    let journal = pool.create_notifying_session(&s).expect("journal");
    let ledger = ActionLedger::new(s.ledger_session(), journal);
    for index in 0..9 {
        ledger
            .accept(s.fence(), request(&format!("accepted-{index}")))
            .expect("accepted");
    }
    for sequence in 1..=9 {
        let page = pool
            .pending_notifications_all(None, 32, deadline())
            .expect("one original source head");
        assert_eq!(page.commits.len(), 1);
        assert_eq!(page.commits[0].source_sequence(), sequence);
        assert!(
            pool.pending_notifications(&TenantId::new(), None, 32, deadline())
                .expect("foreign scan")
                .commits
                .is_empty()
        );
        assert_eq!(
            pool.pending_notifications(s.tenant_id(), None, 32, deadline())
                .expect("own tenant")
                .commits,
            page.commits
        );
        pool.ack_notification(&page.commits[0].ack(), NOW)
            .expect("exact head ack");
    }
    assert!(pool.pending_notifications_all(None, 0, deadline()).is_err());
    assert!(
        pool.pending_notifications_all(None, 33, deadline())
            .is_err()
    );
    assert!(
        pool.pending_notifications_all(None, 32, Instant::now())
            .is_err()
    );
    for index in 0..9 {
        let scope = scope();
        let journal = pool
            .create_notifying_session(&scope)
            .expect("distinct source");
        ActionLedger::new(scope.ledger_session(), journal)
            .accept(scope.fence(), request(&format!("source-{index}")))
            .expect("head");
    }
    let bounded = pool
        .pending_notifications_all(None, 32, deadline())
        .expect("multi source bound");
    assert_eq!(bounded.commits.len(), 8);
    assert!(!bounded.is_complete);
    let mut ids = std::collections::HashSet::new();
    for commit in &bounded.commits {
        assert!(ids.insert(commit.scope().source_id()));
        pool.ack_notification(&commit.ack(), NOW).expect("head ack");
    }
    let last = pool
        .pending_notifications_all(bounded.cursor.as_ref(), 32, deadline())
        .expect("cursor remainder");
    assert_eq!(last.commits.len(), 1);
    assert!(last.is_complete);
    assert!(!ids.contains(&last.commits[0].scope().source_id()));
}
