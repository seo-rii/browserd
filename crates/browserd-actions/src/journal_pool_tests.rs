#![allow(clippy::expect_used, clippy::panic)]
use super::*;
use crate::{
    ActionKind, ActionRequest, ActionSequence, BrowserResult, CanonicalRequestHash,
    DispatchDecision, IdempotencyKey, OutcomeUnknownReason, ResolutionAnnotation, ResolutionKind,
    ResolutionPolicy, ResultDigest, TerminalDetail,
};
use browserd_core::{PlacementFence, PrincipalId};
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use tempfile::TempDir;

const NOW: u64 = 1_800_000_000_000;
fn worker() -> WorkerId {
    WorkerId::new("custody-worker").expect("worker identity")
}
fn new_scope(tenant: TenantId) -> JournalSessionScope {
    JournalSessionScope::new(
        tenant,
        SessionId::new(),
        worker(),
        PlacementFence::new(3, 4, 5),
    )
    .expect("session scope")
}
fn config(dir: &Path) -> ActionJournalPoolConfig {
    ActionJournalPoolConfig::new(
        dir.to_path_buf(),
        ActionJournalLimits::new(8192, 8192, 4 * 1024 * 1024),
    )
    .expect("pool configuration")
}
fn fixture() -> (
    TempDir,
    Arc<ActionJournalPool>,
    JournalSessionScope,
    Arc<ManagedActionJournal>,
    ActionLedger<ManagedActionJournal>,
) {
    let directory = TempDir::new().expect("private directory");
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .expect("directory mode");
    let pool = ActionJournalPool::open(config(directory.path()), worker()).expect("pool open");
    let scope = new_scope(TenantId::new());
    let journal = pool.create_session(&scope).expect("session journal");
    let ledger = ActionLedger::new(scope.ledger_session(), Arc::clone(&journal));
    (directory, pool, scope, journal, ledger)
}
fn request(key: &str) -> ActionRequest {
    ActionRequest::new(
        IdempotencyKey::new(key),
        CanonicalRequestHash::new([17; 32]),
        ActionKind::Mutating,
    )
}
fn success(
    ledger: &ActionLedger<ManagedActionJournal>,
    scope: &JournalSessionScope,
    key: &str,
) -> ActionId {
    let snapshot = ledger
        .accept(scope.fence(), request(key))
        .expect("accepted")
        .snapshot()
        .clone();
    ledger
        .enqueue(scope.fence(), snapshot.action_id())
        .expect("queued");
    ledger
        .mark_ready(scope.fence(), snapshot.action_id())
        .expect("ready");
    let permit = match ledger
        .prepare_dispatch(scope.fence(), snapshot.action_id())
        .expect("dispatch")
    {
        DispatchDecision::Dispatch(p) => p,
        DispatchDecision::DoNotReplay(_) => panic!("first dispatch"),
    };
    ledger
        .record_result(
            scope.fence(),
            &permit,
            BrowserResult::Succeeded(ResultDigest::new([19; 32])),
        )
        .expect("terminal");
    snapshot.action_id().clone()
}
fn unknown(ledger: &ActionLedger<ManagedActionJournal>, scope: &JournalSessionScope) -> ActionId {
    let snapshot = ledger
        .accept(scope.fence(), request("unknown"))
        .expect("accepted")
        .snapshot()
        .clone();
    ledger
        .enqueue(scope.fence(), snapshot.action_id())
        .expect("queued");
    ledger
        .mark_ready(scope.fence(), snapshot.action_id())
        .expect("ready");
    let permit = match ledger
        .prepare_dispatch(scope.fence(), snapshot.action_id())
        .expect("dispatch")
    {
        DispatchDecision::Dispatch(p) => p,
        DispatchDecision::DoNotReplay(_) => panic!("first dispatch"),
    };
    ledger
        .record_transport_loss(
            scope.fence(),
            &permit,
            crate::TransportLoss::Ambiguous(OutcomeUnknownReason::WorkerLost),
        )
        .expect("unknown");
    snapshot.action_id().clone()
}
fn deadline() -> Instant {
    Instant::now() + std::time::Duration::from_secs(5)
}

#[test]
fn copied_terminal_needs_cleanup_seal_retention_and_actual_fd_release() {
    let (dir, pool, scope, journal, ledger) = fixture();
    let id = success(&ledger, &scope, "one");
    let receipt = pool
        .receipt(&scope, &id)
        .expect("receipt")
        .expect("terminal");
    pool.ack_at(&receipt, NOW).expect("copied");
    pool.release_at(&receipt, NOW)
        .expect("final custody release");
    assert_eq!(
        pool.maintain(NOW + RETENTION_DEFAULT, 256, deadline())
            .expect("unsealed"),
        0
    );
    pool.seal(&scope, NOW).expect("cleanup seal");
    assert_eq!(
        pool.maintain(NOW + RETENTION_DEFAULT - 1, 256, deadline())
            .expect("not expired"),
        0
    );
    assert_eq!(
        pool.maintain(NOW - 1, 256, deadline())
            .expect("backwards clock"),
        0
    );
    assert_eq!(
        pool.maintain(NOW + RETENTION_DEFAULT, 256, deadline())
            .expect("ledger pinned"),
        0
    );
    drop(ledger);
    assert_eq!(
        pool.maintain(NOW + RETENTION_DEFAULT, 256, deadline())
            .expect("extra FD pinned"),
        0
    );
    drop(journal);
    assert_eq!(
        pool.maintain(NOW + RETENTION_DEFAULT, 256, deadline())
            .expect("delete"),
        1
    );
    assert!(
        fs::read_dir(dir.path())
            .expect("directory")
            .next()
            .is_none()
    );
    assert!(pool.receipt(&scope, &id).is_err());
}
#[test]
fn nonterminal_and_uncopied_terminal_never_expire() {
    let (_dir, pool, scope, journal, ledger) = fixture();
    let id = ledger
        .accept(scope.fence(), request("pending"))
        .expect("accepted")
        .snapshot()
        .action_id()
        .clone();
    assert!(pool.seal(&scope, NOW).is_err());
    assert!(pool.receipt(&scope, &id).expect("pending query").is_none());
    ledger
        .cancel_before_dispatch(scope.fence(), &id)
        .expect("terminal cancellation");
    pool.seal(&scope, NOW).expect("sealed");
    drop(ledger);
    drop(journal);
    assert_eq!(
        pool.maintain(NOW + RETENTION_DEFAULT * 2, 256, deadline())
            .expect("not copied"),
        0
    );
    let receipt = pool
        .receipt(&scope, &id)
        .expect("historical")
        .expect("terminal");
    pool.ack_at(&receipt, NOW).expect("copy ACK");
    pool.release_at(&receipt, NOW)
        .expect("final custody release");
    assert_eq!(
        pool.maintain(NOW + RETENTION_DEFAULT * 2, 256, deadline())
            .expect("copied"),
        1
    );
}
#[test]
fn resolution_changes_custody_digest_and_invalidates_previous_ack() {
    let (_dir, pool, scope, journal, ledger) = fixture();
    let id = unknown(&ledger, &scope);
    let original = pool
        .receipt(&scope, &id)
        .expect("receipt")
        .expect("terminal");
    pool.ack_at(&original, NOW).expect("unknown copied");
    pool.release_at(&original, NOW)
        .expect("final custody release");
    pool.seal(&scope, NOW).expect("sealed");
    let annotation = ResolutionAnnotation::new(
        ResolutionKind::ConfirmedNotExecuted,
        PrincipalId::new(),
        NOW + 1,
        "operator reviewed exact browser evidence",
    );
    ledger
        .resolve(
            scope.fence(),
            &id,
            annotation.clone(),
            ResolutionPolicy::new(false),
        )
        .expect("resolution");
    let resolved = pool
        .receipt(&scope, &id)
        .expect("resolved receipt")
        .expect("terminal");
    assert_ne!(original.digest(), resolved.digest());
    assert_eq!(resolved.terminal(), original.terminal());
    assert_eq!(resolved.resolution(), Some(&annotation));
    assert!(pool.ack_at(&original, NOW).is_err());
    drop(ledger);
    drop(journal);
    assert_eq!(
        pool.maintain(NOW + RETENTION_DEFAULT, 256, deadline())
            .expect("old ACK"),
        0
    );
    pool.ack_at(&resolved, NOW).expect("new exact ACK");
    pool.release_at(&resolved, NOW)
        .expect("final custody release");
    pool.ack_at(&resolved, NOW).expect("idempotent ACK");
    pool.release_at(&resolved, NOW)
        .expect("final custody release");
    assert_eq!(
        pool.maintain(NOW + RETENTION_DEFAULT, 256, deadline())
            .expect("copied resolution"),
        1
    );
}
#[test]
fn unresolved_unknown_can_be_transferred_without_reclassifying_outcome() {
    let (_dir, pool, scope, journal, ledger) = fixture();
    let id = unknown(&ledger, &scope);
    let receipt = pool
        .receipt(&scope, &id)
        .expect("receipt")
        .expect("terminal");
    assert!(receipt.resolution().is_none());
    assert_eq!(
        receipt.terminal(),
        TerminalDetail::OutcomeUnknown(OutcomeUnknownReason::WorkerLost)
    );
    pool.ack_at(&receipt, NOW).expect("exact unknown custody");
    pool.release_at(&receipt, NOW)
        .expect("final custody release");
    pool.seal(&scope, NOW).expect("sealed");
    drop(ledger);
    drop(journal);
    assert_eq!(
        pool.maintain(NOW + RETENTION_DEFAULT, 1, deadline())
            .expect("delete transferred evidence"),
        1
    );
}
#[test]
fn restart_retains_original_worker_fence_and_replays_without_browser_state() {
    let (dir, pool, scope, journal, ledger) = fixture();
    let id = success(&ledger, &scope, "persisted");
    let original = pool
        .receipt(&scope, &id)
        .expect("receipt")
        .expect("terminal");
    pool.ack_at(&original, NOW).expect("copied");
    pool.release_at(&original, NOW)
        .expect("final custody release");
    pool.seal(&scope, NOW).expect("sealed");
    drop(ledger);
    drop(journal);
    drop(pool);
    let reopened = ActionJournalPool::open(config(dir.path()), worker()).expect("restart");
    assert_eq!(
        reopened.receipt(&scope, &id).expect("historical"),
        Some(original)
    );
    assert_eq!(
        reopened
            .maintain(NOW + RETENTION_DEFAULT, 256, deadline())
            .expect("retention"),
        1
    );
}
#[test]
fn root_exclusion_outlives_owner_when_managed_journal_still_holds_fd() {
    let (dir, pool, _scope, journal, ledger) = fixture();
    assert!(ActionJournalPool::open(config(dir.path()), worker()).is_err());
    drop(pool);
    assert!(ActionJournalPool::open(config(dir.path()), worker()).is_err());
    drop(ledger);
    assert!(ActionJournalPool::open(config(dir.path()), worker()).is_err());
    drop(journal);
    assert!(ActionJournalPool::open(config(dir.path()), worker()).is_ok());
}
#[test]
fn receipt_and_ack_reject_every_original_fence_component_and_tenant_worker() {
    let (_dir, pool, scope, _journal, ledger) = fixture();
    let id = success(&ledger, &scope, "fenced");
    let receipt = pool
        .receipt(&scope, &id)
        .expect("receipt")
        .expect("terminal");
    let bad_scopes = [
        JournalSessionScope::new(
            TenantId::new(),
            scope.session_id().clone(),
            worker(),
            scope.fence(),
        )
        .expect("tenant"),
        JournalSessionScope::new(
            scope.tenant_id().clone(),
            scope.session_id().clone(),
            WorkerId::new("other-worker").expect("worker"),
            scope.fence(),
        )
        .expect("worker scope"),
        JournalSessionScope::new(
            scope.tenant_id().clone(),
            scope.session_id().clone(),
            worker(),
            PlacementFence::new(4, 4, 5),
        )
        .expect("epoch"),
        JournalSessionScope::new(
            scope.tenant_id().clone(),
            scope.session_id().clone(),
            worker(),
            PlacementFence::new(3, 5, 5),
        )
        .expect("placement"),
        JournalSessionScope::new(
            scope.tenant_id().clone(),
            scope.session_id().clone(),
            worker(),
            PlacementFence::new(3, 4, 6),
        )
        .expect("incarnation"),
    ];
    for bad in bad_scopes {
        assert!(pool.receipt(&bad, &id).is_err());
        let forged = TerminalCustodyReceipt::new(
            bad,
            id.clone(),
            receipt.action_sequence(),
            receipt.kind(),
            receipt.request_hash(),
            receipt.dispatch_id().cloned(),
            receipt.terminal(),
            None,
        )
        .expect("internally valid alternate receipt");
        assert!(pool.ack_at(&forged, NOW).is_err());
    }
    let changed_hash = TerminalCustodyReceipt::new(
        scope.clone(),
        id,
        receipt.action_sequence(),
        receipt.kind(),
        CanonicalRequestHash::new([23; 32]),
        receipt.dispatch_id().cloned(),
        receipt.terminal(),
        None,
    )
    .expect("alternate hash");
    assert!(pool.ack_at(&changed_hash, NOW).is_err());
}
#[test]
fn terminal_receipt_wire_rejects_tampering_unknown_fields_and_invalid_resolution() {
    let (_dir, pool, scope, _journal, ledger) = fixture();
    let id = unknown(&ledger, &scope);
    ledger
        .resolve(
            scope.fence(),
            &id,
            ResolutionAnnotation::new(
                ResolutionKind::ConfirmedExecuted,
                PrincipalId::new(),
                NOW,
                "reviewed",
            ),
            ResolutionPolicy::new(false),
        )
        .expect("resolution");
    let receipt = pool
        .receipt(&scope, &id)
        .expect("receipt")
        .expect("terminal");
    let value = serde_json::to_value(&receipt).expect("wire");
    assert_eq!(
        serde_json::from_value::<TerminalCustodyReceipt>(value.clone()).expect("strict roundtrip"),
        receipt
    );
    for (field, replacement) in [
        ("schema_version", serde_json::json!(2)),
        ("action_sequence", serde_json::json!(0)),
        ("accepted_request_hash", serde_json::json!(vec![1; 32])),
        ("digest", serde_json::json!(vec![0; 32])),
    ] {
        let mut changed = value.clone();
        changed[field] = replacement;
        assert!(serde_json::from_value::<TerminalCustodyReceipt>(changed).is_err());
    }
    let mut changed = value.clone();
    changed["unknown"] = serde_json::json!(true);
    assert!(serde_json::from_value::<TerminalCustodyReceipt>(changed).is_err());
    let mut changed = value;
    changed["resolution"]["unknown"] = serde_json::json!(true);
    assert!(serde_json::from_value::<TerminalCustodyReceipt>(changed).is_err());
    assert!(
        JournalSessionScope::new(
            TenantId::new(),
            SessionId::new(),
            worker(),
            PlacementFence::new(0, 1, 1)
        )
        .is_err()
    );
    assert!(
        TerminalCustodyReceipt::new(
            scope,
            ActionId::new(),
            ActionSequence::new(1),
            ActionKind::Mutating,
            CanonicalRequestHash::new([1; 32]),
            None,
            TerminalDetail::OutcomeUnknown(OutcomeUnknownReason::WorkerLost),
            None
        )
        .is_err()
    );
}
#[test]
fn tenant_inode_limit_preserves_other_tenants_and_global_cap() {
    let dir = TempDir::new().expect("directory");
    let limits = ActionJournalPoolLimits::new(
        4 * METADATA_RESERVATION,
        2 * METADATA_RESERVATION,
        6,
        3,
        RETENTION_DEFAULT,
    )
    .expect("limits");
    let pool = ActionJournalPool::open(
        config(dir.path()).with_limits(limits).expect("config"),
        worker(),
    )
    .expect("pool");
    let tenant = TenantId::new();
    let a = new_scope(tenant.clone());
    let b = new_scope(tenant);
    let c = new_scope(TenantId::new());
    let d = new_scope(TenantId::new());
    let _first = pool.create_session(&a).expect("first tenant");
    assert!(pool.create_session(&b).is_err());
    let _second = pool
        .create_session(&c)
        .expect("other tenant remains available");
    assert!(pool.create_session(&d).is_err());
    assert_eq!(pool.state().expect("state").records.len(), 2);
}
#[test]
fn aggregate_byte_budget_reserves_terminal_before_accepting_more_actions() {
    let scratch = TempDir::new().expect("scratch");
    let scratch_scope = new_scope(TenantId::new());
    let scratch_journal = Arc::new(ManagedActionJournal::unmanaged(
        FileActionJournal::create_new(
            scratch.path().join("sizing.wal"),
            config(scratch.path()).journal_limits(),
        )
        .expect("sizing journal"),
    ));
    let scratch_ledger =
        ActionLedger::new(scratch_scope.ledger_session(), Arc::clone(&scratch_journal));
    scratch_ledger
        .accept(scratch_scope.fence(), request("sizing"))
        .expect("sizing acceptance");
    let required = scratch_journal
        .journal
        .charged_bytes()
        .expect("terminal reserve");
    let dir = TempDir::new().expect("directory");
    let cap = METADATA_RESERVATION + required;
    let limits =
        ActionJournalPoolLimits::new(cap, cap, 3, 3, RETENTION_DEFAULT).expect("byte limits");
    let pool = ActionJournalPool::open(
        config(dir.path()).with_limits(limits).expect("config"),
        worker(),
    )
    .expect("pool");
    let scope = new_scope(TenantId::new());
    let journal = pool.create_session(&scope).expect("journal");
    let ledger = ActionLedger::new(scope.ledger_session(), journal);
    let id = ledger
        .accept(scope.fence(), request("first!"))
        .expect("first accepts including terminal reservation")
        .snapshot()
        .action_id()
        .clone();
    assert!(ledger.accept(scope.fence(), request("second")).is_err());
    ledger
        .cancel_before_dispatch(scope.fence(), &id)
        .expect("terminal succeeds at full quota");
    assert_eq!(
        pool.receipt(&scope, &id)
            .expect("receipt")
            .expect("terminal")
            .terminal(),
        TerminalDetail::CancelledBeforeDispatch
    );
}
#[test]
fn post_write_error_holds_aggregate_charge_and_poisoned_journal_never_dispatches() {
    let (dir, pool, scope, journal, ledger) = fixture();
    let before = pool
        .state()
        .expect("state")
        .records
        .get(scope.session_id())
        .expect("record")
        .wal_charge;
    journal.journal.inject_post_write_failure().expect("inject");
    assert!(ledger.accept(scope.fence(), request("uncertain")).is_err());
    let after = pool
        .state()
        .expect("state")
        .records
        .get(scope.session_id())
        .expect("record")
        .wal_charge;
    assert!(after > before);
    assert!(ledger.accept(scope.fence(), request("retry")).is_err());
    assert!(pool.seal(&scope, NOW).is_err());
    drop(ledger);
    drop(journal);
    drop(pool);
    let reopened = ActionJournalPool::open(config(dir.path()), worker())
        .expect("valid full written frame recovered");
    assert!(
        reopened
            .state()
            .expect("state")
            .records
            .get(scope.session_id())
            .expect("record")
            .wal_charge
            > before
    );
    assert_eq!(
        reopened
            .maintain(NOW + RETENTION_DEFAULT * 2, 256, deadline())
            .expect("unsealed remains"),
        0
    );
}
#[test]
fn custody_ack_commit_then_error_restarts_idempotently_without_losing_evidence() {
    let (dir, pool, scope, journal, ledger) = fixture();
    let id = success(&ledger, &scope, "lost-reply");
    let receipt = pool
        .receipt(&scope, &id)
        .expect("receipt")
        .expect("terminal");
    pool.fault.store(1, Ordering::Release);
    assert!(pool.ack_at(&receipt, NOW).is_err());
    assert!(pool.state().expect("state").poisoned);
    drop(ledger);
    drop(journal);
    drop(pool);
    let reopened =
        ActionJournalPool::open(config(dir.path()), worker()).expect("restart after committed ACK");
    reopened
        .ack_at(&receipt, NOW)
        .expect("idempotent positive durable ACK");
    reopened.release_at(&receipt, NOW).expect("final release");
    reopened.seal(&scope, NOW).expect("cleanup seal");
    assert_eq!(
        reopened
            .maintain(NOW + RETENTION_DEFAULT, 256, deadline())
            .expect("delete"),
        1
    );
}
#[test]
fn deletion_error_keeps_charge_until_restart_finishes_exact_intent() {
    let (dir, pool, scope, journal, ledger) = fixture();
    let id = success(&ledger, &scope, "delete-fault");
    let receipt = pool
        .receipt(&scope, &id)
        .expect("receipt")
        .expect("terminal");
    pool.ack_at(&receipt, NOW).expect("ACK");
    pool.release_at(&receipt, NOW)
        .expect("final custody release");
    pool.seal(&scope, NOW).expect("sealed");
    drop(ledger);
    drop(journal);
    let charged = pool
        .state()
        .expect("state")
        .records
        .get(scope.session_id())
        .expect("record")
        .wal_charge;
    pool.fault.store(2, Ordering::Release);
    assert!(
        pool.maintain(NOW + RETENTION_DEFAULT, 256, deadline())
            .is_err()
    );
    assert_eq!(
        pool.state()
            .expect("state")
            .records
            .get(scope.session_id())
            .expect("record")
            .wal_charge,
        charged
    );
    assert!(pool.create_session(&new_scope(TenantId::new())).is_err());
    drop(pool);
    let reopened = ActionJournalPool::open(config(dir.path()), worker())
        .expect("restart exact deletion intent");
    assert_eq!(
        reopened
            .state()
            .expect("state")
            .records
            .get(scope.session_id())
            .expect("record")
            .wal_charge,
        charged
    );
    reopened
        .release_at(&receipt, NOW + RETENTION_DEFAULT)
        .expect("exact released deletion intent retry");
    assert_eq!(
        reopened
            .maintain(NOW + RETENTION_DEFAULT, 256, deadline())
            .expect("finish removal"),
        1
    );
    assert!(
        fs::read_dir(dir.path())
            .expect("directory")
            .next()
            .is_none()
    );
}
#[test]
fn legacy_without_manifest_stays_charged_and_cannot_be_adopted_or_deleted() {
    let dir = TempDir::new().expect("directory");
    let scope = new_scope(TenantId::new());
    let file = Arc::new(
        FileActionJournal::create_new(
            dir.path().join(format!("{}.wal", scope.session_id())),
            config(dir.path()).journal_limits(),
        )
        .expect("legacy WAL"),
    );
    let ledger = ActionLedger::new(scope.ledger_session(), file);
    let id = ledger
        .accept(scope.fence(), request("legacy"))
        .expect("accepted")
        .snapshot()
        .action_id()
        .clone();
    ledger
        .cancel_before_dispatch(scope.fence(), &id)
        .expect("terminal");
    drop(ledger);
    let pool = ActionJournalPool::open(config(dir.path()), worker()).expect("legacy inventory");
    assert!(
        pool.state()
            .expect("state")
            .records
            .get(scope.session_id())
            .expect("legacy record")
            .wal_charge
            > 8
    );
    assert!(pool.receipt(&scope, &id).is_err());
    assert!(pool.seal(&scope, NOW).is_err());
    assert_eq!(
        pool.maintain(NOW + RETENTION_DEFAULT * 10, 256, deadline())
            .expect("legacy pin"),
        0
    );
    assert!(
        dir.path()
            .join(format!("{}.wal", scope.session_id()))
            .is_file()
    );
}
#[test]
fn exact_inode_replacement_is_never_deleted_or_freed() {
    let (dir, pool, scope, journal, ledger) = fixture();
    let id = success(&ledger, &scope, "foreign");
    let receipt = pool
        .receipt(&scope, &id)
        .expect("receipt")
        .expect("terminal");
    pool.ack_at(&receipt, NOW).expect("ACK");
    pool.release_at(&receipt, NOW)
        .expect("final custody release");
    pool.seal(&scope, NOW).expect("sealed");
    drop(ledger);
    drop(journal);
    let path = pool.wal_path(scope.session_id());
    fs::rename(&path, dir.path().join("saved-original")).expect("move original");
    fs::write(&path, b"foreign generation").expect("foreign file");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("private mode");
    assert!(
        pool.maintain(NOW + RETENTION_DEFAULT, 256, deadline())
            .is_err()
    );
    assert_eq!(
        fs::read(&path).expect("foreign remains"),
        b"foreign generation"
    );
    assert!(
        pool.state()
            .expect("state")
            .records
            .contains_key(scope.session_id())
    );
}
#[test]
fn failed_provisioning_discards_only_empty_unpinned_exact_session() {
    let (_dir, pool, scope, journal, ledger) = fixture();
    assert!(pool.discard_unadmitted(&scope).is_err());
    drop(ledger);
    assert!(pool.discard_unadmitted(&scope).is_err());
    drop(journal);
    pool.discard_unadmitted(&scope)
        .expect("empty unpinned cleanup");
    assert!(pool.state().expect("state").records.is_empty());
    let scope = new_scope(TenantId::new());
    let journal = pool.create_session(&scope).expect("next journal");
    let ledger = ActionLedger::new(scope.ledger_session(), Arc::clone(&journal));
    let _ = ledger
        .accept(scope.fence(), request("accepted"))
        .expect("accepted");
    drop(ledger);
    drop(journal);
    assert!(pool.discard_unadmitted(&scope).is_err());
}
#[test]
fn maintenance_is_bounded_fair_and_validates_limits() {
    let (_dir, pool, scope, journal, ledger) = fixture();
    let id = success(&ledger, &scope, "first");
    pool.ack_at(
        &pool
            .receipt(&scope, &id)
            .expect("receipt")
            .expect("terminal"),
        NOW,
    )
    .expect("ACK");
    pool.release_at(
        &pool
            .receipt(&scope, &id)
            .expect("receipt")
            .expect("terminal"),
        NOW,
    )
    .expect("final custody release");
    pool.seal(&scope, NOW).expect("sealed");
    drop(ledger);
    drop(journal);
    let other = new_scope(TenantId::new());
    let other_journal = pool.create_session(&other).expect("second journal");
    let other_ledger = ActionLedger::new(other.ledger_session(), Arc::clone(&other_journal));
    let id = success(&other_ledger, &other, "second");
    pool.ack_at(
        &pool
            .receipt(&other, &id)
            .expect("receipt")
            .expect("terminal"),
        NOW,
    )
    .expect("ACK");
    pool.release_at(
        &pool
            .receipt(&other, &id)
            .expect("receipt")
            .expect("terminal"),
        NOW,
    )
    .expect("final custody release");
    pool.seal(&other, NOW).expect("sealed");
    drop(other_ledger);
    drop(other_journal);
    assert!(pool.maintain(NOW, 0, deadline()).is_err());
    assert!(pool.maintain(NOW, 257, deadline()).is_err());
    assert_eq!(
        pool.maintain(NOW + RETENTION_DEFAULT, 1, Instant::now())
            .expect("deadline"),
        0
    );
    assert_eq!(
        pool.maintain(NOW + RETENTION_DEFAULT, 1, deadline())
            .expect("one session"),
        1
    );
    assert_eq!(
        pool.maintain(NOW + RETENTION_DEFAULT, 1, deadline())
            .expect("remaining session"),
        1
    );
}
#[test]
fn startup_denies_symlink_hardlink_wrong_modes_partial_metadata_and_unknown_files() {
    let dir = TempDir::new().expect("directory");
    let external = TempDir::new().expect("external");
    let session = SessionId::new();
    let path = dir.path().join(format!("{session}.wal"));
    let original = external.path().join("file");
    fs::write(&original, b"BRACTJ01").expect("original");
    fs::set_permissions(&original, fs::Permissions::from_mode(0o600)).expect("mode");
    symlink(&original, &path).expect("symlink");
    assert!(ActionJournalPool::open(config(dir.path()), worker()).is_err());
    fs::remove_file(&path).expect("remove symlink");
    fs::hard_link(&original, &path).expect("hardlink");
    assert!(ActionJournalPool::open(config(dir.path()), worker()).is_err());
    fs::remove_file(&path).expect("remove hardlink");
    fs::write(dir.path().join("unknown"), b"unknown").expect("unknown");
    assert!(ActionJournalPool::open(config(dir.path()), worker()).is_err());
    fs::remove_file(dir.path().join("unknown")).expect("remove");
    fs::write(dir.path().join(format!("{session}.pending")), b"{").expect("partial");
    fs::set_permissions(
        dir.path().join(format!("{session}.pending")),
        fs::Permissions::from_mode(0o600),
    )
    .expect("mode");
    assert!(ActionJournalPool::open(config(dir.path()), worker()).is_err());
    assert!(dir.path().join(format!("{session}.pending")).exists());
}

#[test]
fn interrupted_dispatch_projection_never_fabricates_a_durable_terminal_receipt() {
    let (_dir, pool, scope, journal, ledger) = fixture();
    let terminal = success(&ledger, &scope, "terminal");
    let pending = ledger
        .accept(scope.fence(), request("interrupted"))
        .expect("accepted")
        .snapshot()
        .action_id()
        .clone();
    ledger.enqueue(scope.fence(), &pending).expect("queued");
    ledger.mark_ready(scope.fence(), &pending).expect("ready");
    let _ = ledger
        .prepare_dispatch(scope.fence(), &pending)
        .expect("intent");
    let before = journal.replay().expect("original prefix");
    assert!(
        pool.receipt(&scope, &terminal)
            .expect("other terminal")
            .is_some()
    );
    assert!(pool.receipt(&scope, &pending).expect("pending").is_none());
    assert_eq!(journal.replay().expect("unchanged original prefix"), before);
    assert!(pool.seal(&scope, NOW).is_err());
}
#[test]
fn valid_pending_atomic_ack_replacement_is_recovered_before_new_admission() {
    let (dir, pool, scope, journal, ledger) = fixture();
    let id = success(&ledger, &scope, "pending-replacement");
    let receipt = pool
        .receipt(&scope, &id)
        .expect("receipt")
        .expect("terminal");
    pool.fault.store(3, Ordering::Release);
    assert!(pool.ack_at(&receipt, NOW).is_err());
    assert!(
        dir.path()
            .join(ActionJournalPool::pending_name(scope.session_id()))
            .is_file()
    );
    drop(ledger);
    drop(journal);
    drop(pool);
    let reopened = ActionJournalPool::open(config(dir.path()), worker())
        .expect("recover completed pending envelope");
    assert!(
        !dir.path()
            .join(ActionJournalPool::pending_name(scope.session_id()))
            .exists()
    );
    reopened
        .ack_at(&receipt, NOW)
        .expect("canonical ACK survived");
    reopened.release_at(&receipt, NOW).expect("final release");
    reopened.seal(&scope, NOW).expect("cleanup proof");
    assert_eq!(
        reopened
            .maintain(NOW + RETENTION_DEFAULT, 256, deadline())
            .expect("retention"),
        1
    );
}
#[test]
fn concurrent_accepts_cannot_oversubscribe_shared_worker_byte_reservations() {
    let scratch = TempDir::new().expect("scratch");
    let scratch_scope = new_scope(TenantId::new());
    let file = Arc::new(ManagedActionJournal::unmanaged(
        FileActionJournal::create_new(
            scratch.path().join("sizing.wal"),
            config(scratch.path()).journal_limits(),
        )
        .expect("sizing"),
    ));
    let ledger = ActionLedger::new(scratch_scope.ledger_session(), Arc::clone(&file));
    ledger
        .accept(scratch_scope.fence(), request("sizing"))
        .expect("sizing acceptance");
    let required = file.journal.charged_bytes().expect("reserved bytes");
    let directory = TempDir::new().expect("directory");
    let cap = 2 * METADATA_RESERVATION + 8 + required;
    let limits = ActionJournalPoolLimits::new(cap, cap, 6, 6, RETENTION_DEFAULT).expect("limits");
    let pool = ActionJournalPool::open(
        config(directory.path())
            .with_limits(limits)
            .expect("config"),
        worker(),
    )
    .expect("pool");
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let mut threads = Vec::new();
    for _ in 0..2 {
        let scope = new_scope(TenantId::new());
        let journal = pool.create_session(&scope).expect("journal slot");
        let barrier = Arc::clone(&barrier);
        threads.push(std::thread::spawn(move || {
            let ledger = ActionLedger::new(scope.ledger_session(), journal);
            barrier.wait();
            ledger.accept(scope.fence(), request("sizing")).is_ok()
        }));
    }
    let accepted = threads
        .into_iter()
        .map(|thread| usize::from(thread.join().expect("owned thread")))
        .sum::<usize>();
    assert_eq!(accepted, 1);
}

#[test]
fn delayed_copy_ack_starts_new_horizon_and_copy_alone_never_authorizes_delete() {
    let (dir, pool, scope, journal, ledger) = fixture();
    let id = success(&ledger, &scope, "delayed-ack");
    let receipt = pool
        .receipt(&scope, &id)
        .expect("receipt")
        .expect("terminal");
    pool.seal(&scope, NOW).expect("cleanup");
    drop(ledger);
    drop(journal);
    let late = NOW + 5 * RETENTION_DEFAULT;
    pool.ack_at(&receipt, late).expect("late copy ACK");
    assert_eq!(
        pool.maintain(late, 256, deadline())
            .expect("late ACK remains"),
        0
    );
    assert_eq!(
        pool.maintain(late + 10 * RETENTION_DEFAULT, 256, deadline())
            .expect("no final release means no deletion"),
        0
    );
    assert!(
        dir.path()
            .join(format!("{}.wal", scope.session_id()))
            .is_file()
    );
    pool.release_at(&receipt, late + 10 * RETENTION_DEFAULT)
        .expect("final release");
    let horizon = late + 10 * RETENTION_DEFAULT;
    assert_eq!(
        pool.maintain(horizon + RETENTION_DEFAULT - 1, 256, deadline())
            .expect("full release retry grace"),
        0
    );
    assert_eq!(
        pool.maintain(horizon + RETENTION_DEFAULT, 256, deadline())
            .expect("delete"),
        1
    );
}
#[test]
fn lost_copy_ack_retries_within_grace_after_restart_then_requires_final_release() {
    let (dir, pool, scope, journal, ledger) = fixture();
    let id = success(&ledger, &scope, "lost-late-ack");
    let receipt = pool
        .receipt(&scope, &id)
        .expect("receipt")
        .expect("terminal");
    pool.seal(&scope, NOW).expect("cleanup");
    drop(ledger);
    drop(journal);
    let late = NOW + 5 * RETENTION_DEFAULT;
    pool.fault.store(1, Ordering::Release);
    assert!(pool.ack_at(&receipt, late).is_err());
    drop(pool);
    let reopened = ActionJournalPool::open(config(dir.path()), worker()).expect("restart");
    assert_eq!(
        reopened
            .maintain(late + RETENTION_DEFAULT - 1, 256, deadline())
            .expect("retry grace survives restart"),
        0
    );
    let retry = late + RETENTION_DEFAULT - 1;
    reopened
        .ack_at(&receipt, retry)
        .expect("same exact ACK retry succeeds");
    assert_eq!(
        reopened
            .maintain(retry + 100 * RETENTION_DEFAULT, 256, deadline())
            .expect("copy response lost indefinitely remains pinned"),
        0
    );
    reopened
        .release_at(&receipt, retry)
        .expect("coordinator confirmed ACK then released");
    assert_eq!(
        reopened
            .maintain(retry + RETENTION_DEFAULT - 1, 256, deadline())
            .expect("new retry horizon"),
        0
    );
    assert_eq!(
        reopened
            .maintain(retry + RETENTION_DEFAULT, 256, deadline())
            .expect("delete"),
        1
    );
}
#[test]
fn lost_final_release_response_can_retry_after_deletion_and_restart() {
    let (dir, pool, scope, journal, ledger) = fixture();
    let id = success(&ledger, &scope, "lost-release");
    let receipt = pool
        .receipt(&scope, &id)
        .expect("receipt")
        .expect("terminal");
    pool.ack_at(&receipt, NOW).expect("positive copy ACK");
    pool.seal(&scope, NOW).expect("cleanup");
    drop(ledger);
    drop(journal);
    let release = NOW + 10;
    pool.fault.store(1, Ordering::Release);
    assert!(pool.release_at(&receipt, release).is_err());
    drop(pool);
    let reopened =
        ActionJournalPool::open(config(dir.path()), worker()).expect("restart released manifest");
    assert_eq!(
        reopened
            .maintain(release + RETENTION_DEFAULT, 256, deadline())
            .expect("delete after final release"),
        1
    );
    reopened
        .release_at(&receipt, release + 2 * RETENTION_DEFAULT)
        .expect("lost final response converges after deletion");
    assert!(
        reopened
            .ack_at(&receipt, release + 2 * RETENTION_DEFAULT)
            .is_err()
    );
    drop(reopened);
    let reopened = ActionJournalPool::open(config(dir.path()), worker()).expect("empty restart");
    reopened
        .release_at(&receipt, release + 3 * RETENTION_DEFAULT)
        .expect("absent original scope remains idempotent");
    assert!(reopened.state().expect("state").records.is_empty());
}
#[test]
fn final_release_requires_current_copy_ack_and_old_resolution_release_is_invalid() {
    let (_dir, pool, scope, journal, ledger) = fixture();
    let id = unknown(&ledger, &scope);
    let original = pool
        .receipt(&scope, &id)
        .expect("receipt")
        .expect("terminal");
    assert!(pool.release_at(&original, NOW).is_err());
    pool.ack_at(&original, NOW).expect("copy");
    pool.release_at(&original, NOW).expect("first release");
    pool.seal(&scope, NOW).expect("cleanup");
    ledger
        .resolve(
            scope.fence(),
            &id,
            ResolutionAnnotation::new(
                ResolutionKind::ConfirmedExecuted,
                PrincipalId::new(),
                NOW + 1,
                "new operator review",
            ),
            ResolutionPolicy::new(false),
        )
        .expect("resolution");
    let current = pool
        .receipt(&scope, &id)
        .expect("receipt")
        .expect("current");
    assert!(pool.release_at(&original, NOW + 1).is_err());
    assert!(pool.release_at(&current, NOW + 1).is_err());
    pool.ack_at(&current, NOW + 1)
        .expect("new copy ACK clears old release");
    drop(ledger);
    drop(journal);
    assert_eq!(
        pool.maintain(NOW + RETENTION_DEFAULT * 5, 256, deadline())
            .expect("new resolution needs new final release"),
        0
    );
    pool.release_at(&current, NOW + 2)
        .expect("new final release");
    assert_eq!(
        pool.maintain(NOW + 2 + RETENTION_DEFAULT, 256, deadline())
            .expect("delete current resolution"),
        1
    );
}
#[test]
fn final_release_absence_proof_refuses_recreated_scope_and_foreign_file() {
    let (dir, pool, scope, journal, ledger) = fixture();
    let id = success(&ledger, &scope, "old");
    let receipt = pool
        .receipt(&scope, &id)
        .expect("receipt")
        .expect("terminal");
    pool.ack_at(&receipt, NOW).expect("copy");
    pool.release_at(&receipt, NOW).expect("release");
    pool.seal(&scope, NOW).expect("cleanup");
    drop(ledger);
    drop(journal);
    assert_eq!(
        pool.maintain(NOW + RETENTION_DEFAULT, 256, deadline())
            .expect("delete"),
        1
    );
    let new = JournalSessionScope::new(
        scope.tenant_id().clone(),
        scope.session_id().clone(),
        worker(),
        PlacementFence::new(4, 5, 6),
    )
    .expect("replacement scope");
    let replacement = pool.create_session(&new).expect("replacement");
    assert!(pool.release_at(&receipt, NOW + RETENTION_DEFAULT).is_err());
    drop(replacement);
    pool.discard_unadmitted(&new)
        .expect("empty replacement removal");
    let path = dir.path().join(format!("{}.wal", scope.session_id()));
    fs::write(&path, b"foreign").expect("foreign");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("private");
    assert!(pool.release_at(&receipt, NOW + RETENTION_DEFAULT).is_err());
    assert_eq!(fs::read(path).expect("not removed"), b"foreign");
}
#[test]
fn duplicate_ack_and_release_preserve_monotonic_horizon_under_backwards_clock() {
    let (_dir, pool, scope, journal, ledger) = fixture();
    let id = success(&ledger, &scope, "clock");
    let receipt = pool
        .receipt(&scope, &id)
        .expect("receipt")
        .expect("terminal");
    pool.seal(&scope, NOW).expect("cleanup");
    pool.ack_at(&receipt, NOW + 200).expect("copy");
    pool.release_at(&receipt, NOW + 100).expect("release");
    pool.ack_at(&receipt, NOW + 50)
        .expect("backwards duplicate copy");
    pool.release_at(&receipt, NOW + 20)
        .expect("backwards duplicate release");
    let manifest = pool.exact_record(&scope).expect("manifest").0;
    assert_eq!(manifest.last_ack_at, Some(NOW + 200));
    assert_eq!(manifest.last_release_at, Some(NOW + 100));
    assert!(manifest.acks[0].released);
    drop(ledger);
    drop(journal);
    assert_eq!(
        pool.maintain(NOW + 200 + RETENTION_DEFAULT - 1, 256, deadline())
            .expect("still grace"),
        0
    );
    assert_eq!(
        pool.maintain(NOW + 200 + RETENTION_DEFAULT, 256, deadline())
            .expect("delete"),
        1
    );
}
#[test]
fn worst_case_ack_and_release_metadata_stays_within_reserved_manifest_bound() {
    let scope = new_scope(TenantId::new());
    let manifest = Manifest {
        schema_version: 1,
        scope,
        device: u64::MAX,
        inode: u64::MAX,
        sealed_at: Some(u64::MAX),
        last_ack_at: Some(u64::MAX),
        last_release_at: Some(u64::MAX),
        delete_intent: false,
        delete_charge: None,
        acks: (0..MAX_ACTIONS)
            .map(|_| CustodyAck {
                action_id: ActionId::new(),
                digest: [255; 32],
                released: true,
            })
            .collect(),
        notifications_enabled: false,
        notification_ack: None,
        last_notification_ack_at: None,
    };
    validate_manifest(&manifest, &worker()).expect("bound record valid");
    assert!(
        manifest_bytes(&manifest)
            .expect("complete ACK and release state")
            .len()
            <= MANIFEST_BYTES as usize
    );
}

#[test]
fn notifying_ack_uncertain_atomic_replace_recovers_the_exact_original_commit() {
    let directory = TempDir::new().expect("directory");
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).expect("private");
    let pool = ActionJournalPool::open(config(directory.path()), worker()).expect("pool");
    let scope = new_scope(TenantId::new());
    let journal = pool
        .create_notifying_session(&scope)
        .expect("notifying authority");
    let ledger = ActionLedger::new(scope.ledger_session(), Arc::clone(&journal));
    ledger
        .accept(scope.fence(), request("notification-ack-fault"))
        .expect("authority committed");
    let original = pool
        .pending_notifications_all(None, 32, deadline())
        .expect("read")
        .commits;
    assert_eq!(original.len(), 1);
    drop(ledger);
    drop(journal);
    pool.fault.store(3, Ordering::Release);
    assert!(pool.ack_notification(&original[0].ack(), NOW).is_err());
    assert!(
        pool.pending_notifications_all(None, 32, deadline())
            .is_err(),
        "uncertain replacement poisons publication"
    );
    drop(pool);
    let reopened = ActionJournalPool::open(config(directory.path()), worker())
        .expect("recover synced replacement");
    assert!(
        reopened
            .pending_notifications_all(None, 32, deadline())
            .expect("durable exact ack")
            .commits
            .is_empty()
    );
    reopened
        .ack_notification(&original[0].ack(), NOW)
        .expect("same exact retry");
}
