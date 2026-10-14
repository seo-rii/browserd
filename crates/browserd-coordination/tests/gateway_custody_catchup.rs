#![allow(clippy::expect_used)]

#[allow(dead_code)]
#[path = "support/gateway_custody_cases.rs"]
mod cases;

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use browserd_actions::{
    ActionKind, BrowserResult, CanonicalRequestHash, JournalSessionScope, KnownFailureReason,
    OutcomeUnknownReason, ResolutionAnnotation, ResolutionKind, ResultDigest,
    TerminalCustodyReceipt, TerminalCustodyRequirement, TerminalDetail,
};
use browserd_coordination::{
    ClaimGatewayAction, CoordinationActorConfig, GatewayActionBlockingClient,
    GatewayActionCoordination, GatewayActionCoordinationError as Error,
    GatewayActionRecoveryCursor, GatewayActionRetentionClock, GatewayActionRetentionCursor,
    GatewayActionRetentionLimits, GatewayActionSnapshot, GatewayCustodyCursor,
    MemoryCoordinationDatabase, MemoryGatewayActionStore, StoreConfig,
};
use browserd_core::{ActionId, PrincipalId, TenantId};
use chrono::{DateTime, Duration, Utc};

struct Clock(AtomicI64);
impl Clock {
    fn advance(&self, duration: Duration) {
        self.0
            .fetch_add(duration.num_milliseconds(), Ordering::SeqCst);
    }
}
impl GatewayActionRetentionClock for Clock {
    fn now(&self) -> DateTime<Utc> {
        DateTime::from_timestamp_millis(self.0.load(Ordering::SeqCst)).expect("UTC clock")
    }
}
struct Fixture {
    database: MemoryCoordinationDatabase,
    clock: Arc<Clock>,
    store: MemoryGatewayActionStore,
}
impl Fixture {
    fn new() -> Self {
        let database = MemoryCoordinationDatabase::default();
        let clock = Arc::new(Clock(AtomicI64::new(Utc::now().timestamp_millis())));
        let store = MemoryGatewayActionStore::attach(database.clone(), StoreConfig::default())
            .with_retention_clock(clock.clone());
        Self {
            database,
            clock,
            store,
        }
    }
    async fn terminal(
        &self,
        action: &cases::Action,
        detail: TerminalDetail,
        requirement: Option<TerminalCustodyRequirement>,
    ) -> GatewayActionSnapshot {
        self.store
            .record_worker_terminal_with_custody(
                &action.tenant,
                &action.session,
                &action.action,
                action.armed.revision(),
                &action.placement,
                &action.dispatch,
                action.armed.action_sequence(),
                detail,
                None,
                requirement,
                Utc::now(),
            )
            .await
            .expect("terminal without optional custody")
    }
    async fn get(&self, action: &cases::Action) -> GatewayActionSnapshot {
        self.store
            .get_effective_action(&action.tenant, &action.session, &action.action)
            .await
            .expect("get")
            .expect("retained")
    }
    async fn attach(
        &self,
        action: &cases::Action,
        revision: u64,
        receipt: TerminalCustodyReceipt,
    ) -> Result<GatewayActionSnapshot, Error> {
        self.store
            .attach_terminal_custody(
                &action.tenant,
                &action.session,
                &action.action,
                revision,
                &action.placement,
                receipt,
            )
            .await
    }
}
fn known() -> TerminalDetail {
    TerminalDetail::FailedKnown(KnownFailureReason::BrowserRejected)
}
fn unknown() -> TerminalDetail {
    TerminalDetail::OutcomeUnknown(OutcomeUnknownReason::TimeoutAfterDispatch)
}
fn annotation() -> ResolutionAnnotation {
    ResolutionAnnotation::new(
        ResolutionKind::ConfirmedExecuted,
        PrincipalId::new(),
        42,
        "exact operator observation",
    )
}
fn same_terminal_metadata(before: &GatewayActionSnapshot, after: &GatewayActionSnapshot) {
    assert_eq!(before.terminal(), after.terminal());
    assert_eq!(before.revision(), after.revision());
    assert_eq!(before.resolution(), after.resolution());
    assert_eq!(before.result_content(), after.result_content());
    assert_eq!(before.retain_until(), after.retain_until());
    assert_eq!(before.updated_at(), after.updated_at());
    assert_eq!(
        before.last_source_event_sequence(),
        after.last_source_event_sequence()
    );
    assert_eq!(
        before.original_worker_terminal_revision(),
        after.original_worker_terminal_revision()
    );
}

#[tokio::test]
async fn missing_required_proof_keeps_result_and_capacity_until_copy_and_release() {
    let mut f = Fixture::new();
    f.store = f.store.with_retention_limits(
        GatewayActionRetentionLimits::new(1, 1).expect("one retained payload"),
    );
    let action = cases::Action::new(&f.store).await;
    let bytes = b"known-terminal-body".to_vec();
    let digest = ResultDigest::new([19; 32]);
    let terminal = f
        .store
        .record_worker_result_with_custody(
            &action.tenant,
            &action.session,
            &action.action,
            action.armed.revision(),
            &action.placement,
            &action.dispatch,
            action.armed.action_sequence(),
            BrowserResult::Succeeded(digest),
            Some(bytes.clone()),
            None,
            Some(TerminalCustodyRequirement::Required),
            Utc::now(),
        )
        .await
        .expect("known result survives projection failure");
    assert!(terminal.requires_terminal_custody_catchup());
    assert_eq!(
        terminal.original_worker_terminal_revision(),
        Some(terminal.revision())
    );
    action.events(&f.store).await;
    f.clock.advance(Duration::days(3));
    assert_eq!(
        f.store
            .maintain_action_retention(GatewayActionRetentionCursor::default(), 1)
            .await
            .expect("GC pin")
            .deferred(),
        1
    );
    let claim = ClaimGatewayAction::new(
        action.tenant.clone(),
        action.session.clone(),
        ActionId::new(),
        "no-free-slot",
        CanonicalRequestHash::new([2; 32]),
        ActionKind::ReadOnly,
        action.placement.clone(),
    )
    .expect("claim");
    assert_eq!(
        f.store.claim_action(claim, Utc::now()).await,
        Err(Error::RetainedActionCapacity)
    );
    let page = f
        .store
        .scan_terminal_custody_catchup(GatewayActionRecoveryCursor::default(), 1)
        .await
        .expect("independent discovery");
    assert_eq!(page.examined(), 1);
    assert_eq!(page.actions(), std::slice::from_ref(&terminal));
    let receipt = action.receipt(TerminalDetail::Succeeded(digest), None);
    let attached = f
        .attach(&action, terminal.revision(), receipt.clone())
        .await
        .expect("copy metadata");
    same_terminal_metadata(&terminal, &attached);
    assert_eq!(attached.result_content(), Some(bytes.as_slice()));
    assert!(!attached.requires_terminal_custody_catchup());
    assert!(
        f.store
            .peek_event_projection(&action.tenant, &action.session)
            .await
            .expect("no duplicate source")
            .is_none()
    );
    let page = f
        .store
        .scan_pending_custody(GatewayCustodyCursor::default(), 1)
        .await
        .expect("copy obligation");
    let copy = &page.entries()[0];
    assert_eq!(copy.receipt(), &receipt);
    assert_eq!(copy.action_revision(), terminal.revision());
    f.store
        .ack_pending_custody(copy, Utc::now())
        .await
        .expect("copy ACK");
    assert_eq!(
        f.store
            .maintain_action_retention(GatewayActionRetentionCursor::default(), 1)
            .await
            .expect("release pin")
            .deferred(),
        1
    );
    cases::release_entry(&f.store, copy).await;
    let retry = f
        .attach(&action, 0, receipt)
        .await
        .expect("lost attach reply remains idempotent after release");
    same_terminal_metadata(&terminal, &retry);
    assert!(
        f.store
            .scan_pending_custody(GatewayCustodyCursor::default(), 1)
            .await
            .expect("no new Copy")
            .entries()
            .is_empty()
    );
    assert_eq!(
        f.store
            .maintain_action_retention(GatewayActionRetentionCursor::default(), 1)
            .await
            .expect("released GC")
            .reclaimed(),
        1
    );
}

#[tokio::test]
async fn delayed_unresolved_receipt_uses_original_anchor_after_gateway_resolution() {
    let f = Fixture::new();
    let action = cases::Action::new(&f.store).await;
    let terminal = f
        .terminal(
            &action,
            unknown(),
            Some(TerminalCustodyRequirement::Required),
        )
        .await;
    let resolution = annotation();
    let resolved = f
        .store
        .resolve_unknown(
            &action.tenant,
            &action.session,
            &action.action,
            terminal.revision(),
            &action.placement,
            resolution.clone(),
            Utc::now(),
        )
        .await
        .expect("gateway-only resolution");
    let receipt = action.receipt(unknown(), None);
    let stale = f
        .attach(&action, terminal.revision(), receipt.clone())
        .await;
    assert!(matches!(stale, Err(Error::StaleWrite(_))));
    assert!(
        f.store
            .scan_pending_custody(GatewayCustodyCursor::default(), 1)
            .await
            .expect("no stale Copy")
            .entries()
            .is_empty()
    );
    let attached = f
        .attach(&action, resolved.revision(), receipt)
        .await
        .expect("historical unresolved proof");
    same_terminal_metadata(&resolved, &attached);
    assert_eq!(attached.resolution(), Some(&resolution));
    let page = f
        .store
        .scan_pending_custody(GatewayCustodyCursor::default(), 1)
        .await
        .expect("historical copy");
    assert_eq!(page.entries()[0].action_revision(), terminal.revision());
    assert_eq!(
        action.events(&f.store).await,
        [terminal.revision(), resolved.revision()]
    );
}

#[tokio::test]
async fn recovered_real_worker_annotation_uses_existing_resolution_transition_once() {
    let f = Fixture::new();
    let action = cases::Action::new(&f.store).await;
    let terminal = f
        .terminal(
            &action,
            unknown(),
            Some(TerminalCustodyRequirement::Required),
        )
        .await;
    let resolution = annotation();
    let receipt = action.receipt(unknown(), Some(resolution.clone()));
    assert_eq!(
        f.attach(&action, terminal.revision(), receipt.clone())
            .await,
        Err(Error::InvalidCustodyReceipt)
    );
    f.clock.advance(Duration::days(3));
    let resolved = f
        .store
        .resolve_unknown_with_custody(
            &action.tenant,
            &action.session,
            &action.action,
            terminal.revision(),
            &action.placement,
            resolution.clone(),
            Some(receipt.clone()),
            Some(TerminalCustodyRequirement::Required),
            Utc::now(),
        )
        .await
        .expect("real worker annotation + proof");
    assert_eq!(resolved.revision(), terminal.revision() + 1);
    assert_eq!(
        resolved.original_worker_terminal_revision(),
        Some(terminal.revision())
    );
    assert_eq!(resolved.resolution(), Some(&resolution));
    assert!(!resolved.requires_terminal_custody_catchup());
    assert!(resolved.retain_until() > terminal.retain_until());
    let replay = f
        .store
        .resolve_unknown_with_custody(
            &action.tenant,
            &action.session,
            &action.action,
            terminal.revision(),
            &action.placement,
            resolution,
            Some(receipt),
            Some(TerminalCustodyRequirement::Required),
            Utc::now(),
        )
        .await
        .expect("lost semantic commit reply");
    assert_eq!(replay, resolved);
    assert_eq!(
        action.events(&f.store).await,
        [terminal.revision(), resolved.revision()]
    );
}

#[tokio::test]
async fn only_original_unsupported_can_bypass_catchup_and_late_downgrade_is_rejected() {
    let f = Fixture::new();
    let unsupported = cases::Action::new(&f.store).await;
    let terminal = f
        .terminal(
            &unsupported,
            known(),
            Some(TerminalCustodyRequirement::Unsupported),
        )
        .await;
    assert!(!terminal.requires_terminal_custody_catchup());
    assert_eq!(
        f.attach(
            &unsupported,
            terminal.revision(),
            unsupported.receipt(known(), None)
        )
        .await,
        Err(Error::InvalidCustodyReceipt)
    );
    let legacy = cases::Action::new(&f.store).await;
    let original = f.terminal(&legacy, known(), None).await;
    assert!(original.requires_terminal_custody_catchup());
    let downgrade = f
        .store
        .record_worker_terminal_with_custody(
            &legacy.tenant,
            &legacy.session,
            &legacy.action,
            original.revision(),
            &legacy.placement,
            &legacy.dispatch,
            legacy.armed.action_sequence(),
            known(),
            None,
            Some(TerminalCustodyRequirement::Unsupported),
            Utc::now(),
        )
        .await;
    assert_eq!(downgrade, Err(Error::InvalidCustodyReceipt));
    assert_eq!(f.get(&legacy).await, original);
    unsupported.events(&f.store).await;
    legacy.events(&f.store).await;
    f.clock.advance(Duration::days(3));
    let page = f
        .store
        .maintain_action_retention(GatewayActionRetentionCursor::default(), 256)
        .await
        .expect("different origin gates");
    assert_eq!((page.reclaimed(), page.deferred()), (1, 1));
    let page = f
        .store
        .scan_terminal_custody_catchup(GatewayActionRecoveryCursor::default(), 256)
        .await
        .expect("legacy discovery");
    assert_eq!(page.actions(), [original]);
}

#[tokio::test]
async fn receipt_identity_terminal_and_resolution_mismatches_leave_known_result_unchanged() {
    let f = Fixture::new();
    let action = cases::Action::new(&f.store).await;
    let terminal = f
        .terminal(&action, known(), Some(TerminalCustodyRequirement::Required))
        .await;
    let valid = action.receipt(known(), None);
    let scope = JournalSessionScope::new(
        TenantId::new(),
        action.session.clone(),
        valid.original_worker_id().clone(),
        valid.fence(),
    )
    .expect("foreign tenant scope");
    let foreign = TerminalCustodyReceipt::new(
        scope,
        valid.action_id().clone(),
        valid.action_sequence(),
        valid.kind(),
        valid.request_hash(),
        valid.dispatch_id().cloned(),
        valid.terminal(),
        None,
    )
    .expect("valid foreign receipt");
    for receipt in [foreign, action.receipt(unknown(), None)] {
        assert_eq!(
            f.attach(&action, terminal.revision(), receipt).await,
            Err(Error::InvalidCustodyReceipt)
        );
        assert_eq!(f.get(&action).await, terminal);
    }
    assert!(
        f.store
            .scan_pending_custody(GatewayCustodyCursor::default(), 1)
            .await
            .expect("no mutation")
            .entries()
            .is_empty()
    );
}

#[tokio::test]
async fn examined_catalog_limit_advances_across_pending_and_unsupported_rows() {
    let f = Fixture::new();
    let mut actions = [
        cases::Action::new(&f.store).await,
        cases::Action::new(&f.store).await,
        cases::Action::new(&f.store).await,
    ];
    actions.sort_by(|a, b| {
        (&a.tenant, &a.session, &a.action).cmp(&(&b.tenant, &b.session, &b.action))
    });
    f.terminal(
        &actions[1],
        known(),
        Some(TerminalCustodyRequirement::Unsupported),
    )
    .await;
    let terminal = f
        .terminal(
            &actions[2],
            known(),
            Some(TerminalCustodyRequirement::Required),
        )
        .await;
    let mut cursor = GatewayActionRecoveryCursor::default();
    for index in 0..3 {
        let page = f
            .store
            .scan_terminal_custody_catchup(cursor, 1)
            .await
            .expect("bounded catalog page");
        assert_eq!(page.examined(), 1);
        assert_eq!(page.is_complete(), index == 2);
        if index == 2 {
            assert_eq!(page.actions(), std::slice::from_ref(&terminal));
        } else {
            assert!(page.actions().is_empty());
        }
        cursor = page.next_cursor().clone();
    }
    for limit in [0, 257] {
        assert!(matches!(
            f.store
                .scan_terminal_custody_catchup(GatewayActionRecoveryCursor::default(), limit)
                .await,
            Err(Error::InvalidCustodyScanLimit)
        ));
    }
}

#[tokio::test]
async fn catalog_and_attach_survive_store_reattach_and_blocking_actor() {
    let f = Fixture::new();
    let action = cases::Action::new(&f.store).await;
    let terminal = f
        .terminal(&action, known(), Some(TerminalCustodyRequirement::Required))
        .await;
    let reopened = MemoryGatewayActionStore::attach(f.database.clone(), StoreConfig::default())
        .with_retention_clock(f.clock.clone());
    let client =
        GatewayActionBlockingClient::spawn(Arc::new(reopened), CoordinationActorConfig::default())
            .expect("actor");
    let receipt = action.receipt(known(), None);
    tokio::task::spawn_blocking(move || {
        let page = client
            .scan_terminal_custody_catchup(GatewayActionRecoveryCursor::default(), 1)
            .expect("actor catalog");
        assert_eq!(page.examined(), 1);
        assert_eq!(page.actions(), std::slice::from_ref(&terminal));
        let attached = client
            .attach_terminal_custody(
                &action.tenant,
                &action.session,
                &action.action,
                terminal.revision(),
                &action.placement,
                receipt,
            )
            .expect("actor pure metadata attachment");
        same_terminal_metadata(&terminal, &attached);
        assert_eq!(
            client
                .scan_pending_custody(GatewayCustodyCursor::default(), 1)
                .expect("actor copy")
                .entries()
                .len(),
            1
        );
    })
    .await
    .expect("joined client");
}

#[tokio::test]
async fn concurrent_attach_and_gateway_resolution_keep_one_copy_and_two_source_events() {
    let f = Fixture::new();
    let action = cases::Action::new(&f.store).await;
    let terminal = f
        .terminal(
            &action,
            unknown(),
            Some(TerminalCustodyRequirement::Required),
        )
        .await;
    let barrier = Arc::new(tokio::sync::Barrier::new(3));
    let store = f.store.clone();
    let sync = barrier.clone();
    let tenant = action.tenant.clone();
    let session = action.session.clone();
    let aid = action.action.clone();
    let placement = action.placement.clone();
    let revision = terminal.revision();
    let receipt = action.receipt(unknown(), None);
    let attaching = tokio::spawn(async move {
        sync.wait().await;
        store
            .attach_terminal_custody(&tenant, &session, &aid, revision, &placement, receipt)
            .await
    });
    let store = f.store.clone();
    let sync = barrier.clone();
    let tenant = action.tenant.clone();
    let session = action.session.clone();
    let aid = action.action.clone();
    let placement = action.placement.clone();
    let resolution = annotation();
    let expected = resolution.clone();
    let resolving = tokio::spawn(async move {
        sync.wait().await;
        store
            .resolve_unknown(
                &tenant,
                &session,
                &aid,
                revision,
                &placement,
                resolution,
                Utc::now(),
            )
            .await
    });
    barrier.wait().await;
    let attach = attaching.await.expect("attach join");
    assert!(attach.is_ok() || matches!(attach, Err(Error::StaleWrite(_))));
    resolving.await.expect("resolve join").expect("resolution");
    let current = f.get(&action).await;
    let attached = f
        .attach(&action, current.revision(), action.receipt(unknown(), None))
        .await
        .expect("convergent attachment");
    assert_eq!(attached.resolution(), Some(&expected));
    assert_eq!(
        f.store
            .scan_pending_custody(GatewayCustodyCursor::default(), 256)
            .await
            .expect("one Copy")
            .entries()
            .len(),
        1
    );
    assert_eq!(
        action.events(&f.store).await,
        [terminal.revision(), terminal.revision() + 1]
    );
}
