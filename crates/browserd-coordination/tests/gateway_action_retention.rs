#![allow(clippy::expect_used)]

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use browserd_actions::{
    ActionKind, CanonicalRequestHash, DispatchId, JournalSessionScope, KnownFailureReason,
    OutcomeUnknownReason, ResolutionAnnotation, ResolutionKind, TerminalCustodyReceipt,
    TerminalCustodyRequirement, TerminalDetail,
};
use browserd_coordination::{
    ClaimGatewayAction, CoordinationActorConfig, DirectoryFence, GatewayActionBlockingClient,
    GatewayActionClaimOutcome, GatewayActionCoordination, GatewayActionCoordinationError as Error,
    GatewayActionPlacement, GatewayActionRetentionClock, GatewayActionRetentionCursor,
    GatewayActionRetentionLimits, GatewayActionRetentionPage, GatewayActionSnapshot,
    GatewayCustodyCursor, MemoryCoordinationDatabase, MemoryGatewayActionStore, SessionLossClaim,
    StoreConfig,
};
use browserd_core::{ActionId, PlacementFence, PrincipalId, SessionId, TenantId, WorkerId};
use chrono::{DateTime, Duration, TimeZone, Utc};
use uuid::Uuid;

struct Clock(AtomicI64);
impl Clock {
    fn new() -> Self {
        Self(AtomicI64::new(
            Utc.with_ymd_and_hms(2026, 8, 30, 12, 0, 0)
                .single()
                .expect("fixed UTC")
                .timestamp_millis(),
        ))
    }
    fn set(&self, at: DateTime<Utc>) {
        self.0.store(at.timestamp_millis(), Ordering::SeqCst);
    }
    fn advance(&self, duration: Duration) {
        self.0
            .fetch_add(duration.num_milliseconds(), Ordering::SeqCst);
    }
}
impl GatewayActionRetentionClock for Clock {
    fn now(&self) -> DateTime<Utc> {
        DateTime::from_timestamp_millis(self.0.load(Ordering::SeqCst)).expect("UTC fixture clock")
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
        let clock = Arc::new(Clock::new());
        let store = MemoryGatewayActionStore::attach(database.clone(), StoreConfig::default())
            .with_retention_clock(clock.clone());
        Self {
            database,
            clock,
            store,
        }
    }
    fn reopen(&self) -> MemoryGatewayActionStore {
        MemoryGatewayActionStore::attach(self.database.clone(), StoreConfig::default())
            .with_retention_clock(self.clock.clone())
    }
    async fn claim(&self, scope: &Scope, key: &str, kind: ActionKind) -> GatewayActionSnapshot {
        self.store
            .claim_action(scope.claim(key, ActionId::new(), kind), self.clock.now())
            .await
            .expect("accepted")
            .into_snapshot()
    }
    async fn cancelled(
        &self,
        scope: &Scope,
        snapshot: &GatewayActionSnapshot,
    ) -> GatewayActionSnapshot {
        self.store
            .cancel_before_dispatch(
                &scope.tenant,
                &scope.session,
                snapshot.action_id(),
                snapshot.revision(),
                &scope.placement,
                self.clock.now(),
            )
            .await
            .expect("known pre-dispatch cancellation")
    }
    async fn maintain(&self, limit: usize) -> GatewayActionRetentionPage {
        self.store
            .maintain_action_retention(GatewayActionRetentionCursor::default(), limit)
            .await
            .expect("bounded retention")
    }
    async fn get(&self, scope: &Scope, action: &ActionId) -> Option<GatewayActionSnapshot> {
        self.store
            .get_effective_action(&scope.tenant, &scope.session, action)
            .await
            .expect("get")
    }
    async fn ack_source(&self, scope: &Scope) -> Vec<u64> {
        let mut sequences = Vec::new();
        while let Some(event) = self
            .store
            .peek_event_projection(&scope.tenant, &scope.session)
            .await
            .expect("source peek")
        {
            assert!(sequences.len() < 32, "bounded fixture source queue");
            sequences.push(event.sequence());
            self.store
                .ack_event_projection(&event)
                .await
                .expect("exact source ACK");
        }
        sequences
    }
    async fn complete(
        &self,
        scope: &Scope,
        snapshot: &GatewayActionSnapshot,
        detail: TerminalDetail,
        resolution: Option<ResolutionAnnotation>,
        with_custody: bool,
    ) -> Completed {
        let dispatch = DispatchId::new();
        let armed = self
            .store
            .arm_dispatch(
                &scope.tenant,
                &scope.session,
                snapshot.action_id(),
                snapshot.revision(),
                &scope.placement,
                dispatch.clone(),
                self.clock.now(),
            )
            .await
            .expect("arm");
        let receipt = with_custody.then(|| {
            TerminalCustodyReceipt::new(
                JournalSessionScope::new(
                    scope.tenant.clone(),
                    scope.session.clone(),
                    scope.placement.directory_fence().worker_id().clone(),
                    PlacementFence::new(7, 11, 13),
                )
                .expect("scope"),
                snapshot.action_id().clone(),
                snapshot.action_sequence(),
                snapshot.kind(),
                CanonicalRequestHash::new([91; 32]),
                Some(DispatchId::new()),
                detail,
                resolution,
            )
            .expect("internal worker custody")
        });
        let snapshot = self
            .store
            .record_worker_terminal_with_custody(
                &scope.tenant,
                &scope.session,
                snapshot.action_id(),
                armed.revision(),
                &scope.placement,
                &dispatch,
                snapshot.action_sequence(),
                detail,
                receipt.clone(),
                if with_custody {
                    None
                } else {
                    Some(TerminalCustodyRequirement::Unsupported)
                },
                self.clock.now(),
            )
            .await
            .expect("terminal + optional custody");
        Completed {
            snapshot,
            dispatch,
            receipt,
        }
    }
}
struct Completed {
    snapshot: GatewayActionSnapshot,
    dispatch: DispatchId,
    receipt: Option<TerminalCustodyReceipt>,
}
struct Scope {
    tenant: TenantId,
    session: SessionId,
    placement: GatewayActionPlacement,
}
impl Scope {
    fn new() -> Self {
        Self {
            tenant: TenantId::new(),
            session: SessionId::new(),
            placement: GatewayActionPlacement::new(
                DirectoryFence::new(
                    WorkerId::new("retention-worker").expect("worker"),
                    7,
                    11,
                    13,
                )
                .expect("fence"),
                17,
            )
            .expect("placement"),
        }
    }
    fn claim(&self, key: &str, action: ActionId, kind: ActionKind) -> ClaimGatewayAction {
        ClaimGatewayAction::new(
            self.tenant.clone(),
            self.session.clone(),
            action,
            key,
            CanonicalRequestHash::new([1; 32]),
            kind,
            self.placement.clone(),
        )
        .expect("claim")
    }
}
fn known() -> TerminalDetail {
    TerminalDetail::FailedKnown(KnownFailureReason::BrowserRejected)
}
fn unknown() -> TerminalDetail {
    TerminalDetail::OutcomeUnknown(OutcomeUnknownReason::TimeoutAfterDispatch)
}
fn resolution() -> ResolutionAnnotation {
    ResolutionAnnotation::new(
        ResolutionKind::ConfirmedExecuted,
        PrincipalId::new(),
        42,
        "operator confirmed outcome",
    )
}

#[test]
fn bounded_limits_cursor_and_page_reject_invalid_contracts() {
    assert!(GatewayActionRetentionLimits::new(0, 1).is_err());
    assert!(GatewayActionRetentionLimits::new(10, 11).is_err());
    assert!(GatewayActionRetentionLimits::new(1_048_577, 1).is_err());
    assert!(GatewayActionRetentionLimits::new(65_537, 65_537).is_err());
    assert_eq!(
        GatewayActionRetentionLimits::default().namespace_records(),
        65_536
    );
    assert_eq!(
        GatewayActionRetentionLimits::default().session_records(),
        4096
    );
    let cursor = GatewayActionRetentionCursor::default();
    let mut wire = serde_json::to_value(&cursor).expect("cursor JSON");
    wire["schema_version"] = 2.into();
    assert!(serde_json::from_value::<GatewayActionRetentionCursor>(wire).is_err());
    let mut wire = serde_json::to_value(&cursor).expect("cursor JSON");
    wire["unknown"] = true.into();
    assert!(serde_json::from_value::<GatewayActionRetentionCursor>(wire).is_err());
    assert!(GatewayActionRetentionPage::new(cursor.clone(), true, 1, 1, 1).is_err());
    assert!(GatewayActionRetentionPage::new(cursor, false, 257, 257, 0).is_err());
}

#[tokio::test]
async fn source_ack_is_required_and_gc_preserves_identity_and_sequence() {
    let f = Fixture::new();
    let scope = Scope::new();
    let accepted = f
        .claim(&scope, "reuse-after-retention", ActionKind::Mutating)
        .await;
    let terminal = f.cancelled(&scope, &accepted).await;
    assert_eq!(terminal.last_source_event_sequence(), Some(1));
    f.clock.advance(Duration::days(3));
    let page = f.maintain(1).await;
    assert_eq!(
        (page.examined(), page.reclaimed(), page.deferred()),
        (1, 0, 1)
    );
    assert!(f.get(&scope, terminal.action_id()).await.is_some());
    assert_eq!(f.ack_source(&scope).await, [1]);
    assert_eq!(f.maintain(1).await.reclaimed(), 1);
    assert!(f.get(&scope, terminal.action_id()).await.is_none());
    assert!(matches!(
        f.store
            .claim_action(
                scope.claim(
                    "another-key",
                    terminal.action_id().clone(),
                    ActionKind::Mutating
                ),
                f.clock.now()
            )
            .await,
        Err(Error::ActionIdentityConflict { .. })
    ));
    let next = f
        .claim(&scope, "reuse-after-retention", ActionKind::Mutating)
        .await;
    assert_eq!(next.action_sequence().get(), 2);
    let next = f.cancelled(&scope, &next).await;
    assert_eq!(next.last_source_event_sequence(), Some(2));
}

#[tokio::test]
async fn terminal_horizon_uses_trusted_clock_and_duplicate_reads_do_not_extend_it() {
    let f = Fixture::new();
    let scope = Scope::new();
    let accepted = f.claim(&scope, "fixed", ActionKind::ReadOnly).await;
    f.clock.advance(Duration::days(2));
    // A stale RPC timestamp cannot shorten the trusted retention period.
    let terminal = f
        .store
        .cancel_before_dispatch(
            &scope.tenant,
            &scope.session,
            accepted.action_id(),
            accepted.revision(),
            &scope.placement,
            accepted.created_at(),
        )
        .await
        .expect("cancel stale UTC");
    assert_eq!(terminal.retain_until(), f.clock.now() + Duration::days(1));
    let fixed = terminal.retain_until();
    f.clock.advance(Duration::hours(2));
    for _ in 0..3 {
        let retry = f
            .store
            .claim_action(
                scope.claim("fixed", ActionId::new(), ActionKind::ReadOnly),
                f.clock.now(),
            )
            .await
            .expect("duplicate at later UTC");
        assert_eq!(retry.snapshot().retain_until(), fixed);
        assert_eq!(
            f.get(&scope, terminal.action_id())
                .await
                .expect("terminal")
                .retain_until(),
            fixed
        );
    }
    let replay = f
        .store
        .cancel_before_dispatch(
            &scope.tenant,
            &scope.session,
            terminal.action_id(),
            terminal.revision(),
            &scope.placement,
            f.clock.now(),
        )
        .await
        .expect("terminal replay");
    assert_eq!(replay.retain_until(), fixed);
    f.ack_source(&scope).await;
    f.clock.set(fixed - Duration::milliseconds(1));
    assert_eq!(f.maintain(16).await.examined(), 0);
    f.clock.set(fixed);
    assert_eq!(f.maintain(16).await.reclaimed(), 1);
}

#[tokio::test]
async fn copy_ack_release_and_source_ack_are_independent_gc_gates() {
    let f = Fixture::new();
    let scope = Scope::new();
    let accepted = f.claim(&scope, "custody", ActionKind::Mutating).await;
    let completed = f.complete(&scope, &accepted, known(), None, true).await;
    let fixed = completed.snapshot.retain_until();
    f.ack_source(&scope).await;
    f.clock.advance(Duration::days(30));
    assert_eq!(f.maintain(16).await.deferred(), 1);
    let page = f
        .store
        .scan_pending_custody(GatewayCustodyCursor::default(), 1)
        .await
        .expect("copy queue");
    let copy = page.entries()[0].clone();
    f.store
        .ack_pending_custody(&copy, f.clock.now())
        .await
        .expect("copy ACK");
    f.store
        .ack_pending_custody(&copy, f.clock.now())
        .await
        .expect("lost ACK reply retry");
    assert_eq!(f.maintain(16).await.deferred(), 1);
    let page = f
        .store
        .scan_pending_custody(GatewayCustodyCursor::default(), 1)
        .await
        .expect("release queue");
    let release = &page.entries()[0];
    assert!(release.is_release());
    f.store
        .complete_custody_release(release, f.clock.now())
        .await
        .expect("final release");
    f.store
        .complete_custody_release(release, f.clock.now())
        .await
        .expect("lost release reply retry");
    assert_eq!(
        f.get(&scope, accepted.action_id())
            .await
            .expect("released record")
            .retain_until(),
        fixed
    );
    let replay = f
        .store
        .record_worker_terminal_with_custody(
            &scope.tenant,
            &scope.session,
            accepted.action_id(),
            1,
            &scope.placement,
            &completed.dispatch,
            accepted.action_sequence(),
            known(),
            completed.receipt.clone(),
            None,
            f.clock.now(),
        )
        .await
        .expect("late custody retry");
    assert_eq!(replay.retain_until(), fixed);
    assert_eq!(f.maintain(16).await.reclaimed(), 1);
}

#[tokio::test]
async fn unresolved_unknown_survives_ttl_and_resolution_requires_new_source_ack() {
    let f = Fixture::new();
    let scope = Scope::new();
    let accepted = f.claim(&scope, "unknown", ActionKind::Mutating).await;
    let completed = f.complete(&scope, &accepted, unknown(), None, false).await;
    f.ack_source(&scope).await;
    f.clock.advance(Duration::days(3));
    assert_eq!(f.maintain(16).await.deferred(), 1);
    let annotation = resolution();
    let resolved = f
        .store
        .resolve_unknown(
            &scope.tenant,
            &scope.session,
            accepted.action_id(),
            completed.snapshot.revision(),
            &scope.placement,
            annotation.clone(),
            f.clock.now(),
        )
        .await
        .expect("resolve unknown");
    assert_eq!(resolved.last_source_event_sequence(), Some(2));
    let fixed = resolved.retain_until();
    f.clock.advance(Duration::days(2));
    assert_eq!(f.maintain(16).await.deferred(), 1);
    assert_eq!(f.ack_source(&scope).await, [2]);
    let retry = f
        .store
        .resolve_unknown(
            &scope.tenant,
            &scope.session,
            accepted.action_id(),
            resolved.revision(),
            &scope.placement,
            annotation,
            f.clock.now(),
        )
        .await
        .expect("resolution replay");
    assert_eq!(retry.retain_until(), fixed);
    assert_eq!(f.maintain(16).await.reclaimed(), 1);
    let next = f.claim(&scope, "after-unknown", ActionKind::Mutating).await;
    assert_eq!(next.action_sequence().get(), 2);
}

#[tokio::test]
async fn read_only_unknown_also_requires_resolution_and_backward_clock_never_shortens_horizon() {
    let f = Fixture::new();
    let scope = Scope::new();
    let accepted = f.claim(&scope, "read-unknown", ActionKind::ReadOnly).await;
    let completed = f.complete(&scope, &accepted, unknown(), None, false).await;
    let original = completed.snapshot.retain_until();
    f.ack_source(&scope).await;
    f.clock.advance(Duration::days(3));
    assert_eq!(f.maintain(16).await.deferred(), 1);
    f.clock.set(accepted.created_at() - Duration::days(2));
    let resolved = f
        .store
        .resolve_unknown(
            &scope.tenant,
            &scope.session,
            accepted.action_id(),
            completed.snapshot.revision(),
            &scope.placement,
            resolution(),
            f.clock.now(),
        )
        .await
        .expect("backward clock resolution");
    assert_eq!(resolved.retain_until(), original);
    f.ack_source(&scope).await;
    assert_eq!(f.maintain(16).await.examined(), 0);
    f.clock.set(original);
    assert_eq!(f.maintain(16).await.reclaimed(), 1);
}

#[tokio::test]
async fn already_resolved_worker_receipt_requires_both_immutable_source_events() {
    let f = Fixture::new();
    let scope = Scope::new();
    let accepted = f
        .claim(&scope, "resolved-worker", ActionKind::Mutating)
        .await;
    let completed = f
        .complete(&scope, &accepted, unknown(), Some(resolution()), true)
        .await;
    assert_eq!(completed.snapshot.last_source_event_sequence(), Some(2));
    let page = f
        .store
        .scan_pending_custody(GatewayCustodyCursor::default(), 1)
        .await
        .expect("copy");
    f.store
        .ack_pending_custody(&page.entries()[0], f.clock.now())
        .await
        .expect("copy ACK");
    let page = f
        .store
        .scan_pending_custody(GatewayCustodyCursor::default(), 1)
        .await
        .expect("release");
    f.store
        .complete_custody_release(&page.entries()[0], f.clock.now())
        .await
        .expect("release ACK");
    let first = f
        .store
        .peek_event_projection(&scope.tenant, &scope.session)
        .await
        .expect("peek")
        .expect("first");
    assert_eq!(first.sequence(), 1);
    f.store
        .ack_event_projection(&first)
        .await
        .expect("first source ACK");
    f.clock.advance(Duration::days(3));
    assert_eq!(f.maintain(16).await.deferred(), 1);
    assert_eq!(f.ack_source(&scope).await, [2]);
    assert_eq!(f.maintain(16).await.reclaimed(), 1);
}

#[tokio::test]
async fn retained_caps_include_pending_and_terminal_but_allow_exact_duplicate_and_other_session() {
    let mut f = Fixture::new();
    f.store = f
        .store
        .with_retention_limits(GatewayActionRetentionLimits::new(2, 1).expect("caps"));
    let a = Scope::new();
    let b = Scope::new();
    let c = Scope::new();
    let first = f.claim(&a, "a", ActionKind::Mutating).await;
    let terminal = f.cancelled(&a, &first).await;
    assert_eq!(
        f.store
            .claim_action(
                a.claim("blocked", ActionId::new(), ActionKind::Mutating),
                f.clock.now()
            )
            .await,
        Err(Error::RetainedActionCapacity)
    );
    f.claim(&b, "b", ActionKind::ReadOnly).await;
    assert_eq!(
        f.store
            .claim_action(
                c.claim("global-blocked", ActionId::new(), ActionKind::ReadOnly),
                f.clock.now()
            )
            .await,
        Err(Error::RetainedActionCapacity)
    );
    let duplicate = f
        .store
        .claim_action(
            a.claim("a", ActionId::new(), ActionKind::Mutating),
            f.clock.now(),
        )
        .await
        .expect("duplicate at capacity");
    assert!(matches!(duplicate, GatewayActionClaimOutcome::Existing(_)));
    f.clock.advance(Duration::days(3));
    assert_eq!(f.maintain(16).await.deferred(), 1);
    f.ack_source(&a).await;
    assert_eq!(f.maintain(16).await.reclaimed(), 1);
    assert!(f.get(&a, terminal.action_id()).await.is_none());
    f.claim(&c, "slot-reused", ActionKind::ReadOnly).await;
}

#[tokio::test]
async fn pending_rows_are_never_ttl_candidates() {
    let f = Fixture::new();
    let scope = Scope::new();
    let pending = f.claim(&scope, "pending", ActionKind::ReadOnly).await;
    f.clock.advance(Duration::days(90));
    assert_eq!(f.maintain(256).await.examined(), 0);
    assert!(f.get(&scope, pending.action_id()).await.is_some());
    for limit in [0, 257] {
        assert!(matches!(
            f.store
                .maintain_action_retention(GatewayActionRetentionCursor::default(), limit)
                .await,
            Err(Error::InvalidRetentionScanLimit)
        ));
    }
}

#[tokio::test]
async fn bounded_cursor_does_not_starve_later_tenant_behind_source_outage() {
    let f = Fixture::new();
    let mut scopes = [Scope::new(), Scope::new()];
    scopes.sort_by(|a, b| (&a.tenant, &a.session).cmp(&(&b.tenant, &b.session)));
    let blocked = f.claim(&scopes[0], "blocked", ActionKind::ReadOnly).await;
    let ready = f.claim(&scopes[1], "ready", ActionKind::ReadOnly).await;
    f.cancelled(&scopes[0], &blocked).await;
    f.cancelled(&scopes[1], &ready).await;
    f.ack_source(&scopes[1]).await;
    f.clock.advance(Duration::days(3));
    let first = f.maintain(1).await;
    assert_eq!(
        (first.examined(), first.deferred(), first.reclaimed()),
        (1, 1, 0)
    );
    assert!(!first.is_complete());
    let wire = serde_json::to_vec(first.next_cursor()).expect("bounded cursor wire");
    let cursor = serde_json::from_slice(&wire).expect("strict cursor resume");
    let second = f
        .store
        .maintain_action_retention(cursor, 1)
        .await
        .expect("next tenant");
    assert_eq!(second.reclaimed(), 1);
    assert!(second.is_complete());
    assert!(f.get(&scopes[0], blocked.action_id()).await.is_some());
    assert!(f.get(&scopes[1], ready.action_id()).await.is_none());
}

#[tokio::test]
async fn reattached_store_and_actor_retain_watermark_and_use_backend_clock() {
    let f = Fixture::new();
    let scope = Scope::new();
    let accepted = f.claim(&scope, "actor-restart", ActionKind::ReadOnly).await;
    let terminal = f.cancelled(&scope, &accepted).await;
    f.ack_source(&scope).await;
    f.clock.advance(Duration::days(3));
    let client = GatewayActionBlockingClient::spawn(
        Arc::new(f.reopen()),
        CoordinationActorConfig::default(),
    )
    .expect("actor");
    let tenant = scope.tenant.clone();
    let session = scope.session.clone();
    let action = terminal.action_id().clone();
    tokio::task::spawn_blocking(move || {
        let snapshot = client
            .get_effective_action(&tenant, &session, &action)
            .expect("retained canonical read")
            .expect("not removed by GET");
        assert_eq!(snapshot.last_source_event_sequence(), Some(1));
        assert_eq!(
            client
                .maintain_action_retention(GatewayActionRetentionCursor::default(), 1)
                .expect("actor maintenance")
                .reclaimed(),
            1
        );
        assert!(
            client
                .get_effective_action(&tenant, &session, &action)
                .expect("after maintenance")
                .is_none()
        );
    })
    .await
    .expect("joined actor client");
}

#[tokio::test]
async fn concurrent_claim_and_janitor_never_dangle_idempotency_or_reuse_sequence() {
    let f = Fixture::new();
    let scope = Scope::new();
    let first = f.claim(&scope, "concurrent", ActionKind::ReadOnly).await;
    f.cancelled(&scope, &first).await;
    f.ack_source(&scope).await;
    f.clock.advance(Duration::days(3));
    let barrier = Arc::new(tokio::sync::Barrier::new(3));
    let store = f.store.clone();
    let sync = barrier.clone();
    let janitor = tokio::spawn(async move {
        sync.wait().await;
        store
            .maintain_action_retention(GatewayActionRetentionCursor::default(), 1)
            .await
    });
    let store = f.store.clone();
    let sync = barrier.clone();
    let claim = scope.claim("concurrent", ActionId::new(), ActionKind::ReadOnly);
    let now = f.clock.now();
    let claimant = tokio::spawn(async move {
        sync.wait().await;
        store.claim_action(claim, now).await
    });
    barrier.wait().await;
    assert_eq!(
        janitor
            .await
            .expect("janitor join")
            .expect("janitor")
            .reclaimed(),
        1
    );
    let outcome = claimant
        .await
        .expect("claim join")
        .expect("linearized claim");
    let next = f.claim(&scope, "concurrent", ActionKind::ReadOnly).await;
    assert_eq!(next.action_sequence().get(), 2);
    if let GatewayActionClaimOutcome::Created(snapshot) = outcome {
        assert_eq!(snapshot.action_id(), next.action_id());
    }
}

#[tokio::test]
async fn session_loss_projection_and_placement_survive_payload_reclamation() {
    let f = Fixture::new();
    let scope = Scope::new();
    let pending = f
        .claim(&scope, "lost-unattempted", ActionKind::ReadOnly)
        .await;
    let loss = SessionLossClaim::new(
        scope.tenant.clone(),
        scope.session.clone(),
        scope.placement.clone(),
        Uuid::now_v7(),
    );
    f.store
        .mark_session_lost(&loss, f.clock.now())
        .await
        .expect("positive loss");
    assert_eq!(
        f.store
            .materialize_session_loss(&loss, 1, f.clock.now())
            .await
            .expect("materialize"),
        1
    );
    assert_eq!(
        f.get(&scope, pending.action_id())
            .await
            .expect("loss terminal")
            .last_source_event_sequence(),
        Some(2)
    );
    f.clock.advance(Duration::days(3));
    assert_eq!(f.maintain(1).await.deferred(), 1);
    assert_eq!(f.ack_source(&scope).await, [1, 2]);
    assert_eq!(f.maintain(1).await.reclaimed(), 1);
    assert_eq!(
        f.store
            .claim_action(
                scope.claim("lost-new", ActionId::new(), ActionKind::ReadOnly),
                f.clock.now()
            )
            .await,
        Err(Error::SessionLost)
    );
    let conflicting = GatewayActionPlacement::new(
        DirectoryFence::new(
            scope.placement.directory_fence().worker_id().clone(),
            8,
            11,
            13,
        )
        .expect("fence"),
        18,
    )
    .expect("placement");
    let claim = ClaimGatewayAction::new(
        scope.tenant.clone(),
        scope.session.clone(),
        ActionId::new(),
        "wrong-owner",
        CanonicalRequestHash::new([1; 32]),
        ActionKind::ReadOnly,
        conflicting,
    )
    .expect("claim");
    assert_eq!(
        f.store.claim_action(claim, f.clock.now()).await,
        Err(Error::PlacementMismatch)
    );
}

#[tokio::test]
async fn gc_preserves_later_unacknowledged_source_event_in_same_session() {
    let f = Fixture::new();
    let scope = Scope::new();
    let first = f.claim(&scope, "source-first", ActionKind::ReadOnly).await;
    f.cancelled(&scope, &first).await;
    let event = f
        .store
        .peek_event_projection(&scope.tenant, &scope.session)
        .await
        .expect("first peek")
        .expect("first event");
    f.store
        .ack_event_projection(&event)
        .await
        .expect("first ACK");
    let second = f.claim(&scope, "source-second", ActionKind::ReadOnly).await;
    f.cancelled(&scope, &second).await;
    let preserved = f
        .store
        .peek_event_projection(&scope.tenant, &scope.session)
        .await
        .expect("second peek")
        .expect("second event");
    f.clock.advance(Duration::days(3));
    let page = f.maintain(16).await;
    assert_eq!(
        (page.examined(), page.reclaimed(), page.deferred()),
        (2, 1, 1)
    );
    assert_eq!(
        f.store
            .peek_event_projection(&scope.tenant, &scope.session)
            .await
            .expect("queue after GC"),
        Some(preserved.clone())
    );
    assert!(f.get(&scope, first.action_id()).await.is_none());
    assert!(f.get(&scope, second.action_id()).await.is_some());
    f.store
        .ack_event_projection(&preserved)
        .await
        .expect("retained exact source ACK");
    assert_eq!(f.maintain(16).await.reclaimed(), 1);
}
