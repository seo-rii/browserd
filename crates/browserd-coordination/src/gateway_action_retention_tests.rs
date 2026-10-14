#![allow(clippy::expect_used)]

use super::*;
use browserd_core::WorkerId;
use chrono::TimeZone;

struct FixedClock(DateTime<Utc>);
impl GatewayActionRetentionClock for FixedClock {
    fn now(&self) -> DateTime<Utc> {
        self.0
    }
}
struct Fixture {
    database: MemoryCoordinationDatabase,
    store: MemoryGatewayActionStore,
    tenant: TenantId,
    session: SessionId,
    placement: GatewayActionPlacement,
    terminal: GatewayActionSnapshot,
}
impl Fixture {
    async fn new() -> Self {
        let database = MemoryCoordinationDatabase::default();
        let now = Utc
            .with_ymd_and_hms(2026, 8, 30, 0, 0, 0)
            .single()
            .expect("fixed UTC");
        let store = MemoryGatewayActionStore::attach(database.clone(), StoreConfig::default())
            .with_retention_clock(Arc::new(FixedClock(now)));
        let tenant = TenantId::new();
        let session = SessionId::new();
        let placement = GatewayActionPlacement::new(
            DirectoryFence::new(WorkerId::new("retention-unit").expect("worker"), 1, 2, 3)
                .expect("fence"),
            4,
        )
        .expect("placement");
        let accepted = store
            .claim_action(
                ClaimGatewayAction::new(
                    tenant.clone(),
                    session.clone(),
                    ActionId::new(),
                    "first",
                    CanonicalRequestHash::new([1; 32]),
                    ActionKind::ReadOnly,
                    placement.clone(),
                )
                .expect("claim"),
                now,
            )
            .await
            .expect("accepted")
            .into_snapshot();
        let terminal = store
            .cancel_before_dispatch(&tenant, &session, accepted.action_id(), 0, &placement, now)
            .await
            .expect("cancelled");
        let event = store
            .peek_event_projection(&tenant, &session)
            .await
            .expect("peek")
            .expect("terminal source");
        store
            .ack_event_projection(&event)
            .await
            .expect("source ACK");
        let store =
            store.with_retention_clock(Arc::new(FixedClock(now + chrono::Duration::days(3))));
        Self {
            database,
            store,
            tenant,
            session,
            placement,
            terminal,
        }
    }
}

#[tokio::test]
async fn legacy_missing_watermark_remains_charged_after_expiry() {
    let f = Fixture::new().await;
    {
        let mut state = f.database.gateway_actions.lock().expect("state");
        state
            .sessions
            .get_mut(&(f.tenant.clone(), f.session.clone()))
            .expect("session")
            .actions
            .get_mut(f.terminal.action_id())
            .expect("action")
            .last_source_event_sequence = None;
    }
    let page = f
        .store
        .maintain_action_retention(GatewayActionRetentionCursor::default(), 1)
        .await
        .expect("legacy deferred");
    assert_eq!(
        (page.examined(), page.reclaimed(), page.deferred()),
        (1, 0, 1)
    );
    let state = f.database.gateway_actions.lock().expect("state");
    assert_eq!(state.retained_records.len(), 1);
    assert_eq!(state.action_owners.len(), 1);
}

#[tokio::test]
async fn mismatched_reverse_identity_rejects_cleanup_before_any_removal() {
    let f = Fixture::new().await;
    {
        let mut state = f.database.gateway_actions.lock().expect("state");
        state
            .action_owners
            .get_mut(f.terminal.action_id())
            .expect("reverse")
            .0 = TenantId::new();
    }
    assert!(matches!(
        f.store
            .maintain_action_retention(GatewayActionRetentionCursor::default(), 1)
            .await,
        Err(GatewayActionCoordinationError::CorruptState)
    ));
    let state = f.database.gateway_actions.lock().expect("state");
    assert_eq!(state.retained_records.len(), 1);
    assert_eq!(state.retention_due.len(), 1);
    let session = state.sessions.get(&(f.tenant, f.session)).expect("session");
    assert_eq!(session.actions.len(), 1);
    assert_eq!(session.idempotency.len(), 1);
}

#[tokio::test]
async fn gc_keeps_full_u64_sequence_and_global_identity_highwaters() {
    let f = Fixture::new().await;
    {
        let mut state = f.database.gateway_actions.lock().expect("state");
        state
            .sessions
            .get_mut(&(f.tenant.clone(), f.session.clone()))
            .expect("session")
            .last_action_sequence = u64::MAX - 1;
    }
    let now = f.store.retention_now();
    let accepted = f
        .store
        .claim_action(
            ClaimGatewayAction::new(
                f.tenant.clone(),
                f.session.clone(),
                ActionId::new(),
                "last-u64",
                CanonicalRequestHash::new([2; 32]),
                ActionKind::ReadOnly,
                f.placement.clone(),
            )
            .expect("claim"),
            now,
        )
        .await
        .expect("full sequence")
        .into_snapshot();
    assert_eq!(accepted.action_sequence().get(), u64::MAX);
    f.store
        .cancel_before_dispatch(
            &f.tenant,
            &f.session,
            accepted.action_id(),
            0,
            &f.placement,
            now,
        )
        .await
        .expect("cancel");
    let event = f
        .store
        .peek_event_projection(&f.tenant, &f.session)
        .await
        .expect("peek")
        .expect("second source");
    assert_eq!(event.sequence(), 2);
    f.store.ack_event_projection(&event).await.expect("ACK");
    let store = f
        .store
        .clone()
        .with_retention_clock(Arc::new(FixedClock(now + chrono::Duration::days(3))));
    assert_eq!(
        store
            .maintain_action_retention(GatewayActionRetentionCursor::default(), 256)
            .await
            .expect("GC")
            .reclaimed(),
        2
    );
    {
        let state = f.database.gateway_actions.lock().expect("state");
        assert!(state.retained_records.is_empty());
        assert_eq!(
            state.action_owners.len(),
            2,
            "global ActionId non-reuse semantics preserved"
        );
        let session = state
            .sessions
            .get(&(f.tenant.clone(), f.session.clone()))
            .expect("session");
        assert_eq!(session.last_action_sequence, u64::MAX);
        assert_eq!((session.event_sequence, session.event_ack_sequence), (2, 2));
        assert!(session.actions.is_empty());
        assert!(session.idempotency.is_empty());
    }
    let claim = ClaimGatewayAction::new(
        f.tenant.clone(),
        f.session.clone(),
        ActionId::new(),
        "first",
        CanonicalRequestHash::new([1; 32]),
        ActionKind::ReadOnly,
        f.placement.clone(),
    )
    .expect("claim");
    assert_eq!(
        store.claim_action(claim, now).await,
        Err(GatewayActionCoordinationError::ActionSequenceOverflow)
    );
}

#[tokio::test]
async fn legacy_missing_anchor_cannot_attach_unresolved_proof_over_gateway_resolution() {
    use browserd_actions::{JournalSessionScope, OutcomeUnknownReason, ResolutionKind};
    use browserd_core::{PlacementFence, PrincipalId};
    let f = Fixture::new().await;
    let dispatch = DispatchId::new();
    let detail = TerminalDetail::OutcomeUnknown(OutcomeUnknownReason::TimeoutAfterDispatch);
    let resolution = ResolutionAnnotation::new(
        ResolutionKind::ConfirmedExecuted,
        PrincipalId::new(),
        42,
        "legacy external resolution",
    );
    let mut legacy = f.terminal.clone();
    legacy.evidence = ActionEvidence::new();
    legacy.evidence.arm_dispatch(dispatch.clone()).expect("arm");
    legacy
        .evidence
        .record_worker_terminal(&dispatch, detail)
        .expect("Worker terminal");
    legacy.revision = 3;
    legacy.resolution = Some(resolution.clone());
    legacy.original_worker_terminal_revision = None;
    legacy.custody_requirement = None;
    let scope = JournalSessionScope::new(
        f.tenant,
        f.session,
        f.placement.directory_fence().worker_id().clone(),
        PlacementFence::new(1, 2, 3),
    )
    .expect("scope");
    let receipt = TerminalCustodyReceipt::new(
        scope.clone(),
        legacy.action_id.clone(),
        legacy.action_sequence,
        legacy.kind,
        CanonicalRequestHash::new([99; 32]),
        Some(DispatchId::new()),
        detail,
        None,
    )
    .expect("unresolved proof");
    let before = legacy.clone();
    assert_eq!(
        legacy.attach_terminal_custody_receipt(&receipt),
        Err(GatewayActionCoordinationError::InvalidCustodyReceipt)
    );
    assert_eq!(legacy, before);
    let resolved = TerminalCustodyReceipt::new(
        scope,
        legacy.action_id.clone(),
        legacy.action_sequence,
        legacy.kind,
        CanonicalRequestHash::new([99; 32]),
        receipt.dispatch_id().cloned(),
        detail,
        Some(resolution),
    )
    .expect("current exact resolved proof");
    assert!(
        legacy
            .attach_terminal_custody_receipt(&resolved)
            .expect("exact current legacy proof")
    );
    assert_eq!(legacy.pending_custody().expect("Copy").action_revision(), 3);
    assert_eq!(legacy.original_worker_terminal_revision, None);
}

#[tokio::test]
async fn legacy_exact_unresolved_terminal_can_attach_without_fabricating_anchor() {
    use browserd_actions::{JournalSessionScope, OutcomeUnknownReason};
    use browserd_core::PlacementFence;
    let f = Fixture::new().await;
    let dispatch = DispatchId::new();
    let detail = TerminalDetail::OutcomeUnknown(OutcomeUnknownReason::TimeoutAfterDispatch);
    let mut legacy = f.terminal.clone();
    legacy.evidence = ActionEvidence::new();
    legacy.evidence.arm_dispatch(dispatch.clone()).expect("arm");
    legacy
        .evidence
        .record_worker_terminal(&dispatch, detail)
        .expect("Worker terminal");
    legacy.revision = 2;
    legacy.original_worker_terminal_revision = None;
    legacy.custody_requirement = None;
    let receipt = TerminalCustodyReceipt::new(
        JournalSessionScope::new(
            f.tenant,
            f.session,
            f.placement.directory_fence().worker_id().clone(),
            PlacementFence::new(1, 2, 3),
        )
        .expect("scope"),
        legacy.action_id.clone(),
        legacy.action_sequence,
        legacy.kind,
        CanonicalRequestHash::new([99; 32]),
        Some(DispatchId::new()),
        detail,
        None,
    )
    .expect("proof");
    assert!(legacy.requires_terminal_custody_catchup());
    assert!(
        legacy
            .attach_terminal_custody_receipt(&receipt)
            .expect("exact unresolved legacy proof")
    );
    assert!(!legacy.requires_terminal_custody_catchup());
    assert_eq!(legacy.original_worker_terminal_revision, None);
    assert_eq!(legacy.pending_custody().expect("Copy").action_revision(), 2);
}

#[tokio::test]
async fn attachment_refuses_missing_catalog_or_corrupt_map_identity_before_mutating() {
    use browserd_actions::JournalSessionScope;
    use browserd_core::PlacementFence;
    for corrupt_identity in [false, true] {
        let f = Fixture::new().await;
        let receipt = TerminalCustodyReceipt::new(
            JournalSessionScope::new(
                f.tenant.clone(),
                f.session.clone(),
                f.placement.directory_fence().worker_id().clone(),
                PlacementFence::new(1, 2, 3),
            )
            .expect("scope"),
            f.terminal.action_id.clone(),
            f.terminal.action_sequence,
            f.terminal.kind,
            CanonicalRequestHash::new([99; 32]),
            None,
            f.terminal.terminal().expect("terminal").detail(),
            None,
        )
        .expect("well-formed identity proof");
        {
            let mut state = f.database.gateway_actions.lock().expect("state");
            if corrupt_identity {
                state
                    .sessions
                    .get_mut(&(f.tenant.clone(), f.session.clone()))
                    .expect("session")
                    .actions
                    .get_mut(f.terminal.action_id())
                    .expect("action")
                    .tenant_id = TenantId::new();
            } else {
                state.retained_records.remove(&(
                    f.tenant.clone(),
                    f.session.clone(),
                    f.terminal.action_id.clone(),
                ));
            }
        }
        assert!(matches!(
            f.store
                .attach_terminal_custody(
                    &f.tenant,
                    &f.session,
                    f.terminal.action_id(),
                    f.terminal.revision(),
                    &f.placement,
                    receipt
                )
                .await,
            Err(GatewayActionCoordinationError::CorruptState)
        ));
        let state = f.database.gateway_actions.lock().expect("state");
        assert!(state.pending_custody.is_empty());
        assert!(
            state
                .sessions
                .get(&(f.tenant, f.session))
                .expect("session")
                .actions
                .get(f.terminal.action_id())
                .expect("action")
                .custody
                .is_none()
        );
    }
}
