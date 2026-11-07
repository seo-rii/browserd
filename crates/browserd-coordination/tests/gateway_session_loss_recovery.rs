#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::Arc;

use browserd_actions::{
    ActionKind, CanonicalRequestHash, DispatchId, KnownFailureReason, OutcomeUnknownReason,
    TerminalDetail,
};
use browserd_coordination::{
    ClaimGatewayAction, CoordinationActorConfig, DirectoryFence, GatewayActionBlockingClient,
    GatewayActionCoordination, GatewayActionCoordinationError, GatewayActionPlacement,
    GatewayActionRecoveryCursor, GatewayEventScanCursor, MemoryCoordinationDatabase,
    MemoryGatewayActionStore, OutboxEventKind, SessionLossClaim, SessionLossOutcome, StoreConfig,
};
use browserd_core::{ActionId, SessionId, TenantId, WorkerId};
use chrono::Utc;
use tokio::sync::Barrier;
use uuid::Uuid;

fn placement(
    worker: &str,
    epoch: u64,
    version: u64,
    incarnation: u64,
    revision: u64,
) -> GatewayActionPlacement {
    GatewayActionPlacement::new(
        DirectoryFence::new(WorkerId::new(worker).unwrap(), epoch, version, incarnation).unwrap(),
        revision,
    )
    .unwrap()
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
            placement: placement("loss-worker", 1, 2, 3, 4),
        }
    }

    fn loss(&self) -> SessionLossClaim {
        SessionLossClaim::new(
            self.tenant.clone(),
            self.session.clone(),
            self.placement.clone(),
            Uuid::now_v7(),
        )
    }

    fn action(&self, key: &str) -> ClaimGatewayAction {
        ClaimGatewayAction::new(
            self.tenant.clone(),
            self.session.clone(),
            ActionId::new(),
            key,
            CanonicalRequestHash::new([3; 32]),
            ActionKind::ReadOnly,
            self.placement.clone(),
        )
        .unwrap()
    }
}

async fn drain_events(store: &MemoryGatewayActionStore, scope: &Scope) -> Vec<OutboxEventKind> {
    let mut kinds = Vec::new();
    while let Some(event) = store
        .peek_event_projection(&scope.tenant, &scope.session)
        .await
        .unwrap()
    {
        assert!(kinds.len() < 16, "unexpected duplicate loss projections");
        kinds.push(event.append().kind());
        store.ack_event_projection(&event).await.unwrap();
    }
    kinds
}

#[tokio::test]
async fn no_action_loss_replays_canonically_after_ack_and_store_reattachment() {
    let database = MemoryCoordinationDatabase::default();
    let store = MemoryGatewayActionStore::attach(database.clone(), StoreConfig::default());
    let scope = Scope::new();
    let original = scope.loss();
    let first = store
        .ensure_session_lost(&original, Utc::now())
        .await
        .unwrap();
    assert_eq!(first.claim(), &original);
    assert_eq!(first.outcome(), SessionLossOutcome::Recorded);
    assert_eq!(
        store
            .mark_session_lost(&original, Utc::now())
            .await
            .unwrap(),
        SessionLossOutcome::AlreadyRecorded
    );
    let replacement = scope.loss();
    assert_eq!(
        store.mark_session_lost(&replacement, Utc::now()).await,
        Err(GatewayActionCoordinationError::SessionLossIdentityConflict)
    );
    let repeated = store
        .ensure_session_lost(&replacement, Utc::now())
        .await
        .unwrap();
    assert_eq!(repeated.claim(), &original);
    assert_eq!(repeated.outcome(), SessionLossOutcome::AlreadyRecorded);
    assert_eq!(
        store
            .materialize_session_loss(repeated.claim(), 1, Utc::now())
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        drain_events(&store, &scope).await,
        vec![OutboxEventKind::SessionLost]
    );
    assert!(
        store
            .scan_event_sessions(GatewayEventScanCursor::default(), 1)
            .await
            .unwrap()
            .sessions()
            .is_empty()
    );

    let restarted = MemoryGatewayActionStore::attach(database, StoreConfig::default());
    let recovered = restarted
        .ensure_session_lost(&scope.loss(), Utc::now())
        .await
        .unwrap();
    assert_eq!(recovered.outcome(), SessionLossOutcome::AlreadyRecorded);
    assert_eq!(recovered.into_claim(), original);
    assert!(drain_events(&restarted, &scope).await.is_empty());
    assert!(matches!(
        restarted
            .claim_action(scope.action("after-loss"), Utc::now())
            .await,
        Err(GatewayActionCoordinationError::SessionLost)
    ));
}

#[tokio::test]
async fn committed_loss_with_discarded_reply_is_recovered_without_a_second_event() {
    let database = MemoryCoordinationDatabase::default();
    let scope = Scope::new();
    let original = scope.loss();
    let store = MemoryGatewayActionStore::attach(database.clone(), StoreConfig::default());
    // Model the commit/reply boundary: the caller loses both the reply and its proposal.
    drop(
        store
            .ensure_session_lost(&original, Utc::now())
            .await
            .unwrap(),
    );
    drop(store);
    let restarted = MemoryGatewayActionStore::attach(database, StoreConfig::default());
    let retry = restarted
        .ensure_session_lost(&scope.loss(), Utc::now())
        .await
        .unwrap();
    assert_eq!(retry.claim(), &original);
    assert_eq!(retry.outcome(), SessionLossOutcome::AlreadyRecorded);
    assert_eq!(
        drain_events(&restarted, &scope).await,
        vec![OutboxEventKind::SessionLost]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn independent_loss_proposals_race_to_one_identity_and_one_projection() {
    let store = Arc::new(MemoryGatewayActionStore::default());
    let scope = Scope::new();
    let barrier = Arc::new(Barrier::new(16));
    let proposals: Vec<_> = (0..16).map(|_| scope.loss()).collect();
    let mut tasks = Vec::new();
    for proposal in proposals.clone() {
        let store = Arc::clone(&store);
        let barrier = Arc::clone(&barrier);
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store
                .ensure_session_lost(&proposal, Utc::now())
                .await
                .unwrap()
        }));
    }
    let mut receipts = Vec::new();
    for task in tasks {
        receipts.push(task.await.unwrap());
    }
    let canonical = receipts[0].claim();
    assert!(proposals.contains(canonical));
    assert!(receipts.iter().all(|receipt| receipt.claim() == canonical));
    assert_eq!(
        receipts
            .iter()
            .filter(|receipt| receipt.outcome() == SessionLossOutcome::Recorded)
            .count(),
        1
    );
    assert_eq!(
        drain_events(&store, &scope).await,
        vec![OutboxEventKind::SessionLost]
    );
}

#[tokio::test]
async fn canonical_loss_never_crosses_any_placement_dimension_or_session_scope() {
    let store = MemoryGatewayActionStore::default();
    let scope = Scope::new();
    let original = scope.loss();
    store
        .ensure_session_lost(&original, Utc::now())
        .await
        .unwrap();
    for changed in [
        placement("other-worker", 1, 2, 3, 4),
        placement("loss-worker", 2, 2, 3, 4),
        placement("loss-worker", 1, 3, 3, 4),
        placement("loss-worker", 1, 2, 4, 4),
        placement("loss-worker", 1, 2, 3, 5),
    ] {
        let claim = SessionLossClaim::new(
            scope.tenant.clone(),
            scope.session.clone(),
            changed,
            Uuid::now_v7(),
        );
        assert_eq!(
            store.ensure_session_lost(&claim, Utc::now()).await,
            Err(GatewayActionCoordinationError::PlacementMismatch)
        );
        assert_eq!(
            store.mark_session_lost(&claim, Utc::now()).await,
            Err(GatewayActionCoordinationError::PlacementMismatch)
        );
    }
    for (tenant, session) in [
        (TenantId::new(), scope.session.clone()),
        (scope.tenant.clone(), SessionId::new()),
    ] {
        let other = SessionLossClaim::new(tenant, session, scope.placement.clone(), Uuid::now_v7());
        let receipt = store.ensure_session_lost(&other, Utc::now()).await.unwrap();
        assert_eq!(receipt.outcome(), SessionLossOutcome::Recorded);
        assert_eq!(receipt.into_claim(), other);
    }
    assert_eq!(
        store
            .ensure_session_lost(&scope.loss(), Utc::now())
            .await
            .unwrap()
            .into_claim(),
        original
    );
    assert_eq!(
        drain_events(&store, &scope).await,
        vec![OutboxEventKind::SessionLost]
    );
}

#[tokio::test]
async fn invalid_proposal_ids_do_not_create_or_rewrite_a_loss() {
    let store = MemoryGatewayActionStore::default();
    let scope = Scope::new();
    let invalid = SessionLossClaim::new(
        scope.tenant.clone(),
        scope.session.clone(),
        scope.placement.clone(),
        Uuid::new_v4(),
    );
    for already_lost in [false, true] {
        if already_lost {
            store
                .ensure_session_lost(&scope.loss(), Utc::now())
                .await
                .unwrap();
        }
        assert_eq!(
            store.ensure_session_lost(&invalid, Utc::now()).await,
            Err(GatewayActionCoordinationError::InvalidSessionLossId)
        );
        assert_eq!(
            store.mark_session_lost(&invalid, Utc::now()).await,
            Err(GatewayActionCoordinationError::InvalidSessionLossId)
        );
    }
    assert_eq!(
        drain_events(&store, &scope).await,
        vec![OutboxEventKind::SessionLost]
    );
}

#[tokio::test]
async fn canonical_retry_resumes_bounded_materialization_and_preserves_existing_terminals() {
    let database = MemoryCoordinationDatabase::default();
    let store = MemoryGatewayActionStore::attach(database.clone(), StoreConfig::default());
    let scope = Scope::new();
    let mut actions = Vec::new();
    for key in ["not-attempted", "armed", "already-terminal"] {
        actions.push(
            store
                .claim_action(scope.action(key), Utc::now())
                .await
                .unwrap()
                .into_snapshot(),
        );
    }
    let armed = store
        .arm_dispatch(
            &scope.tenant,
            &scope.session,
            actions[1].action_id(),
            actions[1].revision(),
            &scope.placement,
            DispatchId::new(),
            Utc::now(),
        )
        .await
        .unwrap();
    let terminal = store
        .cancel_before_dispatch(
            &scope.tenant,
            &scope.session,
            actions[2].action_id(),
            actions[2].revision(),
            &scope.placement,
            Utc::now(),
        )
        .await
        .unwrap();
    let original = scope.loss();
    store
        .mark_session_lost(&original, Utc::now())
        .await
        .unwrap();
    let restarted = MemoryGatewayActionStore::attach(database, StoreConfig::default());
    let receipt = restarted
        .ensure_session_lost(&scope.loss(), Utc::now())
        .await
        .unwrap();
    assert_eq!(receipt.claim(), &original);
    assert_eq!(receipt.outcome(), SessionLossOutcome::AlreadyRecorded);
    for expected in [1, 1, 0] {
        assert_eq!(
            restarted
                .materialize_session_loss(receipt.claim(), 1, Utc::now())
                .await
                .unwrap(),
            expected
        );
    }
    for (action, expected) in [
        (
            &actions[0],
            TerminalDetail::FailedKnown(KnownFailureReason::NotDispatched),
        ),
        (
            &armed,
            TerminalDetail::OutcomeUnknown(OutcomeUnknownReason::WorkerLost),
        ),
    ] {
        let effective = restarted
            .get_effective_action(&scope.tenant, &scope.session, action.action_id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(effective.terminal().unwrap().detail(), expected);
    }
    assert_eq!(
        restarted
            .get_effective_action(&scope.tenant, &scope.session, terminal.action_id())
            .await
            .unwrap()
            .unwrap(),
        terminal
    );
    assert!(
        restarted
            .scan_pending_actions(GatewayActionRecoveryCursor::default(), 256)
            .await
            .unwrap()
            .actions()
            .is_empty()
    );
    let events = drain_events(&restarted, &scope).await;
    assert_eq!(events.len(), 4);
    assert_eq!(
        events
            .iter()
            .filter(|kind| **kind == OutboxEventKind::SessionLost)
            .count(),
        1
    );
    assert!(
        restarted
            .scan_event_sessions(GatewayEventScanCursor::default(), 1)
            .await
            .unwrap()
            .sessions()
            .is_empty()
    );
    assert_eq!(
        restarted
            .ensure_session_lost(&scope.loss(), Utc::now())
            .await
            .unwrap()
            .into_claim(),
        original
    );
    assert!(drain_events(&restarted, &scope).await.is_empty());
}

#[test]
fn blocking_actor_returns_canonical_claim_for_restarted_callers_and_keeps_strict_conflicts() {
    let store = Arc::new(MemoryGatewayActionStore::default());
    let actor =
        GatewayActionBlockingClient::spawn(Arc::clone(&store), CoordinationActorConfig::default())
            .unwrap();
    let scope = Scope::new();
    let original = scope.loss();
    assert_eq!(
        actor
            .ensure_session_lost(&original, Utc::now())
            .unwrap()
            .outcome(),
        SessionLossOutcome::Recorded
    );
    drop(actor);
    let actor =
        GatewayActionBlockingClient::spawn(store, CoordinationActorConfig::default()).unwrap();
    let proposed = scope.loss();
    let receipt = actor.ensure_session_lost(&proposed, Utc::now()).unwrap();
    assert_eq!(receipt.claim(), &original);
    assert_eq!(receipt.outcome(), SessionLossOutcome::AlreadyRecorded);
    assert_eq!(
        actor.mark_session_lost(&proposed, Utc::now()),
        Err(GatewayActionCoordinationError::SessionLossIdentityConflict)
    );
    assert_eq!(
        actor
            .materialize_session_loss(receipt.claim(), 1, Utc::now())
            .unwrap(),
        0
    );
    let event = actor
        .peek_event_projection(&scope.tenant, &scope.session)
        .unwrap()
        .unwrap();
    assert_eq!(event.append().kind(), OutboxEventKind::SessionLost);
    actor.ack_event_projection(&event).unwrap();
    assert!(
        actor
            .peek_event_projection(&scope.tenant, &scope.session)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        actor
            .ensure_session_lost(&scope.loss(), Utc::now())
            .unwrap()
            .into_claim(),
        original
    );
}
