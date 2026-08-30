#![allow(clippy::expect_used)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use browserd_actions::{
    ActionKind, ActionSequence, BrowserResult, CanonicalRequestHash, DispatchId,
    KnownFailureReason, TerminalDetail, TransportLoss,
};
use browserd_coordination::{
    ClaimGatewayAction, CoordinationActorConfig, DirectoryFence, GatewayActionBlockingClient,
    GatewayActionClaimOutcome, GatewayActionCoordination, GatewayActionCoordinationError,
    GatewayActionPlacement, GatewayActionSnapshot, MemoryGatewayActionStore, SessionLossClaim,
    SessionLossOutcome,
};
use browserd_core::{ActionId, ActionState, SessionId, TenantId, WorkerId};
use chrono::{TimeZone, Utc};

fn at(second: u32) -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 30, 0, 0, second)
        .single()
        .expect("test timestamp should be valid")
}

struct SlowClaimStore {
    inner: MemoryGatewayActionStore,
    started: Arc<AtomicBool>,
    completed: Arc<AtomicBool>,
    delay: Duration,
}

#[async_trait]
impl GatewayActionCoordination for SlowClaimStore {
    async fn claim_action(
        &self,
        claim: ClaimGatewayAction,
        now: chrono::DateTime<Utc>,
    ) -> Result<GatewayActionClaimOutcome, GatewayActionCoordinationError> {
        self.started.store(true, Ordering::Release);
        tokio::time::sleep(self.delay).await;
        let result = self.inner.claim_action(claim, now).await;
        self.completed.store(true, Ordering::Release);
        result
    }

    async fn get_effective_action(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
    ) -> Result<Option<GatewayActionSnapshot>, GatewayActionCoordinationError> {
        self.inner
            .get_effective_action(tenant_id, session_id, action_id)
            .await
    }

    async fn arm_dispatch(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        dispatch_id: DispatchId,
        now: chrono::DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        self.inner
            .arm_dispatch(
                tenant_id,
                session_id,
                action_id,
                expected_revision,
                placement,
                dispatch_id,
                now,
            )
            .await
    }

    async fn mark_exposure_possible(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        dispatch_id: &DispatchId,
        now: chrono::DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        self.inner
            .mark_exposure_possible(
                tenant_id,
                session_id,
                action_id,
                expected_revision,
                placement,
                dispatch_id,
                now,
            )
            .await
    }

    async fn record_worker_result(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        dispatch_id: &DispatchId,
        action_sequence: ActionSequence,
        result: BrowserResult,
        now: chrono::DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        self.inner
            .record_worker_result(
                tenant_id,
                session_id,
                action_id,
                expected_revision,
                placement,
                dispatch_id,
                action_sequence,
                result,
                now,
            )
            .await
    }

    async fn record_worker_terminal(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        dispatch_id: &DispatchId,
        action_sequence: ActionSequence,
        detail: TerminalDetail,
        now: chrono::DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        self.inner
            .record_worker_terminal(
                tenant_id,
                session_id,
                action_id,
                expected_revision,
                placement,
                dispatch_id,
                action_sequence,
                detail,
                now,
            )
            .await
    }

    async fn record_transport_loss(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        dispatch_id: &DispatchId,
        loss: TransportLoss,
        now: chrono::DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        self.inner
            .record_transport_loss(
                tenant_id,
                session_id,
                action_id,
                expected_revision,
                placement,
                dispatch_id,
                loss,
                now,
            )
            .await
    }

    async fn cancel_before_dispatch(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        now: chrono::DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        self.inner
            .cancel_before_dispatch(
                tenant_id,
                session_id,
                action_id,
                expected_revision,
                placement,
                now,
            )
            .await
    }

    async fn mark_session_lost(
        &self,
        claim: &SessionLossClaim,
        now: chrono::DateTime<Utc>,
    ) -> Result<SessionLossOutcome, GatewayActionCoordinationError> {
        self.inner.mark_session_lost(claim, now).await
    }

    async fn materialize_session_loss(
        &self,
        claim: &SessionLossClaim,
        limit: usize,
        now: chrono::DateTime<Utc>,
    ) -> Result<usize, GatewayActionCoordinationError> {
        self.inner.materialize_session_loss(claim, limit, now).await
    }
}

#[test]
fn blocking_gateway_action_actor_preserves_durable_dispatch_order() {
    let store = Arc::new(MemoryGatewayActionStore::default());
    let config = CoordinationActorConfig::new(8, 2, Duration::from_secs(1), Duration::from_secs(2))
        .expect("bounded actor config should validate");
    let client = GatewayActionBlockingClient::spawn(store, config)
        .expect("gateway action actor should spawn");
    let tenant_id = TenantId::new();
    let session_id = SessionId::new();
    let placement = GatewayActionPlacement::new(
        DirectoryFence::new(
            WorkerId::new("blocking-action-worker").expect("worker ID should validate"),
            41,
            7,
            1,
        )
        .expect("directory fence should validate"),
        11,
    )
    .expect("gateway action placement should validate");
    let action_id = ActionId::new();
    let claim = ClaimGatewayAction::new(
        tenant_id.clone(),
        session_id.clone(),
        action_id.clone(),
        "blocking-action-key",
        CanonicalRequestHash::new([9; 32]),
        ActionKind::Mutating,
        placement.clone(),
    )
    .expect("gateway action claim should validate");

    let claimed = client
        .claim_action(claim, at(1))
        .expect("blocking claim should complete");
    assert!(matches!(claimed, GatewayActionClaimOutcome::Created(_)));
    assert_eq!(claimed.snapshot().action_sequence().get(), 1);

    let dispatch_id = DispatchId::new();
    let armed = client
        .arm_dispatch(
            &tenant_id,
            &session_id,
            &action_id,
            claimed.snapshot().revision(),
            &placement,
            dispatch_id.clone(),
            at(2),
        )
        .expect("dispatch intent should commit before handoff");
    assert_eq!(armed.state(), ActionState::MayHaveExecuted);

    let terminal = client
        .record_transport_loss(
            &tenant_id,
            &session_id,
            &action_id,
            armed.revision(),
            &placement,
            &dispatch_id,
            TransportLoss::ConfirmedNotWritten,
            at(3),
        )
        .expect("proven non-delivery should commit through the actor");
    assert_eq!(
        terminal.terminal().map(|evidence| evidence.detail()),
        Some(TerminalDetail::FailedKnown(
            KnownFailureReason::NotDispatched
        ))
    );

    let recovered = client
        .get_effective_action(&tenant_id, &session_id, &action_id)
        .expect("blocking action lookup should complete")
        .expect("durable action should remain queryable");
    assert_eq!(recovered, terminal);
}

#[test]
fn blocking_gateway_action_actor_rejects_an_invalid_materialization_limit() {
    let client = GatewayActionBlockingClient::spawn(
        Arc::new(MemoryGatewayActionStore::default()),
        CoordinationActorConfig::default(),
    )
    .expect("gateway action actor should spawn");
    let tenant_id = TenantId::new();
    let session_id = SessionId::new();
    let placement = GatewayActionPlacement::new(
        DirectoryFence::new(
            WorkerId::new("blocking-loss-worker").expect("worker ID should validate"),
            42,
            8,
            1,
        )
        .expect("directory fence should validate"),
        12,
    )
    .expect("gateway action placement should validate");
    let loss = browserd_coordination::SessionLossClaim::new(
        tenant_id,
        session_id,
        placement,
        uuid::Uuid::now_v7(),
    );

    assert!(client.materialize_session_loss(&loss, 0, at(1)).is_err());
}

#[test]
fn admitted_mutation_survives_the_last_client_timing_out_and_disconnecting() {
    let started = Arc::new(AtomicBool::new(false));
    let completed = Arc::new(AtomicBool::new(false));
    let store = Arc::new(SlowClaimStore {
        inner: MemoryGatewayActionStore::default(),
        started: Arc::clone(&started),
        completed: Arc::clone(&completed),
        delay: Duration::from_millis(200),
    });
    let config =
        CoordinationActorConfig::new(1, 1, Duration::from_millis(25), Duration::from_millis(50))
            .expect("short bounded actor config should validate");
    let client = GatewayActionBlockingClient::spawn(store, config)
        .expect("gateway action actor should spawn");
    let tenant_id = TenantId::new();
    let session_id = SessionId::new();
    let placement = GatewayActionPlacement::new(
        DirectoryFence::new(
            WorkerId::new("disconnect-action-worker").expect("worker ID should validate"),
            43,
            9,
            1,
        )
        .expect("directory fence should validate"),
        13,
    )
    .expect("gateway action placement should validate");
    let claim = ClaimGatewayAction::new(
        tenant_id,
        session_id,
        ActionId::new(),
        "disconnect-action-key",
        CanonicalRequestHash::new([10; 32]),
        ActionKind::Mutating,
        placement,
    )
    .expect("gateway action claim should validate");

    assert_eq!(
        client.claim_action(claim, at(1)),
        Err(GatewayActionCoordinationError::ActorMutationTimedOut)
    );
    assert!(started.load(Ordering::Acquire));
    drop(client);
    std::thread::sleep(Duration::from_millis(300));
    assert!(completed.load(Ordering::Acquire));
}
