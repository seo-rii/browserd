#![allow(clippy::expect_used)]

use std::collections::HashSet;
use std::sync::Arc;

use browserd_actions::{
    ActionKind, ActionSequence, ActionTerminalSource, BrowserResult, CanonicalRequestHash,
    DispatchId, KnownFailureReason, OutcomeUnknownReason, ResultDigest, TerminalDetail,
};
use browserd_coordination::{
    ClaimGatewayAction, DirectoryFence, GatewayActionClaimOutcome, GatewayActionCoordination,
    GatewayActionCoordinationError, GatewayActionPlacement, MemoryCoordinationDatabase,
    MemoryGatewayActionStore, SessionLossClaim, SessionLossOutcome, StoreConfig,
};
use browserd_core::{ActionId, ActionState, SessionId, TenantId, WorkerId};
use chrono::{TimeZone, Utc};
use uuid::Uuid;

fn at(second: u32) -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 30, 0, 0, second)
        .single()
        .expect("test timestamp should be valid")
}

fn placement(worker_epoch: u64, directory_revision: u64) -> GatewayActionPlacement {
    GatewayActionPlacement::new(
        DirectoryFence::new(
            WorkerId::new("gateway-action-worker").expect("worker ID should be valid"),
            worker_epoch,
            11,
            1,
        )
        .expect("directory fence should be valid"),
        directory_revision,
    )
    .expect("gateway action placement should be valid")
}

fn claim(
    tenant_id: TenantId,
    session_id: SessionId,
    proposed_action_id: ActionId,
    idempotency_key: &str,
    request_byte: u8,
    placement: GatewayActionPlacement,
) -> ClaimGatewayAction {
    ClaimGatewayAction::new(
        tenant_id,
        session_id,
        proposed_action_id,
        idempotency_key,
        CanonicalRequestHash::new([request_byte; 32]),
        ActionKind::Mutating,
        placement,
    )
    .expect("gateway action claim should be valid")
}

#[tokio::test]
async fn concurrent_exact_claims_linearize_to_one_gateway_action_id() {
    const CLAIMANTS: usize = 100;
    let database = MemoryCoordinationDatabase::default();
    let store = MemoryGatewayActionStore::attach(database.clone(), StoreConfig::default());
    let barrier = Arc::new(tokio::sync::Barrier::new(CLAIMANTS + 1));
    let tenant_id = TenantId::new();
    let session_id = SessionId::new();
    let placement = placement(7, 29);
    let mut tasks = Vec::with_capacity(CLAIMANTS);

    for _ in 0..CLAIMANTS {
        let store = store.clone();
        let barrier = Arc::clone(&barrier);
        let claim = claim(
            tenant_id.clone(),
            session_id.clone(),
            ActionId::new(),
            "action-response-loss",
            3,
            placement.clone(),
        );
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store.claim_action(claim, at(1)).await
        }));
    }

    barrier.wait().await;
    let mut created = 0;
    let mut action_ids = HashSet::new();
    for task in tasks {
        let outcome = task
            .await
            .expect("claim task should join")
            .expect("exact claim should succeed");
        created += usize::from(matches!(outcome, GatewayActionClaimOutcome::Created(_)));
        action_ids.insert(outcome.snapshot().action_id().clone());
    }
    assert_eq!(created, 1);
    assert_eq!(action_ids.len(), 1);

    let action_id = action_ids
        .into_iter()
        .next()
        .expect("one action ID should remain");
    drop(store);
    let restarted = MemoryGatewayActionStore::attach(database, StoreConfig::default());
    let recovered = restarted
        .get_effective_action(&tenant_id, &session_id, &action_id)
        .await
        .expect("action lookup should succeed")
        .expect("gateway action mapping should survive store reattachment");
    assert_eq!(recovered.state(), ActionState::Accepted);
    assert_eq!(recovered.action_sequence().get(), 1);
}

#[tokio::test]
async fn concurrent_distinct_gateway_claims_allocate_gapless_session_sequences() {
    const ACTIONS: usize = 64;
    let store = MemoryGatewayActionStore::default();
    let barrier = Arc::new(tokio::sync::Barrier::new(ACTIONS + 1));
    let tenant_id = TenantId::new();
    let session_id = SessionId::new();
    let placement = placement(8, 30);
    let mut tasks = Vec::with_capacity(ACTIONS);

    for index in 0..ACTIONS {
        let store = store.clone();
        let barrier = Arc::clone(&barrier);
        let claim = claim(
            tenant_id.clone(),
            session_id.clone(),
            ActionId::new(),
            &format!("sequence-{index}"),
            index as u8,
            placement.clone(),
        );
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store.claim_action(claim, at(1)).await
        }));
    }

    barrier.wait().await;
    let mut sequences = Vec::with_capacity(ACTIONS);
    for task in tasks {
        let outcome = task
            .await
            .expect("sequence claim task should join")
            .expect("distinct sequence claim should succeed");
        sequences.push(outcome.snapshot().action_sequence().get());
    }
    sequences.sort_unstable();
    assert_eq!(sequences, (1..=ACTIONS as u64).collect::<Vec<_>>());
}

#[tokio::test]
async fn idempotency_and_action_identity_conflicts_fail_closed() {
    let store = MemoryGatewayActionStore::default();
    let tenant_id = TenantId::new();
    let session_id = SessionId::new();
    let placement = placement(9, 31);
    let action_id = ActionId::new();
    store
        .claim_action(
            claim(
                tenant_id.clone(),
                session_id.clone(),
                action_id.clone(),
                "stable-key",
                1,
                placement.clone(),
            ),
            at(1),
        )
        .await
        .expect("initial claim should succeed");

    assert_eq!(
        store
            .claim_action(
                claim(
                    tenant_id.clone(),
                    session_id.clone(),
                    ActionId::new(),
                    "stable-key",
                    2,
                    placement.clone(),
                ),
                at(2),
            )
            .await,
        Err(GatewayActionCoordinationError::IdempotencyConflict {
            existing_action_id: action_id.clone(),
        })
    );
    assert_eq!(
        store
            .claim_action(
                claim(
                    tenant_id,
                    session_id,
                    action_id.clone(),
                    "different-key",
                    1,
                    placement,
                ),
                at(2),
            )
            .await,
        Err(GatewayActionCoordinationError::ActionIdentityConflict { action_id })
    );
}

#[tokio::test]
async fn session_loss_fence_drives_queries_before_bounded_materialization() {
    let database = MemoryCoordinationDatabase::default();
    let store = MemoryGatewayActionStore::attach(database.clone(), StoreConfig::default());
    let tenant_id = TenantId::new();
    let session_id = SessionId::new();
    let placement = placement(19, 41);
    let before_dispatch_id = ActionId::new();
    let armed_id = ActionId::new();

    let before_dispatch = store
        .claim_action(
            claim(
                tenant_id.clone(),
                session_id.clone(),
                before_dispatch_id.clone(),
                "worker-loss-before-dispatch",
                5,
                placement.clone(),
            ),
            at(1),
        )
        .await
        .expect("pre-dispatch action claim should succeed");
    let armed = store
        .claim_action(
            claim(
                tenant_id.clone(),
                session_id.clone(),
                armed_id.clone(),
                "worker-loss-after-dispatch-intent",
                7,
                placement.clone(),
            ),
            at(1),
        )
        .await
        .expect("armed action claim should succeed");
    let dispatch_id = DispatchId::new();
    store
        .arm_dispatch(
            &tenant_id,
            &session_id,
            &armed_id,
            armed.snapshot().revision(),
            &placement,
            dispatch_id.clone(),
            at(2),
        )
        .await
        .expect("dispatch should arm before handoff");

    let loss = SessionLossClaim::new(
        tenant_id.clone(),
        session_id.clone(),
        placement.clone(),
        Uuid::now_v7(),
    );
    assert_eq!(
        store
            .mark_session_lost(&loss, at(3))
            .await
            .expect("session loss should linearize"),
        SessionLossOutcome::Recorded
    );

    let exact_retry = store
        .claim_action(
            claim(
                tenant_id.clone(),
                session_id.clone(),
                ActionId::new(),
                "worker-loss-after-dispatch-intent",
                7,
                placement.clone(),
            ),
            at(4),
        )
        .await
        .expect("exact retry after loss should recover the existing action");
    assert!(matches!(
        exact_retry,
        GatewayActionClaimOutcome::Existing(_)
    ));
    assert_eq!(exact_retry.snapshot().action_id(), &armed_id);
    assert_eq!(
        exact_retry
            .snapshot()
            .terminal()
            .map(|terminal| terminal.detail()),
        Some(TerminalDetail::OutcomeUnknown(
            OutcomeUnknownReason::WorkerLost
        ))
    );

    let known = store
        .get_effective_action(&tenant_id, &session_id, &before_dispatch_id)
        .await
        .expect("pre-dispatch action lookup should succeed")
        .expect("pre-dispatch action should exist");
    let unknown = store
        .get_effective_action(&tenant_id, &session_id, &armed_id)
        .await
        .expect("armed action lookup should succeed")
        .expect("armed action should exist");
    assert_eq!(
        known.terminal().map(|terminal| terminal.detail()),
        Some(TerminalDetail::FailedKnown(
            KnownFailureReason::NotDispatched
        ))
    );
    assert_eq!(
        unknown.terminal().map(|terminal| terminal.detail()),
        Some(TerminalDetail::OutcomeUnknown(
            OutcomeUnknownReason::WorkerLost
        ))
    );
    assert_eq!(
        unknown.terminal().map(|terminal| terminal.source()),
        Some(ActionTerminalSource::WorkerLoss)
    );
    assert_eq!(known.revision(), before_dispatch.snapshot().revision());

    assert_eq!(
        store
            .record_worker_result(
                &tenant_id,
                &session_id,
                &armed_id,
                unknown.revision(),
                &placement,
                &dispatch_id,
                ActionSequence::new(12),
                BrowserResult::Succeeded(ResultDigest::new([9; 32])),
                at(4),
            )
            .await,
        Err(GatewayActionCoordinationError::SessionLost)
    );

    assert_eq!(
        store
            .materialize_session_loss(&loss, 1, at(4))
            .await
            .expect("first bounded materialization should succeed"),
        1
    );
    assert_eq!(
        store
            .materialize_session_loss(&loss, 1, at(5))
            .await
            .expect("second bounded materialization should succeed"),
        1
    );
    let materialized = store
        .get_effective_action(&tenant_id, &session_id, &before_dispatch_id)
        .await
        .expect("materialized action lookup should succeed")
        .expect("materialized action should exist");
    assert_eq!(
        materialized.revision(),
        before_dispatch.snapshot().revision() + 1
    );
    assert_eq!(
        store
            .materialize_session_loss(&loss, 10, at(6))
            .await
            .expect("repeated materialization should be idempotent"),
        0
    );
}

#[tokio::test]
async fn stale_loss_claim_cannot_fence_a_newer_directory_revision() {
    let store = MemoryGatewayActionStore::default();
    let tenant_id = TenantId::new();
    let session_id = SessionId::new();
    let current = placement(23, 52);
    let action_id = ActionId::new();
    store
        .claim_action(
            claim(
                tenant_id.clone(),
                session_id.clone(),
                action_id.clone(),
                "current-placement",
                4,
                current,
            ),
            at(1),
        )
        .await
        .expect("claim should establish the current placement");
    let stale = SessionLossClaim::new(
        tenant_id.clone(),
        session_id.clone(),
        placement(23, 51),
        Uuid::now_v7(),
    );

    assert_eq!(
        store.mark_session_lost(&stale, at(2)).await,
        Err(GatewayActionCoordinationError::PlacementMismatch)
    );
    let snapshot = store
        .get_effective_action(&tenant_id, &session_id, &action_id)
        .await
        .expect("lookup should succeed")
        .expect("action should exist");
    assert_eq!(snapshot.state(), ActionState::Accepted);
    assert_eq!(snapshot.terminal(), None);
}

#[tokio::test]
async fn worker_result_and_loss_fence_have_one_stable_linearization_winner() {
    for iteration in 0..100_u8 {
        let store = MemoryGatewayActionStore::default();
        let tenant_id = TenantId::new();
        let session_id = SessionId::new();
        let placement = placement(31, 61);
        let action_id = ActionId::new();
        let claimed = store
            .claim_action(
                claim(
                    tenant_id.clone(),
                    session_id.clone(),
                    action_id.clone(),
                    "terminal-loss-race",
                    iteration,
                    placement.clone(),
                ),
                at(1),
            )
            .await
            .expect("action claim should succeed");
        let dispatch_id = DispatchId::new();
        let armed = store
            .arm_dispatch(
                &tenant_id,
                &session_id,
                &action_id,
                claimed.snapshot().revision(),
                &placement,
                dispatch_id.clone(),
                at(2),
            )
            .await
            .expect("dispatch should arm");
        let loss = SessionLossClaim::new(
            tenant_id.clone(),
            session_id.clone(),
            placement.clone(),
            Uuid::now_v7(),
        );
        let barrier = Arc::new(tokio::sync::Barrier::new(3));

        let result_store = store.clone();
        let result_barrier = Arc::clone(&barrier);
        let result_tenant = tenant_id.clone();
        let result_session = session_id.clone();
        let result_action = action_id.clone();
        let result_placement = placement.clone();
        let result_dispatch = dispatch_id;
        let result = tokio::spawn(async move {
            result_barrier.wait().await;
            result_store
                .record_worker_result(
                    &result_tenant,
                    &result_session,
                    &result_action,
                    armed.revision(),
                    &result_placement,
                    &result_dispatch,
                    ActionSequence::new(1),
                    BrowserResult::Succeeded(ResultDigest::new([8; 32])),
                    at(3),
                )
                .await
        });
        let loss_store = store.clone();
        let loss_barrier = Arc::clone(&barrier);
        let lost = tokio::spawn(async move {
            loss_barrier.wait().await;
            loss_store.mark_session_lost(&loss, at(3)).await
        });

        barrier.wait().await;
        let result = result.await.expect("result task should join");
        let lost = lost.await.expect("loss task should join");
        assert!(lost.is_ok());
        let effective = store
            .get_effective_action(&tenant_id, &session_id, &action_id)
            .await
            .expect("effective lookup should succeed")
            .expect("action should exist");
        match result {
            Ok(snapshot) => {
                assert_eq!(
                    snapshot.terminal().map(|terminal| terminal.detail()),
                    Some(TerminalDetail::Succeeded(ResultDigest::new([8; 32])))
                );
                assert_eq!(effective.terminal(), snapshot.terminal());
            }
            Err(GatewayActionCoordinationError::SessionLost) => {
                assert_eq!(
                    effective.terminal().map(|terminal| terminal.detail()),
                    Some(TerminalDetail::OutcomeUnknown(
                        OutcomeUnknownReason::WorkerLost
                    ))
                );
            }
            other => assert_eq!(other, Err(GatewayActionCoordinationError::SessionLost)),
        }
    }
}

#[tokio::test]
async fn worker_terminal_receipts_preserve_worker_evidence_source() {
    for (index, detail) in [
        TerminalDetail::CancelledBeforeDispatch,
        TerminalDetail::OutcomeUnknown(OutcomeUnknownReason::TimeoutAfterDispatch),
    ]
    .into_iter()
    .enumerate()
    {
        let store = MemoryGatewayActionStore::default();
        let tenant_id = TenantId::new();
        let session_id = SessionId::new();
        let placement = placement(41, 71);
        let action_id = ActionId::new();
        let idempotency_key = format!("worker-terminal-{index}");
        let claimed = store
            .claim_action(
                claim(
                    tenant_id.clone(),
                    session_id.clone(),
                    action_id.clone(),
                    &idempotency_key,
                    index as u8,
                    placement.clone(),
                ),
                at(1),
            )
            .await
            .expect("action claim should succeed");
        let dispatch_id = DispatchId::new();
        let armed = store
            .arm_dispatch(
                &tenant_id,
                &session_id,
                &action_id,
                claimed.snapshot().revision(),
                &placement,
                dispatch_id.clone(),
                at(2),
            )
            .await
            .expect("dispatch should arm");

        let terminal = store
            .record_worker_terminal(
                &tenant_id,
                &session_id,
                &action_id,
                armed.revision(),
                &placement,
                &dispatch_id,
                claimed.snapshot().action_sequence(),
                detail,
                at(3),
            )
            .await
            .expect("worker terminal should be recorded");
        assert_eq!(
            terminal.terminal().map(|evidence| evidence.detail()),
            Some(detail)
        );
        assert_eq!(
            terminal.terminal().map(|evidence| evidence.source()),
            Some(ActionTerminalSource::Worker)
        );
    }
}
