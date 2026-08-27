#![allow(clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use browserd_coordination::{
    CanonicalRequestHash, ClaimCreateOperation, ClaimOutcome, CoordinationError,
    CreateOperationError, CreateOperationResult, CreateOperationSnapshot,
    CreateSessionCoordination, DispatchLeaseToken, MemoryCoordinationDatabase,
    MemoryCreateSessionStore, OperationMutation, RecoverableCreateIntent, StoreConfig,
};
use browserd_core::{CreateOperationState, OperationId, PrincipalId, SessionId, TenantId};
use chrono::{Duration, TimeZone, Utc};
use serde_json::json;

fn at(hour: u32) -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 28, hour, 0, 0)
        .single()
        .expect("test timestamp should be valid")
}

fn claim(
    tenant_id: TenantId,
    principal_id: PrincipalId,
    operation_id: OperationId,
    key: &str,
    hash_byte: u8,
) -> ClaimCreateOperation {
    ClaimCreateOperation::new(
        tenant_id,
        principal_id,
        operation_id.clone(),
        key,
        CanonicalRequestHash::new([hash_byte; 32]),
        RecoverableCreateIntent::new(
            &operation_id,
            json!({"request": hash_byte}),
            at(0),
            at(0) + Duration::seconds(30),
            json!({}),
        )
        .expect("intent"),
    )
    .expect("test claim should be valid")
}

fn created(outcome: ClaimOutcome) -> CreateOperationSnapshot {
    match outcome {
        ClaimOutcome::Created(snapshot) => snapshot,
        ClaimOutcome::Existing(_) => panic!("claim should create an operation"),
    }
}

#[tokio::test]
async fn claim_is_atomic_across_concurrent_callers() {
    let store = Arc::new(MemoryCreateSessionStore::default());
    let barrier = Arc::new(tokio::sync::Barrier::new(3));
    let tenant_id = TenantId::new();
    let principal_id = PrincipalId::new();
    let first_operation_id = OperationId::new();
    let second_operation_id = OperationId::new();
    let first = claim(
        tenant_id.clone(),
        principal_id.clone(),
        first_operation_id.clone(),
        "create-concurrent",
        7,
    );
    let second = claim(
        tenant_id,
        principal_id,
        second_operation_id.clone(),
        "create-concurrent",
        7,
    );

    let first_store = store.clone();
    let first_barrier = barrier.clone();
    let first_task = tokio::spawn(async move {
        first_barrier.wait().await;
        first_store.claim_create(first, at(1)).await
    });
    let second_store = store.clone();
    let second_barrier = barrier.clone();
    let second_task = tokio::spawn(async move {
        second_barrier.wait().await;
        second_store.claim_create(second, at(1)).await
    });
    barrier.wait().await;
    let left = first_task
        .await
        .expect("first caller task should finish")
        .expect("first claim should succeed");
    let right = second_task
        .await
        .expect("second caller task should finish")
        .expect("second claim should succeed");

    assert_ne!(
        matches!(left, ClaimOutcome::Created(_)),
        matches!(right, ClaimOutcome::Created(_))
    );
    assert_eq!(
        left.snapshot().operation_id(),
        right.snapshot().operation_id()
    );
    assert!(
        left.snapshot().operation_id() == &first_operation_id
            || left.snapshot().operation_id() == &second_operation_id
    );
}

#[tokio::test]
async fn retry_after_response_loss_and_store_restart_returns_the_original_operation() {
    let database = MemoryCoordinationDatabase::default();
    let first_store = MemoryCreateSessionStore::attach(database.clone(), StoreConfig::default());
    let tenant_id = TenantId::new();
    let principal_id = PrincipalId::new();
    let original_operation_id = OperationId::new();

    let lost_response = first_store
        .claim_create(
            claim(
                tenant_id.clone(),
                principal_id.clone(),
                original_operation_id.clone(),
                "response-loss",
                11,
            ),
            at(2),
        )
        .await;
    assert!(lost_response.is_ok());
    drop(first_store);

    let restarted = MemoryCreateSessionStore::attach(database, StoreConfig::default());
    let retry = restarted
        .claim_create(
            claim(
                tenant_id,
                principal_id,
                OperationId::new(),
                "response-loss",
                11,
            ),
            at(3),
        )
        .await
        .expect("retry should find the durable claim");

    assert!(matches!(retry, ClaimOutcome::Existing(_)));
    assert_eq!(retry.snapshot().operation_id(), &original_operation_id);
}

#[tokio::test]
async fn same_key_with_a_different_canonical_hash_is_a_conflict() {
    let store = MemoryCreateSessionStore::default();
    let tenant_id = TenantId::new();
    let principal_id = PrincipalId::new();
    let original_operation_id = OperationId::new();
    created(
        store
            .claim_create(
                claim(
                    tenant_id.clone(),
                    principal_id.clone(),
                    original_operation_id.clone(),
                    "body-conflict",
                    1,
                ),
                at(1),
            )
            .await
            .expect("initial claim should succeed"),
    );

    let conflict = store
        .claim_create(
            claim(
                tenant_id,
                principal_id,
                OperationId::new(),
                "body-conflict",
                2,
            ),
            at(2),
        )
        .await;

    assert!(matches!(
        conflict,
        Err(CoordinationError::IdempotencyConflict { existing_operation_id })
            if existing_operation_id == original_operation_id
    ));
}

#[tokio::test]
async fn idempotency_keys_are_namespaced_by_tenant() {
    let store = MemoryCreateSessionStore::default();
    let first = store
        .claim_create(
            claim(
                TenantId::new(),
                PrincipalId::new(),
                OperationId::new(),
                "shared-key",
                1,
            ),
            at(1),
        )
        .await
        .expect("first tenant claim should succeed");
    let second = store
        .claim_create(
            claim(
                TenantId::new(),
                PrincipalId::new(),
                OperationId::new(),
                "shared-key",
                2,
            ),
            at(1),
        )
        .await
        .expect("second tenant claim should succeed");

    assert!(matches!(first, ClaimOutcome::Created(_)));
    assert!(matches!(second, ClaimOutcome::Created(_)));
    assert_ne!(
        first.snapshot().operation_id(),
        second.snapshot().operation_id()
    );
}

#[tokio::test]
async fn cas_rejects_stale_writers_and_terminal_mutation() {
    let store = MemoryCreateSessionStore::default();
    let tenant_id = TenantId::new();
    let operation = created(
        store
            .claim_create(
                claim(
                    tenant_id.clone(),
                    PrincipalId::new(),
                    OperationId::new(),
                    "cas",
                    3,
                ),
                at(1),
            )
            .await
            .expect("claim should succeed"),
    );

    let queued = store
        .compare_and_set(
            &tenant_id,
            operation.operation_id(),
            operation.revision(),
            CreateOperationState::Accepted,
            OperationMutation::transition(CreateOperationState::Queued),
            at(2),
        )
        .await
        .expect("first CAS should succeed");
    let stale = store
        .compare_and_set(
            &tenant_id,
            operation.operation_id(),
            operation.revision(),
            CreateOperationState::Accepted,
            OperationMutation::transition(CreateOperationState::Cancelled),
            at(3),
        )
        .await;
    assert!(matches!(stale, Err(CoordinationError::StaleWrite(snapshot)) if *snapshot == queued));

    let cancelled = store
        .compare_and_set(
            &tenant_id,
            queued.operation_id(),
            queued.revision(),
            CreateOperationState::Queued,
            OperationMutation::transition(CreateOperationState::Cancelled),
            at(4),
        )
        .await
        .expect("cancellation should succeed");
    let terminal_change = store
        .compare_and_set(
            &tenant_id,
            cancelled.operation_id(),
            cancelled.revision(),
            CreateOperationState::Cancelled,
            OperationMutation::transition(CreateOperationState::Failed),
            at(5),
        )
        .await;
    assert!(matches!(
        terminal_change,
        Err(CoordinationError::TerminalImmutable(
            CreateOperationState::Cancelled
        ))
    ));
}

#[tokio::test]
async fn concurrent_cas_has_exactly_one_winner() {
    let store = Arc::new(MemoryCreateSessionStore::default());
    let barrier = Arc::new(tokio::sync::Barrier::new(3));
    let tenant_id = TenantId::new();
    let operation = created(
        store
            .claim_create(
                claim(
                    tenant_id.clone(),
                    PrincipalId::new(),
                    OperationId::new(),
                    "cas-race",
                    4,
                ),
                at(1),
            )
            .await
            .expect("claim should succeed"),
    );

    let first_store = store.clone();
    let first_tenant_id = tenant_id.clone();
    let first_operation_id = operation.operation_id().clone();
    let expected_revision = operation.revision();
    let expected_state = operation.state();
    let first_barrier = barrier.clone();
    let first_task = tokio::spawn(async move {
        first_barrier.wait().await;
        first_store
            .compare_and_set(
                &first_tenant_id,
                &first_operation_id,
                expected_revision,
                expected_state,
                OperationMutation::transition(CreateOperationState::Queued),
                at(2),
            )
            .await
    });
    let second_store = store.clone();
    let second_barrier = barrier.clone();
    let second_task = tokio::spawn(async move {
        second_barrier.wait().await;
        second_store
            .compare_and_set(
                &tenant_id,
                operation.operation_id(),
                operation.revision(),
                operation.state(),
                OperationMutation::transition(CreateOperationState::Cancelled),
                at(2),
            )
            .await
    });
    barrier.wait().await;
    let left = first_task.await.expect("first CAS task should finish");
    let right = second_task.await.expect("second CAS task should finish");
    assert_ne!(left.is_ok(), right.is_ok());
    assert!(matches!(
        left.as_ref().err().or_else(|| right.as_ref().err()),
        Some(CoordinationError::StaleWrite(_))
    ));
}

#[tokio::test]
async fn concurrent_cas_stale_snapshot_is_the_winner_state() {
    let store = MemoryCreateSessionStore::default();
    let tenant_id = TenantId::new();
    let operation = created(
        store
            .claim_create(
                claim(
                    tenant_id.clone(),
                    PrincipalId::new(),
                    OperationId::new(),
                    "cas-stale-snapshot",
                    8,
                ),
                at(1),
            )
            .await
            .expect("claim should succeed"),
    );
    let winner = store
        .compare_and_set(
            &tenant_id,
            operation.operation_id(),
            operation.revision(),
            operation.state(),
            OperationMutation::transition(CreateOperationState::Queued),
            at(2),
        )
        .await
        .expect("winner should update");
    let stale = store
        .compare_and_set(
            &tenant_id,
            operation.operation_id(),
            operation.revision(),
            operation.state(),
            OperationMutation::transition(CreateOperationState::Cancelled),
            at(2),
        )
        .await;
    assert!(matches!(
        stale,
        Err(CoordinationError::StaleWrite(snapshot)) if *snapshot == winner
    ));
}

#[tokio::test]
async fn terminal_session_result_and_error_are_preserved() {
    let store = MemoryCreateSessionStore::default();
    let tenant_id = TenantId::new();
    let (succeeded, succeeded_token) =
        advance_to_creating(&store, tenant_id.clone(), "success").await;
    let result = CreateOperationResult::new(SessionId::new(), json!({"primary_page_id": "page"}));
    let finished = store
        .compare_and_set(
            &tenant_id,
            succeeded.operation_id(),
            succeeded.revision(),
            CreateOperationState::Creating,
            OperationMutation::succeed_with_lease(succeeded_token, result.clone()),
            at(5),
        )
        .await
        .expect("success should be stored");
    assert_eq!(finished.result(), Some(&result));
    assert_eq!(
        store
            .get(&tenant_id, finished.operation_id())
            .await
            .expect("get should succeed")
            .expect("operation should exist")
            .result(),
        Some(&result)
    );

    let (failed, failed_token) = advance_to_creating(&store, tenant_id.clone(), "failure").await;
    let error =
        CreateOperationError::new("worker_unavailable", "worker disappeared", true, json!({}));
    let finished = store
        .compare_and_set(
            &tenant_id,
            failed.operation_id(),
            failed.revision(),
            CreateOperationState::Creating,
            OperationMutation::fail_with_lease(failed_token, error.clone()),
            at(6),
        )
        .await
        .expect("failure should be stored");
    assert_eq!(finished.error(), Some(&error));

    let (timed_out, timed_out_token) =
        advance_to_creating(&store, tenant_id.clone(), "timeout").await;
    let error = CreateOperationError::new("queue_timeout", "deadline elapsed", true, json!({}));
    let finished = store
        .compare_and_set(
            &tenant_id,
            timed_out.operation_id(),
            timed_out.revision(),
            CreateOperationState::Creating,
            OperationMutation::timeout_with_lease(timed_out_token, error.clone()),
            at(7),
        )
        .await
        .expect("timeout should be stored");
    assert_eq!(finished.state(), CreateOperationState::TimedOut);
    assert_eq!(finished.error(), Some(&error));
}

#[tokio::test]
async fn dispatch_lease_blocks_early_recovery_and_fences_terminal_completion() {
    let store = MemoryCreateSessionStore::default();
    let tenant_id = TenantId::new();
    let mut snapshot = created(
        store
            .claim_create(
                claim(
                    tenant_id.clone(),
                    PrincipalId::new(),
                    OperationId::new(),
                    "dispatch-lease",
                    12,
                ),
                at(0),
            )
            .await
            .expect("claim should succeed"),
    );
    for next in [
        CreateOperationState::Queued,
        CreateOperationState::Reserving,
    ] {
        snapshot = store
            .compare_and_set(
                &tenant_id,
                snapshot.operation_id(),
                snapshot.revision(),
                snapshot.state(),
                OperationMutation::transition(next),
                at(0),
            )
            .await
            .expect("transition should succeed");
    }
    let owner = DispatchLeaseToken::new();
    snapshot = store
        .acquire_dispatch_lease(
            &tenant_id,
            snapshot.operation_id(),
            snapshot.revision(),
            owner.clone(),
            std::time::Duration::from_secs(2 * 60 * 60),
            at(0),
        )
        .await
        .expect("dispatch owner should be stored");

    let early = store
        .acquire_dispatch_lease(
            &tenant_id,
            snapshot.operation_id(),
            snapshot.revision(),
            DispatchLeaseToken::new(),
            std::time::Duration::from_secs(2 * 60 * 60),
            at(1),
        )
        .await;
    assert!(matches!(
        early,
        Err(CoordinationError::DispatchLeaseActive(_))
    ));

    let result = CreateOperationResult::new(SessionId::new(), json!({"ready": true}));
    let wrong_owner = store
        .compare_and_set(
            &tenant_id,
            snapshot.operation_id(),
            snapshot.revision(),
            snapshot.state(),
            OperationMutation::succeed_with_lease(DispatchLeaseToken::new(), result.clone()),
            at(1),
        )
        .await;
    assert!(matches!(
        wrong_owner,
        Err(CoordinationError::DispatchLeaseMismatch)
    ));
    let completed = store
        .compare_and_set(
            &tenant_id,
            snapshot.operation_id(),
            snapshot.revision(),
            snapshot.state(),
            OperationMutation::succeed_with_lease(owner, result.clone()),
            at(1),
        )
        .await
        .expect("current dispatch owner should complete");
    assert_eq!(completed.result(), Some(&result));
    assert!(completed.dispatch_lease().is_none());
}

#[tokio::test]
async fn creating_requires_lease_api_and_recovery_fences_stale_generation() {
    let store = MemoryCreateSessionStore::default();
    let tenant = TenantId::new();
    let mut snapshot = created(
        store
            .claim_create(
                claim(
                    tenant.clone(),
                    PrincipalId::new(),
                    OperationId::new(),
                    "fenced-generation",
                    33,
                ),
                at(0),
            )
            .await
            .expect("claim"),
    );
    for state in [
        CreateOperationState::Queued,
        CreateOperationState::Reserving,
    ] {
        snapshot = store
            .compare_and_set(
                &tenant,
                snapshot.operation_id(),
                snapshot.revision(),
                snapshot.state(),
                OperationMutation::transition(state),
                at(0),
            )
            .await
            .expect("transition");
    }
    let bypass = store
        .compare_and_set(
            &tenant,
            snapshot.operation_id(),
            snapshot.revision(),
            snapshot.state(),
            OperationMutation::transition(CreateOperationState::Creating),
            at(0),
        )
        .await;
    assert!(matches!(
        bypass,
        Err(CoordinationError::InvalidTransition { .. })
    ));
    let old = DispatchLeaseToken::new();
    snapshot = store
        .acquire_dispatch_lease(
            &tenant,
            snapshot.operation_id(),
            snapshot.revision(),
            old.clone(),
            std::time::Duration::from_secs(1),
            at(0),
        )
        .await
        .expect("first lease");
    assert_eq!(snapshot.dispatch_generation(), 1);
    let fresh = DispatchLeaseToken::new();
    snapshot = store
        .acquire_dispatch_lease(
            &tenant,
            snapshot.operation_id(),
            snapshot.revision(),
            fresh.clone(),
            std::time::Duration::from_secs(1),
            at(1),
        )
        .await
        .expect("recovery lease");
    assert_eq!(snapshot.dispatch_generation(), 2);
    let result = CreateOperationResult::new(SessionId::new(), json!({}));
    let stale = store
        .compare_and_set(
            &tenant,
            snapshot.operation_id(),
            snapshot.revision(),
            snapshot.state(),
            OperationMutation::succeed_with_lease(old, result.clone()),
            at(1),
        )
        .await;
    assert!(matches!(
        stale,
        Err(CoordinationError::DispatchLeaseMismatch)
    ));
    assert!(
        store
            .compare_and_set(
                &tenant,
                snapshot.operation_id(),
                snapshot.revision(),
                snapshot.state(),
                OperationMutation::succeed_with_lease(fresh, result),
                at(1)
            )
            .await
            .is_ok()
    );
}

async fn advance_to_creating(
    store: &MemoryCreateSessionStore,
    tenant_id: TenantId,
    key: &str,
) -> (CreateOperationSnapshot, DispatchLeaseToken) {
    let mut snapshot = created(
        store
            .claim_create(
                claim(
                    tenant_id.clone(),
                    PrincipalId::new(),
                    OperationId::new(),
                    key,
                    5,
                ),
                at(1),
            )
            .await
            .expect("claim should succeed"),
    );
    for next in [
        CreateOperationState::Queued,
        CreateOperationState::Reserving,
    ] {
        snapshot = store
            .compare_and_set(
                &tenant_id,
                snapshot.operation_id(),
                snapshot.revision(),
                snapshot.state(),
                OperationMutation::transition(next),
                at(2),
            )
            .await
            .expect("transition should succeed");
    }
    let token = DispatchLeaseToken::new();
    snapshot = store
        .acquire_dispatch_lease(
            &tenant_id,
            snapshot.operation_id(),
            snapshot.revision(),
            token.clone(),
            std::time::Duration::from_secs(30),
            at(2),
        )
        .await
        .expect("lease");
    (snapshot, token)
}

#[tokio::test]
async fn retention_is_at_least_24_hours_and_only_terminal_rows_are_purged() {
    assert!(matches!(
        StoreConfig::new(std::time::Duration::from_secs(86_399)),
        Err(CoordinationError::RetentionBelowMinimum)
    ));

    let config = StoreConfig::new(std::time::Duration::from_secs(86_400))
        .expect("24 hour retention should be valid");
    let store = MemoryCreateSessionStore::attach(MemoryCoordinationDatabase::default(), config);
    let tenant_id = TenantId::new();
    let active = created(
        store
            .claim_create(
                claim(
                    tenant_id.clone(),
                    PrincipalId::new(),
                    OperationId::new(),
                    "active",
                    6,
                ),
                at(0),
            )
            .await
            .expect("active claim should succeed"),
    );
    let terminal = created(
        store
            .claim_create(
                claim(
                    tenant_id.clone(),
                    PrincipalId::new(),
                    OperationId::new(),
                    "terminal",
                    7,
                ),
                at(0),
            )
            .await
            .expect("terminal claim should succeed"),
    );
    store
        .compare_and_set(
            &tenant_id,
            terminal.operation_id(),
            terminal.revision(),
            terminal.state(),
            OperationMutation::transition(CreateOperationState::Cancelled),
            at(1),
        )
        .await
        .expect("terminal transition should succeed");

    assert_eq!(
        store
            .purge_expired(at(23))
            .await
            .expect("purge should succeed"),
        0
    );
    let after_window = at(0) + Duration::hours(24) + Duration::seconds(1);
    assert_eq!(
        store
            .purge_expired(after_window)
            .await
            .expect("purge should succeed"),
        1
    );
    assert!(
        store
            .get(&tenant_id, terminal.operation_id())
            .await
            .expect("get should succeed")
            .is_none()
    );
    assert!(
        store
            .get(&tenant_id, active.operation_id())
            .await
            .expect("get should succeed")
            .is_some()
    );
}
