#![allow(clippy::expect_used)]

use std::sync::Arc;

use browserd_coordination::{
    CanonicalRequestHash, ClaimCreateOperation, ClaimOutcome, CreateOperationResult,
    CreateSessionCoordination, OperationMutation, PostgresCreateSessionStore, StoreConfig,
};
use browserd_core::{CreateOperationState, OperationId, PrincipalId, SessionId, TenantId};
use chrono::Utc;
use serde_json::json;

#[tokio::test]
async fn postgres_claim_and_terminal_result_survive_a_store_restart() {
    let Ok(database_url) = std::env::var("BROWSERD_COORDINATION_TEST_DATABASE_URL") else {
        return;
    };
    let store = Arc::new(
        PostgresCreateSessionStore::connect(&database_url, 4, StoreConfig::default())
            .await
            .expect("test PostgreSQL should be reachable"),
    );
    store.migrate().await.expect("migration should succeed");
    let tenant_id = TenantId::new();
    let principal_id = PrincipalId::new();
    let original_operation_id = OperationId::new();
    let now = Utc::now();
    let first_claim = ClaimCreateOperation::new(
        tenant_id.clone(),
        principal_id.clone(),
        original_operation_id.clone(),
        "postgres-response-loss",
        CanonicalRequestHash::new([42; 32]),
    )
    .expect("claim should be valid");
    let retry_claim = ClaimCreateOperation::new(
        tenant_id.clone(),
        principal_id,
        OperationId::new(),
        "postgres-response-loss",
        CanonicalRequestHash::new([42; 32]),
    )
    .expect("claim should be valid");

    let first = store
        .claim_create(first_claim, now)
        .await
        .expect("initial claim should succeed");
    let retry = store
        .claim_create(retry_claim, now)
        .await
        .expect("retry claim should succeed");
    assert!(matches!(first, ClaimOutcome::Created(_)));
    assert!(matches!(retry, ClaimOutcome::Existing(_)));
    assert_eq!(first.snapshot().operation_id(), &original_operation_id);
    assert_eq!(retry.snapshot().operation_id(), &original_operation_id);

    let mut snapshot = first.snapshot().clone();
    for next in [
        CreateOperationState::Queued,
        CreateOperationState::Reserving,
        CreateOperationState::Creating,
    ] {
        snapshot = store
            .compare_and_set(
                &tenant_id,
                snapshot.operation_id(),
                snapshot.revision(),
                snapshot.state(),
                OperationMutation::transition(next),
                now,
            )
            .await
            .expect("transition should succeed");
    }
    let result = CreateOperationResult::new(SessionId::new(), json!({"ready": true}));
    snapshot = store
        .compare_and_set(
            &tenant_id,
            snapshot.operation_id(),
            snapshot.revision(),
            snapshot.state(),
            OperationMutation::succeed(result.clone()),
            now,
        )
        .await
        .expect("success should be stored");
    drop(store);

    let restarted = PostgresCreateSessionStore::connect(&database_url, 2, StoreConfig::default())
        .await
        .expect("restarted store should connect");
    let recovered = restarted
        .get(&tenant_id, &original_operation_id)
        .await
        .expect("read should succeed")
        .expect("operation should survive restart");
    assert_eq!(recovered, snapshot);
    assert_eq!(recovered.result(), Some(&result));

    sqlx::query("DELETE FROM browserd_create_session_operations WHERE tenant_id = $1")
        .bind(*tenant_id.as_uuid())
        .execute(restarted.pool())
        .await
        .expect("test rows should be cleaned up");
}
