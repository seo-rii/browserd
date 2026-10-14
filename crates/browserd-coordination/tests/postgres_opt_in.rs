#![allow(clippy::expect_used)]

use std::sync::Arc;

use browserd_coordination::{
    CanonicalRequestHash, ClaimCreateOperation, ClaimOutcome, CoordinationError,
    CreateOperationResult, CreateSessionCoordination, DispatchLeaseToken, OperationMutation,
    PostgresCreateSessionStore, RecoverableCreateIntent, StoreConfig,
};
use browserd_core::{CreateOperationState, OperationId, PrincipalId, SessionId, TenantId};
use chrono::{Duration, Utc};
use serde_json::json;

#[tokio::test]
async fn postgres_purge_is_bounded_and_keeps_pending_and_retained_operations() {
    let Ok(database_url) = std::env::var("BROWSERD_COORDINATION_TEST_DATABASE_URL") else {
        return;
    };
    let store = PostgresCreateSessionStore::connect(&database_url, 4, StoreConfig::default())
        .await
        .expect("PostgreSQL");
    store.migrate().await.expect("migrate");
    let tenant = TenantId::new();
    let principal = PrincipalId::new();
    let now = Utc::now();
    let mut pending = None;
    let mut retained = None;
    let mut unresolved = None;
    for index in 0..83 {
        let id = OperationId::new();
        let claim = ClaimCreateOperation::new(
            tenant.clone(),
            principal.clone(),
            id.clone(),
            format!("janitor-{index}"),
            CanonicalRequestHash::new([7; 32]),
            RecoverableCreateIntent::new(
                &id,
                json!({}),
                now,
                now + Duration::seconds(30),
                json!({}),
            )
            .expect("intent"),
        )
        .expect("claim");
        let snapshot = store
            .claim_create(claim, now)
            .await
            .expect("claim")
            .snapshot()
            .clone();
        if index == 80 {
            pending = Some(id);
            continue;
        }
        if index == 82 {
            let queued = store
                .compare_and_set(
                    &tenant,
                    &id,
                    snapshot.revision(),
                    snapshot.state(),
                    OperationMutation::transition(CreateOperationState::Queued),
                    now,
                )
                .await
                .expect("queued");
            let reserving = store
                .compare_and_set(
                    &tenant,
                    &id,
                    queued.revision(),
                    queued.state(),
                    OperationMutation::transition(CreateOperationState::Reserving),
                    now,
                )
                .await
                .expect("reserving");
            store
                .acquire_dispatch_lease(
                    &tenant,
                    &id,
                    reserving.revision(),
                    DispatchLeaseToken::new(),
                    std::time::Duration::from_secs(30),
                    now,
                )
                .await
                .expect("creating");
            unresolved = Some(id);
            continue;
        }
        store
            .compare_and_set(
                &tenant,
                &id,
                snapshot.revision(),
                snapshot.state(),
                OperationMutation::transition(CreateOperationState::Cancelled),
                now,
            )
            .await
            .expect("terminal and outbox commit");
        if index == 81 {
            retained = Some(id);
        }
    }
    sqlx::query("UPDATE browserd_create_session_operations SET created_at=clock_timestamp()-interval '48 hours', updated_at=clock_timestamp()-interval '25 hours', retain_until=clock_timestamp()-interval '24 hours' WHERE tenant_id=$1 AND operation_id<>$2")
        .bind(*tenant.as_uuid()).bind(*retained.as_ref().expect("retained").as_uuid()).execute(store.pool()).await.expect("expire only fixture");
    sqlx::query("UPDATE browserd_create_session_operations SET dispatch_lease_expires_at=clock_timestamp()-interval '1 hour' WHERE tenant_id=$1 AND operation_id=$2")
        .bind(*tenant.as_uuid()).bind(*unresolved.as_ref().expect("unresolved").as_uuid()).execute(store.pool()).await.expect("expire fixture lease without resolving outcome");
    let deleted = store.purge_expired(now).await.expect("bounded pass");
    let pending_exists = store
        .get(&tenant, pending.as_ref().expect("pending"))
        .await
        .expect("pending lookup")
        .is_some();
    let retained_exists = store
        .get(&tenant, retained.as_ref().expect("retained"))
        .await
        .expect("retained lookup")
        .is_some();
    let unresolved_exists = store
        .get(&tenant, unresolved.as_ref().expect("unresolved"))
        .await
        .expect("unresolved lookup")
        .is_some_and(|record| record.state() == CreateOperationState::Creating);
    let journal: i64 =
        sqlx::query_scalar("SELECT count(*) FROM browserd_event_outbox WHERE tenant_id=$1")
            .bind(*tenant.as_uuid())
            .fetch_one(store.pool())
            .await
            .expect("outbox remains durable");
    let remaining: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM browserd_create_session_operations WHERE tenant_id=$1",
    )
    .bind(*tenant.as_uuid())
    .fetch_one(store.pool())
    .await
    .expect("remaining");
    // Clean only this fixture before the intended RED assertion, including on a failed bound.
    sqlx::query("DELETE FROM browserd_create_session_operations WHERE tenant_id=$1")
        .bind(*tenant.as_uuid())
        .execute(store.pool())
        .await
        .expect("fixture cleanup");
    assert!(
        deleted <= 32,
        "one indexed janitor pass must not remove every expired operation"
    );
    assert!(remaining >= 50);
    assert!(pending_exists && retained_exists && unresolved_exists);
    assert!(
        journal >= 167,
        "operation pruning does not remove transactional outbox events"
    );
}

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
        RecoverableCreateIntent::new(
            &original_operation_id,
            json!({}),
            now,
            now + Duration::seconds(30),
            json!({}),
        )
        .expect("intent"),
    )
    .expect("claim should be valid");
    let retry_claim = ClaimCreateOperation::new(
        tenant_id.clone(),
        principal_id,
        original_operation_id.clone(),
        "postgres-response-loss",
        CanonicalRequestHash::new([42; 32]),
        RecoverableCreateIntent::new(
            &original_operation_id,
            json!({}),
            now,
            now + Duration::seconds(30),
            json!({}),
        )
        .expect("intent"),
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
    let dispatch_token = DispatchLeaseToken::new();
    snapshot = store
        .acquire_dispatch_lease(
            &tenant_id,
            snapshot.operation_id(),
            snapshot.revision(),
            dispatch_token.clone(),
            std::time::Duration::from_secs(30),
            now,
        )
        .await
        .expect("dispatch lease should be stored");
    let result = CreateOperationResult::new(SessionId::new(), json!({"ready": true}));
    snapshot = store
        .compare_and_set(
            &tenant_id,
            snapshot.operation_id(),
            snapshot.revision(),
            snapshot.state(),
            OperationMutation::succeed_with_lease(dispatch_token, result.clone()),
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

#[tokio::test]
async fn postgres_exact_defer_preserves_intent_and_generation_across_reconnect() {
    let Ok(database_url) = std::env::var("BROWSERD_COORDINATION_TEST_DATABASE_URL") else {
        return;
    };
    let store = PostgresCreateSessionStore::connect(&database_url, 2, StoreConfig::default())
        .await
        .expect("isolated PostgreSQL connection");
    store.migrate().await.expect("migration");
    let tenant = TenantId::new();
    let operation = OperationId::new();
    let now = Utc::now();
    let claim = ClaimCreateOperation::new(
        tenant.clone(),
        PrincipalId::new(),
        operation.clone(),
        "postgres-fleet-defer",
        CanonicalRequestHash::new([71; 32]),
        RecoverableCreateIntent::new(
            &operation,
            json!({"profile":"fleet", "metadata":{"name":"대기"}}),
            now,
            now + Duration::seconds(30),
            json!({"policy":"immutable"}),
        )
        .expect("intent"),
    )
    .expect("claim");
    let mut snapshot = store
        .claim_create(claim, now)
        .await
        .expect("claim persisted")
        .snapshot()
        .clone();
    for next in [
        CreateOperationState::Queued,
        CreateOperationState::Reserving,
    ] {
        snapshot = store
            .compare_and_set(
                &tenant,
                &operation,
                snapshot.revision(),
                snapshot.state(),
                OperationMutation::transition(next),
                now,
            )
            .await
            .expect("pre-dispatch transition");
    }
    let old_token = DispatchLeaseToken::new();
    let creating = store
        .acquire_dispatch_lease(
            &tenant,
            &operation,
            snapshot.revision(),
            old_token.clone(),
            std::time::Duration::from_secs(30),
            now,
        )
        .await
        .expect("first lease");
    for mutation in [
        OperationMutation::transition(CreateOperationState::Queued),
        OperationMutation::defer_with_lease(DispatchLeaseToken::new()),
    ] {
        assert!(
            store
                .compare_and_set(
                    &tenant,
                    &operation,
                    creating.revision(),
                    creating.state(),
                    mutation,
                    now
                )
                .await
                .is_err()
        );
        assert_eq!(
            store
                .get(&tenant, &operation)
                .await
                .expect("unchanged read")
                .as_ref(),
            Some(&creating)
        );
    }
    let queued = store
        .compare_and_set(
            &tenant,
            &operation,
            creating.revision(),
            creating.state(),
            OperationMutation::defer_with_lease(old_token.clone()),
            now,
        )
        .await
        .expect("exact owner defer");
    assert_eq!(queued.state(), CreateOperationState::Queued);
    assert_eq!(queued.revision(), creating.revision() + 1);
    assert_eq!(queued.dispatch_generation(), creating.dispatch_generation());
    assert!(queued.dispatch_lease().is_none());
    assert_eq!(queued.intent(), creating.intent());
    assert_eq!(queued.request_hash(), creating.request_hash());
    store.pool().close().await;
    drop(store);

    let restarted = PostgresCreateSessionStore::connect(&database_url, 2, StoreConfig::default())
        .await
        .expect("reconnected isolated store");
    let recovered = restarted
        .get(&tenant, &operation)
        .await
        .expect("read after reconnect")
        .expect("durable queued row");
    assert_eq!(recovered, queued);
    let reserving = restarted
        .compare_and_set(
            &tenant,
            &operation,
            recovered.revision(),
            recovered.state(),
            OperationMutation::transition(CreateOperationState::Reserving),
            now,
        )
        .await
        .expect("reserve again");
    let new_token = DispatchLeaseToken::new();
    let fresh = restarted
        .acquire_dispatch_lease(
            &tenant,
            &operation,
            reserving.revision(),
            new_token.clone(),
            std::time::Duration::from_secs(30),
            now,
        )
        .await
        .expect("second dispatch generation");
    assert_eq!(
        fresh.dispatch_generation(),
        creating.dispatch_generation() + 1
    );
    assert_eq!(fresh.intent(), creating.intent());
    assert!(matches!(
        restarted
            .compare_and_set(
                &tenant,
                &operation,
                fresh.revision(),
                fresh.state(),
                OperationMutation::defer_with_lease(old_token),
                now
            )
            .await,
        Err(CoordinationError::DispatchLeaseMismatch)
    ));
    assert_eq!(
        restarted
            .get(&tenant, &operation)
            .await
            .expect("stale rejection unchanged")
            .as_ref(),
        Some(&fresh)
    );
    let final_queued = restarted
        .compare_and_set(
            &tenant,
            &operation,
            fresh.revision(),
            fresh.state(),
            OperationMutation::defer_with_lease(new_token),
            now,
        )
        .await
        .expect("new owner can defer");
    assert_eq!(final_queued.intent(), creating.intent());
    assert_eq!(
        final_queued.dispatch_generation(),
        fresh.dispatch_generation()
    );
    assert!(final_queued.dispatch_lease().is_none());
    sqlx::query("DELETE FROM browserd_create_session_operations WHERE tenant_id = $1")
        .bind(*tenant.as_uuid())
        .execute(restarted.pool())
        .await
        .expect("remove only this test tenant");
}
