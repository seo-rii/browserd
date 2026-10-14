#![allow(clippy::expect_used)]

use std::borrow::Cow;
use std::time::Duration;

use browserd_coordination::{
    CanonicalRequestHash, ClaimCreateOperation, CreateOperationResult, CreateSessionCoordination,
    DispatchLeaseToken, EventCursor, EventOperationState, EventOutbox, EventStateSummary,
    OperationMutation, OutboxEventKind, PostgresCreateSessionStore, PostgresEventOutbox,
    RecoverableCreateIntent, StoreConfig,
};
use browserd_core::{CreateOperationState, OperationId, PrincipalId, SessionId, TenantId};
use chrono::Utc;
use serde_json::json;
use sqlx::SqlSafeStr;
use sqlx::migrate::{Migration, MigrationType, Migrator};
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

async fn store() -> Option<PostgresCreateSessionStore> {
    let url = std::env::var("BROWSERD_COORDINATION_TEST_DATABASE_URL").ok()?;
    let store = PostgresCreateSessionStore::connect(&url, 4, StoreConfig::default())
        .await
        .expect("test PG");
    // The create store owns atomic operation notification installation, without a second caller.
    store
        .migrate()
        .await
        .expect("create migration includes outbox");
    Some(store)
}
fn claim(tenant: &TenantId) -> ClaimCreateOperation {
    let operation = OperationId::new();
    let now = Utc::now();
    ClaimCreateOperation::new(
        tenant.clone(),
        PrincipalId::new(),
        operation.clone(),
        "operation-events",
        CanonicalRequestHash::new([19; 32]),
        RecoverableCreateIntent::new(
            &operation,
            json!({"metadata":{"private":"must-not-appear-in-events"}}),
            now,
            now + chrono::Duration::minutes(4),
            json!({}),
        )
        .expect("intent"),
    )
    .expect("claim")
}
async fn cleanup(store: &PostgresCreateSessionStore, tenant: &TenantId) {
    sqlx::query("DELETE FROM browserd_create_session_operations WHERE tenant_id=$1")
        .bind(tenant.as_uuid())
        .execute(store.pool())
        .await
        .expect("cleanup operations");
    sqlx::query("DELETE FROM browserd_event_outbox WHERE tenant_id=$1")
        .bind(tenant.as_uuid())
        .execute(store.pool())
        .await
        .expect("cleanup events");
    sqlx::query("DELETE FROM browserd_event_outbox_cursor WHERE tenant_id=$1")
        .bind(tenant.as_uuid())
        .execute(store.pool())
        .await
        .expect("cleanup cursor");
}

#[tokio::test]
async fn postgres_operation_events_share_commit_and_ignore_lease_only_changes() {
    let Some(store) = store().await else {
        return;
    };
    let tenant = TenantId::new();
    let claim = claim(&tenant);
    let mut current = store
        .claim_create(claim.clone(), Utc::now())
        .await
        .expect("claim")
        .snapshot()
        .clone();
    assert_eq!(current.revision(), 0);
    let mut expected_revisions = vec![0];
    for state in [
        CreateOperationState::Queued,
        CreateOperationState::Reserving,
    ] {
        current = store
            .compare_and_set(
                &tenant,
                current.operation_id(),
                current.revision(),
                current.state(),
                OperationMutation::transition(state),
                Utc::now(),
            )
            .await
            .expect("state transition");
        expected_revisions.push(current.revision());
    }
    current = store
        .acquire_dispatch_lease(
            &tenant,
            current.operation_id(),
            current.revision(),
            DispatchLeaseToken::new(),
            Duration::from_millis(1),
            Utc::now(),
        )
        .await
        .expect("initial creating");
    expected_revisions.push(current.revision());
    tokio::time::sleep(Duration::from_millis(10)).await;
    let token = DispatchLeaseToken::new();
    current = store
        .acquire_dispatch_lease(
            &tenant,
            current.operation_id(),
            current.revision(),
            token.clone(),
            Duration::from_secs(30),
            Utc::now(),
        )
        .await
        .expect("reacquire creating without a state event");
    current = store
        .renew_dispatch_lease(
            &tenant,
            current.operation_id(),
            current.revision(),
            token.clone(),
            Duration::from_secs(30),
            Utc::now(),
        )
        .await
        .expect("renew without a state event");
    current = store
        .compare_and_set(
            &tenant,
            current.operation_id(),
            current.revision(),
            current.state(),
            OperationMutation::succeed_with_lease(
                token,
                CreateOperationResult::new(SessionId::new(), json!({"ready":true})),
            ),
            Utc::now(),
        )
        .await
        .expect("success");
    expected_revisions.push(current.revision());
    assert_eq!(
        store
            .claim_create(claim, Utc::now())
            .await
            .expect("lost commit response retry")
            .snapshot(),
        &current
    );
    let outbox = PostgresEventOutbox::new(store.pool().clone(), StoreConfig::default());
    let page = outbox
        .read_from(&tenant, EventCursor::start(), 20, Utc::now())
        .await
        .expect("durable events");
    let expected_states = [
        EventOperationState::Accepted,
        EventOperationState::Queued,
        EventOperationState::Reserving,
        EventOperationState::Creating,
        EventOperationState::Succeeded,
    ];
    assert_eq!(page.events().len(), expected_states.len());
    for ((event, state), revision) in page
        .events()
        .iter()
        .zip(expected_states)
        .zip(expected_revisions)
    {
        assert_eq!(event.kind(), OutboxEventKind::OperationStateChanged);
        assert_eq!(
            event.summary(),
            Some(&EventStateSummary::Operation { state })
        );
        assert_eq!(event.aggregate_revision(), revision);
        let bytes = browserd_coordination::encode_outbox_event(event).expect("safe notification");
        assert!(
            !String::from_utf8(bytes)
                .expect("JSON")
                .contains("must-not-appear")
        );
    }
    let url = std::env::var("BROWSERD_COORDINATION_TEST_DATABASE_URL").expect("configured");
    let reopened = PostgresCreateSessionStore::connect(&url, 2, StoreConfig::default())
        .await
        .expect("reopen");
    assert_eq!(
        reopened
            .get(&tenant, current.operation_id())
            .await
            .expect("read restored"),
        Some(current)
    );
    assert_eq!(
        PostgresEventOutbox::new(reopened.pool().clone(), StoreConfig::default())
            .read_from(&tenant, EventCursor::start(), 20, Utc::now())
            .await
            .expect("same event IDs after restart"),
        page
    );
    cleanup(&store, &tenant).await;
}

#[tokio::test]
async fn postgres_operation_and_outbox_rollback_together_on_sequence_exhaustion() {
    let Some(store) = store().await else {
        return;
    };
    let tenant = TenantId::new();
    let claim = claim(&tenant);
    sqlx::query("INSERT INTO browserd_event_outbox_cursor (tenant_id,next_seq) VALUES ($1,$2)")
        .bind(tenant.as_uuid())
        .bind(i64::MAX)
        .execute(store.pool())
        .await
        .expect("isolate exhausted stream");
    assert!(store.claim_create(claim.clone(), Utc::now()).await.is_err());
    assert!(
        store
            .get(&tenant, claim.operation_id())
            .await
            .expect("failed insert rolled back")
            .is_none()
    );
    sqlx::query("UPDATE browserd_event_outbox_cursor SET next_seq=0 WHERE tenant_id=$1")
        .bind(tenant.as_uuid())
        .execute(store.pool())
        .await
        .expect("restore unused fixture stream");
    let accepted = store
        .claim_create(claim, Utc::now())
        .await
        .expect("accept")
        .snapshot()
        .clone();
    sqlx::query("UPDATE browserd_event_outbox_cursor SET next_seq=$2 WHERE tenant_id=$1")
        .bind(tenant.as_uuid())
        .bind(i64::MAX)
        .execute(store.pool())
        .await
        .expect("exhaust before state CAS");
    assert!(
        store
            .compare_and_set(
                &tenant,
                accepted.operation_id(),
                0,
                CreateOperationState::Accepted,
                OperationMutation::transition(CreateOperationState::Queued),
                Utc::now()
            )
            .await
            .is_err()
    );
    assert_eq!(
        store
            .get(&tenant, accepted.operation_id())
            .await
            .expect("state remains accepted"),
        Some(accepted)
    );
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM browserd_event_outbox WHERE tenant_id=$1")
            .bind(tenant.as_uuid())
            .fetch_one(store.pool())
            .await
            .expect("no partial event");
    assert_eq!(count, 1);
    cleanup(&store, &tenant).await;
}

#[tokio::test]
async fn postgres_v3_outbox_upgrade_preserves_legacy_identity_cursor_and_projection_watermark() {
    let Ok(url) = std::env::var("BROWSERD_COORDINATION_TEST_DATABASE_URL") else {
        return;
    };
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("admin fixture pool");
    let schema = format!("browserd_event_upgrade_{}", Uuid::new_v4().simple());
    // The identifier consists only of this literal prefix and hexadecimal UUID.
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")).into_sql_str())
        .execute(&admin)
        .await
        .expect("isolated fixture schema");
    let path = schema.clone();
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .after_connect(move |connection, _| {
            let path = path.clone();
            Box::pin(async move {
                sqlx::query("SELECT set_config('search_path',$1,false)")
                    .bind(path)
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .expect("schema pool");
    let mut migrator = Migrator::with_migrations(vec![
        Migration::new(
            1,
            Cow::Borrowed("event outbox"),
            MigrationType::Simple,
            include_str!("../migrations/outbox/0001_event_outbox.sql").into_sql_str(),
            false,
        ),
        Migration::new(
            2,
            Cow::Borrowed("event projection watermark"),
            MigrationType::Simple,
            include_str!("../migrations/outbox/0002_projection_watermark.sql").into_sql_str(),
            false,
        ),
        Migration::new(
            3,
            Cow::Borrowed("viewer control projection"),
            MigrationType::Simple,
            include_str!("../migrations/outbox/0003_viewer_control_projection.sql").into_sql_str(),
            false,
        ),
    ]);
    migrator.dangerous_set_table_name("_browserd_event_outbox_migrations");
    migrator.run(&pool).await.expect("old exact checksums");
    let tenant = TenantId::new();
    let session = SessionId::new();
    let event_id = Uuid::now_v7();
    let now = Utc::now();
    sqlx::query("INSERT INTO browserd_event_outbox_cursor (tenant_id,next_seq,delivered_through) VALUES ($1,1,1)").bind(tenant.as_uuid()).execute(&pool).await.expect("legacy cursor");
    sqlx::query("INSERT INTO browserd_event_outbox (tenant_id,tenant_seq,event_id,kind,session_id,aggregate_revision,dedup_key,created_at) VALUES ($1,1,$2,'session_lost',$3,1,$4,$5)").bind(tenant.as_uuid()).bind(event_id).bind(session.as_uuid()).bind(format!("S:{session}:1:l")).bind(now).execute(&pool).await.expect("legacy event");
    sqlx::query("INSERT INTO browserd_event_projection_watermark (tenant_id,session_id,projected_through,source) VALUES ($1,$2,1,'terminal')").bind(tenant.as_uuid()).bind(session.as_uuid()).execute(&pool).await.expect("legacy watermark");
    let outbox = PostgresEventOutbox::new(pool.clone(), StoreConfig::default());
    outbox
        .migrate()
        .await
        .expect("upgrade adds only migration four");
    outbox.migrate().await.expect("repeat upgrade");
    let page = outbox
        .read_from(&tenant, EventCursor::start(), 10, now)
        .await
        .expect("legacy row readable");
    assert_eq!(page.events()[0].event_id(), event_id);
    assert!(page.events()[0].summary().is_none());
    assert_eq!(
        outbox
            .delivered_cursor(&tenant)
            .await
            .expect("delivery watermark"),
        EventCursor::from_position(1)
    );
    outbox
        .append_projection(
            browserd_coordination::GatewayEventProjection::new(
                tenant.clone(),
                session.clone(),
                1,
                browserd_coordination::OutboxAppend::session_lost(tenant.clone(), session, 1),
            )
            .expect("legacy projection"),
            now,
        )
        .await
        .expect("lost source ACK retry");
    assert_eq!(
        outbox
            .read_from(&tenant, EventCursor::start(), 10, now)
            .await
            .expect("no duplicate"),
        page
    );
    pool.close().await;
    sqlx::query(sqlx::AssertSqlSafe(format!("DROP SCHEMA {schema} CASCADE")).into_sql_str())
        .execute(&admin)
        .await
        .expect("remove isolated fixture schema");
}
