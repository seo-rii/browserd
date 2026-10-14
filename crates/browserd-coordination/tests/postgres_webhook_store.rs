//! Opt-in real PostgreSQL parity in a unique schema owned by this fixture.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use browserd_coordination::*;
use browserd_core::{PrincipalId, TenantId};
use chrono::Utc;
use sqlx::SqlSafeStr;
use sqlx::postgres::PgPoolOptions;
use std::time::Duration;
use uuid::Uuid;
#[path = "support/webhook_cases.rs"]
mod cases;

async fn source(url: &str, schema: &str) -> PostgresEventOutbox {
    let path = schema.to_owned();
    let pool = PgPoolOptions::new()
        .max_connections(4)
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
        .connect(url)
        .await
        .expect("isolated webhook fixture pool");
    PostgresEventOutbox::new(pool, StoreConfig::default())
}

#[tokio::test]
async fn postgres_registry_delivery_reconnect_lost_replies_and_exact_parallel_claims() {
    let Ok(url) = std::env::var("BROWSERD_COORDINATION_TEST_DATABASE_URL") else {
        return;
    };
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("fixture schema owner");
    let schema = format!("browserd_webhook_contract_{}", Uuid::new_v4().simple());
    // The identifier is a fixed literal prefix followed by hexadecimal UUID bytes.
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")).into_sql_str())
        .execute(&admin)
        .await
        .expect("create isolated webhook schema");
    let outbox = source(&url, &schema).await;
    let store = PostgresWebhookStore::new(outbox.clone(), WebhookStoreConfig::default()).unwrap();
    store.migrate().await.unwrap();
    let tenant = TenantId::new();
    cases::registry_and_delivery_contract(&store, &outbox, &tenant, Utc::now()).await;
    let principal = PrincipalId::new();
    let current = store.get_endpoint(&tenant).await.unwrap().unwrap();
    let request = cases::put(
        &tenant,
        &principal,
        "post-restart",
        Some(current.endpoint_ref().revision()),
        "https://receiver.example/reconnected",
    );
    let saved = store.put_endpoint(request.clone()).await.unwrap();
    drop(store);
    outbox.pool().close().await;
    let reopened_source = source(&url, &schema).await;
    let reopened =
        PostgresWebhookStore::new(reopened_source.clone(), WebhookStoreConfig::default()).unwrap();
    reopened.migrate().await.unwrap();
    assert_eq!(reopened.put_endpoint(request).await.unwrap(), saved);
    cases::event(&reopened_source, &tenant, 4, Utc::now()).await;
    let (left, right) = tokio::join!(
        reopened.claim_due_attempts(
            WebhookDeliveryCursor::default(),
            16,
            4,
            Duration::from_secs(30)
        ),
        reopened.claim_due_attempts(
            WebhookDeliveryCursor::default(),
            16,
            4,
            Duration::from_secs(30)
        )
    );
    let mut leases = left.unwrap().attempts().to_vec();
    leases.extend_from_slice(right.unwrap().attempts());
    assert_eq!(leases.len(), 1);
    let lease = leases.remove(0);
    let done = reopened
        .finish_attempt(
            &lease,
            WebhookAttemptOutcome::Delivered { status_code: 200 },
        )
        .await
        .unwrap();
    drop(reopened);
    reopened_source.pool().close().await;
    let final_source = source(&url, &schema).await;
    let final_store =
        PostgresWebhookStore::new(final_source.clone(), WebhookStoreConfig::default()).unwrap();
    final_store.migrate().await.unwrap();
    assert_eq!(
        final_store
            .finish_attempt(
                &lease,
                WebhookAttemptOutcome::Delivered { status_code: 200 }
            )
            .await
            .unwrap(),
        done
    );
    assert_eq!(
        final_store
            .get_endpoint(&tenant)
            .await
            .unwrap()
            .unwrap()
            .cursor()
            .position(),
        4
    );
    let body: Vec<u8> = sqlx::query_scalar(
        "SELECT payload FROM browserd_webhook_ack_payload WHERE tenant_id=$1 AND attempt_id=$2",
    )
    .bind(tenant.as_uuid())
    .bind(lease.attempt_id())
    .fetch_one(final_source.pool())
    .await
    .unwrap();
    assert_eq!(body, lease.payload().as_bytes());
    drop(final_store);
    final_source.pool().close().await;
    sqlx::query(sqlx::AssertSqlSafe(format!("DROP SCHEMA {schema} CASCADE")).into_sql_str())
        .execute(&admin)
        .await
        .expect("remove only isolated webhook fixture schema");
    admin.close().await;
}
