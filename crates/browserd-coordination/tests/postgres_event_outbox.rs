//! Opt-in conformance tests for the Postgres-backed event outbox (BRD-017 / BRD-003). They
//! early-return unless `BROWSERD_COORDINATION_TEST_DATABASE_URL` points at a real Postgres, use a
//! fresh tenant id per case, and delete their rows on completion.
#![allow(clippy::expect_used, clippy::panic)]

use std::time::Duration;

use browserd_coordination::{
    EventCursor, EventOutbox, EventOutboxError, MINIMUM_EVENT_RETENTION, OutboxAggregate,
    OutboxAppend, OutboxEventKind, PostgresEventOutbox, StoreConfig,
};
use browserd_core::{ActionId, SessionId, TenantId};
use chrono::{DateTime, TimeZone, Utc};
use uuid::Uuid;

const DAY: Duration = MINIMUM_EVENT_RETENTION;

fn at(seconds: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(1_700_000_000 + seconds, 0)
        .single()
        .expect("valid timestamp")
}

fn action_terminal(tenant: &TenantId, session: &SessionId, revision: u64) -> OutboxAppend {
    OutboxAppend::action_terminal(tenant.clone(), session.clone(), ActionId::new(), revision)
}

async fn setup() -> Option<PostgresEventOutbox> {
    let Ok(database_url) = std::env::var("BROWSERD_COORDINATION_TEST_DATABASE_URL") else {
        eprintln!(
            "skipping Postgres event outbox test: BROWSERD_COORDINATION_TEST_DATABASE_URL is unset"
        );
        return None;
    };
    let store = PostgresEventOutbox::connect(&database_url, 4, StoreConfig::default())
        .await
        .expect("test Postgres should be reachable");
    store.migrate().await.expect("migration should succeed");
    Some(store)
}

async fn cleanup(store: &PostgresEventOutbox, tenant: &TenantId) {
    sqlx::query("DELETE FROM browserd_event_outbox WHERE tenant_id = $1")
        .bind(tenant.as_uuid())
        .execute(store.pool())
        .await
        .expect("event rows should be deletable");
    sqlx::query("DELETE FROM browserd_event_outbox_cursor WHERE tenant_id = $1")
        .bind(tenant.as_uuid())
        .execute(store.pool())
        .await
        .expect("cursor row should be deletable");
}

#[tokio::test]
async fn postgres_appends_are_ordered_idempotent_and_isolated() {
    let Some(store) = setup().await else {
        return;
    };
    let tenant_a = TenantId::new();
    let tenant_b = TenantId::new();
    let session = SessionId::new();

    let first = store
        .append(action_terminal(&tenant_a, &session, 3), at(0))
        .await
        .expect("first append");
    let second = store
        .append(action_terminal(&tenant_a, &session, 4), at(1))
        .await
        .expect("second append");
    let other = store
        .append(action_terminal(&tenant_b, &session, 3), at(2))
        .await
        .expect("other tenant append");
    assert_eq!(first.cursor().position(), 1);
    assert_eq!(second.cursor().position(), 2);
    assert_eq!(other.cursor().position(), 1);
    assert_eq!(first.kind(), OutboxEventKind::ActionTerminal);

    // A re-driven terminal commit returns the recorded event, consuming no sequence.
    let action = ActionId::new();
    let append =
        OutboxAppend::action_terminal(tenant_a.clone(), session.clone(), action.clone(), 9);
    let recorded = store.append(append.clone(), at(3)).await.expect("append");
    let redriven = store.append(append, at(7)).await.expect("re-driven append");
    assert_eq!(redriven, recorded);
    assert_eq!(recorded.cursor().position(), 3);
    match recorded.aggregate() {
        OutboxAggregate::Action { action_id, .. } => assert_eq!(action_id, &action),
        other => panic!("unexpected aggregate: {other:?}"),
    }

    cleanup(&store, &tenant_a).await;
    cleanup(&store, &tenant_b).await;
}

#[tokio::test]
async fn postgres_session_lost_is_a_distinct_aggregate() {
    let Some(store) = setup().await else {
        return;
    };
    let tenant = TenantId::new();
    let session = SessionId::new();

    let action = store
        .append(action_terminal(&tenant, &session, 1), at(0))
        .await
        .expect("action terminal");
    let lost = store
        .append(
            OutboxAppend::session_lost(tenant.clone(), session.clone(), 2),
            at(1),
        )
        .await
        .expect("session lost");
    assert_eq!(action.kind(), OutboxEventKind::ActionTerminal);
    assert_eq!(lost.kind(), OutboxEventKind::SessionLost);
    assert_eq!(lost.cursor().position(), 2);
    match lost.aggregate() {
        OutboxAggregate::Session { session_id } => assert_eq!(session_id, &session),
        other => panic!("unexpected aggregate: {other:?}"),
    }

    cleanup(&store, &tenant).await;
}

#[tokio::test]
async fn postgres_read_resumes_by_cursor_and_by_event_id() {
    let Some(store) = setup().await else {
        return;
    };
    let tenant = TenantId::new();
    let session = SessionId::new();

    let mut ids = Vec::new();
    for revision in 0..5u64 {
        let event = store
            .append(
                action_terminal(&tenant, &session, revision),
                at(revision as i64),
            )
            .await
            .expect("append");
        ids.push(event.event_id());
    }

    let page = store
        .read_from(&tenant, EventCursor::start(), 2, at(100))
        .await
        .expect("first page");
    assert_eq!(
        page.events()
            .iter()
            .map(|event| event.cursor().position())
            .collect::<Vec<_>>(),
        vec![1, 2]
    );
    assert!(!page.cursor_expired());
    let page = store
        .read_from(&tenant, page.next_cursor(), 10, at(100))
        .await
        .expect("second page");
    assert_eq!(
        page.events()
            .iter()
            .map(|event| event.cursor().position())
            .collect::<Vec<_>>(),
        vec![3, 4, 5]
    );

    let page = store
        .read_after_event_id(&tenant, Some(ids[1]), 10, at(100))
        .await
        .expect("after known id");
    assert_eq!(
        page.events()
            .iter()
            .map(|event| event.cursor().position())
            .collect::<Vec<_>>(),
        vec![3, 4, 5]
    );
    assert!(!page.cursor_expired());

    let page = store
        .read_after_event_id(&tenant, Some(Uuid::now_v7()), 10, at(100))
        .await
        .expect("after unknown id");
    assert!(page.cursor_expired());
    assert_eq!(page.events().len(), 5);

    cleanup(&store, &tenant).await;
}

#[tokio::test]
async fn postgres_delivery_watermark_advances_and_rejects_running_ahead() {
    let Some(store) = setup().await else {
        return;
    };
    let tenant = TenantId::new();
    let session = SessionId::new();

    for revision in 0..3u64 {
        store
            .append(
                action_terminal(&tenant, &session, revision),
                at(revision as i64),
            )
            .await
            .expect("append");
    }

    assert_eq!(
        store.delivered_cursor(&tenant).await.expect("initial"),
        EventCursor::start()
    );
    store
        .mark_delivered(&tenant, EventCursor::from_position(2))
        .await
        .expect("ack through 2");
    assert_eq!(
        store
            .delivered_cursor(&tenant)
            .await
            .expect("after ack")
            .position(),
        2
    );
    store
        .mark_delivered(&tenant, EventCursor::from_position(1))
        .await
        .expect("stale ack");
    assert_eq!(
        store
            .delivered_cursor(&tenant)
            .await
            .expect("after stale")
            .position(),
        2
    );
    assert_eq!(
        store
            .mark_delivered(&tenant, EventCursor::from_position(9))
            .await,
        Err(EventOutboxError::DeliveryCursorAhead)
    );

    cleanup(&store, &tenant).await;
}

#[tokio::test]
async fn postgres_outbox_survives_a_store_restart() {
    let Some(store) = setup().await else {
        return;
    };
    let database_url =
        std::env::var("BROWSERD_COORDINATION_TEST_DATABASE_URL").expect("URL was present in setup");
    let tenant = TenantId::new();
    let session = SessionId::new();
    let recorded = store
        .append(action_terminal(&tenant, &session, 5), at(0))
        .await
        .expect("append before restart");

    // A restarted gateway: a fresh store over the same database.
    let restarted = PostgresEventOutbox::connect(&database_url, 2, StoreConfig::default())
        .await
        .expect("reconnect should succeed");
    let page = restarted
        .read_from(&tenant, EventCursor::start(), 10, at(1))
        .await
        .expect("read after restart");
    assert_eq!(page.events().len(), 1);
    assert_eq!(page.events()[0].event_id(), recorded.event_id());
    assert_eq!(page.events()[0].aggregate_revision(), 5);

    cleanup(&store, &tenant).await;
}

#[tokio::test]
async fn postgres_retention_prunes_aged_events_and_reports_the_gap() {
    let Some(store) = setup().await else {
        return;
    };
    let tenant = TenantId::new();
    let session = SessionId::new();

    store
        .append(action_terminal(&tenant, &session, 1), at(0))
        .await
        .expect("early one");
    store
        .append(action_terminal(&tenant, &session, 2), at(1))
        .await
        .expect("early two");

    let later_seconds = DAY.as_secs() as i64 + 10;
    let later = store
        .append(action_terminal(&tenant, &session, 3), at(later_seconds))
        .await
        .expect("later");
    assert_eq!(later.cursor().position(), 3);

    let page = store
        .read_from(&tenant, EventCursor::start(), 10, at(later_seconds))
        .await
        .expect("page after prune");
    assert!(page.cursor_expired());
    assert_eq!(page.events().len(), 1);
    assert_eq!(page.events()[0].cursor().position(), 3);

    cleanup(&store, &tenant).await;
}
