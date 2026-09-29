//! Opt-in conformance tests for the Redis-backed event outbox (BRD-017). They early-return unless
//! `BROWSERD_REDIS_TEST_URL` points at a real Redis, and each uses a unique key prefix it deletes
//! on completion so runs never collide.
#![allow(clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::time::Duration;

use browserd_coordination::{
    EventCursor, EventOutbox, EventOutboxError, MINIMUM_EVENT_RETENTION, OutboxAggregate,
    OutboxAppend, OutboxEventKind, RedisEventOutbox, RedisEventOutboxConfig, StoreConfig,
};
use browserd_core::{ActionId, SessionId, TenantId};
use chrono::{DateTime, TimeZone, Utc};
use uuid::Uuid;

const DAY: Duration = MINIMUM_EVENT_RETENTION;

struct RedisFixture {
    config: RedisEventOutboxConfig,
    store: Arc<RedisEventOutbox>,
    endpoint: String,
    prefix: String,
}

fn at(seconds: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(1_700_000_000 + seconds, 0)
        .single()
        .expect("valid timestamp")
}

fn action_terminal(tenant: &TenantId, session: &SessionId, revision: u64) -> OutboxAppend {
    OutboxAppend::action_terminal(tenant.clone(), session.clone(), ActionId::new(), revision)
}

async fn fixture(label: &str) -> Option<RedisFixture> {
    let Ok(endpoint) = std::env::var("BROWSERD_REDIS_TEST_URL") else {
        eprintln!("skipping Redis event outbox test: BROWSERD_REDIS_TEST_URL is unset");
        return None;
    };
    let prefix = format!("browserd-event-outbox-{label}-{}", Uuid::new_v4());
    let config = RedisEventOutboxConfig::new(
        endpoint.clone(),
        prefix.clone(),
        StoreConfig::default(),
        32,
        Duration::from_secs(2),
    )
    .expect("Redis event outbox config should validate");
    let store = Arc::new(
        RedisEventOutbox::connect(config.clone())
            .await
            .expect("Redis event outbox should connect"),
    );
    Some(RedisFixture {
        config,
        store,
        endpoint,
        prefix,
    })
}

async fn cleanup(fixture: &RedisFixture) {
    let client = redis::Client::open(fixture.endpoint.as_str()).expect("endpoint should validate");
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("cleanup connection should open");
    let pattern = format!("{}:*", fixture.prefix);
    let mut cursor = 0_u64;
    let mut keys = Vec::new();
    loop {
        let (next, mut batch): (u64, Vec<String>) = redis::cmd("SCAN")
            .arg(cursor)
            .arg("MATCH")
            .arg(&pattern)
            .arg("COUNT")
            .arg(128_u16)
            .query_async(&mut connection)
            .await
            .expect("namespace should be scannable");
        keys.append(&mut batch);
        cursor = next;
        if cursor == 0 {
            break;
        }
    }
    if !keys.is_empty() {
        let mut command = redis::cmd("DEL");
        for key in keys {
            command.arg(key);
        }
        let _: i64 = command
            .query_async(&mut connection)
            .await
            .expect("namespace should be deletable");
    }
}

#[tokio::test]
async fn redis_appends_are_ordered_idempotent_and_isolated() {
    let Some(fixture) = fixture("append").await else {
        return;
    };
    let store = &fixture.store;
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
    let other_tenant = store
        .append(action_terminal(&tenant_b, &session, 3), at(2))
        .await
        .expect("other tenant append");
    assert_eq!(first.cursor().position(), 1);
    assert_eq!(second.cursor().position(), 2);
    assert_eq!(other_tenant.cursor().position(), 1);
    assert_eq!(first.kind(), OutboxEventKind::ActionTerminal);

    // A re-driven terminal commit (same aggregate, revision, kind) returns the recorded event.
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

    cleanup(&fixture).await;
}

#[tokio::test]
async fn redis_read_resumes_by_cursor_and_by_event_id() {
    let Some(fixture) = fixture("read").await else {
        return;
    };
    let store = &fixture.store;
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

    // Bounded page by cursor, then resume with no overlap.
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

    // Resume by a known event id, then by an unknown one (recover from oldest, flag the gap).
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

    cleanup(&fixture).await;
}

#[tokio::test]
async fn redis_delivery_watermark_advances_and_rejects_running_ahead() {
    let Some(fixture) = fixture("delivery").await else {
        return;
    };
    let store = &fixture.store;
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
    // A stale ack never rewinds.
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
    // Acknowledging beyond the recorded stream is rejected.
    assert_eq!(
        store
            .mark_delivered(&tenant, EventCursor::from_position(9))
            .await,
        Err(EventOutboxError::DeliveryCursorAhead)
    );

    cleanup(&fixture).await;
}

#[tokio::test]
async fn redis_outbox_survives_a_store_restart() {
    let Some(fixture) = fixture("restart").await else {
        return;
    };
    let tenant = TenantId::new();
    let session = SessionId::new();
    let recorded = fixture
        .store
        .append(action_terminal(&tenant, &session, 5), at(0))
        .await
        .expect("append before restart");

    // A restarted gateway: a fresh store instance over the same Redis namespace.
    let restarted = RedisEventOutbox::connect(fixture.config.clone())
        .await
        .expect("reconnect should succeed");
    let page = restarted
        .read_from(&tenant, EventCursor::start(), 10, at(1))
        .await
        .expect("read after restart");
    assert_eq!(page.events().len(), 1);
    assert_eq!(page.events()[0].event_id(), recorded.event_id());
    assert_eq!(page.events()[0].aggregate_revision(), 5);

    cleanup(&fixture).await;
}

#[tokio::test]
async fn redis_retention_prunes_aged_events_and_reports_the_gap() {
    let Some(fixture) = fixture("retention").await else {
        return;
    };
    let store = &fixture.store;
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

    // A day later, a new event ages the earlier pair out of retention on the next touch.
    let later_seconds = DAY.as_secs() as i64 + 10;
    let later = store
        .append(action_terminal(&tenant, &session, 3), at(later_seconds))
        .await
        .expect("later");
    assert_eq!(later.cursor().position(), 3);

    // A consumer resuming from the start is told it missed the pruned prefix and gets the tail.
    let page = store
        .read_from(&tenant, EventCursor::start(), 10, at(later_seconds))
        .await
        .expect("page after prune");
    assert!(page.cursor_expired());
    assert_eq!(page.events().len(), 1);
    assert_eq!(page.events()[0].cursor().position(), 3);

    cleanup(&fixture).await;
}
