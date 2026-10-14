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

#[path = "support/event_outbox_projection.rs"]
mod projection_cases;

#[tokio::test]
async fn redis_projection_retention_gaps_parallel_and_legacy_conformance() {
    let Some(fixture) = fixture("projection").await else {
        return;
    };
    projection_cases::source_lanes_are_independent_and_survive_retention(
        fixture.store.as_ref(),
        &TenantId::new(),
    )
    .await;
    projection_cases::retry_after_retention_does_not_resurrect(
        fixture.store.as_ref(),
        &TenantId::new(),
    )
    .await;
    projection_cases::gaps_fail_without_blocking_other_sessions(
        fixture.store.as_ref(),
        &TenantId::new(),
    )
    .await;
    projection_cases::concurrent_relays_append_once(fixture.store.as_ref(), &TenantId::new()).await;
    projection_cases::normal_append_can_precede_projection(
        fixture.store.as_ref(),
        &TenantId::new(),
    )
    .await;
    cleanup(&fixture).await;
}

#[tokio::test]
async fn redis_projection_watermark_survives_payload_ttl_restart_and_legacy_writes() {
    let Some(fixture) = fixture("projection-ttl").await else {
        return;
    };
    let tenant = TenantId::new();
    let session = SessionId::new();
    let first = projection_cases::projection(&tenant, &session, 1);
    fixture
        .store
        .append_projection(first.clone(), at(0))
        .await
        .expect("first projection");
    fixture
        .store
        .append(action_terminal(&tenant, &session, 4), at(1))
        .await
        .expect("normal append");
    fixture
        .store
        .mark_delivered(&tenant, EventCursor::from_position(2))
        .await
        .expect("delivered");
    let namespace = format!("{}:event-outbox:{{{tenant}}}", fixture.prefix);
    let client = redis::Client::open(fixture.endpoint.as_str()).expect("valid endpoint");
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("connection");
    let ttl: i64 = redis::cmd("PTTL")
        .arg(format!("{namespace}:meta"))
        .query_async(&mut connection)
        .await
        .expect("meta TTL");
    assert_eq!(
        ttl, -1,
        "normal append and delivery must not expire projection watermarks"
    );
    for suffix in ["events", "index", "bytime"] {
        let _: i64 = redis::cmd("PEXPIRE")
            .arg(format!("{namespace}:{suffix}"))
            .arg(1)
            .query_async(&mut connection)
            .await
            .expect("shorten payload TTL");
    }
    tokio::time::sleep(Duration::from_millis(20)).await;
    let restarted = RedisEventOutbox::connect(fixture.config.clone())
        .await
        .expect("reconnect");
    restarted
        .append_projection(first, at(90_000))
        .await
        .expect("retry pruned projection");
    let page = restarted
        .read_from(&tenant, EventCursor::start(), 10, at(90_000))
        .await
        .expect("expired payload page");
    assert!(page.events().is_empty());
    assert!(
        page.cursor_expired(),
        "permanent cursor records the expired payload gap"
    );
    restarted
        .append_projection(
            projection_cases::projection(&tenant, &session, 2),
            at(90_001),
        )
        .await
        .expect("next projection");
    let next = restarted
        .read_from(&tenant, EventCursor::from_position(2), 10, at(90_001))
        .await
        .expect("next page");
    assert_eq!(next.events().len(), 1);
    assert_eq!(
        next.next_cursor().position(),
        3,
        "payload TTL must not reset the tenant cursor"
    );
    cleanup(&fixture).await;
}

#[tokio::test]
async fn redis_projection_sequence_is_exact_above_lua_integer_precision() {
    let Some(fixture) = fixture("projection-large-seq").await else {
        return;
    };
    let tenant = TenantId::new();
    let session = SessionId::new();
    let namespace = format!("{}:event-outbox:{{{tenant}}}", fixture.prefix);
    let client = redis::Client::open(fixture.endpoint.as_str()).expect("valid endpoint");
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("connection");
    let previous = 9_007_199_254_740_991_u64;
    let _: i64 = redis::cmd("HSET")
        .arg(format!("{namespace}:meta"))
        .arg(format!("@projection:{session}"))
        .arg(previous.to_string())
        .arg("projection_persistent")
        .arg("1")
        .query_async(&mut connection)
        .await
        .expect("seed durable highwater");
    fixture
        .store
        .append_projection(
            projection_cases::projection(&tenant, &session, previous + 2),
            at(0),
        )
        .await
        .expect_err("exact gap above f64 precision");
    for sequence in [previous + 1, previous + 2] {
        fixture
            .store
            .append_projection(
                projection_cases::projection(&tenant, &session, sequence),
                at(0),
            )
            .await
            .expect("exact contiguous sequence");
    }
    let page = fixture
        .store
        .read_from(&tenant, EventCursor::start(), 10, at(0))
        .await
        .expect("events");
    assert_eq!(page.events().len(), 2);
    cleanup(&fixture).await;
}

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

#[path = "support/event_outbox_notifications.rs"]
mod notification_cases;

#[tokio::test]
async fn redis_notifications_preserve_all_nine_typed_kinds_and_immutable_wire() {
    let Some(fixture) = fixture("notifications").await else {
        return;
    };
    let tenant = TenantId::new();
    notification_cases::all_kinds(fixture.store.as_ref(), &tenant, at(0)).await;
    let before = fixture
        .store
        .read_from(&tenant, EventCursor::start(), 20, at(0))
        .await
        .expect("before restart");
    let reopened = RedisEventOutbox::connect(fixture.config.clone())
        .await
        .expect("reopen");
    assert_eq!(
        reopened
            .read_from(&tenant, EventCursor::start(), 20, at(0))
            .await
            .expect("restored typed state"),
        before
    );
    cleanup(&fixture).await;
}
