//! Behavioral tests for the durable event outbox substrate (BRD-017): ordered per-tenant
//! sequencing, idempotent append under re-drive, bounded cursor paging, retention pruning with
//! gap detection (`cursor_expired`), and the at-least-once delivery watermark.
#![allow(clippy::expect_used)]

use std::time::Duration;

use browserd_coordination::{
    EventCursor, EventOutbox, EventOutboxError, MAX_EVENT_PAGE_LIMIT, MemoryEventOutbox,
    OutboxAppend, OutboxEventKind,
};
use browserd_core::{ActionId, SessionId, TenantId};
use chrono::{DateTime, TimeZone, Utc};

const DAY: Duration = Duration::from_secs(24 * 60 * 60);

fn at(seconds: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(1_700_000_000 + seconds, 0)
        .single()
        .expect("valid timestamp")
}

fn action_terminal(
    tenant: &TenantId,
    session: &SessionId,
    revision: u64,
) -> (OutboxAppend, ActionId) {
    let action = ActionId::new();
    let append =
        OutboxAppend::action_terminal(tenant.clone(), session.clone(), action.clone(), revision);
    (append, action)
}

#[tokio::test]
async fn appends_assign_gapless_per_tenant_sequences_and_isolate_tenants() {
    let outbox = MemoryEventOutbox::default();
    let tenant_a = TenantId::new();
    let tenant_b = TenantId::new();
    let session = SessionId::new();

    let (first_a, _) = action_terminal(&tenant_a, &session, 3);
    let (second_a, _) = action_terminal(&tenant_a, &session, 4);
    let (first_b, _) = action_terminal(&tenant_b, &session, 3);

    let first_a = outbox.append(first_a, at(0)).await.expect("append a1");
    let second_a = outbox.append(second_a, at(1)).await.expect("append a2");
    let first_b = outbox.append(first_b, at(2)).await.expect("append b1");

    // Each tenant's stream is sequenced independently from 1.
    assert_eq!(first_a.cursor().position(), 1);
    assert_eq!(second_a.cursor().position(), 2);
    assert_eq!(first_b.cursor().position(), 1);
    // Distinct events carry distinct, time-ordered delivery identities.
    assert_ne!(first_a.event_id(), second_a.event_id());
    assert_eq!(first_a.aggregate_revision(), 3);
    assert_eq!(second_a.kind(), OutboxEventKind::ActionTerminal);
}

#[tokio::test]
async fn append_is_idempotent_on_aggregate_revision_and_kind() {
    let outbox = MemoryEventOutbox::default();
    let tenant = TenantId::new();
    let session = SessionId::new();
    let action = ActionId::new();

    let append = OutboxAppend::action_terminal(tenant.clone(), session.clone(), action.clone(), 7);
    let first = outbox
        .append(append.clone(), at(0))
        .await
        .expect("first append");

    // A re-driven terminal commit (same aggregate, revision, kind) returns the recorded event
    // unchanged rather than minting a second one: duplicate delivery, no duplicate effect.
    let redriven = outbox
        .append(append, at(5))
        .await
        .expect("re-driven append");
    assert_eq!(redriven, first);

    // An unrelated action appended afterwards still gets the very next sequence, proving the
    // re-drive consumed no sequence.
    let (other, _) = action_terminal(&tenant, &session, 8);
    let other = outbox.append(other, at(6)).await.expect("other append");
    assert_eq!(other.cursor().position(), 2);
}

#[tokio::test]
async fn read_from_resumes_strictly_after_cursor_with_bounded_pages() {
    let outbox = MemoryEventOutbox::default();
    let tenant = TenantId::new();
    let session = SessionId::new();

    for revision in 0..5u64 {
        let (append, _) = action_terminal(&tenant, &session, revision);
        outbox
            .append(append, at(revision as i64))
            .await
            .expect("append");
    }

    let page = outbox
        .read_from(&tenant, EventCursor::start(), 2, at(100))
        .await
        .expect("first page");
    assert_eq!(page.events().len(), 2);
    assert_eq!(page.events()[0].cursor().position(), 1);
    assert_eq!(page.events()[1].cursor().position(), 2);
    assert_eq!(page.next_cursor().position(), 2);
    assert!(!page.cursor_expired());

    // Resuming from the returned cursor yields the next slice with no overlap and no gap.
    let page = outbox
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
    assert_eq!(page.next_cursor().position(), 5);

    // Draining to the head leaves an empty page whose cursor does not move.
    let tail = outbox
        .read_from(&tenant, page.next_cursor(), 10, at(100))
        .await
        .expect("tail page");
    assert!(tail.events().is_empty());
    assert_eq!(tail.next_cursor().position(), 5);
    assert!(!tail.cursor_expired());
}

#[tokio::test]
async fn read_from_reports_cursor_expired_when_prefix_pruned() {
    let outbox = MemoryEventOutbox::new(DAY).expect("outbox");
    let tenant = TenantId::new();
    let session = SessionId::new();

    // Two early events, then one a full day later. Reading after the day prunes the early prefix.
    let (early_one, _) = action_terminal(&tenant, &session, 1);
    let (early_two, _) = action_terminal(&tenant, &session, 2);
    outbox.append(early_one, at(0)).await.expect("early one");
    outbox.append(early_two, at(1)).await.expect("early two");

    let (later, _) = action_terminal(&tenant, &session, 3);
    let later_seconds = DAY.as_secs() as i64 + 10;
    let later = outbox
        .append(later, at(later_seconds))
        .await
        .expect("later");
    assert_eq!(later.cursor().position(), 3);

    // A consumer resuming from the start has missed the pruned prefix: it is told so, and still
    // receives the surviving tail so it can reconcile forward.
    let page = outbox
        .read_from(&tenant, EventCursor::start(), 10, at(later_seconds))
        .await
        .expect("page after prune");
    assert!(page.cursor_expired());
    assert_eq!(page.events().len(), 1);
    assert_eq!(page.events()[0].cursor().position(), 3);

    // A consumer already past the pruned prefix sees no gap.
    let page = outbox
        .read_from(
            &tenant,
            EventCursor::from_position(2),
            10,
            at(later_seconds),
        )
        .await
        .expect("page past prune");
    assert!(!page.cursor_expired());
    assert_eq!(page.events().len(), 1);
}

#[tokio::test]
async fn delivery_watermark_advances_monotonically_and_rejects_running_ahead() {
    let outbox = MemoryEventOutbox::default();
    let tenant = TenantId::new();
    let session = SessionId::new();

    for revision in 0..3u64 {
        let (append, _) = action_terminal(&tenant, &session, revision);
        outbox
            .append(append, at(revision as i64))
            .await
            .expect("append");
    }

    // Nothing acknowledged yet.
    assert_eq!(
        outbox.delivered_cursor(&tenant).await.expect("initial"),
        EventCursor::start()
    );

    outbox
        .mark_delivered(&tenant, EventCursor::from_position(2))
        .await
        .expect("ack through 2");
    assert_eq!(
        outbox
            .delivered_cursor(&tenant)
            .await
            .expect("after ack")
            .position(),
        2
    );

    // A stale acknowledgement never rewinds the watermark.
    outbox
        .mark_delivered(&tenant, EventCursor::from_position(1))
        .await
        .expect("stale ack");
    assert_eq!(
        outbox
            .delivered_cursor(&tenant)
            .await
            .expect("after stale")
            .position(),
        2
    );

    // Acknowledging beyond the recorded stream is rejected as corrupt caller state.
    let ahead = outbox
        .mark_delivered(&tenant, EventCursor::from_position(9))
        .await;
    assert_eq!(ahead, Err(EventOutboxError::DeliveryCursorAhead));
}

#[tokio::test]
async fn read_from_validates_page_limit_and_unknown_tenant_is_empty() {
    let outbox = MemoryEventOutbox::default();
    let tenant = TenantId::new();

    assert_eq!(
        outbox
            .read_from(&tenant, EventCursor::start(), 0, at(0))
            .await,
        Err(EventOutboxError::InvalidPageLimit)
    );
    assert_eq!(
        outbox
            .read_from(
                &tenant,
                EventCursor::start(),
                MAX_EVENT_PAGE_LIMIT + 1,
                at(0)
            )
            .await,
        Err(EventOutboxError::InvalidPageLimit)
    );

    // A tenant with no recorded events yields an empty, non-expired page anchored at the request.
    let page = outbox
        .read_from(&tenant, EventCursor::from_position(3), 10, at(0))
        .await
        .expect("unknown tenant");
    assert!(page.events().is_empty());
    assert!(!page.cursor_expired());
    assert_eq!(page.next_cursor().position(), 3);
}

#[tokio::test]
async fn session_lost_and_action_terminal_are_distinct_aggregates() {
    let outbox = MemoryEventOutbox::default();
    let tenant = TenantId::new();
    let session = SessionId::new();

    let action = OutboxAppend::action_terminal(tenant.clone(), session.clone(), ActionId::new(), 1);
    let lost = OutboxAppend::session_lost(tenant.clone(), session.clone(), 2);

    let action_event = outbox.append(action, at(0)).await.expect("action terminal");
    let lost_event = outbox.append(lost, at(1)).await.expect("session lost");

    assert_eq!(action_event.kind(), OutboxEventKind::ActionTerminal);
    assert_eq!(lost_event.kind(), OutboxEventKind::SessionLost);
    assert_eq!(action_event.cursor().position(), 1);
    assert_eq!(lost_event.cursor().position(), 2);
}
