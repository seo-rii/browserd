use browserd_coordination::{
    EventCursor, EventOutbox, EventOutboxError, EventProjectionSource, GatewayEventProjection,
    OutboxAppend, OutboxEventKind,
};
use browserd_core::{ActionId, SessionId, TenantId};
use chrono::{DateTime, TimeZone, Utc};

fn at(seconds: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(1_700_000_000 + seconds, 0)
        .single()
        .expect("valid timestamp")
}

pub async fn source_lanes_are_independent_and_survive_retention(
    store: &dyn EventOutbox,
    tenant: &TenantId,
) {
    let session = SessionId::new();
    let terminal = projection(tenant, &session, 1);
    let control = |sequence| {
        GatewayEventProjection::new_with_source(
            EventProjectionSource::ViewerControl,
            tenant.clone(),
            session.clone(),
            sequence,
            OutboxAppend::control_changed(tenant.clone(), session.clone(), sequence),
        )
        .expect("control projection")
    };
    store
        .append_projection(terminal.clone(), at(0))
        .await
        .expect("terminal source seq1");
    store
        .append_projection(control(1), at(1))
        .await
        .expect("control source seq1");
    assert_eq!(
        store.append_projection(control(3), at(2)).await,
        Err(EventOutboxError::ProjectionGap)
    );
    store
        .append_projection(projection(tenant, &session, 2), at(3))
        .await
        .expect("terminal source seq2");
    store
        .append_projection(control(2), at(4))
        .await
        .expect("control source seq2");
    let events = store
        .read_from(tenant, EventCursor::start(), 10, at(5))
        .await
        .expect("events");
    assert_eq!(
        events
            .events()
            .iter()
            .map(|event| event.kind())
            .collect::<Vec<_>>(),
        vec![
            OutboxEventKind::ActionTerminal,
            OutboxEventKind::ControlChanged,
            OutboxEventKind::ActionTerminal,
            OutboxEventKind::ControlChanged
        ]
    );
    store
        .read_from(tenant, EventCursor::start(), 10, at(90_000))
        .await
        .expect("prune");
    store
        .append_projection(terminal, at(90_001))
        .await
        .expect("terminal retained watermark");
    store
        .append_projection(control(1), at(90_001))
        .await
        .expect("control retained watermark");
    assert!(
        store
            .read_from(tenant, EventCursor::start(), 10, at(90_002))
            .await
            .expect("no resurrection")
            .events()
            .is_empty()
    );
    store
        .append_projection(control(3), at(90_003))
        .await
        .expect("next control after pruning");
}

pub fn projection(tenant: &TenantId, session: &SessionId, sequence: u64) -> GatewayEventProjection {
    GatewayEventProjection::new(
        tenant.clone(),
        session.clone(),
        sequence,
        OutboxAppend::action_terminal(tenant.clone(), session.clone(), ActionId::new(), 3),
    )
    .expect("projection should validate")
}

pub async fn retry_after_retention_does_not_resurrect(store: &dyn EventOutbox, tenant: &TenantId) {
    let session = SessionId::new();
    let first = projection(tenant, &session, 1);
    // Simulate a lost post-commit reply by retaining the source intent and retrying later.
    store
        .append_projection(first.clone(), at(0))
        .await
        .expect("initial projection");
    let first_page = store
        .read_from(tenant, EventCursor::start(), 10, at(0))
        .await
        .expect("first page");
    assert_eq!(first_page.events().len(), 1);
    let first_id = first_page.events()[0].event_id();
    store
        .append_projection(first.clone(), at(1))
        .await
        .expect("exact retry");
    let retried = store
        .read_from(tenant, EventCursor::start(), 10, at(1))
        .await
        .expect("retried page");
    assert_eq!(retried.events()[0].event_id(), first_id);
    let pruned = store
        .read_from(tenant, EventCursor::start(), 10, at(90_000))
        .await
        .expect("prune");
    assert!(pruned.events().is_empty());
    assert!(pruned.cursor_expired());
    store
        .append_projection(first, at(90_001))
        .await
        .expect("retry after source ack loss and pruning");
    let empty = store
        .read_from(tenant, EventCursor::start(), 10, at(90_001))
        .await
        .expect("pruned retry page");
    assert!(
        empty.events().is_empty(),
        "pruned projection must not become a new event"
    );
    assert!(empty.cursor_expired());
    store
        .append_projection(projection(tenant, &session, 2), at(90_002))
        .await
        .expect("next projection");
    let next = store
        .read_from(tenant, EventCursor::from_position(1), 10, at(90_002))
        .await
        .expect("next page");
    assert_eq!(next.events().len(), 1);
    assert_eq!(next.events()[0].cursor().position(), 2);
}

pub async fn gaps_fail_without_blocking_other_sessions(store: &dyn EventOutbox, tenant: &TenantId) {
    let session_a = SessionId::new();
    let session_b = SessionId::new();
    let second_a = projection(tenant, &session_a, 2);
    assert_eq!(
        store.append_projection(second_a.clone(), at(0)).await,
        Err(EventOutboxError::ProjectionGap)
    );
    store
        .append_projection(projection(tenant, &session_b, 1), at(1))
        .await
        .expect("independent session");
    store
        .append_projection(projection(tenant, &session_a, 1), at(2))
        .await
        .expect("missing predecessor");
    store
        .append_projection(second_a, at(3))
        .await
        .expect("ordered retry after predecessor");
    let page = store
        .read_from(tenant, EventCursor::start(), 10, at(3))
        .await
        .expect("ordered page");
    assert_eq!(page.events().len(), 3);
    assert_eq!(page.next_cursor().position(), 3);
    assert!(matches!(page.events()[0].aggregate(),
        browserd_coordination::OutboxAggregate::Action { session_id, .. } if session_id == &session_b));
}

pub async fn concurrent_relays_append_once(store: &dyn EventOutbox, tenant: &TenantId) {
    let session = SessionId::new();
    let first = projection(tenant, &session, 1);
    let (a, b, c) = tokio::join!(
        store.append_projection(first.clone(), at(0)),
        store.append_projection(first.clone(), at(0)),
        store.append_projection(first, at(0)),
    );
    a.expect("first relay");
    b.expect("second relay");
    c.expect("third relay");
    let page = store
        .read_from(tenant, EventCursor::start(), 10, at(1))
        .await
        .expect("single event");
    assert_eq!(page.events().len(), 1);
    assert_eq!(page.next_cursor().position(), 1);
}

pub async fn normal_append_can_precede_projection(store: &dyn EventOutbox, tenant: &TenantId) {
    let session = SessionId::new();
    let projected = projection(tenant, &session, 1);
    let initial = store
        .append(projected.append().clone(), at(0))
        .await
        .expect("legacy append");
    store
        .append_projection(projected.clone(), at(1))
        .await
        .expect("project existing append");
    let page = store
        .read_from(tenant, EventCursor::start(), 10, at(1))
        .await
        .expect("one event");
    assert_eq!(page.events(), &[initial]);
    // The dedup hit still commits the projection watermark, so it survives the legacy entry.
    store
        .read_from(tenant, EventCursor::start(), 10, at(90_000))
        .await
        .expect("prune legacy entry");
    store
        .append_projection(projected, at(90_001))
        .await
        .expect("old source retry");
    assert!(
        store
            .read_from(tenant, EventCursor::start(), 10, at(90_001))
            .await
            .expect("no resurrection")
            .events()
            .is_empty()
    );
}
