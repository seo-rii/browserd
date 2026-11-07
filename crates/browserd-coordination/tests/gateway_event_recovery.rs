#![allow(clippy::expect_used)]

use browserd_actions::{ActionKind, CanonicalRequestHash};
use browserd_coordination::{
    ClaimGatewayAction, DirectoryFence, GatewayActionCoordination, GatewayActionPlacement,
    GatewayEventScanCursor, MemoryCoordinationDatabase, MemoryGatewayActionStore, SessionLossClaim,
    StoreConfig,
};
use browserd_core::{ActionId, SessionId, TenantId, WorkerId};
use chrono::Utc;
use uuid::Uuid;

fn placement() -> GatewayActionPlacement {
    GatewayActionPlacement::new(
        DirectoryFence::new(WorkerId::new("event-recovery").expect("worker"), 1, 1, 1)
            .expect("fence"),
        1,
    )
    .expect("placement")
}

#[tokio::test]
async fn terminal_intents_survive_store_reattachment_and_ack_only_the_exact_head() {
    let database = MemoryCoordinationDatabase::default();
    let store = MemoryGatewayActionStore::attach(database.clone(), StoreConfig::default());
    let tenant = TenantId::new();
    let session = SessionId::new();
    let placement = placement();
    for key in ["first", "second"] {
        let action = ActionId::new();
        let claimed = store
            .claim_action(
                ClaimGatewayAction::new(
                    tenant.clone(),
                    session.clone(),
                    action.clone(),
                    key,
                    CanonicalRequestHash::new([1; 32]),
                    ActionKind::ReadOnly,
                    placement.clone(),
                )
                .expect("claim"),
                Utc::now(),
            )
            .await
            .expect("claim action")
            .into_snapshot();
        store
            .cancel_before_dispatch(
                &tenant,
                &session,
                &action,
                claimed.revision(),
                &placement,
                Utc::now(),
            )
            .await
            .expect("cancel");
    }
    let restarted = MemoryGatewayActionStore::attach(database, StoreConfig::default());
    let page = restarted
        .scan_event_sessions(GatewayEventScanCursor::default(), 1)
        .await
        .expect("discover");
    assert_eq!(page.sessions().len(), 1);
    assert_eq!(page.sessions()[0].session_id(), &session);
    let first = restarted
        .peek_event_projection(&tenant, &session)
        .await
        .expect("peek")
        .expect("first intent");
    assert_eq!(first.sequence(), 1);
    restarted
        .ack_event_projection(&first)
        .await
        .expect("ack first");
    let second = restarted
        .peek_event_projection(&tenant, &session)
        .await
        .expect("peek")
        .expect("second intent");
    assert_eq!(second.sequence(), 2);
    restarted
        .ack_event_projection(&first)
        .await
        .expect("idempotent stale ack");
    assert_eq!(
        restarted
            .peek_event_projection(&tenant, &session)
            .await
            .expect("peek"),
        Some(second.clone())
    );
    restarted
        .ack_event_projection(&second)
        .await
        .expect("ack second");
    assert!(
        restarted
            .scan_event_sessions(GatewayEventScanCursor::default(), 1)
            .await
            .expect("scan empty")
            .sessions()
            .is_empty()
    );
}

#[tokio::test]
async fn loss_fence_remains_discoverable_until_all_action_events_are_materialized() {
    let store = MemoryGatewayActionStore::default();
    let tenant = TenantId::new();
    let session = SessionId::new();
    let placement = placement();
    for index in 0..3 {
        store
            .claim_action(
                ClaimGatewayAction::new(
                    tenant.clone(),
                    session.clone(),
                    ActionId::new(),
                    format!("loss-{index}"),
                    CanonicalRequestHash::new([1; 32]),
                    ActionKind::ReadOnly,
                    placement.clone(),
                )
                .expect("claim"),
                Utc::now(),
            )
            .await
            .expect("claim action");
    }
    let loss = SessionLossClaim::new(tenant.clone(), session.clone(), placement, Uuid::now_v7());
    store
        .mark_session_lost(&loss, Utc::now())
        .await
        .expect("record loss");
    let event = store
        .peek_event_projection(&tenant, &session)
        .await
        .expect("peek")
        .expect("loss event");
    store
        .ack_event_projection(&event)
        .await
        .expect("ack loss event");
    let page = store
        .scan_event_sessions(GatewayEventScanCursor::default(), 1)
        .await
        .expect("scan");
    assert_eq!(page.sessions()[0].loss_claim(), Some(&loss));
    for expected_sequence in 2..=4 {
        assert_eq!(
            store
                .materialize_session_loss(&loss, 1, Utc::now())
                .await
                .expect("materialize"),
            1
        );
        let event = store
            .peek_event_projection(&tenant, &session)
            .await
            .expect("peek")
            .expect("materialized event");
        assert_eq!(event.sequence(), expected_sequence);
        store
            .ack_event_projection(&event)
            .await
            .expect("ack materialization");
    }
    assert!(
        store
            .scan_event_sessions(GatewayEventScanCursor::default(), 1)
            .await
            .expect("finished")
            .sessions()
            .is_empty()
    );
}
