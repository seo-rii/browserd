#![allow(clippy::expect_used)]
use browserd_actions::{ActionKind, CanonicalRequestHash};
use browserd_coordination::{
    ClaimGatewayAction, DirectoryFence, GatewayActionCoordination,
    GatewayActionCoordinationError as Error, GatewayActionPlacement,
    GatewayDirectoryLifecycle as Phase, GatewaySessionDirectoryRecord as Record,
    GatewaySessionIsolation as Isolation, MemoryCoordinationDatabase, MemoryGatewayActionStore,
    StoreConfig,
};
use browserd_core::{ActionId, SessionId, TenantId, WorkerId};
use chrono::Utc;
use std::collections::BTreeMap;

fn record(tenant: TenantId, session: SessionId, epoch: u64) -> Record {
    Record::new(
        tenant,
        session,
        GatewayActionPlacement::new(
            DirectoryFence::new(
                WorkerId::new("durable-directory-worker").expect("worker"),
                epoch,
                3,
                1,
            )
            .expect("fence"),
            7,
        )
        .expect("placement"),
        Phase::Ready,
        Isolation::DedicatedProcess,
        Isolation::DedicatedProcess,
        BTreeMap::new(),
    )
    .expect("record")
}

#[tokio::test]
async fn replaced_store_recovers_exact_owner_and_idempotency_mapping() {
    let database = MemoryCoordinationDatabase::default();
    let store = MemoryGatewayActionStore::attach(database.clone(), StoreConfig::default());
    let original = record(TenantId::new(), SessionId::new(), 9);
    assert_eq!(
        store
            .commit_single_host_directory(original.clone(), None)
            .await
            .expect("commit"),
        original
    );
    let claim = ClaimGatewayAction::new(
        original.tenant_id().clone(),
        original.session_id().clone(),
        ActionId::new(),
        "restart-key",
        CanonicalRequestHash::new([2; 32]),
        ActionKind::ReadOnly,
        original.placement().clone(),
    )
    .expect("claim");
    let action = store
        .claim_action(claim, Utc::now())
        .await
        .expect("claim")
        .into_snapshot();
    drop(store);
    let restarted = MemoryGatewayActionStore::attach(database, StoreConfig::default());
    assert_eq!(
        restarted
            .get_single_host_directory(original.tenant_id(), original.session_id())
            .await
            .expect("lookup"),
        Some(original.clone())
    );
    assert_eq!(
        restarted
            .get_action_by_idempotency(original.tenant_id(), original.session_id(), "restart-key")
            .await
            .expect("action lookup"),
        Some(action)
    );
    assert!(
        restarted
            .get_single_host_directory(&TenantId::new(), original.session_id())
            .await
            .expect("foreign tenant")
            .is_none()
    );
    assert!(
        restarted
            .get_action_by_idempotency(&TenantId::new(), original.session_id(), "restart-key")
            .await
            .expect("foreign tenant")
            .is_none()
    );
}

#[tokio::test]
async fn directory_cas_rejects_owner_changes_and_never_reopens_terminal_session() {
    let store = MemoryGatewayActionStore::default();
    let original = record(TenantId::new(), SessionId::new(), 9);
    store
        .commit_single_host_directory(original.clone(), None)
        .await
        .expect("commit");
    let changed = record(
        original.tenant_id().clone(),
        original.session_id().clone(),
        10,
    );
    assert_eq!(
        store
            .commit_single_host_directory(changed, None)
            .await
            .expect_err("changed owner"),
        Error::PlacementMismatch
    );
    let closing = original.with_lifecycle(Phase::Closing).expect("closing");
    store
        .commit_single_host_directory(closing.clone(), Some(original.revision()))
        .await
        .expect("closing commit");
    let closed = closing.with_lifecycle(Phase::Closed).expect("closed");
    assert_eq!(
        store
            .commit_single_host_directory(closed.clone(), Some(original.revision()))
            .await
            .expect_err("stale revision"),
        Error::SessionDirectoryConflict
    );
    store
        .commit_single_host_directory(closed.clone(), Some(closing.revision()))
        .await
        .expect("closed commit");
    assert_eq!(
        store
            .commit_single_host_directory(original, None)
            .await
            .expect("idempotent creation replay"),
        closed
    );
    assert_eq!(
        closed
            .with_lifecycle(Phase::Ready)
            .expect_err("no resurrection"),
        Error::PlacementMismatch
    );
}

#[test]
fn directory_decoder_rejects_unvalidated_fences_and_unknown_fields() {
    let original = record(TenantId::new(), SessionId::new(), 9);
    let mut raw = serde_json::to_value(&original).expect("json");
    raw["placement"]["directory_revision"] = serde_json::json!(0);
    assert!(serde_json::from_value::<Record>(raw).is_err());
    let mut raw = serde_json::to_value(original).expect("json");
    raw["extra"] = serde_json::json!(true);
    assert!(serde_json::from_value::<Record>(raw).is_err());
}

#[tokio::test]
async fn directory_tenant_index_pages_are_bounded_and_keep_the_original_ceiling() {
    let store = MemoryGatewayActionStore::default();
    let tenant = TenantId::new();
    let foreign = record(TenantId::new(), SessionId::new(), 9);
    store
        .commit_single_host_directory(foreign.clone(), None)
        .await
        .expect("foreign commit");
    for index in 1..=600 {
        store
            .commit_single_host_directory(
                record(
                    tenant.clone(),
                    SessionId::from_uuid(uuid::Uuid::from_u128(
                        0x0000_0000_0000_7000_8000_0000_0000_0000 | index,
                    ))
                    .expect("session"),
                    9,
                ),
                None,
            )
            .await
            .expect("commit");
    }
    let first = store
        .list_single_host_directory(&tenant, None, None, 256)
        .await
        .expect("first page");
    assert_eq!(first.records().len(), 256);
    assert!(first.has_more());
    assert!(
        first
            .records()
            .iter()
            .all(|record| record.tenant_id() == &tenant)
    );
    let late = record(
        tenant.clone(),
        SessionId::from_uuid(uuid::Uuid::from_u128(
            0x0000_0000_0000_7000_8000_0000_0000_0000 | 601,
        ))
        .expect("late"),
        9,
    );
    store
        .commit_single_host_directory(late.clone(), None)
        .await
        .expect("late commit");
    let after = first.records().last().expect("last").session_id();
    let second = store
        .list_single_host_directory(&tenant, Some(after), first.ceiling(), 256)
        .await
        .expect("second page");
    let last = store
        .list_single_host_directory(
            &tenant,
            Some(second.records().last().expect("second last").session_id()),
            second.ceiling(),
            256,
        )
        .await
        .expect("last page");
    assert_eq!(second.records().len(), 256);
    assert_eq!(last.records().len(), 88);
    assert!(!last.has_more());
    assert!(
        last.records()
            .iter()
            .all(|record| record.session_id() != late.session_id())
    );
    assert_eq!(first.ceiling(), last.ceiling());
    assert!(
        store
            .list_single_host_directory(&tenant, None, None, 257)
            .await
            .is_err()
    );
}
