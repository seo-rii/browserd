use super::*;
use browserd_coordination::{
    GatewayDirectoryLifecycle as Phase, GatewaySessionDirectoryRecord as Record,
    GatewaySessionIsolation as Isolation,
};
use std::collections::BTreeMap;

#[tokio::test]
async fn redis_directory_restart_cas_and_idempotency_lookup_preserve_exact_owner() {
    let Some(fixture) = redis_fixture("session-directory").await else {
        return;
    };
    let tenant = TenantId::new();
    let session = SessionId::new();
    let original = Record::new(
        tenant.clone(),
        session.clone(),
        placement(7, 9),
        Phase::Ready,
        Isolation::DedicatedProcess,
        Isolation::DedicatedProcess,
        BTreeMap::new(),
    )
    .expect("record");
    fixture
        .store
        .commit_single_host_directory(original.clone(), None)
        .await
        .expect("commit");
    let action = fixture
        .store
        .claim_action(
            claim(
                tenant.clone(),
                session.clone(),
                ActionId::new(),
                "directory-key",
                4,
                original.placement().clone(),
            ),
            Utc::now(),
        )
        .await
        .expect("claim")
        .into_snapshot();
    let restarted = RedisGatewayActionStore::connect(fixture.config.clone())
        .await
        .expect("reconnect");
    assert_eq!(
        restarted
            .get_single_host_directory(&tenant, &session)
            .await
            .expect("lookup"),
        Some(original.clone())
    );
    let directory = restarted
        .list_single_host_directory(&tenant, None, None, 1)
        .await
        .expect("bounded indexed listing");
    assert_eq!(directory.records(), std::slice::from_ref(&original));
    assert!(!directory.has_more());
    assert!(
        restarted
            .list_single_host_directory(&TenantId::new(), None, None, 256)
            .await
            .expect("foreign listing")
            .records()
            .is_empty()
    );
    assert_eq!(
        restarted
            .get_action_by_idempotency(&tenant, &session, "directory-key")
            .await
            .expect("action lookup"),
        Some(action)
    );
    assert!(
        restarted
            .get_single_host_directory(&TenantId::new(), &session)
            .await
            .expect("foreign tenant")
            .is_none()
    );
    let closed = original.with_lifecycle(Phase::Closed).expect("closed");
    restarted
        .commit_single_host_directory(closed.clone(), Some(original.revision()))
        .await
        .expect("close commit");
    assert_eq!(
        restarted
            .commit_single_host_directory(original.clone(), None)
            .await
            .expect("old create replay"),
        closed
    );
    let wrong = Record::new(
        tenant.clone(),
        session.clone(),
        placement(8, 9),
        Phase::Ready,
        Isolation::DedicatedProcess,
        Isolation::DedicatedProcess,
        BTreeMap::new(),
    )
    .expect("changed epoch");
    assert_eq!(
        restarted
            .commit_single_host_directory(wrong, None)
            .await
            .expect_err("wrong owner"),
        GatewayActionCoordinationError::PlacementMismatch
    );
    let mut connection = redis::Client::open(fixture.endpoint.as_str())
        .expect("client")
        .get_multiplexed_async_connection()
        .await
        .expect("connection");
    let key = format!(
        "{}:gateway-directory:{{single-host-v1}}:records",
        fixture.prefix
    );
    let expiry: i64 = redis::cmd("PTTL")
        .arg(key)
        .query_async(&mut connection)
        .await
        .expect("ttl");
    assert_eq!(
        expiry, -1,
        "directory is persistent; terminal expiry uses bounded explicit GC"
    );
    delete_fixture(&fixture).await;
}
