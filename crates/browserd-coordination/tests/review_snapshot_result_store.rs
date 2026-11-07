#![allow(clippy::expect_used)]
use browserd_actions::{
    ActionKind, ActionResultBudget, BrowserResult, CanonicalRequestHash, DispatchId,
    MAX_ACTION_RESULT_CONTENT_BYTES, MAX_SNAPSHOT_RESULT_CONTENT_BYTES, ResultDigest,
};
use browserd_coordination::{
    ClaimGatewayAction, DirectoryFence, GatewayActionCoordination, GatewayActionCoordinationError,
    GatewayActionPlacement, MemoryCoordinationDatabase, MemoryGatewayActionStore, StoreConfig,
};
use browserd_core::{ActionId, SessionId, TenantId, WorkerId};
use chrono::Utc;
use sha2::{Digest, Sha256};

fn placement() -> GatewayActionPlacement {
    GatewayActionPlacement::new(
        DirectoryFence::new(WorkerId::new("snapshot-store").expect("worker"), 7, 3, 2)
            .expect("fence"),
        1,
    )
    .expect("placement")
}
#[tokio::test]
async fn snapshot_profile_persists_its_full_body_and_rejects_only_over_budget_results() {
    for (budget, size, accepted) in [
        (
            ActionResultBudget::Standard,
            MAX_ACTION_RESULT_CONTENT_BYTES,
            true,
        ),
        (
            ActionResultBudget::Standard,
            MAX_ACTION_RESULT_CONTENT_BYTES + 1,
            false,
        ),
        (
            ActionResultBudget::Snapshot,
            MAX_SNAPSHOT_RESULT_CONTENT_BYTES,
            true,
        ),
        (
            ActionResultBudget::Snapshot,
            MAX_SNAPSHOT_RESULT_CONTENT_BYTES + 1,
            false,
        ),
    ] {
        let db = MemoryCoordinationDatabase::default();
        let store = MemoryGatewayActionStore::attach(db.clone(), StoreConfig::default());
        let tenant = TenantId::new();
        let session = SessionId::new();
        let id = ActionId::new();
        let placement = placement();
        let now = Utc::now();
        let claim = ClaimGatewayAction::new(
            tenant.clone(),
            session.clone(),
            id.clone(),
            "snapshot",
            CanonicalRequestHash::new([4; 32]),
            ActionKind::ReadOnly,
            placement.clone(),
        )
        .expect("claim")
        .with_result_budget(budget);
        let original = store
            .claim_action(claim, now)
            .await
            .expect("accepted owned action");
        assert_eq!(original.snapshot().result_budget(), budget);
        let dispatch = DispatchId::new();
        let armed = store
            .arm_dispatch(
                &tenant,
                &session,
                &id,
                original.snapshot().revision(),
                &placement,
                dispatch.clone(),
                now,
            )
            .await
            .expect("armed action");
        let body = vec![b'x'; size];
        let digest = ResultDigest::new(Sha256::digest(&body).into());
        let result = store
            .record_worker_result(
                &tenant,
                &session,
                &id,
                armed.revision(),
                &placement,
                &dispatch,
                armed.action_sequence(),
                BrowserResult::Succeeded(digest),
                Some(body.clone()),
                now,
            )
            .await;
        assert_eq!(result.is_ok(), accepted);
        let restarted = MemoryGatewayActionStore::attach(db, StoreConfig::default());
        let reread = restarted
            .get_effective_action(&tenant, &session, &id)
            .await
            .expect("re-read")
            .expect("owned record");
        assert_eq!(reread.result_budget(), budget);
        if accepted {
            assert_eq!(reread.result_content(), Some(body.as_slice()));
        } else {
            assert!(reread.terminal().is_none());
            assert!(reread.result_content().is_none());
            assert_eq!(reread.revision(), armed.revision());
        }
    }
}
#[tokio::test]
async fn profile_is_immutable_with_the_claim_hash_and_cannot_expand_mutating_actions() {
    let store = MemoryGatewayActionStore::default();
    let tenant = TenantId::new();
    let session = SessionId::new();
    let placement = placement();
    let now = Utc::now();
    let original = ClaimGatewayAction::new(
        tenant.clone(),
        session.clone(),
        ActionId::new(),
        "snapshot",
        CanonicalRequestHash::new([4; 32]),
        ActionKind::ReadOnly,
        placement.clone(),
    )
    .expect("claim")
    .with_result_budget(ActionResultBudget::Snapshot);
    store
        .claim_action(original.clone(), now)
        .await
        .expect("snapshot claim");
    let conflicting = original.with_result_budget(ActionResultBudget::Standard);
    assert!(matches!(
        store.claim_action(conflicting, now).await,
        Err(GatewayActionCoordinationError::IdempotencyConflict { .. })
    ));
    let invalid = ClaimGatewayAction::new(
        tenant,
        session,
        ActionId::new(),
        "mutation",
        CanonicalRequestHash::new([5; 32]),
        ActionKind::Mutating,
        placement,
    )
    .expect("claim")
    .with_result_budget(ActionResultBudget::Snapshot);
    assert!(matches!(
        store.claim_action(invalid, now).await,
        Err(GatewayActionCoordinationError::CorruptState)
    ));
}
