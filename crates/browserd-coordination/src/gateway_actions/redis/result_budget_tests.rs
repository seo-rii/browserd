#![allow(clippy::expect_used)]

use super::*;
use browserd_actions::ActionResultBudget;
use sha2::Digest;

fn persisted(budget: ActionResultBudget) -> PersistedGatewayAction {
    let placement = GatewayActionPlacement::new(
        DirectoryFence::new(
            browserd_core::WorkerId::new("profile-codec").expect("worker"),
            7,
            3,
            2,
        )
        .expect("directory fence"),
        1,
    )
    .expect("placement");
    let claim = ClaimGatewayAction::new(
        TenantId::new(),
        SessionId::new(),
        ActionId::new(),
        "snapshot",
        browserd_actions::CanonicalRequestHash::new([4; 32]),
        ActionKind::ReadOnly,
        placement,
    )
    .expect("trusted normalized claim")
    .with_result_budget(budget);
    let now = Utc::now();
    PersistedGatewayAction::from_claim(&claim, now, now + chrono::Duration::days(1))
}

#[test]
fn redis_record_roundtrip_keeps_the_profile_and_legacy_records_default_to_64k() {
    let encoded = serde_json::to_value(persisted(ActionResultBudget::Snapshot)).expect("record");
    let restored: PersistedGatewayAction =
        serde_json::from_value(encoded.clone()).expect("typed row");
    assert_eq!(
        restored
            .into_snapshot(ActionSequence::new(1))
            .expect("owned snapshot")
            .result_budget(),
        ActionResultBudget::Snapshot
    );
    let mut legacy = encoded;
    legacy.as_object_mut().expect("row").remove("result_budget");
    let old: PersistedGatewayAction = serde_json::from_value(legacy).expect("legacy row");
    assert_eq!(
        old.into_snapshot(ActionSequence::new(1))
            .expect("legacy owner")
            .result_budget(),
        ActionResultBudget::Standard
    );
}

#[test]
fn redis_record_guard_rejects_oversized_or_mutating_snapshot_profiles() {
    for (budget, size, accepted) in [
        (ActionResultBudget::Standard, 64 * 1024, true),
        (ActionResultBudget::Standard, 64 * 1024 + 1, false),
        (ActionResultBudget::Snapshot, 4 * 1024 * 1024, true),
        (ActionResultBudget::Snapshot, 4 * 1024 * 1024 + 1, false),
    ] {
        let mut row = persisted(budget);
        let body = vec![b'x'; size];
        let dispatch = DispatchId::new();
        row.evidence
            .arm_dispatch(dispatch.clone())
            .expect("armed worker dispatch");
        row.evidence
            .record_worker_result(
                &dispatch,
                BrowserResult::Succeeded(browserd_actions::ResultDigest::new(
                    sha2::Sha256::digest(&body).into(),
                )),
            )
            .expect("terminal body digest");
        row.result_content = Some(body);
        row.revision = 2;
        assert_eq!(row.into_snapshot(ActionSequence::new(1)).is_ok(), accepted);
    }
    let mut invalid = persisted(ActionResultBudget::Snapshot);
    invalid.kind = ActionKind::Mutating;
    assert!(invalid.into_snapshot(ActionSequence::new(1)).is_err());
}
