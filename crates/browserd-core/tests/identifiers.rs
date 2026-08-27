use std::collections::HashSet;

use browserd_core::{
    ActionId, ApprovalId, ArtifactId, LeaseId, OperationId, PageId, PrincipalId, SessionId,
    ShardId, SnapshotId, TenantId, WorkerId,
};
use uuid::{Uuid, Version};

macro_rules! assert_uuid_v7_id_contract {
    ($id_type:ty) => {{
        let id = <$id_type>::new();
        let rendered = id.to_string();

        assert_eq!(id.as_uuid().get_version(), Some(Version::SortRand));
        assert_eq!(rendered.parse::<$id_type>().ok().as_ref(), Some(&id));

        let encoded = serde_json::to_string(&id).unwrap_or_default();
        assert!(!encoded.is_empty());
        assert_eq!(
            serde_json::from_str::<$id_type>(&encoded).ok().as_ref(),
            Some(&id)
        );
    }};
}

macro_rules! assert_opaque_id_contract {
    ($id_type:ty) => {{
        let generated = (0..256).map(|_| <$id_type>::new()).collect::<HashSet<_>>();
        assert_eq!(generated.len(), 256, "opaque IDs must not collide");

        for id in generated.iter().take(8) {
            let rendered = id.to_string();
            assert!(!rendered.is_empty());
            assert_eq!(id.as_uuid().get_version(), Some(Version::Random));
            assert_eq!(rendered.parse::<$id_type>().ok().as_ref(), Some(id));

            let encoded = serde_json::to_string(id).unwrap_or_default();
            assert!(!encoded.is_empty());
            assert_eq!(
                serde_json::from_str::<$id_type>(&encoded).ok().as_ref(),
                Some(id)
            );
        }
    }};
}

#[test]
fn externally_persisted_ids_are_uuid_v7_and_round_trip() {
    assert_uuid_v7_id_contract!(TenantId);
    assert_uuid_v7_id_contract!(PrincipalId);
    assert_uuid_v7_id_contract!(OperationId);
    assert_uuid_v7_id_contract!(SessionId);
    assert_uuid_v7_id_contract!(ShardId);
    assert_uuid_v7_id_contract!(ActionId);
    assert_uuid_v7_id_contract!(ApprovalId);
    assert_uuid_v7_id_contract!(ArtifactId);
}

#[test]
fn browser_internal_handles_are_random_opaque_round_trippable_values() {
    assert_opaque_id_contract!(PageId);
    assert_opaque_id_contract!(SnapshotId);
    assert_opaque_id_contract!(LeaseId);
}

#[test]
fn worker_id_is_a_validated_stable_deployment_identity() {
    let worker = WorkerId::new("worker-apne2-a-001");
    assert!(worker.is_ok());
    let Some(worker) = worker.ok() else {
        return;
    };

    assert_eq!(worker.as_str(), "worker-apne2-a-001");
    assert_eq!(
        worker.to_string().parse::<WorkerId>().ok().as_ref(),
        Some(&worker)
    );

    let encoded = serde_json::to_string(&worker).unwrap_or_default();
    assert!(!encoded.is_empty());
    assert_eq!(
        serde_json::from_str::<WorkerId>(&encoded).ok().as_ref(),
        Some(&worker)
    );
    assert!(WorkerId::new("").is_err());
    assert!(WorkerId::new("   ").is_err());
    assert!(serde_json::from_str::<WorkerId>(r#""   ""#).is_err());
}

#[test]
fn parsing_and_deserialization_reject_the_wrong_uuid_version() {
    let random = Uuid::new_v4();
    let time_ordered = Uuid::now_v7();

    assert!(random.to_string().parse::<TenantId>().is_err());
    assert!(random.to_string().parse::<ApprovalId>().is_err());
    assert!(time_ordered.to_string().parse::<PageId>().is_err());

    let random_json = serde_json::to_string(&random).unwrap_or_default();
    let time_ordered_json = serde_json::to_string(&time_ordered).unwrap_or_default();
    assert!(serde_json::from_str::<TenantId>(&random_json).is_err());
    assert!(serde_json::from_str::<PageId>(&time_ordered_json).is_err());
}

#[test]
fn independently_generated_ids_do_not_alias() {
    let sessions = (0..1_024).map(|_| SessionId::new()).collect::<HashSet<_>>();
    let actions = (0..1_024).map(|_| ActionId::new()).collect::<HashSet<_>>();

    assert_eq!(sessions.len(), 1_024);
    assert_eq!(actions.len(), 1_024);
}
