#![allow(clippy::expect_used)]
use super::*;

fn artifact_commit() -> NotificationCommit {
    let tenant = TenantId::new();
    let source = NotificationSourceScope::new(
        tenant,
        WorkerId::new("worker-original").expect("worker"),
        Uuid::new_v4(),
        NotificationSourceFamily::ArtifactRegistry,
    )
    .expect("source");
    let session = NotificationSessionScope::new(SessionId::new(), PlacementFence::new(3, 4, 5))
        .expect("session");
    let artifact = ArtifactId::new();
    NotificationCommit::new(
        source,
        1,
        1_800_000_000_000,
        vec![
            NotificationDescriptor::fresh(
                session.clone(),
                WorkerNotificationEvent::ArtifactStateChanged {
                    artifact_id: artifact.clone(),
                    state: NotificationArtifactState::Available,
                },
            )
            .expect("available"),
            NotificationDescriptor::fresh(
                session,
                WorkerNotificationEvent::DownloadCompleted {
                    artifact_id: artifact,
                },
            )
            .expect("download"),
        ],
    )
    .expect("commit")
}

#[test]
fn immutable_atomic_metadata_rejects_tampering_and_unsafe_payloads() {
    let commit = artifact_commit();
    let encoded = serde_json::to_vec(&commit).expect("encode");
    assert_eq!(
        serde_json::from_slice::<NotificationCommit>(&encoded).expect("decode"),
        commit
    );
    let baseline = serde_json::to_value(&commit).expect("wire");
    for path in [
        "sequence",
        "timestamp",
        "fence",
        "source",
        "event",
        "payload",
    ] {
        let mut value = baseline.clone();
        match path {
            "sequence" => value["source_sequence"] = serde_json::json!(2),
            "timestamp" => value["occurred_at_unix_ms"] = serde_json::json!(0),
            "fence" => {
                value["descriptors"][0]["session_scope"]["worker_epoch"] = serde_json::json!(9)
            }
            "source" => value["scope"]["source_id"] = serde_json::json!(Uuid::new_v4()),
            "event" => value["descriptors"][0]["event"]["state"] = serde_json::json!("deleted"),
            _ => {
                value["descriptors"][0]["event"]["url"] =
                    serde_json::json!("https://sensitive.example")
            }
        }
        assert!(
            serde_json::from_value::<NotificationCommit>(value).is_err(),
            "{path}"
        );
    }
    assert_eq!(
        serde_json::from_value::<NotificationAck>(
            serde_json::to_value(commit.ack()).expect("ack wire")
        )
        .expect("ack decode"),
        commit.ack()
    );
}

#[test]
fn whole_commit_bounds_identity_and_family_are_enforced() {
    let commit = artifact_commit();
    let source = commit.scope().clone();
    let descriptors = commit.descriptors().to_vec();
    assert!(NotificationCommit::new(source.clone(), 0, 0, descriptors.clone()).is_err());
    assert!(
        NotificationCommit::new(source.clone(), i64::MAX as u64 + 1, 0, descriptors.clone())
            .is_err()
    );
    assert!(
        NotificationCommit::new(source.clone(), 1, i64::MAX as u64 + 1, descriptors.clone())
            .is_err()
    );
    assert!(NotificationCommit::new(source.clone(), 1, 0, Vec::new()).is_err());
    assert!(
        NotificationCommit::new(source.clone(), 1, 0, vec![descriptors[0].clone(); 9]).is_err()
    );
    assert!(
        NotificationCommit::new(source.clone(), 1, 0, vec![descriptors[0].clone(); 2]).is_err()
    );
    let duplicate = NotificationDescriptor::fresh(
        descriptors[0].session_scope().clone(),
        descriptors[0].event().clone(),
    )
    .expect("fresh event same resource/kind");
    assert!(
        NotificationCommit::new(
            source.clone(),
            1,
            0,
            vec![descriptors[0].clone(), duplicate]
        )
        .is_err()
    );
    let foreign = NotificationDescriptor::fresh(
        descriptors[0].session_scope().clone(),
        WorkerNotificationEvent::BrowserControlChanged {
            state: NotificationControlState::Human,
        },
    )
    .expect("foreign descriptor");
    assert!(NotificationCommit::new(source, 1, 0, vec![foreign]).is_err());
    assert!(
        NotificationSourceScope::new(
            TenantId::new(),
            WorkerId::new("w").expect("worker"),
            Uuid::nil(),
            NotificationSourceFamily::ActionJournal
        )
        .is_err()
    );
    assert!(
        NotificationDescriptor::new(
            Uuid::new_v4(),
            descriptors[0].session_scope().clone(),
            descriptors[0].event().clone()
        )
        .is_err()
    );
}

#[test]
fn execution_and_resolution_cannot_fabricate_a_state() {
    let session = NotificationSessionScope::new(SessionId::new(), PlacementFence::new(1, 2, 3))
        .expect("session");
    for (state, action_id) in [
        (
            NotificationSessionExecutionState::Idle,
            Some(ActionId::new()),
        ),
        (NotificationSessionExecutionState::Running, None),
        (NotificationSessionExecutionState::PendingApproval, None),
        (
            NotificationSessionExecutionState::ReconciliationRequired,
            None,
        ),
    ] {
        assert!(
            NotificationDescriptor::fresh(
                session.clone(),
                WorkerNotificationEvent::SessionExecutionChanged { state, action_id }
            )
            .is_err()
        );
    }
    assert!(
        NotificationDescriptor::fresh(
            session,
            WorkerNotificationEvent::ActionStateChanged {
                action_id: ActionId::new(),
                state: NotificationActionState::Succeeded,
                resolution: Some(NotificationActionResolution::ConfirmedExecuted)
            }
        )
        .is_err()
    );
}

#[test]
fn registry_scope_survives_boots_while_each_event_keeps_original_fence() {
    let commit = artifact_commit();
    let source = commit.scope().clone();
    let newer = NotificationSessionScope::new(SessionId::new(), PlacementFence::new(10, 11, 12))
        .expect("new original scope");
    let next = NotificationCommit::new(
        source.clone(),
        2,
        commit.occurred_at_unix_ms() - 1,
        vec![
            NotificationDescriptor::fresh(
                newer.clone(),
                WorkerNotificationEvent::ArtifactStateChanged {
                    artifact_id: ArtifactId::new(),
                    state: NotificationArtifactState::Rejected,
                },
            )
            .expect("metadata only"),
        ],
    )
    .expect("next authority");
    assert_eq!(next.scope(), &source);
    assert_eq!(next.descriptors()[0].session_scope(), &newer);
    assert_eq!(
        commit.descriptors()[0].session_scope().fence().worker_epoch,
        3
    );
    assert_ne!(next.digest(), commit.digest());
}
