#![allow(clippy::expect_used)]

mod common;

use browserd_artifacts::{
    Artifact, ArtifactError, ArtifactEvent, ArtifactState, TransitionOutcome,
};

use common::artifact_fixture;

fn apply_and_replay(artifact: &mut Artifact, event: ArtifactEvent) {
    assert_eq!(artifact.apply(event), Ok(TransitionOutcome::Applied));
    assert_eq!(
        artifact.apply(event),
        Ok(TransitionOutcome::AlreadyApplied),
        "replaying the same transition must be idempotent"
    );
}

#[test]
fn upload_passes_through_storage_scanning_availability_and_deletion() {
    let mut artifact = Artifact::new_upload(artifact_fixture().key);

    assert_eq!(artifact.state(), ArtifactState::Uploading);

    apply_and_replay(&mut artifact, ArtifactEvent::UploadStored);
    assert_eq!(artifact.state(), ArtifactState::Stored);

    apply_and_replay(&mut artifact, ArtifactEvent::ScanStarted);
    assert_eq!(artifact.state(), ArtifactState::Scanning);

    apply_and_replay(&mut artifact, ArtifactEvent::ScanPassed);
    assert_eq!(artifact.state(), ArtifactState::Available);

    apply_and_replay(&mut artifact, ArtifactEvent::DeleteRequested);
    assert_eq!(artifact.state(), ArtifactState::Deleting);

    apply_and_replay(&mut artifact, ArtifactEvent::DeleteCompleted);
    assert_eq!(artifact.state(), ArtifactState::Deleted);
}

#[test]
fn scanner_can_quarantine_or_reject_an_upload_but_not_publish_it_afterward() {
    for terminal in [ArtifactEvent::ScanQuarantined, ArtifactEvent::ScanRejected] {
        let mut artifact = Artifact::new_upload(artifact_fixture().key);
        artifact
            .apply(ArtifactEvent::UploadStored)
            .expect("upload should become stored");
        artifact
            .apply(ArtifactEvent::ScanStarted)
            .expect("stored upload should begin scanning");

        apply_and_replay(&mut artifact, terminal);

        let expected = if terminal == ArtifactEvent::ScanQuarantined {
            ArtifactState::Quarantined
        } else {
            ArtifactState::Rejected
        };
        assert_eq!(artifact.state(), expected);
        assert!(matches!(
            artifact.apply(ArtifactEvent::ScanPassed),
            Err(ArtifactError::InvalidTransition { .. })
        ));
    }
}

#[test]
fn generated_artifact_finalizes_to_available_and_can_then_be_deleted() {
    let mut artifact = Artifact::new_generated(artifact_fixture().key);

    assert_eq!(artifact.state(), ArtifactState::Generating);
    apply_and_replay(&mut artifact, ArtifactEvent::GenerationCompleted);
    assert_eq!(artifact.state(), ArtifactState::Finalizing);
    apply_and_replay(&mut artifact, ArtifactEvent::FinalizationSucceeded);
    assert_eq!(artifact.state(), ArtifactState::Available);
    apply_and_replay(&mut artifact, ArtifactEvent::DeleteRequested);
    apply_and_replay(&mut artifact, ArtifactEvent::DeleteCompleted);
    assert_eq!(artifact.state(), ArtifactState::Deleted);
}

#[test]
fn generated_artifact_can_fail_only_from_finalizing() {
    let mut artifact = Artifact::new_generated(artifact_fixture().key);

    assert!(matches!(
        artifact.apply(ArtifactEvent::FinalizationFailed),
        Err(ArtifactError::InvalidTransition { .. })
    ));

    artifact
        .apply(ArtifactEvent::GenerationCompleted)
        .expect("generation should enter finalization");
    apply_and_replay(&mut artifact, ArtifactEvent::FinalizationFailed);
    assert_eq!(artifact.state(), ArtifactState::Failed);
}

#[test]
fn upload_and_generated_transition_families_cannot_be_mixed() {
    let mut upload = Artifact::new_upload(artifact_fixture().key);
    let mut generated = Artifact::new_generated(artifact_fixture().key);

    assert!(matches!(
        upload.apply(ArtifactEvent::GenerationCompleted),
        Err(ArtifactError::InvalidTransition { .. })
    ));
    assert!(matches!(
        generated.apply(ArtifactEvent::UploadStored),
        Err(ArtifactError::InvalidTransition { .. })
    ));
}
