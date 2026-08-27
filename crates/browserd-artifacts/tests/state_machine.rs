#![allow(clippy::expect_used)]

mod common;

use browserd_artifacts::{
    Artifact, ArtifactChecksum, ArtifactContentMetadata, ArtifactContentSource, ArtifactError,
    ArtifactEvent, ArtifactState, TransitionOutcome,
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

fn apply_materialized_and_replay(
    artifact: &mut Artifact,
    event: ArtifactEvent,
    metadata: ArtifactContentMetadata,
) {
    assert_eq!(
        artifact.apply_materialized(event, metadata.clone()),
        Ok(TransitionOutcome::Applied)
    );
    assert_eq!(
        artifact.apply_materialized(event, metadata),
        Ok(TransitionOutcome::AlreadyApplied),
        "replaying exact materialization must be idempotent"
    );
}

#[test]
fn upload_passes_through_storage_scanning_availability_and_deletion() {
    let mut artifact = Artifact::new_upload(artifact_fixture().key);

    assert_eq!(artifact.state(), ArtifactState::Uploading);

    apply_materialized_and_replay(
        &mut artifact,
        ArtifactEvent::UploadStored,
        upload_metadata(4, 7),
    );
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
            .apply_materialized(ArtifactEvent::UploadStored, upload_metadata(4, 7))
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
    apply_materialized_and_replay(
        &mut artifact,
        ArtifactEvent::GenerationCompleted,
        generated_metadata(4, 7),
    );
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
        .apply_materialized(ArtifactEvent::GenerationCompleted, generated_metadata(4, 7))
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

fn upload_metadata(size_bytes: u64, checksum_byte: u8) -> ArtifactContentMetadata {
    ArtifactContentMetadata::new(
        size_bytes,
        ArtifactChecksum::new([checksum_byte; 32]),
        "application/octet-stream",
        ArtifactContentSource::ClientUpload,
        "api-upload",
    )
    .expect("fixed artifact metadata should be valid")
}

fn generated_metadata(size_bytes: u64, checksum_byte: u8) -> ArtifactContentMetadata {
    ArtifactContentMetadata::new(
        size_bytes,
        ArtifactChecksum::new([checksum_byte; 32]),
        "image/png",
        ArtifactContentSource::Generated,
        "screenshot",
    )
    .expect("fixed generated metadata should be valid")
}

fn metadata_with_strings(
    content_type: impl Into<String>,
    origin: impl Into<String>,
) -> Result<ArtifactContentMetadata, ArtifactError> {
    ArtifactContentMetadata::new(
        0,
        ArtifactChecksum::new([0; 32]),
        content_type,
        ArtifactContentSource::Generated,
        origin,
    )
}

#[test]
fn materialization_records_immutable_size_checksum_type_source_and_origin() {
    let mut artifact = Artifact::new_upload(artifact_fixture().key);
    let metadata = upload_metadata(4, 7);

    assert_eq!(
        artifact.apply_materialized(ArtifactEvent::UploadStored, metadata.clone()),
        Ok(TransitionOutcome::Applied)
    );
    assert_eq!(artifact.content_metadata(), Some(&metadata));

    assert_eq!(
        artifact.apply_materialized(ArtifactEvent::UploadStored, metadata.clone()),
        Ok(TransitionOutcome::AlreadyApplied),
        "a lost response may replay the exact materialization"
    );
    assert_eq!(artifact.content_metadata(), Some(&metadata));
}

#[test]
fn materialization_replay_with_different_integrity_metadata_fails_closed() {
    let mut artifact = Artifact::new_upload(artifact_fixture().key);
    artifact
        .apply_materialized(ArtifactEvent::UploadStored, upload_metadata(4, 7))
        .expect("first materialization should succeed");

    assert!(matches!(
        artifact.apply_materialized(ArtifactEvent::UploadStored, upload_metadata(5, 8)),
        Err(ArtifactError::MetadataConflict)
    ));
    assert_eq!(artifact.content_metadata(), Some(&upload_metadata(4, 7)));
}

#[test]
fn metadata_source_must_match_the_artifact_kind_and_materializing_event() {
    let mut generated = Artifact::new_generated(artifact_fixture().key);
    let upload_metadata = upload_metadata(4, 7);

    assert!(matches!(
        generated.apply_materialized(ArtifactEvent::GenerationCompleted, upload_metadata),
        Err(ArtifactError::MetadataSourceMismatch)
    ));
    assert!(matches!(
        generated.apply_materialized(
            ArtifactEvent::FinalizationSucceeded,
            ArtifactContentMetadata::new(
                4,
                ArtifactChecksum::new([7; 32]),
                "image/png",
                ArtifactContentSource::Generated,
                "screenshot",
            )
            .expect("fixed artifact metadata should be valid"),
        ),
        Err(ArtifactError::MetadataNotAllowed)
    ));
    assert_eq!(generated.state(), ArtifactState::Generating);
}

#[test]
fn empty_content_type_or_origin_is_rejected() {
    assert!(matches!(
        ArtifactContentMetadata::new(
            0,
            ArtifactChecksum::new([0; 32]),
            "  ",
            ArtifactContentSource::Generated,
            "screenshot",
        ),
        Err(ArtifactError::InvalidMetadata)
    ));
    assert!(matches!(
        ArtifactContentMetadata::new(
            0,
            ArtifactChecksum::new([0; 32]),
            "image/png",
            ArtifactContentSource::Generated,
            "  ",
        ),
        Err(ArtifactError::InvalidMetadata)
    ));
}

#[test]
fn materializing_transition_without_metadata_is_rejected() {
    let mut upload = Artifact::new_upload(artifact_fixture().key);
    let mut generated = Artifact::new_generated(artifact_fixture().key);

    assert_eq!(
        upload.apply(ArtifactEvent::UploadStored),
        Err(ArtifactError::MetadataRequired)
    );
    assert_eq!(upload.state(), ArtifactState::Uploading);
    assert_eq!(
        generated.apply(ArtifactEvent::GenerationCompleted),
        Err(ArtifactError::MetadataRequired)
    );
    assert_eq!(generated.state(), ArtifactState::Generating);
}

#[test]
fn content_type_and_origin_enforce_byte_length_boundaries() {
    assert!(metadata_with_strings("a".repeat(255), "b".repeat(2_048)).is_ok());
    assert_eq!(
        metadata_with_strings("a".repeat(256), "origin"),
        Err(ArtifactError::InvalidMetadata)
    );
    assert_eq!(
        metadata_with_strings("application/octet-stream", "b".repeat(2_049)),
        Err(ArtifactError::InvalidMetadata)
    );
    assert!(metadata_with_strings(format!("{}a", "é".repeat(127)), "origin").is_ok());
    assert_eq!(
        metadata_with_strings("é".repeat(128), "origin"),
        Err(ArtifactError::InvalidMetadata),
        "limits are measured in encoded bytes, not scalar values"
    );
}

#[test]
fn content_type_and_origin_reject_outer_whitespace_and_control_characters() {
    for invalid_content_type in [
        " application/octet-stream",
        "application/octet-stream ",
        "application/\0octet-stream",
        "application/\noctet-stream",
    ] {
        assert_eq!(
            metadata_with_strings(invalid_content_type, "api-upload"),
            Err(ArtifactError::InvalidMetadata)
        );
    }

    for invalid_origin in [" api-upload", "api-upload ", "api\0upload", "api\nupload"] {
        assert_eq!(
            metadata_with_strings("application/octet-stream", invalid_origin),
            Err(ArtifactError::InvalidMetadata)
        );
    }
}
