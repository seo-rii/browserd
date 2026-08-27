#![allow(clippy::expect_used)]

mod common;

use std::sync::Arc;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use browserd_artifacts::{
    ArtifactMultipartStore, ArtifactQuota, ArtifactWriteError, FilesystemArtifactStore,
    MultipartUploadId, QuotaLimits, StreamingArtifactWriter,
};
use bytes::Bytes;
use common::artifact_fixture;

fn artifact_directory() -> tempfile::TempDir {
    let directory = tempfile::tempdir().expect("artifact directory should be created");
    #[cfg(unix)]
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
        .expect("artifact directory should be private");
    directory
}

#[tokio::test]
async fn committed_bytes_and_receipt_survive_store_reopen() {
    let directory = artifact_directory();
    let fixture = artifact_fixture();
    let quota = ArtifactQuota::new(
        fixture.namespace,
        QuotaLimits {
            max_committed_bytes: 64,
            max_in_flight_bytes: 64,
        },
    );
    let store = FilesystemArtifactStore::open(directory.path())
        .expect("absolute artifact root should open");
    let reservation = quota
        .reserve(fixture.key.clone(), 64)
        .await
        .expect("reservation should succeed");
    let mut writer = StreamingArtifactWriter::begin(reservation, store)
        .await
        .expect("multipart upload should begin");
    writer
        .write_chunk(Bytes::from_static(b"durable "))
        .await
        .expect("first chunk should append");
    writer
        .write_chunk(Bytes::from_static(b"artifact"))
        .await
        .expect("second chunk should append");
    let receipt = writer.finish().await.expect("upload should commit");

    let reopened =
        FilesystemArtifactStore::open(directory.path()).expect("artifact store should reopen");
    let stored = reopened
        .read_verified(&fixture.key)
        .await
        .expect("committed artifact should verify")
        .expect("committed artifact should exist");

    assert_eq!(stored.bytes(), &Bytes::from_static(b"durable artifact"));
    assert_eq!(stored.receipt(), &receipt);
}

#[tokio::test]
async fn concurrent_uploads_for_one_artifact_have_exactly_one_committed_winner() {
    let directory = artifact_directory();
    let fixture = artifact_fixture();
    let store = FilesystemArtifactStore::open(directory.path())
        .expect("absolute artifact root should open");
    let barrier = Arc::new(tokio::sync::Barrier::new(3));

    let mut tasks = Vec::new();
    for content in [Bytes::from_static(b"first"), Bytes::from_static(b"second")] {
        let quota = ArtifactQuota::new(
            fixture.namespace.clone(),
            QuotaLimits {
                max_committed_bytes: 64,
                max_in_flight_bytes: 64,
            },
        );
        let reservation = quota
            .reserve(fixture.key.clone(), 64)
            .await
            .expect("reservation should succeed");
        let mut writer = StreamingArtifactWriter::begin(reservation, store.clone())
            .await
            .expect("multipart upload should begin");
        writer
            .write_chunk(content.clone())
            .await
            .expect("content should append");
        let task_barrier = Arc::clone(&barrier);
        tasks.push(tokio::spawn(async move {
            task_barrier.wait().await;
            (content, writer.finish().await)
        }));
    }

    barrier.wait().await;
    let left = tasks
        .remove(0)
        .await
        .expect("first completion task should finish");
    let right = tasks
        .remove(0)
        .await
        .expect("second completion task should finish");
    assert_ne!(left.1.is_ok(), right.1.is_ok());
    assert!(matches!(
        left.1.as_ref().err().or(right.1.as_ref().err()),
        Some(ArtifactWriteError::Store(_))
    ));

    let winner = if left.1.is_ok() { left.0 } else { right.0 };
    let stored = store
        .read_verified(&fixture.key)
        .await
        .expect("winner should verify")
        .expect("winner should exist");
    assert_eq!(stored.bytes(), &winner);
}

#[tokio::test]
async fn abort_is_idempotent_across_store_reopen_and_rejects_untrusted_ids() {
    let directory = artifact_directory();
    let fixture = artifact_fixture();
    let store = FilesystemArtifactStore::open(directory.path())
        .expect("absolute artifact root should open");
    let upload_id = store
        .begin(&fixture.key)
        .await
        .expect("multipart upload should begin");
    store
        .append(&upload_id, Bytes::from_static(b"partial"))
        .await
        .expect("partial bytes should append");
    drop(store);

    let reopened =
        FilesystemArtifactStore::open(directory.path()).expect("artifact store should reopen");
    reopened
        .abort(&upload_id)
        .await
        .expect("first abort should clean the partial");
    reopened
        .abort(&upload_id)
        .await
        .expect("replayed abort should be idempotent");
    assert!(
        reopened
            .append(
                &MultipartUploadId::new("../escape"),
                Bytes::from_static(b"x")
            )
            .await
            .is_err()
    );
}

#[test]
fn relative_roots_are_rejected() {
    assert!(FilesystemArtifactStore::open("relative/artifacts").is_err());
}

#[cfg(unix)]
#[test]
fn group_accessible_roots_are_rejected() {
    let directory = artifact_directory();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o750))
        .expect("test should loosen artifact root permissions");

    assert!(FilesystemArtifactStore::open(directory.path()).is_err());
}

#[cfg(unix)]
#[test]
fn group_accessible_store_children_are_rejected() {
    let directory = artifact_directory();
    let multipart = directory.path().join(".multipart");
    std::fs::create_dir(&multipart).expect("test multipart directory should be created");
    std::fs::set_permissions(&multipart, std::fs::Permissions::from_mode(0o770))
        .expect("test should loosen multipart permissions");

    assert!(FilesystemArtifactStore::open(directory.path()).is_err());
}
