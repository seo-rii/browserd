#![allow(clippy::expect_used)]

mod common;

use std::sync::Arc;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use browserd_artifacts::{
    ArtifactChunkReader, ArtifactContentMetadata, ArtifactContentSource, ArtifactDeleteOutcome,
    ArtifactMultipartStore, ArtifactObjectError, ArtifactObjectGeneration, ArtifactObjectStore,
    ArtifactQuota, ArtifactReadLimits, ArtifactWriteReceipt, FilesystemArtifactStore, QuotaLimits,
    StreamingArtifactWriter,
};
use browserd_core::{ArtifactId, TenantId};
use bytes::Bytes;
use common::{artifact_fixture, artifact_key};
use sha2::{Digest, Sha256};

fn artifact_directory() -> tempfile::TempDir {
    let directory = tempfile::tempdir().expect("artifact directory should be created");
    #[cfg(unix)]
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
        .expect("artifact directory should be private");
    directory
}

async fn commit_object(
    store: &FilesystemArtifactStore,
    namespace: &browserd_artifacts::ArtifactNamespace,
    key: &browserd_artifacts::ArtifactKey,
    bytes: &'static [u8],
) -> (ArtifactWriteReceipt, ArtifactContentMetadata) {
    let limit = u64::try_from(bytes.len()).expect("fixture length should fit u64");
    let quota = ArtifactQuota::new(
        namespace.clone(),
        QuotaLimits {
            max_committed_bytes: limit,
            max_in_flight_bytes: limit,
        },
    );
    let reservation = quota
        .reserve(key.clone(), limit)
        .await
        .expect("fixture reservation should succeed");
    let mut writer = StreamingArtifactWriter::begin(reservation, store.clone())
        .await
        .expect("fixture multipart upload should begin");
    writer
        .write_chunk(Bytes::from_static(bytes))
        .await
        .expect("fixture bytes should append");
    let receipt = writer.finish().await.expect("fixture should commit");
    let metadata = ArtifactContentMetadata::new(
        receipt.size_bytes(),
        *receipt.checksum(),
        "application/octet-stream",
        ArtifactContentSource::Generated,
        "object-store-contract",
    )
    .expect("fixture metadata should validate");
    (receipt, metadata)
}

fn different_generation(current: ArtifactObjectGeneration) -> ArtifactObjectGeneration {
    let mut bytes = *current.as_bytes();
    bytes[0] ^= 0xff;
    ArtifactObjectGeneration::new(bytes)
}

#[tokio::test]
async fn committed_object_reopens_and_reads_only_as_bounded_chunks_under_the_exact_fence() {
    let directory = artifact_directory();
    let fixture = artifact_fixture();
    let store = FilesystemArtifactStore::open(directory.path())
        .expect("absolute artifact root should open");
    let expected = b"bounded artifact stream";
    let (receipt, metadata) =
        commit_object(&store, &fixture.namespace, &fixture.key, expected).await;
    let generation = receipt.object_generation();
    drop(store);

    let reopened = FilesystemArtifactStore::open(directory.path())
        .expect("committed artifact store should reopen");
    let limits = ArtifactReadLimits::new(4).expect("four-byte chunks should be bounded");
    let mut reader = reopened
        .open_read(
            &fixture.namespace,
            &fixture.key,
            generation,
            &metadata,
            limits,
        )
        .await
        .expect("exact committed object fence should open");

    let mut reconstructed = Vec::new();
    let mut chunks = 0;
    while let Some(chunk) = reader
        .next_chunk()
        .await
        .expect("verified chunk should read")
    {
        assert!(!chunk.is_empty());
        assert!(chunk.len() <= limits.max_chunk_bytes());
        chunks += 1;
        reconstructed.extend_from_slice(&chunk);
    }

    assert!(
        chunks > 1,
        "the API must not return the whole object as one Vec"
    );
    assert_eq!(reconstructed, expected);
    assert_eq!(
        reader.next_chunk().await,
        Ok(None),
        "end-of-stream retries must stay terminal"
    );
    assert_eq!(
        ArtifactReadLimits::new(0),
        Err(ArtifactObjectError::InvalidBounds)
    );
    assert_eq!(
        ArtifactReadLimits::new(usize::MAX),
        Err(ArtifactObjectError::InvalidBounds)
    );
}

#[tokio::test]
async fn read_rejects_cross_tenant_missing_and_generation_mismatch_before_disclosing_bytes() {
    let directory = artifact_directory();
    let fixture = artifact_fixture();
    let store = FilesystemArtifactStore::open(directory.path())
        .expect("absolute artifact root should open");
    let (receipt, metadata) =
        commit_object(&store, &fixture.namespace, &fixture.key, b"tenant-secret").await;
    let generation = receipt.object_generation();
    let limits = ArtifactReadLimits::new(4).expect("read limits should validate");
    let missing_key = artifact_key(&fixture.namespace);
    let alien_namespace = browserd_artifacts::ArtifactNamespace::new(
        TenantId::new(),
        fixture.namespace.session_id().clone(),
    );
    let alien_session_namespace = browserd_artifacts::ArtifactNamespace::new(
        fixture.namespace.tenant_id().clone(),
        browserd_core::SessionId::new(),
    );

    assert!(matches!(
        store
            .open_read(
                &alien_namespace,
                &fixture.key,
                generation,
                &metadata,
                limits,
            )
            .await,
        Err(ArtifactObjectError::NamespaceDenied)
    ));
    assert!(matches!(
        store
            .open_read(
                &alien_session_namespace,
                &fixture.key,
                generation,
                &metadata,
                limits,
            )
            .await,
        Err(ArtifactObjectError::NamespaceDenied)
    ));
    assert!(matches!(
        store
            .open_read(
                &fixture.namespace,
                &missing_key,
                generation,
                &metadata,
                limits,
            )
            .await,
        Err(ArtifactObjectError::NotAvailable)
    ));
    assert!(matches!(
        store
            .open_read(
                &fixture.namespace,
                &fixture.key,
                different_generation(generation),
                &metadata,
                limits,
            )
            .await,
        Err(ArtifactObjectError::GenerationMismatch)
    ));
}

#[tokio::test]
async fn size_or_checksum_mismatch_fails_before_a_reader_can_expose_any_chunk() {
    let directory = artifact_directory();
    let fixture = artifact_fixture();
    let store = FilesystemArtifactStore::open(directory.path())
        .expect("absolute artifact root should open");
    let (checksum_receipt, checksum_metadata) =
        commit_object(&store, &fixture.namespace, &fixture.key, b"integrity").await;
    let checksum_path = directory
        .path()
        .join("objects")
        .join(fixture.key.tenant_id().to_string())
        .join(fixture.key.session_id().to_string())
        .join(fixture.key.artifact_id().to_string())
        .join("data");
    std::fs::write(checksum_path, b"corrupted").expect("test should corrupt committed bytes");

    assert!(matches!(
        store
            .open_read(
                &fixture.namespace,
                &fixture.key,
                checksum_receipt.object_generation(),
                &checksum_metadata,
                ArtifactReadLimits::new(4).expect("read limits should validate"),
            )
            .await,
        Err(ArtifactObjectError::IntegrityMismatch)
    ));

    let size_key = artifact_key(&fixture.namespace);
    let (size_receipt, size_metadata) =
        commit_object(&store, &fixture.namespace, &size_key, b"size").await;
    let size_path = directory
        .path()
        .join("objects")
        .join(size_key.tenant_id().to_string())
        .join(size_key.session_id().to_string())
        .join(size_key.artifact_id().to_string())
        .join("data");
    std::fs::write(size_path, b"size-extra").expect("test should change committed size");

    assert!(matches!(
        store
            .open_read(
                &fixture.namespace,
                &size_key,
                size_receipt.object_generation(),
                &size_metadata,
                ArtifactReadLimits::new(4).expect("read limits should validate"),
            )
            .await,
        Err(ArtifactObjectError::IntegrityMismatch)
    ));
}

#[tokio::test]
async fn delete_is_an_exact_generation_cas_with_one_concurrent_effect_and_idempotent_retry() {
    let directory = artifact_directory();
    let fixture = artifact_fixture();
    let store = FilesystemArtifactStore::open(directory.path())
        .expect("absolute artifact root should open");
    let (receipt, metadata) =
        commit_object(&store, &fixture.namespace, &fixture.key, b"delete-once").await;
    let generation = receipt.object_generation();
    let stale_generation = different_generation(generation);
    let alien_namespace = browserd_artifacts::ArtifactNamespace::new(
        TenantId::new(),
        fixture.namespace.session_id().clone(),
    );

    assert_eq!(
        store
            .delete_exact(&alien_namespace, &fixture.key, generation)
            .await,
        Err(ArtifactObjectError::NamespaceDenied)
    );
    assert_eq!(
        store
            .delete_exact(&fixture.namespace, &fixture.key, stale_generation)
            .await,
        Err(ArtifactObjectError::GenerationMismatch)
    );
    assert!(
        store
            .open_read(
                &fixture.namespace,
                &fixture.key,
                generation,
                &metadata,
                ArtifactReadLimits::new(4).expect("read limits should validate"),
            )
            .await
            .is_ok(),
        "denied deletes must have no effect"
    );

    let barrier = Arc::new(tokio::sync::Barrier::new(3));
    let left_store = store.clone();
    let left_namespace = fixture.namespace.clone();
    let left_key = fixture.key.clone();
    let left_barrier = Arc::clone(&barrier);
    let left = tokio::spawn(async move {
        left_barrier.wait().await;
        left_store
            .delete_exact(&left_namespace, &left_key, generation)
            .await
    });
    let right_store = store.clone();
    let right_namespace = fixture.namespace.clone();
    let right_key = fixture.key.clone();
    let right_barrier = Arc::clone(&barrier);
    let right = tokio::spawn(async move {
        right_barrier.wait().await;
        right_store
            .delete_exact(&right_namespace, &right_key, generation)
            .await
    });
    barrier.wait().await;

    let outcomes = [
        left.await
            .expect("left delete task should join")
            .expect("left exact delete should resolve"),
        right
            .await
            .expect("right delete task should join")
            .expect("right exact delete should resolve"),
    ];
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == ArtifactDeleteOutcome::Deleted)
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == ArtifactDeleteOutcome::AlreadyDeleted)
            .count(),
        1
    );
    drop(store);
    let reopened = FilesystemArtifactStore::open(directory.path())
        .expect("deleted artifact store should reopen");
    assert_eq!(
        reopened
            .delete_exact(&fixture.namespace, &fixture.key, generation)
            .await,
        Ok(ArtifactDeleteOutcome::AlreadyDeleted)
    );
    assert_eq!(
        reopened
            .delete_exact(&fixture.namespace, &fixture.key, stale_generation)
            .await,
        Err(ArtifactObjectError::GenerationMismatch)
    );
    assert!(matches!(
        reopened
            .open_read(
                &fixture.namespace,
                &fixture.key,
                generation,
                &metadata,
                ArtifactReadLimits::new(4).expect("read limits should validate"),
            )
            .await,
        Err(ArtifactObjectError::NotAvailable)
    ));
}

#[tokio::test]
async fn recreated_key_uses_a_fresh_generation_and_stale_deletes_cannot_remove_it() {
    let directory = artifact_directory();
    let fixture = artifact_fixture();
    let store = FilesystemArtifactStore::open(directory.path())
        .expect("absolute artifact root should open");
    let bytes = b"same object bytes";
    let (first_receipt, _) = commit_object(&store, &fixture.namespace, &fixture.key, bytes).await;
    let first_generation = first_receipt.object_generation();
    assert_eq!(
        store
            .delete_exact(&fixture.namespace, &fixture.key, first_generation)
            .await,
        Ok(ArtifactDeleteOutcome::Deleted)
    );

    let (second_receipt, second_metadata) =
        commit_object(&store, &fixture.namespace, &fixture.key, bytes).await;
    let second_generation = second_receipt.object_generation();
    assert_ne!(
        second_generation, first_generation,
        "generation identifies the incarnation, not only the key and bytes"
    );
    assert_eq!(
        store
            .delete_exact(&fixture.namespace, &fixture.key, first_generation)
            .await,
        Err(ArtifactObjectError::GenerationMismatch),
        "an exact retry stops being current after the key is recreated"
    );
    let mut second_reader = store
        .open_read(
            &fixture.namespace,
            &fixture.key,
            second_generation,
            &second_metadata,
            ArtifactReadLimits::new(3).expect("read limits should validate"),
        )
        .await
        .expect("the stale delete must leave the replacement readable");
    let mut second_bytes = Vec::new();
    while let Some(chunk) = second_reader
        .next_chunk()
        .await
        .expect("replacement chunks should read")
    {
        second_bytes.extend_from_slice(&chunk);
    }
    assert_eq!(second_bytes, bytes);
    assert_eq!(
        store
            .delete_exact(&fixture.namespace, &fixture.key, second_generation)
            .await,
        Ok(ArtifactDeleteOutcome::Deleted)
    );

    let different_bytes = b"different object bytes";
    let (third_receipt, third_metadata) =
        commit_object(&store, &fixture.namespace, &fixture.key, different_bytes).await;
    let third_generation = third_receipt.object_generation();
    assert_ne!(third_generation, first_generation);
    assert_ne!(third_generation, second_generation);
    for stale_generation in [first_generation, second_generation] {
        assert_eq!(
            store
                .delete_exact(&fixture.namespace, &fixture.key, stale_generation)
                .await,
            Err(ArtifactObjectError::GenerationMismatch)
        );
    }
    let mut third_reader = store
        .open_read(
            &fixture.namespace,
            &fixture.key,
            third_generation,
            &third_metadata,
            ArtifactReadLimits::new(4).expect("read limits should validate"),
        )
        .await
        .expect("stale generations must not remove the current object");
    let mut third_bytes = Vec::new();
    while let Some(chunk) = third_reader
        .next_chunk()
        .await
        .expect("current chunks should read")
    {
        third_bytes.extend_from_slice(&chunk);
    }
    assert_eq!(third_bytes, different_bytes);
    assert_eq!(
        store
            .delete_exact(&fixture.namespace, &fixture.key, third_generation)
            .await,
        Ok(ArtifactDeleteOutcome::Deleted)
    );
}

#[tokio::test]
async fn partial_multipart_bytes_are_never_visible_as_a_committed_object() {
    let directory = artifact_directory();
    let fixture = artifact_fixture();
    let store = FilesystemArtifactStore::open(directory.path())
        .expect("absolute artifact root should open");
    let upload_id = store
        .begin(&fixture.key)
        .await
        .expect("partial multipart should begin");
    let partial = Bytes::from_static(b"not committed");
    store
        .append(&upload_id, partial.clone())
        .await
        .expect("partial bytes should append");
    let checksum = ArtifactContentMetadata::new(
        u64::try_from(partial.len()).expect("partial length should fit u64"),
        browserd_artifacts::ArtifactChecksum::new(Sha256::digest(&partial).into()),
        "application/octet-stream",
        ArtifactContentSource::Generated,
        "partial-object-contract",
    )
    .expect("partial metadata should validate");

    assert!(matches!(
        store
            .open_read(
                &fixture.namespace,
                &fixture.key,
                ArtifactObjectGeneration::new([7; 32]),
                &checksum,
                ArtifactReadLimits::new(4).expect("read limits should validate"),
            )
            .await,
        Err(ArtifactObjectError::NotAvailable)
    ));
    assert_eq!(
        store
            .delete_exact(
                &fixture.namespace,
                &fixture.key,
                ArtifactObjectGeneration::new([7; 32]),
            )
            .await,
        Err(ArtifactObjectError::NotAvailable)
    );

    store
        .abort(&upload_id)
        .await
        .expect("partial multipart cleanup should succeed");
    let missing = browserd_artifacts::ArtifactKey::new(
        fixture.namespace.tenant_id().clone(),
        fixture.namespace.session_id().clone(),
        ArtifactId::new(),
    );
    assert_eq!(
        store
            .delete_exact(
                &fixture.namespace,
                &missing,
                ArtifactObjectGeneration::new([9; 32]),
            )
            .await,
        Err(ArtifactObjectError::NotAvailable)
    );
}
