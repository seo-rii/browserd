#![allow(clippy::expect_used)]

mod common;

use std::sync::{Arc, Mutex};

use browserd_artifacts::{
    ArtifactMultipartStore, ArtifactQuota, ArtifactStoreError, ArtifactWriteError,
    MultipartUploadId, QuotaLimits, ReservationAbortOutcome, StreamingArtifactWriter,
    WriterAbortOutcome,
};
use bytes::Bytes;

use common::artifact_fixture;

#[derive(Clone, Default)]
struct RecordingStore {
    state: Arc<Mutex<RecordingStoreState>>,
}

#[derive(Default)]
struct RecordingStoreState {
    partial_exists: bool,
    partial_bytes: Vec<u8>,
    abort_calls: usize,
    complete_calls: usize,
}

impl ArtifactMultipartStore for RecordingStore {
    async fn begin(
        &self,
        _key: &browserd_artifacts::ArtifactKey,
    ) -> Result<MultipartUploadId, ArtifactStoreError> {
        let mut state = self
            .state
            .lock()
            .expect("recording store lock should not be poisoned");
        state.partial_exists = true;
        Ok(MultipartUploadId::new("test-multipart"))
    }

    async fn append(
        &self,
        _upload_id: &MultipartUploadId,
        chunk: Bytes,
    ) -> Result<(), ArtifactStoreError> {
        self.state
            .lock()
            .expect("recording store lock should not be poisoned")
            .partial_bytes
            .extend_from_slice(&chunk);
        Ok(())
    }

    async fn complete(&self, _upload_id: &MultipartUploadId) -> Result<(), ArtifactStoreError> {
        let mut state = self
            .state
            .lock()
            .expect("recording store lock should not be poisoned");
        state.partial_exists = false;
        state.complete_calls += 1;
        Ok(())
    }

    async fn abort(&self, _upload_id: &MultipartUploadId) -> Result<(), ArtifactStoreError> {
        let mut state = self
            .state
            .lock()
            .expect("recording store lock should not be poisoned");
        state.partial_exists = false;
        state.partial_bytes.clear();
        state.abort_calls += 1;
        Ok(())
    }
}

#[tokio::test]
async fn crossing_the_stream_limit_aborts_the_partial_object_and_releases_quota() {
    let fixture = artifact_fixture();
    let quota = ArtifactQuota::new(
        fixture.namespace,
        QuotaLimits {
            max_committed_bytes: 5,
            max_in_flight_bytes: 5,
        },
    );
    let reservation = quota
        .reserve(fixture.key, 5)
        .await
        .expect("stream reservation should succeed");
    let store = RecordingStore::default();
    let mut writer = StreamingArtifactWriter::begin(reservation, store.clone())
        .await
        .expect("multipart writer should begin");

    writer
        .write_chunk(Bytes::from_static(b"1234"))
        .await
        .expect("chunk within reservation should be written");
    assert!(matches!(
        writer.write_chunk(Bytes::from_static(b"56")).await,
        Err(ArtifactWriteError::Quota(_))
    ));

    {
        let state = store
            .state
            .lock()
            .expect("recording store lock should not be poisoned");
        assert!(!state.partial_exists);
        assert!(state.partial_bytes.is_empty());
        assert_eq!(state.abort_calls, 1);
    }

    let snapshot = quota.snapshot().await;
    assert_eq!(snapshot.reserved_bytes, 0);
    assert_eq!(snapshot.actual_bytes_in_flight, 0);
    assert_eq!(snapshot.active_reservations, 0);

    assert_eq!(
        writer
            .abort()
            .await
            .expect("repeat writer abort should be idempotent"),
        WriterAbortOutcome::AlreadyAborted
    );
    assert_eq!(
        store
            .state
            .lock()
            .expect("recording store lock should not be poisoned")
            .abort_calls,
        1
    );
}

#[tokio::test]
async fn explicit_abort_is_idempotent_and_cleans_a_written_partial() {
    let fixture = artifact_fixture();
    let quota = ArtifactQuota::new(
        fixture.namespace,
        QuotaLimits {
            max_committed_bytes: 10,
            max_in_flight_bytes: 10,
        },
    );
    let reservation = quota
        .reserve(fixture.key, 10)
        .await
        .expect("stream reservation should succeed");
    let store = RecordingStore::default();
    let mut writer = StreamingArtifactWriter::begin(reservation, store.clone())
        .await
        .expect("multipart writer should begin");

    writer
        .write_chunk(Bytes::from_static(b"partial"))
        .await
        .expect("partial chunk should be written");
    assert_eq!(
        writer
            .abort()
            .await
            .expect("first writer abort should succeed"),
        WriterAbortOutcome::Aborted
    );
    assert_eq!(
        writer
            .abort()
            .await
            .expect("repeat writer abort should be idempotent"),
        WriterAbortOutcome::AlreadyAborted
    );

    {
        let state = store
            .state
            .lock()
            .expect("recording store lock should not be poisoned");
        assert!(!state.partial_exists);
        assert!(state.partial_bytes.is_empty());
        assert_eq!(state.abort_calls, 1);
    }

    assert_eq!(quota.snapshot().await.reserved_bytes, 0);
    assert_eq!(quota.snapshot().await.actual_bytes_in_flight, 0);
}

#[tokio::test]
async fn successful_finish_finalizes_once_and_commits_the_actual_byte_count() {
    let fixture = artifact_fixture();
    let quota = ArtifactQuota::new(
        fixture.namespace,
        QuotaLimits {
            max_committed_bytes: 10,
            max_in_flight_bytes: 10,
        },
    );
    let reservation = quota
        .reserve(fixture.key, 10)
        .await
        .expect("stream reservation should succeed");
    let store = RecordingStore::default();
    let mut writer = StreamingArtifactWriter::begin(reservation, store.clone())
        .await
        .expect("multipart writer should begin");

    writer
        .write_chunk(Bytes::from_static(b"done"))
        .await
        .expect("final chunk should be written");
    writer.finish().await.expect("first finish should succeed");
    writer
        .finish()
        .await
        .expect("repeat finish should be idempotent");

    {
        let state = store
            .state
            .lock()
            .expect("recording store lock should not be poisoned");
        assert!(!state.partial_exists);
        assert_eq!(state.complete_calls, 1);
        assert_eq!(state.abort_calls, 0);
    }

    let snapshot = quota.snapshot().await;
    assert_eq!(snapshot.committed_bytes, 4);
    assert_eq!(snapshot.reserved_bytes, 0);
    assert_eq!(snapshot.actual_bytes_in_flight, 0);
}

#[allow(dead_code)]
fn reservation_abort_outcome_remains_part_of_the_streaming_contract(
    outcome: ReservationAbortOutcome,
) -> bool {
    matches!(
        outcome,
        ReservationAbortOutcome::Aborted | ReservationAbortOutcome::AlreadyAborted
    )
}
