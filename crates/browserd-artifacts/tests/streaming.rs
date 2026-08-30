#![allow(clippy::expect_used)]

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use browserd_artifacts::{
    ArtifactChecksum, ArtifactMultipartStore, ArtifactQuota, ArtifactStoreError,
    ArtifactWriteError, ArtifactWriteReceipt, MultipartUploadId, QuotaLimits,
    ReservationAbortOutcome, StreamingArtifactWriter, WriterAbortOutcome,
};
use bytes::Bytes;
use sha2::{Digest, Sha256};
use tokio::sync::Notify;

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
    abort_failures_remaining: usize,
    complete_calls: usize,
    verified_receipt: Option<ArtifactWriteReceipt>,
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

    async fn complete_verified(
        &self,
        _upload_id: &MultipartUploadId,
        receipt: &ArtifactWriteReceipt,
    ) -> Result<(), ArtifactStoreError> {
        let mut state = self
            .state
            .lock()
            .expect("recording store lock should not be poisoned");
        let actual = ArtifactChecksum::new(Sha256::digest(&state.partial_bytes).into());
        if receipt.size_bytes()
            != u64::try_from(state.partial_bytes.len()).expect("test content length should fit u64")
            || receipt.checksum() != &actual
        {
            return Err(ArtifactStoreError::new("integrity metadata mismatch"));
        }
        state.partial_exists = false;
        state.complete_calls += 1;
        state.verified_receipt = Some(receipt.clone());
        Ok(())
    }

    async fn abort(&self, _upload_id: &MultipartUploadId) -> Result<(), ArtifactStoreError> {
        let mut state = self
            .state
            .lock()
            .expect("recording store lock should not be poisoned");
        state.abort_calls += 1;
        if state.abort_failures_remaining > 0 {
            state.abort_failures_remaining -= 1;
            return Err(ArtifactStoreError::new("injected abort failure"));
        }
        state.partial_exists = false;
        state.partial_bytes.clear();
        Ok(())
    }
}

#[derive(Clone, Default)]
struct PausingAppendStore {
    inner: RecordingStore,
    append_reached: Arc<Notify>,
}

impl ArtifactMultipartStore for PausingAppendStore {
    async fn begin(
        &self,
        key: &browserd_artifacts::ArtifactKey,
    ) -> Result<MultipartUploadId, ArtifactStoreError> {
        self.inner.begin(key).await
    }

    async fn append(
        &self,
        upload_id: &MultipartUploadId,
        chunk: Bytes,
    ) -> Result<(), ArtifactStoreError> {
        self.inner.append(upload_id, chunk).await?;
        self.append_reached.notify_one();
        std::future::pending().await
    }

    async fn complete_verified(
        &self,
        upload_id: &MultipartUploadId,
        receipt: &ArtifactWriteReceipt,
    ) -> Result<(), ArtifactStoreError> {
        self.inner.complete_verified(upload_id, receipt).await
    }

    async fn abort(&self, upload_id: &MultipartUploadId) -> Result<(), ArtifactStoreError> {
        self.inner.abort(upload_id).await
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
        .reserve(fixture.key.clone(), 10)
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
        .reserve(fixture.key.clone(), 10)
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
    let first_receipt = writer.finish().await.expect("first finish should succeed");
    let replayed_receipt = writer
        .finish()
        .await
        .expect("repeat finish should be idempotent");
    assert_eq!(first_receipt, replayed_receipt);
    assert_eq!(first_receipt.size_bytes(), 4);
    assert_eq!(first_receipt.key(), &fixture.key);
    assert_eq!(
        first_receipt.checksum(),
        &ArtifactChecksum::new(Sha256::digest(b"done").into())
    );

    {
        let state = store
            .state
            .lock()
            .expect("recording store lock should not be poisoned");
        assert!(!state.partial_exists);
        assert_eq!(state.complete_calls, 1);
        assert_eq!(state.abort_calls, 0);
        assert_eq!(state.verified_receipt.as_ref(), Some(&first_receipt));
    }

    let snapshot = quota.snapshot().await;
    assert_eq!(snapshot.committed_bytes, 4);
    assert_eq!(snapshot.reserved_bytes, 0);
    assert_eq!(snapshot.actual_bytes_in_flight, 0);
}

#[tokio::test]
async fn checksum_covers_the_exact_successfully_appended_chunk_sequence() {
    let fixture = artifact_fixture();
    let quota = ArtifactQuota::new(
        fixture.namespace,
        QuotaLimits {
            max_committed_bytes: 10,
            max_in_flight_bytes: 10,
        },
    );
    let reservation = quota
        .reserve(fixture.key.clone(), 10)
        .await
        .expect("stream reservation should succeed");
    let store = RecordingStore::default();
    let mut writer = StreamingArtifactWriter::begin(reservation, store)
        .await
        .expect("multipart writer should begin");

    writer
        .write_chunk(Bytes::from_static(b"ab"))
        .await
        .expect("first chunk should be persisted");
    writer
        .write_chunk(Bytes::from_static(b"cd"))
        .await
        .expect("second chunk should be persisted");
    let receipt = writer.finish().await.expect("writer should finish");

    assert_eq!(receipt.key(), &fixture.key);
    assert_eq!(receipt.size_bytes(), 4);
    assert_eq!(
        receipt.checksum(),
        &ArtifactChecksum::new(Sha256::digest(b"abcd").into())
    );
}

#[tokio::test]
async fn failed_partial_cleanup_remains_retryable_without_holding_quota() {
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
    store
        .state
        .lock()
        .expect("recording store lock should not be poisoned")
        .abort_failures_remaining = 1;
    let mut writer = StreamingArtifactWriter::begin(reservation, store.clone())
        .await
        .expect("multipart writer should begin");
    writer
        .write_chunk(Bytes::from_static(b"partial"))
        .await
        .expect("partial chunk should be persisted");

    assert!(matches!(
        writer.abort().await,
        Err(ArtifactWriteError::Store(_))
    ));
    assert_eq!(quota.snapshot().await.reserved_bytes, 0);
    assert!(
        store
            .state
            .lock()
            .expect("recording store lock should not be poisoned")
            .partial_exists,
        "the failed store cleanup still needs a retry"
    );

    assert_eq!(
        writer.abort().await.expect("cleanup retry should succeed"),
        WriterAbortOutcome::Aborted
    );
    assert_eq!(
        writer
            .abort()
            .await
            .expect("completed cleanup replay should be idempotent"),
        WriterAbortOutcome::AlreadyAborted
    );
    let state = store
        .state
        .lock()
        .expect("recording store lock should not be poisoned");
    assert!(!state.partial_exists);
    assert_eq!(state.abort_calls, 2);
}

#[tokio::test]
async fn cancelling_an_in_flight_chunk_fences_finish_until_explicit_abort() {
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
    let store = PausingAppendStore::default();
    let mut writer = StreamingArtifactWriter::begin(reservation, store.clone())
        .await
        .expect("multipart writer should begin");

    {
        let write = writer.write_chunk(Bytes::from_static(b"lost"));
        tokio::pin!(write);
        tokio::select! {
            result = &mut write => panic!("injected append should remain pending: {result:?}"),
            () = store.append_reached.notified() => {}
        }
    }

    assert!(
        matches!(writer.finish().await, Err(ArtifactWriteError::Closed)),
        "a cancelled chunk must make the writer non-finishable"
    );
    assert_eq!(
        writer
            .abort()
            .await
            .expect("cancelled chunk cleanup should remain available"),
        WriterAbortOutcome::Aborted
    );
    let snapshot = quota.snapshot().await;
    assert_eq!(snapshot.committed_bytes, 0);
    assert_eq!(snapshot.reserved_bytes, 0);
    assert_eq!(snapshot.actual_bytes_in_flight, 0);
    let state = store
        .inner
        .state
        .lock()
        .expect("recording store lock should not be poisoned");
    assert!(!state.partial_exists);
    assert_eq!(state.complete_calls, 0);
    assert_eq!(state.abort_calls, 1);
}

#[tokio::test]
async fn dropping_a_writer_after_chunk_cancellation_schedules_partial_cleanup() {
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
    let store = PausingAppendStore::default();
    let mut writer = StreamingArtifactWriter::begin(reservation, store.clone())
        .await
        .expect("multipart writer should begin");
    {
        let write = writer.write_chunk(Bytes::from_static(b"orphan"));
        tokio::pin!(write);
        tokio::select! {
            result = &mut write => panic!("injected append should remain pending: {result:?}"),
            () = store.append_reached.notified() => {}
        }
    }

    drop(writer);

    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let cleaned = {
                let state = store
                    .inner
                    .state
                    .lock()
                    .expect("recording store lock should not be poisoned");
                !state.partial_exists && state.abort_calls == 1
            };
            if cleaned {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("writer drop should schedule bounded partial cleanup");
    let snapshot = quota.snapshot().await;
    assert_eq!(snapshot.committed_bytes, 0);
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
