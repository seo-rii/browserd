use std::fmt;
use std::future::Future;
use std::time::Duration;

use bytes::Bytes;
use sha2::{Digest, Sha256};

use crate::{
    ArtifactChecksum, ArtifactKey, ArtifactObjectGeneration, ArtifactReservation, QuotaError,
};

const OBJECT_GENERATION_DOMAIN: &[u8] = b"browserd:artifact-object-generation:v1\0";

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct MultipartUploadId(String);

impl MultipartUploadId {
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactStoreError {
    message: String,
    completion_uncertain: bool,
}

impl ArtifactStoreError {
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            completion_uncertain: false,
        }
    }

    /// Reports that completion may already be externally visible but has not
    /// yet passed the backend's durability/reconciliation barrier.
    ///
    /// The streaming writer retries this exact completion without releasing
    /// its quota reservation. Implementations must use this only when retrying
    /// the same upload and receipt is safe.
    #[must_use]
    pub fn completion_uncertain(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            completion_uncertain: true,
        }
    }

    #[must_use]
    pub const fn is_completion_uncertain(&self) -> bool {
        self.completion_uncertain
    }
}

impl fmt::Display for ArtifactStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ArtifactStoreError {}

/// Multipart storage must make verified completion an explicit operation.
///
/// An implementation that provides only an unverified completion primitive is
/// deliberately incomplete:
///
/// ```compile_fail
/// use browserd_artifacts::{
///     ArtifactKey, ArtifactMultipartStore, ArtifactStoreError, MultipartUploadId,
/// };
/// use bytes::Bytes;
///
/// struct UnverifiedStore;
///
/// impl ArtifactMultipartStore for UnverifiedStore {
///     async fn begin(
///         &self,
///         _key: &ArtifactKey,
///     ) -> Result<MultipartUploadId, ArtifactStoreError> {
///         unimplemented!()
///     }
///
///     async fn append(
///         &self,
///         _upload_id: &MultipartUploadId,
///         _chunk: Bytes,
///     ) -> Result<(), ArtifactStoreError> {
///         unimplemented!()
///     }
///
///     async fn abort(
///         &self,
///         _upload_id: &MultipartUploadId,
///     ) -> Result<(), ArtifactStoreError> {
///         Ok(())
///     }
/// }
/// ```
pub trait ArtifactMultipartStore: Send + Sync {
    /// Begins an upload and returns an identifier that must never be reused for
    /// another object incarnation under the same artifact key.
    fn begin(
        &self,
        key: &ArtifactKey,
    ) -> impl Future<Output = Result<MultipartUploadId, ArtifactStoreError>> + Send;

    fn append(
        &self,
        upload_id: &MultipartUploadId,
        chunk: Bytes,
    ) -> impl Future<Output = Result<(), ArtifactStoreError>> + Send;

    /// Atomically commits the multipart object with the expected byte count
    /// and checksum. The implementation must consume the receipt, reject a
    /// mismatch, and persist the verified metadata with the committed object.
    fn complete_verified(
        &self,
        upload_id: &MultipartUploadId,
        receipt: &ArtifactWriteReceipt,
    ) -> impl Future<Output = Result<(), ArtifactStoreError>> + Send;

    fn abort(
        &self,
        upload_id: &MultipartUploadId,
    ) -> impl Future<Output = Result<(), ArtifactStoreError>> + Send;
}

#[derive(Debug)]
pub enum ArtifactWriteError {
    Quota(QuotaError),
    Store(ArtifactStoreError),
    StoreAndCleanup {
        operation: ArtifactStoreError,
        cleanup: ArtifactStoreError,
    },
    Closed,
    SizeOverflow,
}

impl fmt::Display for ArtifactWriteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Quota(error) => write!(formatter, "artifact quota error: {error}"),
            Self::Store(error) => write!(formatter, "artifact store error: {error}"),
            Self::StoreAndCleanup { operation, cleanup } => write!(
                formatter,
                "artifact store operation failed ({operation}); partial cleanup also failed ({cleanup})"
            ),
            Self::Closed => formatter.write_str("artifact stream writer is closed"),
            Self::SizeOverflow => formatter.write_str("artifact stream chunk size overflowed"),
        }
    }
}

impl std::error::Error for ArtifactWriteError {}

impl From<QuotaError> for ArtifactWriteError {
    fn from(error: QuotaError) -> Self {
        Self::Quota(error)
    }
}

impl From<ArtifactStoreError> for ArtifactWriteError {
    fn from(error: ArtifactStoreError) -> Self {
        Self::Store(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WriterState {
    Open,
    Writing,
    Finishing,
    CleanupPending,
    Finished,
    Aborted,
}

struct FinishTaskResult<S> {
    store: S,
    reservation: ArtifactReservation,
    state: WriterState,
    result: Result<ArtifactWriteReceipt, ArtifactWriteError>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriterAbortOutcome {
    Aborted,
    AlreadyAborted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactWriteReceipt {
    pub(crate) key: ArtifactKey,
    pub(crate) size_bytes: u64,
    pub(crate) checksum: ArtifactChecksum,
    pub(crate) object_generation: ArtifactObjectGeneration,
}

impl ArtifactWriteReceipt {
    #[must_use]
    pub const fn key(&self) -> &ArtifactKey {
        &self.key
    }

    #[must_use]
    pub const fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    #[must_use]
    pub const fn checksum(&self) -> &ArtifactChecksum {
        &self.checksum
    }

    #[must_use]
    pub const fn object_generation(&self) -> ArtifactObjectGeneration {
        self.object_generation
    }
}

pub struct StreamingArtifactWriter<S>
where
    S: ArtifactMultipartStore + 'static,
{
    reservation: Option<ArtifactReservation>,
    store: Option<S>,
    upload_id: MultipartUploadId,
    state: WriterState,
    hasher: Sha256,
    bytes_written: u64,
    receipt: Option<ArtifactWriteReceipt>,
    finish_task: Option<tokio::task::JoinHandle<FinishTaskResult<S>>>,
}

impl<S> Drop for StreamingArtifactWriter<S>
where
    S: ArtifactMultipartStore + 'static,
{
    fn drop(&mut self) {
        if matches!(
            self.state,
            WriterState::Finishing | WriterState::Finished | WriterState::Aborted
        ) {
            return;
        }
        let Some(store) = self.store.take() else {
            return;
        };
        let Some(reservation) = self.reservation.take() else {
            return;
        };
        let upload_id = self.upload_id.clone();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            drop(runtime.spawn(async move {
                let _ = store.abort(&upload_id).await;
                let _ = reservation.abort().await;
            }));
        }
    }
}

impl<S> StreamingArtifactWriter<S>
where
    S: ArtifactMultipartStore + 'static,
{
    pub async fn begin(
        reservation: ArtifactReservation,
        store: S,
    ) -> Result<Self, ArtifactWriteError> {
        let upload_id = store.begin(reservation.key()).await?;
        Ok(Self {
            reservation: Some(reservation),
            store: Some(store),
            upload_id,
            state: WriterState::Open,
            hasher: Sha256::new(),
            bytes_written: 0,
            receipt: None,
            finish_task: None,
        })
    }

    pub async fn write_chunk(&mut self, chunk: Bytes) -> Result<(), ArtifactWriteError> {
        if self.state != WriterState::Open {
            return Err(ArtifactWriteError::Closed);
        }

        let bytes = match u64::try_from(chunk.len()) {
            Ok(bytes) => bytes,
            Err(_) => {
                self.abort_after_failure().await?;
                return Err(ArtifactWriteError::SizeOverflow);
            }
        };
        let next_size = match self.bytes_written.checked_add(bytes) {
            Some(next_size) => next_size,
            None => {
                self.abort_after_failure().await?;
                return Err(ArtifactWriteError::SizeOverflow);
            }
        };

        if self.reservation.is_none() || self.store.is_none() {
            return Err(ArtifactWriteError::Closed);
        }
        self.state = WriterState::Writing;
        let quota_result = match self.reservation.as_ref() {
            Some(reservation) => reservation.add_actual_bytes(bytes).await,
            None => return Err(ArtifactWriteError::Closed),
        };
        if let Err(quota_error) = quota_result {
            match self.abort_after_failure().await {
                Ok(()) => return Err(ArtifactWriteError::Quota(quota_error)),
                Err(cleanup_error) => return Err(cleanup_error),
            }
        }

        let checksum_chunk = chunk.clone();
        let append_result = match self.store.as_ref() {
            Some(store) => store.append(&self.upload_id, chunk).await,
            None => return Err(ArtifactWriteError::Closed),
        };
        if let Err(operation) = append_result {
            self.state = WriterState::CleanupPending;
            let cleanup = match self.store.as_ref() {
                Some(store) => store.abort(&self.upload_id).await,
                None => return Err(ArtifactWriteError::Closed),
            };
            if let Some(reservation) = self.reservation.as_ref() {
                let _ = reservation.abort().await;
            }
            self.state = if cleanup.is_ok() {
                WriterState::Aborted
            } else {
                WriterState::CleanupPending
            };
            return match cleanup {
                Ok(()) => Err(ArtifactWriteError::Store(operation)),
                Err(cleanup) => Err(ArtifactWriteError::StoreAndCleanup { operation, cleanup }),
            };
        }

        self.hasher.update(checksum_chunk);
        self.bytes_written = next_size;
        self.state = WriterState::Open;

        Ok(())
    }

    pub async fn finish(&mut self) -> Result<ArtifactWriteReceipt, ArtifactWriteError> {
        match self.state {
            WriterState::Finished => {
                return self.receipt.clone().ok_or(ArtifactWriteError::Closed);
            }
            WriterState::Finishing => {}
            WriterState::Writing | WriterState::CleanupPending | WriterState::Aborted => {
                return Err(ArtifactWriteError::Closed);
            }
            WriterState::Open => {
                let receipt = ArtifactWriteReceipt {
                    key: self
                        .reservation
                        .as_ref()
                        .ok_or(ArtifactWriteError::Closed)?
                        .key()
                        .clone(),
                    size_bytes: self.bytes_written,
                    checksum: ArtifactChecksum::new(self.hasher.clone().finalize().into()),
                    object_generation: object_generation_for_upload_id(self.upload_id.as_str()),
                };
                let store = self.store.take().ok_or(ArtifactWriteError::Closed)?;
                let reservation = self.reservation.take().ok_or(ArtifactWriteError::Closed)?;
                let upload_id = self.upload_id.clone();
                let task_receipt = receipt.clone();
                self.state = WriterState::Finishing;
                self.finish_task = Some(tokio::spawn(async move {
                    let mut completion_retry_delay = Duration::from_millis(10);
                    let completion = loop {
                        match store.complete_verified(&upload_id, &task_receipt).await {
                            Ok(()) => break Ok(()),
                            Err(error) if error.is_completion_uncertain() => {
                                tokio::time::sleep(completion_retry_delay).await;
                                completion_retry_delay = completion_retry_delay
                                    .saturating_mul(2)
                                    .min(Duration::from_secs(1));
                            }
                            Err(error) => break Err(error),
                        }
                    };
                    let (state, result) = if let Err(operation) = completion {
                        let cleanup = store.abort(&upload_id).await;
                        let _ = reservation.abort().await;
                        let state = if cleanup.is_ok() {
                            WriterState::Aborted
                        } else {
                            WriterState::CleanupPending
                        };
                        let result = match cleanup {
                            Ok(()) => Err(ArtifactWriteError::Store(operation)),
                            Err(cleanup) => {
                                Err(ArtifactWriteError::StoreAndCleanup { operation, cleanup })
                            }
                        };
                        (state, result)
                    } else if let Err(quota_error) = reservation.commit().await {
                        let cleanup = store.abort(&upload_id).await;
                        let _ = reservation.abort().await;
                        let state = if cleanup.is_ok() {
                            WriterState::Aborted
                        } else {
                            WriterState::CleanupPending
                        };
                        let result = match cleanup {
                            Ok(()) => Err(ArtifactWriteError::Quota(quota_error)),
                            Err(cleanup) => Err(ArtifactWriteError::Store(cleanup)),
                        };
                        (state, result)
                    } else {
                        (WriterState::Finished, Ok(task_receipt))
                    };
                    FinishTaskResult {
                        store,
                        reservation,
                        state,
                        result,
                    }
                }));
            }
        }
        let joined = self
            .finish_task
            .as_mut()
            .ok_or(ArtifactWriteError::Closed)?
            .await;
        self.finish_task = None;
        let completed = joined.map_err(|error| {
            self.state = WriterState::Aborted;
            ArtifactWriteError::Store(ArtifactStoreError::new(format!(
                "artifact finish task failed: {error}"
            )))
        })?;
        self.store = Some(completed.store);
        self.reservation = Some(completed.reservation);
        self.state = completed.state;
        if let Ok(receipt) = &completed.result {
            self.receipt = Some(receipt.clone());
        }
        completed.result
    }

    pub async fn abort(&mut self) -> Result<WriterAbortOutcome, ArtifactWriteError> {
        match self.state {
            WriterState::Aborted => return Ok(WriterAbortOutcome::AlreadyAborted),
            WriterState::Finishing | WriterState::Finished => {
                return Err(ArtifactWriteError::Closed);
            }
            WriterState::Open | WriterState::Writing | WriterState::CleanupPending => {}
        }

        self.abort_after_failure().await?;
        Ok(WriterAbortOutcome::Aborted)
    }

    async fn abort_after_failure(&mut self) -> Result<(), ArtifactWriteError> {
        match self.state {
            WriterState::Aborted => return Ok(()),
            WriterState::Finishing | WriterState::Finished => {
                return Err(ArtifactWriteError::Closed);
            }
            WriterState::Open | WriterState::Writing | WriterState::CleanupPending => {}
        }

        self.state = WriterState::CleanupPending;

        let store = self.store.as_ref().ok_or(ArtifactWriteError::Closed)?;
        let reservation = self
            .reservation
            .as_ref()
            .ok_or(ArtifactWriteError::Closed)?;
        let store_result = store.abort(&self.upload_id).await;
        let quota_result = reservation.abort().await;
        self.state = if store_result.is_ok() {
            WriterState::Aborted
        } else {
            WriterState::CleanupPending
        };

        match (store_result, quota_result) {
            (Ok(()), Ok(_)) => Ok(()),
            (Err(error), _) => Err(ArtifactWriteError::Store(error)),
            (Ok(()), Err(error)) => Err(ArtifactWriteError::Quota(error)),
        }
    }
}

pub(crate) fn object_generation_for_upload_id(upload_id: &str) -> ArtifactObjectGeneration {
    let mut hasher = Sha256::new();
    hasher.update(OBJECT_GENERATION_DOMAIN);
    hasher.update(upload_id.as_bytes());
    ArtifactObjectGeneration::new(hasher.finalize().into())
}
