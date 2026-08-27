use std::fmt;

use bytes::Bytes;
use sha2::{Digest, Sha256};

use crate::{ArtifactChecksum, ArtifactKey, ArtifactReservation, QuotaError};

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
}

impl ArtifactStoreError {
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
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
#[allow(async_fn_in_trait)]
pub trait ArtifactMultipartStore: Send + Sync {
    async fn begin(&self, key: &ArtifactKey) -> Result<MultipartUploadId, ArtifactStoreError>;

    async fn append(
        &self,
        upload_id: &MultipartUploadId,
        chunk: Bytes,
    ) -> Result<(), ArtifactStoreError>;

    /// Atomically commits the multipart object with the expected byte count
    /// and checksum. The implementation must consume the receipt, reject a
    /// mismatch, and persist the verified metadata with the committed object.
    async fn complete_verified(
        &self,
        upload_id: &MultipartUploadId,
        receipt: &ArtifactWriteReceipt,
    ) -> Result<(), ArtifactStoreError>;

    async fn abort(&self, upload_id: &MultipartUploadId) -> Result<(), ArtifactStoreError>;
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
    CleanupPending,
    Finished,
    Aborted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriterAbortOutcome {
    Aborted,
    AlreadyAborted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactWriteReceipt {
    key: ArtifactKey,
    size_bytes: u64,
    checksum: ArtifactChecksum,
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
}

pub struct StreamingArtifactWriter<S> {
    reservation: ArtifactReservation,
    store: S,
    upload_id: MultipartUploadId,
    state: WriterState,
    hasher: Sha256,
    bytes_written: u64,
    receipt: Option<ArtifactWriteReceipt>,
}

impl<S> StreamingArtifactWriter<S>
where
    S: ArtifactMultipartStore,
{
    pub async fn begin(
        reservation: ArtifactReservation,
        store: S,
    ) -> Result<Self, ArtifactWriteError> {
        let upload_id = store.begin(reservation.key()).await?;
        Ok(Self {
            reservation,
            store,
            upload_id,
            state: WriterState::Open,
            hasher: Sha256::new(),
            bytes_written: 0,
            receipt: None,
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

        if let Err(quota_error) = self.reservation.add_actual_bytes(bytes).await {
            match self.abort_after_failure().await {
                Ok(()) => return Err(ArtifactWriteError::Quota(quota_error)),
                Err(cleanup_error) => return Err(cleanup_error),
            }
        }

        let checksum_chunk = chunk.clone();
        if let Err(operation) = self.store.append(&self.upload_id, chunk).await {
            let cleanup = self.store.abort(&self.upload_id).await;
            let _ = self.reservation.abort().await;
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

        Ok(())
    }

    pub async fn finish(&mut self) -> Result<ArtifactWriteReceipt, ArtifactWriteError> {
        match self.state {
            WriterState::Finished => {
                return self.receipt.clone().ok_or(ArtifactWriteError::Closed);
            }
            WriterState::CleanupPending | WriterState::Aborted => {
                return Err(ArtifactWriteError::Closed);
            }
            WriterState::Open => {}
        }

        let receipt = ArtifactWriteReceipt {
            key: self.reservation.key().clone(),
            size_bytes: self.bytes_written,
            checksum: ArtifactChecksum::new(self.hasher.clone().finalize().into()),
        };
        if let Err(operation) = self
            .store
            .complete_verified(&self.upload_id, &receipt)
            .await
        {
            let cleanup = self.store.abort(&self.upload_id).await;
            let _ = self.reservation.abort().await;
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

        if let Err(quota_error) = self.reservation.commit().await {
            let cleanup = self.store.abort(&self.upload_id).await;
            let _ = self.reservation.abort().await;
            self.state = if cleanup.is_ok() {
                WriterState::Aborted
            } else {
                WriterState::CleanupPending
            };
            return match cleanup {
                Ok(()) => Err(ArtifactWriteError::Quota(quota_error)),
                Err(cleanup) => Err(ArtifactWriteError::Store(cleanup)),
            };
        }
        self.state = WriterState::Finished;
        self.receipt = Some(receipt.clone());
        Ok(receipt)
    }

    pub async fn abort(&mut self) -> Result<WriterAbortOutcome, ArtifactWriteError> {
        match self.state {
            WriterState::Aborted => return Ok(WriterAbortOutcome::AlreadyAborted),
            WriterState::Finished => return Err(ArtifactWriteError::Closed),
            WriterState::Open | WriterState::CleanupPending => {}
        }

        self.abort_after_failure().await?;
        Ok(WriterAbortOutcome::Aborted)
    }

    async fn abort_after_failure(&mut self) -> Result<(), ArtifactWriteError> {
        match self.state {
            WriterState::Aborted => return Ok(()),
            WriterState::Finished => return Err(ArtifactWriteError::Closed),
            WriterState::Open | WriterState::CleanupPending => {}
        }

        let store_result = self.store.abort(&self.upload_id).await;
        let quota_result = self.reservation.abort().await;
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
