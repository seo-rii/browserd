use std::fmt;

use bytes::Bytes;

use crate::{ArtifactKey, ArtifactReservation, QuotaError};

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

#[allow(async_fn_in_trait)]
pub trait ArtifactMultipartStore: Send + Sync {
    async fn begin(&self, key: &ArtifactKey) -> Result<MultipartUploadId, ArtifactStoreError>;

    async fn append(
        &self,
        upload_id: &MultipartUploadId,
        chunk: Bytes,
    ) -> Result<(), ArtifactStoreError>;

    async fn complete(&self, upload_id: &MultipartUploadId) -> Result<(), ArtifactStoreError>;

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
    Finished,
    Aborted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriterAbortOutcome {
    Aborted,
    AlreadyAborted,
}

pub struct StreamingArtifactWriter<S> {
    reservation: ArtifactReservation,
    store: S,
    upload_id: MultipartUploadId,
    state: WriterState,
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

        if let Err(quota_error) = self.reservation.add_actual_bytes(bytes).await {
            match self.abort_after_failure().await {
                Ok(()) => return Err(ArtifactWriteError::Quota(quota_error)),
                Err(cleanup_error) => return Err(cleanup_error),
            }
        }

        if let Err(operation) = self.store.append(&self.upload_id, chunk).await {
            let cleanup = self.store.abort(&self.upload_id).await;
            let _ = self.reservation.abort().await;
            self.state = WriterState::Aborted;
            return match cleanup {
                Ok(()) => Err(ArtifactWriteError::Store(operation)),
                Err(cleanup) => Err(ArtifactWriteError::StoreAndCleanup { operation, cleanup }),
            };
        }

        Ok(())
    }

    pub async fn finish(&mut self) -> Result<(), ArtifactWriteError> {
        match self.state {
            WriterState::Finished => return Ok(()),
            WriterState::Aborted => return Err(ArtifactWriteError::Closed),
            WriterState::Open => {}
        }

        if let Err(operation) = self.store.complete(&self.upload_id).await {
            let cleanup = self.store.abort(&self.upload_id).await;
            let _ = self.reservation.abort().await;
            self.state = WriterState::Aborted;
            return match cleanup {
                Ok(()) => Err(ArtifactWriteError::Store(operation)),
                Err(cleanup) => Err(ArtifactWriteError::StoreAndCleanup { operation, cleanup }),
            };
        }

        self.reservation.commit().await?;
        self.state = WriterState::Finished;
        Ok(())
    }

    pub async fn abort(&mut self) -> Result<WriterAbortOutcome, ArtifactWriteError> {
        match self.state {
            WriterState::Aborted => return Ok(WriterAbortOutcome::AlreadyAborted),
            WriterState::Finished => return Err(ArtifactWriteError::Closed),
            WriterState::Open => {}
        }

        self.abort_after_failure().await?;
        Ok(WriterAbortOutcome::Aborted)
    }

    async fn abort_after_failure(&mut self) -> Result<(), ArtifactWriteError> {
        if self.state == WriterState::Aborted {
            return Ok(());
        }

        let store_result = self.store.abort(&self.upload_id).await;
        let quota_result = self.reservation.abort().await;
        self.state = WriterState::Aborted;

        match (store_result, quota_result) {
            (Ok(()), Ok(_)) => Ok(()),
            (Err(error), _) => Err(ArtifactWriteError::Store(error)),
            (Ok(()), Err(error)) => Err(ArtifactWriteError::Quota(error)),
        }
    }
}
