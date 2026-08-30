use std::fmt;
use std::future::Future;

use bytes::Bytes;

use crate::{
    ArtifactContentMetadata, ArtifactKey, ArtifactNamespace, ArtifactObjectGeneration,
    ArtifactStoreError,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArtifactReadLimits {
    max_chunk_bytes: usize,
}

impl ArtifactReadLimits {
    pub const MAX_CHUNK_BYTES: usize = 1024 * 1024;

    pub const fn new(max_chunk_bytes: usize) -> Result<Self, ArtifactObjectError> {
        if max_chunk_bytes == 0 || max_chunk_bytes > Self::MAX_CHUNK_BYTES {
            return Err(ArtifactObjectError::InvalidBounds);
        }
        Ok(Self { max_chunk_bytes })
    }

    #[must_use]
    pub const fn max_chunk_bytes(self) -> usize {
        self.max_chunk_bytes
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ArtifactObjectError {
    InvalidBounds,
    NamespaceDenied,
    NotAvailable,
    GenerationMismatch,
    IntegrityMismatch,
    Store(ArtifactStoreError),
}

impl fmt::Display for ArtifactObjectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBounds => formatter.write_str("artifact read bounds are invalid"),
            Self::NamespaceDenied => formatter.write_str("artifact namespace access denied"),
            Self::NotAvailable => formatter.write_str("artifact object is not available"),
            Self::GenerationMismatch => {
                formatter.write_str("artifact object generation does not match")
            }
            Self::IntegrityMismatch => {
                formatter.write_str("artifact object failed integrity verification")
            }
            Self::Store(error) => write!(formatter, "artifact object store error: {error}"),
        }
    }
}

impl std::error::Error for ArtifactObjectError {}

impl From<ArtifactStoreError> for ArtifactObjectError {
    fn from(error: ArtifactStoreError) -> Self {
        Self::Store(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactDeleteOutcome {
    Deleted,
    AlreadyDeleted,
}

pub trait ArtifactChunkReader: Send {
    fn next_chunk(
        &mut self,
    ) -> impl Future<Output = Result<Option<Bytes>, ArtifactObjectError>> + Send;
}

pub trait ArtifactObjectStore: Send + Sync {
    type Reader: ArtifactChunkReader + Send + 'static;

    fn open_read(
        &self,
        namespace: &ArtifactNamespace,
        key: &ArtifactKey,
        expected_generation: ArtifactObjectGeneration,
        expected_metadata: &ArtifactContentMetadata,
        limits: ArtifactReadLimits,
    ) -> impl Future<Output = Result<Self::Reader, ArtifactObjectError>> + Send;

    fn delete_exact(
        &self,
        namespace: &ArtifactNamespace,
        key: &ArtifactKey,
        expected_generation: ArtifactObjectGeneration,
    ) -> impl Future<Output = Result<ArtifactDeleteOutcome, ArtifactObjectError>> + Send;
}
