//! Session-scoped artifact state, quota, streaming, token, and cleanup
//! primitives for browserd.

mod filesystem;
mod integrity;
mod janitor;
mod namespace;
mod quota;
mod state;
mod streaming;
mod token;

pub use filesystem::{FilesystemArtifactStore, VerifiedArtifact};
pub use integrity::{ArtifactChecksum, ArtifactContentMetadata, ArtifactContentSource};
pub use janitor::{
    ArtifactJanitor, ArtifactObjectGeneration, AuthorizedCleanupCandidate, CleanupCandidate,
    CleanupKind, CleanupOutcome, JanitorBackend, JanitorError, JanitorReport,
};
pub use namespace::{ArtifactError, ArtifactKey, ArtifactNamespace};
pub use quota::{
    ArtifactQuota, ArtifactReservation, CommittedReleaseOutcome, QuotaDimension, QuotaError,
    QuotaLimits, QuotaSnapshot, ReservationAbortOutcome, ReservationCommitOutcome,
};
pub use state::{Artifact, ArtifactEvent, ArtifactKind, ArtifactState, TransitionOutcome};
pub use streaming::{
    ArtifactMultipartStore, ArtifactStoreError, ArtifactWriteError, ArtifactWriteReceipt,
    MultipartUploadId, StreamingArtifactWriter, WriterAbortOutcome,
};
pub use token::{DownloadToken, DownloadTokenError, OneTimeDownloadTokenRegistry};
