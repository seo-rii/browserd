//! Session-scoped artifact state, quota, streaming, token, and cleanup
//! primitives for browserd.

mod janitor;
mod namespace;
mod quota;
mod state;
mod streaming;
mod token;

pub use janitor::{
    ArtifactJanitor, CleanupCandidate, CleanupKind, CleanupOutcome, JanitorBackend, JanitorError,
    JanitorReport,
};
pub use namespace::{ArtifactError, ArtifactKey, ArtifactNamespace};
pub use quota::{
    ArtifactQuota, ArtifactReservation, QuotaDimension, QuotaError, QuotaLimits, QuotaSnapshot,
    ReservationAbortOutcome, ReservationCommitOutcome,
};
pub use state::{Artifact, ArtifactEvent, ArtifactKind, ArtifactState, TransitionOutcome};
pub use streaming::{
    ArtifactMultipartStore, ArtifactStoreError, ArtifactWriteError, MultipartUploadId,
    StreamingArtifactWriter, WriterAbortOutcome,
};
pub use token::{DownloadToken, DownloadTokenError, OneTimeDownloadTokenRegistry};
