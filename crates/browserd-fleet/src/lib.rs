//! Fair scheduling, worker reservations, and fenced shard placement.

#![forbid(unsafe_code)]

mod directory;
mod placement;
mod queue;
mod reservation;
mod worker_directory;

pub use directory::{
    AttachOutcome, DirectoryError, DirectoryFence, DirectoryTime, SessionAttachment,
    SessionDirectory, SessionRoute,
};
pub use placement::{
    CandidateAdmission, CandidateHealth, CandidateLifecycle, CompatibilityKey, EpochError,
    ShardCandidate, ShardSelector, WorkerEpochRegistry,
};
pub use queue::{FairQueue, QueueClaim, QueueError, QueueTime, QueuedOperation};
pub use reservation::{
    ActiveAllocation, ReservationError, ReservationLease, ReservationOutcome, ReservationPool,
    ReservationSnapshot, ResourceVector,
};
pub use worker_directory::{
    RegisterWorkerOutcome, WorkerAdvertisement, WorkerDirectory, WorkerDirectoryError,
    WorkerDirectorySnapshot, WorkerHeartbeat,
};
