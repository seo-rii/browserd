//! Fair scheduling, worker reservations, and fenced shard placement.

#![forbid(unsafe_code)]

mod placement;
mod queue;
mod reservation;

pub use placement::{
    CandidateAdmission, CandidateHealth, CandidateLifecycle, CompatibilityKey, EpochError,
    ShardCandidate, ShardSelector, WorkerEpochRegistry,
};
pub use queue::{FairQueue, QueueClaim, QueueError, QueueTime, QueuedOperation};
pub use reservation::{
    ActiveAllocation, ReservationError, ReservationLease, ReservationOutcome, ReservationPool,
    ReservationSnapshot, ResourceVector,
};
