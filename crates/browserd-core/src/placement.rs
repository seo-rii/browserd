use std::fmt;
use std::time::Duration;

use crate::{PlacementState, ShardId, WorkerId};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Placement {
    worker_id: WorkerId,
    worker_epoch: u64,
    shard_id: ShardId,
    placement_version: u64,
    state: PlacementState,
}

impl Placement {
    #[must_use]
    pub fn new(
        worker_id: WorkerId,
        worker_epoch: u64,
        shard_id: ShardId,
        placement_version: u64,
        state: PlacementState,
    ) -> Self {
        Self {
            worker_id,
            worker_epoch,
            shard_id,
            placement_version,
            state,
        }
    }

    #[must_use]
    pub fn with_state(mut self, state: PlacementState) -> Self {
        self.state = state;
        self
    }

    #[must_use]
    pub fn worker_id(&self) -> &WorkerId {
        &self.worker_id
    }

    #[must_use]
    pub const fn worker_epoch(&self) -> u64 {
        self.worker_epoch
    }

    #[must_use]
    pub const fn shard_id(&self) -> &ShardId {
        &self.shard_id
    }

    #[must_use]
    pub const fn placement_version(&self) -> u64 {
        self.placement_version
    }

    #[must_use]
    pub const fn state(&self) -> PlacementState {
        self.state
    }

    pub fn validate_fence(
        &self,
        current_session_incarnation: u64,
        received: &PlacementFence,
    ) -> Result<(), PlacementFenceError> {
        if self.state != PlacementState::Attached {
            return Err(PlacementFenceError::PlacementNotAttached { state: self.state });
        }
        if received.worker_epoch != self.worker_epoch {
            return Err(PlacementFenceError::WorkerEpochMismatch {
                expected: self.worker_epoch,
                received: received.worker_epoch,
            });
        }
        if received.placement_version != self.placement_version {
            return Err(PlacementFenceError::PlacementVersionMismatch {
                expected: self.placement_version,
                received: received.placement_version,
            });
        }
        if received.session_incarnation != current_session_incarnation {
            return Err(PlacementFenceError::SessionIncarnationMismatch {
                expected: current_session_incarnation,
                received: received.session_incarnation,
            });
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlacementFence {
    pub worker_epoch: u64,
    pub placement_version: u64,
    pub session_incarnation: u64,
}

impl PlacementFence {
    #[must_use]
    pub const fn new(worker_epoch: u64, placement_version: u64, session_incarnation: u64) -> Self {
        Self {
            worker_epoch,
            placement_version,
            session_incarnation,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlacementFenceError {
    PlacementNotAttached { state: PlacementState },
    WorkerEpochMismatch { expected: u64, received: u64 },
    PlacementVersionMismatch { expected: u64, received: u64 },
    SessionIncarnationMismatch { expected: u64, received: u64 },
}

impl fmt::Display for PlacementFenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PlacementNotAttached { state } => {
                write!(formatter, "placement is not attached: {state:?}")
            }
            Self::WorkerEpochMismatch { expected, received } => write!(
                formatter,
                "worker epoch mismatch: expected {expected}, received {received}"
            ),
            Self::PlacementVersionMismatch { expected, received } => write!(
                formatter,
                "placement version mismatch: expected {expected}, received {received}"
            ),
            Self::SessionIncarnationMismatch { expected, received } => write!(
                formatter,
                "session incarnation mismatch: expected {expected}, received {received}"
            ),
        }
    }
}

impl std::error::Error for PlacementFenceError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LeaseConfig {
    supervisor_lease_ttl: Duration,
    directory_lease_ttl: Duration,
}

impl LeaseConfig {
    pub fn new(
        supervisor_lease_ttl: Duration,
        directory_lease_ttl: Duration,
    ) -> Result<Self, LeaseConfigError> {
        if supervisor_lease_ttl.is_zero() {
            return Err(LeaseConfigError::ZeroSupervisorTtl);
        }
        if directory_lease_ttl.is_zero() {
            return Err(LeaseConfigError::ZeroDirectoryTtl);
        }
        if supervisor_lease_ttl > directory_lease_ttl {
            return Err(LeaseConfigError::SupervisorExceedsDirectory);
        }
        Ok(Self {
            supervisor_lease_ttl,
            directory_lease_ttl,
        })
    }

    #[must_use]
    pub const fn supervisor_lease_ttl(self) -> Duration {
        self.supervisor_lease_ttl
    }

    #[must_use]
    pub const fn directory_lease_ttl(self) -> Duration {
        self.directory_lease_ttl
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LeaseConfigError {
    ZeroSupervisorTtl,
    ZeroDirectoryTtl,
    SupervisorExceedsDirectory,
}

impl fmt::Display for LeaseConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroSupervisorTtl => formatter.write_str("supervisor lease TTL must be nonzero"),
            Self::ZeroDirectoryTtl => formatter.write_str("directory lease TTL must be nonzero"),
            Self::SupervisorExceedsDirectory => {
                formatter.write_str("supervisor lease TTL must not exceed directory lease TTL")
            }
        }
    }
}

impl std::error::Error for LeaseConfigError {}
