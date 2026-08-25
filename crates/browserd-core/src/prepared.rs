use std::fmt;
use std::num::NonZeroU64;

use serde::{Deserialize, Serialize};

use crate::{SessionId, ShardId, WorkerId};

macro_rules! generation_type {
    ($name:ident) => {
        #[derive(
            Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
        )]
        #[serde(transparent)]
        pub struct $name(NonZeroU64);

        impl $name {
            #[must_use]
            pub const fn new(value: u64) -> Option<Self> {
                match NonZeroU64::new(value) {
                    Some(value) => Some(Self(value)),
                    None => None,
                }
            }

            #[must_use]
            pub const fn get(self) -> u64 {
                self.0.get()
            }
        }
    };
}

generation_type!(WorkerEpoch);
generation_type!(LaunchGeneration);
generation_type!(RouteGeneration);
generation_type!(SessionIncarnation);

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct OwnerFence {
    worker_id: WorkerId,
    worker_epoch: WorkerEpoch,
}

impl OwnerFence {
    #[must_use]
    pub const fn new(worker_id: WorkerId, worker_epoch: WorkerEpoch) -> Self {
        Self {
            worker_id,
            worker_epoch,
        }
    }

    #[must_use]
    pub const fn worker_id(&self) -> &WorkerId {
        &self.worker_id
    }

    #[must_use]
    pub const fn worker_epoch(&self) -> WorkerEpoch {
        self.worker_epoch
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ShardFence {
    owner: OwnerFence,
    shard_id: ShardId,
    launch_generation: LaunchGeneration,
}

impl ShardFence {
    #[must_use]
    pub const fn new(
        owner: OwnerFence,
        shard_id: ShardId,
        launch_generation: LaunchGeneration,
    ) -> Self {
        Self {
            owner,
            shard_id,
            launch_generation,
        }
    }

    #[must_use]
    pub const fn owner(&self) -> &OwnerFence {
        &self.owner
    }

    #[must_use]
    pub const fn shard_id(&self) -> &ShardId {
        &self.shard_id
    }

    #[must_use]
    pub const fn launch_generation(&self) -> LaunchGeneration {
        self.launch_generation
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct EgressFence {
    shard: ShardFence,
    route_generation: RouteGeneration,
    session_id: SessionId,
    session_incarnation: SessionIncarnation,
}

impl EgressFence {
    #[must_use]
    pub const fn new(
        shard: ShardFence,
        route_generation: RouteGeneration,
        session_id: SessionId,
        session_incarnation: SessionIncarnation,
    ) -> Self {
        Self {
            shard,
            route_generation,
            session_id,
            session_incarnation,
        }
    }

    #[must_use]
    pub const fn shard(&self) -> &ShardFence {
        &self.shard
    }

    #[must_use]
    pub const fn route_generation(&self) -> RouteGeneration {
        self.route_generation
    }

    #[must_use]
    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    #[must_use]
    pub const fn session_incarnation(&self) -> SessionIncarnation {
        self.session_incarnation
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreparedShardState {
    Reserved,
    FilesystemCgroupReady,
    ChildGated,
    ProcessIdentityProven,
    CgroupAttached,
    NetnsIdentityProven,
    IngressRegistered,
    CdpClaimed,
    ContainmentProven,
    ReleaseIntent,
    Released,
    Revoking,
    AbortingGate,
    Killing,
    Cleaning,
    ReleasedTombstone,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PreparedShardTransition {
    FilesystemCgroupReady,
    ChildGated,
    ProcessIdentityProven,
    CgroupAttached,
    NetnsIdentityProven,
    IngressRegistered(EgressFence),
    CdpClaimed,
    ContainmentProven,
    ReleaseIntentRecorded,
    ReleaseTokenSent { release_sequence: u64 },
    RevokeStarted,
    GateAbortStarted,
    CgroupKillStarted,
    CleanupStarted,
    CleanupCompleted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransitionOutcome {
    Applied,
    AlreadyApplied,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PreparedShardLifecycle {
    fence: ShardFence,
    state: PreparedShardState,
    egress_fence: Option<EgressFence>,
    release_sequence: Option<u64>,
}

impl PreparedShardLifecycle {
    #[must_use]
    pub const fn new(fence: ShardFence) -> Self {
        Self {
            fence,
            state: PreparedShardState::Reserved,
            egress_fence: None,
            release_sequence: None,
        }
    }

    #[must_use]
    pub const fn fence(&self) -> &ShardFence {
        &self.fence
    }

    #[must_use]
    pub const fn state(&self) -> PreparedShardState {
        self.state
    }

    #[must_use]
    pub const fn egress_fence(&self) -> Option<&EgressFence> {
        self.egress_fence.as_ref()
    }

    #[must_use]
    pub const fn release_sequence(&self) -> Option<u64> {
        self.release_sequence
    }

    pub fn apply(
        &mut self,
        received_fence: &ShardFence,
        transition: PreparedShardTransition,
    ) -> Result<TransitionOutcome, PreparedShardTransitionError> {
        if received_fence != &self.fence {
            return Err(PreparedShardTransitionError::FenceMismatch {
                expected: self.fence.clone(),
                received: received_fence.clone(),
            });
        }

        if let PreparedShardTransition::IngressRegistered(received) = &transition {
            if received.shard() != &self.fence {
                return Err(PreparedShardTransitionError::EgressFenceMismatch);
            }
            if let Some(recorded) = &self.egress_fence {
                return if recorded == received {
                    Ok(TransitionOutcome::AlreadyApplied)
                } else {
                    Err(PreparedShardTransitionError::ConflictingEgressFence)
                };
            }
        }

        if let PreparedShardTransition::ReleaseTokenSent { release_sequence } = &transition {
            if *release_sequence == 0 {
                return Err(PreparedShardTransitionError::ZeroReleaseSequence);
            }
            if let Some(recorded) = self.release_sequence {
                return if recorded == *release_sequence {
                    Ok(TransitionOutcome::AlreadyApplied)
                } else {
                    Err(PreparedShardTransitionError::ConflictingReleaseSequence {
                        recorded,
                        received: *release_sequence,
                    })
                };
            }
        }

        let previous = self.state;
        let next = match transition {
            PreparedShardTransition::FilesystemCgroupReady => {
                if previous == PreparedShardState::FilesystemCgroupReady {
                    return Ok(TransitionOutcome::AlreadyApplied);
                }
                if previous != PreparedShardState::Reserved {
                    return Err(PreparedShardTransitionError::InvalidTransition {
                        state: previous,
                        transition: "filesystem_cgroup_ready",
                    });
                }
                PreparedShardState::FilesystemCgroupReady
            }
            PreparedShardTransition::ChildGated => {
                if previous == PreparedShardState::ChildGated {
                    return Ok(TransitionOutcome::AlreadyApplied);
                }
                if previous != PreparedShardState::FilesystemCgroupReady {
                    return Err(PreparedShardTransitionError::InvalidTransition {
                        state: previous,
                        transition: "child_gated",
                    });
                }
                PreparedShardState::ChildGated
            }
            PreparedShardTransition::ProcessIdentityProven => {
                if previous == PreparedShardState::ProcessIdentityProven {
                    return Ok(TransitionOutcome::AlreadyApplied);
                }
                if previous != PreparedShardState::ChildGated {
                    return Err(PreparedShardTransitionError::InvalidTransition {
                        state: previous,
                        transition: "process_identity_proven",
                    });
                }
                PreparedShardState::ProcessIdentityProven
            }
            PreparedShardTransition::CgroupAttached => {
                if previous == PreparedShardState::CgroupAttached {
                    return Ok(TransitionOutcome::AlreadyApplied);
                }
                if previous != PreparedShardState::ProcessIdentityProven {
                    return Err(PreparedShardTransitionError::InvalidTransition {
                        state: previous,
                        transition: "cgroup_attached",
                    });
                }
                PreparedShardState::CgroupAttached
            }
            PreparedShardTransition::NetnsIdentityProven => {
                if previous == PreparedShardState::NetnsIdentityProven {
                    return Ok(TransitionOutcome::AlreadyApplied);
                }
                if previous != PreparedShardState::CgroupAttached {
                    return Err(PreparedShardTransitionError::InvalidTransition {
                        state: previous,
                        transition: "netns_identity_proven",
                    });
                }
                PreparedShardState::NetnsIdentityProven
            }
            PreparedShardTransition::IngressRegistered(egress_fence) => {
                if previous != PreparedShardState::NetnsIdentityProven {
                    return Err(PreparedShardTransitionError::InvalidTransition {
                        state: previous,
                        transition: "ingress_registered",
                    });
                }
                self.egress_fence = Some(egress_fence);
                PreparedShardState::IngressRegistered
            }
            PreparedShardTransition::CdpClaimed => {
                if previous == PreparedShardState::CdpClaimed {
                    return Ok(TransitionOutcome::AlreadyApplied);
                }
                if previous != PreparedShardState::IngressRegistered {
                    return Err(PreparedShardTransitionError::InvalidTransition {
                        state: previous,
                        transition: "cdp_claimed",
                    });
                }
                PreparedShardState::CdpClaimed
            }
            PreparedShardTransition::ContainmentProven => {
                if previous == PreparedShardState::ContainmentProven {
                    return Ok(TransitionOutcome::AlreadyApplied);
                }
                if previous != PreparedShardState::CdpClaimed {
                    return Err(PreparedShardTransitionError::InvalidTransition {
                        state: previous,
                        transition: "containment_proven",
                    });
                }
                PreparedShardState::ContainmentProven
            }
            PreparedShardTransition::ReleaseIntentRecorded => {
                if previous == PreparedShardState::ReleaseIntent {
                    return Ok(TransitionOutcome::AlreadyApplied);
                }
                if previous != PreparedShardState::ContainmentProven {
                    return Err(PreparedShardTransitionError::InvalidTransition {
                        state: previous,
                        transition: "release_intent_recorded",
                    });
                }
                PreparedShardState::ReleaseIntent
            }
            PreparedShardTransition::ReleaseTokenSent { release_sequence } => {
                if matches!(
                    previous,
                    PreparedShardState::Revoking
                        | PreparedShardState::AbortingGate
                        | PreparedShardState::Killing
                        | PreparedShardState::Cleaning
                        | PreparedShardState::ReleasedTombstone
                ) {
                    return Err(PreparedShardTransitionError::ReleaseForbidden { state: previous });
                }
                if previous != PreparedShardState::ReleaseIntent {
                    return Err(PreparedShardTransitionError::InvalidTransition {
                        state: previous,
                        transition: "release_token_sent",
                    });
                }
                self.release_sequence = Some(release_sequence);
                PreparedShardState::Released
            }
            PreparedShardTransition::RevokeStarted => {
                if matches!(
                    previous,
                    PreparedShardState::Revoking
                        | PreparedShardState::AbortingGate
                        | PreparedShardState::Killing
                        | PreparedShardState::Cleaning
                        | PreparedShardState::ReleasedTombstone
                ) {
                    return Ok(TransitionOutcome::AlreadyApplied);
                }
                PreparedShardState::Revoking
            }
            PreparedShardTransition::GateAbortStarted => {
                if matches!(
                    previous,
                    PreparedShardState::AbortingGate
                        | PreparedShardState::Killing
                        | PreparedShardState::Cleaning
                        | PreparedShardState::ReleasedTombstone
                ) {
                    return Ok(TransitionOutcome::AlreadyApplied);
                }
                if previous != PreparedShardState::Revoking {
                    return Err(PreparedShardTransitionError::InvalidTransition {
                        state: previous,
                        transition: "gate_abort_started",
                    });
                }
                PreparedShardState::AbortingGate
            }
            PreparedShardTransition::CgroupKillStarted => {
                if matches!(
                    previous,
                    PreparedShardState::Killing
                        | PreparedShardState::Cleaning
                        | PreparedShardState::ReleasedTombstone
                ) {
                    return Ok(TransitionOutcome::AlreadyApplied);
                }
                if previous != PreparedShardState::AbortingGate {
                    return Err(PreparedShardTransitionError::InvalidTransition {
                        state: previous,
                        transition: "cgroup_kill_started",
                    });
                }
                PreparedShardState::Killing
            }
            PreparedShardTransition::CleanupStarted => {
                if matches!(
                    previous,
                    PreparedShardState::Cleaning | PreparedShardState::ReleasedTombstone
                ) {
                    return Ok(TransitionOutcome::AlreadyApplied);
                }
                if previous != PreparedShardState::Killing {
                    return Err(PreparedShardTransitionError::InvalidTransition {
                        state: previous,
                        transition: "cleanup_started",
                    });
                }
                PreparedShardState::Cleaning
            }
            PreparedShardTransition::CleanupCompleted => {
                if previous == PreparedShardState::ReleasedTombstone {
                    return Ok(TransitionOutcome::AlreadyApplied);
                }
                if previous != PreparedShardState::Cleaning {
                    return Err(PreparedShardTransitionError::InvalidTransition {
                        state: previous,
                        transition: "cleanup_completed",
                    });
                }
                PreparedShardState::ReleasedTombstone
            }
        };
        self.state = next;
        Ok(TransitionOutcome::Applied)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PreparedShardTransitionError {
    FenceMismatch {
        expected: ShardFence,
        received: ShardFence,
    },
    EgressFenceMismatch,
    ConflictingEgressFence,
    ZeroReleaseSequence,
    ConflictingReleaseSequence {
        recorded: u64,
        received: u64,
    },
    ReleaseForbidden {
        state: PreparedShardState,
    },
    InvalidTransition {
        state: PreparedShardState,
        transition: &'static str,
    },
}

impl fmt::Display for PreparedShardTransitionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FenceMismatch { .. } => formatter.write_str("prepared shard fence mismatch"),
            Self::EgressFenceMismatch => {
                formatter.write_str("egress fence does not belong to the prepared shard")
            }
            Self::ConflictingEgressFence => {
                formatter.write_str("prepared shard already has a different egress fence")
            }
            Self::ZeroReleaseSequence => formatter.write_str("release sequence must be positive"),
            Self::ConflictingReleaseSequence { recorded, received } => write!(
                formatter,
                "release sequence conflicts: recorded {recorded}, received {received}"
            ),
            Self::ReleaseForbidden { state } => {
                write!(formatter, "release is forbidden while shard is {state:?}")
            }
            Self::InvalidTransition { state, transition } => write!(
                formatter,
                "prepared shard cannot apply {transition} while in {state:?}"
            ),
        }
    }
}

impl std::error::Error for PreparedShardTransitionError {}
