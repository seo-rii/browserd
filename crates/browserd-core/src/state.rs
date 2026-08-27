use std::fmt;

use crate::ActionId;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransitionError {
    machine: &'static str,
    reason: &'static str,
}

impl TransitionError {
    const fn new(machine: &'static str, reason: &'static str) -> Self {
        Self { machine, reason }
    }
}

impl fmt::Display for TransitionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid {} transition: {}",
            self.machine, self.reason
        )
    }
}

impl std::error::Error for TransitionError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CreateOperationState {
    Accepted,
    Queued,
    Reserving,
    Creating,
    Succeeded,
    TimedOut,
    Cancelled,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CreateOperationEvent {
    Enqueue,
    BeginReservation,
    CapacityRace,
    ReservationCommitted,
    SessionReady,
    DeadlineElapsed,
    CancelBeforeCommit,
    Fatal,
}

impl CreateOperationState {
    pub fn transition(self, event: CreateOperationEvent) -> Result<Self, TransitionError> {
        use CreateOperationEvent as Event;
        use CreateOperationState as State;

        match (self, event) {
            (State::Accepted, Event::Enqueue) => Ok(State::Queued),
            (State::Queued, Event::BeginReservation) => Ok(State::Reserving),
            (State::Reserving, Event::CapacityRace) => Ok(State::Queued),
            (State::Reserving, Event::ReservationCommitted) => Ok(State::Creating),
            (State::Creating, Event::SessionReady) => Ok(State::Succeeded),
            (
                State::Accepted | State::Queued | State::Reserving | State::Creating,
                Event::DeadlineElapsed,
            ) => Ok(State::TimedOut),
            (
                State::Accepted | State::Queued | State::Reserving | State::Creating,
                Event::CancelBeforeCommit,
            ) => Ok(State::Cancelled),
            (
                State::Accepted | State::Queued | State::Reserving | State::Creating,
                Event::Fatal,
            ) => Ok(State::Failed),
            _ => Err(TransitionError::new(
                "create operation",
                "event is not valid in the current state",
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShardLifecycle {
    Starting,
    Active,
    Draining,
    Stopping,
    Dead,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShardHealth {
    Healthy,
    Degraded,
    Tainted,
    Compromised,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShardAdmission {
    Open,
    Closed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShardEvent {
    ReadinessSucceeded,
    BeginDraining,
    TaintDetected,
    StopWhenEmpty { live_sessions: usize },
    Stopped,
    ImmediateTermination,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShardState {
    lifecycle: ShardLifecycle,
    health: ShardHealth,
    admission: ShardAdmission,
}

impl ShardState {
    #[must_use]
    pub const fn starting() -> Self {
        Self {
            lifecycle: ShardLifecycle::Starting,
            health: ShardHealth::Healthy,
            admission: ShardAdmission::Closed,
        }
    }

    #[must_use]
    pub const fn active() -> Self {
        Self {
            lifecycle: ShardLifecycle::Active,
            health: ShardHealth::Healthy,
            admission: ShardAdmission::Open,
        }
    }

    #[must_use]
    pub const fn lifecycle(&self) -> ShardLifecycle {
        self.lifecycle
    }

    #[must_use]
    pub const fn health(&self) -> ShardHealth {
        self.health
    }

    #[must_use]
    pub const fn admission(&self) -> ShardAdmission {
        self.admission
    }

    pub fn transition(mut self, event: ShardEvent) -> Result<Self, TransitionError> {
        use ShardEvent as Event;
        use ShardLifecycle as Lifecycle;

        match (self.lifecycle, event) {
            (Lifecycle::Starting, Event::ReadinessSucceeded) => {
                self.lifecycle = Lifecycle::Active;
                self.admission = ShardAdmission::Open;
            }
            (Lifecycle::Active, Event::BeginDraining) => {
                self.lifecycle = Lifecycle::Draining;
                self.admission = ShardAdmission::Closed;
            }
            (
                Lifecycle::Starting | Lifecycle::Active | Lifecycle::Draining,
                Event::TaintDetected,
            ) => {
                self.lifecycle = Lifecycle::Draining;
                self.health = ShardHealth::Tainted;
                self.admission = ShardAdmission::Closed;
            }
            (Lifecycle::Draining, Event::StopWhenEmpty { live_sessions: 0 }) => {
                self.lifecycle = Lifecycle::Stopping;
                self.admission = ShardAdmission::Closed;
            }
            (Lifecycle::Draining, Event::StopWhenEmpty { .. }) => {
                return Err(TransitionError::new(
                    "shard",
                    "cannot stop while live sessions remain",
                ));
            }
            (Lifecycle::Stopping, Event::Stopped) => {
                self.lifecycle = Lifecycle::Dead;
                self.admission = ShardAdmission::Closed;
            }
            (lifecycle, Event::ImmediateTermination) if lifecycle != Lifecycle::Dead => {
                self.lifecycle = Lifecycle::Dead;
                self.admission = ShardAdmission::Closed;
            }
            _ => {
                return Err(TransitionError::new(
                    "shard",
                    "event is not valid in the current state",
                ));
            }
        }
        Ok(self)
    }
}

impl Default for ShardState {
    fn default() -> Self {
        Self::starting()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionLifecycle {
    Creating,
    Ready,
    Closing,
    Closed,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionLifecycleEvent {
    CreationSucceeded,
    CloseRequested,
    CleanupFinished,
    Fatal,
}

impl SessionLifecycle {
    pub fn transition(self, event: SessionLifecycleEvent) -> Result<Self, TransitionError> {
        use SessionLifecycle as State;
        use SessionLifecycleEvent as Event;

        match (self, event) {
            (State::Creating, Event::CreationSucceeded) => Ok(State::Ready),
            (State::Creating | State::Ready, Event::CloseRequested) => Ok(State::Closing),
            (State::Closing, Event::CleanupFinished) => Ok(State::Closed),
            (State::Creating | State::Ready | State::Closing, Event::Fatal) => Ok(State::Failed),
            _ => Err(TransitionError::new(
                "session lifecycle",
                "event is not valid in the current state",
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlacementState {
    Reserved,
    Attached,
    Lost,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlacementEvent {
    Attach,
    OwnershipLost,
}

impl PlacementState {
    pub fn transition(self, event: PlacementEvent) -> Result<Self, TransitionError> {
        match (self, event) {
            (Self::Reserved, PlacementEvent::Attach) => Ok(Self::Attached),
            (Self::Reserved | Self::Attached, PlacementEvent::OwnershipLost) => Ok(Self::Lost),
            _ => Err(TransitionError::new(
                "session placement",
                "event is not valid in the current state",
            )),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionExecution {
    Idle,
    Running(ActionId),
    PendingApproval(ActionId),
    ReconciliationRequired(ActionId),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionExecutionEvent {
    ActionAccepted(ActionId),
    ApprovalRequired(ActionId),
    ApprovalGranted(ActionId),
    KnownCompletion(ActionId),
    OutcomeUnknown(ActionId),
    Resolve(ActionId),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionCommand {
    Read,
    Snapshot,
    MutatingAction,
    Resolve,
    Close,
}

impl SessionExecution {
    pub fn transition(self, event: SessionExecutionEvent) -> Result<Self, TransitionError> {
        use SessionExecution as State;
        use SessionExecutionEvent as Event;

        match (self, event) {
            (State::Idle, Event::ActionAccepted(action_id)) => Ok(State::Running(action_id)),
            (State::Running(current), Event::ApprovalRequired(event)) if current == event => {
                Ok(State::PendingApproval(current))
            }
            (State::PendingApproval(current), Event::ApprovalGranted(event))
                if current == event =>
            {
                Ok(State::Running(current))
            }
            (State::Running(current), Event::KnownCompletion(event)) if current == event => {
                Ok(State::Idle)
            }
            (State::PendingApproval(current), Event::KnownCompletion(event))
                if current == event =>
            {
                Ok(State::Idle)
            }
            (State::Running(current), Event::OutcomeUnknown(event)) if current == event => {
                Ok(State::ReconciliationRequired(current))
            }
            (State::ReconciliationRequired(current), Event::Resolve(event)) if current == event => {
                Ok(State::Idle)
            }
            _ => Err(TransitionError::new(
                "session execution",
                "event or action identity is not valid in the current state",
            )),
        }
    }

    #[must_use]
    pub const fn allows(&self, command: SessionCommand) -> bool {
        match self {
            Self::ReconciliationRequired(_) => matches!(
                command,
                SessionCommand::Read
                    | SessionCommand::Snapshot
                    | SessionCommand::Resolve
                    | SessionCommand::Close
            ),
            _ => !matches!(command, SessionCommand::Resolve),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActionState {
    Accepted,
    Queued,
    PendingApproval,
    ReadyToDispatch,
    MayHaveExecuted,
    Succeeded,
    FailedKnown,
    CancelledBeforeDispatch,
    CancelledConfirmed,
    OutcomeUnknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActionEvent {
    Enqueue,
    ApprovalRequired,
    ApprovalGranted,
    ApprovalDenied,
    ApprovalTimedOut,
    ReadyForDispatch,
    RecordDispatchIntent,
    CancelBeforeDispatch,
    Succeeded,
    FailedKnown,
    CancellationConfirmed,
    OutcomeUncertain,
}

impl ActionState {
    pub fn transition(self, event: ActionEvent) -> Result<Self, TransitionError> {
        use ActionEvent as Event;
        use ActionState as State;

        match (self, event) {
            (State::Accepted, Event::Enqueue) => Ok(State::Queued),
            (State::Queued, Event::ApprovalRequired) => Ok(State::PendingApproval),
            (State::Queued, Event::ReadyForDispatch) => Ok(State::ReadyToDispatch),
            (State::PendingApproval, Event::ApprovalGranted) => Ok(State::ReadyToDispatch),
            (State::PendingApproval, Event::ApprovalDenied | Event::ApprovalTimedOut) => {
                Ok(State::FailedKnown)
            }
            (State::ReadyToDispatch, Event::RecordDispatchIntent) => Ok(State::MayHaveExecuted),
            (
                State::Accepted | State::Queued | State::PendingApproval | State::ReadyToDispatch,
                Event::CancelBeforeDispatch,
            ) => Ok(State::CancelledBeforeDispatch),
            (State::MayHaveExecuted, Event::Succeeded) => Ok(State::Succeeded),
            (State::MayHaveExecuted, Event::FailedKnown) => Ok(State::FailedKnown),
            (State::MayHaveExecuted, Event::CancellationConfirmed) => Ok(State::CancelledConfirmed),
            (State::MayHaveExecuted, Event::OutcomeUncertain) => Ok(State::OutcomeUnknown),
            _ => Err(TransitionError::new(
                "action",
                "event is not valid in the current state",
            )),
        }
    }

    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded
                | Self::FailedKnown
                | Self::CancelledBeforeDispatch
                | Self::CancelledConfirmed
                | Self::OutcomeUnknown
        )
    }
}
