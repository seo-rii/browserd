//! Domain types, state machines, policy primitives, and invariants for browserd.

mod error;
mod identifiers;
mod isolation;
mod placement;
mod resources;
mod safety;
mod state;

pub use error::{ErrorCode, ErrorSemantics, ResponseRepresentation, RetryClass};
pub use identifiers::{
    ActionId, ArtifactId, IdParseError, InvalidWorkerId, LeaseId, OperationId, PageId, PrincipalId,
    SessionId, ShardId, SnapshotId, TenantId, WorkerId,
};
pub use isolation::{IsolationDecision, IsolationEscalation, IsolationPolicy, IsolationProfile};
pub use placement::{
    LeaseConfig, LeaseConfigError, Placement, PlacementFence, PlacementFenceError,
};
pub use resources::{
    ActionLimits, ActionResourceClass, ArtifactLimits, MemoryLimits, MemoryThreshold,
    ResourceRequest, ResourceValidationError, RuntimeLimits, SessionLimits, SnapshotLimits,
    ViewerLimits,
};
pub use safety::{
    SafetySwitchError, SafetySwitchMutation, SafetySwitchRegistry, SafetySwitchSnapshot,
    SafetySwitchUpdate,
};
pub use state::{
    ActionEvent, ActionState, CreateOperationEvent, CreateOperationState, PlacementEvent,
    PlacementState, SessionCommand, SessionExecution, SessionExecutionEvent, SessionLifecycle,
    SessionLifecycleEvent, ShardAdmission, ShardEvent, ShardHealth, ShardLifecycle, ShardState,
    TransitionError,
};
