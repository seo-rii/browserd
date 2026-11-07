//! Domain types, state machines, policy primitives, and invariants for browserd.

mod error;
mod identifiers;
mod isolation;
mod notifications;
mod placement;
mod prepared;
mod resources;
mod runtime_safety;
mod safety;
mod state;

pub use error::{ErrorCode, ErrorSemantics, ResponseRepresentation, RetryClass};
pub use identifiers::{
    ActionId, ApprovalId, ArtifactId, IdParseError, InvalidWorkerId, LeaseId, OperationId, PageId,
    PrincipalId, SessionId, ShardId, SnapshotId, TenantId, WorkerId,
};
pub use isolation::{IsolationDecision, IsolationEscalation, IsolationPolicy, IsolationProfile};
pub use notifications::{
    MAX_NOTIFICATION_COMMIT_BYTES, MAX_NOTIFICATION_DESCRIPTORS, NotificationAck,
    NotificationActionResolution, NotificationActionState, NotificationApprovalDecision,
    NotificationArtifactState, NotificationCommit, NotificationControlState,
    NotificationDescriptor, NotificationError, NotificationSessionExecutionState,
    NotificationSessionLifecycleState, NotificationSessionScope, NotificationSourceFamily,
    NotificationSourceScope, WorkerNotificationEvent,
};
pub use placement::{
    LeaseConfig, LeaseConfigError, Placement, PlacementFence, PlacementFenceError,
};
pub use prepared::{
    EgressFence, LaunchGeneration, OwnerFence, PreparedShardLifecycle, PreparedShardState,
    PreparedShardTransition, PreparedShardTransitionError, RouteGeneration, SessionIncarnation,
    ShardFence, TransitionOutcome, WorkerEpoch,
};
pub use resources::{
    ActionLimits, ActionResourceClass, ArtifactLimits, MemoryLimits, MemoryThreshold,
    ResourceRequest, ResourceValidationError, RuntimeLimits, SessionLimits, SnapshotLimits,
    ViewerLimits,
};
pub use runtime_safety::{
    MAX_RUNTIME_SAFETY_FRESHNESS, RuntimeSafetyCache, RuntimeSafetyError, RuntimeSafetyGeneration,
};
pub use safety::{
    MAX_SAFETY_RULES_PER_SET, MAX_SAFETY_SNAPSHOT_BYTES, SafetySwitchError, SafetySwitchMutation,
    SafetySwitchRegistry, SafetySwitchSnapshot, SafetySwitchUpdate, normalize_safety_ip,
};
pub use state::{
    ActionEvent, ActionState, CreateOperationEvent, CreateOperationState, PlacementEvent,
    PlacementState, SessionCommand, SessionExecution, SessionExecutionEvent, SessionLifecycle,
    SessionLifecycleEvent, ShardAdmission, ShardEvent, ShardHealth, ShardLifecycle, ShardState,
    TransitionError,
};
