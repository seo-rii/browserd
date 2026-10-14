//! Target bootstrap, admission, page/frame epochs, and opaque node handles.

#![forbid(unsafe_code)]

mod admission;
mod bootstrap;
mod nodes;
mod page;
mod types;

pub use admission::{
    TargetAdmission, TargetAdmissionError, TargetAdmissionPermit, TargetInventory, TargetLimits,
    TargetPolicy,
};
pub use bootstrap::{
    BootstrapBackend, BootstrapDisposition, BootstrapError, BootstrapStage, BootstrapStageFailure,
    PausedTarget, ReadyTarget, ShardTaintReason, TargetBootstrapBarrier,
};
pub use browserd_core::PageId;
pub use nodes::{
    BackendNodeId, FrameEpochFence, NodeBinding, NodeFrameScope, NodeHandle, NodeHandleStore,
    NodeOwnerBinding, NodeResolutionContext, NodeResolutionError, ResolvedNode, SnapshotId,
    classify_selector_match_count,
};
pub use page::{FrameState, PageEpochError, PageEpochTracker};
pub use types::{
    DocumentEpoch, FlattenedSessionId, FrameId, SessionIncarnation, TargetIncarnation, TargetKind,
    TargetTime, UrlRevision,
};
