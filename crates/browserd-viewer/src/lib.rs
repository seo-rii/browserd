//! Viewer connection, control lease, and input fencing primitives.

mod control;
mod frame;
mod ticket;
mod types;

pub use control::ControlManager;
pub use frame::{FrameBroadcaster, FrameError, FramePolicy, PublishOutcome, ViewerFrame};
pub use ticket::TicketRegistry;
pub use types::{
    AcquireOutcome, ConnectionId, ControlError, ControlInput, ControlLease, ControlPolicy,
    ControlSnapshot, InputCleanup, InputDecision, InputDiscardReason, InputEffect, InputKind,
    InputStateSnapshot, TicketError, TicketPolicy, ViewerConnection, ViewerScopes, ViewerTicket,
};
