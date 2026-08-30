//! Durable local control primitives for the browser egress daemon.

mod daemon;
mod daemon_epoch;

#[cfg(test)]
mod daemon_tests;

pub use daemon::{
    AttachmentStatusView, DaemonControlError, DaemonLimits, EgressDaemon, PreparedRouteRequest,
    PreparedRouteResponse, RenewRouteRequest, RenewedRouteResponse,
};
pub use daemon_epoch::{DaemonEpochStoreError, allocate_daemon_epoch};
