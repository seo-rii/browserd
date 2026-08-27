//! Durable local control primitives for the browser egress daemon.

mod daemon_epoch;

pub use daemon_epoch::{DaemonEpochStoreError, allocate_daemon_epoch};
