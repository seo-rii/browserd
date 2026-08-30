use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::time::{MissedTickBehavior, interval};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecycleBackendError;

#[async_trait]
pub trait WorkerLifecycleBackend: Send + Sync + 'static {
    async fn heartbeat(&self) -> Result<(), LifecycleBackendError>;

    async fn expire_due(&self) -> Result<(), LifecycleBackendError>;

    async fn begin_drain(&self) -> Result<(), LifecycleBackendError>;

    async fn graceful_shutdown(&self) -> Result<(), LifecycleBackendError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecycleBoundsError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecycleBounds {
    heartbeat_interval: Duration,
    expiration_interval: Duration,
    shutdown_timeout: Duration,
}

impl LifecycleBounds {
    pub fn new(
        heartbeat_interval: Duration,
        expiration_interval: Duration,
        ownership_lease_bound: Duration,
        shutdown_timeout: Duration,
    ) -> Result<Self, LifecycleBoundsError> {
        if heartbeat_interval.is_zero()
            || expiration_interval.is_zero()
            || ownership_lease_bound.is_zero()
            || heartbeat_interval >= ownership_lease_bound
            || shutdown_timeout.is_zero()
        {
            return Err(LifecycleBoundsError);
        }

        Ok(Self {
            heartbeat_interval,
            expiration_interval,
            shutdown_timeout,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleError {
    Heartbeat,
    Expiration,
    Drain,
    Shutdown,
    ShutdownTimeout,
}

pub async fn run_worker_lifecycle<B>(
    backend: Arc<B>,
    bounds: LifecycleBounds,
    cancellation: CancellationToken,
) -> Result<(), LifecycleError>
where
    B: WorkerLifecycleBackend,
{
    let mut heartbeat = interval(bounds.heartbeat_interval);
    heartbeat.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut expiration = interval(bounds.expiration_interval);
    expiration.set_missed_tick_behavior(MissedTickBehavior::Skip);

    let primary_error = loop {
        tokio::select! {
            biased;
            () = cancellation.cancelled() => break None,
            _ = heartbeat.tick() => {
                if backend.heartbeat().await.is_err() {
                    cancellation.cancel();
                    break Some(LifecycleError::Heartbeat);
                }
            }
            _ = expiration.tick() => {
                if backend.expire_due().await.is_err() {
                    cancellation.cancel();
                    break Some(LifecycleError::Expiration);
                }
            }
        }
    };

    let drain_error = backend.begin_drain().await.err();
    let shutdown_result =
        tokio::time::timeout(bounds.shutdown_timeout, backend.graceful_shutdown()).await;

    if let Some(error) = primary_error {
        return Err(error);
    }
    if drain_error.is_some() {
        return Err(LifecycleError::Drain);
    }
    match shutdown_result {
        Err(_) => Err(LifecycleError::ShutdownTimeout),
        Ok(Err(_)) => Err(LifecycleError::Shutdown),
        Ok(Ok(())) => Ok(()),
    }
}
