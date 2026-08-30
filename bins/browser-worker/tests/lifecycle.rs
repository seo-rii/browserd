use std::future::pending;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use browser_worker::{
    LifecycleBackendError, LifecycleBounds, LifecycleError, WorkerLifecycleBackend,
    run_worker_lifecycle,
};
use tokio_util::sync::CancellationToken;

struct Backend {
    cancellation: CancellationToken,
    fail_heartbeat: AtomicBool,
    hang_shutdown: AtomicBool,
    heartbeats: AtomicUsize,
    expirations: AtomicUsize,
    drains: AtomicUsize,
    shutdowns: AtomicUsize,
}

impl Backend {
    fn new(cancellation: CancellationToken) -> Self {
        Self {
            cancellation,
            fail_heartbeat: AtomicBool::new(false),
            hang_shutdown: AtomicBool::new(false),
            heartbeats: AtomicUsize::new(0),
            expirations: AtomicUsize::new(0),
            drains: AtomicUsize::new(0),
            shutdowns: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl WorkerLifecycleBackend for Backend {
    async fn heartbeat(&self) -> Result<(), LifecycleBackendError> {
        self.heartbeats.fetch_add(1, Ordering::SeqCst);
        if self.fail_heartbeat.load(Ordering::SeqCst) {
            Err(LifecycleBackendError)
        } else {
            Ok(())
        }
    }

    async fn expire_due(&self) -> Result<(), LifecycleBackendError> {
        self.expirations.fetch_add(1, Ordering::SeqCst);
        if self.heartbeats.load(Ordering::SeqCst) != 0 {
            self.cancellation.cancel();
        }
        Ok(())
    }

    async fn begin_drain(&self) -> Result<(), LifecycleBackendError> {
        self.drains.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn graceful_shutdown(&self) -> Result<(), LifecycleBackendError> {
        self.shutdowns.fetch_add(1, Ordering::SeqCst);
        if self.hang_shutdown.load(Ordering::SeqCst) {
            pending::<()>().await;
        }
        Ok(())
    }
}

fn bounds(shutdown_timeout: Duration) -> Option<LifecycleBounds> {
    let bounds = LifecycleBounds::new(
        Duration::from_millis(5),
        Duration::from_millis(7),
        Duration::from_millis(50),
        shutdown_timeout,
    );
    assert!(bounds.is_ok());
    bounds.ok()
}

#[tokio::test]
async fn external_shutdown_drains_and_cleans_up_exactly_once() {
    let cancellation = CancellationToken::new();
    let backend = Arc::new(Backend::new(cancellation.clone()));
    let Some(bounds) = bounds(Duration::from_millis(100)) else {
        return;
    };

    let result = run_worker_lifecycle(Arc::clone(&backend), bounds, cancellation).await;

    assert_eq!(result, Ok(()));
    assert!(backend.heartbeats.load(Ordering::SeqCst) >= 1);
    assert!(backend.expirations.load(Ordering::SeqCst) >= 1);
    assert_eq!(backend.drains.load(Ordering::SeqCst), 1);
    assert_eq!(backend.shutdowns.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn heartbeat_failure_is_fail_closed_through_drain_and_shutdown() {
    let cancellation = CancellationToken::new();
    let backend = Arc::new(Backend::new(cancellation.clone()));
    backend.fail_heartbeat.store(true, Ordering::SeqCst);
    let Some(bounds) = bounds(Duration::from_millis(100)) else {
        return;
    };

    let result = run_worker_lifecycle(Arc::clone(&backend), bounds, cancellation).await;

    assert_eq!(result, Err(LifecycleError::Heartbeat));
    assert_eq!(backend.heartbeats.load(Ordering::SeqCst), 1);
    assert_eq!(backend.drains.load(Ordering::SeqCst), 1);
    assert_eq!(backend.shutdowns.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn shutdown_is_bounded_when_cleanup_does_not_return() {
    let cancellation = CancellationToken::new();
    cancellation.cancel();
    let backend = Arc::new(Backend::new(cancellation.clone()));
    backend.hang_shutdown.store(true, Ordering::SeqCst);
    let Some(bounds) = bounds(Duration::from_millis(20)) else {
        return;
    };

    let result = tokio::time::timeout(
        Duration::from_millis(200),
        run_worker_lifecycle(Arc::clone(&backend), bounds, cancellation),
    )
    .await;

    assert!(result.is_ok());
    assert_eq!(result.ok(), Some(Err(LifecycleError::ShutdownTimeout)));
    assert_eq!(backend.drains.load(Ordering::SeqCst), 1);
    assert_eq!(backend.shutdowns.load(Ordering::SeqCst), 1);
}

#[test]
fn lifecycle_bounds_reject_unbounded_or_expired_heartbeat_schedules() {
    assert!(
        LifecycleBounds::new(
            Duration::ZERO,
            Duration::from_secs(1),
            Duration::from_secs(10),
            Duration::from_secs(30),
        )
        .is_err()
    );
    assert!(
        LifecycleBounds::new(
            Duration::from_secs(10),
            Duration::from_secs(1),
            Duration::from_secs(10),
            Duration::from_secs(30),
        )
        .is_err()
    );
    assert!(
        LifecycleBounds::new(
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(10),
            Duration::ZERO,
        )
        .is_err()
    );
}
