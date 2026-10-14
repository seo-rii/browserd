use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use browserd_session::SessionTime;
use browserd_worker::{
    AuthenticatedPeer, ChromiumDriver, DependencyError, SandboxClient, WorkerControlPlane,
    WorkerControlPlaneRpcHandler, WorkerError, WorkerRpcConfig, WorkerRpcError, WorkerRpcServer,
};
use tokio_util::sync::CancellationToken;

use crate::{
    LifecycleBackendError, LifecycleBounds, LifecycleError, WorkerLifecycleBackend,
    run_worker_lifecycle,
};

#[derive(Debug)]
pub enum ProductionWorkerRuntimeError {
    NotReady,
    Rpc(WorkerRpcError),
    Lifecycle(LifecycleError),
}

impl fmt::Display for ProductionWorkerRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotReady => formatter.write_str("worker dependency qualification failed"),
            Self::Rpc(error) => write!(formatter, "worker RPC runtime failed: {error}"),
            Self::Lifecycle(error) => write!(formatter, "worker lifecycle failed: {error:?}"),
        }
    }
}

impl std::error::Error for ProductionWorkerRuntimeError {}

impl From<WorkerRpcError> for ProductionWorkerRuntimeError {
    fn from(error: WorkerRpcError) -> Self {
        Self::Rpc(error)
    }
}

impl From<LifecycleError> for ProductionWorkerRuntimeError {
    fn from(error: LifecycleError) -> Self {
        Self::Lifecycle(error)
    }
}

/// Optional storage maintenance, independent of browser session admission and readiness.
///
/// The runtime invokes this on a blocking thread with at most one callback in flight. The
/// provider owns its trusted UTC clock and must stop admitting new filesystem effects after
/// `deadline`. A timeout or caller cancellation must not release ownership of effects already
/// started: detached work must retain its exact generation, quota reservation, and root handle.
pub trait ArtifactMaintenance: Send + Sync + 'static {
    fn sweep_expired(&self, limit: usize, deadline: Instant) -> Result<usize, DependencyError>;
}

const ARTIFACT_MAINTENANCE_INTERVAL: Duration = Duration::from_secs(30);
const ARTIFACT_MAINTENANCE_DEADLINE: Duration = Duration::from_secs(5);
const ARTIFACT_MAINTENANCE_LIMIT: usize = 32;

pub struct ProductionWorkerRuntime<D, S> {
    worker: Arc<WorkerControlPlane<D, S>>,
    peer: AuthenticatedPeer,
    rpc_config: WorkerRpcConfig,
    lifecycle_bounds: LifecycleBounds,
    artifact_maintenance: Option<Arc<dyn ArtifactMaintenance>>,
}

impl<D, S> ProductionWorkerRuntime<D, S>
where
    D: ChromiumDriver,
    S: SandboxClient,
{
    pub fn new(
        worker: Arc<WorkerControlPlane<D, S>>,
        peer: AuthenticatedPeer,
        rpc_config: WorkerRpcConfig,
        lifecycle_bounds: LifecycleBounds,
    ) -> Result<Self, ProductionWorkerRuntimeError> {
        if !worker.control_plane_qualified() {
            return Err(ProductionWorkerRuntimeError::NotReady);
        }
        Ok(Self {
            worker,
            peer,
            rpc_config,
            lifecycle_bounds,
            artifact_maintenance: None,
        })
    }

    #[must_use]
    pub fn with_artifact_maintenance(mut self, maintenance: Arc<dyn ArtifactMaintenance>) -> Self {
        self.artifact_maintenance = Some(maintenance);
        self
    }

    pub async fn serve(
        self,
        shutdown: CancellationToken,
    ) -> Result<(), ProductionWorkerRuntimeError> {
        let lifecycle = Arc::new(ControlPlaneLifecycle {
            worker: Arc::clone(&self.worker),
            peer: self.peer.clone(),
        });
        let download_worker = Arc::clone(&self.worker);
        let download_peer = self.peer.clone();
        let journal_worker = Arc::clone(&self.worker);
        let journal_peer = self.peer.clone();
        let handler = Arc::new(WorkerControlPlaneRpcHandler::new(self.worker, self.peer));
        let server = WorkerRpcServer::bind(self.rpc_config, handler).await?;
        let runtime_shutdown = shutdown.child_token();
        let rpc_shutdown = runtime_shutdown.clone();
        let lifecycle_shutdown = runtime_shutdown.clone();
        let rpc = server.serve(rpc_shutdown);
        let lifecycle = run_worker_lifecycle(lifecycle, self.lifecycle_bounds, lifecycle_shutdown);
        tokio::pin!(rpc);
        tokio::pin!(lifecycle);

        let downloads = async {
            let mut tick = tokio::time::interval(Duration::from_secs(1));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    biased;
                    () = runtime_shutdown.cancelled() => break,
                    _ = tick.tick() => {},
                }
                let worker = Arc::clone(&download_worker);
                let peer = download_peer.clone();
                // Scanner rejection affects its download; exact rollback receipts
                // remain for retry. This task never delays the heartbeat timer.
                let _ = run_blocking(move || worker.reconcile_browser_downloads_due(&peer)).await;
            }
        };
        let supervise = async {
            tokio::select! {
                result = &mut rpc => {
                    runtime_shutdown.cancel();
                    (result, lifecycle.await)
                }
                result = &mut lifecycle => {
                    runtime_shutdown.cancel();
                    (rpc.await, result)
                }
            }
        };
        let artifacts = run_artifact_maintenance(
            self.artifact_maintenance,
            runtime_shutdown.clone(),
            ARTIFACT_MAINTENANCE_INTERVAL,
            ARTIFACT_MAINTENANCE_DEADLINE,
        );
        let journals = run_artifact_maintenance(
            Some(Arc::new(ActionJournalMaintenance {
                worker: journal_worker,
                peer: journal_peer,
            })),
            runtime_shutdown.clone(),
            ARTIFACT_MAINTENANCE_INTERVAL,
            ARTIFACT_MAINTENANCE_DEADLINE,
        );
        let ((rpc_result, lifecycle_result), (), (), ()) =
            tokio::join!(supervise, downloads, artifacts, journals);
        if let Err(error) = rpc_result {
            return Err(error.into());
        }
        lifecycle_result.map_err(Into::into)
    }
}

struct ActionJournalMaintenance<D, S> {
    worker: Arc<WorkerControlPlane<D, S>>,
    peer: AuthenticatedPeer,
}

impl<D: ChromiumDriver, S: SandboxClient> ArtifactMaintenance for ActionJournalMaintenance<D, S> {
    fn sweep_expired(&self, limit: usize, deadline: Instant) -> Result<usize, DependencyError> {
        self.worker
            .maintain_action_journals(&self.peer, limit, deadline)
            .map_err(|_| DependencyError::Unavailable)
    }
}

async fn run_artifact_maintenance(
    maintenance: Option<Arc<dyn ArtifactMaintenance>>,
    shutdown: CancellationToken,
    interval: Duration,
    timeout: Duration,
) {
    let Some(maintenance) = maintenance else {
        return;
    };
    let mut tick = tokio::time::interval(interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut active: Option<tokio::task::JoinHandle<Result<usize, DependencyError>>> = None;
    loop {
        tokio::select! {
            biased;
            () = shutdown.cancelled() => {
                // Dropping the JoinHandle detaches a started blocking callback. Its owned Arc
                // keeps the storage authority alive; shutdown never pretends to cancel a syscall.
                return;
            }
            _ = async {
                match active.as_mut() {
                    Some(operation) => { let _ = operation.await; }
                    None => std::future::pending().await,
                }
            }, if active.is_some() => {
                // Failures retry on a later scheduled tick, without changing worker readiness.
                active = None;
            }
            _ = tick.tick() => {
                // Consume missed ticks while a callback runs, including after its deadline.
                // Timing out its JoinHandle would detach it and allow overlapping passes.
                if active.is_some() {
                    continue;
                }
                let deadline = Instant::now() + timeout;
                let maintenance = Arc::clone(&maintenance);
                let operation_shutdown = shutdown.clone();
                active = Some(tokio::task::spawn_blocking(move || {
                    if operation_shutdown.is_cancelled() || Instant::now() >= deadline {
                        return Err(DependencyError::Unavailable);
                    }
                    maintenance.sweep_expired(ARTIFACT_MAINTENANCE_LIMIT, deadline)
                }));
            }
        }
    }
}

struct ControlPlaneLifecycle<D, S> {
    worker: Arc<WorkerControlPlane<D, S>>,
    peer: AuthenticatedPeer,
}

#[async_trait]
impl<D, S> WorkerLifecycleBackend for ControlPlaneLifecycle<D, S>
where
    D: ChromiumDriver,
    S: SandboxClient,
{
    async fn heartbeat(&self) -> Result<(), LifecycleBackendError> {
        let now = current_session_time()?;
        let worker = Arc::clone(&self.worker);
        let peer = self.peer.clone();
        run_blocking(move || worker.heartbeat(&peer, now)).await
    }

    async fn expire_due(&self) -> Result<(), LifecycleBackendError> {
        let now = current_session_time()?;
        let worker = Arc::clone(&self.worker);
        let peer = self.peer.clone();
        run_blocking(move || worker.expire_due(&peer, now))
            .await
            .map(|_| ())
    }

    async fn begin_drain(&self) -> Result<(), LifecycleBackendError> {
        let worker = Arc::clone(&self.worker);
        let peer = self.peer.clone();
        run_blocking(move || worker.begin_drain(&peer)).await
    }

    async fn graceful_shutdown(&self) -> Result<(), LifecycleBackendError> {
        let now = current_session_time()?;
        let worker = Arc::clone(&self.worker);
        let peer = self.peer.clone();
        run_blocking(move || worker.graceful_shutdown(&peer, now)).await
    }
}

fn current_session_time() -> Result<SessionTime, LifecycleBackendError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| LifecycleBackendError)?;
    let millis = u64::try_from(now.as_millis()).map_err(|_| LifecycleBackendError)?;
    Ok(SessionTime::new(millis))
}

async fn run_blocking<T>(
    operation: impl FnOnce() -> Result<T, WorkerError> + Send + 'static,
) -> Result<T, LifecycleBackendError>
where
    T: Send + 'static,
{
    tokio::task::spawn_blocking(operation)
        .await
        .map_err(|_| LifecycleBackendError)?
        .map_err(|_| LifecycleBackendError)
}

#[cfg(test)]
#[path = "production_runtime/artifact_maintenance_tests.rs"]
mod artifact_maintenance_tests;
