use std::fmt;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use browserd_session::SessionTime;
use browserd_worker::{
    AuthenticatedPeer, ChromiumDriver, SandboxClient, WorkerControlPlane,
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

pub struct ProductionWorkerRuntime<D, S> {
    worker: Arc<WorkerControlPlane<D, S>>,
    peer: AuthenticatedPeer,
    rpc_config: WorkerRpcConfig,
    lifecycle_bounds: LifecycleBounds,
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
        if !worker.is_ready() {
            return Err(ProductionWorkerRuntimeError::NotReady);
        }
        Ok(Self {
            worker,
            peer,
            rpc_config,
            lifecycle_bounds,
        })
    }

    pub async fn serve(
        self,
        shutdown: CancellationToken,
    ) -> Result<(), ProductionWorkerRuntimeError> {
        let lifecycle = Arc::new(ControlPlaneLifecycle {
            worker: Arc::clone(&self.worker),
            peer: self.peer.clone(),
        });
        let handler = Arc::new(WorkerControlPlaneRpcHandler::new(self.worker, self.peer));
        let server = WorkerRpcServer::bind(self.rpc_config, handler).await?;
        let runtime_shutdown = shutdown.child_token();
        let rpc_shutdown = runtime_shutdown.clone();
        let lifecycle_shutdown = runtime_shutdown.clone();
        let rpc = server.serve(rpc_shutdown);
        let lifecycle = run_worker_lifecycle(lifecycle, self.lifecycle_bounds, lifecycle_shutdown);
        tokio::pin!(rpc);
        tokio::pin!(lifecycle);

        let (rpc_result, lifecycle_result) = tokio::select! {
            result = &mut rpc => {
                runtime_shutdown.cancel();
                (result, lifecycle.await)
            }
            result = &mut lifecycle => {
                runtime_shutdown.cancel();
                (rpc.await, result)
            }
        };
        if let Err(error) = rpc_result {
            return Err(error.into());
        }
        lifecycle_result.map_err(Into::into)
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
