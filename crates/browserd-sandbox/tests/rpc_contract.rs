#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use browserd_core::{ShardId, WorkerId};
use browserd_sandbox::{
    CleanupReason, CreateShardOutcome, InspectResources, KillShardOutcome, LaunchSpec,
    RpcFailureCode, SandboxBackend, SandboxCapabilities, SandboxError, SandboxHandle,
    SandboxRpcClient, SandboxRpcConfig, SandboxRpcError, SandboxRpcServer, SandboxSupervisor,
    SupervisorConfig,
};
use tempfile::tempdir;
use tokio::net::UnixListener;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Default)]
struct RecordingBackend {
    events: Arc<Mutex<Vec<String>>>,
}

impl RecordingBackend {
    fn record(&self, event: &str) {
        self.events.lock().unwrap().push(event.to_owned());
    }

    fn events(&self) -> Vec<String> {
        self.events.lock().unwrap().clone()
    }
}

#[async_trait]
impl SandboxBackend for RecordingBackend {
    fn capabilities(&self) -> SandboxCapabilities {
        SandboxCapabilities::production_required()
    }

    async fn provision(&self, spec: &LaunchSpec) -> Result<SandboxHandle, SandboxError> {
        self.record("provision");
        Ok(SandboxHandle::new(spec.shard_id().clone(), "rpc-handle"))
    }

    async fn revoke_egress(
        &self,
        _handle: &SandboxHandle,
        _reason: CleanupReason,
    ) -> Result<(), SandboxError> {
        self.record("revoke");
        Ok(())
    }

    async fn kill_cgroup(
        &self,
        _handle: &SandboxHandle,
        _reason: CleanupReason,
    ) -> Result<(), SandboxError> {
        self.record("kill");
        Ok(())
    }

    async fn cleanup_namespaces(&self, _handle: &SandboxHandle) -> Result<(), SandboxError> {
        self.record("cleanup");
        Ok(())
    }

    async fn inspect(&self, _handle: &SandboxHandle) -> Result<InspectResources, SandboxError> {
        Ok(InspectResources {
            memory_current_bytes: 10,
            memory_peak_bytes: 20,
            process_count: 3,
            egress_route_active: true,
        })
    }
}

#[derive(Clone)]
struct DelayedBackend {
    inner: RecordingBackend,
    started: Arc<Notify>,
    release: Arc<Notify>,
}

#[async_trait]
impl SandboxBackend for DelayedBackend {
    fn capabilities(&self) -> SandboxCapabilities {
        self.inner.capabilities()
    }

    async fn provision(&self, spec: &LaunchSpec) -> Result<SandboxHandle, SandboxError> {
        self.started.notify_one();
        self.release.notified().await;
        self.inner.provision(spec).await
    }

    async fn revoke_egress(
        &self,
        handle: &SandboxHandle,
        reason: CleanupReason,
    ) -> Result<(), SandboxError> {
        self.inner.revoke_egress(handle, reason).await
    }

    async fn kill_cgroup(
        &self,
        handle: &SandboxHandle,
        reason: CleanupReason,
    ) -> Result<(), SandboxError> {
        self.inner.kill_cgroup(handle, reason).await
    }

    async fn cleanup_namespaces(&self, handle: &SandboxHandle) -> Result<(), SandboxError> {
        self.inner.cleanup_namespaces(handle).await
    }

    async fn inspect(&self, handle: &SandboxHandle) -> Result<InspectResources, SandboxError> {
        self.inner.inspect(handle).await
    }
}

fn worker() -> WorkerId {
    WorkerId::new("worker-rpc-1").expect("worker ID is valid")
}

fn supervisor(backend: RecordingBackend) -> Arc<SandboxSupervisor<RecordingBackend>> {
    let config = SupervisorConfig::new(Duration::from_millis(100), Duration::from_secs(1))
        .expect("lease ordering is valid");
    Arc::new(SandboxSupervisor::new(config, backend))
}

fn rpc_config() -> SandboxRpcConfig {
    SandboxRpcConfig::new(
        4 * 1024,
        4,
        Duration::from_millis(200),
        Duration::from_millis(5),
        Some(nix::unistd::Uid::effective().as_raw()),
    )
    .expect("RPC config is valid")
}

#[test]
fn rpc_server_requires_an_explicit_local_peer_uid() {
    assert_eq!(
        SandboxRpcConfig::new(
            4 * 1024,
            4,
            Duration::from_millis(200),
            Duration::from_millis(5),
            None,
        ),
        Err(SandboxRpcError::InvalidConfig)
    );
}

#[tokio::test]
async fn local_rpc_round_trips_fenced_lifecycle_operations() {
    let temporary = tempdir().expect("temporary directory is available");
    let socket = temporary.path().join("sandboxd.sock");
    let listener = UnixListener::bind(&socket).expect("Unix socket binds");
    let shutdown = CancellationToken::new();
    let server = SandboxRpcServer::new(supervisor(RecordingBackend::default()), rpc_config());
    let server_shutdown = shutdown.clone();
    let task = tokio::spawn(async move { server.serve(listener, server_shutdown).await });
    let client = SandboxRpcClient::new(
        socket,
        rpc_config().max_frame_bytes(),
        Duration::from_millis(200),
    )
    .expect("client config is valid");
    let shard_id = ShardId::new();
    let spec = LaunchSpec::production(shard_id.clone(), worker(), 9);

    assert_eq!(
        client.create_shard(spec, Duration::from_millis(80)).await,
        Ok(CreateShardOutcome::Created)
    );
    assert!(matches!(
        client
            .create_shard(
                LaunchSpec::production(shard_id.clone(), worker(), 8),
                Duration::from_millis(80),
            )
            .await,
        Err(SandboxRpcError::Remote {
            code: RpcFailureCode::WorkerEpochMismatch,
            ..
        })
    ));
    assert_eq!(
        client.inspect_resources(&shard_id, 9).await,
        Ok(InspectResources {
            memory_current_bytes: 10,
            memory_peak_bytes: 20,
            process_count: 3,
            egress_route_active: true,
        })
    );
    assert!(matches!(
        client.inspect_resources(&shard_id, 8).await,
        Err(SandboxRpcError::Remote {
            code: RpcFailureCode::WorkerEpochMismatch,
            ..
        })
    ));
    assert!(
        client
            .renew_owner_lease(&shard_id, 9, Duration::from_millis(90))
            .await
            .is_ok()
    );
    assert!(matches!(
        client
            .kill_shard(&shard_id, 9, CleanupReason::Administrative)
            .await,
        Ok(KillShardOutcome::Terminated(_))
    ));

    shutdown.cancel();
    assert!(matches!(task.await, Ok(Ok(()))));
}

#[tokio::test]
async fn supervisor_sweeps_expired_rpc_leases_without_worker_cooperation() {
    let temporary = tempdir().expect("temporary directory is available");
    let socket = temporary.path().join("sandboxd.sock");
    let listener = UnixListener::bind(&socket).expect("Unix socket binds");
    let shutdown = CancellationToken::new();
    let backend = RecordingBackend::default();
    let server = SandboxRpcServer::new(supervisor(backend.clone()), rpc_config());
    let server_shutdown = shutdown.clone();
    let task = tokio::spawn(async move { server.serve(listener, server_shutdown).await });
    let client = SandboxRpcClient::new(
        socket,
        rpc_config().max_frame_bytes(),
        Duration::from_millis(200),
    )
    .expect("client config is valid");
    let shard_id = ShardId::new();

    assert_eq!(
        client
            .create_shard(
                LaunchSpec::production(shard_id.clone(), worker(), 10),
                Duration::from_millis(20),
            )
            .await,
        Ok(CreateShardOutcome::Created)
    );
    tokio::time::sleep(Duration::from_millis(60)).await;
    assert!(matches!(
        client.inspect_resources(&shard_id, 10).await,
        Err(SandboxRpcError::Remote {
            code: RpcFailureCode::ShardNotFound,
            ..
        })
    ));
    assert_eq!(backend.events(), ["provision", "revoke", "kill", "cleanup"]);

    shutdown.cancel();
    assert!(matches!(task.await, Ok(Ok(()))));
}

#[tokio::test]
async fn client_timeout_does_not_cancel_an_inflight_provision_and_skip_rollback_boundaries() {
    let temporary = tempdir().expect("temporary directory is available");
    let socket = temporary.path().join("sandboxd.sock");
    let listener = UnixListener::bind(&socket).expect("Unix socket binds");
    let shutdown = CancellationToken::new();
    let inner = RecordingBackend::default();
    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let backend = DelayedBackend {
        inner,
        started: Arc::clone(&started),
        release: Arc::clone(&release),
    };
    let supervisor_config =
        SupervisorConfig::new(Duration::from_millis(100), Duration::from_secs(1))
            .expect("lease ordering is valid");
    let supervisor = Arc::new(SandboxSupervisor::new(supervisor_config, backend));
    let server_config = SandboxRpcConfig::new(
        4 * 1024,
        4,
        Duration::from_millis(20),
        Duration::from_millis(5),
        Some(nix::unistd::Uid::effective().as_raw()),
    )
    .expect("RPC config is valid");
    let server = SandboxRpcServer::new(supervisor, server_config);
    let server_shutdown = shutdown.clone();
    let task = tokio::spawn(async move { server.serve(listener, server_shutdown).await });
    let client = SandboxRpcClient::new(socket, 4 * 1024, Duration::from_millis(10))
        .expect("client config is valid");
    let shard_id = ShardId::new();
    let request = {
        let client = client.clone();
        let shard_id = shard_id.clone();
        tokio::spawn(async move {
            client
                .create_shard(
                    LaunchSpec::production(shard_id, worker(), 11),
                    Duration::from_millis(90),
                )
                .await
        })
    };

    started.notified().await;
    assert!(matches!(request.await, Ok(Err(SandboxRpcError::TimedOut))));
    tokio::time::sleep(Duration::from_millis(20)).await;
    release.notify_one();
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert!(client.inspect_resources(&shard_id, 11).await.is_ok());

    shutdown.cancel();
    assert!(matches!(task.await, Ok(Ok(()))));
}
