//! Lowering `RLIMIT_NOFILE` affects the whole process, so this test owns its binary.
#![allow(clippy::expect_used)]

use std::io::Write;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use browserd_core::{LaunchGeneration, ShardId};
use browserd_sandbox::{
    CleanupReason, InspectResources, LaunchSpec, RpcFailureCode, SandboxBackend,
    SandboxCapabilities, SandboxError, SandboxHandle, SandboxRpcClient, SandboxRpcConfig,
    SandboxRpcError, SandboxRpcServer, SandboxSupervisor, SupervisorConfig,
};
use nix::sys::resource::{Resource, getrlimit, setrlimit};
use nix::sys::socket::{AddressFamily, SockFlag, SockType, UnixAddr, connect, socket};
use tempfile::tempdir;
use tokio::io::AsyncReadExt;
use tokio::net::{UnixListener, UnixStream};
use tokio_util::sync::CancellationToken;

const SANDBOXD_EPOCH: u64 = 73;

struct UnusedBackend;

#[async_trait]
impl SandboxBackend for UnusedBackend {
    fn capabilities(&self) -> SandboxCapabilities {
        SandboxCapabilities::production_required()
    }

    async fn provision(&self, _spec: &LaunchSpec) -> Result<SandboxHandle, SandboxError> {
        Err(SandboxError::Backend("unused".into()))
    }

    async fn revoke_egress(
        &self,
        _handle: &SandboxHandle,
        _reason: CleanupReason,
    ) -> Result<(), SandboxError> {
        Err(SandboxError::Backend("unused".into()))
    }

    async fn kill_cgroup(
        &self,
        _handle: &SandboxHandle,
        _reason: CleanupReason,
    ) -> Result<(), SandboxError> {
        Err(SandboxError::Backend("unused".into()))
    }

    async fn cleanup_namespaces(&self, _handle: &SandboxHandle) -> Result<(), SandboxError> {
        Err(SandboxError::Backend("unused".into()))
    }

    async fn inspect(&self, _handle: &SandboxHandle) -> Result<InspectResources, SandboxError> {
        Err(SandboxError::Backend("unused".into()))
    }
}

#[tokio::test]
async fn descriptor_exhaustion_backs_off_and_keeps_serving() {
    let temporary = tempdir().expect("temporary directory is available");
    let socket_path = temporary.path().join("sandboxd.sock");
    let listener = UnixListener::bind(&socket_path).expect("Unix socket binds");
    let uid = nix::unistd::Uid::effective().as_raw();
    let config = SandboxRpcConfig::new(
        4 * 1024,
        4,
        Duration::from_millis(200),
        Duration::from_millis(5),
        Some(uid),
    )
    .expect("base RPC config is valid")
    .with_daemon_epoch(SANDBOXD_EPOCH)
    .expect("RPC config is valid");
    let supervisor_config =
        SupervisorConfig::new(Duration::from_millis(100), Duration::from_secs(1))
            .expect("lease ordering is valid");
    let server = SandboxRpcServer::new(
        Arc::new(SandboxSupervisor::new(supervisor_config, UnusedBackend)),
        config,
    );
    let shutdown = CancellationToken::new();
    let server_shutdown = shutdown.clone();
    let task = tokio::spawn(async move { server.serve(listener, server_shutdown).await });
    let client = SandboxRpcClient::new(
        socket_path.clone(),
        4 * 1024,
        Duration::from_secs(1),
        uid,
        SANDBOXD_EPOCH,
    )
    .expect("client config is valid");

    // connect(2) needs no new descriptor but accept(2) does, so the client socket exists before
    // the limit drops to exactly the descriptors already open.
    let parked = socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::SOCK_CLOEXEC,
        None,
    )
    .expect("client socket is created");
    let (soft_limit, hard_limit) = getrlimit(Resource::RLIMIT_NOFILE).expect("limit is readable");
    let reserve = nix::unistd::dup(&parked).expect("lowest free descriptor is reserved");
    let exhausted_limit = u64::try_from(reserve.as_raw_fd()).expect("descriptor is positive") + 1;
    setrlimit(Resource::RLIMIT_NOFILE, exhausted_limit, hard_limit).expect("limit lowers");
    connect(
        parked.as_raw_fd(),
        &UnixAddr::new(&socket_path).expect("socket path is valid"),
    )
    .expect("client connects into the backlog");
    let mut parked = std::os::unix::net::UnixStream::from(parked);
    parked
        .write_all(&[0, 0, 0, 1, b'x'])
        .expect("malformed request is queued");
    tokio::time::sleep(Duration::from_millis(200)).await;
    let stopped_while_exhausted = task.is_finished();
    setrlimit(Resource::RLIMIT_NOFILE, soft_limit, hard_limit).expect("limit restores");
    drop(reserve);
    assert!(
        !stopped_while_exhausted,
        "EMFILE from accept must not stop the RPC server"
    );

    parked
        .set_nonblocking(true)
        .expect("client socket becomes nonblocking");
    let mut parked = UnixStream::from_std(parked).expect("client socket registers");
    let mut response = [0_u8; 1];
    assert!(
        matches!(
            tokio::time::timeout(Duration::from_secs(2), parked.read(&mut response)).await,
            Ok(Ok(0))
        ),
        "the connection parked during exhaustion is accepted and rejected once descriptors free"
    );
    assert!(matches!(
        client
            .inspect_resources(
                &ShardId::new(),
                9,
                LaunchGeneration::new(1).expect("launch generation is positive"),
            )
            .await,
        Err(SandboxRpcError::Remote {
            code: RpcFailureCode::ShardNotFound,
            ..
        })
    ));

    shutdown.cancel();
    assert!(matches!(task.await, Ok(Ok(()))));
}
