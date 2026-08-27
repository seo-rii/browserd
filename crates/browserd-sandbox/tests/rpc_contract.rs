#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::{IoSlice, IoSliceMut};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use browserd_core::{
    EgressFence, LaunchGeneration, LeaseId, OwnerFence, RouteGeneration, SessionId,
    SessionIncarnation, ShardFence, ShardId, TenantId, WorkerEpoch, WorkerId,
};
use browserd_sandbox::{
    ChromiumCdpPipes, CleanupReason, CreateShardOutcome, DedicatedEgressSpec, EgressPolicyBinding,
    InspectResources, KillShardOutcome, LaunchSpec, RpcFailureCode, SandboxBackend,
    SandboxCapabilities, SandboxError, SandboxHandle, SandboxRpcClient, SandboxRpcConfig,
    SandboxRpcError, SandboxRpcServer, SandboxSupervisor, SupervisorConfig, WorkerOwnership,
};
use nix::sys::socket::{ControlMessage, ControlMessageOwned, MsgFlags, recvmsg, sendmsg};
use serde_json::json;
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt, Interest};
use tokio::net::unix::pipe::{Receiver, Sender};
use tokio::net::{UnixListener, UnixStream};
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

#[derive(Clone)]
struct ClaimingBackend {
    inner: RecordingBackend,
    pipes: Arc<Mutex<Option<ChromiumCdpPipes>>>,
    kill_called: Arc<Notify>,
}

impl ClaimingBackend {
    fn new() -> (Self, Receiver, Sender) {
        let (command_reader, command_writer) =
            nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).expect("command pipe is created");
        let (event_reader, event_writer) =
            nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).expect("event pipe is created");
        let pipes = ChromiumCdpPipes::from_owned_fds(command_writer, event_reader)
            .expect("parent capabilities are valid");
        let command_reader =
            Receiver::from_owned_fd(command_reader).expect("command reader becomes async");
        let event_writer = Sender::from_owned_fd(event_writer).expect("event writer becomes async");
        (
            Self {
                inner: RecordingBackend::default(),
                pipes: Arc::new(Mutex::new(Some(pipes))),
                kill_called: Arc::new(Notify::new()),
            },
            command_reader,
            event_writer,
        )
    }
}

#[async_trait]
impl SandboxBackend for ClaimingBackend {
    fn capabilities(&self) -> SandboxCapabilities {
        self.inner.capabilities()
    }

    async fn provision(&self, spec: &LaunchSpec) -> Result<SandboxHandle, SandboxError> {
        self.inner.provision(spec).await
    }

    async fn claim_cdp_pipes(
        &self,
        _handle: &SandboxHandle,
    ) -> Result<ChromiumCdpPipes, SandboxError> {
        self.pipes
            .lock()
            .unwrap()
            .take()
            .ok_or(SandboxError::CdpPipesAlreadyClaimed)
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
        let result = self.inner.kill_cgroup(handle, reason).await;
        self.kill_called.notify_one();
        result
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

fn launch_spec(shard_id: ShardId, worker_id: WorkerId, worker_epoch: u64) -> LaunchSpec {
    let worker_epoch = WorkerEpoch::new(worker_epoch).expect("worker epoch is positive");
    let egress_fence = EgressFence::new(
        ShardFence::new(
            OwnerFence::new(worker_id, worker_epoch),
            shard_id,
            LaunchGeneration::new(1).expect("launch generation is positive"),
        ),
        RouteGeneration::new(1).expect("route generation is positive"),
        SessionId::new(),
        SessionIncarnation::new(1).expect("session incarnation is positive"),
    );
    let policy_binding =
        EgressPolicyBinding::new("test-public-web", [1; 32]).expect("policy binding is valid");
    let dedicated_egress =
        DedicatedEgressSpec::new(egress_fence, policy_binding, Duration::from_millis(50))
            .expect("dedicated egress spec is valid");
    LaunchSpec::production(TenantId::new(), dedicated_egress)
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

async fn accept_fake_claim_through_final_receipt(listener: &UnixListener) -> UnixStream {
    let (command_reader, command_writer) =
        nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).expect("command pipe is created");
    let (event_reader, event_writer) =
        nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).expect("event pipe is created");
    let _command_reader = command_reader;
    let _event_writer = event_writer;
    let (mut stream, _) = listener.accept().await.expect("fake server accepts");
    let mut request_length = [0_u8; 4];
    stream
        .read_exact(&mut request_length)
        .await
        .expect("claim request length reads");
    let request_length = u32::from_be_bytes(request_length) as usize;
    let mut request = vec![0_u8; request_length];
    stream
        .read_exact(&mut request)
        .await
        .expect("claim request body reads");
    let request: serde_json::Value =
        serde_json::from_slice(&request).expect("claim request is JSON");
    assert_eq!(request["operation"], "claim_cdp_pipes");

    let transfer_id = LeaseId::new();
    let response = serde_json::to_vec(&json!({
        "status": "success",
        "value": {
            "result": "cdp_pipes_ready",
            "value": {"transfer_id": transfer_id.clone()}
        }
    }))
    .expect("ready response encodes");
    let response_length = u32::try_from(response.len())
        .expect("ready response fits")
        .to_be_bytes();
    stream
        .write_all(&response_length)
        .await
        .expect("ready response length writes");
    stream
        .write_all(&response)
        .await
        .expect("ready response body writes");
    let mut ready = [0_u8; 17];
    stream
        .read_exact(&mut ready)
        .await
        .expect("descriptor ready frame reads");
    assert_eq!(ready[0], 0x51);
    assert_eq!(&ready[1..], transfer_id.as_bytes());

    let descriptors = [command_writer.as_raw_fd(), event_reader.as_raw_fd()];
    let marker = [0x52];
    let bytes_sent = stream
        .async_io(Interest::WRITABLE, || {
            let buffers = [IoSlice::new(&marker)];
            let rights = ControlMessage::ScmRights(&descriptors);
            sendmsg::<()>(
                stream.as_raw_fd(),
                &buffers,
                &[rights],
                MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_NOSIGNAL,
                None,
            )
            .map_err(std::io::Error::from)
        })
        .await
        .expect("descriptor offer sends");
    assert_eq!(bytes_sent, 1);
    let offer_challenge = [0x31_u8; 16];
    stream
        .write_all(&offer_challenge)
        .await
        .expect("offer challenge writes");
    let mut accepted = [0_u8; 17];
    stream
        .read_exact(&mut accepted)
        .await
        .expect("descriptor acceptance reads");
    assert_eq!(accepted[0], 0x53);
    assert_eq!(&accepted[1..], &offer_challenge);

    let committed_challenge = [0x32_u8; 16];
    let mut committed = [0_u8; 17];
    committed[0] = 0x54;
    committed[1..].copy_from_slice(&committed_challenge);
    stream
        .write_all(&committed)
        .await
        .expect("descriptor commit writes");
    let mut final_receipt = [0_u8; 17];
    stream
        .read_exact(&mut final_receipt)
        .await
        .expect("client final receipt reads");
    assert_eq!(final_receipt[0], 0x55);
    assert_eq!(&final_receipt[1..], &committed_challenge);
    stream
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
    let spec = launch_spec(shard_id.clone(), worker(), 9);

    assert_eq!(
        client.create_shard(spec, Duration::from_millis(80)).await,
        Ok(CreateShardOutcome::Created)
    );
    assert!(matches!(
        client
            .create_shard(
                launch_spec(shard_id.clone(), worker(), 8),
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
async fn claim_cdp_pipes_transfers_exact_capabilities_once() {
    let temporary = tempdir().expect("temporary directory is available");
    let socket = temporary.path().join("sandboxd.sock");
    let listener = UnixListener::bind(&socket).expect("Unix socket binds");
    let shutdown = CancellationToken::new();
    let (backend, mut command_reader, mut event_writer) = ClaimingBackend::new();
    let supervisor_config =
        SupervisorConfig::new(Duration::from_millis(100), Duration::from_secs(1))
            .expect("lease ordering is valid");
    let supervisor = Arc::new(SandboxSupervisor::new(supervisor_config, backend));
    let server = SandboxRpcServer::new(supervisor, rpc_config());
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
                launch_spec(shard_id.clone(), worker(), 12),
                Duration::from_millis(90),
            )
            .await,
        Ok(CreateShardOutcome::Created)
    );
    let wrong_worker = WorkerId::new("worker-rpc-impostor").expect("worker ID is valid");
    assert!(matches!(
        client.claim_cdp_pipes(&shard_id, &wrong_worker, 12).await,
        Err(SandboxRpcError::Remote {
            code: RpcFailureCode::OwnershipMismatch,
            ..
        })
    ));
    assert!(matches!(
        client.claim_cdp_pipes(&shard_id, &worker(), 11).await,
        Err(SandboxRpcError::Remote {
            code: RpcFailureCode::WorkerEpochMismatch,
            ..
        })
    ));
    let pipes = client
        .claim_cdp_pipes(&shard_id, &worker(), 12)
        .await
        .expect("the exact owner should receive the CDP capabilities");
    let (command_writer, event_reader) = pipes.into_owned_fds();
    let mut command_writer =
        Sender::from_owned_fd(command_writer).expect("command writer becomes async");
    let mut event_reader =
        Receiver::from_owned_fd(event_reader).expect("event reader becomes async");

    command_writer
        .write_all(b"command")
        .await
        .expect("transferred command writer works");
    let mut command = [0_u8; 7];
    command_reader
        .read_exact(&mut command)
        .await
        .expect("the Chromium side receives commands");
    assert_eq!(&command, b"command");
    event_writer
        .write_all(b"event")
        .await
        .expect("the Chromium side emits events");
    let mut event = [0_u8; 5];
    event_reader
        .read_exact(&mut event)
        .await
        .expect("the transferred event reader works");
    assert_eq!(&event, b"event");

    drop(command_writer);
    drop(event_reader);
    let mut byte = [0_u8; 1];
    let command_eof =
        tokio::time::timeout(Duration::from_millis(200), command_reader.read(&mut byte)).await;
    assert!(
        matches!(command_eof, Ok(Ok(0))),
        "the server must close its command-writer original after the final receipt"
    );
    let event_closed = tokio::time::timeout(
        Duration::from_millis(200),
        event_writer.write_all(b"closed"),
    )
    .await;
    assert!(
        matches!(event_closed, Ok(Err(_))),
        "the server must close its event-reader original after the final receipt"
    );

    assert!(matches!(
        client.claim_cdp_pipes(&shard_id, &worker(), 12).await,
        Err(SandboxRpcError::Remote {
            code: RpcFailureCode::CdpPipesAlreadyClaimed,
            ..
        })
    ));

    shutdown.cancel();
    assert!(matches!(task.await, Ok(Ok(()))));
}

#[tokio::test]
async fn client_requires_server_completion_ack_before_reporting_claim_success() {
    let temporary = tempdir().expect("temporary directory is available");
    let socket = temporary.path().join("incomplete-sandboxd.sock");
    let listener = UnixListener::bind(&socket).expect("Unix socket binds");
    let fake_server = tokio::spawn(async move {
        drop(accept_fake_claim_through_final_receipt(&listener).await);
    });
    let client = SandboxRpcClient::new(socket, 4 * 1024, Duration::from_millis(500))
        .expect("client config is valid");

    let result = client.claim_cdp_pipes(&ShardId::new(), &worker(), 16).await;
    fake_server.await.expect("fake server finishes");

    assert!(
        result.is_err(),
        "a final client receipt is not proof that the server completed the handoff"
    );
}

#[tokio::test]
async fn cancelling_claim_while_completion_ack_is_pending_requests_exact_shard_cleanup() {
    let temporary = tempdir().expect("temporary directory is available");
    let socket = temporary.path().join("cancelled-handoff-sandboxd.sock");
    let listener = UnixListener::bind(&socket).expect("Unix socket binds");
    let final_receipt_read = Arc::new(Notify::new());
    let server_receipt = Arc::clone(&final_receipt_read);
    let fake_server = tokio::spawn(async move {
        let handoff_stream = accept_fake_claim_through_final_receipt(&listener).await;
        server_receipt.notify_one();
        let cleanup_connection =
            tokio::time::timeout(Duration::from_millis(500), listener.accept()).await;
        let Ok(Ok((mut cleanup_stream, _))) = cleanup_connection else {
            drop(handoff_stream);
            return None;
        };
        let mut request_length = [0_u8; 4];
        cleanup_stream
            .read_exact(&mut request_length)
            .await
            .expect("cleanup request length reads");
        let request_length = u32::from_be_bytes(request_length) as usize;
        let mut request = vec![0_u8; request_length];
        cleanup_stream
            .read_exact(&mut request)
            .await
            .expect("cleanup request body reads");
        let request: serde_json::Value =
            serde_json::from_slice(&request).expect("cleanup request is JSON");
        let response = serde_json::to_vec(&json!({
            "status": "failure",
            "value": {
                "code": "shard_not_found",
                "message": "the fake supervisor observed cleanup"
            }
        }))
        .expect("cleanup response encodes");
        let response_length = u32::try_from(response.len())
            .expect("cleanup response fits")
            .to_be_bytes();
        cleanup_stream
            .write_all(&response_length)
            .await
            .expect("cleanup response length writes");
        cleanup_stream
            .write_all(&response)
            .await
            .expect("cleanup response body writes");
        drop(handoff_stream);
        Some(request)
    });
    let client = SandboxRpcClient::new(socket, 4 * 1024, Duration::from_secs(1))
        .expect("client config is valid");
    let shard_id = ShardId::new();
    let claim_shard_id = shard_id.clone();
    let owner = worker();
    let claim =
        tokio::spawn(async move { client.claim_cdp_pipes(&claim_shard_id, &owner, 18).await });

    tokio::time::timeout(Duration::from_secs(2), final_receipt_read.notified())
        .await
        .expect("claim must reach the final-receipt boundary before its request timeout");
    claim.abort();
    assert!(
        claim
            .await
            .expect_err("claim task must be cancelled while completion is pending")
            .is_cancelled()
    );
    let cleanup_request = fake_server
        .await
        .expect("fake server task finishes")
        .expect("a cancelled committed handoff must issue a cleanup RPC");
    assert_eq!(cleanup_request["operation"], "kill_shard");
    assert_eq!(cleanup_request["shard_id"], json!(shard_id));
    assert_eq!(cleanup_request["worker_epoch"], 18);
    assert_eq!(cleanup_request["reason"], "browser_failure");
}

#[tokio::test]
async fn cancellation_cleanup_retries_until_supervisor_confirms_shard_is_gone() {
    let temporary = tempdir().expect("temporary directory is available");
    let socket = temporary.path().join("retry-cleanup-sandboxd.sock");
    let listener = UnixListener::bind(&socket).expect("Unix socket binds");
    let final_receipt_read = Arc::new(Notify::new());
    let server_receipt = Arc::clone(&final_receipt_read);
    let fake_server = tokio::spawn(async move {
        let handoff_stream = accept_fake_claim_through_final_receipt(&listener).await;
        server_receipt.notify_one();

        let first_connection =
            tokio::time::timeout(Duration::from_secs(1), listener.accept()).await;
        let Ok(Ok((mut first_stream, _))) = first_connection else {
            drop(handoff_stream);
            return (None, None);
        };
        let mut first_length = [0_u8; 4];
        first_stream
            .read_exact(&mut first_length)
            .await
            .expect("first cleanup request length reads");
        let first_length = u32::from_be_bytes(first_length) as usize;
        let mut first_request = vec![0_u8; first_length];
        first_stream
            .read_exact(&mut first_request)
            .await
            .expect("first cleanup request body reads");
        let first_request: serde_json::Value =
            serde_json::from_slice(&first_request).expect("first cleanup request is JSON");
        let incomplete = serde_json::to_vec(&json!({
            "status": "success",
            "value": {
                "result": "kill_shard",
                "value": "cancellation_requested"
            }
        }))
        .expect("incomplete cleanup response encodes");
        let incomplete_length = u32::try_from(incomplete.len())
            .expect("incomplete cleanup response fits")
            .to_be_bytes();
        first_stream
            .write_all(&incomplete_length)
            .await
            .expect("incomplete cleanup response length writes");
        first_stream
            .write_all(&incomplete)
            .await
            .expect("incomplete cleanup response body writes");
        drop(first_stream);

        let second_connection =
            tokio::time::timeout(Duration::from_secs(1), listener.accept()).await;
        let Ok(Ok((mut second_stream, _))) = second_connection else {
            drop(handoff_stream);
            return (Some(first_request), None);
        };
        let mut second_length = [0_u8; 4];
        second_stream
            .read_exact(&mut second_length)
            .await
            .expect("second cleanup request length reads");
        let second_length = u32::from_be_bytes(second_length) as usize;
        let mut second_request = vec![0_u8; second_length];
        second_stream
            .read_exact(&mut second_request)
            .await
            .expect("second cleanup request body reads");
        let second_request: serde_json::Value =
            serde_json::from_slice(&second_request).expect("second cleanup request is JSON");
        let gone = serde_json::to_vec(&json!({
            "status": "failure",
            "value": {
                "code": "shard_not_found",
                "message": "the fake supervisor confirms cleanup"
            }
        }))
        .expect("terminal cleanup response encodes");
        let gone_length = u32::try_from(gone.len())
            .expect("terminal cleanup response fits")
            .to_be_bytes();
        second_stream
            .write_all(&gone_length)
            .await
            .expect("terminal cleanup response length writes");
        second_stream
            .write_all(&gone)
            .await
            .expect("terminal cleanup response body writes");
        let mut eof = [0_u8; 1];
        let terminal_response_consumed =
            tokio::time::timeout(Duration::from_millis(200), second_stream.read(&mut eof)).await;
        assert!(
            matches!(terminal_response_consumed, Ok(Ok(0))),
            "the cleanup client must consume the terminal response and close its connection"
        );
        let unexpected_third =
            tokio::time::timeout(Duration::from_millis(50), listener.accept()).await;
        assert!(
            unexpected_third.is_err(),
            "a terminal shard-not-found response must stop cleanup retries"
        );
        drop(handoff_stream);
        (Some(first_request), Some(second_request))
    });
    let client = SandboxRpcClient::new(socket, 4 * 1024, Duration::from_secs(1))
        .expect("client config is valid");
    let shard_id = ShardId::new();
    let claim_shard_id = shard_id.clone();
    let owner = worker();
    let claim =
        tokio::spawn(async move { client.claim_cdp_pipes(&claim_shard_id, &owner, 19).await });

    tokio::time::timeout(Duration::from_secs(2), final_receipt_read.notified())
        .await
        .expect("claim must reach the final-receipt boundary before its request timeout");
    claim.abort();
    assert!(
        claim
            .await
            .expect_err("claim task must be cancelled while completion is pending")
            .is_cancelled()
    );
    let (first_request, second_request) = fake_server
        .await
        .expect("fake server task finishes after bounded accepts");
    let first_request = first_request.expect("cancellation must issue an initial cleanup RPC");
    let second_request = second_request
        .expect("an incomplete successful cleanup outcome must trigger another cleanup RPC");
    for cleanup_request in [&first_request, &second_request] {
        assert_eq!(cleanup_request["operation"], "kill_shard");
        assert_eq!(cleanup_request["shard_id"], json!(shard_id));
        assert_eq!(cleanup_request["worker_epoch"], 19);
        assert_eq!(cleanup_request["reason"], "browser_failure");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn expired_owner_claim_is_typed_separately_from_an_invalid_lease() {
    let temporary = tempdir().expect("temporary directory is available");
    let socket = temporary.path().join("sandboxd.sock");
    let listener = UnixListener::bind(&socket).expect("Unix socket binds");
    let (backend, _command_reader, _event_writer) = ClaimingBackend::new();
    let supervisor_config =
        SupervisorConfig::new(Duration::from_millis(100), Duration::from_secs(1))
            .expect("lease ordering is valid");
    let supervisor = Arc::new(SandboxSupervisor::new(supervisor_config, backend));
    let shard_id = ShardId::new();
    let owner = worker();
    supervisor
        .create_shard(
            launch_spec(shard_id.clone(), owner.clone(), 15),
            WorkerOwnership::new(
                owner.clone(),
                15,
                tokio::time::Instant::now() + Duration::from_millis(20),
            ),
        )
        .await
        .expect("the supervisor directly creates the test shard");
    tokio::time::sleep(Duration::from_millis(30)).await;

    let shutdown = CancellationToken::new();
    let server_config = SandboxRpcConfig::new(
        4 * 1024,
        4,
        Duration::from_secs(5),
        Duration::from_secs(5),
        Some(nix::unistd::Uid::effective().as_raw()),
    )
    .expect("RPC config is valid");
    let server = SandboxRpcServer::new(supervisor, server_config);
    let server_shutdown = shutdown.clone();
    let task = tokio::spawn(async move { server.serve(listener, server_shutdown).await });
    tokio::time::sleep(Duration::from_millis(1)).await;
    let client = SandboxRpcClient::new(socket, 4 * 1024, Duration::from_millis(200))
        .expect("client config is valid");
    let claim = client.claim_cdp_pipes(&shard_id, &owner, 15).await;

    shutdown.cancel();
    assert!(matches!(task.await, Ok(Ok(()))));
    assert!(
        matches!(
            &claim,
            Err(SandboxRpcError::Remote {
                code: RpcFailureCode::LeaseExpired,
                ..
            })
        ),
        "an expired owner must remain typed until the claim handler observes it, got {claim:?}"
    );
}

#[tokio::test]
async fn abandoning_a_ready_descriptor_handoff_kills_the_shard_and_closes_originals() {
    let temporary = tempdir().expect("temporary directory is available");
    let socket = temporary.path().join("sandboxd.sock");
    let listener = UnixListener::bind(&socket).expect("Unix socket binds");
    let shutdown = CancellationToken::new();
    let (backend, mut command_reader, mut event_writer) = ClaimingBackend::new();
    let observed_backend = backend.clone();
    let supervisor_config = SupervisorConfig::new(Duration::from_secs(1), Duration::from_secs(2))
        .expect("lease ordering is valid");
    let supervisor = Arc::new(SandboxSupervisor::new(supervisor_config, backend));
    let server = SandboxRpcServer::new(supervisor, rpc_config());
    let server_shutdown = shutdown.clone();
    let task = tokio::spawn(async move { server.serve(listener, server_shutdown).await });
    let client = SandboxRpcClient::new(
        socket.clone(),
        rpc_config().max_frame_bytes(),
        Duration::from_millis(200),
    )
    .expect("client config is valid");
    let shard_id = ShardId::new();
    let owner = worker();
    assert_eq!(
        client
            .create_shard(
                launch_spec(shard_id.clone(), owner.clone(), 13),
                Duration::from_millis(900),
            )
            .await,
        Ok(CreateShardOutcome::Created)
    );

    let mut raw_client = UnixStream::connect(&socket)
        .await
        .expect("raw worker connects");
    let request = serde_json::to_vec(&json!({
        "operation": "claim_cdp_pipes",
        "shard_id": shard_id,
        "worker_id": owner,
        "worker_epoch": 13
    }))
    .expect("raw request encodes");
    let request_length = u32::try_from(request.len())
        .expect("test request fits a frame")
        .to_be_bytes();
    raw_client
        .write_all(&request_length)
        .await
        .expect("request length writes");
    raw_client
        .write_all(&request)
        .await
        .expect("request body writes");
    let mut response_length = [0_u8; 4];
    raw_client
        .read_exact(&mut response_length)
        .await
        .expect("ready response length reads");
    let response_length = u32::from_be_bytes(response_length) as usize;
    let mut response = vec![0_u8; response_length];
    raw_client
        .read_exact(&mut response)
        .await
        .expect("ready response body reads");
    let response: serde_json::Value =
        serde_json::from_slice(&response).expect("ready response is JSON");
    assert_eq!(response["status"], "success");
    assert_eq!(response["value"]["result"], "cdp_pipes_ready");
    drop(raw_client);

    tokio::time::timeout(
        Duration::from_millis(200),
        observed_backend.kill_called.notified(),
    )
    .await
    .expect("abandoned handoff must trigger cgroup kill");
    assert_eq!(
        observed_backend.inner.events(),
        ["provision", "revoke", "kill", "cleanup"]
    );
    let mut byte = [0_u8; 1];
    let command_eof =
        tokio::time::timeout(Duration::from_millis(100), command_reader.read(&mut byte)).await;
    assert!(matches!(command_eof, Ok(Ok(0))));
    let event_closed =
        tokio::time::timeout(Duration::from_millis(100), event_writer.write_all(b"event")).await;
    assert!(matches!(event_closed, Ok(Err(_))));

    shutdown.cancel();
    assert!(matches!(task.await, Ok(Ok(()))));
}

#[tokio::test]
async fn abandoning_after_commit_before_final_receipt_kills_and_closes_every_pipe_copy() {
    let temporary = tempdir().expect("temporary directory is available");
    let socket = temporary.path().join("sandboxd.sock");
    let listener = UnixListener::bind(&socket).expect("Unix socket binds");
    let shutdown = CancellationToken::new();
    let (backend, mut command_reader, mut event_writer) = ClaimingBackend::new();
    let observed_backend = backend.clone();
    let supervisor_config = SupervisorConfig::new(Duration::from_secs(1), Duration::from_secs(2))
        .expect("lease ordering is valid");
    let supervisor = Arc::new(SandboxSupervisor::new(supervisor_config, backend));
    let server = SandboxRpcServer::new(supervisor, rpc_config());
    let server_shutdown = shutdown.clone();
    let task = tokio::spawn(async move { server.serve(listener, server_shutdown).await });
    let client = SandboxRpcClient::new(
        socket.clone(),
        rpc_config().max_frame_bytes(),
        Duration::from_millis(200),
    )
    .expect("client config is valid");
    let shard_id = ShardId::new();
    let owner = worker();
    assert_eq!(
        client
            .create_shard(
                launch_spec(shard_id.clone(), owner.clone(), 17),
                Duration::from_millis(900),
            )
            .await,
        Ok(CreateShardOutcome::Created)
    );

    let mut raw_client = UnixStream::connect(&socket)
        .await
        .expect("raw worker connects");
    let request = serde_json::to_vec(&json!({
        "operation": "claim_cdp_pipes",
        "shard_id": shard_id,
        "worker_id": owner,
        "worker_epoch": 17
    }))
    .expect("raw request encodes");
    let request_length = u32::try_from(request.len())
        .expect("test request fits a frame")
        .to_be_bytes();
    raw_client
        .write_all(&request_length)
        .await
        .expect("request length writes");
    raw_client
        .write_all(&request)
        .await
        .expect("request body writes");
    let mut response_length = [0_u8; 4];
    raw_client
        .read_exact(&mut response_length)
        .await
        .expect("ready response length reads");
    let response_length = u32::from_be_bytes(response_length) as usize;
    let mut response = vec![0_u8; response_length];
    raw_client
        .read_exact(&mut response)
        .await
        .expect("ready response body reads");
    let response: serde_json::Value =
        serde_json::from_slice(&response).expect("ready response is JSON");
    assert_eq!(response["status"], "success");
    assert_eq!(response["value"]["result"], "cdp_pipes_ready");
    let transfer_id: LeaseId =
        serde_json::from_value(response["value"]["value"]["transfer_id"].clone())
            .expect("ready response contains a transfer ID");
    let mut ready = [0_u8; 17];
    ready[0] = 0x51;
    ready[1..].copy_from_slice(transfer_id.as_bytes());
    raw_client
        .write_all(&ready)
        .await
        .expect("descriptor ready frame writes");

    let (marker, bytes, flags, rights_messages, descriptors) = raw_client
        .async_io(Interest::READABLE, || {
            let mut marker = [0_u8; 1];
            let mut control = nix::cmsg_space!([RawFd; 4]);
            let mut buffers = [IoSliceMut::new(&mut marker)];
            let message = recvmsg::<()>(
                raw_client.as_raw_fd(),
                &mut buffers,
                Some(&mut control),
                MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_CMSG_CLOEXEC,
            )
            .map_err(std::io::Error::from)?;
            let bytes = message.bytes;
            let flags = message.flags;
            let mut rights_messages = 0_usize;
            let mut descriptors = Vec::new();
            for control_message in message.cmsgs().map_err(std::io::Error::from)? {
                if let ControlMessageOwned::ScmRights(raw_descriptors) = control_message {
                    rights_messages += 1;
                    for raw_descriptor in raw_descriptors {
                        // SAFETY: recvmsg installed each descriptor into this test process.
                        descriptors.push(unsafe { OwnedFd::from_raw_fd(raw_descriptor) });
                    }
                }
            }
            Ok((marker[0], bytes, flags, rights_messages, descriptors))
        })
        .await
        .expect("descriptor offer receives");
    assert_eq!(marker, 0x52);
    assert_eq!(bytes, 1);
    assert!(!flags.intersects(MsgFlags::MSG_CTRUNC | MsgFlags::MSG_TRUNC));
    assert_eq!(rights_messages, 1);
    assert_eq!(descriptors.len(), 2);
    let mut offer_challenge = [0_u8; 16];
    raw_client
        .read_exact(&mut offer_challenge)
        .await
        .expect("offer challenge reads");
    let mut accepted = [0_u8; 17];
    accepted[0] = 0x53;
    accepted[1..].copy_from_slice(&offer_challenge);
    raw_client
        .write_all(&accepted)
        .await
        .expect("descriptor acceptance writes");
    let mut committed = [0_u8; 17];
    raw_client
        .read_exact(&mut committed)
        .await
        .expect("descriptor commit reads");
    assert_eq!(committed[0], 0x54);

    drop(raw_client);
    tokio::time::timeout(
        Duration::from_millis(200),
        observed_backend.kill_called.notified(),
    )
    .await
    .expect("missing final receipt must trigger cgroup kill");
    assert_eq!(
        observed_backend.inner.events(),
        ["provision", "revoke", "kill", "cleanup"]
    );
    drop(descriptors);
    let mut byte = [0_u8; 1];
    let command_eof =
        tokio::time::timeout(Duration::from_millis(100), command_reader.read(&mut byte)).await;
    assert!(matches!(command_eof, Ok(Ok(0))));
    let event_closed =
        tokio::time::timeout(Duration::from_millis(100), event_writer.write_all(b"event")).await;
    assert!(matches!(event_closed, Ok(Err(_))));

    shutdown.cancel();
    assert!(matches!(task.await, Ok(Ok(()))));
}

#[tokio::test]
async fn client_rejects_excess_descriptors_and_closes_every_received_copy() {
    let temporary = tempdir().expect("temporary directory is available");
    let socket = temporary.path().join("malicious-sandboxd.sock");
    let listener = UnixListener::bind(&socket).expect("Unix socket binds");
    let (command_reader, command_writer) =
        nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).expect("command pipe is created");
    let (event_reader, event_writer) =
        nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).expect("event pipe is created");
    let (extra_reader, extra_writer) =
        nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).expect("extra pipe is created");
    let mut command_reader =
        Receiver::from_owned_fd(command_reader).expect("command reader becomes async");
    let mut event_writer = Sender::from_owned_fd(event_writer).expect("event writer becomes async");
    let mut extra_reader =
        Receiver::from_owned_fd(extra_reader).expect("extra reader becomes async");
    let fake_server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("fake server accepts");
        let mut request_length = [0_u8; 4];
        stream
            .read_exact(&mut request_length)
            .await
            .expect("claim request length reads");
        let request_length = u32::from_be_bytes(request_length) as usize;
        let mut request = vec![0_u8; request_length];
        stream
            .read_exact(&mut request)
            .await
            .expect("claim request body reads");
        let request: serde_json::Value =
            serde_json::from_slice(&request).expect("claim request is JSON");
        assert_eq!(request["operation"], "claim_cdp_pipes");

        let transfer_id = LeaseId::new();
        let response = serde_json::to_vec(&json!({
            "status": "success",
            "value": {
                "result": "cdp_pipes_ready",
                "value": {"transfer_id": transfer_id.clone()}
            }
        }))
        .expect("ready response encodes");
        let response_length = u32::try_from(response.len())
            .expect("ready response fits")
            .to_be_bytes();
        stream
            .write_all(&response_length)
            .await
            .expect("ready response length writes");
        stream
            .write_all(&response)
            .await
            .expect("ready response body writes");
        let mut ready = [0_u8; 17];
        stream
            .read_exact(&mut ready)
            .await
            .expect("descriptor ready frame reads");
        assert_eq!(ready[0], 0x51);
        assert_eq!(&ready[1..], transfer_id.as_bytes());

        let descriptors = [
            command_writer.as_raw_fd(),
            event_reader.as_raw_fd(),
            extra_writer.as_raw_fd(),
        ];
        let marker = [0x52];
        let bytes_sent = stream
            .async_io(Interest::WRITABLE, || {
                let buffers = [IoSlice::new(&marker)];
                let rights = ControlMessage::ScmRights(&descriptors);
                sendmsg::<()>(
                    stream.as_raw_fd(),
                    &buffers,
                    &[rights],
                    MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_NOSIGNAL,
                    None,
                )
                .map_err(std::io::Error::from)
            })
            .await
            .expect("malformed descriptor offer sends");
        assert_eq!(bytes_sent, 1);
        drop(command_writer);
        drop(event_reader);
        drop(extra_writer);
    });
    let client = SandboxRpcClient::new(socket, 4 * 1024, Duration::from_millis(200))
        .expect("client config is valid");

    assert!(matches!(
        client.claim_cdp_pipes(&ShardId::new(), &worker(), 14).await,
        Err(SandboxRpcError::Protocol)
    ));
    fake_server.await.expect("fake server finishes");

    let mut byte = [0_u8; 1];
    let command_eof =
        tokio::time::timeout(Duration::from_millis(100), command_reader.read(&mut byte)).await;
    assert!(matches!(command_eof, Ok(Ok(0))));
    let event_closed =
        tokio::time::timeout(Duration::from_millis(100), event_writer.write_all(b"event")).await;
    assert!(matches!(event_closed, Ok(Err(_))));
    let extra_eof =
        tokio::time::timeout(Duration::from_millis(100), extra_reader.read(&mut byte)).await;
    assert!(matches!(extra_eof, Ok(Ok(0))));
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
                launch_spec(shard_id.clone(), worker(), 10),
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
                    launch_spec(shard_id, worker(), 11),
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
