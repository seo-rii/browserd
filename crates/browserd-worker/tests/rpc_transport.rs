use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixListener as StdUnixListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

use async_trait::async_trait;
use browserd_actions::{ActionKind, ActionSequence};
use browserd_core::{
    ActionId, LeaseId, OperationId, PageId, PrincipalId, SessionId, TenantId, WorkerId,
};
use browserd_worker::{
    WORKER_RPC_PROTOCOL_VERSION, WorkerActionCommand, WorkerActionExecutionTimeout,
    WorkerActionReceipt, WorkerActionStatus, WorkerCreateSessionReceipt,
    WorkerCreateSessionRequest, WorkerIsolationProfile, WorkerProbeReceipt, WorkerRpcClient,
    WorkerRpcCompletionError, WorkerRpcConfig, WorkerRpcError, WorkerRpcHandler, WorkerRpcRequest,
    WorkerRpcResponse, WorkerRpcServer, WorkerSessionFence,
};
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

struct BlockingCreateHandler {
    calls: AtomicUsize,
    started: Semaphore,
    release: Semaphore,
    receipt: WorkerCreateSessionReceipt,
}

struct KeyedCreateHandler {
    slow_started: Semaphore,
    slow_release: Semaphore,
}

struct MismatchedActionHandler;

struct LargeResponseHandler;

#[async_trait]
impl WorkerRpcHandler for LargeResponseHandler {
    async fn handle(&self, _request: WorkerRpcRequest) -> WorkerRpcResponse {
        WorkerRpcResponse::Action(WorkerActionReceipt {
            fence: WorkerSessionFence {
                tenant_id: TenantId::new(),
                session_id: SessionId::new(),
                worker_epoch: 41,
                placement_version: 1,
                session_incarnation: 1,
            },
            action_id: ActionId::new(),
            action_sequence: ActionSequence::new(1),
            idempotency_key: "large-response".to_owned(),
            canonical_request_hash: [7; 32],
            kind: ActionKind::ReadOnly,
            status: WorkerActionStatus::Succeeded,
            dispatch_acknowledged: true,
            approval_decision: None,
            terminal_detail: None,
            result: Some(vec![0; 256 * 1024]),
            resolution: None,
        })
    }
}

struct DrainingProbeHandler {
    started: Semaphore,
    release: Semaphore,
}

#[async_trait]
impl WorkerRpcHandler for DrainingProbeHandler {
    async fn handle(&self, request: WorkerRpcRequest) -> WorkerRpcResponse {
        let WorkerRpcRequest::Probe {
            expected_worker_epoch,
        } = request
        else {
            return WorkerRpcResponse::Empty;
        };
        self.started.add_permits(1);
        let permit = self.release.acquire().await;
        assert!(permit.is_ok());
        if let Ok(permit) = permit {
            permit.forget();
        }
        let worker_id = WorkerId::new("worker-draining-transport");
        assert!(worker_id.is_ok());
        let Some(worker_id) = worker_id.ok() else {
            return WorkerRpcResponse::Empty;
        };
        WorkerRpcResponse::Probe(WorkerProbeReceipt {
            worker_id,
            worker_epoch: expected_worker_epoch,
            ready: true,
        })
    }
}

#[async_trait]
impl WorkerRpcHandler for MismatchedActionHandler {
    async fn handle(&self, request: WorkerRpcRequest) -> WorkerRpcResponse {
        let WorkerRpcRequest::SubmitAction {
            fence,
            action_sequence,
            idempotency_key,
            canonical_request_hash,
            kind,
            ..
        } = request
        else {
            return WorkerRpcResponse::Empty;
        };
        WorkerRpcResponse::Action(WorkerActionReceipt {
            fence,
            action_id: ActionId::new(),
            action_sequence,
            idempotency_key,
            canonical_request_hash,
            kind,
            status: WorkerActionStatus::Queued,
            dispatch_acknowledged: false,
            approval_decision: None,
            terminal_detail: None,
            result: None,
            resolution: None,
        })
    }
}

#[async_trait]
impl WorkerRpcHandler for KeyedCreateHandler {
    async fn handle(&self, request: WorkerRpcRequest) -> WorkerRpcResponse {
        let WorkerRpcRequest::CreateSession(request) = request else {
            return WorkerRpcResponse::Empty;
        };
        if request.idempotency_key == "slow" {
            self.slow_started.add_permits(1);
            let permit = self.slow_release.acquire().await;
            assert!(permit.is_ok());
            if let Ok(permit) = permit {
                permit.forget();
            }
        }
        WorkerRpcResponse::SessionCreated(WorkerCreateSessionReceipt {
            operation_id: request.operation_id,
            tenant_id: request.tenant_id,
            session_id: SessionId::new(),
            session_incarnation: request.session_incarnation,
            effective_isolation: request.requested_isolation,
            primary_page_id: PageId::new(),
            worker_epoch: request.expected_worker_epoch,
            placement_version: request.placement_version,
            existing: false,
        })
    }
}

#[async_trait]
impl WorkerRpcHandler for BlockingCreateHandler {
    async fn handle(&self, request: WorkerRpcRequest) -> WorkerRpcResponse {
        if let WorkerRpcRequest::Probe {
            expected_worker_epoch,
        } = request
        {
            let worker_id = WorkerId::new("worker-transport");
            assert!(worker_id.is_ok());
            let Some(worker_id) = worker_id.ok() else {
                return WorkerRpcResponse::Empty;
            };
            return WorkerRpcResponse::Probe(WorkerProbeReceipt {
                worker_id,
                worker_epoch: expected_worker_epoch,
                ready: true,
            });
        }
        if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            self.started.add_permits(1);
            let permit = self.release.acquire().await;
            assert!(permit.is_ok());
            if let Ok(permit) = permit {
                permit.forget();
            }
        }
        WorkerRpcResponse::SessionCreated(self.receipt.clone())
    }
}

fn current_uid() -> Option<u32> {
    let (stream, _peer) = UnixStream::pair().ok()?;
    Some(stream.peer_cred().ok()?.uid())
}

fn create_request(operation_id: OperationId) -> WorkerCreateSessionRequest {
    WorkerCreateSessionRequest {
        operation_id,
        tenant_id: TenantId::new(),
        idempotency_key: "create-1".to_owned(),
        canonical_request_hash: [7; 32],
        expected_worker_epoch: 41,
        placement_version: 9,
        session_incarnation: 1,
        requested_isolation: WorkerIsolationProfile::SharedContext,
        now_unix_millis: 1234,
    }
}

#[tokio::test]
async fn server_owns_a_private_socket_and_removes_it_after_shutdown() {
    let Some(uid) = current_uid() else {
        return;
    };
    let directory = tempfile::tempdir();
    assert!(directory.is_ok());
    let Some(directory) = directory.ok() else {
        return;
    };
    let socket_path = directory.path().join("worker-owned.sock");
    let config = WorkerRpcConfig::new(
        socket_path.clone(),
        16 * 1024,
        2,
        Duration::from_millis(250),
        Some(uid),
    );
    assert!(config.is_ok());
    let Some(config) = config.ok() else {
        return;
    };
    let server = WorkerRpcServer::bind(config, Arc::new(MismatchedActionHandler)).await;
    assert!(server.is_ok());
    let metadata = std::fs::symlink_metadata(&socket_path);
    assert!(metadata.is_ok());
    assert_eq!(
        metadata.ok().map(|metadata| metadata.mode() & 0o777),
        Some(0o600)
    );
    let Some(server) = server.ok() else {
        return;
    };
    let shutdown = CancellationToken::new();
    let server_task = tokio::spawn(server.serve(shutdown.clone()));
    shutdown.cancel();
    let stopped = tokio::time::timeout(Duration::from_secs(1), server_task).await;
    assert!(stopped.is_ok_and(|joined| joined.is_ok_and(|result| result.is_ok())));
    assert!(!socket_path.exists());
}

#[tokio::test]
async fn server_reclaims_an_owned_private_stale_socket() {
    let Some(uid) = current_uid() else {
        return;
    };
    let directory = tempfile::tempdir();
    assert!(directory.is_ok());
    let Some(directory) = directory.ok() else {
        return;
    };
    let socket_path = directory.path().join("worker-stale.sock");
    let stale = StdUnixListener::bind(&socket_path);
    assert!(stale.is_ok());
    assert!(std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600)).is_ok());
    drop(stale);
    let config = WorkerRpcConfig::new(
        socket_path.clone(),
        16 * 1024,
        2,
        Duration::from_millis(250),
        Some(uid),
    );
    assert!(config.is_ok());
    let Some(config) = config.ok() else {
        return;
    };
    let server = WorkerRpcServer::bind(config, Arc::new(MismatchedActionHandler)).await;
    assert!(
        server.is_ok(),
        "an owned stale socket should be recoverable"
    );
    drop(server);
    assert!(!socket_path.exists());
}

#[tokio::test]
async fn server_refuses_to_bind_while_the_singleton_lock_is_owned() {
    let Some(uid) = current_uid() else {
        return;
    };
    let directory = tempfile::tempdir();
    assert!(directory.is_ok());
    let Some(directory) = directory.ok() else {
        return;
    };
    let socket_path = directory.path().join("worker-locked.sock");
    let mut lock_path = socket_path.as_os_str().to_os_string();
    lock_path.push(".lock");
    let lock_fd = nix::fcntl::open(
        std::path::Path::new(&lock_path),
        nix::fcntl::OFlag::O_RDWR
            | nix::fcntl::OFlag::O_CREAT
            | nix::fcntl::OFlag::O_CLOEXEC
            | nix::fcntl::OFlag::O_NOFOLLOW,
        nix::sys::stat::Mode::from_bits_truncate(0o600),
    );
    assert!(lock_fd.is_ok());
    let Some(lock_fd) = lock_fd.ok() else {
        return;
    };
    let singleton = nix::fcntl::Flock::lock(lock_fd, nix::fcntl::FlockArg::LockExclusiveNonblock);
    assert!(singleton.is_ok());
    let config = WorkerRpcConfig::new(
        socket_path.clone(),
        16 * 1024,
        2,
        Duration::from_millis(250),
        Some(uid),
    );
    assert!(config.is_ok());
    let Some(config) = config.ok() else {
        return;
    };
    let server = WorkerRpcServer::bind(config, Arc::new(MismatchedActionHandler)).await;
    assert!(server.is_err());
    assert!(!socket_path.exists());
    drop(singleton);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn server_drains_every_accepted_connection_before_returning() {
    let Some(uid) = current_uid() else {
        return;
    };
    let directory = tempfile::tempdir();
    assert!(directory.is_ok());
    let Some(directory) = directory.ok() else {
        return;
    };
    let socket_path = directory.path().join("worker-drain.sock");
    let config = WorkerRpcConfig::new(
        socket_path.clone(),
        16 * 1024,
        2,
        Duration::from_secs(2),
        Some(uid),
    );
    assert!(config.is_ok());
    let Some(config) = config.ok() else {
        return;
    };
    let handler = Arc::new(DrainingProbeHandler {
        started: Semaphore::new(0),
        release: Semaphore::new(0),
    });
    let server = WorkerRpcServer::bind(config.clone(), Arc::clone(&handler)).await;
    assert!(server.is_ok());
    let Some(server) = server.ok() else {
        return;
    };
    let shutdown = CancellationToken::new();
    let mut server_task = tokio::spawn(server.serve(shutdown.clone()));
    let client = WorkerRpcClient::new(
        socket_path,
        config.max_frame_bytes(),
        Duration::from_secs(2),
        Some(uid),
    );
    assert!(client.is_ok());
    let Some(client) = client.ok() else {
        return;
    };
    let request = tokio::spawn(async move { client.probe(41).await });
    let started = handler.started.acquire().await;
    assert!(started.is_ok());
    if let Ok(started) = started {
        started.forget();
    }

    shutdown.cancel();
    assert!(
        tokio::time::timeout(Duration::from_millis(50), &mut server_task)
            .await
            .is_err(),
        "server returned before its accepted handler completed"
    );
    handler.release.add_permits(1);
    assert!(request.await.is_ok_and(|result| result.is_ok()));
    assert!(server_task.await.is_ok_and(|result| result.is_ok()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn server_shutdown_bounds_a_nonreading_response_peer() {
    let Some(uid) = current_uid() else {
        return;
    };
    let directory = tempfile::tempdir();
    assert!(directory.is_ok());
    let Some(directory) = directory.ok() else {
        return;
    };
    let socket_path = directory.path().join("worker-nonreading.sock");
    let config = WorkerRpcConfig::new(
        socket_path.clone(),
        4 * 1024 * 1024,
        2,
        Duration::from_millis(100),
        Some(uid),
    );
    assert!(config.is_ok());
    let Some(config) = config.ok() else {
        return;
    };
    let server = WorkerRpcServer::bind(config, Arc::new(LargeResponseHandler)).await;
    assert!(server.is_ok());
    let Some(server) = server.ok() else {
        return;
    };
    let shutdown = CancellationToken::new();
    let mut server_task = tokio::spawn(server.serve(shutdown.clone()));
    let stream = UnixStream::connect(&socket_path).await;
    assert!(stream.is_ok());
    let Some(mut stream) = stream.ok() else {
        return;
    };
    let request = serde_json::to_vec(&serde_json::json!({
        "protocol_version": WORKER_RPC_PROTOCOL_VERSION,
        "request_id": LeaseId::new(),
        "request": WorkerRpcRequest::Probe {
            expected_worker_epoch: 41,
        },
    }));
    assert!(request.is_ok());
    let Some(request) = request.ok() else {
        return;
    };
    let length = u32::try_from(request.len()).map(u32::to_be_bytes);
    assert!(length.is_ok());
    let Some(length) = length.ok() else {
        return;
    };
    assert!(stream.write_all(&length).await.is_ok());
    assert!(stream.write_all(&request).await.is_ok());
    tokio::time::sleep(Duration::from_millis(20)).await;

    shutdown.cancel();
    let stopped = tokio::time::timeout(Duration::from_secs(1), &mut server_task).await;
    if stopped.is_err() {
        drop(stream);
        let _ = tokio::time::timeout(Duration::from_secs(1), server_task).await;
    }
    assert!(
        stopped.is_ok(),
        "a peer that never reads its response kept shutdown open past the request timeout"
    );
}

#[tokio::test]
async fn blocking_client_separates_enqueue_acceptance_from_completion_failure() {
    let Some(uid) = current_uid() else {
        return;
    };
    let missing_socket = std::env::temp_dir().join(format!(
        "browserd-missing-worker-{}.sock",
        OperationId::new()
    ));
    let client = WorkerRpcClient::new(
        missing_socket,
        16 * 1024,
        Duration::from_millis(100),
        Some(uid),
    );
    assert!(client.is_ok());
    let Some(client) = client.ok() else {
        return;
    };
    let blocking = client.blocking(1);
    assert!(blocking.is_ok());
    let Some(blocking) = blocking.ok() else {
        return;
    };

    let pending = blocking.enqueue(WorkerRpcRequest::Probe {
        expected_worker_epoch: 41,
    });
    assert!(pending.is_ok());
    let Some(pending) = pending.ok() else {
        return;
    };
    assert!(matches!(
        pending.wait(),
        Err(WorkerRpcCompletionError::Exchange(WorkerRpcError::Io(_)))
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn accepted_create_survives_caller_disconnect_and_retry_returns_the_same_receipt() {
    let Some(uid) = current_uid() else {
        return;
    };
    let directory = tempfile::tempdir();
    assert!(directory.is_ok());
    let Some(directory) = directory.ok() else {
        return;
    };
    let socket_path = directory.path().join("worker.sock");
    let config = WorkerRpcConfig::new(
        socket_path.clone(),
        16 * 1024,
        4,
        Duration::from_secs(2),
        Some(uid),
    );
    assert!(config.is_ok());
    let Some(config) = config.ok() else {
        return;
    };
    let operation_id = OperationId::new();
    let receipt = WorkerCreateSessionReceipt {
        operation_id: operation_id.clone(),
        tenant_id: TenantId::new(),
        session_id: SessionId::new(),
        session_incarnation: 1,
        effective_isolation: WorkerIsolationProfile::SharedContext,
        primary_page_id: PageId::new(),
        worker_epoch: 41,
        placement_version: 9,
        existing: false,
    };
    let handler = Arc::new(BlockingCreateHandler {
        calls: AtomicUsize::new(0),
        started: Semaphore::new(0),
        release: Semaphore::new(0),
        receipt: receipt.clone(),
    });
    let server = WorkerRpcServer::bind(config.clone(), handler.clone()).await;
    assert!(server.is_ok());
    let Some(server) = server.ok() else {
        return;
    };
    let shutdown = CancellationToken::new();
    let server_task = tokio::spawn(server.serve(shutdown.clone()));
    let client = WorkerRpcClient::new(
        socket_path,
        config.max_frame_bytes(),
        Duration::from_secs(2),
        Some(uid),
    );
    assert!(client.is_ok());
    let Some(client) = client.ok() else {
        return;
    };

    let first = {
        let client = client.clone();
        let request = create_request(operation_id.clone());
        tokio::spawn(async move { client.create_session(request).await })
    };
    let started = handler.started.acquire().await;
    assert!(started.is_ok());
    if let Ok(started) = started {
        started.forget();
    }
    first.abort();
    handler.release.add_permits(1);

    let retry = client.create_session(create_request(operation_id)).await;
    assert_eq!(retry, Ok(receipt));

    let blocking = client.blocking(4);
    assert!(blocking.is_ok());
    let Some(blocking) = blocking.ok() else {
        return;
    };
    let blocking_receipt = blocking.create_session(create_request(OperationId::new()));
    assert!(blocking_receipt.is_ok());
    let probe = blocking.probe(41);
    assert!(probe.is_ok());
    assert!(probe.is_ok_and(|receipt| receipt.worker_epoch == 41 && receipt.ready));
    assert_eq!(blocking.probe(0), Err(WorkerRpcError::InvalidRequest));

    shutdown.cancel();
    let stopped = server_task.await;
    assert!(stopped.is_ok());
    assert!(stopped.ok().is_some_and(|result| result.is_ok()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn blocking_client_runs_independent_exchanges_without_head_of_line_blocking() {
    let Some(uid) = current_uid() else {
        return;
    };
    let directory = tempfile::tempdir();
    assert!(directory.is_ok());
    let Some(directory) = directory.ok() else {
        return;
    };
    let socket_path = directory.path().join("worker-concurrent.sock");
    let config = WorkerRpcConfig::new(
        socket_path.clone(),
        16 * 1024,
        4,
        Duration::from_secs(2),
        Some(uid),
    );
    assert!(config.is_ok());
    let Some(config) = config.ok() else {
        return;
    };
    let handler = Arc::new(KeyedCreateHandler {
        slow_started: Semaphore::new(0),
        slow_release: Semaphore::new(0),
    });
    let server = WorkerRpcServer::bind(config.clone(), handler.clone()).await;
    assert!(server.is_ok());
    let Some(server) = server.ok() else {
        return;
    };
    let shutdown = CancellationToken::new();
    let server_task = tokio::spawn(server.serve(shutdown.clone()));
    let client = WorkerRpcClient::new(
        socket_path,
        config.max_frame_bytes(),
        Duration::from_secs(2),
        Some(uid),
    );
    assert!(client.is_ok());
    let Some(client) = client.ok() else {
        return;
    };
    let blocking = client.blocking_with_limits(2, 2);
    assert!(blocking.is_ok());
    let Some(blocking) = blocking.ok() else {
        return;
    };

    let slow = {
        let blocking = blocking.clone();
        thread::spawn(move || {
            let mut request = create_request(OperationId::new());
            request.idempotency_key = "slow".to_owned();
            blocking.create_session(request)
        })
    };
    let started = handler.slow_started.acquire().await;
    assert!(started.is_ok());
    if let Ok(started) = started {
        started.forget();
    }

    let fast = {
        let blocking = blocking.clone();
        tokio::task::spawn_blocking(move || {
            let mut request = create_request(OperationId::new());
            request.idempotency_key = "fast".to_owned();
            blocking.create_session(request)
        })
    };
    let fast_result = tokio::time::timeout(Duration::from_millis(500), fast).await;
    assert!(fast_result.is_ok());
    assert!(fast_result.ok().is_some_and(|joined| joined.is_ok()));

    handler.slow_release.add_permits(1);
    assert!(slow.join().is_ok_and(|result| result.is_ok()));
    shutdown.cancel();
    assert!(server_task.await.is_ok_and(|result| result.is_ok()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn blocking_client_fails_closed_when_bounded_ingress_is_full() {
    let Some(uid) = current_uid() else {
        return;
    };
    let directory = tempfile::tempdir();
    assert!(directory.is_ok());
    let Some(directory) = directory.ok() else {
        return;
    };
    let socket_path = directory.path().join("worker-overload.sock");
    let config = WorkerRpcConfig::new(
        socket_path.clone(),
        16 * 1024,
        2,
        Duration::from_secs(2),
        Some(uid),
    );
    assert!(config.is_ok());
    let Some(config) = config.ok() else {
        return;
    };
    let handler = Arc::new(KeyedCreateHandler {
        slow_started: Semaphore::new(0),
        slow_release: Semaphore::new(0),
    });
    let server = WorkerRpcServer::bind(config.clone(), handler.clone()).await;
    assert!(server.is_ok());
    let Some(server) = server.ok() else {
        return;
    };
    let shutdown = CancellationToken::new();
    let server_task = tokio::spawn(server.serve(shutdown.clone()));
    let client = WorkerRpcClient::new(
        socket_path,
        config.max_frame_bytes(),
        Duration::from_secs(2),
        Some(uid),
    );
    assert!(client.is_ok());
    let Some(client) = client.ok() else {
        return;
    };
    let blocking = client.blocking_with_limits(1, 1);
    assert!(blocking.is_ok());
    let Some(blocking) = blocking.ok() else {
        return;
    };

    let first = {
        let blocking = blocking.clone();
        thread::spawn(move || {
            let mut request = create_request(OperationId::new());
            request.idempotency_key = "slow".to_owned();
            blocking.create_session(request)
        })
    };
    let started = handler.slow_started.acquire().await;
    assert!(started.is_ok());
    if let Ok(started) = started {
        started.forget();
    }

    let contenders = 8;
    let start = Arc::new(Barrier::new(contenders + 1));
    let (result_sender, result_receiver) = std::sync::mpsc::channel();
    let mut joins = Vec::new();
    for index in 0..contenders {
        let blocking = blocking.clone();
        let start = start.clone();
        let result_sender = result_sender.clone();
        joins.push(thread::spawn(move || {
            start.wait();
            let mut request = create_request(OperationId::new());
            request.idempotency_key = format!("queued-{index}");
            let _ = result_sender.send(blocking.create_session(request));
        }));
    }
    drop(result_sender);
    start.wait();
    let mut queue_full = 0;
    while queue_full < contenders - 1 {
        let result = result_receiver.recv_timeout(Duration::from_secs(1));
        assert!(result.is_ok());
        if matches!(result.ok(), Some(Err(WorkerRpcError::QueueFull))) {
            queue_full += 1;
        }
    }
    assert_eq!(queue_full, contenders - 1);

    handler.slow_release.add_permits(2);
    assert!(first.join().is_ok_and(|result| result.is_ok()));
    for join in joins {
        assert!(join.join().is_ok());
    }
    shutdown.cancel();
    assert!(server_task.await.is_ok_and(|result| result.is_ok()));
}

#[tokio::test]
async fn action_client_rejects_a_receipt_with_a_different_identity() {
    let Some(uid) = current_uid() else {
        return;
    };
    let directory = tempfile::tempdir();
    assert!(directory.is_ok());
    let Some(directory) = directory.ok() else {
        return;
    };
    let socket_path = directory.path().join("action-worker.sock");
    let config = WorkerRpcConfig::new(
        socket_path.clone(),
        16 * 1024,
        2,
        Duration::from_secs(2),
        Some(uid),
    );
    assert!(config.is_ok());
    let Some(config) = config.ok() else {
        return;
    };
    let server = WorkerRpcServer::bind(config.clone(), Arc::new(MismatchedActionHandler)).await;
    assert!(server.is_ok());
    let Some(server) = server.ok() else {
        return;
    };
    let shutdown = CancellationToken::new();
    let server_task = tokio::spawn(server.serve(shutdown.clone()));
    let client = WorkerRpcClient::new(
        socket_path,
        config.max_frame_bytes(),
        Duration::from_secs(2),
        Some(uid),
    );
    assert!(client.is_ok());
    let Some(client) = client.ok() else {
        return;
    };
    let request = WorkerRpcRequest::SubmitAction {
        fence: WorkerSessionFence {
            tenant_id: TenantId::new(),
            session_id: SessionId::new(),
            worker_epoch: 41,
            placement_version: 9,
            session_incarnation: 1,
        },
        action_id: ActionId::new(),
        action_sequence: ActionSequence::new(1),
        requester_principal_id: PrincipalId::new(),
        idempotency_key: "action-correlation".to_owned(),
        canonical_request_hash: [7; 32],
        kind: ActionKind::Mutating,
        page_id: Some(PageId::new()),
        action: WorkerActionCommand::Reload,
        execution_timeout_ms: WorkerActionExecutionTimeout::DEFAULT,
        approval: None,
        now_unix_millis: 1,
    };
    assert_eq!(
        client.execute_action(request).await,
        Err(WorkerRpcError::Protocol)
    );

    shutdown.cancel();
    assert!(server_task.await.is_ok_and(|result| result.is_ok()));
}

#[tokio::test]
async fn client_rejects_a_future_response_variant_as_a_protocol_violation() {
    let response = serde_json::json!({
        "protocol_version": WORKER_RPC_PROTOCOL_VERSION,
        "response": {"result": "future_response", "value": {}},
    });
    let result = exchange_with_raw_response(response).await;
    assert_eq!(result, Err(WorkerRpcError::Protocol));
}

#[tokio::test]
async fn client_rejects_a_response_from_another_protocol_version() {
    let response = serde_json::json!({
        "protocol_version": WORKER_RPC_PROTOCOL_VERSION + 1,
        "response": {"result": "empty"},
    });
    let result = exchange_with_raw_response(response).await;
    assert_eq!(result, Err(WorkerRpcError::Protocol));
}

async fn exchange_with_raw_response(
    mut response: serde_json::Value,
) -> Result<WorkerRpcResponse, WorkerRpcError> {
    let Some(uid) = current_uid() else {
        return Err(WorkerRpcError::Runtime);
    };
    let directory = tempfile::tempdir().map_err(|error| WorkerRpcError::Io(error.to_string()))?;
    let socket_path = directory.path().join("raw-worker.sock");
    let listener = StdUnixListener::bind(&socket_path)
        .map_err(|error| WorkerRpcError::Io(error.to_string()))?;
    let server = thread::spawn(move || {
        let accepted = listener.accept();
        assert!(accepted.is_ok());
        let Some((mut stream, _)) = accepted.ok() else {
            return;
        };
        let mut length = [0_u8; 4];
        assert!(stream.read_exact(&mut length).is_ok());
        let mut request = vec![0; u32::from_be_bytes(length) as usize];
        assert!(stream.read_exact(&mut request).is_ok());
        let request: serde_json::Value = serde_json::from_slice(&request).unwrap_or_default();
        response["request_id"] = request["request_id"].clone();
        let encoded = serde_json::to_vec(&response).unwrap_or_default();
        let length = u32::try_from(encoded.len())
            .unwrap_or_default()
            .to_be_bytes();
        assert!(stream.write_all(&length).is_ok());
        assert!(stream.write_all(&encoded).is_ok());
    });
    let client = WorkerRpcClient::new(socket_path, 16 * 1024, Duration::from_secs(1), Some(uid))?;
    let result = client
        .exchange(WorkerRpcRequest::GetSession {
            fence: WorkerSessionFence {
                tenant_id: TenantId::new(),
                session_id: SessionId::new(),
                worker_epoch: 1,
                placement_version: 1,
                session_incarnation: 1,
            },
        })
        .await;
    assert!(server.join().is_ok());
    result
}

#[test]
fn rpc_configuration_requires_an_absolute_socket_and_authenticated_peer_uid() {
    assert!(
        WorkerRpcConfig::new("relative.sock", 1024, 1, Duration::from_secs(1), Some(1),).is_err()
    );
    assert!(
        WorkerRpcConfig::new(
            "/tmp/browserd-worker-test.sock",
            1024,
            1,
            Duration::from_secs(1),
            None,
        )
        .is_err()
    );
}
