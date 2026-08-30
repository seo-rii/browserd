use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use browserd_auth::{ServiceClaims, ServiceTokenSigner};
use browserd_core::{PrincipalId, SessionId, TenantId};
use browserd_worker::WORKER_RPC_PROTOCOL_VERSION;
use browserd_worker::{
    WorkerRpcClient, WorkerRpcRequest, WorkerRpcResponse, WorkerSessionFence,
    WorkerSessionLifecycle,
};
use jsonwebtoken::Algorithm;

type TestResult = Result<(), Box<dyn Error>>;

struct RunningBrowserd {
    child: Child,
    runtime_dir: PathBuf,
}

impl Drop for RunningBrowserd {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.runtime_dir);
    }
}

#[test]
fn all_in_one_qualifies_worker_before_readiness_and_shuts_down_cleanly() -> TestResult {
    let reserved_listener = TcpListener::bind(("127.0.0.1", 0))?;
    let bind_address = reserved_listener.local_addr()?;
    drop(reserved_listener);

    let unique = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let runtime_dir = std::env::temp_dir().join(format!(
        "browserd-all-in-one-contract-{}-{unique}",
        std::process::id()
    ));
    let action_journal_dir = runtime_dir.join("actions");
    let worker_socket = runtime_dir.join("worker.sock");
    let worker_epoch_file = runtime_dir.join("worker.epoch");
    fs::create_dir_all(&action_journal_dir)?;
    fs::set_permissions(&runtime_dir, fs::Permissions::from_mode(0o700))?;
    fs::set_permissions(&action_journal_dir, fs::Permissions::from_mode(0o700))?;

    let uid_output = Command::new("id").arg("-u").output()?;
    if !uid_output.status.success() {
        return Err(std::io::Error::other("could not determine the test process uid").into());
    }
    let worker_uid = String::from_utf8(uid_output.stdout)?.trim().to_owned();

    let child = Command::new(env!("CARGO_BIN_EXE_browserd"))
        .env("BROWSERD_ALL_IN_ONE_DEV", "true")
        .env("BROWSERD_BIND", bind_address.to_string())
        .env("BROWSERD_RUNTIME_DIR", &runtime_dir)
        .env("BROWSERD_WORKER_ID", "browserd-all-in-one-test")
        .env("BROWSERD_WORKER_EPOCH_FILE", &worker_epoch_file)
        .env("BROWSERD_WORKER_SOCKET", &worker_socket)
        .env(
            "BROWSERD_INTERNAL_ENDPOINT",
            format!("unix:{}", worker_socket.display()),
        )
        .env("BROWSERD_INTERNAL_PEER", "browserd-all-in-one-gateway")
        .env("BROWSERD_WORKER_UID", &worker_uid)
        .env("BROWSERD_WORKER_EPOCH", "1")
        .env("BROWSERD_PLACEMENT_VERSION", "1")
        .env("BROWSERD_ACTION_JOURNAL_DIR", &action_journal_dir)
        .env("BROWSERD_COORDINATION_MODE", "memory")
        .env("BROWSERD_AUTH_ISSUER", "browserd-contract-test")
        .env("BROWSERD_AUTH_AUDIENCE", "browserd")
        .env("BROWSERD_AUTH_KEY_ID", "contract-test-key")
        .env(
            "BROWSERD_AUTH_HMAC_SECRET",
            "contract-test-secret-with-at-least-32-bytes",
        )
        .env("BROWSERD_VIEWER_ORIGINS", "https://browserd.internal")
        .env(
            "BROWSERD_POSTGRES_URL",
            "postgres://unused.invalid/browserd",
        )
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;
    let mut process = RunningBrowserd { child, runtime_dir };

    let readiness_deadline = Instant::now() + Duration::from_secs(5);
    let mut ready_response = None;
    let mut last_response = None;
    while Instant::now() < readiness_deadline {
        if let Some(status) = process.child.try_wait()? {
            return Err(std::io::Error::other(format!(
                "all-in-one process exited before readiness: {status}"
            ))
            .into());
        }
        if let Ok(mut stream) =
            TcpStream::connect_timeout(&bind_address, Duration::from_millis(100))
        {
            stream.set_read_timeout(Some(Duration::from_millis(250)))?;
            stream.set_write_timeout(Some(Duration::from_millis(250)))?;
            stream.write_all(
                b"GET /health/ready HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            )?;
            let mut response = Vec::new();
            if stream.read_to_end(&mut response).is_ok() {
                if response.starts_with(b"HTTP/1.1 200") {
                    ready_response = Some(response);
                    break;
                }
                last_response = Some(response);
            }
        }
        thread::sleep(Duration::from_millis(25));
    }
    let ready_response = ready_response.ok_or_else(|| {
        std::io::Error::other(format!(
            "all-in-one runtime did not become ready within five seconds; last response: {}",
            last_response
                .as_deref()
                .map(String::from_utf8_lossy)
                .unwrap_or_else(|| "<no response>".into())
        ))
    })?;
    let ready_response = String::from_utf8(ready_response)?;
    assert!(ready_response.contains("\"status\":\"ready\""));

    // Readiness is not merely the HTTP listener: the exact local worker epoch must already be
    // reachable through the authenticated, bounded worker RPC transport.
    let mut worker = UnixStream::connect(&worker_socket)?;
    worker.set_read_timeout(Some(Duration::from_secs(1)))?;
    worker.set_write_timeout(Some(Duration::from_secs(1)))?;
    let probe = format!(
        r#"{{"protocol_version":{WORKER_RPC_PROTOCOL_VERSION},"request_id":"550e8400-e29b-41d4-a716-446655440000","request":{{"method":"probe","params":{{"expected_worker_epoch":1}}}}}}"#
    );
    let probe_len = u32::try_from(probe.len())?;
    worker.write_all(&probe_len.to_be_bytes())?;
    worker.write_all(probe.as_bytes())?;
    let mut response_len = [0_u8; 4];
    worker.read_exact(&mut response_len)?;
    let response_len = usize::try_from(u32::from_be_bytes(response_len))?;
    if response_len == 0 || response_len > 64 * 1024 {
        return Err(std::io::Error::other("worker returned an invalid RPC frame length").into());
    }
    let mut worker_response = vec![0_u8; response_len];
    worker.read_exact(&mut worker_response)?;
    let worker_response = String::from_utf8(worker_response)?;
    assert!(worker_response.contains("\"result\":\"probe\""));
    assert!(worker_response.contains("\"worker_epoch\":1"));
    assert!(worker_response.contains("\"ready\":true"));

    let tenant_id = TenantId::new();
    let now = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
    let claims = ServiceClaims::new(
        "browserd-contract-test",
        "browserd",
        PrincipalId::new(),
        tenant_id.clone(),
        ["session:create", "session:read", "session:close"]
            .into_iter()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>(),
        "browserd-all-in-one-contract-jti",
        now - 1,
        now + 120,
        None,
    );
    let token = ServiceTokenSigner::new(
        "contract-test-key",
        Algorithm::HS256,
        b"contract-test-secret-with-at-least-32-bytes",
    )
    .sign(&claims)?;
    let request = |request: &str| -> Result<Vec<u8>, Box<dyn Error>> {
        let mut stream = TcpStream::connect_timeout(&bind_address, Duration::from_secs(1))?;
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
        stream.set_write_timeout(Some(Duration::from_secs(2)))?;
        stream.write_all(request.as_bytes())?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response)?;
        Ok(response)
    };

    let create_body =
        include_str!("../../../crates/browserd-api/tests/session_create_fixture.json");
    let create_request = format!(
        "POST /v1/sessions HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nIdempotency-Key: 550e8400-e29b-41d4-a716-446655440001\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{create_body}",
        create_body.len()
    );
    let created = request(&create_request)?;
    assert!(
        created.starts_with(b"HTTP/1.1 201"),
        "unexpected create response: {}",
        String::from_utf8_lossy(&created)
    );
    let created = String::from_utf8(created)?;
    let created_body = created
        .split_once("\r\n\r\n")
        .ok_or("create response body missing")?
        .1;
    let created_body: serde_json::Value = serde_json::from_str(created_body)?;
    assert_eq!(created_body["data"]["operation"]["state"], "succeeded");

    let listed = request(&format!(
        "GET /v1/sessions HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"
    ))?;
    assert!(listed.starts_with(b"HTTP/1.1 200"));
    let listed = String::from_utf8(listed)?;
    let listed_body = listed
        .split_once("\r\n\r\n")
        .ok_or("session list response body missing")?
        .1;
    let listed_body: serde_json::Value = serde_json::from_str(listed_body)?;
    let sessions = listed_body["data"]["sessions"]
        .as_array()
        .ok_or("session list missing")?;
    assert_eq!(sessions.len(), 1);
    let session_id = sessions[0]
        .as_str()
        .ok_or("session id missing")?
        .parse::<SessionId>()?;

    let worker_uid = worker_uid.parse::<u32>()?;
    let worker_rpc = WorkerRpcClient::new(
        &worker_socket,
        64 * 1024,
        Duration::from_secs(1),
        Some(worker_uid),
    )?
    .blocking_with_limits(4, 2)?;
    let fence = WorkerSessionFence {
        tenant_id: tenant_id.clone(),
        session_id: session_id.clone(),
        worker_epoch: 1,
        placement_version: 1,
        session_incarnation: 1,
    };
    let WorkerRpcResponse::Session(worker_session) =
        worker_rpc.request_blocking(WorkerRpcRequest::GetSession {
            fence: fence.clone(),
        })?
    else {
        return Err(std::io::Error::other("worker session receipt missing").into());
    };
    assert_eq!(worker_session.fence, fence);
    assert_eq!(worker_session.lifecycle, WorkerSessionLifecycle::Ready);

    let rejected_close = request(&format!(
        "DELETE /v1/sessions/{session_id} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer invalid\r\nConnection: close\r\n\r\n"
    ))?;
    assert!(rejected_close.starts_with(b"HTTP/1.1 401"));
    let WorkerRpcResponse::Session(worker_session) =
        worker_rpc.request_blocking(WorkerRpcRequest::GetSession {
            fence: fence.clone(),
        })?
    else {
        return Err(
            std::io::Error::other("worker session receipt missing after rejected close").into(),
        );
    };
    assert_eq!(worker_session.lifecycle, WorkerSessionLifecycle::Ready);

    let closed = request(&format!(
        "DELETE /v1/sessions/{session_id} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"
    ))?;
    assert!(closed.starts_with(b"HTTP/1.1 200"));
    let closed = String::from_utf8(closed)?;
    let closed_body = closed
        .split_once("\r\n\r\n")
        .ok_or("close response body missing")?
        .1;
    let closed_body: serde_json::Value = serde_json::from_str(closed_body)?;
    assert_eq!(closed_body["data"]["session"]["id"], session_id.to_string());
    assert_eq!(closed_body["data"]["session"]["state"], "closed");
    let WorkerRpcResponse::Session(worker_session) =
        worker_rpc.request_blocking(WorkerRpcRequest::GetSession { fence })?
    else {
        return Err(std::io::Error::other("worker closed-session receipt missing").into());
    };
    assert_eq!(worker_session.lifecycle, WorkerSessionLifecycle::Closed);

    let signal = Command::new("kill")
        .arg("-TERM")
        .arg(process.child.id().to_string())
        .status()?;
    if !signal.success() {
        return Err(std::io::Error::other("could not signal the all-in-one process").into());
    }
    let shutdown_deadline = Instant::now() + Duration::from_secs(5);
    let exit_status = loop {
        if let Some(status) = process.child.try_wait()? {
            break status;
        }
        if Instant::now() >= shutdown_deadline {
            return Err(std::io::Error::other(
                "all-in-one runtime did not complete graceful shutdown within five seconds",
            )
            .into());
        }
        thread::sleep(Duration::from_millis(25));
    };
    assert!(exit_status.success(), "graceful shutdown must exit cleanly");
    assert!(
        !worker_socket.exists(),
        "the owned worker RPC socket must be unlinked after shutdown"
    );
    assert!(
        worker_epoch_file.exists(),
        "the monotonic worker epoch must survive graceful shutdown"
    );

    Ok(())
}
