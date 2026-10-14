#![allow(clippy::expect_used, clippy::panic)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use browser_gateway::{GatewayViewer, GatewayWorkerClient, GatewayWorkerPending};
use browserd_core::{PageId, PlacementFence, SessionId, TenantId};
use browserd_http::{ViewerAttachError, ViewerTransport};
use browserd_viewer::ViewerScopes;
use browserd_worker::{
    WorkerCreateSessionReceipt, WorkerCreateSessionRequest, WorkerRpcCompletionError,
    WorkerRpcEnqueueError, WorkerRpcError, WorkerRpcRequest, WorkerRpcResponse,
    WorkerViewerControl, WorkerViewerController, WorkerViewerFrame, WorkerViewerSnapshot,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

struct Pending;
impl GatewayWorkerPending for Pending {
    fn wait(self) -> Result<WorkerRpcResponse, WorkerRpcCompletionError> {
        Err(WorkerRpcCompletionError::Exchange(WorkerRpcError::Protocol))
    }
}

struct ViewerWorker {
    requests: Mutex<Vec<WorkerRpcRequest>>,
    page_id: PageId,
    corrupt_binding: bool,
    streaming: bool,
    polls: AtomicU64,
}

impl GatewayWorkerClient for ViewerWorker {
    type PendingAction = Pending;

    fn create_session(
        &self,
        request: WorkerCreateSessionRequest,
    ) -> Result<WorkerCreateSessionReceipt, WorkerRpcError> {
        Ok(WorkerCreateSessionReceipt {
            operation_id: request.operation_id,
            tenant_id: request.tenant_id,
            session_id: SessionId::new(),
            worker_epoch: request.expected_worker_epoch,
            placement_version: request.placement_version,
            session_incarnation: request.session_incarnation,
            primary_page_id: self.page_id.clone(),
            effective_isolation: request.requested_isolation,
            existing: false,
            restored_checkpoint: None,
        })
    }

    fn enqueue_action(&self, request: WorkerRpcRequest) -> Result<Pending, WorkerRpcEnqueueError> {
        Err(WorkerRpcEnqueueError::Closed(Box::new(request)))
    }

    fn request(&self, request: WorkerRpcRequest) -> Result<WorkerRpcResponse, WorkerRpcError> {
        self.requests
            .lock()
            .expect("request history")
            .push(request.clone());
        let (mut fence, connection_id, frame) = match request {
            WorkerRpcRequest::GetSession { fence } => {
                return Ok(WorkerRpcResponse::Session(
                    browserd_worker::WorkerSessionReceipt {
                        fence,
                        lifecycle: browserd_worker::WorkerSessionLifecycle::Ready,
                        primary_page_id: self.page_id.clone(),
                    },
                ));
            }
            WorkerRpcRequest::ViewerOpen(request) => (
                request.fence,
                request.connection.id().clone(),
                Some(WorkerViewerFrame {
                    frame_id: 1,
                    page_id: self.page_id.clone(),
                    frame_transform_id: 1,
                    metadata: br#"{"width":1280,"height":720}"#.to_vec(),
                    jpeg_base64: "/9j/2Q==".to_owned(),
                }),
            ),
            WorkerRpcRequest::ViewerPoll(request) => {
                let frame_id = self.polls.fetch_add(1, Ordering::AcqRel) + 2;
                (
                    request.fence,
                    request.connection_id,
                    self.streaming.then(|| WorkerViewerFrame {
                        frame_id,
                        page_id: self.page_id.clone(),
                        frame_transform_id: 1,
                        metadata: br#"{"width":1280,"height":720}"#.to_vec(),
                        jpeg_base64: "/9j/2Q==".to_owned(),
                    }),
                )
            }
            WorkerRpcRequest::ViewerMessage(request) => {
                (request.fence, request.connection_id, None)
            }
            WorkerRpcRequest::ViewerClose(_) => return Ok(WorkerRpcResponse::Empty),
            _ => return Err(WorkerRpcError::InvalidRequest),
        };
        if self.corrupt_binding {
            fence.session_incarnation += 1;
        }
        Ok(WorkerRpcResponse::Viewer(WorkerViewerSnapshot {
            fence,
            connection_id,
            page_id: self.page_id.clone(),
            frame_transform_id: 1,
            frame,
            control: WorkerViewerControl {
                controller: WorkerViewerController::Agent,
                lease_epoch: 0,
            },
        }))
    }
}

async fn grant(viewer: &GatewayViewer) -> browserd_http::ConsumedViewerGrant {
    let session_id = SessionId::new();
    let ticket = viewer
        .issue(
            TenantId::new(),
            session_id.clone(),
            PlacementFence {
                worker_epoch: 3,
                placement_version: 4,
                session_incarnation: 5,
            },
            ViewerScopes::new(true, true, false),
            Duration::from_secs(30),
        )
        .expect("issue");
    let secret = viewer.present_viewer_ticket(&ticket).expect("presentation");
    viewer
        .consume_ticket(&session_id, "https://viewer.test", &secret)
        .await
        .expect("grant")
}

#[tokio::test]
async fn attached_viewer_delivers_worker_frames_and_closes_exact_connection() {
    let worker = Arc::new(ViewerWorker {
        requests: Mutex::new(Vec::new()),
        page_id: PageId::new(),
        corrupt_binding: false,
        streaming: false,
        polls: AtomicU64::new(0),
    });
    let viewer = GatewayViewer::new(Duration::from_secs(30), ["https://viewer.test"], 8)
        .expect("viewer")
        .with_worker_client(Arc::clone(&worker));
    let attached = viewer
        .attach(grant(&viewer).await)
        .await
        .expect("attachment");
    let frame = attached
        .next_frame()
        .expect("frame source")
        .expect("initial frame");
    assert_eq!(frame.jpeg_payload(), &[255, 216, 255, 217]);
    let mut messages = attached.take_server_messages().expect("server messages");
    let state: serde_json::Value =
        serde_json::from_slice(&messages.recv().await.expect("initial state")).expect("json");
    assert_eq!(state["controller"], "agent");
    attached
        .receive_text(br#"{"type":"ping"}"#)
        .await
        .expect("ping");
    attached.disconnect().await;
    assert!(worker.requests.lock().expect("requests").iter().any(|request|
        matches!(request, WorkerRpcRequest::ViewerClose(close) if close.connection_id == *attached.connection().id())));
}

#[tokio::test]
async fn attachment_rejects_worker_reply_bound_to_a_different_incarnation() {
    let worker = Arc::new(ViewerWorker {
        requests: Mutex::new(Vec::new()),
        page_id: PageId::new(),
        corrupt_binding: true,
        streaming: false,
        polls: AtomicU64::new(0),
    });
    let viewer = GatewayViewer::new(Duration::from_secs(30), ["https://viewer.test"], 8)
        .expect("viewer")
        .with_worker_client(worker);
    assert!(matches!(
        viewer.attach(grant(&viewer).await).await,
        Err(ViewerAttachError::StalePlacement)
    ));
}

#[tokio::test]
async fn four_slow_observers_keep_only_the_latest_two_frames_without_client_acks() {
    let worker = Arc::new(ViewerWorker {
        requests: Mutex::new(Vec::new()),
        page_id: PageId::new(),
        corrupt_binding: false,
        streaming: true,
        polls: AtomicU64::new(0),
    });
    let viewer = GatewayViewer::new(Duration::from_secs(30), ["https://viewer.test"], 8)
        .expect("viewer")
        .with_worker_client(worker.clone());
    let mut attached = Vec::new();
    for _ in 0..4 {
        attached.push(viewer.attach(grant(&viewer).await).await.expect("observer"));
    }
    tokio::time::timeout(Duration::from_secs(3), async {
        while worker.polls.load(Ordering::Acquire) < 20 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("frames flow without any client ACK");
    for observer in attached {
        let mut frames = Vec::new();
        while let Some(frame) = observer.next_frame().expect("frame source") {
            frames.push(frame);
        }
        assert!((1..=2).contains(&frames.len()));
        assert!(frames.last().expect("latest frame").frame_id() > 4);
        observer.disconnect().await;
    }
}

struct RejectAuth;
impl browserd_http::Authenticator for RejectAuth {
    fn authenticate(
        &self,
        _: &str,
    ) -> Result<browserd_auth::AuthenticatedPrincipal, browserd_http::AuthenticationError> {
        Err(browserd_http::AuthenticationError)
    }
}

struct Ready;
impl browserd_http::Readiness for Ready {
    fn ready(&self) -> bool {
        true
    }
}

#[tokio::test]
async fn production_viewer_websocket_delivers_worker_frame_and_closes_on_bad_input() {
    let worker = Arc::new(ViewerWorker {
        requests: Mutex::new(Vec::new()),
        page_id: PageId::new(),
        corrupt_binding: false,
        streaming: false,
        polls: AtomicU64::new(0),
    });
    let viewer = Arc::new(
        GatewayViewer::new(Duration::from_secs(30), ["https://viewer.test"], 8)
            .expect("viewer")
            .with_worker_client(Arc::clone(&worker)),
    );
    let session = SessionId::new();
    let ticket = viewer
        .issue(
            TenantId::new(),
            session.clone(),
            PlacementFence::new(3, 4, 5),
            ViewerScopes::new(true, true, false),
            Duration::from_secs(30),
        )
        .expect("ticket");
    let secret = viewer.present_viewer_ticket(&ticket).expect("secret");
    let app = browserd_http::router(
        browserd_http::HttpConfig::new(1_048_576).expect("config"),
        Arc::new(browserd_api::InMemoryApiService::default()),
        Arc::new(RejectAuth),
        viewer,
        Arc::new(Ready),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let address = listener.local_addr().expect("address");
    let server = tokio::spawn(async move {
        let _result = axum::serve(listener, app).await;
    });
    let mut socket = TcpStream::connect(address).await.expect("socket");
    let handshake = format!(
        "GET /v1/sessions/{session}/viewer HTTP/1.1\r\nHost: {address}\r\nOrigin: https://viewer.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Protocol: browser-viewer.v1\r\nCookie: browserd_viewer_ticket={secret}\r\n\r\n"
    );
    socket
        .write_all(handshake.as_bytes())
        .await
        .expect("handshake");
    let mut response = Vec::new();
    while !response.ends_with(b"\r\n\r\n") {
        assert!(response.len() < 16_384);
        response.push(
            tokio::time::timeout(Duration::from_secs(2), socket.read_u8())
                .await
                .expect("deadline")
                .expect("header"),
        );
    }
    assert!(response.starts_with(b"HTTP/1.1 101 "));
    let (mut saw_control, mut saw_jpeg) = (false, false);
    for _ in 0..2 {
        let (opcode, payload) = server_frame(&mut socket).await;
        match opcode {
            1 => {
                let state: serde_json::Value = serde_json::from_slice(&payload).expect("state");
                assert_eq!(state["controller"], "agent");
                saw_control = true;
            }
            2 => {
                assert_eq!(payload[0], 1);
                assert!(payload.ends_with(&[255, 216, 255, 217]));
                saw_jpeg = true;
            }
            _ => panic!("unexpected initial frame"),
        }
    }
    assert!(saw_control && saw_jpeg);
    // RFC6455 masked client text; a malformed typed control message closes and cleans up.
    let payload = br#"{"type":"ping","unexpected":true}"#;
    let mut frame = vec![
        0x81,
        0x80 | u8::try_from(payload.len()).expect("small frame"),
    ];
    let mask = [1, 2, 3, 4];
    frame.extend_from_slice(&mask);
    frame.extend(
        payload
            .iter()
            .enumerate()
            .map(|(index, byte)| byte ^ mask[index % 4]),
    );
    socket.write_all(&frame).await.expect("bad message");
    let (opcode, _) = server_frame(&mut socket).await;
    assert_eq!(opcode, 8);
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if worker
                .requests
                .lock()
                .expect("requests")
                .iter()
                .any(|request| matches!(request, WorkerRpcRequest::ViewerClose(_)))
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("worker detached");
    server.abort();
    let _result = server.await;
}

async fn server_frame(socket: &mut TcpStream) -> (u8, Vec<u8>) {
    tokio::time::timeout(Duration::from_secs(2), async {
        let first = socket.read_u8().await.expect("opcode");
        let second = socket.read_u8().await.expect("length");
        assert_eq!(second & 0x80, 0);
        let length = match second & 0x7f {
            126 => usize::from(socket.read_u16().await.expect("length16")),
            127 => {
                usize::try_from(socket.read_u64().await.expect("length64")).expect("bounded length")
            }
            value => usize::from(value),
        };
        assert!(length <= 2 * 1024 * 1024);
        let mut payload = vec![0; length];
        socket.read_exact(&mut payload).await.expect("payload");
        (first & 0x0f, payload)
    })
    .await
    .expect("frame deadline")
}

#[test]
fn runtime_issues_one_time_viewer_ticket_only_for_current_tenant_and_incarnation()
-> Result<(), Box<dyn std::error::Error>> {
    use browserd_api::{ApiRequest, ApiResponse, ApiRouter, ApiService, ViewerTicketRequest};
    use browserd_auth::{
        AuthConfig, RevocationRegistry, ServiceClaims, ServiceTokenSigner, ServiceTokenVerifier,
        VerificationKeySet,
    };
    use jsonwebtoken::Algorithm;
    let worker = Arc::new(ViewerWorker {
        requests: Mutex::new(Vec::new()),
        page_id: PageId::new(),
        corrupt_binding: false,
        streaming: false,
        polls: AtomicU64::new(0),
    });
    let viewer = Arc::new(
        GatewayViewer::new(Duration::from_secs(30), ["https://viewer.test"], 8)?
            .with_worker_client(worker.clone()),
    );
    let placement = browser_gateway::GatewayWorkerPlacement::new(
        browserd_core::WorkerId::new("viewer-worker")?,
        3,
        4,
        1,
    )?;
    let runtime = Arc::new(
        browser_gateway::GatewayWorkerRuntime::new(worker, placement)?.with_viewer(viewer.clone()),
    );
    let router = ApiRouter::new(runtime);
    let secret = [19_u8; 32];
    let mut keys = VerificationKeySet::new();
    keys.insert_hmac("viewer", Algorithm::HS256, &secret)?;
    let verifier = ServiceTokenVerifier::new(
        AuthConfig::new("issuer", "audience", [Algorithm::HS256], 0, false),
        keys,
        RevocationRegistry::new(),
    );
    let signer = ServiceTokenSigner::new("viewer", Algorithm::HS256, &secret);
    let principal = verifier.verify_at(
        &signer.sign(&ServiceClaims::new(
            "issuer",
            "audience",
            browserd_core::PrincipalId::new(),
            TenantId::new(),
            ["session:create", "viewer:read", "viewer:control"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            "viewer-test",
            1,
            100,
            None,
        ))?,
        None,
        10,
    )?;
    let body = browserd_api::decode_session_create(
        r#"{"isolation":"dedicated_process","workload_class_hint":"interactive","viewport":{"width":1280,"height":720,"device_scale_factor":1},"locale":"en-US","timezone":"UTC","user_agent":null,"network_policy_id":"public-web-default","network_class":"public","checkpoint_ref":null,"dialog_policy":"auto_dismiss","feature_profile":"standard","ttl_seconds":1800,"idle_timeout_seconds":600,"metadata":{}}"#,
    )?;
    let created = router.execute(
        &principal,
        ApiRequest::CreateSession {
            body,
            idempotency_key: uuid::Uuid::new_v4().to_string(),
            received_at: std::time::Instant::now(),
        },
    )?;
    let ApiResponse::SessionCreate(created) = created else {
        panic!("session response");
    };
    let session = created.data().operation().session().expect("session");
    let request = ViewerTicketRequest {
        session_id: session.id.clone(),
        session_incarnation: session.incarnation,
        scopes: ViewerScopes::new(true, true, false),
        ttl: Duration::from_secs(30),
    };
    let issued = router.execute(&principal, ApiRequest::IssueViewerTicket(request.clone()))?;
    let ApiResponse::ViewerTicket(ticket) = issued else {
        panic!("ticket response");
    };
    assert!(viewer.present_viewer_ticket(ticket.data()).is_some());
    let mut stale = request.clone();
    stale.session_incarnation += 1;
    assert!(
        router
            .execute(&principal, ApiRequest::IssueViewerTicket(stale))
            .is_err()
    );
    let mut missing = request;
    missing.session_id = SessionId::new();
    assert!(
        router
            .execute(&principal, ApiRequest::IssueViewerTicket(missing))
            .is_err()
    );
    Ok(())
}
