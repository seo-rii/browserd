#![allow(clippy::expect_used)]

use std::error::Error;
use std::future::pending;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use browserd_api::InMemoryApiService;
use browserd_auth::AuthenticatedPrincipal;
use browserd_core::{PageId, PlacementFence, SessionId, TenantId};
use browserd_http::{
    AttachedViewer, AuthenticationError, Authenticator, ConsumedViewerGrant, HttpConfig, Readiness,
    ViewerAttachError, ViewerClientMessageError, ViewerGateError, ViewerSocketLimits,
    ViewerTransport, router,
};
use browserd_viewer::{
    FrameBroadcaster, FramePolicy, PublishOutcome, TicketPolicy, TicketRegistry, ViewerConnection,
    ViewerFrame, ViewerScopes,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex as AsyncMutex, Notify, mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

const ORIGIN: &str = "https://viewer.example.test";
const TICKET: &str = "one-time-viewer-ticket";
const MAX_HANDSHAKE_BYTES: usize = 16 * 1024;

struct RejectAuth;

impl Authenticator for RejectAuth {
    fn authenticate(&self, _bearer: &str) -> Result<AuthenticatedPrincipal, AuthenticationError> {
        Err(AuthenticationError)
    }
}

struct Ready;

impl Readiness for Ready {
    fn ready(&self) -> bool {
        true
    }
}

struct EdgeCancellation {
    enabled: AtomicBool,
    receiver: Mutex<Option<oneshot::Receiver<()>>>,
    sender: Mutex<Option<oneshot::Sender<()>>>,
    armed: Notify,
}

struct ContractViewer {
    session_id: SessionId,
    grant: Mutex<Option<ConsumedViewerGrant>>,
    broadcaster: Arc<FrameBroadcaster>,
    client_messages: mpsc::Sender<Vec<u8>>,
    server_messages: Mutex<Option<mpsc::Receiver<Vec<u8>>>>,
    cancellation: CancellationToken,
    edge_cancellation: Arc<EdgeCancellation>,
    hang_disconnect: Arc<AtomicBool>,
    consumed: Arc<AtomicUsize>,
    attached: Arc<AtomicUsize>,
    disconnected: Arc<AtomicUsize>,
    aborted: Arc<AtomicUsize>,
    attached_binding: Arc<Mutex<Option<(ViewerConnection, PlacementFence)>>>,
    attached_notify: Arc<Notify>,
}

#[async_trait]
impl ViewerTransport for ContractViewer {
    async fn consume_ticket(
        &self,
        session_id: &SessionId,
        origin: &str,
        ticket: &str,
    ) -> Result<ConsumedViewerGrant, ViewerGateError> {
        if session_id != &self.session_id || origin != ORIGIN || ticket != TICKET {
            return Err(ViewerGateError::TicketDenied);
        }
        let grant = self
            .grant
            .lock()
            .map_err(|_| ViewerGateError::TicketDenied)?
            .take()
            .ok_or(ViewerGateError::TicketDenied)?;
        self.consumed.fetch_add(1, Ordering::AcqRel);
        Ok(grant)
    }

    async fn attach(
        &self,
        grant: ConsumedViewerGrant,
    ) -> Result<Box<dyn AttachedViewer>, ViewerAttachError> {
        self.broadcaster
            .attach(grant.connection())
            .map_err(|_| ViewerAttachError::BackendUnavailable)?;
        let connection = grant.connection().clone();
        let placement_fence = grant.placement_fence();
        let server_messages = self
            .server_messages
            .lock()
            .map_err(|_| ViewerAttachError::BackendUnavailable)?
            .take()
            .ok_or(ViewerAttachError::CapacityExceeded)?;
        *self
            .attached_binding
            .lock()
            .map_err(|_| ViewerAttachError::BackendUnavailable)? =
            Some((connection.clone(), placement_fence));
        self.attached.fetch_add(1, Ordering::AcqRel);
        self.attached_notify.notify_one();
        Ok(Box::new(ContractAttachment {
            connection,
            placement_fence,
            broadcaster: Arc::clone(&self.broadcaster),
            client_messages: self.client_messages.clone(),
            server_messages: Mutex::new(Some(server_messages)),
            cancellation: self.cancellation.clone(),
            edge_cancellation: Arc::clone(&self.edge_cancellation),
            hang_disconnect: Arc::clone(&self.hang_disconnect),
            detached: AtomicBool::new(false),
            disconnected: Arc::clone(&self.disconnected),
            aborted: Arc::clone(&self.aborted),
        }))
    }
}

struct ContractAttachment {
    connection: ViewerConnection,
    placement_fence: PlacementFence,
    broadcaster: Arc<FrameBroadcaster>,
    client_messages: mpsc::Sender<Vec<u8>>,
    server_messages: Mutex<Option<mpsc::Receiver<Vec<u8>>>>,
    cancellation: CancellationToken,
    edge_cancellation: Arc<EdgeCancellation>,
    hang_disconnect: Arc<AtomicBool>,
    detached: AtomicBool,
    disconnected: Arc<AtomicUsize>,
    aborted: Arc<AtomicUsize>,
}

impl ContractAttachment {
    fn cleanup(&self) {
        if !self.detached.swap(true, Ordering::AcqRel) {
            let _result = self.broadcaster.detach(self.connection.id());
            self.disconnected.fetch_add(1, Ordering::AcqRel);
        }
    }
}

impl Drop for ContractAttachment {
    fn drop(&mut self) {
        self.cleanup();
    }
}

#[async_trait]
impl AttachedViewer for ContractAttachment {
    fn connection(&self) -> &ViewerConnection {
        &self.connection
    }

    fn placement_fence(&self) -> PlacementFence {
        self.placement_fence
    }

    fn next_frame(&self) -> Result<Option<ViewerFrame>, ViewerAttachError> {
        self.broadcaster
            .next_frame(self.connection.id())
            .map_err(|_| ViewerAttachError::BackendUnavailable)
    }

    fn take_server_messages(&self) -> Result<mpsc::Receiver<Vec<u8>>, ViewerAttachError> {
        self.server_messages
            .lock()
            .map_err(|_| ViewerAttachError::BackendUnavailable)?
            .take()
            .ok_or(ViewerAttachError::BackendUnavailable)
    }

    async fn receive_text(&self, message: &[u8]) -> Result<(), ViewerClientMessageError> {
        if message != br#"{"type":"ping"}"# {
            return Err(ViewerClientMessageError::Unsupported);
        }
        if self.edge_cancellation.enabled.load(Ordering::Acquire) {
            let sender = self
                .edge_cancellation
                .sender
                .lock()
                .map_err(|_| ViewerClientMessageError::BackendUnavailable)?
                .take();
            if let Some(sender) = sender {
                let _result = sender.send(());
            }
        }
        self.client_messages
            .try_send(message.to_vec())
            .map_err(|_| ViewerClientMessageError::BackendUnavailable)
    }

    async fn cancelled(&self) {
        if self.edge_cancellation.enabled.load(Ordering::Acquire) {
            let receiver = self
                .edge_cancellation
                .receiver
                .lock()
                .ok()
                .and_then(|mut receiver| receiver.take());
            self.edge_cancellation.armed.notify_one();
            if let Some(receiver) = receiver {
                let _result = receiver.await;
            } else {
                pending::<()>().await;
            }
            return;
        }
        self.cancellation.cancelled().await;
    }

    async fn disconnect(&self) {
        if self.hang_disconnect.load(Ordering::Acquire) {
            pending::<()>().await;
        }
        self.cleanup();
    }

    fn abort(&self) {
        self.aborted.fetch_add(1, Ordering::AcqRel);
        self.cleanup();
    }
}

struct ContractBackend {
    broadcaster: Arc<FrameBroadcaster>,
    page_id: PageId,
    messages: AsyncMutex<mpsc::Receiver<Vec<u8>>>,
    server_messages: mpsc::Sender<Vec<u8>>,
    cancellation: CancellationToken,
    edge_cancellation: Arc<EdgeCancellation>,
    hang_disconnect: Arc<AtomicBool>,
    consumed: Arc<AtomicUsize>,
    attached: Arc<AtomicUsize>,
    disconnected: Arc<AtomicUsize>,
    aborted: Arc<AtomicUsize>,
    attached_binding: Arc<Mutex<Option<(ViewerConnection, PlacementFence)>>>,
    attached_notify: Arc<Notify>,
}

impl ContractBackend {
    fn publish_frame(&self, frame: ViewerFrame) -> Result<PublishOutcome, Box<dyn Error>> {
        Ok(self.broadcaster.ingest(frame, |_| Ok(()))?)
    }

    async fn next_client_message(&self) -> Option<Vec<u8>> {
        self.messages.lock().await.recv().await
    }

    fn cancel(&self) {
        self.cancellation.cancel();
    }

    fn send_server_message(&self, message: &[u8]) -> Result<(), Box<dyn Error>> {
        self.server_messages.try_send(message.to_vec())?;
        Ok(())
    }

    fn enable_edge_cancellation(&self) {
        self.edge_cancellation
            .enabled
            .store(true, Ordering::Release);
    }

    async fn wait_edge_cancellation_armed(&self) -> Result<(), Box<dyn Error>> {
        timeout(
            Duration::from_secs(1),
            self.edge_cancellation.armed.notified(),
        )
        .await?;
        Ok(())
    }

    fn hang_disconnect(&self) {
        self.hang_disconnect.store(true, Ordering::Release);
    }

    async fn wait_attached(&self) -> Result<(), Box<dyn Error>> {
        if self.attached.load(Ordering::Acquire) == 0 {
            timeout(Duration::from_secs(1), self.attached_notify.notified()).await?;
        }
        Ok(())
    }

    async fn wait_disconnected(&self) -> Result<(), Box<dyn Error>> {
        timeout(Duration::from_secs(1), async {
            while self.disconnected.load(Ordering::Acquire) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        Ok(())
    }

    fn attached_binding(&self) -> Option<(ViewerConnection, PlacementFence)> {
        self.attached_binding.lock().ok()?.clone()
    }
}

struct RunningServer {
    address: SocketAddr,
    task: JoinHandle<()>,
}

impl RunningServer {
    async fn start(
        viewer: Arc<dyn ViewerTransport>,
        config: HttpConfig,
    ) -> Result<Self, Box<dyn Error>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let app = router(
            config,
            Arc::new(InMemoryApiService::default()),
            Arc::new(RejectAuth),
            viewer,
            Arc::new(Ready),
        );
        let task = tokio::spawn(async move {
            let _result = axum::serve(listener, app).await;
        });
        Ok(Self { address, task })
    }

    async fn stop(self) {
        self.task.abort();
        let _result = self.task.await;
    }
}

struct ServerFrame {
    opcode: u8,
    payload: Vec<u8>,
}

type ViewerParts = (
    SessionId,
    ViewerConnection,
    PlacementFence,
    Arc<ContractViewer>,
    ContractBackend,
);

fn viewer_parts(frame_queue_depth: usize) -> Result<ViewerParts, Box<dyn Error>> {
    let tenant_id = TenantId::new();
    let session_id = SessionId::new();
    let session_incarnation = 7;
    let registry = TicketRegistry::new(TicketPolicy::new(Duration::from_secs(30), [ORIGIN])?);
    let ticket = registry.issue(
        tenant_id.clone(),
        session_id.clone(),
        session_incarnation,
        ViewerScopes::new(true, true, false),
        1_000,
        Duration::from_secs(10),
    )?;
    let connection = registry.consume(
        &ticket,
        &tenant_id,
        &session_id,
        session_incarnation,
        ORIGIN,
        1_001,
    )?;
    let placement_fence = PlacementFence::new(11, 13, session_incarnation);
    let grant = ConsumedViewerGrant::new(connection.clone(), placement_fence)?;
    let page_id = PageId::new();
    let broadcaster = Arc::new(FrameBroadcaster::new(
        tenant_id,
        session_id.clone(),
        session_incarnation,
        page_id.clone(),
        5,
        FramePolicy::new(4, frame_queue_depth, 1_024, 1_024)?,
    ));
    let (client_messages, messages) = mpsc::channel(1);
    let (server_messages, server_message_receiver) = mpsc::channel(1);
    let (edge_sender, edge_receiver) = oneshot::channel();
    let cancellation = CancellationToken::new();
    let edge_cancellation = Arc::new(EdgeCancellation {
        enabled: AtomicBool::new(false),
        receiver: Mutex::new(Some(edge_receiver)),
        sender: Mutex::new(Some(edge_sender)),
        armed: Notify::new(),
    });
    let hang_disconnect = Arc::new(AtomicBool::new(false));
    let consumed = Arc::new(AtomicUsize::new(0));
    let attached = Arc::new(AtomicUsize::new(0));
    let disconnected = Arc::new(AtomicUsize::new(0));
    let aborted = Arc::new(AtomicUsize::new(0));
    let attached_binding = Arc::new(Mutex::new(None));
    let attached_notify = Arc::new(Notify::new());
    let viewer = Arc::new(ContractViewer {
        session_id: session_id.clone(),
        grant: Mutex::new(Some(grant)),
        broadcaster: Arc::clone(&broadcaster),
        client_messages,
        server_messages: Mutex::new(Some(server_message_receiver)),
        cancellation: cancellation.clone(),
        edge_cancellation: Arc::clone(&edge_cancellation),
        hang_disconnect: Arc::clone(&hang_disconnect),
        consumed: Arc::clone(&consumed),
        attached: Arc::clone(&attached),
        disconnected: Arc::clone(&disconnected),
        aborted: Arc::clone(&aborted),
        attached_binding: Arc::clone(&attached_binding),
        attached_notify: Arc::clone(&attached_notify),
    });
    let backend = ContractBackend {
        broadcaster,
        page_id,
        messages: AsyncMutex::new(messages),
        server_messages,
        cancellation,
        edge_cancellation,
        hang_disconnect,
        consumed,
        attached,
        disconnected,
        aborted,
        attached_binding,
        attached_notify,
    };
    Ok((session_id, connection, placement_fence, viewer, backend))
}

async fn connect_viewer(
    address: SocketAddr,
    session_id: &SessionId,
) -> Result<TcpStream, Box<dyn Error>> {
    let mut stream = TcpStream::connect(address).await?;
    let request = format!(
        "GET /v1/sessions/{session_id}/viewer HTTP/1.1\r\nHost: {address}\r\nOrigin: {ORIGIN}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Protocol: browser-viewer.v1\r\nCookie: browserd_viewer_ticket={TICKET}\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await?;

    let mut response = Vec::new();
    while !response.ends_with(b"\r\n\r\n") {
        if response.len() >= MAX_HANDSHAKE_BYTES {
            return Err(io::Error::other("WebSocket handshake response is too large").into());
        }
        response.push(timeout(Duration::from_secs(1), stream.read_u8()).await??);
    }
    let response = String::from_utf8(response)?;
    if !response.starts_with("HTTP/1.1 101 ") {
        return Err(io::Error::other(format!("upgrade failed: {response}")).into());
    }
    if !response
        .to_ascii_lowercase()
        .contains("sec-websocket-protocol: browser-viewer.v1\r\n")
    {
        return Err(io::Error::other("viewer subprotocol was not negotiated").into());
    }
    Ok(stream)
}

async fn send_client_frame(
    stream: &mut TcpStream,
    opcode: u8,
    payload: &[u8],
) -> Result<(), Box<dyn Error>> {
    let mut frame = Vec::with_capacity(payload.len().saturating_add(14));
    frame.push(0x80 | opcode);
    match payload.len() {
        length @ 0..=125 => frame.push(0x80 | u8::try_from(length)?),
        length @ 126..=65_535 => {
            frame.push(0x80 | 126);
            frame.extend_from_slice(&u16::try_from(length)?.to_be_bytes());
        }
        length => {
            frame.push(0x80 | 127);
            frame.extend_from_slice(&u64::try_from(length)?.to_be_bytes());
        }
    }
    let mask = [0x11, 0x22, 0x33, 0x44];
    frame.extend_from_slice(&mask);
    frame.extend(
        payload
            .iter()
            .enumerate()
            .map(|(index, byte)| byte ^ mask[index % mask.len()]),
    );
    stream.write_all(&frame).await?;
    Ok(())
}

async fn read_server_frame(stream: &mut TcpStream) -> Result<ServerFrame, Box<dyn Error>> {
    let first = stream.read_u8().await?;
    let second = stream.read_u8().await?;
    if first & 0x80 == 0 {
        return Err(io::Error::other("server sent a fragmented test frame").into());
    }
    if second & 0x80 != 0 {
        return Err(io::Error::other("server WebSocket frames must not be masked").into());
    }
    let payload_len = match second & 0x7f {
        length @ 0..=125 => u64::from(length),
        126 => u64::from(stream.read_u16().await?),
        127 => stream.read_u64().await?,
        _ => return Err(io::Error::other("invalid WebSocket payload length tag").into()),
    };
    let payload_len = usize::try_from(payload_len)?;
    let mut payload = vec![0; payload_len];
    stream.read_exact(&mut payload).await?;
    Ok(ServerFrame {
        opcode: first & 0x0f,
        payload,
    })
}

fn close_code(frame: &ServerFrame) -> Option<u16> {
    (frame.opcode == 0x8 && frame.payload.len() >= 2)
        .then(|| u16::from_be_bytes([frame.payload[0], frame.payload[1]]))
}

#[test]
fn consumed_grant_rejects_zero_or_stale_placement_fences() -> Result<(), Box<dyn Error>> {
    let (_session_id, connection, _fence, _viewer, _backend) = viewer_parts(1)?;
    assert!(matches!(
        ConsumedViewerGrant::new(connection.clone(), PlacementFence::new(0, 13, 7)),
        Err(ViewerGateError::TicketDenied)
    ));
    assert!(matches!(
        ConsumedViewerGrant::new(connection, PlacementFence::new(11, 13, 8)),
        Err(ViewerGateError::TicketDenied)
    ));
    Ok(())
}

#[tokio::test]
async fn consumed_grant_does_not_attach_before_the_upgrade_callback() -> Result<(), Box<dyn Error>>
{
    let (session_id, _connection, _fence, viewer, backend) = viewer_parts(1)?;
    let _grant = viewer.consume_ticket(&session_id, ORIGIN, TICKET).await?;

    assert_eq!(backend.consumed.load(Ordering::Acquire), 1);
    assert_eq!(backend.attached.load(Ordering::Acquire), 0);
    assert_eq!(backend.disconnected.load(Ordering::Acquire), 0);
    Ok(())
}

#[tokio::test]
async fn upgrade_preserves_binding_and_stays_open_until_runtime_cancellation()
-> Result<(), Box<dyn Error>> {
    let (session_id, connection, fence, viewer, backend) = viewer_parts(1)?;
    let server = RunningServer::start(viewer, HttpConfig::default()).await?;
    let mut socket = connect_viewer(server.address, &session_id).await?;
    backend.wait_attached().await?;

    assert_eq!(backend.consumed.load(Ordering::Acquire), 1);
    assert_eq!(backend.attached.load(Ordering::Acquire), 1);
    assert_eq!(backend.attached_binding(), Some((connection, fence)));
    assert!(
        timeout(Duration::from_millis(100), read_server_frame(&mut socket))
            .await
            .is_err(),
        "an accepted viewer must not be closed immediately"
    );

    let ping = br#"{"type":"ping"}"#;
    send_client_frame(&mut socket, 0x1, ping).await?;
    let delivered = timeout(Duration::from_secs(1), backend.next_client_message())
        .await?
        .ok_or_else(|| io::Error::other("viewer command channel closed"))?;
    assert_eq!(delivered, ping);

    backend.cancel();
    let closed = timeout(Duration::from_secs(1), read_server_frame(&mut socket)).await??;
    assert_eq!(closed.opcode, 0x8);
    backend.wait_disconnected().await?;
    assert_eq!(backend.disconnected.load(Ordering::Acquire), 1);
    assert_eq!(backend.aborted.load(Ordering::Acquire), 0);

    server.stop().await;
    Ok(())
}

#[tokio::test]
async fn backend_control_messages_are_delivered_as_bounded_text_frames()
-> Result<(), Box<dyn Error>> {
    let (session_id, _connection, _fence, viewer, backend) = viewer_parts(1)?;
    let server = RunningServer::start(viewer, HttpConfig::default()).await?;
    let mut socket = connect_viewer(server.address, &session_id).await?;
    backend.wait_attached().await?;

    let control = br#"{"type":"control_changed","controller":"agent"}"#;
    backend.send_server_message(control)?;
    let delivered = timeout(Duration::from_secs(1), read_server_frame(&mut socket)).await??;
    assert_eq!(delivered.opcode, 0x1);
    assert_eq!(delivered.payload, control);

    backend.cancel();
    let _closed = timeout(Duration::from_secs(1), read_server_frame(&mut socket)).await??;
    backend.wait_disconnected().await?;
    server.stop().await;
    Ok(())
}

#[tokio::test]
async fn cancellation_wait_survives_other_ready_branches() -> Result<(), Box<dyn Error>> {
    let (session_id, _connection, _fence, viewer, backend) = viewer_parts(1)?;
    backend.enable_edge_cancellation();
    let server = RunningServer::start(viewer, HttpConfig::default()).await?;
    let mut socket = connect_viewer(server.address, &session_id).await?;
    backend.wait_attached().await?;
    backend.wait_edge_cancellation_armed().await?;

    send_client_frame(&mut socket, 0x1, br#"{"type":"ping"}"#).await?;
    let delivered = timeout(Duration::from_secs(1), backend.next_client_message())
        .await?
        .ok_or_else(|| io::Error::other("viewer command channel closed"))?;
    assert_eq!(delivered, br#"{"type":"ping"}"#);
    let closed = timeout(Duration::from_secs(1), read_server_frame(&mut socket)).await??;
    assert_eq!(close_code(&closed), Some(1_001));

    backend.wait_disconnected().await?;
    server.stop().await;
    Ok(())
}

#[tokio::test]
async fn hanging_backend_disconnect_is_aborted_within_the_socket_timeout()
-> Result<(), Box<dyn Error>> {
    let (session_id, _connection, _fence, viewer, backend) = viewer_parts(1)?;
    backend.hang_disconnect();
    let limits = ViewerSocketLimits::new(64, Duration::from_millis(50))?;
    let config = HttpConfig::default().with_viewer_socket_limits(limits);
    let server = RunningServer::start(viewer, config).await?;
    let mut socket = connect_viewer(server.address, &session_id).await?;
    backend.wait_attached().await?;

    send_client_frame(&mut socket, 0x2, b"unsupported").await?;
    let closed = timeout(Duration::from_secs(1), read_server_frame(&mut socket)).await??;
    assert_eq!(close_code(&closed), Some(1_003));
    backend.wait_disconnected().await?;
    assert_eq!(backend.aborted.load(Ordering::Acquire), 1);

    server.stop().await;
    Ok(())
}

#[tokio::test]
async fn slow_viewer_observes_frame_broadcasters_latest_depth_one_value()
-> Result<(), Box<dyn Error>> {
    let (session_id, _connection, _fence, viewer, backend) = viewer_parts(1)?;
    let server = RunningServer::start(viewer, HttpConfig::default()).await?;
    let mut socket = connect_viewer(server.address, &session_id).await?;
    backend.wait_attached().await?;
    let page_id = backend.page_id.clone();

    assert_eq!(
        backend
            .publish_frame(ViewerFrame::new(
                1,
                page_id.clone(),
                5,
                br#"{"width":2,"height":2}"#.to_vec(),
                vec![1],
            ))?
            .dropped_frames(),
        0
    );
    assert_eq!(
        backend
            .publish_frame(ViewerFrame::new(
                2,
                page_id.clone(),
                5,
                br#"{"width":2,"height":2}"#.to_vec(),
                vec![2],
            ))?
            .dropped_frames(),
        1
    );
    assert_eq!(
        backend
            .publish_frame(ViewerFrame::new(
                3,
                page_id,
                5,
                br#"{"width":2,"height":2}"#.to_vec(),
                vec![3],
            ))?
            .dropped_frames(),
        1
    );

    let delivered = timeout(Duration::from_secs(1), read_server_frame(&mut socket)).await??;
    assert_eq!(delivered.opcode, 0x2);
    assert_eq!(u64::from_be_bytes(delivered.payload[1..9].try_into()?), 3);
    assert_eq!(u64::from_be_bytes(delivered.payload[9..17].try_into()?), 5);
    let metadata_len = usize::try_from(u32::from_be_bytes(delivered.payload[17..21].try_into()?))?;
    assert_eq!(
        &delivered.payload[21..21 + metadata_len],
        br#"{"width":2,"height":2}"#
    );
    assert_eq!(&delivered.payload[21 + metadata_len..], &[3]);

    backend.cancel();
    let closed = timeout(Duration::from_secs(1), read_server_frame(&mut socket)).await??;
    assert_eq!(closed.opcode, 0x8);
    backend.wait_disconnected().await?;
    server.stop().await;
    Ok(())
}

#[tokio::test]
async fn binary_client_payload_is_rejected_without_backend_delivery() -> Result<(), Box<dyn Error>>
{
    let (session_id, _connection, _fence, viewer, backend) = viewer_parts(1)?;
    let server = RunningServer::start(viewer, HttpConfig::default()).await?;
    let mut socket = connect_viewer(server.address, &session_id).await?;
    backend.wait_attached().await?;

    send_client_frame(&mut socket, 0x2, b"not a client text command").await?;
    let closed = timeout(Duration::from_secs(1), read_server_frame(&mut socket)).await??;
    assert_eq!(close_code(&closed), Some(1_003));
    assert!(
        timeout(Duration::from_millis(100), backend.next_client_message())
            .await
            .is_err()
    );
    backend.wait_disconnected().await?;
    server.stop().await;
    Ok(())
}

#[tokio::test]
async fn unknown_text_variant_is_rejected_without_backend_delivery() -> Result<(), Box<dyn Error>> {
    let (session_id, _connection, _fence, viewer, backend) = viewer_parts(1)?;
    let server = RunningServer::start(viewer, HttpConfig::default()).await?;
    let mut socket = connect_viewer(server.address, &session_id).await?;
    backend.wait_attached().await?;

    send_client_frame(&mut socket, 0x1, br#"{"type":"raw_cdp"}"#).await?;
    let closed = timeout(Duration::from_secs(1), read_server_frame(&mut socket)).await??;
    assert_eq!(close_code(&closed), Some(1_003));
    assert!(
        timeout(Duration::from_millis(100), backend.next_client_message())
            .await
            .is_err()
    );
    backend.wait_disconnected().await?;
    server.stop().await;
    Ok(())
}

#[tokio::test]
async fn oversized_text_payload_is_rejected_without_backend_delivery() -> Result<(), Box<dyn Error>>
{
    let (session_id, _connection, _fence, viewer, backend) = viewer_parts(1)?;
    let limits = ViewerSocketLimits::new(32, Duration::from_secs(1))?;
    let config = HttpConfig::default().with_viewer_socket_limits(limits);
    let server = RunningServer::start(viewer, config).await?;
    let mut socket = connect_viewer(server.address, &session_id).await?;
    backend.wait_attached().await?;

    send_client_frame(&mut socket, 0x1, &[b'x'; 33]).await?;
    let closed = timeout(Duration::from_secs(1), read_server_frame(&mut socket)).await??;
    assert_eq!(close_code(&closed), Some(1_009));
    assert!(
        timeout(Duration::from_millis(100), backend.next_client_message())
            .await
            .is_err()
    );
    backend.wait_disconnected().await?;
    server.stop().await;
    Ok(())
}

#[tokio::test]
async fn oversized_binary_payload_is_rejected_with_a_size_close() -> Result<(), Box<dyn Error>> {
    let (session_id, _connection, _fence, viewer, backend) = viewer_parts(1)?;
    let limits = ViewerSocketLimits::new(32, Duration::from_secs(1))?;
    let config = HttpConfig::default().with_viewer_socket_limits(limits);
    let server = RunningServer::start(viewer, config).await?;
    let mut socket = connect_viewer(server.address, &session_id).await?;
    backend.wait_attached().await?;

    send_client_frame(&mut socket, 0x2, &[b'x'; 33]).await?;
    let closed = timeout(Duration::from_secs(1), read_server_frame(&mut socket)).await??;
    assert_eq!(close_code(&closed), Some(1_009));
    assert!(
        timeout(Duration::from_millis(100), backend.next_client_message())
            .await
            .is_err()
    );
    backend.wait_disconnected().await?;
    server.stop().await;
    Ok(())
}
