//! Axum public HTTP and viewer WebSocket transport for browserd.

#![forbid(unsafe_code)]

use std::fmt;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use axum::body::{Body, to_bytes};
use axum::extract::ws::{CloseFrame, Message, WebSocketUpgrade, close_code};
use axum::extract::{FromRequest, State};
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE, COOKIE, ORIGIN};
use axum::http::{HeaderName, HeaderValue, Method, Request, StatusCode};
use axum::middleware::{Next, from_fn};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use browserd_api::{
    ActionGetRequest, ActionResolveRequest, ActionSubmitCommand, ApiError, ApiRequest, ApiResponse,
    ApiService, ApprovalDecisionBody, ApprovalListQuery, ApprovalStateFilter, ArtifactRequest,
    ArtifactUploadRequest, PageActivateRequest, PageCreateRequest, PageDeleteRequest,
    PageListRequest, SessionListQuery, ViewerScopeRequest, ViewerTicketBody, decode_action_resolve,
    decode_action_submit, decode_approval_decision, decode_artifact_upload, decode_page_create,
    decode_session_create, validate_idempotency_key, validate_last_event_id,
};
use browserd_artifacts::DownloadToken;
use browserd_auth::AuthenticatedPrincipal;
use browserd_core::{
    ActionId, ArtifactId, CreateOperationState, IsolationProfile, OperationId, PageId,
    PlacementFence, RetryClass, SessionId, SessionLifecycle, WorkerId,
};
use browserd_session::{ClientBinding, OwnershipFence, ReconnectToken, SessionTime};
use browserd_viewer::{ViewerConnection, ViewerFrame, ViewerTicket};
use chrono::Utc;
use futures::StreamExt;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::mpsc;
use uuid::Uuid;

const GLOBAL_BODY_LIMIT: usize = 262_144;
const SESSION_BODY_LIMIT: usize = 65_536;
const ACTION_BODY_LIMIT: usize = browserd_api::MAX_ACTION_BODY_BYTES;
const SMALL_BODY_LIMIT: usize = 16_384;
const VIEWER_PROTOCOL: &str = "browser-viewer.v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticationError;

pub trait Authenticator: Send + Sync {
    fn authenticate(&self, bearer: &str) -> Result<AuthenticatedPrincipal, AuthenticationError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ViewerGateError {
    OriginDenied,
    TicketDenied,
}

impl fmt::Display for ViewerGateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "viewer gate rejected the connection: {self:?}")
    }
}

impl std::error::Error for ViewerGateError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ViewerAttachError {
    StalePlacement,
    CapacityExceeded,
    BackendUnavailable,
}

impl fmt::Display for ViewerAttachError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "viewer attachment failed: {self:?}")
    }
}

impl std::error::Error for ViewerAttachError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ViewerClientMessageError {
    Unsupported,
    Invalid,
    BackendUnavailable,
}

impl fmt::Display for ViewerClientMessageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "viewer client message was rejected: {self:?}")
    }
}

impl std::error::Error for ViewerClientMessageError {}

pub struct ConsumedViewerGrant {
    connection: ViewerConnection,
    placement_fence: PlacementFence,
}

impl ConsumedViewerGrant {
    pub fn new(
        connection: ViewerConnection,
        placement_fence: PlacementFence,
    ) -> Result<Self, ViewerGateError> {
        if placement_fence.worker_epoch == 0
            || placement_fence.placement_version == 0
            || placement_fence.session_incarnation == 0
            || connection.session_incarnation() != placement_fence.session_incarnation
        {
            return Err(ViewerGateError::TicketDenied);
        }
        Ok(Self {
            connection,
            placement_fence,
        })
    }

    #[must_use]
    pub const fn connection(&self) -> &ViewerConnection {
        &self.connection
    }

    #[must_use]
    pub const fn placement_fence(&self) -> PlacementFence {
        self.placement_fence
    }
}

#[async_trait]
pub trait AttachedViewer: Send + Sync {
    fn connection(&self) -> &ViewerConnection;

    fn placement_fence(&self) -> PlacementFence;

    fn next_frame(&self) -> Result<Option<ViewerFrame>, ViewerAttachError>;

    fn take_server_messages(&self) -> Result<mpsc::Receiver<Vec<u8>>, ViewerAttachError>;

    async fn receive_text(&self, message: &[u8]) -> Result<(), ViewerClientMessageError>;

    async fn cancelled(&self);

    async fn disconnect(&self);

    fn abort(&self);
}

struct AttachedViewerGuard {
    attachment: Box<dyn AttachedViewer>,
    settled: bool,
}

impl AttachedViewerGuard {
    fn new(attachment: Box<dyn AttachedViewer>) -> Self {
        Self {
            attachment,
            settled: false,
        }
    }

    fn attachment(&self) -> &dyn AttachedViewer {
        self.attachment.as_ref()
    }

    fn abort(&mut self) {
        if !self.settled {
            self.attachment.abort();
            self.settled = true;
        }
    }

    async fn shutdown(mut self, timeout_duration: Duration) {
        if tokio::time::timeout(timeout_duration, self.attachment.disconnect())
            .await
            .is_ok()
        {
            self.settled = true;
        } else {
            self.abort();
        }
    }
}

impl Drop for AttachedViewerGuard {
    fn drop(&mut self) {
        self.abort();
    }
}

#[async_trait]
pub trait ViewerTransport: Send + Sync {
    async fn consume_ticket(
        &self,
        session_id: &SessionId,
        origin: &str,
        ticket: &str,
    ) -> Result<ConsumedViewerGrant, ViewerGateError>;

    async fn attach(
        &self,
        grant: ConsumedViewerGrant,
    ) -> Result<Box<dyn AttachedViewer>, ViewerAttachError>;

    fn present_viewer_ticket(&self, _ticket: &ViewerTicket) -> Option<String> {
        None
    }

    fn present_download_token(&self, _token: &DownloadToken) -> Option<String> {
        None
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ViewerSocketLimits {
    max_client_message_bytes: usize,
    send_timeout: Duration,
}

impl ViewerSocketLimits {
    pub fn new(max_client_message_bytes: usize, send_timeout: Duration) -> Result<Self, ApiError> {
        if !(1..=1_048_576).contains(&max_client_message_bytes)
            || send_timeout.is_zero()
            || send_timeout > Duration::from_secs(60)
        {
            return Err(ApiError::invalid_request("invalid viewer socket limits"));
        }
        Ok(Self {
            max_client_message_bytes,
            send_timeout,
        })
    }
}

impl Default for ViewerSocketLimits {
    fn default() -> Self {
        Self {
            max_client_message_bytes: 65_536,
            send_timeout: Duration::from_secs(5),
        }
    }
}

pub trait Readiness: Send + Sync {
    fn ready(&self) -> bool;
}

#[derive(Clone, Debug)]
pub struct HttpConfig {
    global_body_limit: usize,
    viewer_socket_limits: ViewerSocketLimits,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            global_body_limit: GLOBAL_BODY_LIMIT,
            viewer_socket_limits: ViewerSocketLimits::default(),
        }
    }
}

impl HttpConfig {
    pub fn new(global_body_limit: usize) -> Result<Self, ApiError> {
        if !(ACTION_BODY_LIMIT..=1_048_576).contains(&global_body_limit) {
            return Err(ApiError::invalid_request("invalid HTTP body limit"));
        }
        Ok(Self {
            global_body_limit,
            viewer_socket_limits: ViewerSocketLimits::default(),
        })
    }

    #[must_use]
    pub const fn with_viewer_socket_limits(mut self, limits: ViewerSocketLimits) -> Self {
        self.viewer_socket_limits = limits;
        self
    }
}

#[derive(Clone)]
struct HttpState {
    service: Arc<dyn ApiService>,
    authenticator: Arc<dyn Authenticator>,
    viewer: Arc<dyn ViewerTransport>,
    readiness: Arc<dyn Readiness>,
    global_body_limit: usize,
    viewer_socket_limits: ViewerSocketLimits,
}

pub fn router(
    config: HttpConfig,
    service: Arc<dyn ApiService>,
    authenticator: Arc<dyn Authenticator>,
    viewer: Arc<dyn ViewerTransport>,
    readiness: Arc<dyn Readiness>,
) -> Router {
    Router::new()
        .route("/health/live", get(health_live))
        .route("/health/ready", get(health_ready))
        .route("/metrics", get(metrics))
        .fallback(dispatch)
        .with_state(HttpState {
            service,
            authenticator,
            viewer,
            readiness,
            global_body_limit: config.global_body_limit,
            viewer_socket_limits: config.viewer_socket_limits,
        })
        .layer(axum::extract::DefaultBodyLimit::disable())
        .layer(from_fn(request_id_middleware))
}

async fn request_id_middleware(mut request: Request<Body>, next: Next) -> Response {
    if request.headers().get_all("x-request-id").iter().count() > 1 {
        return transport_error(StatusCode::BAD_REQUEST, "invalid_request");
    }
    let request_id = match request.headers().get("x-request-id") {
        Some(value) => match value.to_str() {
            Ok(value)
                if !value.is_empty()
                    && value.len() <= 128
                    && !value.chars().any(char::is_control) =>
            {
                value.to_owned()
            }
            _ => {
                return transport_error(StatusCode::BAD_REQUEST, "invalid_request");
            }
        },
        None => Uuid::now_v7().to_string(),
    };
    request.extensions_mut().insert(request_id.clone());
    let mut response = next.run(request).await;
    if let Ok(value) = HeaderValue::from_str(&request_id) {
        response
            .headers_mut()
            .insert(HeaderName::from_static("x-request-id"), value);
    }
    if !response.headers().contains_key("x-trace-id")
        && let Ok(value) = HeaderValue::from_str(&Uuid::now_v7().to_string())
    {
        response
            .headers_mut()
            .insert(HeaderName::from_static("x-trace-id"), value);
    }
    response
}

async fn health_live() -> Response {
    json_response(
        StatusCode::OK,
        json!({"data":{"status":"live"},"trace_id":Uuid::now_v7()}),
    )
}

async fn health_ready(State(state): State<HttpState>) -> Response {
    let ready = state.readiness.ready();
    json_response(
        if ready {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        json!({"data":{"status":if ready {"ready"} else {"not_ready"}},"trace_id":Uuid::now_v7()}),
    )
}

async fn metrics(State(state): State<HttpState>) -> Response {
    let ready = usize::from(state.readiness.ready());
    let trace_id = Uuid::now_v7();
    let mut response = (
        StatusCode::OK,
        format!("# TYPE browserd_gateway_up gauge\nbrowserd_gateway_up 1\n# TYPE browserd_gateway_ready gauge\nbrowserd_gateway_ready {ready}\n"),
    )
        .into_response();
    if let Ok(value) = HeaderValue::from_str(&trace_id.to_string()) {
        response
            .headers_mut()
            .insert(HeaderName::from_static("x-trace-id"), value);
    }
    response
}

fn json_response(status: StatusCode, value: Value) -> Response {
    let trace_id = value
        .get("trace_id")
        .and_then(Value::as_str)
        .and_then(|value| HeaderValue::from_str(value).ok());
    let mut response = (status, Json(value)).into_response();
    if let Some(trace_id) = trace_id {
        response
            .headers_mut()
            .insert(HeaderName::from_static("x-trace-id"), trace_id);
    }
    response
}

fn transport_error(status: StatusCode, code: &str) -> Response {
    let trace_id = Uuid::now_v7();
    json_response(
        status,
        json!({"error":{"code":code,"message":"request failed","retryable":false,"details":{},"trace_id":trace_id},"trace_id":trace_id}),
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReconnectBody {
    token: ReconnectToken,
    channel_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FenceBody {
    worker_id: String,
    worker_epoch: u64,
    placement_version: u64,
    session_incarnation: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TransferBody {
    current_fence: FenceBody,
    new_worker_id: String,
    new_worker_epoch: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ViewerTicketHttpBody {
    session_incarnation: u64,
    scopes: ViewerScopeRequest,
    ttl_seconds: u64,
}

async fn dispatch(State(state): State<HttpState>, request: Request<Body>) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    if path.contains("//") || (path.len() > 1 && path.ends_with('/')) {
        return transport_error(StatusCode::BAD_REQUEST, "invalid_request");
    }
    let segments = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();

    if segments.len() == 4
        && segments[0] == "v1"
        && segments[1] == "sessions"
        && segments[3] == "viewer"
        && method == Method::GET
    {
        let session_id = match SessionId::from_str(segments[2]) {
            Ok(value) => value,
            Err(_) => return transport_error(StatusCode::BAD_REQUEST, "invalid_request"),
        };
        if request.uri().query().is_some() {
            return transport_error(StatusCode::BAD_REQUEST, "invalid_request");
        }
        if request
            .headers()
            .get("sec-websocket-protocol")
            .and_then(|value| value.to_str().ok())
            != Some(VIEWER_PROTOCOL)
        {
            return transport_error(StatusCode::BAD_REQUEST, "invalid_request");
        }
        let origin = match request
            .headers()
            .get(ORIGIN)
            .and_then(|value| value.to_str().ok())
        {
            Some(value)
                if value.len() <= 2_048
                    && url::Url::parse(value)
                        .map(|origin| {
                            matches!(origin.scheme(), "http" | "https")
                                && origin.origin().ascii_serialization() == value
                        })
                        .unwrap_or(false) =>
            {
                value.to_owned()
            }
            _ => return transport_error(StatusCode::FORBIDDEN, "permission_denied"),
        };
        let tickets = request
            .headers()
            .get(COOKIE)
            .and_then(|value| value.to_str().ok())
            .map(|cookies| {
                cookies
                    .split(';')
                    .filter_map(|cookie| {
                        cookie
                            .trim()
                            .strip_prefix("browserd_viewer_ticket=")
                            .map(str::to_owned)
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let ticket = match tickets.as_slice() {
            [value] if !value.is_empty() && value.len() <= 2_048 => value.clone(),
            _ => return transport_error(StatusCode::UNAUTHORIZED, "unauthenticated"),
        };
        let connection_upgrade = request
            .headers()
            .get_all("connection")
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(','))
            .any(|value| value.trim().eq_ignore_ascii_case("upgrade"));
        let websocket_upgrade = request.headers().get_all("upgrade").iter().count() == 1
            && request
                .headers()
                .get("upgrade")
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.eq_ignore_ascii_case("websocket"));
        let websocket_version = request
            .headers()
            .get("sec-websocket-version")
            .and_then(|value| value.to_str().ok())
            == Some("13")
            && request
                .headers()
                .get_all("sec-websocket-version")
                .iter()
                .count()
                == 1;
        let websocket_key = request
            .headers()
            .get("sec-websocket-key")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| BASE64_STANDARD.decode(value).ok())
            .is_some_and(|value| value.len() == 16)
            && request
                .headers()
                .get_all("sec-websocket-key")
                .iter()
                .count()
                == 1;
        if request.version() != axum::http::Version::HTTP_11
            || !connection_upgrade
            || !websocket_upgrade
            || !websocket_version
            || !websocket_key
        {
            return transport_error(StatusCode::BAD_REQUEST, "invalid_request");
        }
        let upgrade = match WebSocketUpgrade::from_request(request, &()).await {
            Ok(value) => value,
            Err(_) => return transport_error(StatusCode::BAD_REQUEST, "invalid_request"),
        };
        let grant = match state
            .viewer
            .consume_ticket(&session_id, &origin, &ticket)
            .await
        {
            Ok(grant) => grant,
            Err(error) => {
                return match error {
                    ViewerGateError::OriginDenied => {
                        transport_error(StatusCode::FORBIDDEN, "permission_denied")
                    }
                    ViewerGateError::TicketDenied => {
                        transport_error(StatusCode::UNAUTHORIZED, "unauthenticated")
                    }
                };
            }
        };
        let expected_connection = grant.connection().clone();
        let expected_fence = grant.placement_fence();
        let viewer = Arc::clone(&state.viewer);
        let limits = state.viewer_socket_limits;
        return upgrade
            .max_message_size(limits.max_client_message_bytes)
            .max_frame_size(limits.max_client_message_bytes)
            .protocols([VIEWER_PROTOCOL])
            .on_upgrade(move |mut socket| async move {
                let attachment = match viewer.attach(grant).await {
                    Ok(attachment)
                        if attachment.connection() == &expected_connection
                            && attachment.placement_fence() == expected_fence =>
                    {
                        AttachedViewerGuard::new(attachment)
                    }
                    Ok(attachment) => {
                        let attachment = AttachedViewerGuard::new(attachment);
                        let close = Message::Close(Some(CloseFrame {
                            code: close_code::ERROR,
                            reason: "viewer binding mismatch".into(),
                        }));
                        let _result =
                            tokio::time::timeout(limits.send_timeout, socket.send(close)).await;
                        attachment.shutdown(limits.send_timeout).await;
                        return;
                    }
                    Err(_) => {
                        let close = Message::Close(Some(CloseFrame {
                            code: close_code::ERROR,
                            reason: "viewer attachment failed".into(),
                        }));
                        let _result =
                            tokio::time::timeout(limits.send_timeout, socket.send(close)).await;
                        return;
                    }
                };
                let mut server_messages = match attachment.attachment().take_server_messages() {
                    Ok(messages) => messages,
                    Err(_) => {
                        let close = Message::Close(Some(CloseFrame {
                            code: close_code::ERROR,
                            reason: "viewer message source failed".into(),
                        }));
                        let _result =
                            tokio::time::timeout(limits.send_timeout, socket.send(close)).await;
                        attachment.shutdown(limits.send_timeout).await;
                        return;
                    }
                };
                let mut frames = tokio::time::interval(Duration::from_millis(83));
                frames.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                let closing = {
                    let attached = attachment.attachment();
                    let cancellation = attached.cancelled();
                    tokio::pin!(cancellation);
                    let mut closing = None;
                    loop {
                        tokio::select! {
                            () = &mut cancellation => {
                                closing = Some(CloseFrame {
                                    code: close_code::AWAY,
                                    reason: "viewer cancelled".into(),
                                });
                                break;
                            }
                            incoming = socket.next() => {
                                match incoming {
                                    Some(Ok(Message::Text(message))) => {
                                        if message.len() > limits.max_client_message_bytes {
                                            closing = Some(CloseFrame {
                                                code: close_code::SIZE,
                                                reason: "viewer message too large".into(),
                                            });
                                            break;
                                        }
                                        let delivery = tokio::time::timeout(
                                            limits.send_timeout,
                                            attached.receive_text(message.as_bytes()),
                                        )
                                        .await;
                                        match delivery {
                                            Ok(Ok(())) => {}
                                            Ok(Err(ViewerClientMessageError::Unsupported)) => {
                                                closing = Some(CloseFrame {
                                                    code: close_code::UNSUPPORTED,
                                                    reason: "unsupported viewer message".into(),
                                                });
                                                break;
                                            }
                                            Ok(Err(ViewerClientMessageError::Invalid)) => {
                                                closing = Some(CloseFrame {
                                                    code: close_code::POLICY,
                                                    reason: "invalid viewer message".into(),
                                                });
                                                break;
                                            }
                                            Ok(Err(ViewerClientMessageError::BackendUnavailable))
                                            | Err(_) => {
                                                closing = Some(CloseFrame {
                                                    code: close_code::ERROR,
                                                    reason: "viewer backend unavailable".into(),
                                                });
                                                break;
                                            }
                                        }
                                    }
                                    Some(Ok(Message::Binary(message))) => {
                                        closing = Some(if message.len() > limits.max_client_message_bytes {
                                            CloseFrame {
                                                code: close_code::SIZE,
                                                reason: "viewer message too large".into(),
                                            }
                                        } else {
                                            CloseFrame {
                                                code: close_code::UNSUPPORTED,
                                                reason: "binary client messages are unsupported".into(),
                                            }
                                        });
                                        break;
                                    }
                                    Some(Ok(Message::Close(_))) | None => break,
                                    Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                                    Some(Err(_)) => {
                                        closing = Some(CloseFrame {
                                            code: close_code::SIZE,
                                            reason: "viewer message exceeded parser limits".into(),
                                        });
                                        break;
                                    }
                                }
                            }
                            message = server_messages.recv() => {
                                let Some(message) = message else {
                                    closing = Some(CloseFrame {
                                        code: close_code::ERROR,
                                        reason: "viewer message source closed".into(),
                                    });
                                    break;
                                };
                                if message.len() > limits.max_client_message_bytes {
                                    closing = Some(CloseFrame {
                                        code: close_code::ERROR,
                                        reason: "viewer server message is too large".into(),
                                    });
                                    break;
                                }
                                let Ok(message) = String::from_utf8(message) else {
                                    closing = Some(CloseFrame {
                                        code: close_code::ERROR,
                                        reason: "viewer server message is invalid".into(),
                                    });
                                    break;
                                };
                                match tokio::time::timeout(
                                    limits.send_timeout,
                                    socket.send(Message::Text(message.into())),
                                )
                                .await
                                {
                                    Ok(Ok(())) => {}
                                    Ok(Err(_)) | Err(_) => break,
                                }
                            }
                            _ = frames.tick() => {
                                let frame = match attached.next_frame() {
                                    Ok(Some(frame)) => frame,
                                    Ok(None) => continue,
                                    Err(_) => {
                                        closing = Some(CloseFrame {
                                            code: close_code::ERROR,
                                            reason: "viewer frame source failed".into(),
                                        });
                                        break;
                                    }
                                };
                                let Ok(metadata_len) = u32::try_from(frame.metadata().len()) else {
                                    closing = Some(CloseFrame {
                                        code: close_code::ERROR,
                                        reason: "viewer frame metadata is too large".into(),
                                    });
                                    break;
                                };
                                let Some(capacity) = 21_usize
                                    .checked_add(frame.metadata().len())
                                    .and_then(|length| length.checked_add(frame.jpeg_payload().len()))
                                else {
                                    closing = Some(CloseFrame {
                                        code: close_code::ERROR,
                                        reason: "viewer frame is too large".into(),
                                    });
                                    break;
                                };
                                let mut payload = Vec::with_capacity(capacity);
                                payload.push(1);
                                payload.extend_from_slice(&frame.frame_id().to_be_bytes());
                                payload.extend_from_slice(&frame.transform_epoch().to_be_bytes());
                                payload.extend_from_slice(&metadata_len.to_be_bytes());
                                payload.extend_from_slice(frame.metadata());
                                payload.extend_from_slice(frame.jpeg_payload());
                                match tokio::time::timeout(
                                    limits.send_timeout,
                                    socket.send(Message::Binary(payload.into())),
                                )
                                .await
                                {
                                    Ok(Ok(())) => {}
                                    Ok(Err(_)) | Err(_) => break,
                                }
                            }
                        }
                    }
                    closing
                };
                if let Some(close) = closing {
                    let _result = tokio::time::timeout(
                        limits.send_timeout,
                        socket.send(Message::Close(Some(close))),
                    )
                    .await;
                }
                attachment.shutdown(limits.send_timeout).await;
            });
    }

    if segments.first() != Some(&"v1") {
        return transport_error(StatusCode::NOT_FOUND, "not_found");
    }
    if request.headers().get_all(AUTHORIZATION).iter().count() != 1 {
        return transport_error(StatusCode::UNAUTHORIZED, "unauthenticated");
    }
    let bearer = match request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
    {
        Some(value) if !value.is_empty() && !value.contains(char::is_whitespace) => value,
        _ => return transport_error(StatusCode::UNAUTHORIZED, "unauthenticated"),
    };
    let principal = match state.authenticator.authenticate(bearer) {
        Ok(value) => value,
        Err(_) => return transport_error(StatusCode::UNAUTHORIZED, "unauthenticated"),
    };
    let query = request.uri().query().unwrap_or_default().to_owned();
    if query.len() > 4_096
        || query.as_bytes().iter().enumerate().any(|(index, byte)| {
            *byte == b'%'
                && (query
                    .as_bytes()
                    .get(index + 1)
                    .is_none_or(|value| !value.is_ascii_hexdigit())
                    || query
                        .as_bytes()
                        .get(index + 2)
                        .is_none_or(|value| !value.is_ascii_hexdigit()))
        })
    {
        return transport_error(StatusCode::BAD_REQUEST, "invalid_request");
    }
    let query_allowed = matches!(
        (method.clone(), segments.as_slice()),
        (Method::GET, ["v1", "sessions"])
            | (Method::GET, ["v1", "events"])
            | (Method::GET, ["v1", "approvals"])
    );
    if !query.is_empty() && !query_allowed {
        return transport_error(StatusCode::BAD_REQUEST, "invalid_request");
    }
    let headers = request.headers().clone();
    let route_limit = match (method.clone(), segments.as_slice()) {
        (Method::POST, ["v1", "sessions"]) => SESSION_BODY_LIMIT,
        (Method::POST, ["v1", "sessions", _, "actions"]) => ACTION_BODY_LIMIT,
        (
            Method::POST,
            [
                "v1",
                "sessions",
                _,
                "reconnect" | "transfer" | "pages" | "viewer-ticket",
            ],
        )
        | (Method::POST, ["v1", "sessions", _, "artifacts", "uploads"])
        | (Method::POST, ["v1", "sessions", _, "actions", _, "resolve"])
        | (Method::POST, ["v1", "approvals", _, "decision"]) => SMALL_BODY_LIMIT,
        _ => 0,
    };
    let body = match to_bytes(request.into_body(), state.global_body_limit + 1).await {
        Ok(value) => value,
        Err(_) => return transport_error(StatusCode::PAYLOAD_TOO_LARGE, "invalid_request"),
    };
    if body.len() > state.global_body_limit {
        return transport_error(StatusCode::PAYLOAD_TOO_LARGE, "invalid_request");
    }
    if route_limit == 0 && !body.is_empty() {
        return transport_error(StatusCode::BAD_REQUEST, "invalid_request");
    }
    if body.len() > route_limit {
        return transport_error(StatusCode::PAYLOAD_TOO_LARGE, "invalid_request");
    }
    if !body.is_empty()
        && !headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                value == "application/json" || value == "application/json; charset=utf-8"
            })
    {
        return transport_error(StatusCode::BAD_REQUEST, "invalid_request");
    }
    let body_text = match std::str::from_utf8(&body) {
        Ok(value) => value,
        Err(_) => return transport_error(StatusCode::BAD_REQUEST, "invalid_request"),
    };

    let api_request = match (method.clone(), segments.as_slice()) {
        (Method::POST, ["v1", "sessions"]) => {
            if !query.is_empty() {
                return transport_error(StatusCode::BAD_REQUEST, "invalid_request");
            }
            if headers.get_all("idempotency-key").iter().count() != 1 {
                return transport_error(StatusCode::BAD_REQUEST, "invalid_request");
            }
            let idempotency_key = match headers
                .get("idempotency-key")
                .and_then(|value| value.to_str().ok())
            {
                Some(value) if validate_idempotency_key(value).is_ok() => value.to_owned(),
                _ => return transport_error(StatusCode::BAD_REQUEST, "invalid_request"),
            };
            match decode_session_create(body_text) {
                Ok(body) => ApiRequest::CreateSession {
                    body,
                    idempotency_key,
                    received_at: Instant::now(),
                },
                Err(_) => return transport_error(StatusCode::BAD_REQUEST, "invalid_request"),
            }
        }
        (Method::GET, ["v1", "sessions"]) => {
            let mut request = SessionListQuery::default();
            let mut seen = std::collections::HashSet::new();
            for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
                if !seen.insert(key.to_string()) {
                    return transport_error(StatusCode::BAD_REQUEST, "invalid_request");
                }
                match key.as_ref() {
                    "lifecycle" => {
                        request.lifecycle = match value.as_ref() {
                            "creating" => Some(SessionLifecycle::Creating),
                            "ready" => Some(SessionLifecycle::Ready),
                            "closing" => Some(SessionLifecycle::Closing),
                            "closed" => Some(SessionLifecycle::Closed),
                            "failed" => Some(SessionLifecycle::Failed),
                            _ => {
                                return transport_error(StatusCode::BAD_REQUEST, "invalid_request");
                            }
                        };
                    }
                    "isolation" => {
                        request.isolation = match value.as_ref() {
                            "shared_context" => Some(IsolationProfile::SharedContext),
                            "tenant_dedicated_shard" => {
                                Some(IsolationProfile::TenantDedicatedShard)
                            }
                            "dedicated_process" => Some(IsolationProfile::DedicatedProcess),
                            "dedicated_worker" => Some(IsolationProfile::DedicatedWorker),
                            _ => {
                                return transport_error(StatusCode::BAD_REQUEST, "invalid_request");
                            }
                        };
                    }
                    "metadata_key" => request.metadata_key = Some(value.into_owned()),
                    "limit" => match value.parse() {
                        Ok(limit) => request.limit = limit,
                        Err(_) => {
                            return transport_error(StatusCode::BAD_REQUEST, "invalid_request");
                        }
                    },
                    "page_token" => request.page_token = Some(value.into_owned()),
                    _ => return transport_error(StatusCode::BAD_REQUEST, "invalid_request"),
                }
            }
            ApiRequest::ListSessions(request)
        }
        (Method::GET, ["v1", "operations", operation_id]) => {
            match operation_id.parse::<OperationId>() {
                Ok(value) => ApiRequest::GetOperation(value),
                Err(_) => return transport_error(StatusCode::BAD_REQUEST, "invalid_request"),
            }
        }
        (Method::DELETE, ["v1", "operations", operation_id]) => {
            match operation_id.parse::<OperationId>() {
                Ok(value) => ApiRequest::CancelOperation(value),
                Err(_) => return transport_error(StatusCode::BAD_REQUEST, "invalid_request"),
            }
        }
        (Method::GET, ["v1", "sessions", session_id]) => match session_id.parse::<SessionId>() {
            Ok(value) => ApiRequest::GetSession(value),
            Err(_) => return transport_error(StatusCode::BAD_REQUEST, "invalid_request"),
        },
        (Method::DELETE, ["v1", "sessions", session_id]) => match session_id.parse::<SessionId>() {
            Ok(value) => ApiRequest::DeleteSession(value),
            Err(_) => return transport_error(StatusCode::BAD_REQUEST, "invalid_request"),
        },
        (Method::POST, ["v1", "sessions", session_id, "reconnect"]) => {
            let session_id = match session_id.parse::<SessionId>() {
                Ok(value) => value,
                Err(_) => return transport_error(StatusCode::BAD_REQUEST, "invalid_request"),
            };
            let parsed: ReconnectBody = match serde_json::from_str(body_text) {
                Ok(value) => value,
                Err(_) => return transport_error(StatusCode::BAD_REQUEST, "invalid_request"),
            };
            if parsed.channel_id.is_empty()
                || parsed.channel_id.len() > 255
                || parsed.channel_id.chars().any(char::is_control)
            {
                return transport_error(StatusCode::BAD_REQUEST, "invalid_request");
            }
            ApiRequest::ReconnectSession(browserd_api::SessionReconnectRequest {
                session_id,
                token: parsed.token,
                binding: ClientBinding::new(
                    principal.principal_id().to_string(),
                    parsed.channel_id,
                ),
                now: match u64::try_from(Utc::now().timestamp_millis()) {
                    Ok(value) => SessionTime::new(value),
                    Err(_) => {
                        return transport_error(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "worker_unavailable",
                        );
                    }
                },
            })
        }
        (Method::POST, ["v1", "sessions", session_id, "transfer"]) => {
            let session_id = match session_id.parse::<SessionId>() {
                Ok(value) => value,
                Err(_) => return transport_error(StatusCode::BAD_REQUEST, "invalid_request"),
            };
            let parsed: TransferBody = match serde_json::from_str(body_text) {
                Ok(value) => value,
                Err(_) => return transport_error(StatusCode::BAD_REQUEST, "invalid_request"),
            };
            let current_worker = match WorkerId::new(parsed.current_fence.worker_id) {
                Ok(value) => value,
                Err(_) => return transport_error(StatusCode::BAD_REQUEST, "invalid_request"),
            };
            let new_worker_id = match WorkerId::new(parsed.new_worker_id) {
                Ok(value) => value,
                Err(_) => return transport_error(StatusCode::BAD_REQUEST, "invalid_request"),
            };
            ApiRequest::TransferSession(browserd_api::SessionTransferRequest {
                session_id,
                current_fence: OwnershipFence::new(
                    current_worker,
                    parsed.current_fence.worker_epoch,
                    parsed.current_fence.placement_version,
                    parsed.current_fence.session_incarnation,
                ),
                new_worker_id,
                new_worker_epoch: parsed.new_worker_epoch,
                now: match u64::try_from(Utc::now().timestamp_millis()) {
                    Ok(value) => SessionTime::new(value),
                    Err(_) => {
                        return transport_error(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "worker_unavailable",
                        );
                    }
                },
            })
        }
        (Method::GET, ["v1", "sessions", session_id, "pages"]) => {
            match session_id.parse::<SessionId>() {
                Ok(value) => ApiRequest::ListPages(PageListRequest { session_id: value }),
                Err(_) => return transport_error(StatusCode::BAD_REQUEST, "invalid_request"),
            }
        }
        (Method::POST, ["v1", "sessions", session_id, "pages"]) => {
            let session_id = match session_id.parse::<SessionId>() {
                Ok(value) => value,
                Err(_) => return transport_error(StatusCode::BAD_REQUEST, "invalid_request"),
            };
            match decode_page_create(body_text) {
                Ok(body) => ApiRequest::CreatePage(PageCreateRequest { session_id, body }),
                Err(_) => return transport_error(StatusCode::BAD_REQUEST, "invalid_request"),
            }
        }
        (Method::DELETE, ["v1", "sessions", session_id, "pages", page_id]) => {
            let (session_id, page_id) =
                match (session_id.parse::<SessionId>(), page_id.parse::<PageId>()) {
                    (Ok(session_id), Ok(page_id)) => (session_id, page_id),
                    _ => return transport_error(StatusCode::BAD_REQUEST, "invalid_request"),
                };
            ApiRequest::DeletePage(PageDeleteRequest {
                session_id,
                page_id,
            })
        }
        (Method::POST, ["v1", "sessions", session_id, "pages", page_id, "activate"]) => {
            if !body.is_empty() {
                return transport_error(StatusCode::BAD_REQUEST, "invalid_request");
            }
            let (session_id, page_id) =
                match (session_id.parse::<SessionId>(), page_id.parse::<PageId>()) {
                    (Ok(session_id), Ok(page_id)) => (session_id, page_id),
                    _ => return transport_error(StatusCode::BAD_REQUEST, "invalid_request"),
                };
            ApiRequest::ActivatePage(PageActivateRequest {
                session_id,
                page_id,
            })
        }
        (Method::POST, ["v1", "sessions", session_id, "actions"]) => {
            let session_id = match session_id.parse::<SessionId>() {
                Ok(value) => value,
                Err(_) => return transport_error(StatusCode::BAD_REQUEST, "invalid_request"),
            };
            if headers.get_all("idempotency-key").iter().count() != 1
                || headers.get_all("prefer").iter().count() > 1
            {
                return transport_error(StatusCode::BAD_REQUEST, "invalid_request");
            }
            let idempotency_key = match headers
                .get("idempotency-key")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| validate_idempotency_key(value).ok())
            {
                Some(value) => value,
                None => return transport_error(StatusCode::BAD_REQUEST, "invalid_request"),
            };
            if let Some(prefer) = headers.get("prefer").and_then(|value| value.to_str().ok()) {
                let wait = prefer
                    .strip_prefix("wait=")
                    .and_then(|value| value.parse::<u64>().ok());
                if wait.is_none_or(|wait| wait > 30_000) {
                    return transport_error(StatusCode::BAD_REQUEST, "invalid_request");
                }
            }
            match decode_action_submit(body_text) {
                Ok(body) => ApiRequest::SubmitAction(ActionSubmitCommand {
                    session_id,
                    idempotency_key,
                    body,
                }),
                Err(_) => return transport_error(StatusCode::BAD_REQUEST, "invalid_request"),
            }
        }
        (Method::GET, ["v1", "sessions", session_id, "actions", action_id])
        | (Method::DELETE, ["v1", "sessions", session_id, "actions", action_id]) => {
            let (session_id, action_id) = match (
                session_id.parse::<SessionId>(),
                action_id.parse::<ActionId>(),
            ) {
                (Ok(session_id), Ok(action_id)) => (session_id, action_id),
                _ => return transport_error(StatusCode::BAD_REQUEST, "invalid_request"),
            };
            let request = ActionGetRequest {
                session_id,
                action_id,
            };
            if method == Method::GET {
                ApiRequest::GetAction(request)
            } else {
                ApiRequest::CancelAction(request)
            }
        }
        (
            Method::POST,
            [
                "v1",
                "sessions",
                session_id,
                "actions",
                action_id,
                "resolve",
            ],
        ) => {
            let (session_id, action_id) = match (
                session_id.parse::<SessionId>(),
                action_id.parse::<ActionId>(),
            ) {
                (Ok(session_id), Ok(action_id)) => (session_id, action_id),
                _ => return transport_error(StatusCode::BAD_REQUEST, "invalid_request"),
            };
            match decode_action_resolve(body_text) {
                Ok(body) => ApiRequest::ResolveAction(ActionResolveRequest {
                    session_id,
                    action_id,
                    body,
                }),
                Err(_) => return transport_error(StatusCode::BAD_REQUEST, "invalid_request"),
            }
        }
        (Method::GET, ["v1", "events"]) => {
            let mut cursor = None;
            let mut limit = 50;
            let mut seen = std::collections::HashSet::new();
            for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
                if !seen.insert(key.to_string()) {
                    return transport_error(StatusCode::BAD_REQUEST, "invalid_request");
                }
                match key.as_ref() {
                    "cursor" => match validate_last_event_id(&value) {
                        Ok(value) => cursor = Some(value),
                        Err(_) => {
                            return transport_error(StatusCode::BAD_REQUEST, "invalid_request");
                        }
                    },
                    "limit" => match value.parse() {
                        Ok(value) => limit = value,
                        Err(_) => {
                            return transport_error(StatusCode::BAD_REQUEST, "invalid_request");
                        }
                    },
                    _ => return transport_error(StatusCode::BAD_REQUEST, "invalid_request"),
                }
            }
            if let Some(header_cursor) = headers
                .get("last-event-id")
                .and_then(|value| value.to_str().ok())
            {
                if cursor.is_some() {
                    return transport_error(StatusCode::BAD_REQUEST, "invalid_request");
                }
                cursor = match validate_last_event_id(header_cursor) {
                    Ok(value) => Some(value),
                    Err(_) => return transport_error(StatusCode::BAD_REQUEST, "invalid_request"),
                };
            }
            ApiRequest::ResumeEvents {
                last_event_id: cursor,
                limit,
                now: Utc::now(),
            }
        }
        (Method::POST, ["v1", "sessions", session_id, "viewer-ticket"]) => {
            let session_id = match session_id.parse::<SessionId>() {
                Ok(value) => value,
                Err(_) => return transport_error(StatusCode::BAD_REQUEST, "invalid_request"),
            };
            let parsed: ViewerTicketHttpBody = match serde_json::from_str(body_text) {
                Ok(value) => value,
                Err(_) => return transport_error(StatusCode::BAD_REQUEST, "invalid_request"),
            };
            match (ViewerTicketBody {
                scopes: parsed.scopes,
                ttl_seconds: parsed.ttl_seconds,
            })
            .into_request(session_id, parsed.session_incarnation)
            {
                Ok(value) => ApiRequest::IssueViewerTicket(value),
                Err(_) => return transport_error(StatusCode::BAD_REQUEST, "invalid_request"),
            }
        }
        (Method::POST, ["v1", "sessions", session_id, "artifacts", "uploads"]) => {
            let session_id = match session_id.parse::<SessionId>() {
                Ok(value) => value,
                Err(_) => return transport_error(StatusCode::BAD_REQUEST, "invalid_request"),
            };
            match decode_artifact_upload(body_text) {
                Ok(body) => ApiRequest::UploadArtifact(ArtifactUploadRequest { session_id, body }),
                Err(_) => return transport_error(StatusCode::BAD_REQUEST, "invalid_request"),
            }
        }
        (Method::GET, ["v1", "sessions", session_id, "artifacts", artifact_id])
        | (
            Method::POST,
            [
                "v1",
                "sessions",
                session_id,
                "artifacts",
                artifact_id,
                "download",
            ],
        ) => {
            let (session_id, artifact_id) = match (
                session_id.parse::<SessionId>(),
                artifact_id.parse::<ArtifactId>(),
            ) {
                (Ok(session_id), Ok(artifact_id)) => (session_id, artifact_id),
                _ => return transport_error(StatusCode::BAD_REQUEST, "invalid_request"),
            };
            let request = ArtifactRequest {
                session_id,
                artifact_id,
            };
            if method == Method::GET {
                ApiRequest::GetArtifact(request)
            } else {
                ApiRequest::DownloadArtifact(request)
            }
        }
        (Method::GET, ["v1", "approvals"]) => {
            let mut request = ApprovalListQuery::default();
            let mut seen = std::collections::HashSet::new();
            for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
                if !seen.insert(key.to_string()) {
                    return transport_error(StatusCode::BAD_REQUEST, "invalid_request");
                }
                match key.as_ref() {
                    "state" => {
                        request.state = match value.as_ref() {
                            "pending" => Some(ApprovalStateFilter::Pending),
                            "approved" => Some(ApprovalStateFilter::Approved),
                            "denied" => Some(ApprovalStateFilter::Denied),
                            "expired" => Some(ApprovalStateFilter::Expired),
                            _ => {
                                return transport_error(StatusCode::BAD_REQUEST, "invalid_request");
                            }
                        };
                    }
                    "session_id" => match value.parse() {
                        Ok(value) => request.session_id = Some(value),
                        Err(_) => {
                            return transport_error(StatusCode::BAD_REQUEST, "invalid_request");
                        }
                    },
                    "limit" => match value.parse() {
                        Ok(value) => request.limit = value,
                        Err(_) => {
                            return transport_error(StatusCode::BAD_REQUEST, "invalid_request");
                        }
                    },
                    "page_token" => request.page_token = Some(value.into_owned()),
                    _ => return transport_error(StatusCode::BAD_REQUEST, "invalid_request"),
                }
            }
            ApiRequest::ListApprovals(request)
        }
        (Method::GET, ["v1", "approvals", approval_id]) => match Uuid::parse_str(approval_id) {
            Ok(value) => ApiRequest::GetApproval(value),
            Err(_) => return transport_error(StatusCode::BAD_REQUEST, "invalid_request"),
        },
        (Method::POST, ["v1", "approvals", approval_id, "decision"]) => {
            let approval_id = match Uuid::parse_str(approval_id) {
                Ok(value) => value,
                Err(_) => return transport_error(StatusCode::BAD_REQUEST, "invalid_request"),
            };
            let body: ApprovalDecisionBody = match decode_approval_decision(body_text) {
                Ok(value) => value,
                Err(_) => return transport_error(StatusCode::BAD_REQUEST, "invalid_request"),
            };
            ApiRequest::DecideApproval { approval_id, body }
        }
        _ => return transport_error(StatusCode::NOT_FOUND, "not_found"),
    };

    let service = Arc::clone(&state.service);
    let result =
        tokio::task::spawn_blocking(move || service.execute(&principal, api_request)).await;
    let result = match result {
        Ok(result) => result,
        Err(_) => {
            return transport_error(StatusCode::SERVICE_UNAVAILABLE, "worker_unavailable");
        }
    };
    let response = match result {
        Ok(response) => response,
        Err(error) => {
            let status = StatusCode::from_u16(error.mapping().http_status())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            let retryable = !matches!(
                error.mapping().retry_class(),
                RetryClass::Never | RetryClass::MutationDisallowed
            );
            return json_response(
                status,
                json!({"error":{"code":error.code().to_string(),"message":"request failed","retryable":retryable,"details":error.details(),"trace_id":error.trace_id()},"trace_id":error.trace_id()}),
            );
        }
    };
    match response {
        ApiResponse::ViewerTicket(envelope) => {
            let ticket = match state.viewer.present_viewer_ticket(envelope.data()) {
                Some(ticket)
                    if !ticket.is_empty()
                        && ticket.len() <= 4_096
                        && !ticket.chars().any(|character| {
                            character.is_control() || matches!(character, ';' | ',')
                        }) =>
                {
                    ticket
                }
                _ => {
                    return transport_error(StatusCode::SERVICE_UNAVAILABLE, "worker_unavailable");
                }
            };
            let cookie_path = format!("{}/viewer", path.trim_end_matches("/viewer-ticket"));
            let cookie = format!(
                "browserd_viewer_ticket={ticket}; Path={cookie_path}; Secure; HttpOnly; SameSite=Strict"
            );
            let mut response = json_response(
                StatusCode::CREATED,
                json!({"data":{"ticket_issued":true},"trace_id":envelope.trace_id()}),
            );
            if let Ok(cookie) = HeaderValue::from_str(&cookie) {
                response.headers_mut().insert("set-cookie", cookie);
            }
            response.headers_mut().insert(
                HeaderName::from_static("cache-control"),
                HeaderValue::from_static("no-store"),
            );
            response
        }
        ApiResponse::ArtifactDownload(envelope) => {
            let token = match state.viewer.present_download_token(envelope.data()) {
                Some(token)
                    if !token.is_empty()
                        && token.len() <= 4_096
                        && !token.chars().any(char::is_control) =>
                {
                    token
                }
                _ => {
                    return transport_error(StatusCode::SERVICE_UNAVAILABLE, "worker_unavailable");
                }
            };
            json_response(
                StatusCode::OK,
                json!({"data":{"download_token":token},"trace_id":envelope.trace_id()}),
            )
        }
        response => render_api_response(response, method, &path),
    }
}

pub fn render_api_response(response: ApiResponse, method: Method, path: &str) -> Response {
    let (status, trace_id, data) = match response {
        ApiResponse::SessionCreate(envelope) => {
            let operation = envelope.data().operation();
            let status = if operation.state() == CreateOperationState::Succeeded {
                StatusCode::CREATED
            } else {
                StatusCode::ACCEPTED
            };
            (
                status,
                envelope.trace_id(),
                json!({"operation":{"id":operation.id().to_string(),"state":format!("{:?}",operation.state()).to_ascii_lowercase(),"poll_url":operation.poll_url()}}),
            )
        }
        ApiResponse::Operation(envelope) => {
            let operation = envelope.data();
            (
                if method == Method::DELETE
                    && matches!(
                        operation.state(),
                        CreateOperationState::Accepted
                            | CreateOperationState::Queued
                            | CreateOperationState::Reserving
                            | CreateOperationState::Creating
                    )
                {
                    StatusCode::ACCEPTED
                } else {
                    StatusCode::OK
                },
                envelope.trace_id(),
                json!({"operation":{"id":operation.id().to_string(),"state":format!("{:?}",operation.state()).to_ascii_lowercase(),"poll_url":operation.poll_url()}}),
            )
        }
        ApiResponse::Sessions(envelope) => (
            StatusCode::OK,
            envelope.trace_id(),
            json!({"sessions":envelope.data().items().iter().map(|session| session.id.to_string()).collect::<Vec<_>>(),"next_page_token":envelope.data().next_page_token()}),
        ),
        ApiResponse::Session(envelope) | ApiResponse::SessionClosed(envelope) => {
            let session = envelope.data();
            let status =
                if method == Method::DELETE && session.lifecycle != SessionLifecycle::Closed {
                    StatusCode::ACCEPTED
                } else {
                    StatusCode::OK
                };
            (
                status,
                envelope.trace_id(),
                json!({"session":{"id":session.id.to_string(),"state":format!("{:?}",session.lifecycle).to_ascii_lowercase(),"incarnation":session.incarnation,"metadata":session.metadata}}),
            )
        }
        ApiResponse::Reconnected(envelope) | ApiResponse::Transferred(envelope) => (
            StatusCode::OK,
            envelope.trace_id(),
            json!({"ownership":{"worker_id":envelope.data().worker_id().to_string(),"worker_epoch":envelope.data().worker_epoch(),"placement_version":envelope.data().placement_version(),"session_incarnation":envelope.data().session_incarnation()}}),
        ),
        ApiResponse::Pages(envelope) => (
            StatusCode::OK,
            envelope.trace_id(),
            json!({"pages":envelope.data().iter().map(|page| page.page_id.to_string()).collect::<Vec<_>>() }),
        ),
        ApiResponse::Page(envelope) => (
            if method == Method::POST && path.ends_with("/pages") {
                StatusCode::CREATED
            } else {
                StatusCode::OK
            },
            envelope.trace_id(),
            json!({"page":{"id":envelope.data().page_id.to_string(),"active":envelope.data().active}}),
        ),
        ApiResponse::PageDeleted(envelope) => (
            StatusCode::OK,
            envelope.trace_id(),
            json!({"page":{"id":envelope.data().page_id.to_string(),"deleted":true}}),
        ),
        ApiResponse::Action(envelope) => {
            let state_name = match envelope.data().state() {
                browserd_core::ActionState::Accepted => "accepted",
                browserd_core::ActionState::Queued => "queued",
                browserd_core::ActionState::PendingApproval => "pending_approval",
                browserd_core::ActionState::ReadyToDispatch => "ready_to_dispatch",
                browserd_core::ActionState::MayHaveExecuted => "may_have_executed",
                browserd_core::ActionState::Succeeded => "succeeded",
                browserd_core::ActionState::FailedKnown => "failed_known",
                browserd_core::ActionState::CancelledBeforeDispatch => "cancelled_before_dispatch",
                browserd_core::ActionState::CancelledConfirmed => "cancelled_confirmed",
                browserd_core::ActionState::OutcomeUnknown => "outcome_unknown",
            };
            let pending = matches!(
                envelope.data().state(),
                browserd_core::ActionState::Accepted
                    | browserd_core::ActionState::Queued
                    | browserd_core::ActionState::PendingApproval
                    | browserd_core::ActionState::ReadyToDispatch
                    | browserd_core::ActionState::MayHaveExecuted
            );
            let mut data = serde_json::Map::from_iter([
                (
                    "action_id".to_owned(),
                    json!(envelope.data().action_id().to_string()),
                ),
                ("status".to_owned(), json!(state_name)),
                (
                    "session_sequence".to_owned(),
                    json!(envelope.data().action_sequence().get()),
                ),
            ]);
            match envelope.data().terminal_detail() {
                Some(browserd_actions::TerminalDetail::FailedKnown(reason)) => {
                    let reason = match reason {
                        browserd_actions::KnownFailureReason::NotDispatched => "not_dispatched",
                        browserd_actions::KnownFailureReason::BrowserRejected => "browser_rejected",
                        browserd_actions::KnownFailureReason::PolicyDenied => "policy_denied",
                        browserd_actions::KnownFailureReason::ApprovalDenied => "approval_denied",
                        browserd_actions::KnownFailureReason::ApprovalTimedOut => {
                            "approval_timed_out"
                        }
                        browserd_actions::KnownFailureReason::ExecutionTimedOut => {
                            "execution_timed_out"
                        }
                    };
                    data.insert("reason".to_owned(), json!(reason));
                }
                Some(browserd_actions::TerminalDetail::OutcomeUnknown(reason)) => {
                    let reason = match reason {
                        browserd_actions::OutcomeUnknownReason::AmbiguousTransportLoss => {
                            "ambiguous_transport_loss"
                        }
                        browserd_actions::OutcomeUnknownReason::WorkerLost => "worker_lost",
                        browserd_actions::OutcomeUnknownReason::TimeoutAfterDispatch => {
                            "timeout_after_dispatch"
                        }
                    };
                    data.insert("reason".to_owned(), json!(reason));
                    data.insert("retryable".to_owned(), json!(false));
                }
                Some(
                    browserd_actions::TerminalDetail::Succeeded(_)
                    | browserd_actions::TerminalDetail::CancelledBeforeDispatch
                    | browserd_actions::TerminalDetail::CancelledConfirmed,
                )
                | None => {}
            }
            // Surface the live result content of a succeeded action as parsed JSON. Absent on
            // durable re-reads, which retain only the integrity digest.
            if let Some(content) = envelope.data().result_content()
                && let Ok(result) = serde_json::from_slice::<serde_json::Value>(content)
            {
                data.insert("result".to_owned(), result);
            }
            (
                if method == Method::POST && pending {
                    StatusCode::ACCEPTED
                } else {
                    StatusCode::OK
                },
                envelope.trace_id(),
                serde_json::Value::Object(data),
            )
        }
        ApiResponse::Events(envelope) => (
            StatusCode::OK,
            envelope.trace_id(),
            json!({"events":envelope.data().events().iter().map(|event| {
                let kind = match event.kind() {
                    browserd_api::EventKind::OperationStateChanged => "operation.state_changed",
                    browserd_api::EventKind::SessionLifecycleChanged => "session.lifecycle_changed",
                    browserd_api::EventKind::SessionExecutionChanged => "session.execution_changed",
                    browserd_api::EventKind::ActionStateChanged => "action.state_changed",
                    browserd_api::EventKind::ActionApprovalRequired => "action.approval_required",
                    browserd_api::EventKind::ApprovalDecided => "approval.decided",
                    browserd_api::EventKind::BrowserControlChanged => "browser.control_changed",
                    browserd_api::EventKind::DownloadCompleted => "download.completed",
                    browserd_api::EventKind::ArtifactStateChanged => "artifact.state_changed",
                };
                json!({"event_id":event.event_id(),"kind":kind,"created_at":event.created_at()})
            }).collect::<Vec<_>>(),"gap":envelope.data().gap(),"next_cursor":envelope.data().next_cursor()}),
        ),
        ApiResponse::ViewerTicket(_) => {
            return transport_error(StatusCode::SERVICE_UNAVAILABLE, "worker_unavailable");
        }
        ApiResponse::ArtifactUpload(envelope) | ApiResponse::Artifact(envelope) => {
            let artifact = envelope.data();
            (
                if path.ends_with("/uploads") {
                    StatusCode::CREATED
                } else {
                    StatusCode::OK
                },
                envelope.trace_id(),
                json!({"artifact":{"id":artifact.key.artifact_id().to_string(),"state":format!("{:?}",artifact.state).to_ascii_lowercase(),"size_bytes":artifact.size_bytes,"content_type":artifact.content_type}}),
            )
        }
        ApiResponse::ArtifactDownload(_) => {
            return transport_error(StatusCode::SERVICE_UNAVAILABLE, "worker_unavailable");
        }
        ApiResponse::Approvals(envelope) => (
            StatusCode::OK,
            envelope.trace_id(),
            json!({"approvals":envelope.data().items().iter().map(|approval| approval.approval_id).collect::<Vec<_>>(),"next_page_token":envelope.data().next_page_token()}),
        ),
        ApiResponse::Approval(envelope) => (
            StatusCode::OK,
            envelope.trace_id(),
            json!({"approval":{"id":envelope.data().approval_id,"session_id":envelope.data().session_id.to_string(),"action_id":envelope.data().action_id.to_string(),"state":match &envelope.data().state { browserd_policy::ApprovalState::Pending => "pending", browserd_policy::ApprovalState::Approved { .. } => "approved", browserd_policy::ApprovalState::Denied { .. } => "denied", browserd_policy::ApprovalState::Expired => "expired" }}}),
        ),
    };
    json_response(status, json!({"data":data,"trace_id":trace_id}))
}
