//! Production viewer ticket presentation and bounded worker bridge.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use browserd_api::{ApiEnvelope, ApiError, ApiResponse, ViewerTicketRequest};
use browserd_auth::AuthenticatedPrincipal;
use browserd_coordination::{EventProjectionSource, GatewayEventProjection, OutboxAppend};
use browserd_core::{ErrorCode, PageId, PlacementFence, SessionId, SessionLifecycle, TenantId};
use browserd_http::{
    AttachedViewer, ConsumedViewerGrant, ViewerAttachError, ViewerClientMessageError,
    ViewerGateError, ViewerTransport,
};
use browserd_viewer::{
    TicketError, TicketPolicy, TicketRegistry, ViewerConnection, ViewerFrame, ViewerScopes,
    ViewerTicket,
};
use browserd_worker::{
    MAX_VIEWER_JPEG_BYTES, MAX_VIEWER_METADATA_BYTES, MAX_VIEWER_SAFE_INTEGER, ViewerClientMessage,
    WorkerRpcError, WorkerRpcFailureCode, WorkerRpcRequest, WorkerRpcResponse, WorkerSessionFence,
    WorkerSessionLifecycle, WorkerViewerCloseRequest, WorkerViewerControl, WorkerViewerController,
    WorkerViewerMessageRequest, WorkerViewerOpenRequest, WorkerViewerPollRequest,
    WorkerViewerSnapshot,
};
use tokio::sync::{Mutex as AsyncMutex, Semaphore, mpsc};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::{
    GatewayConfigurationError, GatewayWorkerClient, GatewayWorkerRuntime, worker_api_error,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayViewerError {
    InvalidPolicy,
    CapacityExceeded,
    ClockUnavailable,
    TicketRejected,
    StateUnavailable,
}

impl fmt::Display for GatewayViewerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "gateway viewer error: {self:?}")
    }
}

impl std::error::Error for GatewayViewerError {}

struct PresentedTicket {
    ticket: ViewerTicket,
    tenant_id: TenantId,
    session_id: SessionId,
    placement_fence: PlacementFence,
    expires_at_millis: u64,
    backend: Option<Arc<dyn ViewerBackend>>,
}

#[derive(Default)]
struct ViewerPresentationState {
    by_ticket: HashMap<ViewerTicket, String>,
    by_secret: HashMap<String, PresentedTicket>,
    consumed: HashMap<browserd_viewer::ConnectionId, (Arc<dyn ViewerBackend>, u64)>,
}

pub struct GatewayViewer {
    tickets: TicketRegistry,
    max_outstanding: usize,
    state: Mutex<ViewerPresentationState>,
    backend: Option<Arc<dyn ViewerBackend>>,
}

impl GatewayViewer {
    pub fn new<I, S>(
        max_ttl: Duration,
        allowed_origins: I,
        max_outstanding: usize,
    ) -> Result<Self, GatewayConfigurationError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        if max_outstanding == 0 {
            return Err(GatewayConfigurationError::InvalidViewerPolicy);
        }
        let policy = TicketPolicy::new(max_ttl, allowed_origins)
            .map_err(|_| GatewayConfigurationError::InvalidViewerPolicy)?;
        Ok(Self {
            tickets: TicketRegistry::new(policy),
            max_outstanding,
            state: Mutex::new(ViewerPresentationState::default()),
            backend: None,
        })
    }

    pub fn issue(
        &self,
        tenant_id: TenantId,
        session_id: SessionId,
        placement_fence: PlacementFence,
        scopes: ViewerScopes,
        ttl: Duration,
    ) -> Result<ViewerTicket, GatewayViewerError> {
        self.issue_bound(tenant_id, session_id, placement_fence, scopes, ttl, None)
    }

    #[allow(clippy::too_many_arguments)]
    fn issue_bound(
        &self,
        tenant_id: TenantId,
        session_id: SessionId,
        placement_fence: PlacementFence,
        scopes: ViewerScopes,
        ttl: Duration,
        backend: Option<Arc<dyn ViewerBackend>>,
    ) -> Result<ViewerTicket, GatewayViewerError> {
        if placement_fence.worker_epoch == 0
            || placement_fence.placement_version == 0
            || placement_fence.session_incarnation == 0
        {
            return Err(GatewayViewerError::TicketRejected);
        }
        let now_millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|duration| u64::try_from(duration.as_millis()).ok())
            .ok_or(GatewayViewerError::ClockUnavailable)?;
        let ttl_millis =
            u64::try_from(ttl.as_millis()).map_err(|_| GatewayViewerError::TicketRejected)?;
        let expires_at_millis = now_millis
            .checked_add(ttl_millis)
            .ok_or(GatewayViewerError::TicketRejected)?;
        let mut state = lock_viewer_state(&self.state)?;
        state
            .consumed
            .retain(|_, (_, expires)| *expires > now_millis);
        let expired = state
            .by_secret
            .iter()
            .filter(|(_, record)| record.expires_at_millis <= now_millis)
            .map(|(secret, record)| (secret.clone(), record.ticket.clone()))
            .collect::<Vec<_>>();
        for (secret, ticket) in expired {
            state.by_secret.remove(&secret);
            state.by_ticket.remove(&ticket);
            self.tickets
                .discard(&ticket)
                .map_err(|_| GatewayViewerError::StateUnavailable)?;
        }
        if state.by_secret.len() + state.consumed.len() >= self.max_outstanding {
            return Err(GatewayViewerError::CapacityExceeded);
        }
        let ticket = self
            .tickets
            .issue(
                tenant_id.clone(),
                session_id.clone(),
                placement_fence.session_incarnation,
                scopes,
                now_millis,
                ttl,
            )
            .map_err(|_| GatewayViewerError::TicketRejected)?;
        let secret = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        state.by_ticket.insert(ticket.clone(), secret.clone());
        state.by_secret.insert(
            secret,
            PresentedTicket {
                ticket: ticket.clone(),
                tenant_id,
                session_id,
                placement_fence,
                expires_at_millis,
                backend,
            },
        );
        Ok(ticket)
    }
}

#[async_trait]
impl ViewerTransport for GatewayViewer {
    async fn consume_ticket(
        &self,
        session_id: &SessionId,
        origin: &str,
        presented: &str,
    ) -> Result<ConsumedViewerGrant, ViewerGateError> {
        let now_millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|duration| u64::try_from(duration.as_millis()).ok())
            .ok_or(ViewerGateError::TicketDenied)?;
        let mut state =
            lock_viewer_state(&self.state).map_err(|_| ViewerGateError::TicketDenied)?;
        let record = state
            .by_secret
            .get(presented)
            .ok_or(ViewerGateError::TicketDenied)?;
        if &record.session_id != session_id {
            return Err(ViewerGateError::TicketDenied);
        }
        let ticket = record.ticket.clone();
        let placement_fence = record.placement_fence;
        let backend = record.backend.clone();
        let expires = record.expires_at_millis;
        let result = self.tickets.consume(
            &ticket,
            &record.tenant_id,
            &record.session_id,
            placement_fence.session_incarnation,
            origin,
            now_millis,
        );
        match result {
            Ok(connection) => {
                if let Some(backend) = backend {
                    state
                        .consumed
                        .insert(connection.id().clone(), (backend, expires));
                }
                state.by_secret.remove(presented);
                state.by_ticket.remove(&ticket);
                self.tickets
                    .discard(&ticket)
                    .map_err(|_| ViewerGateError::TicketDenied)?;
                ConsumedViewerGrant::new(connection, placement_fence)
            }
            Err(TicketError::OriginDenied) => Err(ViewerGateError::OriginDenied),
            Err(_) => {
                state.by_secret.remove(presented);
                state.by_ticket.remove(&ticket);
                self.tickets
                    .discard(&ticket)
                    .map_err(|_| ViewerGateError::TicketDenied)?;
                Err(ViewerGateError::TicketDenied)
            }
        }
    }

    async fn attach(
        &self,
        grant: ConsumedViewerGrant,
    ) -> Result<Box<dyn AttachedViewer>, ViewerAttachError> {
        let backend = lock_viewer_state(&self.state)
            .map_err(|_| ViewerAttachError::BackendUnavailable)?
            .consumed
            .remove(grant.connection().id())
            .map(|(backend, _)| backend)
            .or_else(|| self.backend.clone())
            .ok_or(ViewerAttachError::BackendUnavailable)?;
        WorkerAttachment::open(backend, grant)
            .await
            .map(|attachment| Box::new(attachment) as Box<dyn AttachedViewer>)
    }

    fn present_viewer_ticket(&self, ticket: &ViewerTicket) -> Option<String> {
        lock_viewer_state(&self.state)
            .ok()
            .and_then(|state| state.by_ticket.get(ticket).cloned())
    }
}

fn lock_viewer_state(
    state: &Mutex<ViewerPresentationState>,
) -> Result<MutexGuard<'_, ViewerPresentationState>, GatewayViewerError> {
    state
        .lock()
        .map_err(|_| GatewayViewerError::StateUnavailable)
}

#[async_trait]
trait ViewerBackend: Send + Sync {
    async fn request(&self, request: WorkerRpcRequest)
    -> Result<WorkerRpcResponse, WorkerRpcError>;
}

struct WorkerBackend<C> {
    client: Arc<C>,
    admission: Arc<Semaphore>,
    authority: Option<(
        browserd_coordination::GatewayActionBlockingClient,
        browserd_coordination::GatewaySessionAuthorityRef,
    )>,
}

#[async_trait]
impl<C: GatewayWorkerClient> ViewerBackend for WorkerBackend<C> {
    async fn request(
        &self,
        request: WorkerRpcRequest,
    ) -> Result<WorkerRpcResponse, WorkerRpcError> {
        // The permit lives inside the blocking closure, including when an async caller times out.
        let permit = self
            .admission
            .clone()
            .try_acquire_owned()
            .map_err(|_| WorkerRpcError::Runtime)?;
        let client = Arc::clone(&self.client);
        let authority = self.authority.clone();
        tokio::time::timeout(
            Duration::from_secs(5),
            tokio::task::spawn_blocking(move || {
                let _permit = permit;
                if !matches!(request, WorkerRpcRequest::ViewerClose(_))
                    && let Some((actions, expected)) = authority
                {
                    actions
                        .validate_session_authority(&expected)
                        .map_err(|_| WorkerRpcError::Protocol)?;
                }
                client.request(request)
            }),
        )
        .await
        .map_err(|_| WorkerRpcError::Timeout)?
        .map_err(|_| WorkerRpcError::Runtime)?
    }
}

impl GatewayViewer {
    #[must_use]
    pub fn with_worker_client<C: GatewayWorkerClient>(mut self, client: Arc<C>) -> Self {
        self.backend = Some(Arc::new(WorkerBackend {
            client,
            admission: Arc::new(Semaphore::new(64)),
            authority: None,
        }));
        self
    }
}

impl<C: GatewayWorkerClient> GatewayWorkerRuntime<C> {
    /// Project pending notifications from the authenticated worker's permanent control journal.
    /// Recovery intentionally does not depend on a live gateway session or the event's old epoch.
    pub fn reconcile_viewer_control_events(&self, limit: usize) -> Result<usize, ApiError> {
        if !(1..=browserd_worker::MAX_CONTROL_EVENT_PAGE).contains(&limit) {
            return Err(ApiError::invalid_request(
                "invalid control notification page size",
            ));
        }
        let outbox = self.outbox.as_ref().ok_or_else(|| {
            ApiError::new(
                ErrorCode::WorkerUnavailable,
                "event outbox is not configured",
            )
        })?;
        let client = self.next_control_event_client()?;
        let events = match client
            .request(WorkerRpcRequest::PendingControlEvents { limit })
            .map_err(worker_api_error)?
        {
            WorkerRpcResponse::ControlEvents(events) if events.len() <= limit => events,
            WorkerRpcResponse::Failure(error) => {
                return Err(worker_api_error(WorkerRpcError::Remote(error)));
            }
            _ => {
                return Err(ApiError::new(
                    ErrorCode::WorkerUnavailable,
                    "worker returned an invalid control notification page",
                ));
            }
        };
        let mut delivered = 0;
        for event in events {
            if !event.fence.is_valid()
                || event.control_epoch == 0
                || event.control_epoch > MAX_VIEWER_SAFE_INTEGER
                || (event.human && event.page_id.is_none())
            {
                return Err(ApiError::new(
                    ErrorCode::PlacementMismatch,
                    "control notification contains an invalid source fence",
                ));
            }
            let projection = GatewayEventProjection::new_with_source(
                EventProjectionSource::ViewerControl,
                event.fence.tenant_id.clone(),
                event.fence.session_id.clone(),
                event.sequence,
                OutboxAppend::control_changed(
                    event.fence.tenant_id.clone(),
                    event.fence.session_id.clone(),
                    event.sequence,
                ),
            )
            .map_err(|_| {
                ApiError::new(
                    ErrorCode::WorkerUnavailable,
                    "control notification sequence is invalid",
                )
            })?;
            outbox
                .append_projection(projection, chrono::Utc::now())
                .map_err(|_| {
                    ApiError::new(
                        ErrorCode::WorkerUnavailable,
                        "control notification sink is unavailable",
                    )
                })?;
            // Exact source acknowledgement comes strictly after the atomic sink projection.
            match client
                .request(WorkerRpcRequest::AckControlEvent { event })
                .map_err(worker_api_error)?
            {
                WorkerRpcResponse::Empty => delivered += 1,
                WorkerRpcResponse::Failure(error) => {
                    return Err(worker_api_error(WorkerRpcError::Remote(error)));
                }
                _ => {
                    return Err(ApiError::new(
                        ErrorCode::WorkerUnavailable,
                        "control journal acknowledgement is unconfirmed",
                    ));
                }
            }
        }
        Ok(delivered)
    }

    #[must_use]
    pub fn with_viewer(mut self, viewer: Arc<GatewayViewer>) -> Self {
        self.viewer = Some(viewer);
        self
    }

    pub(crate) fn issue_viewer_ticket(
        &self,
        principal: &AuthenticatedPrincipal,
        request: ViewerTicketRequest,
    ) -> Result<ApiResponse, ApiError> {
        let viewer = self.viewer.as_ref().ok_or_else(|| {
            ApiError::new(
                ErrorCode::WorkerUnavailable,
                "viewer transport is unavailable",
            )
        })?;
        let record = self.session_record(principal.tenant_id(), &request.session_id)?;
        if record.fence.session_incarnation != request.session_incarnation
            || record.resource.lifecycle != SessionLifecycle::Ready
        {
            return Err(ApiError::new(
                ErrorCode::PlacementMismatch,
                "viewer request does not match the active session",
            ));
        }
        // Refresh readiness at issuance; the worker repeats the complete check on attachment.
        let authority = self.authority_ref(principal.tenant_id(), &request.session_id)?;
        let client = self.client_for_fence(&record.fence)?;
        let response = client
            .request(WorkerRpcRequest::GetSession {
                fence: record.fence.clone(),
            })
            .map_err(worker_api_error)?;
        match response {
            WorkerRpcResponse::Session(receipt)
                if receipt.fence == record.fence
                    && receipt.lifecycle == WorkerSessionLifecycle::Ready => {}
            WorkerRpcResponse::Failure(error) => {
                return Err(worker_api_error(WorkerRpcError::Remote(error)));
            }
            _ => {
                return Err(ApiError::new(
                    ErrorCode::PlacementMismatch,
                    "worker rejected viewer session ownership",
                ));
            }
        }
        let ticket = viewer
            .issue_bound(
                principal.tenant_id().clone(),
                request.session_id,
                PlacementFence {
                    worker_epoch: record.fence.worker_epoch,
                    placement_version: record.fence.placement_version,
                    session_incarnation: record.fence.session_incarnation,
                },
                request.scopes,
                request.ttl,
                Some(Arc::new(WorkerBackend {
                    client,
                    admission: Arc::new(Semaphore::new(64)),
                    authority: authority.map(|authority| (self.actions.clone(), authority)),
                })),
            )
            .map_err(|_| {
                ApiError::new(
                    ErrorCode::WorkerUnavailable,
                    "viewer ticket could not be issued",
                )
            })?;
        Ok(ApiResponse::ViewerTicket(ApiEnvelope::new(ticket)))
    }
}

#[derive(Default)]
struct AttachmentState {
    frames: VecDeque<ViewerFrame>,
    last_frame_id: u64,
    transform_epoch: u64,
    page_id: Option<PageId>,
    control: Option<WorkerViewerControl>,
}

struct AttachmentInner {
    backend: Arc<dyn ViewerBackend>,
    connection: ViewerConnection,
    fence: WorkerSessionFence,
    placement: PlacementFence,
    state: Mutex<AttachmentState>,
    rpc_order: AsyncMutex<()>,
    outgoing: mpsc::Sender<Vec<u8>>,
    cancelled: CancellationToken,
    closed: CancellationToken,
}

impl AttachmentInner {
    async fn exchange(
        &self,
        request: WorkerRpcRequest,
    ) -> Result<WorkerViewerSnapshot, WorkerRpcError> {
        match self.backend.request(request).await? {
            WorkerRpcResponse::Viewer(snapshot) => Ok(snapshot),
            WorkerRpcResponse::Failure(error) => Err(WorkerRpcError::Remote(error)),
            _ => Err(WorkerRpcError::Protocol),
        }
    }

    fn apply(&self, snapshot: WorkerViewerSnapshot) -> Result<(), ViewerAttachError> {
        if snapshot.fence != self.fence || snapshot.connection_id != *self.connection.id() {
            return Err(ViewerAttachError::StalePlacement);
        }
        if snapshot.frame_transform_id == 0
            || snapshot.frame_transform_id > MAX_VIEWER_SAFE_INTEGER
            || snapshot.control.lease_epoch > MAX_VIEWER_SAFE_INTEGER
            || (snapshot.control.controller != WorkerViewerController::Agent
                && snapshot.control.lease_epoch == 0)
        {
            return Err(ViewerAttachError::BackendUnavailable);
        }
        let frame = match snapshot.frame {
            None => None,
            Some(frame) => {
                if frame.page_id != snapshot.page_id
                    || frame.frame_transform_id != snapshot.frame_transform_id
                    || frame.frame_id == 0
                    || frame.metadata.len() > MAX_VIEWER_METADATA_BYTES
                    || frame.jpeg_base64.len() > MAX_VIEWER_JPEG_BYTES.div_ceil(3) * 4
                {
                    return Err(ViewerAttachError::BackendUnavailable);
                }
                let metadata: serde_json::Value = serde_json::from_slice(&frame.metadata)
                    .map_err(|_| ViewerAttachError::BackendUnavailable)?;
                if !metadata.is_object()
                    || !["width", "height"].into_iter().all(|key| {
                        metadata
                            .get(key)
                            .and_then(serde_json::Value::as_u64)
                            .is_some_and(|value| (1..=16_384).contains(&value))
                    })
                {
                    return Err(ViewerAttachError::BackendUnavailable);
                }
                let jpeg = STANDARD
                    .decode(&frame.jpeg_base64)
                    .map_err(|_| ViewerAttachError::BackendUnavailable)?;
                if jpeg.len() > MAX_VIEWER_JPEG_BYTES
                    || !jpeg.starts_with(&[0xff, 0xd8])
                    || !jpeg.ends_with(&[0xff, 0xd9])
                {
                    return Err(ViewerAttachError::BackendUnavailable);
                }
                Some(ViewerFrame::new(
                    frame.frame_id,
                    frame.page_id,
                    frame.frame_transform_id,
                    frame.metadata,
                    jpeg,
                ))
            }
        };
        let mut state = self
            .state
            .lock()
            .map_err(|_| ViewerAttachError::BackendUnavailable)?;
        if snapshot.frame_transform_id < state.transform_epoch {
            return Err(ViewerAttachError::StalePlacement);
        }
        let changed = state.control.as_ref() != Some(&snapshot.control)
            || state.page_id.as_ref() != Some(&snapshot.page_id)
            || state.transform_epoch != snapshot.frame_transform_id;
        if state.page_id.as_ref() != Some(&snapshot.page_id)
            || state.transform_epoch != snapshot.frame_transform_id
        {
            state.frames.clear();
            state.last_frame_id = 0;
        }
        state.page_id = Some(snapshot.page_id.clone());
        state.transform_epoch = snapshot.frame_transform_id;
        if let Some(frame) = frame
            && frame.frame_id() > state.last_frame_id
        {
            state.last_frame_id = frame.frame_id();
            if state.frames.len() == 2 {
                state.frames.pop_front();
            }
            state.frames.push_back(frame);
        }
        if changed {
            let controller = match snapshot.control.controller {
                WorkerViewerController::Agent => "agent",
                WorkerViewerController::ThisConnection => "human",
                WorkerViewerController::OtherConnection => "human_other",
            };
            let message = serde_json::to_vec(&serde_json::json!({
                "type":"control_changed", "controller":controller,
                "lease_epoch":snapshot.control.lease_epoch, "page_id":snapshot.page_id,
                "frame_transform_id":snapshot.frame_transform_id,
            }))
            .map_err(|_| ViewerAttachError::BackendUnavailable)?;
            self.outgoing
                .try_send(message)
                .map_err(|_| ViewerAttachError::CapacityExceeded)?;
            state.control = Some(snapshot.control);
        }
        Ok(())
    }

    async fn run(self: Arc<Self>) {
        let mut interval = tokio::time::interval(Duration::from_millis(83));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                biased;
                () = self.cancelled.cancelled() => break,
                _ = interval.tick() => {}
            }
            let _order = self.rpc_order.lock().await;
            if self.cancelled.is_cancelled() {
                break;
            }
            let after_frame_id = match self.state.lock() {
                Ok(state) => state.last_frame_id,
                Err(_) => break,
            };
            let request = WorkerRpcRequest::ViewerPoll(WorkerViewerPollRequest {
                fence: self.fence.clone(),
                connection_id: self.connection.id().clone(),
                after_frame_id,
            });
            match self.exchange(request).await {
                Ok(snapshot) => {
                    if self.apply(snapshot).is_err() {
                        break;
                    }
                }
                _ => break,
            }
        }
        self.cancelled.cancel();
        let _order = self.rpc_order.lock().await;
        let _result = self
            .backend
            .request(WorkerRpcRequest::ViewerClose(WorkerViewerCloseRequest {
                fence: self.fence.clone(),
                connection_id: self.connection.id().clone(),
            }))
            .await;
        self.closed.cancel();
    }
}

struct WorkerAttachment {
    inner: Arc<AttachmentInner>,
    incoming: Mutex<Option<mpsc::Receiver<Vec<u8>>>>,
}

impl WorkerAttachment {
    async fn open(
        backend: Arc<dyn ViewerBackend>,
        grant: ConsumedViewerGrant,
    ) -> Result<Self, ViewerAttachError> {
        let connection = grant.connection().clone();
        let placement = grant.placement_fence();
        let fence = WorkerSessionFence {
            tenant_id: connection.tenant_id().clone(),
            session_id: connection.session_id().clone(),
            worker_epoch: placement.worker_epoch,
            placement_version: placement.placement_version,
            session_incarnation: placement.session_incarnation,
        };
        let (outgoing, incoming) = mpsc::channel(8);
        let inner = Arc::new(AttachmentInner {
            backend,
            connection,
            fence,
            placement,
            state: Mutex::new(AttachmentState::default()),
            rpc_order: AsyncMutex::new(()),
            outgoing,
            cancelled: CancellationToken::new(),
            closed: CancellationToken::new(),
        });
        // Starting the cleanup task before awaiting Open also covers cancellation of attachment.
        let attachment = Self {
            inner: Arc::clone(&inner),
            incoming: Mutex::new(Some(incoming)),
        };
        let order = inner.rpc_order.lock().await;
        tokio::spawn(Arc::clone(&inner).run());
        let result = inner
            .exchange(WorkerRpcRequest::ViewerOpen(WorkerViewerOpenRequest {
                fence: inner.fence.clone(),
                connection: inner.connection.clone(),
            }))
            .await
            .map_err(attach_error)
            .and_then(|snapshot| inner.apply(snapshot));
        drop(order);
        result?;
        Ok(attachment)
    }
}

impl Drop for WorkerAttachment {
    fn drop(&mut self) {
        self.inner.cancelled.cancel();
    }
}

#[async_trait]
impl AttachedViewer for WorkerAttachment {
    fn connection(&self) -> &ViewerConnection {
        &self.inner.connection
    }
    fn placement_fence(&self) -> PlacementFence {
        self.inner.placement
    }
    fn next_frame(&self) -> Result<Option<ViewerFrame>, ViewerAttachError> {
        if self.inner.cancelled.is_cancelled() {
            return Err(ViewerAttachError::BackendUnavailable);
        }
        Ok(self
            .inner
            .state
            .lock()
            .map_err(|_| ViewerAttachError::BackendUnavailable)?
            .frames
            .pop_front())
    }
    fn take_server_messages(&self) -> Result<mpsc::Receiver<Vec<u8>>, ViewerAttachError> {
        self.incoming
            .lock()
            .map_err(|_| ViewerAttachError::BackendUnavailable)?
            .take()
            .ok_or(ViewerAttachError::BackendUnavailable)
    }
    async fn receive_text(&self, message: &[u8]) -> Result<(), ViewerClientMessageError> {
        if message.len() > 64 * 1024 {
            return Err(ViewerClientMessageError::Invalid);
        }
        let message: ViewerClientMessage =
            serde_json::from_slice(message).map_err(|_| ViewerClientMessageError::Invalid)?;
        if !message.is_valid() {
            return Err(ViewerClientMessageError::Invalid);
        }
        if matches!(
            message,
            ViewerClientMessage::Ack { .. } | ViewerClientMessage::ResizeViewOnly { .. }
        ) {
            return Ok(());
        }
        let _order = self.inner.rpc_order.lock().await;
        if self.inner.cancelled.is_cancelled() {
            return Err(ViewerClientMessageError::BackendUnavailable);
        }
        match self
            .inner
            .exchange(WorkerRpcRequest::ViewerMessage(
                WorkerViewerMessageRequest {
                    fence: self.inner.fence.clone(),
                    connection_id: self.inner.connection.id().clone(),
                    message,
                },
            ))
            .await
        {
            Ok(snapshot) => self
                .inner
                .apply(snapshot)
                .map_err(|_| ViewerClientMessageError::BackendUnavailable),
            Err(WorkerRpcError::Remote(failure))
                if failure.code == WorkerRpcFailureCode::Conflict =>
            {
                self.inner
                    .outgoing
                    .try_send(br#"{"type":"error","code":"control_rejected"}"#.to_vec())
                    .map_err(|_| ViewerClientMessageError::BackendUnavailable)
            }
            Err(_) => Err(ViewerClientMessageError::BackendUnavailable),
        }
    }
    async fn cancelled(&self) {
        self.inner.cancelled.cancelled().await;
    }
    async fn disconnect(&self) {
        self.inner.cancelled.cancel();
        self.inner.closed.cancelled().await;
    }
    fn abort(&self) {
        self.inner.cancelled.cancel();
    }
}

fn attach_error(error: WorkerRpcError) -> ViewerAttachError {
    match error {
        WorkerRpcError::Remote(failure) if failure.code == WorkerRpcFailureCode::FenceMismatch => {
            ViewerAttachError::StalePlacement
        }
        WorkerRpcError::Remote(failure) if failure.code == WorkerRpcFailureCode::Capacity => {
            ViewerAttachError::CapacityExceeded
        }
        _ => ViewerAttachError::BackendUnavailable,
    }
}
