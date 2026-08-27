//! Production-facing gateway adapters that are independent of HTTP routing.

#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use browserd_actions::{ActionKind, ActionSnapshot};
use browserd_api::{
    ActionGetRequest, ActionPayload, ActionResolveRequest, ActionSubmitCommand, ApiEnvelope,
    ApiError, ApiRequest, ApiResponse, ApprovalCatalog, ApprovalDecisionBody,
    ApprovalDecisionRequest, ApprovalListQuery, ApprovalResource, ArtifactMetadata,
    ArtifactRequest, CreateAuthority, IsolationRequest, PageActivateRequest, PageCreateRequest,
    PageDeleteRequest, PageListRequest, PageResource, RuntimeApiBackend, RuntimeCreateResult,
    SessionCatalog, SessionCreateDispatch, SessionCreateRequest, SessionResource,
    public_approval_id,
};
use browserd_artifacts::{
    ArtifactChecksum, ArtifactContentMetadata, ArtifactContentSource, ArtifactKey, ArtifactState,
};
use browserd_auth::{AuthConfig, RevocationRegistry, ServiceTokenVerifier, VerificationKeySet};
use browserd_core::{
    ApprovalId, ErrorCode, IsolationProfile, SessionId, SessionLifecycle, TenantId,
};
use browserd_http::{
    AuthenticationError, Authenticator, Readiness, ViewerGateError, ViewerTransport,
};
use browserd_viewer::{TicketError, TicketPolicy, TicketRegistry, ViewerScopes, ViewerTicket};
use browserd_worker::{
    WorkerActionReceipt, WorkerApprovalDecision, WorkerApprovalReceipt, WorkerApprovalState,
    WorkerArtifactReceipt, WorkerArtifactSource, WorkerArtifactState, WorkerCreateSessionReceipt,
    WorkerCreateSessionRequest, WorkerIsolationProfile, WorkerPageReceipt, WorkerRpcBlockingClient,
    WorkerRpcError, WorkerRpcFailureCode, WorkerRpcRequest, WorkerRpcResponse, WorkerSessionFence,
    WorkerSessionLifecycle,
};
use jsonwebtoken::Algorithm;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayConfigurationError {
    InvalidAuthentication,
    InvalidViewerPolicy,
    InvalidWorkerPlacement,
}

impl fmt::Display for GatewayConfigurationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "gateway configuration error: {self:?}")
    }
}

impl std::error::Error for GatewayConfigurationError {}

pub struct GatewayAuthenticator {
    verifier: ServiceTokenVerifier,
}

impl GatewayAuthenticator {
    pub fn from_hmac_parts(
        issuer: &str,
        audience: &str,
        key_id: &str,
        secret: &[u8],
        clock_skew_seconds: u64,
    ) -> Result<Self, GatewayConfigurationError> {
        let invalid_text = |value: &str| {
            value.is_empty()
                || value.len() > 255
                || value.trim() != value
                || value.chars().any(char::is_control)
        };
        if invalid_text(issuer)
            || invalid_text(audience)
            || invalid_text(key_id)
            || !(32..=4_096).contains(&secret.len())
            || clock_skew_seconds > 300
        {
            return Err(GatewayConfigurationError::InvalidAuthentication);
        }
        let mut keys = VerificationKeySet::new();
        keys.insert_hmac(key_id, Algorithm::HS256, secret)
            .map_err(|_| GatewayConfigurationError::InvalidAuthentication)?;
        Ok(Self {
            verifier: ServiceTokenVerifier::new(
                AuthConfig::new(
                    issuer,
                    audience,
                    [Algorithm::HS256],
                    clock_skew_seconds,
                    false,
                ),
                keys,
                RevocationRegistry::default(),
            ),
        })
    }
}

impl Authenticator for GatewayAuthenticator {
    fn authenticate(
        &self,
        bearer: &str,
    ) -> Result<browserd_auth::AuthenticatedPrincipal, AuthenticationError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|duration| i64::try_from(duration.as_secs()).ok())
            .ok_or(AuthenticationError)?;
        self.verifier
            .verify_at(bearer, None, now)
            .map_err(|_| AuthenticationError)
    }
}

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
    session_incarnation: u64,
    expires_at_millis: u64,
}

#[derive(Default)]
struct ViewerPresentationState {
    by_ticket: HashMap<ViewerTicket, String>,
    by_secret: HashMap<String, PresentedTicket>,
}

pub struct GatewayViewer {
    tickets: TicketRegistry,
    max_outstanding: usize,
    state: Mutex<ViewerPresentationState>,
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
        })
    }

    pub fn issue(
        &self,
        tenant_id: TenantId,
        session_id: SessionId,
        session_incarnation: u64,
        scopes: ViewerScopes,
        ttl: Duration,
    ) -> Result<ViewerTicket, GatewayViewerError> {
        if session_incarnation == 0 {
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
        if state.by_secret.len() >= self.max_outstanding {
            return Err(GatewayViewerError::CapacityExceeded);
        }
        let ticket = self
            .tickets
            .issue(
                tenant_id.clone(),
                session_id.clone(),
                session_incarnation,
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
                session_incarnation,
                expires_at_millis,
            },
        );
        Ok(ticket)
    }
}

impl ViewerTransport for GatewayViewer {
    fn consume_ticket(
        &self,
        session_id: &SessionId,
        origin: &str,
        presented: &str,
    ) -> Result<(), ViewerGateError> {
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
        let result = self.tickets.consume(
            &ticket,
            &record.tenant_id,
            &record.session_id,
            record.session_incarnation,
            origin,
            now_millis,
        );
        match result {
            Ok(_) => {
                state.by_secret.remove(presented);
                state.by_ticket.remove(&ticket);
                self.tickets
                    .discard(&ticket)
                    .map_err(|_| ViewerGateError::TicketDenied)?;
                Ok(())
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

    fn connected(&self, _session_id: SessionId) {}

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

#[derive(Default)]
pub struct GatewayReadiness {
    worker_ready: AtomicBool,
    coordination_ready: AtomicBool,
}

impl GatewayReadiness {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            worker_ready: AtomicBool::new(false),
            coordination_ready: AtomicBool::new(false),
        }
    }

    pub fn set_worker_ready(&self, ready: bool) {
        self.worker_ready.store(ready, Ordering::Release);
    }

    pub fn set_coordination_ready(&self, ready: bool) {
        self.coordination_ready.store(ready, Ordering::Release);
    }
}

impl Readiness for GatewayReadiness {
    fn ready(&self) -> bool {
        self.worker_ready.load(Ordering::Acquire) && self.coordination_ready.load(Ordering::Acquire)
    }
}

pub trait GatewayWorkerClient: Send + Sync + 'static {
    fn create_session(
        &self,
        request: WorkerCreateSessionRequest,
    ) -> Result<WorkerCreateSessionReceipt, WorkerRpcError>;

    fn request(&self, request: WorkerRpcRequest) -> Result<WorkerRpcResponse, WorkerRpcError>;
}

impl GatewayWorkerClient for WorkerRpcBlockingClient {
    fn create_session(
        &self,
        request: WorkerCreateSessionRequest,
    ) -> Result<WorkerCreateSessionReceipt, WorkerRpcError> {
        WorkerRpcBlockingClient::create_session(self, request)
    }

    fn request(&self, request: WorkerRpcRequest) -> Result<WorkerRpcResponse, WorkerRpcError> {
        self.request_blocking(request)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GatewayWorkerPlacement {
    worker_epoch: u64,
    placement_version: u64,
}

impl GatewayWorkerPlacement {
    pub fn new(
        worker_epoch: u64,
        placement_version: u64,
    ) -> Result<Self, GatewayConfigurationError> {
        if worker_epoch == 0 || placement_version == 0 {
            return Err(GatewayConfigurationError::InvalidWorkerPlacement);
        }
        Ok(Self {
            worker_epoch,
            placement_version,
        })
    }
}

pub struct GatewayWorkerRuntime<C> {
    client: Arc<C>,
    placement: GatewayWorkerPlacement,
    sessions: Mutex<HashMap<(TenantId, SessionId), GatewaySessionRecord>>,
    action_identities:
        Mutex<HashMap<(TenantId, SessionId, browserd_core::ActionId), GatewayActionIdentity>>,
    catalog: SessionCatalog,
}

#[derive(Clone)]
struct GatewaySessionRecord {
    fence: WorkerSessionFence,
    resource: SessionResource,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct GatewayActionIdentity {
    idempotency_key: String,
    canonical_request_hash: [u8; 32],
    kind: ActionKind,
}

const MAX_APPROVAL_ROUTE_SCAN: usize = 256;
const MAX_APPROVAL_RECEIPTS: usize = 16_384;
const MAX_SESSION_PAGES: usize = 8;
const MAX_TRACKED_ACTION_IDENTITIES: usize = 16_384;

impl<C> GatewayWorkerRuntime<C> {
    #[must_use]
    pub fn new(client: Arc<C>, placement: GatewayWorkerPlacement) -> Self {
        Self {
            client,
            placement,
            sessions: Mutex::new(HashMap::new()),
            action_identities: Mutex::new(HashMap::new()),
            catalog: SessionCatalog::default(),
        }
    }
}

fn current_unix_millis() -> Result<u64, ApiError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .ok_or_else(|| ApiError::new(ErrorCode::WorkerUnavailable, "gateway clock unavailable"))
}

fn worker_api_error(error: WorkerRpcError) -> ApiError {
    worker_api_error_with_codes(
        error,
        ErrorCode::SessionNotFound,
        ErrorCode::IdempotencyConflict,
        ErrorCode::GlobalCapacityExceeded,
    )
}

fn worker_api_error_with_codes(
    error: WorkerRpcError,
    not_found: ErrorCode,
    conflict: ErrorCode,
    capacity: ErrorCode,
) -> ApiError {
    match error {
        WorkerRpcError::Remote(failure) => {
            let code = match failure.code {
                WorkerRpcFailureCode::InvalidRequest => ErrorCode::InvalidRequest,
                WorkerRpcFailureCode::Unauthorized => ErrorCode::PermissionDenied,
                WorkerRpcFailureCode::FenceMismatch => ErrorCode::PlacementMismatch,
                WorkerRpcFailureCode::NotFound => not_found,
                WorkerRpcFailureCode::Conflict => conflict,
                WorkerRpcFailureCode::Capacity => capacity,
                WorkerRpcFailureCode::NotReady
                | WorkerRpcFailureCode::Dependency
                | WorkerRpcFailureCode::Durability
                | WorkerRpcFailureCode::Timeout => ErrorCode::WorkerUnavailable,
                WorkerRpcFailureCode::Internal => ErrorCode::Internal,
            };
            ApiError::new(code, "worker rejected the request")
        }
        WorkerRpcError::InvalidConfig
        | WorkerRpcError::InvalidRequest
        | WorkerRpcError::Protocol
        | WorkerRpcError::Serialization(_) => {
            ApiError::new(ErrorCode::Internal, "worker RPC contract failure")
        }
        WorkerRpcError::UnauthorizedPeer => ApiError::new(
            ErrorCode::PermissionDenied,
            "worker RPC peer rejected gateway",
        ),
        WorkerRpcError::FrameTooLarge
        | WorkerRpcError::Timeout
        | WorkerRpcError::QueueFull
        | WorkerRpcError::Runtime
        | WorkerRpcError::Io(_) => {
            ApiError::new(ErrorCode::WorkerUnavailable, "worker RPC unavailable")
        }
    }
}

impl<C> GatewayWorkerRuntime<C>
where
    C: GatewayWorkerClient,
{
    fn session_record(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
    ) -> Result<GatewaySessionRecord, ApiError> {
        self.sessions
            .lock()
            .map_err(|_| ApiError::new(ErrorCode::WorkerUnavailable, "session state unavailable"))?
            .get(&(tenant_id.clone(), session_id.clone()))
            .cloned()
            .ok_or_else(|| ApiError::new(ErrorCode::SessionNotFound, "session not found"))
    }

    fn validate_current_fence(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        expected: &WorkerSessionFence,
    ) -> Result<(), ApiError> {
        if &expected.tenant_id != tenant_id
            || &expected.session_id != session_id
            || expected.worker_epoch != self.placement.worker_epoch
            || expected.placement_version != self.placement.placement_version
            || expected.session_incarnation == 0
        {
            return Err(ApiError::new(
                ErrorCode::PlacementMismatch,
                "worker response escaped the session placement fence",
            ));
        }
        let sessions = self.sessions.lock().map_err(|_| {
            ApiError::new(ErrorCode::WorkerUnavailable, "session state unavailable")
        })?;
        if sessions
            .get(&(tenant_id.clone(), session_id.clone()))
            .is_none_or(|current| current.fence != *expected)
        {
            return Err(ApiError::new(
                ErrorCode::PlacementMismatch,
                "session placement changed during worker request",
            ));
        }
        Ok(())
    }

    fn page_resource(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        expected_fence: &WorkerSessionFence,
        receipt: WorkerPageReceipt,
        expected_page_id: Option<&browserd_core::PageId>,
    ) -> Result<PageResource, ApiError> {
        if receipt.fence != *expected_fence
            || expected_page_id.is_some_and(|page_id| page_id != &receipt.page_id)
            || receipt.target_incarnation == 0
            || receipt.document_epoch == 0
        {
            return Err(ApiError::new(
                ErrorCode::PlacementMismatch,
                "worker returned a mismatched page receipt",
            ));
        }
        self.validate_current_fence(tenant_id, session_id, &receipt.fence)?;
        Ok(PageResource {
            session_id: session_id.clone(),
            page_id: receipt.page_id,
            active: receipt.active,
            target_incarnation: receipt.target_incarnation,
            document_epoch: receipt.document_epoch,
            url_revision: receipt.url_revision,
        })
    }

    fn list_pages(
        &self,
        principal: &browserd_auth::AuthenticatedPrincipal,
        command: PageListRequest,
    ) -> Result<ApiResponse, ApiError> {
        let record = self.session_record(principal.tenant_id(), &command.session_id)?;
        let receipts = match self
            .client
            .request(WorkerRpcRequest::ListPages {
                fence: record.fence.clone(),
            })
            .map_err(|error| {
                worker_api_error_with_codes(
                    error,
                    ErrorCode::SessionNotFound,
                    ErrorCode::PlacementMismatch,
                    ErrorCode::TargetLimitExceeded,
                )
            })? {
            WorkerRpcResponse::Pages(receipts) => receipts,
            WorkerRpcResponse::Failure(failure) => {
                return Err(worker_api_error_with_codes(
                    WorkerRpcError::Remote(failure),
                    ErrorCode::SessionNotFound,
                    ErrorCode::PlacementMismatch,
                    ErrorCode::TargetLimitExceeded,
                ));
            }
            _ => {
                return Err(ApiError::new(
                    ErrorCode::Internal,
                    "worker returned an unexpected page-list response",
                ));
            }
        };
        if receipts.len() > MAX_SESSION_PAGES {
            return Err(ApiError::new(
                ErrorCode::TargetLimitExceeded,
                "worker page list exceeded the gateway bound",
            ));
        }
        let mut page_ids = HashSet::with_capacity(receipts.len());
        let mut active_seen = false;
        let mut pages = Vec::with_capacity(receipts.len());
        for receipt in receipts {
            if !page_ids.insert(receipt.page_id.clone()) || (receipt.active && active_seen) {
                return Err(ApiError::new(
                    ErrorCode::PlacementMismatch,
                    "worker returned contradictory page state",
                ));
            }
            active_seen |= receipt.active;
            pages.push(self.page_resource(
                principal.tenant_id(),
                &command.session_id,
                &record.fence,
                receipt,
                None,
            )?);
        }
        Ok(ApiResponse::Pages(ApiEnvelope::new(pages)))
    }

    fn create_page(
        &self,
        principal: &browserd_auth::AuthenticatedPrincipal,
        command: PageCreateRequest,
    ) -> Result<ApiResponse, ApiError> {
        if command.body.url.is_some() {
            return Err(ApiError::new(
                ErrorCode::InvalidRequest,
                "worker RPC does not support an atomic initial page URL",
            ));
        }
        let record = self.session_record(principal.tenant_id(), &command.session_id)?;
        let receipt = match self
            .client
            .request(WorkerRpcRequest::CreatePage {
                fence: record.fence.clone(),
                now_unix_millis: current_unix_millis()?,
            })
            .map_err(|error| {
                worker_api_error_with_codes(
                    error,
                    ErrorCode::SessionNotFound,
                    ErrorCode::PlacementMismatch,
                    ErrorCode::TargetLimitExceeded,
                )
            })? {
            WorkerRpcResponse::Page(receipt) => receipt,
            WorkerRpcResponse::Failure(failure) => {
                return Err(worker_api_error_with_codes(
                    WorkerRpcError::Remote(failure),
                    ErrorCode::SessionNotFound,
                    ErrorCode::PlacementMismatch,
                    ErrorCode::TargetLimitExceeded,
                ));
            }
            _ => {
                return Err(ApiError::new(
                    ErrorCode::Internal,
                    "worker returned an unexpected page-create response",
                ));
            }
        };
        self.page_resource(
            principal.tenant_id(),
            &command.session_id,
            &record.fence,
            receipt,
            None,
        )
        .map(ApiEnvelope::new)
        .map(ApiResponse::Page)
    }

    fn activate_page(
        &self,
        principal: &browserd_auth::AuthenticatedPrincipal,
        command: PageActivateRequest,
    ) -> Result<ApiResponse, ApiError> {
        let record = self.session_record(principal.tenant_id(), &command.session_id)?;
        let receipt = match self
            .client
            .request(WorkerRpcRequest::ActivatePage {
                fence: record.fence.clone(),
                page_id: command.page_id.clone(),
                now_unix_millis: current_unix_millis()?,
            })
            .map_err(|error| {
                worker_api_error_with_codes(
                    error,
                    ErrorCode::PageNotFound,
                    ErrorCode::PlacementMismatch,
                    ErrorCode::TargetLimitExceeded,
                )
            })? {
            WorkerRpcResponse::Page(receipt) => receipt,
            WorkerRpcResponse::Failure(failure) => {
                return Err(worker_api_error_with_codes(
                    WorkerRpcError::Remote(failure),
                    ErrorCode::PageNotFound,
                    ErrorCode::PlacementMismatch,
                    ErrorCode::TargetLimitExceeded,
                ));
            }
            _ => {
                return Err(ApiError::new(
                    ErrorCode::Internal,
                    "worker returned an unexpected page-activation response",
                ));
            }
        };
        self.page_resource(
            principal.tenant_id(),
            &command.session_id,
            &record.fence,
            receipt,
            Some(&command.page_id),
        )
        .map(ApiEnvelope::new)
        .map(ApiResponse::Page)
    }

    fn delete_page(
        &self,
        principal: &browserd_auth::AuthenticatedPrincipal,
        command: PageDeleteRequest,
    ) -> Result<ApiResponse, ApiError> {
        let record = self.session_record(principal.tenant_id(), &command.session_id)?;
        let receipt = match self
            .client
            .request(WorkerRpcRequest::ClosePage {
                fence: record.fence.clone(),
                page_id: command.page_id.clone(),
                now_unix_millis: current_unix_millis()?,
            })
            .map_err(|error| {
                worker_api_error_with_codes(
                    error,
                    ErrorCode::PageNotFound,
                    ErrorCode::PlacementMismatch,
                    ErrorCode::TargetLimitExceeded,
                )
            })? {
            WorkerRpcResponse::PageClosed(receipt) => receipt,
            WorkerRpcResponse::Failure(failure) => {
                return Err(worker_api_error_with_codes(
                    WorkerRpcError::Remote(failure),
                    ErrorCode::PageNotFound,
                    ErrorCode::PlacementMismatch,
                    ErrorCode::TargetLimitExceeded,
                ));
            }
            _ => {
                return Err(ApiError::new(
                    ErrorCode::Internal,
                    "worker returned an unexpected page-close response",
                ));
            }
        };
        self.page_resource(
            principal.tenant_id(),
            &command.session_id,
            &record.fence,
            receipt,
            Some(&command.page_id),
        )
        .map(ApiEnvelope::new)
        .map(ApiResponse::PageDeleted)
    }
}

impl<C> GatewayWorkerRuntime<C>
where
    C: GatewayWorkerClient,
{
    fn action_snapshot(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        expected_fence: &WorkerSessionFence,
        receipt: WorkerActionReceipt,
        expected_action_id: Option<&browserd_core::ActionId>,
        expected_submission: Option<(&str, [u8; 32], ActionKind)>,
    ) -> Result<ActionSnapshot, ApiError> {
        if receipt.fence != *expected_fence
            || expected_action_id.is_some_and(|action_id| action_id != &receipt.action_id)
            || expected_submission.is_some_and(|(key, hash, kind)| {
                receipt.idempotency_key.as_str() != key
                    || receipt.canonical_request_hash != hash
                    || receipt.kind != kind
            })
        {
            return Err(ApiError::new(
                ErrorCode::PlacementMismatch,
                "worker returned a mismatched action receipt",
            ));
        }
        let snapshot = receipt.to_action_snapshot().map_err(|_| {
            ApiError::new(
                ErrorCode::Internal,
                "worker returned contradictory action facts",
            )
        })?;
        self.validate_current_fence(tenant_id, session_id, &receipt.fence)?;
        let identity = GatewayActionIdentity {
            idempotency_key: snapshot.request().idempotency_key().as_str().to_owned(),
            canonical_request_hash: *snapshot.request().canonical_request_hash().as_bytes(),
            kind: snapshot.request().kind(),
        };
        let key = (
            tenant_id.clone(),
            session_id.clone(),
            snapshot.action_id().clone(),
        );
        let mut identities = self.action_identities.lock().map_err(|_| {
            ApiError::new(
                ErrorCode::WorkerUnavailable,
                "gateway action identity state unavailable",
            )
        })?;
        if let Some(existing) = identities.get(&key) {
            if existing != &identity {
                return Err(ApiError::new(
                    ErrorCode::PlacementMismatch,
                    "worker action identity changed after acceptance",
                ));
            }
        } else {
            if identities.len() >= MAX_TRACKED_ACTION_IDENTITIES {
                return Err(ApiError::new(
                    ErrorCode::WorkerUnavailable,
                    "gateway action identity bound exceeded",
                ));
            }
            identities.insert(key, identity);
        }
        Ok(snapshot)
    }

    fn submit_action(
        &self,
        principal: &browserd_auth::AuthenticatedPrincipal,
        command: ActionSubmitCommand,
    ) -> Result<ApiResponse, ApiError> {
        let record = self.session_record(principal.tenant_id(), &command.session_id)?;
        if command.body.if_session_incarnation != record.fence.session_incarnation {
            return Err(ApiError::new(
                ErrorCode::GenerationMismatch,
                "session incarnation precondition failed",
            ));
        }
        let canonical = serde_json::to_value(&command.body)
            .map_err(|_| ApiError::new(ErrorCode::Internal, "action canonicalization failed"))?;
        let canonical_request_hash =
            *browserd_operations::CanonicalRequestHash::from_json(&canonical).as_bytes();
        let payload = serde_json::to_vec(&command.body)
            .map_err(|_| ApiError::new(ErrorCode::Internal, "action serialization failed"))?;
        let kind = if matches!(
            &command.body.action,
            ActionPayload::Snapshot
                | ActionPayload::GetText { .. }
                | ActionPayload::GetHtml { .. }
                | ActionPayload::GetUrl
                | ActionPayload::GetTitle
                | ActionPayload::GetAttribute { .. }
                | ActionPayload::GetProperties { .. }
                | ActionPayload::GetComputedStyle { .. }
                | ActionPayload::QueryAll { .. }
                | ActionPayload::ExtractTable { .. }
                | ActionPayload::Screenshot
                | ActionPayload::Pdf
                | ActionPayload::Scrape
                | ActionPayload::Checkpoint
        ) {
            ActionKind::ReadOnly
        } else {
            ActionKind::Mutating
        };
        let idempotency_key = command.idempotency_key.to_string();
        let receipt = match self
            .client
            .request(WorkerRpcRequest::SubmitAction {
                fence: record.fence.clone(),
                requester_principal_id: principal.principal_id().clone(),
                idempotency_key: idempotency_key.clone(),
                canonical_request_hash,
                kind,
                page_id: Some(command.body.page_id.clone()),
                payload,
                approval: None,
                now_unix_millis: current_unix_millis()?,
            })
            .map_err(|error| {
                worker_api_error_with_codes(
                    error,
                    ErrorCode::SessionNotFound,
                    ErrorCode::IdempotencyConflict,
                    ErrorCode::GlobalCapacityExceeded,
                )
            })? {
            WorkerRpcResponse::Action(receipt) => receipt,
            WorkerRpcResponse::Failure(failure) => {
                return Err(worker_api_error_with_codes(
                    WorkerRpcError::Remote(failure),
                    ErrorCode::SessionNotFound,
                    ErrorCode::IdempotencyConflict,
                    ErrorCode::GlobalCapacityExceeded,
                ));
            }
            _ => {
                return Err(ApiError::new(
                    ErrorCode::Internal,
                    "worker returned an unexpected action-submit response",
                ));
            }
        };
        self.action_snapshot(
            principal.tenant_id(),
            &command.session_id,
            &record.fence,
            receipt,
            None,
            Some((&idempotency_key, canonical_request_hash, kind)),
        )
        .map(ApiEnvelope::new)
        .map(ApiResponse::Action)
    }

    fn get_action(
        &self,
        principal: &browserd_auth::AuthenticatedPrincipal,
        command: ActionGetRequest,
    ) -> Result<ApiResponse, ApiError> {
        let record = self.session_record(principal.tenant_id(), &command.session_id)?;
        let receipt = match self
            .client
            .request(WorkerRpcRequest::GetAction {
                fence: record.fence.clone(),
                action_id: command.action_id.clone(),
            })
            .map_err(|error| {
                worker_api_error_with_codes(
                    error,
                    ErrorCode::SessionNotFound,
                    ErrorCode::ActionResolutionInvalid,
                    ErrorCode::GlobalCapacityExceeded,
                )
            })? {
            WorkerRpcResponse::Action(receipt) => receipt,
            WorkerRpcResponse::Failure(failure) => {
                return Err(worker_api_error_with_codes(
                    WorkerRpcError::Remote(failure),
                    ErrorCode::SessionNotFound,
                    ErrorCode::ActionResolutionInvalid,
                    ErrorCode::GlobalCapacityExceeded,
                ));
            }
            _ => {
                return Err(ApiError::new(
                    ErrorCode::Internal,
                    "worker returned an unexpected action response",
                ));
            }
        };
        self.action_snapshot(
            principal.tenant_id(),
            &command.session_id,
            &record.fence,
            receipt,
            Some(&command.action_id),
            None,
        )
        .map(ApiEnvelope::new)
        .map(ApiResponse::Action)
    }

    fn cancel_action(
        &self,
        principal: &browserd_auth::AuthenticatedPrincipal,
        command: ActionGetRequest,
    ) -> Result<ApiResponse, ApiError> {
        let record = self.session_record(principal.tenant_id(), &command.session_id)?;
        let receipt = match self
            .client
            .request(WorkerRpcRequest::CancelAction {
                fence: record.fence.clone(),
                action_id: command.action_id.clone(),
                now_unix_millis: current_unix_millis()?,
            })
            .map_err(|error| {
                worker_api_error_with_codes(
                    error,
                    ErrorCode::SessionNotFound,
                    ErrorCode::ActionResolutionInvalid,
                    ErrorCode::GlobalCapacityExceeded,
                )
            })? {
            WorkerRpcResponse::Action(receipt) => receipt,
            WorkerRpcResponse::Failure(failure) => {
                return Err(worker_api_error_with_codes(
                    WorkerRpcError::Remote(failure),
                    ErrorCode::SessionNotFound,
                    ErrorCode::ActionResolutionInvalid,
                    ErrorCode::GlobalCapacityExceeded,
                ));
            }
            _ => {
                return Err(ApiError::new(
                    ErrorCode::Internal,
                    "worker returned an unexpected action-cancel response",
                ));
            }
        };
        self.action_snapshot(
            principal.tenant_id(),
            &command.session_id,
            &record.fence,
            receipt,
            Some(&command.action_id),
            None,
        )
        .map(ApiEnvelope::new)
        .map(ApiResponse::Action)
    }

    fn resolve_action(
        &self,
        principal: &browserd_auth::AuthenticatedPrincipal,
        command: ActionResolveRequest,
    ) -> Result<ApiResponse, ApiError> {
        if command.body.note.is_some() {
            return Err(ApiError::new(
                ErrorCode::InvalidRequest,
                "worker RPC does not support a separate resolution note",
            ));
        }
        let record = self.session_record(principal.tenant_id(), &command.session_id)?;
        let resolution = command.body.resolution.into();
        let now_unix_millis = current_unix_millis()?;
        let receipt = match self
            .client
            .request(WorkerRpcRequest::ResolveAction {
                fence: record.fence.clone(),
                action_id: command.action_id.clone(),
                resolution,
                resolved_by: principal.principal_id().clone(),
                basis: command.body.basis.clone(),
                now_unix_millis,
            })
            .map_err(|error| {
                worker_api_error_with_codes(
                    error,
                    ErrorCode::SessionNotFound,
                    ErrorCode::ActionResolutionInvalid,
                    ErrorCode::GlobalCapacityExceeded,
                )
            })? {
            WorkerRpcResponse::Action(receipt) => receipt,
            WorkerRpcResponse::Failure(failure) => {
                return Err(worker_api_error_with_codes(
                    WorkerRpcError::Remote(failure),
                    ErrorCode::SessionNotFound,
                    ErrorCode::ActionResolutionInvalid,
                    ErrorCode::GlobalCapacityExceeded,
                ));
            }
            _ => {
                return Err(ApiError::new(
                    ErrorCode::Internal,
                    "worker returned an unexpected action-resolution response",
                ));
            }
        };
        let snapshot = self.action_snapshot(
            principal.tenant_id(),
            &command.session_id,
            &record.fence,
            receipt,
            Some(&command.action_id),
            None,
        )?;
        if snapshot.resolution().is_none_or(|annotation| {
            annotation.kind() != resolution
                || annotation.resolved_by() != principal.principal_id()
                || annotation.resolved_at_millis() != now_unix_millis
                || annotation.basis() != command.body.basis
        }) {
            return Err(ApiError::new(
                ErrorCode::ActionResolutionInvalid,
                "worker returned a mismatched action resolution",
            ));
        }
        Ok(ApiResponse::Action(ApiEnvelope::new(snapshot)))
    }
}

impl<C> GatewayWorkerRuntime<C>
where
    C: GatewayWorkerClient,
{
    fn artifact_metadata(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        expected_fence: &WorkerSessionFence,
        expected_artifact_id: &browserd_core::ArtifactId,
        receipt: WorkerArtifactReceipt,
    ) -> Result<ArtifactMetadata, ApiError> {
        if receipt.fence != *expected_fence
            || &receipt.artifact_id != expected_artifact_id
            || receipt.object_generation == [0; 32]
        {
            return Err(ApiError::new(
                ErrorCode::PlacementMismatch,
                "worker returned a mismatched artifact receipt",
            ));
        }
        let source = match receipt.source {
            WorkerArtifactSource::ClientUpload => ArtifactContentSource::ClientUpload,
            WorkerArtifactSource::BrowserDownload => ArtifactContentSource::BrowserDownload,
            WorkerArtifactSource::Generated => ArtifactContentSource::Generated,
        };
        let content = ArtifactContentMetadata::new(
            receipt.size_bytes,
            ArtifactChecksum::new(receipt.checksum_sha256),
            receipt.content_type,
            source,
            receipt.origin,
        )
        .map_err(|_| {
            ApiError::new(
                ErrorCode::Internal,
                "worker returned invalid artifact metadata",
            )
        })?;
        let state = match receipt.state {
            WorkerArtifactState::Uploading => ArtifactState::Uploading,
            WorkerArtifactState::Stored => ArtifactState::Stored,
            WorkerArtifactState::Scanning => ArtifactState::Scanning,
            WorkerArtifactState::Available => ArtifactState::Available,
            WorkerArtifactState::Quarantined => ArtifactState::Quarantined,
            WorkerArtifactState::Rejected => ArtifactState::Rejected,
            WorkerArtifactState::Generating => ArtifactState::Generating,
            WorkerArtifactState::Finalizing => ArtifactState::Finalizing,
            WorkerArtifactState::Failed => ArtifactState::Failed,
            WorkerArtifactState::Deleting => ArtifactState::Deleting,
            WorkerArtifactState::Deleted => ArtifactState::Deleted,
        };
        self.validate_current_fence(tenant_id, session_id, &receipt.fence)?;
        Ok(ArtifactMetadata {
            key: ArtifactKey::new(tenant_id.clone(), session_id.clone(), receipt.artifact_id),
            state,
            checksum_sha256: Some(*content.checksum().as_bytes()),
            size_bytes: Some(content.size_bytes()),
            content_type: Some(content.content_type().to_owned()),
            source_origin: Some(content.origin().to_owned()),
        })
    }

    fn get_artifact(
        &self,
        principal: &browserd_auth::AuthenticatedPrincipal,
        command: ArtifactRequest,
    ) -> Result<ApiResponse, ApiError> {
        let record = self.session_record(principal.tenant_id(), &command.session_id)?;
        let receipt = match self
            .client
            .request(WorkerRpcRequest::GetArtifact {
                fence: record.fence.clone(),
                artifact_id: command.artifact_id.clone(),
            })
            .map_err(|error| {
                worker_api_error_with_codes(
                    error,
                    ErrorCode::SessionNotFound,
                    ErrorCode::PlacementMismatch,
                    ErrorCode::GlobalCapacityExceeded,
                )
            })? {
            WorkerRpcResponse::Artifact(receipt) => receipt,
            WorkerRpcResponse::Failure(failure) => {
                return Err(worker_api_error_with_codes(
                    WorkerRpcError::Remote(failure),
                    ErrorCode::SessionNotFound,
                    ErrorCode::PlacementMismatch,
                    ErrorCode::GlobalCapacityExceeded,
                ));
            }
            _ => {
                return Err(ApiError::new(
                    ErrorCode::Internal,
                    "worker returned an unexpected artifact response",
                ));
            }
        };
        self.artifact_metadata(
            principal.tenant_id(),
            &command.session_id,
            &record.fence,
            &command.artifact_id,
            receipt,
        )
        .map(ApiEnvelope::new)
        .map(ApiResponse::Artifact)
    }
}

impl<C> GatewayWorkerRuntime<C>
where
    C: GatewayWorkerClient,
{
    fn active_approval_routes(
        &self,
        tenant_id: &TenantId,
    ) -> Result<Vec<GatewaySessionRecord>, ApiError> {
        let sessions = self.sessions.lock().map_err(|_| {
            ApiError::new(ErrorCode::WorkerUnavailable, "session state unavailable")
        })?;
        let mut routes = Vec::new();
        for ((stored_tenant, _), record) in sessions.iter() {
            if stored_tenant == tenant_id
                && !matches!(
                    record.resource.lifecycle,
                    SessionLifecycle::Closed | SessionLifecycle::Failed
                )
            {
                if routes.len() == MAX_APPROVAL_ROUTE_SCAN {
                    return Err(ApiError::new(
                        ErrorCode::WorkerUnavailable,
                        "approval route scan exceeded the gateway bound",
                    ));
                }
                routes.push(record.clone());
            }
        }
        Ok(routes)
    }

    fn approval_resource(
        &self,
        tenant_id: &TenantId,
        expected_fence: &WorkerSessionFence,
        expected_approval_id: Option<&ApprovalId>,
        receipt: &WorkerApprovalReceipt,
    ) -> Result<ApprovalResource, ApiError> {
        if receipt.fence != *expected_fence
            || expected_approval_id.is_some_and(|approval_id| approval_id != &receipt.approval_id)
        {
            return Err(ApiError::new(
                ErrorCode::PlacementMismatch,
                "worker returned a mismatched approval receipt",
            ));
        }
        let proposal = receipt.canonical_proposal().map_err(|_| {
            ApiError::new(
                ErrorCode::ApprovalStale,
                "worker returned a stale approval proposal",
            )
        })?;
        self.validate_current_fence(tenant_id, &receipt.fence.session_id, &receipt.fence)?;
        let state = match &receipt.state {
            WorkerApprovalState::Pending => browserd_policy::ApprovalState::Pending,
            WorkerApprovalState::Approved { by } => {
                browserd_policy::ApprovalState::Approved { by: by.clone() }
            }
            WorkerApprovalState::Denied { by } => {
                browserd_policy::ApprovalState::Denied { by: by.clone() }
            }
            WorkerApprovalState::Expired => browserd_policy::ApprovalState::Expired,
        };
        Ok(ApprovalResource {
            approval_id: *receipt.approval_id.as_uuid(),
            tenant_id: tenant_id.clone(),
            session_id: receipt.fence.session_id.clone(),
            action_id: receipt.action_id.clone(),
            state,
            proposal,
        })
    }

    fn route_approval(
        &self,
        tenant_id: &TenantId,
        approval_id: &ApprovalId,
    ) -> Result<
        (
            GatewaySessionRecord,
            WorkerApprovalReceipt,
            ApprovalResource,
        ),
        ApiError,
    > {
        let routes = self.active_approval_routes(tenant_id)?;
        let mut found = None;
        for route in routes {
            let response = match self.client.request(WorkerRpcRequest::GetApproval {
                fence: route.fence.clone(),
                approval_id: approval_id.clone(),
            }) {
                Ok(response) => response,
                Err(WorkerRpcError::Remote(failure))
                    if failure.code == WorkerRpcFailureCode::NotFound =>
                {
                    continue;
                }
                Err(error) => {
                    return Err(worker_api_error_with_codes(
                        error,
                        ErrorCode::OperationNotFound,
                        ErrorCode::ApprovalStale,
                        ErrorCode::GlobalCapacityExceeded,
                    ));
                }
            };
            let receipt = match response {
                WorkerRpcResponse::Approval(receipt) => receipt,
                WorkerRpcResponse::Failure(failure)
                    if failure.code == WorkerRpcFailureCode::NotFound =>
                {
                    continue;
                }
                WorkerRpcResponse::Failure(failure) => {
                    return Err(worker_api_error_with_codes(
                        WorkerRpcError::Remote(failure),
                        ErrorCode::OperationNotFound,
                        ErrorCode::ApprovalStale,
                        ErrorCode::GlobalCapacityExceeded,
                    ));
                }
                _ => {
                    return Err(ApiError::new(
                        ErrorCode::Internal,
                        "worker returned an unexpected approval response",
                    ));
                }
            };
            let resource =
                self.approval_resource(tenant_id, &route.fence, Some(approval_id), &receipt)?;
            if found.is_some() {
                return Err(ApiError::new(
                    ErrorCode::PlacementMismatch,
                    "approval ID is bound to multiple active session routes",
                ));
            }
            found = Some((route, receipt, resource));
        }
        found.ok_or_else(|| ApiError::new(ErrorCode::OperationNotFound, "approval not found"))
    }

    fn list_approvals(
        &self,
        principal: &browserd_auth::AuthenticatedPrincipal,
        query: ApprovalListQuery,
    ) -> Result<ApiResponse, ApiError> {
        query.validate()?;
        let routes = if let Some(session_id) = &query.session_id {
            vec![self.session_record(principal.tenant_id(), session_id)?]
        } else {
            self.active_approval_routes(principal.tenant_id())?
        };
        let mut seen = HashSet::new();
        let catalog = ApprovalCatalog::default();
        let mut receipt_count = 0_usize;
        for route in routes {
            let receipts = match self
                .client
                .request(WorkerRpcRequest::ListApprovals {
                    fence: route.fence.clone(),
                })
                .map_err(|error| {
                    worker_api_error_with_codes(
                        error,
                        ErrorCode::OperationNotFound,
                        ErrorCode::ApprovalStale,
                        ErrorCode::GlobalCapacityExceeded,
                    )
                })? {
                WorkerRpcResponse::Approvals(receipts) => receipts,
                WorkerRpcResponse::Failure(failure) => {
                    return Err(worker_api_error_with_codes(
                        WorkerRpcError::Remote(failure),
                        ErrorCode::OperationNotFound,
                        ErrorCode::ApprovalStale,
                        ErrorCode::GlobalCapacityExceeded,
                    ));
                }
                _ => {
                    return Err(ApiError::new(
                        ErrorCode::Internal,
                        "worker returned an unexpected approval-list response",
                    ));
                }
            };
            receipt_count = receipt_count.checked_add(receipts.len()).ok_or_else(|| {
                ApiError::new(
                    ErrorCode::GlobalCapacityExceeded,
                    "approval result bound overflowed",
                )
            })?;
            if receipt_count > MAX_APPROVAL_RECEIPTS {
                return Err(ApiError::new(
                    ErrorCode::GlobalCapacityExceeded,
                    "approval result set exceeded the gateway bound",
                ));
            }
            for receipt in receipts {
                if !seen.insert(receipt.approval_id.clone()) {
                    return Err(ApiError::new(
                        ErrorCode::PlacementMismatch,
                        "approval ID is duplicated in worker state",
                    ));
                }
                catalog.upsert(self.approval_resource(
                    principal.tenant_id(),
                    &route.fence,
                    None,
                    &receipt,
                )?)?;
            }
        }
        catalog
            .list(principal.tenant_id(), &query)
            .map(ApiEnvelope::new)
            .map(ApiResponse::Approvals)
    }

    fn get_approval(
        &self,
        principal: &browserd_auth::AuthenticatedPrincipal,
        approval_id: Uuid,
    ) -> Result<ApiResponse, ApiError> {
        let approval_id = public_approval_id(approval_id)?;
        let (_, _, resource) = self.route_approval(principal.tenant_id(), &approval_id)?;
        Ok(ApiResponse::Approval(ApiEnvelope::new(resource)))
    }

    fn decide_approval(
        &self,
        principal: &browserd_auth::AuthenticatedPrincipal,
        approval_id: Uuid,
        body: ApprovalDecisionBody,
    ) -> Result<ApiResponse, ApiError> {
        let approval_id = public_approval_id(approval_id)?;
        let (route, existing, _) = self.route_approval(principal.tenant_id(), &approval_id)?;
        let decision = match body.decision {
            ApprovalDecisionRequest::Approve => WorkerApprovalDecision::Approve,
            ApprovalDecisionRequest::Deny => WorkerApprovalDecision::Deny,
        };
        let receipt = match self
            .client
            .request(WorkerRpcRequest::DecideApproval {
                fence: route.fence.clone(),
                approval_id: approval_id.clone(),
                decision,
                principal_id: principal.principal_id().clone(),
                reason: body.reason,
                now_unix_millis: current_unix_millis()?,
            })
            .map_err(|error| {
                worker_api_error_with_codes(
                    error,
                    ErrorCode::OperationNotFound,
                    ErrorCode::ApprovalStale,
                    ErrorCode::GlobalCapacityExceeded,
                )
            })? {
            WorkerRpcResponse::Approval(receipt) => receipt,
            WorkerRpcResponse::Failure(failure) => {
                return Err(worker_api_error_with_codes(
                    WorkerRpcError::Remote(failure),
                    ErrorCode::OperationNotFound,
                    ErrorCode::ApprovalStale,
                    ErrorCode::GlobalCapacityExceeded,
                ));
            }
            _ => {
                return Err(ApiError::new(
                    ErrorCode::Internal,
                    "worker returned an unexpected approval-decision response",
                ));
            }
        };
        if receipt.action_id != existing.action_id
            || receipt.proposal != existing.proposal
            || receipt.proposal_hash != existing.proposal_hash
            || !match (&decision, &receipt.state) {
                (WorkerApprovalDecision::Approve, WorkerApprovalState::Approved { by })
                | (WorkerApprovalDecision::Deny, WorkerApprovalState::Denied { by }) => {
                    by == principal.principal_id()
                }
                _ => false,
            }
        {
            return Err(ApiError::new(
                ErrorCode::ApprovalStale,
                "worker returned a mismatched approval decision",
            ));
        }
        self.approval_resource(
            principal.tenant_id(),
            &route.fence,
            Some(&approval_id),
            &receipt,
        )
        .map(ApiEnvelope::new)
        .map(ApiResponse::Approval)
    }
}

impl<C> RuntimeApiBackend for GatewayWorkerRuntime<C>
where
    C: GatewayWorkerClient,
{
    fn create_session(
        &self,
        authority: &CreateAuthority,
        dispatch: &SessionCreateDispatch,
        request: &SessionCreateRequest,
    ) -> RuntimeCreateResult {
        let now_unix_millis = match current_unix_millis() {
            Ok(now_unix_millis) => now_unix_millis,
            Err(error) => return RuntimeCreateResult::ConfirmedFailure(error),
        };
        let worker_request = WorkerCreateSessionRequest {
            operation_id: dispatch.operation_id().clone(),
            tenant_id: authority.tenant_id().clone(),
            idempotency_key: hex::encode(dispatch.downstream_dedupe_key().as_bytes()),
            canonical_request_hash: *dispatch.canonical_request_hash(),
            expected_worker_epoch: self.placement.worker_epoch,
            placement_version: self.placement.placement_version,
            session_incarnation: 1,
            requested_isolation: match request.isolation {
                IsolationRequest::SharedContext => WorkerIsolationProfile::SharedContext,
                IsolationRequest::TenantDedicatedShard => {
                    WorkerIsolationProfile::TenantDedicatedShard
                }
                IsolationRequest::DedicatedProcess => WorkerIsolationProfile::DedicatedProcess,
                IsolationRequest::DedicatedWorker => WorkerIsolationProfile::DedicatedWorker,
            },
            now_unix_millis,
        };
        let receipt = match self.client.create_session(worker_request) {
            Ok(receipt) => receipt,
            Err(error) => {
                let outcome_unknown = matches!(
                    &error,
                    WorkerRpcError::Protocol
                        | WorkerRpcError::Timeout
                        | WorkerRpcError::Runtime
                        | WorkerRpcError::Io(_)
                ) || matches!(
                    &error,
                    WorkerRpcError::Remote(failure)
                        if matches!(
                            failure.code,
                            WorkerRpcFailureCode::Timeout | WorkerRpcFailureCode::Internal
                        )
                );
                let error = worker_api_error(error);
                return if outcome_unknown {
                    RuntimeCreateResult::OutcomeUnknown(error)
                } else {
                    RuntimeCreateResult::ConfirmedFailure(error)
                };
            }
        };
        if receipt.operation_id != *dispatch.operation_id()
            || receipt.tenant_id != *authority.tenant_id()
            || receipt.worker_epoch != self.placement.worker_epoch
            || receipt.placement_version != self.placement.placement_version
            || receipt.session_incarnation != 1
        {
            return RuntimeCreateResult::OutcomeUnknown(ApiError::new(
                ErrorCode::PlacementMismatch,
                "worker returned a mismatched creation receipt",
            ));
        }
        let resource = SessionResource {
            id: receipt.session_id.clone(),
            lifecycle: SessionLifecycle::Ready,
            incarnation: receipt.session_incarnation,
            requested_isolation: request.isolation.into(),
            effective_isolation: match receipt.effective_isolation {
                WorkerIsolationProfile::SharedContext => IsolationProfile::SharedContext,
                WorkerIsolationProfile::TenantDedicatedShard => {
                    IsolationProfile::TenantDedicatedShard
                }
                WorkerIsolationProfile::DedicatedProcess => IsolationProfile::DedicatedProcess,
                WorkerIsolationProfile::DedicatedWorker => IsolationProfile::DedicatedWorker,
            },
            metadata: request.metadata.clone(),
        };
        let fence = WorkerSessionFence {
            tenant_id: receipt.tenant_id,
            session_id: receipt.session_id,
            worker_epoch: receipt.worker_epoch,
            placement_version: receipt.placement_version,
            session_incarnation: receipt.session_incarnation,
        };
        {
            let mut sessions = match self.sessions.lock() {
                Ok(sessions) => sessions,
                Err(_) => {
                    return RuntimeCreateResult::OutcomeUnknown(ApiError::new(
                        ErrorCode::WorkerUnavailable,
                        "session state unavailable",
                    ));
                }
            };
            let key = (authority.tenant_id().clone(), resource.id.clone());
            if sessions
                .get(&key)
                .is_some_and(|existing| existing.fence != fence)
            {
                return RuntimeCreateResult::OutcomeUnknown(ApiError::new(
                    ErrorCode::PlacementMismatch,
                    "session ID is already bound to another worker fence",
                ));
            }
            sessions.insert(
                key,
                GatewaySessionRecord {
                    fence,
                    resource: resource.clone(),
                },
            );
        }
        if let Err(error) = self
            .catalog
            .upsert(authority.tenant_id().clone(), resource.clone())
        {
            return RuntimeCreateResult::OutcomeUnknown(error);
        }
        RuntimeCreateResult::Succeeded(resource)
    }

    fn execute_runtime(
        &self,
        principal: &browserd_auth::AuthenticatedPrincipal,
        request: ApiRequest,
    ) -> Result<ApiResponse, ApiError> {
        match request {
            ApiRequest::ListSessions(query) => self
                .catalog
                .list(principal.tenant_id(), &query)
                .map(ApiEnvelope::new)
                .map(ApiResponse::Sessions),
            ApiRequest::GetSession(session_id) => {
                let record = self
                    .sessions
                    .lock()
                    .map_err(|_| {
                        ApiError::new(ErrorCode::WorkerUnavailable, "session state unavailable")
                    })?
                    .get(&(principal.tenant_id().clone(), session_id.clone()))
                    .cloned()
                    .ok_or_else(|| {
                        ApiError::new(ErrorCode::SessionNotFound, "session not found")
                    })?;
                let receipt = match self
                    .client
                    .request(WorkerRpcRequest::GetSession {
                        fence: record.fence.clone(),
                    })
                    .map_err(worker_api_error)?
                {
                    WorkerRpcResponse::Session(receipt) => receipt,
                    WorkerRpcResponse::Failure(failure) => {
                        return Err(worker_api_error(WorkerRpcError::Remote(failure)));
                    }
                    _ => {
                        return Err(ApiError::new(
                            ErrorCode::Internal,
                            "worker returned an unexpected session response",
                        ));
                    }
                };
                if receipt.fence != record.fence {
                    return Err(ApiError::new(
                        ErrorCode::PlacementMismatch,
                        "worker returned a mismatched session fence",
                    ));
                }
                let mut resource = record.resource;
                resource.lifecycle = match receipt.lifecycle {
                    WorkerSessionLifecycle::Creating => SessionLifecycle::Creating,
                    WorkerSessionLifecycle::Ready => SessionLifecycle::Ready,
                    WorkerSessionLifecycle::Closing => SessionLifecycle::Closing,
                    WorkerSessionLifecycle::Closed => SessionLifecycle::Closed,
                    WorkerSessionLifecycle::Failed => SessionLifecycle::Failed,
                };
                {
                    let mut sessions = self.sessions.lock().map_err(|_| {
                        ApiError::new(ErrorCode::WorkerUnavailable, "session state unavailable")
                    })?;
                    let current = sessions
                        .get_mut(&(principal.tenant_id().clone(), session_id.clone()))
                        .filter(|current| current.fence == receipt.fence)
                        .ok_or_else(|| {
                            ApiError::new(
                                ErrorCode::PlacementMismatch,
                                "session placement changed during worker lookup",
                            )
                        })?;
                    let advances = matches!(
                        (current.resource.lifecycle, resource.lifecycle),
                        (SessionLifecycle::Creating, _)
                            | (
                                SessionLifecycle::Ready,
                                SessionLifecycle::Ready
                                    | SessionLifecycle::Closing
                                    | SessionLifecycle::Closed
                                    | SessionLifecycle::Failed
                            )
                            | (
                                SessionLifecycle::Closing,
                                SessionLifecycle::Closing
                                    | SessionLifecycle::Closed
                                    | SessionLifecycle::Failed
                            )
                            | (SessionLifecycle::Closed, SessionLifecycle::Closed)
                            | (SessionLifecycle::Failed, SessionLifecycle::Failed)
                    );
                    if advances {
                        current.resource = resource.clone();
                    } else {
                        resource = current.resource.clone();
                    }
                }
                if matches!(
                    resource.lifecycle,
                    SessionLifecycle::Closed | SessionLifecycle::Failed
                ) {
                    self.action_identities
                        .lock()
                        .map_err(|_| {
                            ApiError::new(
                                ErrorCode::WorkerUnavailable,
                                "gateway action identity state unavailable",
                            )
                        })?
                        .retain(|(tenant_id, stored_session_id, _), _| {
                            tenant_id != principal.tenant_id() || stored_session_id != &session_id
                        });
                }
                self.catalog
                    .upsert(principal.tenant_id().clone(), resource.clone())?;
                Ok(ApiResponse::Session(ApiEnvelope::new(resource)))
            }
            ApiRequest::DeleteSession(session_id) => {
                let record = self
                    .sessions
                    .lock()
                    .map_err(|_| {
                        ApiError::new(ErrorCode::WorkerUnavailable, "session state unavailable")
                    })?
                    .get(&(principal.tenant_id().clone(), session_id.clone()))
                    .cloned()
                    .ok_or_else(|| {
                        ApiError::new(ErrorCode::SessionNotFound, "session not found")
                    })?;
                let receipt = match self
                    .client
                    .request(WorkerRpcRequest::CloseSession {
                        fence: record.fence.clone(),
                        now_unix_millis: current_unix_millis()?,
                    })
                    .map_err(worker_api_error)?
                {
                    WorkerRpcResponse::SessionClosed(receipt) => receipt,
                    WorkerRpcResponse::Failure(failure) => {
                        return Err(worker_api_error(WorkerRpcError::Remote(failure)));
                    }
                    _ => {
                        return Err(ApiError::new(
                            ErrorCode::Internal,
                            "worker returned an unexpected close response",
                        ));
                    }
                };
                if receipt.fence != record.fence {
                    return Err(ApiError::new(
                        ErrorCode::PlacementMismatch,
                        "worker returned a mismatched close fence",
                    ));
                }
                let mut resource = record.resource;
                resource.lifecycle = match receipt.lifecycle {
                    WorkerSessionLifecycle::Creating => SessionLifecycle::Creating,
                    WorkerSessionLifecycle::Ready => SessionLifecycle::Ready,
                    WorkerSessionLifecycle::Closing => SessionLifecycle::Closing,
                    WorkerSessionLifecycle::Closed => SessionLifecycle::Closed,
                    WorkerSessionLifecycle::Failed => SessionLifecycle::Failed,
                };
                {
                    let mut sessions = self.sessions.lock().map_err(|_| {
                        ApiError::new(ErrorCode::WorkerUnavailable, "session state unavailable")
                    })?;
                    let current = sessions
                        .get_mut(&(principal.tenant_id().clone(), session_id.clone()))
                        .filter(|current| current.fence == receipt.fence)
                        .ok_or_else(|| {
                            ApiError::new(
                                ErrorCode::PlacementMismatch,
                                "session placement changed during worker close",
                            )
                        })?;
                    let advances = matches!(
                        (current.resource.lifecycle, resource.lifecycle),
                        (SessionLifecycle::Creating, _)
                            | (
                                SessionLifecycle::Ready,
                                SessionLifecycle::Ready
                                    | SessionLifecycle::Closing
                                    | SessionLifecycle::Closed
                                    | SessionLifecycle::Failed
                            )
                            | (
                                SessionLifecycle::Closing,
                                SessionLifecycle::Closing
                                    | SessionLifecycle::Closed
                                    | SessionLifecycle::Failed
                            )
                            | (SessionLifecycle::Closed, SessionLifecycle::Closed)
                            | (SessionLifecycle::Failed, SessionLifecycle::Failed)
                    );
                    if advances {
                        current.resource = resource.clone();
                    } else {
                        resource = current.resource.clone();
                    }
                }
                if matches!(
                    resource.lifecycle,
                    SessionLifecycle::Closed | SessionLifecycle::Failed
                ) {
                    self.action_identities
                        .lock()
                        .map_err(|_| {
                            ApiError::new(
                                ErrorCode::WorkerUnavailable,
                                "gateway action identity state unavailable",
                            )
                        })?
                        .retain(|(tenant_id, stored_session_id, _), _| {
                            tenant_id != principal.tenant_id() || stored_session_id != &session_id
                        });
                }
                self.catalog
                    .upsert(principal.tenant_id().clone(), resource.clone())?;
                Ok(ApiResponse::SessionClosed(ApiEnvelope::new(resource)))
            }
            ApiRequest::ListPages(command) => self.list_pages(principal, command),
            ApiRequest::CreatePage(command) => self.create_page(principal, command),
            ApiRequest::DeletePage(command) => self.delete_page(principal, command),
            ApiRequest::ActivatePage(command) => self.activate_page(principal, command),
            ApiRequest::SubmitAction(command) => self.submit_action(principal, command),
            ApiRequest::GetAction(command) => self.get_action(principal, command),
            ApiRequest::CancelAction(command) => self.cancel_action(principal, command),
            ApiRequest::ResolveAction(command) => self.resolve_action(principal, command),
            ApiRequest::GetArtifact(command) => self.get_artifact(principal, command),
            ApiRequest::ListApprovals(query) => self.list_approvals(principal, query),
            ApiRequest::GetApproval(approval_id) => self.get_approval(principal, approval_id),
            ApiRequest::DecideApproval { approval_id, body } => {
                self.decide_approval(principal, approval_id, body)
            }
            _ => Err(ApiError::new(
                ErrorCode::WorkerUnavailable,
                "runtime endpoint is not available",
            )),
        }
    }
}
