//! Production-facing gateway adapters that are independent of HTTP routing.

#![forbid(unsafe_code)]

mod action_custody;
mod action_custody_catchup;
mod action_recovery;
mod action_retention;
pub use action_retention::action_retention_limits_from_lookup;
mod artifact_downloads;
mod artifact_retention;
mod fleet;
mod fleet_config;
pub use fleet::{GatewayFleetInventory, GatewayFleetPass, GatewayFleetPeer};
pub use fleet_config::GatewayFleetConfig;
pub mod config;
mod notifications;
#[cfg(test)]
mod session_cache_tests;
mod session_directory;
mod session_loss;
mod viewer;
pub use viewer::{GatewayViewer, GatewayViewerError};
mod webhooks;
pub use webhooks::{GatewayWebhookDelivery, WebhookDeliveryPass};
mod webhook_keys;
mod webhook_transport;
pub use webhook_keys::{WebhookMasterKeyRing, load_webhook_signing_keys};
pub use webhook_transport::{
    ReqwestWebhookTransport, WEBHOOK_EVENT_ID_HEADER, WEBHOOK_KEY_ID_HEADER,
    WEBHOOK_REPLAY_WINDOW_SECONDS, WEBHOOK_SIGNATURE_HEADER, WEBHOOK_TIMESTAMP_HEADER,
    WebhookTransport, verify_webhook_signature,
};

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use browserd_actions::{
    ActionDeliveryEvidence, ActionKind, ActionSnapshot, ActionSnapshotFacts, ApprovalDecision,
    CanonicalRequestHash as ActionCanonicalRequestHash, DispatchId, IdempotencyKey,
    KnownFailureReason, OutcomeUnknownReason, ResolutionAnnotation, TerminalDetail, TransportLoss,
};
use browserd_api::{
    ActionGetRequest, ActionPayload, ActionResolveRequest, ActionSubmitCommand, ApiEnvelope,
    ApiError, ApiRequest, ApiResponse, ApprovalCatalog, ApprovalDecisionBody,
    ApprovalDecisionRequest, ApprovalListQuery, ApprovalResource, ArtifactListPage,
    ArtifactListRequest, ArtifactMetadata, ArtifactRequest, CreateAuthority, IsolationRequest,
    PageActivateRequest, PageCreateRequest, PageDeleteRequest, PageListRequest, PageResource,
    RuntimeApiBackend, RuntimeCreateResult, SessionCatalog, SessionCreateDispatch,
    SessionCreateRequest, SessionResource, WaitCondition as ApiWaitCondition,
    WaitUntil as ApiWaitUntil, public_approval_id,
};
use browserd_artifacts::{
    ArtifactChecksum, ArtifactContentMetadata, ArtifactContentSource, ArtifactKey, ArtifactState,
};
use browserd_auth::{AuthConfig, RevocationRegistry, ServiceTokenVerifier, VerificationKeySet};
use browserd_coordination::{
    ClaimGatewayAction, CoordinationActorConfig, DirectoryFence, EventOutboxBlockingClient,
    GatewayActionBlockingClient, GatewayActionClaimOutcome, GatewayActionCoordination,
    GatewayActionCoordinationError, GatewayActionPlacement, GatewayActionRecoveryCursor,
    GatewayActionSnapshot, GatewayActionSubmissionLease, GatewayEventScanCursor,
    MemoryGatewayActionStore,
};
use browserd_core::{
    ActionId, ApprovalId, ErrorCode, IsolationProfile, SessionId, SessionLifecycle, TenantId,
    WorkerId,
};
use browserd_http::{AuthenticationError, Authenticator, Readiness};
use browserd_worker::{
    PendingWorkerRpc, WORKER_SESSION_OPTIONS_VERSION, WorkerActionCommand,
    WorkerActionExecutionTimeout, WorkerActionReceipt, WorkerApprovalDecision,
    WorkerApprovalReceipt, WorkerApprovalState, WorkerArtifactReceipt, WorkerArtifactSource,
    WorkerArtifactState, WorkerCreateSessionReceipt, WorkerCreateSessionRequest,
    WorkerIsolationProfile, WorkerNavigateWaitUntil, WorkerPageReceipt, WorkerRpcBlockingClient,
    WorkerRpcCompletionError, WorkerRpcEnqueueError, WorkerRpcError, WorkerRpcFailureCode,
    WorkerRpcRequest, WorkerRpcResponse, WorkerSessionFence, WorkerSessionLifecycle,
    WorkerSessionOptionsV1, WorkerViewport, WorkerWaitCondition,
};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use jsonwebtoken::Algorithm;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayConfigurationError {
    InvalidAuthentication,
    InvalidViewerPolicy,
    InvalidWorkerPlacement,
    ActionCoordinationUnavailable,
    InvalidActionRetention(&'static str),
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

/// Turns a stream of dependency probe outcomes into a stable readiness bit with hysteresis.
///
/// A single transient probe failure does not flip a ready dependency to unready; it takes
/// `unhealthy_threshold` consecutive failures. Recovery takes `healthy_threshold` consecutive
/// successes. This keeps advertised readiness from flapping on an isolated error while still
/// failing closed on a sustained outage, so a dependency that dies after startup is reflected
/// instead of remaining stuck ready (BRD-014). The counters saturate, so a long healthy or
/// unhealthy run never overflows.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DependencyHealthGate {
    healthy_threshold: u32,
    unhealthy_threshold: u32,
    consecutive_successes: u32,
    consecutive_failures: u32,
    ready: bool,
}

impl DependencyHealthGate {
    /// Creates a gate. Thresholds below one are clamped to one so the gate can always move.
    #[must_use]
    pub fn new(healthy_threshold: u32, unhealthy_threshold: u32, initially_ready: bool) -> Self {
        Self {
            healthy_threshold: healthy_threshold.max(1),
            unhealthy_threshold: unhealthy_threshold.max(1),
            consecutive_successes: 0,
            consecutive_failures: 0,
            ready: initially_ready,
        }
    }

    /// Records one probe outcome and returns the (possibly updated) readiness.
    pub fn record(&mut self, healthy: bool) -> bool {
        if healthy {
            self.consecutive_failures = 0;
            self.consecutive_successes = self.consecutive_successes.saturating_add(1);
            if !self.ready && self.consecutive_successes >= self.healthy_threshold {
                self.ready = true;
            }
        } else {
            self.consecutive_successes = 0;
            self.consecutive_failures = self.consecutive_failures.saturating_add(1);
            if self.ready && self.consecutive_failures >= self.unhealthy_threshold {
                self.ready = false;
            }
        }
        self.ready
    }

    /// The current readiness the gate advertises.
    #[must_use]
    pub const fn ready(&self) -> bool {
        self.ready
    }
}

pub trait GatewayWorkerPending: Send {
    fn wait(self) -> Result<WorkerRpcResponse, WorkerRpcCompletionError>;
}

impl GatewayWorkerPending for PendingWorkerRpc {
    fn wait(self) -> Result<WorkerRpcResponse, WorkerRpcCompletionError> {
        PendingWorkerRpc::wait(self)
    }
}

pub trait GatewayWorkerClient: Send + Sync + 'static {
    type PendingAction: GatewayWorkerPending;

    fn create_session(
        &self,
        request: WorkerCreateSessionRequest,
    ) -> Result<WorkerCreateSessionReceipt, WorkerRpcError>;

    fn request(&self, request: WorkerRpcRequest) -> Result<WorkerRpcResponse, WorkerRpcError>;

    fn enqueue_action(
        &self,
        request: WorkerRpcRequest,
    ) -> Result<Self::PendingAction, WorkerRpcEnqueueError>;
}

impl GatewayWorkerClient for WorkerRpcBlockingClient {
    type PendingAction = PendingWorkerRpc;

    fn create_session(
        &self,
        request: WorkerCreateSessionRequest,
    ) -> Result<WorkerCreateSessionReceipt, WorkerRpcError> {
        WorkerRpcBlockingClient::create_session(self, request)
    }

    fn request(&self, request: WorkerRpcRequest) -> Result<WorkerRpcResponse, WorkerRpcError> {
        self.request_blocking(request)
    }

    fn enqueue_action(
        &self,
        request: WorkerRpcRequest,
    ) -> Result<Self::PendingAction, WorkerRpcEnqueueError> {
        self.enqueue(request)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayWorkerPlacement {
    worker_id: WorkerId,
    worker_epoch: u64,
    placement_version: u64,
    directory_revision: u64,
}

impl GatewayWorkerPlacement {
    pub fn new(
        worker_id: WorkerId,
        worker_epoch: u64,
        placement_version: u64,
        directory_revision: u64,
    ) -> Result<Self, GatewayConfigurationError> {
        if worker_epoch == 0 || placement_version == 0 || directory_revision == 0 {
            return Err(GatewayConfigurationError::InvalidWorkerPlacement);
        }
        Ok(Self {
            worker_id,
            worker_epoch,
            placement_version,
            directory_revision,
        })
    }
}

pub struct GatewayWorkerRuntime<C> {
    client: Arc<C>,
    placement: GatewayWorkerPlacement,
    sessions: Mutex<BTreeMap<(TenantId, SessionId), GatewaySessionRecord>>,
    session_gc_after: Mutex<Option<(TenantId, SessionId)>>,
    actions: GatewayActionBlockingClient,
    durable_sessions: bool,
    safety: Option<browserd_coordination::SafetyAuthorityBlockingClient>,
    /// Optional durable event outbox (BRD-017). When present, each terminal action transition is
    /// recorded here for at-least-once tenant notification; absent, the runtime behaves as before.
    outbox: Option<EventOutboxBlockingClient>,
    event_scan: Mutex<GatewayEventScanCursor>,
    recovery_scan: Mutex<GatewayActionRecoveryCursor>,
    recovery_running: AtomicBool,
    custody_scan: Mutex<browserd_coordination::GatewayCustodyCursor>,
    custody_running: AtomicBool,
    custody_catchup_scan: Mutex<GatewayActionRecoveryCursor>,
    custody_catchup_running: AtomicBool,
    retention_scan: Mutex<browserd_coordination::GatewayActionRetentionCursor>,
    retention_running: AtomicBool,
    catalog: SessionCatalog,
    downloads: Mutex<artifact_downloads::DownloadTokens>,
    viewer: Option<Arc<GatewayViewer>>,
    fleet: Option<Arc<fleet::GatewayFleet<C>>>,
    notification_scan: Mutex<notifications::NotificationRelayCursor>,
    notification_running: AtomicBool,
}

#[derive(Clone)]
struct GatewaySessionRecord {
    fence: WorkerSessionFence,
    action_placement: GatewayActionPlacement,
    resource: SessionResource,
    admission_lane: Arc<SessionAdmissionLane>,
    retired_at: Option<DateTime<Utc>>,
}

#[derive(Default)]
struct SessionAdmissionLane {
    state: Mutex<SessionAdmissionState>,
    changed: Condvar,
}

#[derive(Default)]
struct SessionAdmissionState {
    occupied: bool,
    waiters: usize,
}

struct SessionAdmissionPermit {
    lane: Arc<SessionAdmissionLane>,
}

impl SessionAdmissionLane {
    fn idle(&self) -> bool {
        self.state
            .try_lock()
            .is_ok_and(|state| !state.occupied && state.waiters == 0)
    }
    fn acquire(self: &Arc<Self>) -> Result<SessionAdmissionPermit, ApiError> {
        let deadline = Instant::now() + ACTION_ADMISSION_WAIT;
        let mut state = self.state.lock().map_err(|_| {
            ApiError::new(
                ErrorCode::WorkerUnavailable,
                "session admission lane unavailable",
            )
        })?;
        if state.waiters >= MAX_SESSION_ADMISSION_WAITERS {
            return Err(ApiError::new(
                ErrorCode::ActionAdmissionTimeout,
                "session admission queue is full",
            ));
        }
        state.waiters += 1;
        loop {
            if !state.occupied {
                state.waiters = state.waiters.saturating_sub(1);
                state.occupied = true;
                return Ok(SessionAdmissionPermit {
                    lane: Arc::clone(self),
                });
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                state.waiters = state.waiters.saturating_sub(1);
                return Err(ApiError::new(
                    ErrorCode::ActionAdmissionTimeout,
                    "session admission deadline elapsed",
                ));
            }
            let (next, timeout) = self.changed.wait_timeout(state, remaining).map_err(|_| {
                ApiError::new(
                    ErrorCode::WorkerUnavailable,
                    "session admission lane unavailable",
                )
            })?;
            state = next;
            if timeout.timed_out() && state.occupied {
                state.waiters = state.waiters.saturating_sub(1);
                return Err(ApiError::new(
                    ErrorCode::ActionAdmissionTimeout,
                    "session admission deadline elapsed",
                ));
            }
        }
    }
}

impl Drop for SessionAdmissionPermit {
    fn drop(&mut self) {
        if let Ok(mut state) = self.lane.state.lock() {
            state.occupied = false;
            self.lane.changed.notify_one();
        }
    }
}

const MAX_APPROVAL_ROUTE_SCAN: usize = 256;
const MAX_APPROVAL_RECEIPTS: usize = 16_384;
const MAX_SESSION_PAGES: usize = 8;
const MAX_SESSION_ADMISSION_WAITERS: usize = 32;
const ACTION_ADMISSION_WAIT: Duration = Duration::from_secs(1);

impl<C> GatewayWorkerRuntime<C> {
    /// Reclaim terminal session-listing entries whose last write is older than `retention`
    /// (BRD-018), keeping the listing catalog bounded under session churn while a recently-closed
    /// session stays listable for the window. Returns the number reclaimed; a transient catalog
    /// lock failure yields 0 and is retried on the next maintenance pass.
    #[must_use]
    pub fn reclaim_retired_sessions(&self, now: DateTime<Utc>, retention: ChronoDuration) -> usize {
        let reclaimed = self.catalog.reclaim(now, retention).unwrap_or(0);
        let (Ok(mut after), Ok(mut sessions)) =
            (self.session_gc_after.try_lock(), self.sessions.try_lock())
        else {
            return reclaimed;
        };
        let mut selected: Vec<_> = match after.as_ref() {
            Some(cursor) => sessions
                .range((
                    std::ops::Bound::Excluded(cursor.clone()),
                    std::ops::Bound::Unbounded,
                ))
                .take(32)
                .map(|(key, _)| key.clone())
                .collect(),
            None => sessions.keys().take(32).cloned().collect(),
        };
        if selected.is_empty() && after.is_some() {
            selected = sessions.keys().take(32).cloned().collect();
        }
        *after = selected.last().cloned();
        for key in selected {
            if sessions.get(&key).is_some_and(|record| {
                record
                    .retired_at
                    .is_some_and(|at| now.signed_duration_since(at) >= retention)
                    && matches!(
                        record.resource.lifecycle,
                        SessionLifecycle::Closed | SessionLifecycle::Failed
                    )
                    && record.admission_lane.idle()
                    && Arc::strong_count(&record.admission_lane) == 1
            }) {
                sessions.remove(&key);
            }
        }
        reclaimed
    }

    pub fn new(
        client: Arc<C>,
        placement: GatewayWorkerPlacement,
    ) -> Result<Self, GatewayConfigurationError>
    where
        C: GatewayWorkerClient,
    {
        Self::with_action_coordination(
            client,
            placement,
            Arc::new(MemoryGatewayActionStore::default()),
            CoordinationActorConfig::default(),
        )
    }

    pub fn with_action_coordination<S>(
        client: Arc<C>,
        placement: GatewayWorkerPlacement,
        action_store: Arc<S>,
        actor_config: CoordinationActorConfig,
    ) -> Result<Self, GatewayConfigurationError>
    where
        C: GatewayWorkerClient,
        S: GatewayActionCoordination + 'static,
    {
        let actions = GatewayActionBlockingClient::spawn(action_store, actor_config)
            .map_err(|_| GatewayConfigurationError::ActionCoordinationUnavailable)?;
        Ok(Self {
            client,
            placement,
            sessions: Mutex::new(BTreeMap::new()),
            session_gc_after: Mutex::new(None),
            actions,
            durable_sessions: false,
            safety: None,
            outbox: None,
            event_scan: Mutex::new(GatewayEventScanCursor::default()),
            recovery_scan: Mutex::new(GatewayActionRecoveryCursor::default()),
            recovery_running: AtomicBool::new(false),
            custody_scan: Mutex::new(browserd_coordination::GatewayCustodyCursor::default()),
            custody_running: AtomicBool::new(false),
            custody_catchup_scan: Mutex::new(GatewayActionRecoveryCursor::default()),
            custody_catchup_running: AtomicBool::new(false),
            retention_scan: Mutex::new(
                browserd_coordination::GatewayActionRetentionCursor::default(),
            ),
            retention_running: AtomicBool::new(false),
            catalog: SessionCatalog::default(),
            downloads: Mutex::new(artifact_downloads::DownloadTokens::default()),
            viewer: None,
            fleet: None,
            notification_scan: Mutex::new(notifications::NotificationRelayCursor::default()),
            notification_running: AtomicBool::new(false),
        })
    }

    /// Attach the sink for the action store's durable pending-event journal. A sink failure
    /// leaves the projection pending for autonomous recovery without replaying browser effects.
    #[must_use]
    pub fn with_terminal_event_outbox(mut self, outbox: EventOutboxBlockingClient) -> Self {
        self.outbox = Some(outbox);
        self
    }

    /// Resolve single-host session ownership through the durable action coordinator.
    #[must_use]
    pub fn with_durable_session_directory(mut self) -> Self {
        self.durable_sessions = true;
        self
    }

    #[must_use]
    pub fn with_runtime_safety(
        mut self,
        safety: browserd_coordination::SafetyAuthorityBlockingClient,
    ) -> Self {
        self.safety = Some(safety);
        self
    }

    fn safety_create_isolation(
        &self,
        request: &SessionCreateRequest,
    ) -> Result<IsolationRequest, ApiError> {
        let Some(authority) = &self.safety else {
            return Ok(request.isolation);
        };
        let current = authority.read().map_err(|_| {
            ApiError::new(
                ErrorCode::WorkerUnavailable,
                "runtime safety authority unavailable",
            )
        })?;
        if current
            .snapshot()
            .network_class_stopped(&request.network_class)
        {
            return Err(ApiError::new(
                ErrorCode::NetworkPolicyDenied,
                "network class is stopped",
            ));
        }
        if request.checkpoint_ref.is_some() && current.snapshot().checkpoint_disabled() {
            return Err(ApiError::invalid_request("checkpoint restore is disabled"));
        }
        Ok(
            match current
                .snapshot()
                .effective_isolation(request.isolation.into())
            {
                IsolationProfile::SharedContext => IsolationRequest::SharedContext,
                IsolationProfile::TenantDedicatedShard => IsolationRequest::TenantDedicatedShard,
                IsolationProfile::DedicatedProcess => IsolationRequest::DedicatedProcess,
                IsolationProfile::DedicatedWorker => IsolationRequest::DedicatedWorker,
            },
        )
    }

    /// Deliver one already-committed journal entry. Only a confirmed sink receipt permits
    /// deleting the source entry; a lost response is retried with the same projection sequence.
    fn relay_terminal_event(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
    ) -> Result<bool, ApiError> {
        let outbox = self.outbox.as_ref().ok_or_else(|| {
            ApiError::new(
                ErrorCode::WorkerUnavailable,
                "event outbox is not configured",
            )
        })?;
        let Some(projection) = self
            .actions
            .peek_event_projection(tenant_id, session_id)
            .map_err(action_coordination_api_error)?
        else {
            return Ok(false);
        };
        outbox
            .append_projection(projection.clone(), Utc::now())
            .map_err(|_| ApiError::new(ErrorCode::WorkerUnavailable, "event outbox unavailable"))?;
        self.actions
            .ack_event_projection(&projection)
            .map_err(action_coordination_api_error)?;
        Ok(true)
    }

    /// Recover notifications independently of live sessions, client polling and gateway
    /// incarnation. Each pass examines at most `limit` sessions and relays one event per
    /// session; loss materialization is also limited to one action per visited session.
    pub fn reconcile_terminal_events(&self, limit: usize) -> Result<usize, ApiError> {
        if !(1..=256).contains(&limit) {
            return Err(ApiError::new(
                ErrorCode::InvalidRequest,
                "event recovery limit must be 1..=256",
            ));
        }
        if self.outbox.is_none() {
            return Err(ApiError::new(
                ErrorCode::WorkerUnavailable,
                "event outbox is not configured",
            ));
        }
        let mut cursor = self.event_scan.lock().map_err(|_| {
            ApiError::new(
                ErrorCode::WorkerUnavailable,
                "event recovery state unavailable",
            )
        })?;
        let page = self
            .actions
            .scan_event_sessions(cursor.clone(), limit)
            .map_err(action_coordination_api_error)?;
        let mut relayed = 0;
        for session in page.sessions() {
            if let Some(loss) = session.loss_claim() {
                self.actions
                    .materialize_session_loss(loss, 1, Utc::now())
                    .map_err(action_coordination_api_error)?;
            }
            relayed +=
                usize::from(self.relay_terminal_event(session.tenant_id(), session.session_id())?);
        }
        // Keep the previous cursor on any error. A repeated page only encounters exact
        // journal retries, and every unacknowledged entry remains discoverable after restart.
        *cursor = if page.is_complete() {
            GatewayEventScanCursor::default()
        } else {
            page.next_cursor().clone()
        };
        Ok(relayed)
    }

    /// Opportunistic delivery reduces latency; the production monitor owns recovery.
    fn note_terminal_transition(&self, snapshot: &GatewayActionSnapshot) {
        if self.outbox.is_none() || snapshot.terminal().is_none() {
            return;
        }
        if let Err(error) = self.relay_terminal_event(snapshot.tenant_id(), snapshot.session_id()) {
            eprintln!(
                "gateway event projection remains pending for action {}: {error:?}",
                snapshot.action_id()
            );
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

fn action_coordination_api_error(error: GatewayActionCoordinationError) -> ApiError {
    let code = match error {
        GatewayActionCoordinationError::IdempotencyConflict { .. } => {
            ErrorCode::IdempotencyConflict
        }
        GatewayActionCoordinationError::PlacementMismatch => ErrorCode::PlacementMismatch,
        GatewayActionCoordinationError::MutationInFlight { .. }
        | GatewayActionCoordinationError::ActionDispatchInFlight { .. }
        | GatewayActionCoordinationError::RetainedActionCapacity
        | GatewayActionCoordinationError::PendingActionCapacity
        | GatewayActionCoordinationError::SubmissionLeaseExpired => {
            ErrorCode::ActionAdmissionTimeout
        }
        GatewayActionCoordinationError::ReconciliationRequired { .. } => {
            ErrorCode::ReconciliationRequired
        }
        GatewayActionCoordinationError::SessionLost => ErrorCode::WorkerLost,
        GatewayActionCoordinationError::NotFound => ErrorCode::ActionResolutionInvalid,
        GatewayActionCoordinationError::ResolutionNotAllowed
        | GatewayActionCoordinationError::ResolutionConflict => ErrorCode::ActionResolutionInvalid,
        GatewayActionCoordinationError::UnsupportedSessionAdmission
        | GatewayActionCoordinationError::UnsupportedSessionDirectory
        | GatewayActionCoordinationError::SessionDirectoryCapacity
        | GatewayActionCoordinationError::SessionDirectoryConflict
        | GatewayActionCoordinationError::AdmissionCapacity
        | GatewayActionCoordinationError::AdmissionConflict
        | GatewayActionCoordinationError::AdmissionRevisionMismatch
        | GatewayActionCoordinationError::InvalidFleetObservation
        | GatewayActionCoordinationError::SessionActivationExpired
        | GatewayActionCoordinationError::SessionAuthorityUnavailable
        | GatewayActionCoordinationError::ManagedActionAdmissionRequired
        | GatewayActionCoordinationError::LockUnavailable
        | GatewayActionCoordinationError::RedisUnavailable
        | GatewayActionCoordinationError::RedisTimedOut
        | GatewayActionCoordinationError::ActorSpawn
        | GatewayActionCoordinationError::ActorQueueFull
        | GatewayActionCoordinationError::ActorDisconnected
        | GatewayActionCoordinationError::ActorQueryTimedOut
        | GatewayActionCoordinationError::ActorMutationTimedOut
        | GatewayActionCoordinationError::RecoveryMigrationRequired
        | GatewayActionCoordinationError::RecoveryMigrationInProgress
        | GatewayActionCoordinationError::PendingCustodyCapacity => ErrorCode::WorkerUnavailable,
        GatewayActionCoordinationError::InvalidSessionAdmission
        | GatewayActionCoordinationError::InvalidSessionDirectory
        | GatewayActionCoordinationError::InvalidIdempotencyKey
        | GatewayActionCoordinationError::InvalidPlacement
        | GatewayActionCoordinationError::InvalidSessionLossId
        | GatewayActionCoordinationError::ActionIdentityConflict { .. }
        | GatewayActionCoordinationError::SessionLossNotRecorded
        | GatewayActionCoordinationError::SessionLossIdentityConflict
        | GatewayActionCoordinationError::StaleWrite(_)
        | GatewayActionCoordinationError::ActionSequenceConflict
        | GatewayActionCoordinationError::InvalidActionSequence
        | GatewayActionCoordinationError::ActionSequenceOverflow
        | GatewayActionCoordinationError::InvalidMaterializationLimit
        | GatewayActionCoordinationError::RetentionTimestampOverflow
        | GatewayActionCoordinationError::RevisionOverflow
        | GatewayActionCoordinationError::CorruptState
        | GatewayActionCoordinationError::InvalidRedisConfig
        | GatewayActionCoordinationError::InvalidRedisResponse
        | GatewayActionCoordinationError::Evidence(_)
        | GatewayActionCoordinationError::UnsupportedEventRecovery
        | GatewayActionCoordinationError::InvalidEventScanLimit
        | GatewayActionCoordinationError::EventSequenceOverflow
        | GatewayActionCoordinationError::EventAckConflict
        | GatewayActionCoordinationError::InvalidSubmissionLease
        | GatewayActionCoordinationError::SubmissionLeaseRequired
        | GatewayActionCoordinationError::SubmissionLeaseMismatch
        | GatewayActionCoordinationError::SubmissionLeaseNotExpired
        | GatewayActionCoordinationError::InvalidRecoveryScanLimit
        | GatewayActionCoordinationError::UnsupportedActionRecovery
        | GatewayActionCoordinationError::OfflineMigrationConfirmationRequired
        | GatewayActionCoordinationError::UnsupportedCustodyRecovery
        | GatewayActionCoordinationError::InvalidCustodyReceipt
        | GatewayActionCoordinationError::CustodyAckConflict
        | GatewayActionCoordinationError::InvalidCustodyScanLimit
        | GatewayActionCoordinationError::UnsupportedActionRetention
        | GatewayActionCoordinationError::InvalidRetentionScanLimit
        | GatewayActionCoordinationError::InvalidRetentionLimits => ErrorCode::Internal,
    };
    ApiError::new(code, "gateway action coordination failed")
}

fn coordinated_action_snapshot(
    snapshot: &GatewayActionSnapshot,
) -> Result<ActionSnapshot, ApiError> {
    let terminal_detail = snapshot.terminal().map(|terminal| terminal.detail());
    let approval_decision = match terminal_detail {
        Some(TerminalDetail::FailedKnown(KnownFailureReason::ApprovalDenied)) => {
            Some(ApprovalDecision::Denied)
        }
        Some(TerminalDetail::FailedKnown(KnownFailureReason::ApprovalTimedOut)) => {
            Some(ApprovalDecision::TimedOut)
        }
        _ => None,
    };
    ActionSnapshot::from_facts_with_result_budget(
        ActionSnapshotFacts {
            action_id: snapshot.action_id().clone(),
            action_sequence: snapshot.action_sequence(),
            idempotency_key: IdempotencyKey::new(snapshot.idempotency_key()),
            canonical_request_hash: ActionCanonicalRequestHash::new(
                *snapshot.request_hash().as_bytes(),
            ),
            kind: snapshot.kind(),
            state: snapshot.state(),
            dispatch_acknowledged: matches!(
                snapshot.delivery(),
                ActionDeliveryEvidence::ExposurePossible(_)
            ),
            approval_decision,
            terminal_detail,
            resolution: snapshot.resolution().cloned(),
            // The durable ledger persists a succeeded action's result body alongside its digest, so
            // GET, same-key resubmission, and restart all return the same bytes as the live receipt.
            result_content: snapshot.result_content().map(<[u8]>::to_vec),
        },
        snapshot.result_budget(),
    )
    .map_err(|_| ApiError::new(ErrorCode::Internal, "durable action state is contradictory"))
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
        if self.fleet.is_some() {
            return self.fleet_session_record(tenant_id, session_id);
        }
        if self.durable_sessions {
            return self.durable_session_record(tenant_id, session_id);
        }
        self.sessions
            .lock()
            .map_err(|_| ApiError::new(ErrorCode::WorkerUnavailable, "session state unavailable"))?
            .get(&(tenant_id.clone(), session_id.clone()))
            .cloned()
            .ok_or_else(|| ApiError::new(ErrorCode::SessionNotFound, "session not found"))
    }

    fn admit_session_transition(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
    ) -> Result<(GatewaySessionRecord, SessionAdmissionPermit), ApiError> {
        let initial = self.session_record(tenant_id, session_id)?;
        if initial.resource.lifecycle != SessionLifecycle::Ready {
            return Err(ApiError::new(
                ErrorCode::SessionNotFound,
                "session no longer accepts transitions",
            ));
        }
        let permit = initial.admission_lane.acquire()?;
        let current = self.session_record(tenant_id, session_id)?;
        if current.fence != initial.fence {
            return Err(ApiError::new(
                ErrorCode::PlacementMismatch,
                "session placement changed during admission",
            ));
        }
        if current.resource.lifecycle != SessionLifecycle::Ready {
            return Err(ApiError::new(
                ErrorCode::SessionNotFound,
                "session no longer accepts transitions",
            ));
        }
        if self.durable_sessions && self.fleet.is_none() {
            self.verify_single_host_worker_ready(&current)?;
        }
        Ok((current, permit))
    }

    fn validate_current_fence(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        expected: &WorkerSessionFence,
    ) -> Result<(), ApiError> {
        if &expected.tenant_id != tenant_id
            || &expected.session_id != session_id
            || (self.fleet.is_none()
                && (expected.worker_epoch != self.placement.worker_epoch
                    || expected.placement_version != self.placement.placement_version))
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
        let (record, _admission) =
            self.admit_session_transition(principal.tenant_id(), &command.session_id)?;
        let receipts = match self
            .request_worker(WorkerRpcRequest::ListPages {
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
        let (record, _admission) =
            self.admit_session_transition(principal.tenant_id(), &command.session_id)?;
        let receipt = match self
            .request_worker(WorkerRpcRequest::CreatePage {
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
        let (record, _admission) =
            self.admit_session_transition(principal.tenant_id(), &command.session_id)?;
        let receipt = match self
            .request_worker(WorkerRpcRequest::ActivatePage {
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
        let (record, _admission) =
            self.admit_session_transition(principal.tenant_id(), &command.session_id)?;
        let receipt = match self
            .request_worker(WorkerRpcRequest::ClosePage {
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
    fn effective_action_after_race(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        error: GatewayActionCoordinationError,
    ) -> Result<GatewayActionSnapshot, ApiError> {
        match error {
            GatewayActionCoordinationError::StaleWrite(current) => Ok(*current),
            GatewayActionCoordinationError::MutationInFlight { .. } => Err(ApiError::new(
                ErrorCode::ActionAdmissionTimeout,
                "another mutating action still owns the session admission lane",
            )),
            GatewayActionCoordinationError::SessionLost => self
                .actions
                .get_effective_action(tenant_id, session_id, action_id)
                .map_err(action_coordination_api_error)?
                .ok_or_else(|| {
                    ApiError::new(
                        ErrorCode::ActionResolutionInvalid,
                        "durable action disappeared during session loss",
                    )
                }),
            other => Err(action_coordination_api_error(other)),
        }
    }

    fn record_action_transport_loss(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        record: &GatewaySessionRecord,
        snapshot: &GatewayActionSnapshot,
        dispatch_id: &DispatchId,
        loss: TransportLoss,
    ) -> Result<ActionSnapshot, ApiError> {
        let effective = match self.actions.record_transport_loss(
            tenant_id,
            session_id,
            snapshot.action_id(),
            snapshot.revision(),
            &record.action_placement,
            dispatch_id,
            loss,
            Utc::now(),
        ) {
            Ok(effective) => effective,
            Err(error) => self.effective_action_after_race(
                tenant_id,
                session_id,
                snapshot.action_id(),
                error,
            )?,
        };
        self.note_terminal_transition(&effective);
        coordinated_action_snapshot(&effective)
    }

    fn reconcile_worker_action(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        record: &GatewaySessionRecord,
        durable: &GatewayActionSnapshot,
        dispatch_id: &DispatchId,
        receipt: WorkerActionReceipt,
    ) -> Result<ActionSnapshot, ApiError> {
        let receipt_matches = record.action_placement == *durable.placement()
            && receipt.fence == record.fence
            && receipt.action_id == *durable.action_id()
            && receipt.action_sequence == durable.action_sequence()
            && receipt.idempotency_key == durable.idempotency_key()
            && receipt.canonical_request_hash == *durable.request_hash().as_bytes()
            && receipt.kind == durable.kind();
        if !receipt_matches {
            return self.record_action_transport_loss(
                tenant_id,
                session_id,
                record,
                durable,
                dispatch_id,
                TransportLoss::Ambiguous(OutcomeUnknownReason::AmbiguousTransportLoss),
            );
        }
        let custody = self.validated_terminal_custody(durable, &receipt)?;
        let custody_requirement = receipt.custody_requirement;
        let terminal_detail = receipt.terminal_detail;
        let worker_snapshot = match self.action_snapshot(
            tenant_id,
            session_id,
            &record.fence,
            receipt,
            Some(durable.action_id()),
            Some((
                durable.idempotency_key(),
                *durable.request_hash().as_bytes(),
                durable.kind(),
                durable.result_budget(),
            )),
        ) {
            Ok(snapshot) => snapshot,
            Err(_) => {
                return self.record_action_transport_loss(
                    tenant_id,
                    session_id,
                    record,
                    durable,
                    dispatch_id,
                    TransportLoss::Ambiguous(OutcomeUnknownReason::AmbiguousTransportLoss),
                );
            }
        };
        let Some(detail) = terminal_detail else {
            return Ok(worker_snapshot);
        };
        // Original completions and restart queries share bounded receipt CAS convergence.
        // In particular, an exposure write can commit while its reply is lost: the original
        // positive result must still persist after that revision changes.
        self.persist_worker_action_snapshot(
            durable,
            &worker_snapshot,
            detail,
            custody,
            custody_requirement,
        )
    }

    fn action_snapshot(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        expected_fence: &WorkerSessionFence,
        receipt: WorkerActionReceipt,
        expected_action_id: Option<&browserd_core::ActionId>,
        expected_submission: Option<(
            &str,
            [u8; 32],
            ActionKind,
            browserd_actions::ActionResultBudget,
        )>,
    ) -> Result<ActionSnapshot, ApiError> {
        if receipt.fence != *expected_fence
            || expected_action_id.is_some_and(|action_id| action_id != &receipt.action_id)
            || expected_submission.is_some_and(|(key, hash, kind, _)| {
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
        let result_budget = expected_submission.map_or(
            browserd_actions::ActionResultBudget::Standard,
            |(_, _, _, budget)| budget,
        );
        let snapshot = receipt
            .to_action_snapshot_with_result_budget(result_budget)
            .map_err(|_| {
                ApiError::new(
                    ErrorCode::Internal,
                    "worker returned contradictory action facts",
                )
            })?;
        self.validate_current_fence(tenant_id, session_id, &receipt.fence)?;
        Ok(snapshot)
    }

    fn submit_action(
        &self,
        principal: &browserd_auth::AuthenticatedPrincipal,
        command: ActionSubmitCommand,
    ) -> Result<ApiResponse, ApiError> {
        self.submit_action_observed(principal, command, &mut |_| {})
    }

    fn submit_action_observed(
        &self,
        principal: &browserd_auth::AuthenticatedPrincipal,
        command: ActionSubmitCommand,
        accepted: &mut (dyn FnMut(ApiEnvelope<ActionSnapshot>) + Send),
    ) -> Result<ApiResponse, ApiError> {
        if self.durable_sessions
            && self.fleet.is_none()
            && let Some(replay) = self.replay_durable_action(principal.tenant_id(), &command)?
        {
            return coordinated_action_snapshot(&replay)
                .map(ApiEnvelope::new)
                .map(ApiResponse::Action);
        }
        let (record, _admission) =
            self.admit_session_transition(principal.tenant_id(), &command.session_id)?;
        if matches!(
            record.resource.lifecycle,
            SessionLifecycle::Closing | SessionLifecycle::Closed | SessionLifecycle::Failed
        ) {
            return Err(ApiError::new(
                ErrorCode::SessionNotFound,
                "session no longer accepts actions",
            ));
        }
        if command.idempotency_key.is_nil() {
            return Err(ApiError::invalid_request(
                "Idempotency-Key must not be the nil UUID",
            ));
        }
        if command.body.if_session_incarnation != record.fence.session_incarnation {
            return Err(ApiError::new(
                ErrorCode::GenerationMismatch,
                "session incarnation precondition failed",
            ));
        }
        let action = match &command.body.action {
            ActionPayload::Navigate { url, wait_until } => WorkerActionCommand::Navigate {
                url: url.clone(),
                wait_until: match wait_until {
                    ApiWaitUntil::Domcontentloaded => WorkerNavigateWaitUntil::Domcontentloaded,
                    ApiWaitUntil::Load => WorkerNavigateWaitUntil::Load,
                },
            },
            ActionPayload::Reload => WorkerActionCommand::Reload,
            ActionPayload::TypeText { text } => {
                WorkerActionCommand::TypeText { text: text.clone() }
            }
            ActionPayload::GetUrl => WorkerActionCommand::GetUrl,
            ActionPayload::GetTitle => WorkerActionCommand::GetTitle,
            ActionPayload::GoBack => WorkerActionCommand::GoBack,
            ActionPayload::GoForward => WorkerActionCommand::GoForward,
            ActionPayload::PressKey { key } => WorkerActionCommand::PressKey { key: key.clone() },
            ActionPayload::Scroll { delta_x, delta_y } => WorkerActionCommand::Scroll {
                delta_x: *delta_x,
                delta_y: *delta_y,
            },
            ActionPayload::QueryAll {
                selector,
                frame_path,
            } => WorkerActionCommand::QueryAll {
                selector: selector.clone(),
                frame_path: frame_path.clone(),
            },
            ActionPayload::GetText { node_ref } => WorkerActionCommand::GetText {
                node_ref: node_ref.clone(),
            },
            ActionPayload::GetHtml { node_ref } => WorkerActionCommand::GetHtml {
                node_ref: node_ref.clone(),
            },
            ActionPayload::GetAttribute { node_ref, name } => WorkerActionCommand::GetAttribute {
                node_ref: node_ref.clone(),
                name: name.clone(),
            },
            ActionPayload::GetProperties { node_ref } => WorkerActionCommand::GetProperties {
                node_ref: node_ref.clone(),
            },
            ActionPayload::GetComputedStyle { node_ref } => WorkerActionCommand::GetComputedStyle {
                node_ref: node_ref.clone(),
            },
            ActionPayload::ExtractTable { node_ref } => WorkerActionCommand::ExtractTable {
                node_ref: node_ref.clone(),
            },
            ActionPayload::Click { node_ref } => WorkerActionCommand::Click {
                node_ref: node_ref.clone(),
            },
            ActionPayload::DoubleClick { node_ref } => WorkerActionCommand::DoubleClick {
                node_ref: node_ref.clone(),
            },
            ActionPayload::Hover { node_ref } => WorkerActionCommand::Hover {
                node_ref: node_ref.clone(),
            },
            ActionPayload::Focus { node_ref } => WorkerActionCommand::Focus {
                node_ref: node_ref.clone(),
            },
            ActionPayload::Blur { node_ref } => WorkerActionCommand::Blur {
                node_ref: node_ref.clone(),
            },
            ActionPayload::Check { node_ref } => WorkerActionCommand::Check {
                node_ref: node_ref.clone(),
            },
            ActionPayload::Uncheck { node_ref } => WorkerActionCommand::Uncheck {
                node_ref: node_ref.clone(),
            },
            ActionPayload::Fill { node_ref, value } => WorkerActionCommand::Fill {
                node_ref: node_ref.clone(),
                value: value.clone(),
            },
            ActionPayload::FillSecret {
                node_ref,
                secret_ref,
            } => WorkerActionCommand::FillSecret {
                node_ref: node_ref.clone(),
                secret_ref: secret_ref.clone(),
            },
            ActionPayload::SelectOption { node_ref, values } => WorkerActionCommand::SelectOption {
                node_ref: node_ref.clone(),
                values: values.clone(),
            },
            ActionPayload::Evaluate { expression } => WorkerActionCommand::Evaluate {
                expression: expression.clone(),
            },
            ActionPayload::WaitFor { condition } => WorkerActionCommand::WaitFor {
                condition: match condition {
                    ApiWaitCondition::SelectorAttached { selector } => {
                        WorkerWaitCondition::SelectorAttached {
                            selector: selector.clone(),
                        }
                    }
                    ApiWaitCondition::SelectorVisible { selector } => {
                        WorkerWaitCondition::SelectorVisible {
                            selector: selector.clone(),
                        }
                    }
                    ApiWaitCondition::SelectorHidden { selector } => {
                        WorkerWaitCondition::SelectorHidden {
                            selector: selector.clone(),
                        }
                    }
                    ApiWaitCondition::UrlMatches { pattern } => WorkerWaitCondition::UrlMatches {
                        pattern: pattern.clone(),
                    },
                    ApiWaitCondition::LoadState { state } => WorkerWaitCondition::LoadState {
                        state: match state {
                            ApiWaitUntil::Domcontentloaded => {
                                WorkerNavigateWaitUntil::Domcontentloaded
                            }
                            ApiWaitUntil::Load => WorkerNavigateWaitUntil::Load,
                        },
                    },
                    ApiWaitCondition::NetworkQuiet { quiet_ms } => {
                        WorkerWaitCondition::NetworkQuiet {
                            quiet_ms: *quiet_ms,
                        }
                    }
                },
            },
            ActionPayload::HandleDialog {
                accept,
                prompt_text,
            } => WorkerActionCommand::HandleDialog {
                accept: *accept,
                prompt_text: prompt_text.clone(),
            },
            ActionPayload::Snapshot => WorkerActionCommand::Snapshot,
            ActionPayload::Screenshot { options } => WorkerActionCommand::Screenshot {
                options: options.clone(),
            },
            ActionPayload::Pdf { options } => WorkerActionCommand::Pdf {
                options: options.clone(),
            },
            ActionPayload::Scrape { options } => WorkerActionCommand::Scrape {
                options: options.clone(),
            },
            ActionPayload::SetFiles {
                node_ref,
                artifact_ids,
            } => WorkerActionCommand::SetFiles {
                node_ref: node_ref.clone(),
                artifact_ids: artifact_ids.clone(),
            },
            ActionPayload::Checkpoint { origins } => WorkerActionCommand::Checkpoint {
                origins: origins.clone(),
            },
            ActionPayload::NewPage { .. }
            | ActionPayload::ClosePage
            | ActionPayload::ActivatePage => {
                return Err(ApiError::invalid_request(
                    "action is not supported by the production worker",
                ));
            }
        };
        if !action.is_valid() {
            return Err(ApiError::invalid_request(
                "action exceeds the production worker bounds",
            ));
        }
        let execution_timeout_ms =
            WorkerActionExecutionTimeout::new(command.body.execution_timeout_ms)
                .ok_or_else(|| ApiError::invalid_request("action execution timeout is invalid"))?;
        let canonical = serde_json::to_value(&command.body)
            .map_err(|_| ApiError::new(ErrorCode::Internal, "action canonicalization failed"))?;
        let canonical_request_hash =
            *browserd_operations::CanonicalRequestHash::from_json(&canonical).as_bytes();
        let kind = action.kind();
        let idempotency_key = command.idempotency_key.to_string();
        let claimed_at = Utc::now();
        let admission_deadline = claimed_at + ChronoDuration::seconds(1);
        let submission_lease = GatewayActionSubmissionLease::new(
            Uuid::now_v7(),
            1,
            admission_deadline,
            admission_deadline,
        )
        .map_err(action_coordination_api_error)?;
        let claim = ClaimGatewayAction::new(
            principal.tenant_id().clone(),
            command.session_id.clone(),
            ActionId::new(),
            idempotency_key.clone(),
            ActionCanonicalRequestHash::new(canonical_request_hash),
            kind,
            record.action_placement.clone(),
        )
        .map_err(action_coordination_api_error)?
        .with_result_budget(if matches!(&action, WorkerActionCommand::Snapshot) {
            browserd_actions::ActionResultBudget::Snapshot
        } else {
            browserd_actions::ActionResultBudget::Standard
        })
        .with_submission_lease(submission_lease.clone());
        let authority = self.authority_ref(principal.tenant_id(), &command.session_id)?;
        let claim_outcome = match &authority {
            Some(authority) => self
                .actions
                .claim_action_authorized(claim, authority, claimed_at),
            None => self.actions.claim_action(claim, claimed_at),
        }
        .map_err(action_coordination_api_error)?;
        let mut durable = match claim_outcome {
            GatewayActionClaimOutcome::Created(created) => created,
            GatewayActionClaimOutcome::Existing(existing) => {
                return coordinated_action_snapshot(&existing)
                    .map(ApiEnvelope::new)
                    .map(ApiResponse::Action);
            }
        };
        if durable.terminal().is_some() {
            return coordinated_action_snapshot(&durable)
                .map(ApiEnvelope::new)
                .map(ApiResponse::Action);
        }
        let (dispatch_id, now_unix_millis) = match durable.delivery() {
            ActionDeliveryEvidence::NotAttempted => {
                let now_unix_millis = current_unix_millis()?;
                let dispatch_id = DispatchId::new();
                let armed = match &authority {
                    Some(authority) => self.actions.arm_dispatch_owned_authorized(
                        principal.tenant_id(),
                        &command.session_id,
                        durable.action_id(),
                        durable.revision(),
                        &record.action_placement,
                        dispatch_id.clone(),
                        &submission_lease,
                        authority,
                        Utc::now(),
                    ),
                    None => self.actions.arm_dispatch_owned(
                        principal.tenant_id(),
                        &command.session_id,
                        durable.action_id(),
                        durable.revision(),
                        &record.action_placement,
                        dispatch_id.clone(),
                        &submission_lease,
                        Utc::now(),
                    ),
                };
                durable = match armed {
                    Ok(armed) => armed,
                    Err(
                        error @ (GatewayActionCoordinationError::MutationInFlight { .. }
                        | GatewayActionCoordinationError::ActionDispatchInFlight { .. }),
                    ) => {
                        match self.actions.cancel_before_dispatch(
                            principal.tenant_id(),
                            &command.session_id,
                            durable.action_id(),
                            durable.revision(),
                            &record.action_placement,
                            Utc::now(),
                        ) {
                            Ok(_) => {}
                            Err(GatewayActionCoordinationError::StaleWrite(current))
                                if matches!(
                                    current.terminal().map(|terminal| terminal.detail()),
                                    Some(TerminalDetail::CancelledBeforeDispatch)
                                ) => {}
                            Err(cancel_error) => {
                                return Err(action_coordination_api_error(cancel_error));
                            }
                        }
                        return Err(action_coordination_api_error(error));
                    }
                    Err(error) => {
                        let effective = self.effective_action_after_race(
                            principal.tenant_id(),
                            &command.session_id,
                            durable.action_id(),
                            error,
                        )?;
                        self.note_terminal_transition(&effective);
                        return coordinated_action_snapshot(&effective)
                            .map(ApiEnvelope::new)
                            .map(ApiResponse::Action);
                    }
                };
                (dispatch_id, now_unix_millis)
            }
            ActionDeliveryEvidence::DispatchArmed(_)
            | ActionDeliveryEvidence::ExposurePossible(_) => {
                return coordinated_action_snapshot(&durable)
                    .map(ApiEnvelope::new)
                    .map(ApiResponse::Action);
            }
        };
        // The durable claim and dispatch arm now own this action ID. Session admission
        // remains held: the observer must never block or re-enter this runtime. A receipt
        // acknowledges acceptance only; enqueue failure can still become NotDispatched.
        accepted(ApiEnvelope::new(coordinated_action_snapshot(&durable)?));
        let request = WorkerRpcRequest::SubmitAction {
            fence: record.fence.clone(),
            action_id: durable.action_id().clone(),
            action_sequence: durable.action_sequence(),
            requester_principal_id: principal.principal_id().clone(),
            idempotency_key,
            canonical_request_hash,
            kind,
            page_id: Some(command.body.page_id),
            action,
            execution_timeout_ms,
            approval: None,
            now_unix_millis,
        };
        let pending = match self
            .client_for_fence(&record.fence)?
            .enqueue_action(request)
        {
            Ok(pending) => pending,
            Err(WorkerRpcEnqueueError::Full(_) | WorkerRpcEnqueueError::Closed(_)) => {
                return self
                    .record_action_transport_loss(
                        principal.tenant_id(),
                        &command.session_id,
                        &record,
                        &durable,
                        &dispatch_id,
                        TransportLoss::ConfirmedNotWritten,
                    )
                    .map(ApiEnvelope::new)
                    .map(ApiResponse::Action);
            }
        };
        durable = match self.actions.mark_exposure_possible(
            principal.tenant_id(),
            &command.session_id,
            durable.action_id(),
            durable.revision(),
            &record.action_placement,
            &dispatch_id,
            Utc::now(),
        ) {
            Ok(exposed) => exposed,
            Err(error) => {
                // Enqueue transferred ownership to the RPC actor. Keep its completion owner
                // even when the exposure write fails or another observer commits a terminal
                // result. The immutable dispatch arm still permits recording a positive result.
                self.effective_action_after_race(
                    principal.tenant_id(),
                    &command.session_id,
                    durable.action_id(),
                    error,
                )
                .unwrap_or_else(|_| durable.clone())
            }
        };
        let completion = pending.wait();
        if durable.terminal().is_some() {
            self.note_terminal_transition(&durable);
            return coordinated_action_snapshot(&durable)
                .map(ApiEnvelope::new)
                .map(ApiResponse::Action);
        }
        let action = match completion {
            Ok(WorkerRpcResponse::Action(receipt)) => self.reconcile_worker_action(
                principal.tenant_id(),
                &command.session_id,
                &record,
                &durable,
                &dispatch_id,
                receipt,
            )?,
            Err(
                WorkerRpcCompletionError::Timeout
                | WorkerRpcCompletionError::Exchange(WorkerRpcError::Timeout),
            ) => self.record_action_transport_loss(
                principal.tenant_id(),
                &command.session_id,
                &record,
                &durable,
                &dispatch_id,
                TransportLoss::Ambiguous(OutcomeUnknownReason::TimeoutAfterDispatch),
            )?,
            Ok(_)
            | Err(WorkerRpcCompletionError::Exchange(_) | WorkerRpcCompletionError::Disconnected) => {
                self.record_action_transport_loss(
                    principal.tenant_id(),
                    &command.session_id,
                    &record,
                    &durable,
                    &dispatch_id,
                    TransportLoss::Ambiguous(OutcomeUnknownReason::AmbiguousTransportLoss),
                )?
            }
        };
        Ok(ApiResponse::Action(ApiEnvelope::new(action)))
    }

    fn get_action(
        &self,
        principal: &browserd_auth::AuthenticatedPrincipal,
        command: ActionGetRequest,
    ) -> Result<ApiResponse, ApiError> {
        // Read the durable action before requiring a live session record, so a terminal action
        // (including its persisted result body) is retrievable even after a gateway restart or
        // from another gateway that has not hydrated this session's placement (BRD-002). A live
        // worker query is only needed, and the session record only required, when the action is
        // still non-terminal.
        let durable = self
            .actions
            .get_effective_action(
                principal.tenant_id(),
                &command.session_id,
                &command.action_id,
            )
            .map_err(action_coordination_api_error)?
            .ok_or_else(|| ApiError::new(ErrorCode::OperationNotFound, "action not found"))?;
        if durable.terminal().is_some() {
            return coordinated_action_snapshot(&durable)
                .map(ApiEnvelope::new)
                .map(ApiResponse::Action);
        }
        if matches!(durable.delivery(), ActionDeliveryEvidence::NotAttempted) {
            let recovered = self.recover_action_receipt(&durable)?;
            return recovered
                .map_or_else(|| coordinated_action_snapshot(&durable), Ok)
                .map(ApiEnvelope::new)
                .map(ApiResponse::Action);
        }
        let record = match self.session_record(principal.tenant_id(), &command.session_id) {
            Ok(record) => record,
            Err(error) if error.code() == ErrorCode::SessionNotFound => {
                let recovered = self.recover_action_receipt(&durable)?;
                return recovered
                    .map_or_else(|| coordinated_action_snapshot(&durable), Ok)
                    .map(ApiEnvelope::new)
                    .map(ApiResponse::Action);
            }
            Err(error) => return Err(error),
        };
        let dispatch_id = match durable.delivery() {
            ActionDeliveryEvidence::DispatchArmed(dispatch_id)
            | ActionDeliveryEvidence::ExposurePossible(dispatch_id) => dispatch_id.clone(),
            ActionDeliveryEvidence::NotAttempted => unreachable!("handled above"),
        };
        let response = self.request_worker(WorkerRpcRequest::GetAction {
            fence: record.fence.clone(),
            action_id: command.action_id.clone(),
        });
        let action = match response {
            Ok(WorkerRpcResponse::Action(receipt)) => self.reconcile_worker_action(
                principal.tenant_id(),
                &command.session_id,
                &record,
                &durable,
                &dispatch_id,
                receipt,
            )?,
            Ok(_) | Err(_) => coordinated_action_snapshot(&durable)?,
        };
        Ok(ApiResponse::Action(ApiEnvelope::new(action)))
    }

    fn cancel_action(
        &self,
        principal: &browserd_auth::AuthenticatedPrincipal,
        command: ActionGetRequest,
    ) -> Result<ApiResponse, ApiError> {
        let record = self.session_record(principal.tenant_id(), &command.session_id)?;
        let durable = self
            .actions
            .get_effective_action(
                principal.tenant_id(),
                &command.session_id,
                &command.action_id,
            )
            .map_err(action_coordination_api_error)?
            .ok_or_else(|| ApiError::new(ErrorCode::ActionResolutionInvalid, "action not found"))?;
        if durable.terminal().is_some() {
            return coordinated_action_snapshot(&durable)
                .map(ApiEnvelope::new)
                .map(ApiResponse::Action);
        }
        let dispatch_id = match durable.delivery() {
            ActionDeliveryEvidence::NotAttempted => {
                let effective = match self.actions.cancel_before_dispatch(
                    principal.tenant_id(),
                    &command.session_id,
                    durable.action_id(),
                    durable.revision(),
                    &record.action_placement,
                    Utc::now(),
                ) {
                    Ok(cancelled) => cancelled,
                    Err(error) => self.effective_action_after_race(
                        principal.tenant_id(),
                        &command.session_id,
                        durable.action_id(),
                        error,
                    )?,
                };
                self.note_terminal_transition(&effective);
                return coordinated_action_snapshot(&effective)
                    .map(ApiEnvelope::new)
                    .map(ApiResponse::Action);
            }
            ActionDeliveryEvidence::DispatchArmed(dispatch_id)
            | ActionDeliveryEvidence::ExposurePossible(dispatch_id) => dispatch_id.clone(),
        };
        let response = self.request_worker(WorkerRpcRequest::CancelAction {
            fence: record.fence.clone(),
            action_id: command.action_id.clone(),
            now_unix_millis: current_unix_millis()?,
        });
        let action = match response {
            Ok(WorkerRpcResponse::Action(receipt)) => self.reconcile_worker_action(
                principal.tenant_id(),
                &command.session_id,
                &record,
                &durable,
                &dispatch_id,
                receipt,
            )?,
            Ok(_) | Err(_) => coordinated_action_snapshot(&durable)?,
        };
        Ok(ApiResponse::Action(ApiEnvelope::new(action)))
    }

    fn resolve_action(
        &self,
        principal: &browserd_auth::AuthenticatedPrincipal,
        command: ActionResolveRequest,
    ) -> Result<ApiResponse, ApiError> {
        if command.body.note.is_some() {
            return Err(ApiError::new(
                ErrorCode::InvalidRequest,
                "a separate resolution note is not supported",
            ));
        }
        let (record, _admission) =
            self.admit_session_transition(principal.tenant_id(), &command.session_id)?;
        let resolution = command.body.resolution.into();
        let durable = self
            .actions
            .get_effective_action(
                principal.tenant_id(),
                &command.session_id,
                &command.action_id,
            )
            .map_err(action_coordination_api_error)?
            .ok_or_else(|| ApiError::new(ErrorCode::ActionResolutionInvalid, "action not found"))?;
        if let Some(existing) = durable.resolution() {
            if existing.kind() == resolution
                && existing.resolved_by() == principal.principal_id()
                && existing.basis() == command.body.basis
            {
                return coordinated_action_snapshot(&durable)
                    .map(ApiEnvelope::new)
                    .map(ApiResponse::Action);
            }
            return Err(ApiError::new(
                ErrorCode::ActionResolutionInvalid,
                "action already has a different resolution",
            ));
        }
        let requested_annotation = ResolutionAnnotation::new(
            resolution,
            principal.principal_id().clone(),
            current_unix_millis()?,
            command.body.basis.clone(),
        );
        let (annotation, custody, custody_requirement) = match self
            .request_worker(WorkerRpcRequest::ResolveAction {
                fence: record.fence.clone(),
                action_id: command.action_id.clone(),
                resolution,
                resolved_by: principal.principal_id().clone(),
                basis: command.body.basis,
                now_unix_millis: requested_annotation.resolved_at_millis(),
            })
            .map_err(worker_api_error)?
        {
            WorkerRpcResponse::Action(receipt) => {
                if receipt.fence != record.fence
                    || receipt.action_id != command.action_id
                    || receipt.action_sequence != durable.action_sequence()
                    || receipt.idempotency_key != durable.idempotency_key()
                    || receipt.canonical_request_hash != *durable.request_hash().as_bytes()
                    || receipt.kind != durable.kind()
                {
                    return Err(ApiError::new(
                        ErrorCode::PlacementMismatch,
                        "worker returned a mismatched resolution receipt",
                    ));
                }
                receipt
                    .to_action_snapshot_with_result_budget(durable.result_budget())
                    .map_err(|_| {
                        ApiError::new(
                            ErrorCode::Internal,
                            "worker returned contradictory resolution facts",
                        )
                    })?;
                let custody = self.validated_terminal_custody(&durable, &receipt)?;
                let worker_annotation = receipt.resolution.ok_or_else(|| {
                    ApiError::new(
                        ErrorCode::ActionResolutionInvalid,
                        "worker omitted the durable resolution annotation",
                    )
                })?;
                if worker_annotation.kind() != requested_annotation.kind()
                    || worker_annotation.resolved_by() != requested_annotation.resolved_by()
                    || worker_annotation.basis() != requested_annotation.basis()
                {
                    return Err(ApiError::new(
                        ErrorCode::ActionResolutionInvalid,
                        "worker resolved the action with different evidence",
                    ));
                }
                (worker_annotation, custody, receipt.custody_requirement)
            }
            WorkerRpcResponse::Failure(failure)
                if failure.code == WorkerRpcFailureCode::NotFound =>
            {
                (requested_annotation, None, None)
            }
            WorkerRpcResponse::Failure(failure) => {
                return Err(worker_api_error(WorkerRpcError::Remote(failure)));
            }
            _ => {
                return Err(ApiError::new(
                    ErrorCode::Internal,
                    "worker returned an unexpected resolution response",
                ));
            }
        };
        let resolved = match self.actions.resolve_unknown_with_custody(
            principal.tenant_id(),
            &command.session_id,
            durable.action_id(),
            durable.revision(),
            &record.action_placement,
            annotation.clone(),
            custody,
            custody_requirement,
            Utc::now(),
        ) {
            Ok(resolved) => resolved,
            Err(GatewayActionCoordinationError::StaleWrite(current))
                if current.resolution() == Some(&annotation) =>
            {
                *current
            }
            Err(error) => return Err(action_coordination_api_error(error)),
        };
        self.note_terminal_transition(&resolved);
        coordinated_action_snapshot(&resolved)
            .map(ApiEnvelope::new)
            .map(ApiResponse::Action)
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
        self.validate_current_fence(tenant_id, session_id, &receipt.fence)?;
        Self::artifact_content_metadata(tenant_id, session_id, receipt)
    }

    fn artifact_content_metadata(
        tenant_id: &TenantId,
        session_id: &SessionId,
        receipt: WorkerArtifactReceipt,
    ) -> Result<ArtifactMetadata, ApiError> {
        if &receipt.fence.tenant_id != tenant_id || &receipt.fence.session_id != session_id {
            return Err(ApiError::new(
                ErrorCode::PlacementMismatch,
                "artifact namespace mismatch",
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
        let metadata = ArtifactMetadata {
            key: ArtifactKey::new(tenant_id.clone(), session_id.clone(), receipt.artifact_id),
            state,
            checksum_sha256: Some(*content.checksum().as_bytes()),
            size_bytes: Some(content.size_bytes()),
            content_type: Some(content.content_type().to_owned()),
            source_origin: Some(content.origin().to_owned()),
            display_filename: receipt.display_filename,
        };
        metadata.validate_display_filename()?;
        Ok(metadata)
    }

    fn list_artifacts(
        &self,
        principal: &browserd_auth::AuthenticatedPrincipal,
        command: ArtifactListRequest,
    ) -> Result<ApiResponse, ApiError> {
        command.validate()?;
        let Some(record) = self.live_artifact_record(principal.tenant_id(), &command.session_id)?
        else {
            return self.list_retained_artifacts(principal, command);
        };
        let receipts = match self
            .request_worker(WorkerRpcRequest::ListArtifacts {
                fence: record.fence.clone(),
                after: command.after.clone(),
                limit: command.limit + 1,
            })
            .map_err(|error| {
                worker_api_error_with_codes(
                    error,
                    ErrorCode::SessionNotFound,
                    ErrorCode::PlacementMismatch,
                    ErrorCode::GlobalCapacityExceeded,
                )
            })? {
            WorkerRpcResponse::Artifacts(receipts) => receipts,
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
                    "worker returned an unexpected artifact list",
                ));
            }
        };
        if receipts.len() > command.limit + 1 {
            return Err(ApiError::new(
                ErrorCode::Internal,
                "worker returned an unbounded artifact list",
            ));
        }
        let mut previous = command.after;
        let mut items = Vec::with_capacity(receipts.len());
        for receipt in receipts {
            let id = receipt.artifact_id.clone();
            if previous.as_ref().is_some_and(|previous| &id <= previous) {
                return Err(ApiError::new(
                    ErrorCode::Internal,
                    "worker returned invalid artifact ordering",
                ));
            }
            previous = Some(id.clone());
            // Verify the extra pagination item too; a hidden cross-fence receipt
            // must never authorize a partially accepted public page.
            items.push(self.artifact_metadata(
                principal.tenant_id(),
                &command.session_id,
                &record.fence,
                &id,
                receipt,
            )?);
        }
        self.validate_current_fence(principal.tenant_id(), &command.session_id, &record.fence)?;
        let next_cursor = if items.len() > command.limit {
            items.truncate(command.limit);
            items.last().map(|item| item.key.artifact_id().clone())
        } else {
            None
        };
        Ok(ApiResponse::Artifacts(ApiEnvelope::new(ArtifactListPage {
            items,
            next_cursor,
        })))
    }

    fn get_artifact(
        &self,
        principal: &browserd_auth::AuthenticatedPrincipal,
        command: ArtifactRequest,
    ) -> Result<ApiResponse, ApiError> {
        let Some(record) = self.live_artifact_record(principal.tenant_id(), &command.session_id)?
        else {
            return self.get_retained_artifact(principal, command);
        };
        let receipt = match self
            .request_worker(WorkerRpcRequest::GetArtifact {
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
        let worker_id = self
            .placement_authority(tenant_id, &receipt.fence.session_id)?
            .map(|authority| authority.entry().fence().worker_id().clone())
            .unwrap_or_else(|| self.placement.worker_id.clone());
        if proposal
            .typed_binding()
            .is_some_and(|binding| binding.fence.worker_id != worker_id)
        {
            return Err(ApiError::new(
                ErrorCode::PlacementMismatch,
                "worker approval belongs to a different worker",
            ));
        }
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
            let response = match self.request_worker(WorkerRpcRequest::GetApproval {
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
                .request_worker(WorkerRpcRequest::ListApprovals {
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
            .request_worker(WorkerRpcRequest::DecideApproval {
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
    fn manages_create_admission(&self) -> bool {
        self.fleet.is_some()
    }
    fn create_projection_committed(
        &self,
        authority: &CreateAuthority,
        dispatch: &SessionCreateDispatch,
        session: &SessionResource,
    ) -> Result<(), ApiError> {
        if self.fleet.is_some() {
            self.ack_fleet_projection(authority.tenant_id(), dispatch.operation_id(), &session.id)?;
        }
        Ok(())
    }

    fn create_session(
        &self,
        authority: &CreateAuthority,
        dispatch: &SessionCreateDispatch,
        request: &SessionCreateRequest,
    ) -> RuntimeCreateResult {
        if self.fleet.is_some() {
            return self.create_fleet_session(authority, dispatch, request);
        }
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
            // Preserve the canonical request for exact lost-response recovery. The worker
            // applies current safety only when starting an actual unreserved context.
            requested_isolation: match request.isolation {
                IsolationRequest::SharedContext => WorkerIsolationProfile::SharedContext,
                IsolationRequest::TenantDedicatedShard => {
                    WorkerIsolationProfile::TenantDedicatedShard
                }
                IsolationRequest::DedicatedProcess => WorkerIsolationProfile::DedicatedProcess,
                IsolationRequest::DedicatedWorker => WorkerIsolationProfile::DedicatedWorker,
            },
            options_version: WORKER_SESSION_OPTIONS_VERSION,
            options: WorkerSessionOptionsV1 {
                workload_class_hint: request.workload_class_hint.clone(),
                viewport: WorkerViewport {
                    width: request.viewport.width,
                    height: request.viewport.height,
                    device_scale_factor: request.viewport.device_scale_factor,
                },
                locale: request.locale.clone(),
                timezone: request.timezone.clone(),
                user_agent: request.user_agent.clone(),
                network_policy_id: request.network_policy_id.clone(),
                network_class: request.network_class.clone(),
                checkpoint_ref: request.checkpoint_ref.clone(),
                dialog_policy: request.dialog_policy.clone(),
                feature_profile: request.feature_profile.clone(),
                ttl_seconds: request.ttl_seconds,
                idle_timeout_seconds: request.idle_timeout_seconds,
                metadata: request.metadata.clone(),
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
            || match (&request.checkpoint_ref, &receipt.restored_checkpoint) {
                (None, None) => false,
                (Some(expected), Some(restored)) => {
                    restored.checkpoint_ref != *expected
                        || restored.source_session_id == receipt.session_id
                }
                _ => true,
            }
        {
            return RuntimeCreateResult::OutcomeUnknown(ApiError::new(
                ErrorCode::PlacementMismatch,
                "worker returned a mismatched creation receipt",
            ));
        }
        let mut metadata = request.metadata.clone();
        metadata.remove("restored_from_checkpoint");
        metadata.remove("recovered_from_session");
        if let Some(restored) = &receipt.restored_checkpoint {
            metadata.insert(
                "restored_from_checkpoint".to_owned(),
                restored.checkpoint_ref.clone(),
            );
            metadata.insert(
                "recovered_from_session".to_owned(),
                restored.source_session_id.to_string(),
            );
        }
        let mut resource = SessionResource {
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
            metadata,
        };
        let fence = WorkerSessionFence {
            tenant_id: receipt.tenant_id,
            session_id: receipt.session_id,
            worker_epoch: receipt.worker_epoch,
            placement_version: receipt.placement_version,
            session_incarnation: receipt.session_incarnation,
        };
        let directory_fence = match DirectoryFence::new(
            self.placement.worker_id.clone(),
            fence.worker_epoch,
            fence.placement_version,
            fence.session_incarnation,
        ) {
            Ok(directory_fence) => directory_fence,
            Err(_) => {
                return RuntimeCreateResult::OutcomeUnknown(ApiError::new(
                    ErrorCode::Internal,
                    "worker placement could not be represented durably",
                ));
            }
        };
        let action_placement =
            match GatewayActionPlacement::new(directory_fence, self.placement.directory_revision) {
                Ok(action_placement) => action_placement,
                Err(_) => {
                    return RuntimeCreateResult::OutcomeUnknown(ApiError::new(
                        ErrorCode::Internal,
                        "worker directory revision could not be represented durably",
                    ));
                }
            };
        if self.durable_sessions {
            resource = match self.publish_durable_session(
                authority.tenant_id(),
                &action_placement,
                &resource,
            ) {
                Ok(resource) => resource,
                Err(error) => return RuntimeCreateResult::OutcomeUnknown(error),
            };
        }
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
            if let Some(existing) = sessions.get_mut(&key) {
                existing.fence = fence;
                existing.action_placement = action_placement;
                existing.resource = resource.clone();
            } else {
                if sessions.len() >= 16_384 {
                    return RuntimeCreateResult::OutcomeUnknown(ApiError::new(
                        ErrorCode::GlobalCapacityExceeded,
                        "session cache is full",
                    ));
                }
                sessions.insert(
                    key,
                    GatewaySessionRecord {
                        fence,
                        action_placement,
                        resource: resource.clone(),
                        admission_lane: Arc::new(SessionAdmissionLane::default()),
                        retired_at: matches!(
                            resource.lifecycle,
                            SessionLifecycle::Closed | SessionLifecycle::Failed
                        )
                        .then(Utc::now),
                    },
                );
            }
        }
        if let Err(error) =
            self.catalog
                .upsert(authority.tenant_id().clone(), resource.clone(), Utc::now())
        {
            return RuntimeCreateResult::OutcomeUnknown(error);
        }
        RuntimeCreateResult::Succeeded(resource)
    }

    fn execute_runtime_with_action_acceptance(
        &self,
        principal: &browserd_auth::AuthenticatedPrincipal,
        request: ApiRequest,
        accepted: &mut (dyn FnMut(ApiEnvelope<ActionSnapshot>) + Send),
    ) -> Result<ApiResponse, ApiError> {
        match request {
            ApiRequest::SubmitAction(command) => {
                self.submit_action_observed(principal, command, accepted)
            }
            request => self.execute_runtime(principal, request),
        }
    }

    fn execute_runtime(
        &self,
        principal: &browserd_auth::AuthenticatedPrincipal,
        request: ApiRequest,
    ) -> Result<ApiResponse, ApiError> {
        match request {
            ApiRequest::ListSessions(query) => {
                let page = if self.durable_sessions && self.fleet.is_none() {
                    self.list_durable_sessions(principal.tenant_id(), &query)
                } else {
                    self.catalog.list(principal.tenant_id(), &query)
                }?;
                Ok(ApiResponse::Sessions(ApiEnvelope::new(page)))
            }
            ApiRequest::GetSession(session_id) => {
                let record = self.session_record(principal.tenant_id(), &session_id)?;
                if self.durable_sessions
                    && self.fleet.is_none()
                    && matches!(
                        record.resource.lifecycle,
                        SessionLifecycle::Closed | SessionLifecycle::Failed
                    )
                {
                    return Ok(ApiResponse::Session(ApiEnvelope::new(record.resource)));
                }
                let receipt = match self
                    .request_worker(WorkerRpcRequest::GetSession {
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
                self.confirm_session_terminal(&record, receipt.lifecycle)?;
                if self.durable_sessions && self.fleet.is_none() {
                    self.persist_directory_phase(
                        principal.tenant_id(),
                        &session_id,
                        &receipt.fence,
                        receipt.lifecycle,
                    )?;
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
                        if matches!(
                            resource.lifecycle,
                            SessionLifecycle::Closed | SessionLifecycle::Failed
                        ) {
                            current.retired_at.get_or_insert_with(Utc::now);
                        }
                    } else {
                        resource = current.resource.clone();
                    }
                }
                self.catalog
                    .upsert(principal.tenant_id().clone(), resource.clone(), Utc::now())?;
                Ok(ApiResponse::Session(ApiEnvelope::new(resource)))
            }
            ApiRequest::DeleteSession(session_id) => {
                if self.durable_sessions && self.fleet.is_none() {
                    self.session_record(principal.tenant_id(), &session_id)?;
                }
                if self.fleet.is_some() {
                    self.session_record(principal.tenant_id(), &session_id)?;
                    self.begin_fleet_close(principal.tenant_id(), &session_id)?;
                }
                let record = {
                    let mut sessions = self.sessions.lock().map_err(|_| {
                        ApiError::new(ErrorCode::WorkerUnavailable, "session state unavailable")
                    })?;
                    let record = sessions
                        .get_mut(&(principal.tenant_id().clone(), session_id.clone()))
                        .ok_or_else(|| {
                            ApiError::new(ErrorCode::SessionNotFound, "session not found")
                        })?;
                    if matches!(
                        record.resource.lifecycle,
                        SessionLifecycle::Creating | SessionLifecycle::Ready
                    ) {
                        record.resource.lifecycle = SessionLifecycle::Closing;
                    }
                    record.clone()
                };
                self.catalog.upsert(
                    principal.tenant_id().clone(),
                    record.resource.clone(),
                    Utc::now(),
                )?;
                if self.durable_sessions
                    && self.fleet.is_none()
                    && record.resource.lifecycle == SessionLifecycle::Closing
                {
                    self.persist_directory_phase(
                        principal.tenant_id(),
                        &session_id,
                        &record.fence,
                        WorkerSessionLifecycle::Closing,
                    )?;
                }
                if matches!(
                    record.resource.lifecycle,
                    SessionLifecycle::Closed | SessionLifecycle::Failed
                ) {
                    return Ok(ApiResponse::SessionClosed(ApiEnvelope::new(
                        record.resource,
                    )));
                }
                let admission_lane = Arc::clone(&record.admission_lane);
                let _admission = admission_lane.acquire()?;
                let receipt = match self
                    .request_worker(WorkerRpcRequest::CloseSession {
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
                self.confirm_session_terminal(&record, receipt.lifecycle)?;
                if self.durable_sessions && self.fleet.is_none() {
                    self.persist_directory_phase(
                        principal.tenant_id(),
                        &session_id,
                        &receipt.fence,
                        receipt.lifecycle,
                    )?;
                }
                if self.fleet.is_some()
                    && matches!(
                        receipt.lifecycle,
                        WorkerSessionLifecycle::Closed | WorkerSessionLifecycle::Failed
                    )
                {
                    self.finish_fleet_close(principal.tenant_id(), &session_id)?;
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
                        if matches!(
                            resource.lifecycle,
                            SessionLifecycle::Closed | SessionLifecycle::Failed
                        ) {
                            current.retired_at.get_or_insert_with(Utc::now);
                        }
                    } else {
                        resource = current.resource.clone();
                    }
                }
                self.catalog
                    .upsert(principal.tenant_id().clone(), resource.clone(), Utc::now())?;
                Ok(ApiResponse::SessionClosed(ApiEnvelope::new(resource)))
            }
            ApiRequest::IssueViewerTicket(command) => self.issue_viewer_ticket(principal, command),
            ApiRequest::ListPages(command) => self.list_pages(principal, command),
            ApiRequest::CreatePage(command) => self.create_page(principal, command),
            ApiRequest::DeletePage(command) => self.delete_page(principal, command),
            ApiRequest::ActivatePage(command) => self.activate_page(principal, command),
            ApiRequest::SubmitAction(command) => self.submit_action(principal, command),
            ApiRequest::GetAction(command) => self.get_action(principal, command),
            ApiRequest::CancelAction(command) => self.cancel_action(principal, command),
            ApiRequest::ResolveAction(command) => self.resolve_action(principal, command),
            ApiRequest::GetArtifact(command) => self.get_artifact(principal, command),
            ApiRequest::ListArtifacts(command) => self.list_artifacts(principal, command),
            ApiRequest::UploadArtifact(command) => self.upload_artifact(principal, command),
            ApiRequest::DownloadArtifact(command) => {
                self.issue_artifact_download(principal, command)
            }
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
