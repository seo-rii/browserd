//! Fenced, transport-neutral browser worker control plane.

#![forbid(unsafe_code)]

mod cdp_driver;
mod chromium_owner;
mod production_sandbox;
mod rpc;
mod shard_actor;
mod shard_driver;
mod target_manager;

pub use cdp_driver::CdpChromiumDriver;
pub use chromium_owner::{
    ChromiumConnectionOwner, ChromiumTargetManager, ChromiumTargetManagerBackend,
    ChromiumTargetRoute,
};
pub use production_sandbox::{
    CdpPipeAcceptor, ProductionSandboxShardRuntime, SandboxShardRpc, ShardLaunchDescriptor,
};
pub use rpc::{
    WORKER_RPC_PROTOCOL_VERSION, WorkerActionApprovalRequirement, WorkerActionReceipt,
    WorkerActionStatus, WorkerApprovalActionType, WorkerApprovalDecision, WorkerApprovalReceipt,
    WorkerApprovalState, WorkerArtifactReceipt, WorkerArtifactSource, WorkerArtifactState,
    WorkerCanonicalActionProposal, WorkerControlPlaneRpcHandler, WorkerCreateSessionReceipt,
    WorkerCreateSessionRequest, WorkerIsolationProfile, WorkerPageReceipt, WorkerProbeReceipt,
    WorkerRpcBlockingClient, WorkerRpcClient, WorkerRpcConfig, WorkerRpcError, WorkerRpcFailure,
    WorkerRpcFailureCode, WorkerRpcHandler, WorkerRpcRequest, WorkerRpcResponse, WorkerRpcServer,
    WorkerSessionFence, WorkerSessionLifecycle, WorkerSessionReceipt,
};
pub use shard_actor::{
    AttachSessionOutcome, BrowserShardActor, BrowserShardActorConfig, BrowserShardRuntime,
    BrowserShardSnapshot, DetachSessionOutcome, ShardActorError, ShardRuntimeError,
};
pub use shard_driver::{ActorChromiumDriver, ChromiumDriverShardRuntime};
pub use target_manager::{
    ProductionTargetManager, TargetBootstrapSnapshot, TargetManagedShardRuntime,
    TargetManagerBackend, TargetManagerDrain, TargetManagerEvent, TargetManagerIngress,
    TargetManagerIngressError,
};

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use browserd_actions::{
    AcceptDecision, ActionJournalLimits, ActionKind, ActionLedger, ActionLedgerError,
    ActionRequest, ActionSequence, ApprovalDecision as ActionApprovalDecision, BrowserResult,
    CanonicalRequestHash as ActionRequestHash, DispatchDecision, DispatchPermit, FileActionJournal,
    IdempotencyKey as ActionIdempotencyKey, KnownFailureReason, LedgerSession,
    OutcomeUnknownReason, ResolutionAnnotation, ResolutionKind, ResolutionOutcome,
    ResolutionPolicy, ResultDigest, TerminalDetail, TransportLoss,
};
use browserd_artifacts::{
    Artifact, ArtifactChecksum, ArtifactContentMetadata, ArtifactContentSource, ArtifactEvent,
    ArtifactKey, ArtifactObjectGeneration, ArtifactState,
};
use browserd_core::{
    ActionId, ActionState, ArtifactId, IsolationProfile, OperationId, PageId, PrincipalId,
    SessionExecution, SessionId, TenantId, WorkerId,
};
use browserd_features::{BuiltinFeature, FeatureRegistry};
use browserd_fleet::WorkerEpochRegistry;
use browserd_operations::{
    CanonicalRequestHash, IdempotencyClaim, IdempotencyKey, IdempotencyRegistry,
};
use browserd_policy::{
    ActionArgumentsHash, ActionType, ApprovalAuthorizationError, ApprovalDecision, ApprovalError,
    ApprovalRequest, ApprovalState, CanonicalActionProposal, EmergencyPolicy, ExecutionContext,
    NodeReference, Origin, ProposalHash, StaleApprovalReason,
};
use browserd_sandbox::CleanupReason;
use browserd_session::{
    CleanupBackend, CleanupFailure, CleanupStage, ExpireDecision, LeasePolicy, OwnershipFence,
    SessionError, SessionLifecycle, SessionMachine, SessionSnapshot, SessionTime,
    SessionTimeoutPolicy, TargetId,
};
use browserd_viewer::{TicketPolicy, TicketRegistry, ViewerScopes, ViewerTicket};
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub use browserd_core::ApprovalId;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkerError {
    InvalidConfiguration,
    UnauthorizedPeer,
    NotReady,
    Draining,
    Stopped,
    StateUnavailable,
    CapacityExceeded,
    SessionNotFound,
    StaleFence,
    IdempotencyConflict,
    QueueFull,
    PageNotFound,
    ActionNotFound,
    ApprovalNotFound,
    ApprovalEvidenceMismatch,
    ApprovalPolicy(ApprovalError),
    ArtifactNotFound,
    InvalidActionTransition,
    InvalidApprovalTransition,
    DurabilityUnavailable,
    DependencyUnavailable,
    CleanupFailed,
}

/// Trusted UTC clock in the same Unix-millisecond domain as approval proposal deadlines and all
/// externally supplied [`SessionTime`] values.
///
/// Implementations must return promptly and must not re-enter worker or policy APIs. Approval
/// admission samples this clock while holding only its short policy-linearization locks.
pub trait WorkerClock: Send + Sync + 'static {
    fn now(&self) -> Result<SessionTime, WorkerError>;
}

#[derive(Default)]
pub struct SystemWorkerClock;

impl WorkerClock for SystemWorkerClock {
    fn now(&self) -> Result<SessionTime, WorkerError> {
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| WorkerError::StateUnavailable)?;
        let unix_millis =
            u64::try_from(elapsed.as_millis()).map_err(|_| WorkerError::StateUnavailable)?;
        Ok(SessionTime::new(unix_millis))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DependencyError {
    Unavailable,
    Rejected,
    OutcomeUncertain,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ActionExecutionResult {
    Succeeded(Vec<u8>),
    FailedKnown(String),
    OutcomeUnknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiveApprovalContext {
    pub target_incarnation: u64,
    pub frame_document_epoch: u64,
    pub current_origin: Origin,
    pub url_revision: u64,
    pub node_ref: Option<NodeReference>,
    pub node_valid: bool,
    pub resolved_ips: Vec<IpAddr>,
    pub credential_refs: Vec<String>,
    pub chromium_build: String,
    pub effective_isolation: IsolationProfile,
}

impl LiveApprovalContext {
    #[must_use]
    pub fn stale_reason(&self, observed: &Self) -> Option<StaleApprovalReason> {
        if self.target_incarnation != observed.target_incarnation {
            Some(StaleApprovalReason::TargetIncarnation)
        } else if self.frame_document_epoch != observed.frame_document_epoch {
            Some(StaleApprovalReason::DocumentEpoch)
        } else if self.current_origin != observed.current_origin {
            Some(StaleApprovalReason::Origin)
        } else if self.url_revision != observed.url_revision {
            Some(StaleApprovalReason::UrlRevision)
        } else if !observed.node_valid
            || self.node_valid != observed.node_valid
            || self.node_ref != observed.node_ref
        {
            Some(StaleApprovalReason::Node)
        } else if self.credential_refs != observed.credential_refs {
            Some(StaleApprovalReason::CredentialRefs)
        } else if self.resolved_ips != observed.resolved_ips
            || self.chromium_build != observed.chromium_build
            || self.effective_isolation != observed.effective_isolation
        {
            Some(StaleApprovalReason::ActionBinding)
        } else {
            None
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApprovedActionError {
    ApprovalStale(StaleApprovalReason),
    DispatchRevoked,
    Unavailable,
    OutcomeUncertain,
}

enum ApprovalAdmissionClockError {
    Clock(WorkerError),
    PlacementOwnershipInvalid(SessionTime),
}

pub trait ChromiumDriver: Send + Sync + 'static {
    fn qualify(&self) -> Result<(), DependencyError>;
    fn shard_managed_contexts(&self) -> bool {
        false
    }
    fn create_context(&self, session_id: &SessionId) -> Result<PageId, DependencyError>;
    fn create_context_fenced(
        &self,
        session_id: &SessionId,
        _fence: &OwnershipFence,
    ) -> Result<PageId, DependencyError> {
        self.create_context(session_id)
    }
    fn create_context_owned(
        &self,
        _tenant_id: &TenantId,
        session_id: &SessionId,
        fence: &OwnershipFence,
    ) -> Result<PageId, DependencyError> {
        self.create_context_fenced(session_id, fence)
    }
    fn close_context(&self, session_id: &SessionId) -> Result<(), DependencyError>;
    fn close_context_fenced(
        &self,
        session_id: &SessionId,
        _fence: &OwnershipFence,
    ) -> Result<(), DependencyError> {
        self.close_context(session_id)
    }
    fn create_page(&self, session_id: &SessionId) -> Result<PageId, DependencyError>;
    fn close_page(&self, session_id: &SessionId, page_id: &PageId) -> Result<(), DependencyError>;
    fn activate_page(
        &self,
        session_id: &SessionId,
        page_id: &PageId,
    ) -> Result<(), DependencyError>;
    fn execute_action(
        &self,
        session_id: &SessionId,
        page_id: Option<&PageId>,
        payload: &[u8],
    ) -> ActionExecutionResult;
    fn inspect_approval_context(
        &self,
        session_id: &SessionId,
        page_id: &PageId,
        proposal: &CanonicalActionProposal,
    ) -> Result<LiveApprovalContext, DependencyError>;
    /// Reobserves the proposal target and invokes `authorize_and_commit` at the effect-start
    /// boundary.
    ///
    /// Implementations must serialize this boundary with `cancel_action`, `close_page`, and
    /// `close_context`: they reject any difference from `inspected` with an exact
    /// [`ApprovedActionError::ApprovalStale`] reason, perform no browser effect when
    /// `authorize_and_commit` rejects, and begin the effect before target cancellation or disposal
    /// can complete after it accepts. The callback performs the short worker/policy admission;
    /// those locks are released before the browser operation completes.
    fn execute_approved_action(
        &self,
        session_id: &SessionId,
        page_id: &PageId,
        payload: &[u8],
        proposal: &CanonicalActionProposal,
        inspected: &LiveApprovalContext,
        authorize_and_commit: &mut dyn FnMut(
            &LiveApprovalContext,
        ) -> Result<(), ApprovedActionError>,
    ) -> Result<ActionExecutionResult, ApprovedActionError>;
    fn cancel_action(
        &self,
        session_id: &SessionId,
        action_id: &ActionId,
    ) -> Result<bool, DependencyError>;
}

pub trait SandboxClient: Send + Sync + 'static {
    fn qualify(&self) -> Result<(), DependencyError>;
    fn provision(
        &self,
        session_id: &SessionId,
        fence: &OwnershipFence,
    ) -> Result<(), DependencyError>;
    fn cleanup(&self, session_id: &SessionId, reason: CleanupReason)
    -> Result<(), DependencyError>;
    fn heartbeat(&self, worker_id: &WorkerId, worker_epoch: u64) -> Result<(), DependencyError>;
    fn store_artifact(
        &self,
        request: &ArtifactStoreRequest,
    ) -> Result<ArtifactStoreReceipt, DependencyError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedPeer(String);

impl AuthenticatedPeer {
    pub fn new(identity: impl Into<String>) -> Result<Self, WorkerError> {
        let identity = identity.into();
        if identity.is_empty()
            || identity.trim() != identity
            || identity.len() > 255
            || identity.chars().any(char::is_control)
        {
            return Err(WorkerError::InvalidConfiguration);
        }
        Ok(Self(identity))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InternalEndpoint {
    Loopback(SocketAddr),
    Unix(PathBuf),
}

impl InternalEndpoint {
    pub fn loopback(address: SocketAddr) -> Result<Self, WorkerError> {
        if !address.ip().is_loopback() || address.port() == 0 {
            return Err(WorkerError::InvalidConfiguration);
        }
        Ok(Self::Loopback(address))
    }

    pub fn unix(path: impl Into<PathBuf>) -> Result<Self, WorkerError> {
        let path = path.into();
        if !path.is_absolute() || path.as_os_str().is_empty() {
            return Err(WorkerError::InvalidConfiguration);
        }
        Ok(Self::Unix(path))
    }
}

#[derive(Clone, Debug)]
pub struct ActionJournalConfig {
    directory: PathBuf,
    limits: ActionJournalLimits,
}

impl ActionJournalConfig {
    pub fn new(
        directory: impl Into<PathBuf>,
        limits: ActionJournalLimits,
    ) -> Result<Self, WorkerError> {
        let directory = directory.into();
        let config = Self { directory, limits };
        if !config.directory.is_absolute()
            || config.directory.as_os_str().is_empty()
            || !config.qualify()
        {
            return Err(WorkerError::InvalidConfiguration);
        }
        Ok(config)
    }

    pub fn with_default_limits(directory: impl Into<PathBuf>) -> Result<Self, WorkerError> {
        Self::new(directory, ActionJournalLimits::default())
    }

    fn session_path(&self, session_id: &SessionId) -> PathBuf {
        self.directory.join(format!("{session_id}.wal"))
    }

    fn qualify(&self) -> bool {
        if self.limits.max_record_bytes() == 0
            || self.limits.max_records() == 0
            || self.limits.max_file_bytes() < 8
        {
            return false;
        }
        std::fs::symlink_metadata(&self.directory).is_ok_and(|metadata| {
            metadata.is_dir() && !metadata.file_type().is_symlink() && metadata.mode() & 0o022 == 0
        })
    }
}

#[derive(Clone, Debug)]
pub struct WorkerConfig {
    worker_id: WorkerId,
    worker_epoch: u64,
    endpoint: InternalEndpoint,
    trusted_peer: AuthenticatedPeer,
    max_sessions: usize,
    action_queue_capacity: usize,
    lease_policy: LeasePolicy,
    timeout_policy: SessionTimeoutPolicy,
    approval_timeout_millis: u64,
    action_journal: ActionJournalConfig,
    artifact_limits: WorkerArtifactLimits,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkerArtifactLimits {
    max_file_bytes: u64,
    max_committed_bytes: u64,
    max_in_flight_bytes: u64,
}

impl WorkerArtifactLimits {
    pub const DEFAULT_MAX_FILE_BYTES: u64 = 50 * 1024 * 1024;
    pub const DEFAULT_MAX_COMMITTED_BYTES: u64 = 500 * 1024 * 1024;
    pub const DEFAULT_MAX_IN_FLIGHT_BYTES: u64 = 128 * 1024 * 1024;

    pub const fn new(
        max_file_bytes: u64,
        max_committed_bytes: u64,
        max_in_flight_bytes: u64,
    ) -> Result<Self, WorkerError> {
        if max_file_bytes == 0
            || max_committed_bytes == 0
            || max_in_flight_bytes == 0
            || max_file_bytes > max_committed_bytes
            || max_file_bytes > max_in_flight_bytes
        {
            return Err(WorkerError::InvalidConfiguration);
        }
        Ok(Self {
            max_file_bytes,
            max_committed_bytes,
            max_in_flight_bytes,
        })
    }
}

impl Default for WorkerArtifactLimits {
    fn default() -> Self {
        Self {
            max_file_bytes: Self::DEFAULT_MAX_FILE_BYTES,
            max_committed_bytes: Self::DEFAULT_MAX_COMMITTED_BYTES,
            max_in_flight_bytes: Self::DEFAULT_MAX_IN_FLIGHT_BYTES,
        }
    }
}

impl WorkerConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        worker_id: WorkerId,
        worker_epoch: u64,
        endpoint: InternalEndpoint,
        trusted_peer: AuthenticatedPeer,
        max_sessions: usize,
        action_queue_capacity: usize,
        lease_policy: LeasePolicy,
        timeout_policy: SessionTimeoutPolicy,
        approval_timeout: Duration,
        action_journal: ActionJournalConfig,
    ) -> Result<Self, WorkerError> {
        let approval_timeout_millis = u64::try_from(approval_timeout.as_millis())
            .map_err(|_| WorkerError::InvalidConfiguration)?;
        if worker_epoch == 0
            || max_sessions == 0
            || action_queue_capacity == 0
            || approval_timeout_millis == 0
        {
            return Err(WorkerError::InvalidConfiguration);
        }
        Ok(Self {
            worker_id,
            worker_epoch,
            endpoint,
            trusted_peer,
            max_sessions,
            action_queue_capacity,
            lease_policy,
            timeout_policy,
            approval_timeout_millis,
            action_journal,
            artifact_limits: WorkerArtifactLimits::default(),
        })
    }

    #[must_use]
    pub const fn with_artifact_limits(mut self, limits: WorkerArtifactLimits) -> Self {
        self.artifact_limits = limits;
        self
    }

    pub const fn endpoint(&self) -> &InternalEndpoint {
        &self.endpoint
    }

    pub const fn worker_id(&self) -> &WorkerId {
        &self.worker_id
    }

    pub const fn worker_epoch(&self) -> u64 {
        self.worker_epoch
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateSessionCommand {
    pub tenant_id: TenantId,
    pub idempotency_key: String,
    pub canonical_request_hash: [u8; 32],
    pub placement_version: u64,
    pub session_incarnation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateSessionOutcome {
    pub operation_id: OperationId,
    pub session_id: SessionId,
    pub primary_page_id: PageId,
    pub fence: OwnershipFence,
    pub existing: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActionStatus {
    PendingApproval,
    Queued,
    Running,
    Succeeded,
    FailedKnown,
    CancelledBeforeDispatch,
    CancelledConfirmed,
    OutcomeUnknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerActionSnapshot {
    pub action_id: ActionId,
    pub action_sequence: ActionSequence,
    pub idempotency_key: String,
    pub canonical_request_hash: [u8; 32],
    pub status: ActionStatus,
    pub kind: ActionKind,
    pub dispatch_acknowledged: bool,
    pub approval_decision: Option<ActionApprovalDecision>,
    pub terminal_detail: Option<TerminalDetail>,
    pub feature: Option<BuiltinFeature>,
    pub result: Option<Vec<u8>>,
    pub resolution: Option<ResolutionAnnotation>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerPageSnapshot {
    pub page_id: PageId,
    pub active: bool,
    pub target_incarnation: u64,
    pub document_epoch: u64,
    pub url_revision: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactUpload {
    pub bytes: Vec<u8>,
    pub content_type: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactScanVerdict {
    Clean,
    Quarantined,
    Rejected,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactStoreRequest {
    key: ArtifactKey,
    fence: OwnershipFence,
    bytes: Vec<u8>,
    declared_content_type: String,
    expected_size_bytes: u64,
    expected_checksum: ArtifactChecksum,
    max_bytes: u64,
}

impl ArtifactStoreRequest {
    #[must_use]
    pub const fn key(&self) -> &ArtifactKey {
        &self.key
    }

    #[must_use]
    pub const fn fence(&self) -> &OwnershipFence {
        &self.fence
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub fn declared_content_type(&self) -> &str {
        &self.declared_content_type
    }

    #[must_use]
    pub const fn expected_size_bytes(&self) -> u64 {
        self.expected_size_bytes
    }

    #[must_use]
    pub const fn expected_checksum(&self) -> &ArtifactChecksum {
        &self.expected_checksum
    }

    #[must_use]
    pub const fn max_bytes(&self) -> u64 {
        self.max_bytes
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactStoreReceipt {
    key: ArtifactKey,
    size_bytes: u64,
    checksum: ArtifactChecksum,
    detected_content_type: String,
    object_generation: ArtifactObjectGeneration,
    scan_verdict: ArtifactScanVerdict,
}

impl ArtifactStoreReceipt {
    pub fn new(
        key: ArtifactKey,
        size_bytes: u64,
        checksum: ArtifactChecksum,
        detected_content_type: impl Into<String>,
        object_generation: ArtifactObjectGeneration,
        scan_verdict: ArtifactScanVerdict,
    ) -> Result<Self, WorkerError> {
        let detected_content_type = detected_content_type.into();
        ArtifactContentMetadata::new(
            size_bytes,
            checksum,
            detected_content_type.clone(),
            ArtifactContentSource::ClientUpload,
            "artifact-store-receipt",
        )
        .map_err(|_| WorkerError::InvalidConfiguration)?;
        Ok(Self {
            key,
            size_bytes,
            checksum,
            detected_content_type,
            object_generation,
            scan_verdict,
        })
    }

    #[must_use]
    pub const fn key(&self) -> &ArtifactKey {
        &self.key
    }

    #[must_use]
    pub const fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    #[must_use]
    pub const fn checksum(&self) -> &ArtifactChecksum {
        &self.checksum
    }

    #[must_use]
    pub fn detected_content_type(&self) -> &str {
        &self.detected_content_type
    }

    #[must_use]
    pub const fn object_generation(&self) -> ArtifactObjectGeneration {
        self.object_generation
    }

    #[must_use]
    pub const fn scan_verdict(&self) -> ArtifactScanVerdict {
        self.scan_verdict
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerArtifactSnapshot {
    pub artifact_id: ArtifactId,
    pub state: ArtifactState,
    pub size_bytes: u64,
    pub checksum_sha256: [u8; 32],
    pub content_type: String,
    pub source: ArtifactContentSource,
    pub origin: String,
    pub object_generation: ArtifactObjectGeneration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerApprovalSnapshot {
    pub approval_id: ApprovalId,
    pub action_id: ActionId,
    pub state: ApprovalState,
    pub proposal_hash: ProposalHash,
    pub proposal: CanonicalActionProposal,
}

#[derive(Clone, Debug)]
pub struct ActionApprovalRequirement {
    proposal: CanonicalActionProposal,
    action_type: ActionType,
    require_four_eyes: bool,
}

impl ActionApprovalRequirement {
    #[must_use]
    pub const fn new(
        proposal: CanonicalActionProposal,
        action_type: ActionType,
        require_four_eyes: bool,
    ) -> Self {
        Self {
            proposal,
            action_type,
            require_four_eyes,
        }
    }

    #[must_use]
    pub const fn proposal(&self) -> &CanonicalActionProposal {
        &self.proposal
    }
}

struct ActionRecord {
    snapshot: WorkerActionSnapshot,
    requester_principal_id: PrincipalId,
    page_id: Option<PageId>,
    payload: Vec<u8>,
    approval_id: Option<ApprovalId>,
    dispatch_permit: Option<DispatchPermit>,
}

struct ArtifactRecord {
    artifact: Artifact,
    object_generation: ArtifactObjectGeneration,
}

struct ApprovalRecord {
    action_id: ActionId,
    state: ApprovalState,
    expires_at: SessionTime,
    proposal: CanonicalActionProposal,
    feature: String,
    require_four_eyes: bool,
    request: Option<Arc<ApprovalRequest>>,
}

struct SessionJournalGuard {
    path: PathBuf,
    committed: bool,
}

impl Drop for SessionJournalGuard {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        if std::fs::remove_file(&self.path).is_ok()
            && let Some(parent) = self.path.parent()
            && let Ok(directory) = File::open(parent)
        {
            let _ = directory.sync_all();
        }
    }
}

type ActionIdempotencyRecord = (
    [u8; 32],
    PrincipalId,
    Option<(ProposalHash, ActionType, bool)>,
    ActionId,
);

struct SessionState {
    tenant_id: TenantId,
    machine: SessionMachine,
    occupies_capacity: bool,
    primary_page_id: PageId,
    active_page_id: PageId,
    pages: BTreeSet<PageId>,
    closing_pages: BTreeSet<PageId>,
    closed_pages: BTreeSet<PageId>,
    action_idempotency: HashMap<String, ActionIdempotencyRecord>,
    actions: HashMap<ActionId, ActionRecord>,
    action_queue: VecDeque<ActionId>,
    artifacts: HashMap<ArtifactId, ArtifactRecord>,
    artifact_committed_bytes: u64,
    approvals: HashMap<ApprovalId, ApprovalRecord>,
    action_ledger: ActionLedger<FileActionJournal>,
    durability_degraded: bool,
}

struct SessionExecutor {
    state: Mutex<SessionState>,
    action_owner: AtomicBool,
    approved_dispatch_phase: AtomicU8,
    approved_dispatch_wait: Mutex<()>,
    approved_dispatch_changed: Condvar,
    cleanup_owner: Mutex<()>,
}

const APPROVED_DISPATCH_IDLE: u8 = 0;
const APPROVED_DISPATCH_INSPECTING: u8 = 1;
const APPROVED_DISPATCH_DRIVER_PENDING: u8 = 2;
const APPROVED_DISPATCH_AUTHORIZING: u8 = 3;
const APPROVED_DISPATCH_STARTED: u8 = 4;
const APPROVED_DISPATCH_STOPPED: u8 = 5;
const APPROVED_DISPATCH_REVOKE_REQUESTED: u8 = 6;
const APPROVED_DISPATCH_AUTHORIZATION_REJECTED: u8 = 7;
const APPROVED_DISPATCH_RETURNED_UNCERTAIN: u8 = 8;

struct CreateOperationWaiter {
    completion: Mutex<Option<Result<CreateSessionOutcome, WorkerError>>>,
    ready: Condvar,
}

#[derive(Clone)]
enum CreateOperationResult {
    Pending(Arc<CreateOperationWaiter>),
    Succeeded(CreateSessionOutcome),
    Failed(WorkerError),
}

struct WorkerState {
    sessions: HashMap<SessionId, Arc<SessionExecutor>>,
    create_operations: HashMap<OperationId, CreateOperationResult>,
    creating_sessions: usize,
    create_cleanup_failed: bool,
    draining: bool,
    stopped: bool,
    heartbeat_expires_at: Option<SessionTime>,
}

pub struct WorkerControlPlane<D, S> {
    config: WorkerConfig,
    driver: Arc<D>,
    sandbox: Arc<S>,
    state: Mutex<WorkerState>,
    create_idle: Condvar,
    create_idempotency: IdempotencyRegistry,
    viewer_tickets: Option<TicketRegistry>,
    emergency_policy: Arc<EmergencyPolicy>,
    clock: Arc<dyn WorkerClock>,
    stopped_dispatch_terminalization_hook: Arc<dyn Fn() -> Result<(), WorkerError> + Send + Sync>,
    _fleet_epochs: WorkerEpochRegistry,
    _features: FeatureRegistry,
}

impl<D: ChromiumDriver, S: SandboxClient> WorkerControlPlane<D, S> {
    #[must_use]
    pub fn new(config: WorkerConfig, driver: Arc<D>, sandbox: Arc<S>) -> Self {
        Self::new_with_emergency_policy(
            config,
            driver,
            sandbox,
            Arc::new(EmergencyPolicy::default()),
        )
    }

    #[must_use]
    pub fn new_with_clock<C: WorkerClock>(
        config: WorkerConfig,
        driver: Arc<D>,
        sandbox: Arc<S>,
        clock: Arc<C>,
    ) -> Self {
        Self::new_with_emergency_policy_and_clock(
            config,
            driver,
            sandbox,
            Arc::new(EmergencyPolicy::default()),
            clock,
        )
    }

    #[must_use]
    pub fn new_with_emergency_policy(
        config: WorkerConfig,
        driver: Arc<D>,
        sandbox: Arc<S>,
        emergency_policy: Arc<EmergencyPolicy>,
    ) -> Self {
        Self::new_with_emergency_policy_and_clock(
            config,
            driver,
            sandbox,
            emergency_policy,
            Arc::new(SystemWorkerClock),
        )
    }

    #[must_use]
    pub fn new_with_emergency_policy_and_clock<C: WorkerClock>(
        config: WorkerConfig,
        driver: Arc<D>,
        sandbox: Arc<S>,
        emergency_policy: Arc<EmergencyPolicy>,
        clock: Arc<C>,
    ) -> Self {
        Self::new_with_emergency_policy_and_clock_and_terminalization_hook(
            config,
            driver,
            sandbox,
            emergency_policy,
            clock,
            Arc::new(|| Ok(())),
        )
    }

    /// Test seam for exercising journal failures after dispatch revocation.
    #[doc(hidden)]
    #[must_use]
    pub fn new_with_emergency_policy_and_clock_and_terminalization_hook<
        C: WorkerClock,
        F: Fn() -> Result<(), WorkerError> + Send + Sync + 'static,
    >(
        config: WorkerConfig,
        driver: Arc<D>,
        sandbox: Arc<S>,
        emergency_policy: Arc<EmergencyPolicy>,
        clock: Arc<C>,
        stopped_dispatch_terminalization_hook: Arc<F>,
    ) -> Self {
        let fleet_epochs = WorkerEpochRegistry::new();
        let _ = fleet_epochs.register(config.worker_id.clone(), config.worker_epoch);
        let viewer_policy =
            TicketPolicy::new(Duration::from_secs(60), ["https://browserd.internal"]);
        let viewer_tickets = viewer_policy.ok().map(TicketRegistry::new);
        Self {
            config,
            driver,
            sandbox,
            state: Mutex::new(WorkerState {
                sessions: HashMap::new(),
                create_operations: HashMap::new(),
                creating_sessions: 0,
                create_cleanup_failed: false,
                draining: false,
                stopped: false,
                heartbeat_expires_at: None,
            }),
            create_idle: Condvar::new(),
            create_idempotency: IdempotencyRegistry::default(),
            viewer_tickets,
            emergency_policy,
            clock,
            stopped_dispatch_terminalization_hook,
            _fleet_epochs: fleet_epochs,
            _features: FeatureRegistry::builtin(),
        }
    }

    #[must_use]
    pub fn is_ready(&self) -> bool {
        let Ok(worker) = self.state.lock() else {
            return false;
        };
        if worker.draining || worker.stopped {
            return false;
        }
        let sessions = worker.sessions.values().cloned().collect::<Vec<_>>();
        drop(worker);
        sessions.iter().all(|executor| {
            executor
                .state
                .lock()
                .is_ok_and(|session| !session.durability_degraded)
        }) && self.config.action_journal.qualify()
            && self.driver.qualify().is_ok()
            && self.sandbox.qualify().is_ok()
    }

    pub fn create_session(
        &self,
        peer: &AuthenticatedPeer,
        command: CreateSessionCommand,
        now: SessionTime,
    ) -> Result<CreateSessionOutcome, WorkerError> {
        self.authorize(peer)?;
        if self.driver.qualify().is_err() || self.sandbox.qualify().is_err() {
            return Err(WorkerError::NotReady);
        }
        if command.placement_version == 0 || command.session_incarnation == 0 {
            return Err(WorkerError::InvalidConfiguration);
        }
        let key = IdempotencyKey::new(command.idempotency_key)
            .map_err(|_| WorkerError::InvalidConfiguration)?;
        let request_hash = CanonicalRequestHash::from_json(&Value::Array(
            command
                .canonical_request_hash
                .iter()
                .map(|byte| Value::from(*byte))
                .collect(),
        ));
        let (operation_id, waiter) = {
            let mut worker = self.lock_worker()?;
            if worker.stopped {
                return Err(WorkerError::Stopped);
            }
            if worker.draining {
                return Err(WorkerError::Draining);
            }
            let claim = self
                .create_idempotency
                .claim(command.tenant_id.clone(), key, request_hash, Instant::now())
                .map_err(|error| match error {
                    browserd_operations::IdempotencyError::Conflict { .. } => {
                        WorkerError::IdempotencyConflict
                    }
                    browserd_operations::IdempotencyError::CoordinationUnavailable => {
                        WorkerError::StateUnavailable
                    }
                })?;
            if let IdempotencyClaim::Existing(operation_id) = &claim {
                let existing = worker
                    .create_operations
                    .get(operation_id)
                    .cloned()
                    .ok_or(WorkerError::StateUnavailable)?;
                drop(worker);
                return match existing {
                    CreateOperationResult::Pending(waiter) => {
                        let mut completion = waiter
                            .completion
                            .lock()
                            .map_err(|_| WorkerError::StateUnavailable)?;
                        loop {
                            if let Some(result) = completion.clone() {
                                break result.map(|mut outcome| {
                                    outcome.existing = true;
                                    outcome
                                });
                            }
                            completion = waiter
                                .ready
                                .wait(completion)
                                .map_err(|_| WorkerError::StateUnavailable)?;
                        }
                    }
                    CreateOperationResult::Succeeded(mut outcome) => {
                        outcome.existing = true;
                        Ok(outcome)
                    }
                    CreateOperationResult::Failed(error) => Err(error),
                };
            }

            let operation_id = claim.operation_id().clone();
            let occupied = worker.sessions.values().try_fold(
                worker.creating_sessions,
                |count, executor| {
                    let session = executor
                        .state
                        .lock()
                        .map_err(|_| WorkerError::StateUnavailable)?;
                    Ok::<_, WorkerError>(
                        count.saturating_add(usize::from(session.occupies_capacity)),
                    )
                },
            )?;
            if occupied >= self.config.max_sessions {
                worker.create_operations.insert(
                    operation_id,
                    CreateOperationResult::Failed(WorkerError::CapacityExceeded),
                );
                return Err(WorkerError::CapacityExceeded);
            }
            let waiter = Arc::new(CreateOperationWaiter {
                completion: Mutex::new(None),
                ready: Condvar::new(),
            });
            worker.creating_sessions = worker.creating_sessions.saturating_add(1);
            worker.create_operations.insert(
                operation_id.clone(),
                CreateOperationResult::Pending(Arc::clone(&waiter)),
            );
            (operation_id, waiter)
        };

        let creation = (|| {
            let session_id = SessionId::new();
            let fence = OwnershipFence::new(
                self.config.worker_id.clone(),
                self.config.worker_epoch,
                command.placement_version,
                command.session_incarnation,
            );
            let journal_path = self.config.action_journal.session_path(&session_id);
            let journal =
                FileActionJournal::create_new(&journal_path, self.config.action_journal.limits)
                    .map_err(|_| WorkerError::DurabilityUnavailable)?;
            let journal_guard = SessionJournalGuard {
                path: journal_path,
                committed: false,
            };
            let action_ledger = ActionLedger::new(
                LedgerSession::new(
                    command.tenant_id.clone(),
                    session_id.clone(),
                    fence.as_placement_fence(),
                ),
                Arc::new(journal),
            );
            let (mut machine, _) = SessionMachine::create_with_timeouts(
                session_id.clone(),
                fence.clone(),
                self.config.lease_policy,
                self.config.timeout_policy,
                now,
            );
            machine
                .start(&fence, now)
                .and_then(|_| machine.mark_running(&fence, now))
                .map_err(map_session_error)?;
            if !self.driver.shard_managed_contexts()
                && self.sandbox.provision(&session_id, &fence).is_err()
            {
                return if self
                    .sandbox
                    .cleanup(&session_id, CleanupReason::BrowserFailure)
                    .is_ok()
                {
                    Err(WorkerError::DependencyUnavailable)
                } else {
                    Err(WorkerError::CleanupFailed)
                };
            }
            let primary_page_id =
                match self
                    .driver
                    .create_context_owned(&command.tenant_id, &session_id, &fence)
                {
                    Ok(page_id) => page_id,
                    Err(_) => {
                        let sandbox_clean = self.driver.shard_managed_contexts()
                            || self
                                .sandbox
                                .cleanup(&session_id, CleanupReason::BrowserFailure)
                                .is_ok();
                        return if sandbox_clean {
                            Err(WorkerError::DependencyUnavailable)
                        } else {
                            Err(WorkerError::CleanupFailed)
                        };
                    }
                };
            if let Err(error) = machine
                .register_target(&fence, TargetId::new(primary_page_id.to_string()))
                .map_err(map_session_error)
            {
                let driver_clean = self
                    .driver
                    .close_context_fenced(&session_id, &fence)
                    .is_ok();
                let sandbox_clean = self.driver.shard_managed_contexts()
                    || self
                        .sandbox
                        .cleanup(&session_id, CleanupReason::BrowserFailure)
                        .is_ok();
                return if driver_clean && sandbox_clean {
                    Err(error)
                } else {
                    Err(WorkerError::CleanupFailed)
                };
            }
            let mut pages = BTreeSet::new();
            pages.insert(primary_page_id.clone());
            let executor = Arc::new(SessionExecutor {
                state: Mutex::new(SessionState {
                    tenant_id: command.tenant_id,
                    machine,
                    occupies_capacity: true,
                    primary_page_id: primary_page_id.clone(),
                    active_page_id: primary_page_id.clone(),
                    pages,
                    closing_pages: BTreeSet::new(),
                    closed_pages: BTreeSet::new(),
                    action_idempotency: HashMap::new(),
                    actions: HashMap::new(),
                    action_queue: VecDeque::new(),
                    artifacts: HashMap::new(),
                    artifact_committed_bytes: 0,
                    approvals: HashMap::new(),
                    action_ledger,
                    durability_degraded: false,
                }),
                action_owner: AtomicBool::new(false),
                approved_dispatch_phase: AtomicU8::new(APPROVED_DISPATCH_IDLE),
                approved_dispatch_wait: Mutex::new(()),
                approved_dispatch_changed: Condvar::new(),
                cleanup_owner: Mutex::new(()),
            });
            Ok((
                CreateSessionOutcome {
                    operation_id: operation_id.clone(),
                    session_id,
                    primary_page_id,
                    fence,
                    existing: false,
                },
                executor,
                journal_guard,
            ))
        })();

        let terminal_result = match creation {
            Err(error) => {
                match self.lock_worker() {
                    Ok(mut worker) => {
                        worker.creating_sessions = worker.creating_sessions.saturating_sub(1);
                        worker.create_cleanup_failed |=
                            matches!(&error, WorkerError::CleanupFailed);
                        worker.create_operations.insert(
                            operation_id.clone(),
                            CreateOperationResult::Failed(error.clone()),
                        );
                    }
                    Err(_) => {
                        let mut completion = waiter
                            .completion
                            .lock()
                            .map_err(|_| WorkerError::StateUnavailable)?;
                        *completion = Some(Err(WorkerError::StateUnavailable));
                        waiter.ready.notify_all();
                        return Err(WorkerError::StateUnavailable);
                    }
                }
                self.create_idle.notify_all();
                Err(error)
            }
            Ok((outcome, executor, mut journal_guard)) => {
                let mut worker = match self.lock_worker() {
                    Ok(worker) => worker,
                    Err(_) => {
                        let _ = self
                            .driver
                            .close_context_fenced(&outcome.session_id, &outcome.fence);
                        if !self.driver.shard_managed_contexts() {
                            let _ = self
                                .sandbox
                                .cleanup(&outcome.session_id, CleanupReason::BrowserFailure);
                        }
                        let mut completion = waiter
                            .completion
                            .lock()
                            .map_err(|_| WorkerError::StateUnavailable)?;
                        *completion = Some(Err(WorkerError::StateUnavailable));
                        waiter.ready.notify_all();
                        return Err(WorkerError::StateUnavailable);
                    }
                };
                let rejected = if worker.stopped {
                    Some(WorkerError::Stopped)
                } else if worker.draining {
                    Some(WorkerError::Draining)
                } else {
                    None
                };
                if let Some(error) = rejected {
                    drop(worker);
                    let driver_clean = self
                        .driver
                        .close_context_fenced(&outcome.session_id, &outcome.fence)
                        .is_ok();
                    let sandbox_clean = self.driver.shard_managed_contexts()
                        || self
                            .sandbox
                            .cleanup(&outcome.session_id, CleanupReason::Administrative)
                            .is_ok();
                    drop(journal_guard);
                    let final_error = if driver_clean && sandbox_clean {
                        error
                    } else {
                        WorkerError::CleanupFailed
                    };
                    let mut worker = self.lock_worker()?;
                    worker.creating_sessions = worker.creating_sessions.saturating_sub(1);
                    worker.create_cleanup_failed |= !(driver_clean && sandbox_clean);
                    worker.create_operations.insert(
                        operation_id.clone(),
                        CreateOperationResult::Failed(final_error.clone()),
                    );
                    self.create_idle.notify_all();
                    Err(final_error)
                } else {
                    worker.sessions.insert(outcome.session_id.clone(), executor);
                    journal_guard.committed = true;
                    worker.creating_sessions = worker.creating_sessions.saturating_sub(1);
                    worker.create_operations.insert(
                        operation_id.clone(),
                        CreateOperationResult::Succeeded(outcome.clone()),
                    );
                    self.create_idle.notify_all();
                    Ok(outcome)
                }
            }
        };
        let mut completion = waiter
            .completion
            .lock()
            .map_err(|_| WorkerError::StateUnavailable)?;
        *completion = Some(terminal_result.clone());
        waiter.ready.notify_all();
        terminal_result
    }

    pub fn get_session(
        &self,
        peer: &AuthenticatedPeer,
        session_id: &SessionId,
        fence: &OwnershipFence,
    ) -> Result<SessionSnapshot, WorkerError> {
        self.authorize(peer)?;
        let executor = self.session(session_id)?;
        let session = executor
            .state
            .lock()
            .map_err(|_| WorkerError::StateUnavailable)?;
        validate_fence(&session, fence)?;
        Ok(session.machine.snapshot())
    }

    pub fn close_session(
        &self,
        peer: &AuthenticatedPeer,
        session_id: &SessionId,
        fence: &OwnershipFence,
        now: SessionTime,
    ) -> Result<SessionSnapshot, WorkerError> {
        self.authorize(peer)?;
        let executor = self.session(session_id)?;
        {
            let session = executor
                .state
                .lock()
                .map_err(|_| WorkerError::StateUnavailable)?;
            validate_fence(&session, fence)?;
        }
        let _cleanup_owner = executor
            .cleanup_owner
            .lock()
            .map_err(|_| WorkerError::StateUnavailable)?;
        let (mut session, approved_dispatch_phase) = loop {
            let session = executor
                .state
                .lock()
                .map_err(|_| WorkerError::StateUnavailable)?;
            validate_fence(&session, fence)?;
            match executor.approved_dispatch_phase.load(Ordering::Acquire) {
                APPROVED_DISPATCH_INSPECTING
                | APPROVED_DISPATCH_DRIVER_PENDING
                | APPROVED_DISPATCH_AUTHORIZING => {
                    drop(session);
                    stop_or_observe_approved_dispatch(&executor);
                }
                phase => break (session, phase),
            }
        };
        let stopped_dispatch_terminalization =
            if approved_dispatch_phase == APPROVED_DISPATCH_STOPPED {
                terminalize_stopped_approved_dispatch(
                    &mut session,
                    fence,
                    now,
                    &*self.stopped_dispatch_terminalization_hook,
                )
            } else {
                Ok(())
            };
        let lifecycle = session
            .machine
            .begin_close(fence, now)
            .map_err(map_session_error)?;
        let remaining_terminalization = terminalize_actions_for_shutdown(&mut session);
        let terminalization = match stopped_dispatch_terminalization {
            Ok(()) => remaining_terminalization,
            Err(first_error) => Err(first_error),
        };
        if lifecycle == SessionLifecycle::Closed {
            terminalization?;
            return Ok(session.machine.snapshot());
        }
        let mut cleanup_machine = session.machine.clone();
        drop(session);
        let mut cleanup = WorkerCleanup {
            driver: &*self.driver,
            sandbox: &*self.sandbox,
            session_id,
            fence,
        };
        let cleanup_result = cleanup_machine.run_cleanup(fence, &mut cleanup);
        let mut session = executor
            .state
            .lock()
            .map_err(|_| WorkerError::StateUnavailable)?;
        validate_fence(&session, fence)?;
        session.machine = cleanup_machine;
        if cleanup_result.is_ok() {
            session.occupies_capacity = false;
        }
        cleanup_result.map_err(|_| WorkerError::CleanupFailed)?;
        terminalization?;
        Ok(session.machine.snapshot())
    }

    pub fn create_page(
        &self,
        peer: &AuthenticatedPeer,
        session_id: &SessionId,
        fence: &OwnershipFence,
        now: SessionTime,
    ) -> Result<PageId, WorkerError> {
        self.authorize(peer)?;
        let executor = self.session(session_id)?;
        let _owner = ActionOwner::claim(&executor.action_owner)?;
        let _cleanup_owner = executor
            .cleanup_owner
            .lock()
            .map_err(|_| WorkerError::StateUnavailable)?;
        {
            let mut session = executor
                .state
                .lock()
                .map_err(|_| WorkerError::StateUnavailable)?;
            validate_fence(&session, fence)?;
            session
                .machine
                .record_activity(fence, now)
                .map_err(map_session_error)?;
        }
        let page_id = self
            .driver
            .create_page(session_id)
            .map_err(|_| WorkerError::DependencyUnavailable)?;
        let registration = (|| {
            let mut session = executor
                .state
                .lock()
                .map_err(|_| WorkerError::StateUnavailable)?;
            validate_fence(&session, fence)?;
            if session.pages.contains(&page_id)
                || session.closing_pages.contains(&page_id)
                || session.closed_pages.contains(&page_id)
            {
                return Err(WorkerError::StateUnavailable);
            }
            session
                .machine
                .register_target(fence, TargetId::new(page_id.to_string()))
                .map_err(map_session_error)?;
            session.pages.insert(page_id.clone());
            Ok(page_id.clone())
        })();
        if registration.is_err() {
            let _ = self.driver.close_page(session_id, &page_id);
        }
        registration
    }

    pub fn get_page(
        &self,
        peer: &AuthenticatedPeer,
        session_id: &SessionId,
        page_id: &PageId,
        fence: &OwnershipFence,
    ) -> Result<WorkerPageSnapshot, WorkerError> {
        self.authorize(peer)?;
        let executor = self.session(session_id)?;
        let session = executor
            .state
            .lock()
            .map_err(|_| WorkerError::StateUnavailable)?;
        validate_fence(&session, fence)?;
        page_snapshot(&session, page_id)
    }

    pub fn list_pages(
        &self,
        peer: &AuthenticatedPeer,
        session_id: &SessionId,
        fence: &OwnershipFence,
    ) -> Result<Vec<WorkerPageSnapshot>, WorkerError> {
        self.authorize(peer)?;
        let executor = self.session(session_id)?;
        let session = executor
            .state
            .lock()
            .map_err(|_| WorkerError::StateUnavailable)?;
        validate_fence(&session, fence)?;
        session
            .pages
            .iter()
            .map(|page_id| page_snapshot(&session, page_id))
            .collect()
    }

    pub fn activate_page(
        &self,
        peer: &AuthenticatedPeer,
        session_id: &SessionId,
        page_id: &PageId,
        fence: &OwnershipFence,
        now: SessionTime,
    ) -> Result<(), WorkerError> {
        self.authorize(peer)?;
        let executor = self.session(session_id)?;
        let _owner = ActionOwner::claim(&executor.action_owner)?;
        let _cleanup_owner = executor
            .cleanup_owner
            .lock()
            .map_err(|_| WorkerError::StateUnavailable)?;
        {
            let mut session = executor
                .state
                .lock()
                .map_err(|_| WorkerError::StateUnavailable)?;
            validate_fence(&session, fence)?;
            if !session.pages.contains(page_id) {
                return Err(WorkerError::PageNotFound);
            }
            if session.closing_pages.contains(page_id) {
                return Err(WorkerError::InvalidActionTransition);
            }
            session
                .machine
                .record_activity(fence, now)
                .map_err(map_session_error)?;
        }
        self.driver
            .activate_page(session_id, page_id)
            .map_err(|_| WorkerError::DependencyUnavailable)?;
        let mut session = executor
            .state
            .lock()
            .map_err(|_| WorkerError::StateUnavailable)?;
        validate_fence(&session, fence)?;
        if !session.pages.contains(page_id) || session.closing_pages.contains(page_id) {
            return Err(WorkerError::InvalidActionTransition);
        }
        session.active_page_id = page_id.clone();
        Ok(())
    }

    pub fn close_page(
        &self,
        peer: &AuthenticatedPeer,
        session_id: &SessionId,
        page_id: &PageId,
        fence: &OwnershipFence,
        now: SessionTime,
    ) -> Result<(), WorkerError> {
        self.authorize(peer)?;
        let executor = self.session(session_id)?;
        let _owner = ActionOwner::claim(&executor.action_owner)?;
        let _cleanup_owner = executor
            .cleanup_owner
            .lock()
            .map_err(|_| WorkerError::StateUnavailable)?;
        let needs_replacement = {
            let mut session = executor
                .state
                .lock()
                .map_err(|_| WorkerError::StateUnavailable)?;
            validate_fence(&session, fence)?;
            if !session.pages.contains(page_id) {
                return if session.closed_pages.contains(page_id) {
                    Ok(())
                } else {
                    Err(WorkerError::PageNotFound)
                };
            }
            if session.closing_pages.contains(page_id)
                || session.actions.values().any(|action| {
                    action.page_id.as_ref() == Some(page_id)
                        && matches!(
                            action.snapshot.status,
                            ActionStatus::PendingApproval
                                | ActionStatus::Queued
                                | ActionStatus::Running
                        )
                })
            {
                return Err(WorkerError::InvalidActionTransition);
            }
            session
                .machine
                .record_activity(fence, now)
                .map_err(map_session_error)?;
            session.closing_pages.insert(page_id.clone());
            session.primary_page_id == *page_id && session.pages.len() == 1
        };

        if needs_replacement {
            let replacement = match self.driver.create_page(session_id) {
                Ok(replacement) => replacement,
                Err(_) => {
                    let mut session = executor
                        .state
                        .lock()
                        .map_err(|_| WorkerError::StateUnavailable)?;
                    session.closing_pages.remove(page_id);
                    return Err(WorkerError::DependencyUnavailable);
                }
            };
            let replacement_registration = {
                let mut session = executor
                    .state
                    .lock()
                    .map_err(|_| WorkerError::StateUnavailable)?;
                validate_fence(&session, fence)?;
                if session.pages.contains(&replacement)
                    || session.closed_pages.contains(&replacement)
                    || session.closing_pages.contains(&replacement)
                {
                    Err(WorkerError::StateUnavailable)
                } else {
                    session
                        .machine
                        .register_target(fence, TargetId::new(replacement.to_string()))
                        .map_err(map_session_error)?;
                    session.pages.insert(replacement.clone());
                    Ok(())
                }
            };
            if let Err(error) = replacement_registration {
                let _ = self.driver.close_page(session_id, &replacement);
                let mut session = executor
                    .state
                    .lock()
                    .map_err(|_| WorkerError::StateUnavailable)?;
                session.closing_pages.remove(page_id);
                return Err(error);
            }
        }

        if self.driver.close_page(session_id, page_id).is_err() {
            let mut session = executor
                .state
                .lock()
                .map_err(|_| WorkerError::StateUnavailable)?;
            session.closing_pages.remove(page_id);
            return Err(WorkerError::DependencyUnavailable);
        }
        let mut session = executor
            .state
            .lock()
            .map_err(|_| WorkerError::StateUnavailable)?;
        validate_fence(&session, fence)?;
        session
            .machine
            .unregister_target(fence, &TargetId::new(page_id.to_string()))
            .map_err(map_session_error)?;
        session.pages.remove(page_id);
        session.closing_pages.remove(page_id);
        session.closed_pages.insert(page_id.clone());
        if session.primary_page_id == *page_id {
            session.primary_page_id = session
                .pages
                .first()
                .cloned()
                .ok_or(WorkerError::StateUnavailable)?;
        }
        if session.active_page_id == *page_id {
            session.active_page_id = session.primary_page_id.clone();
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn submit_action(
        &self,
        peer: &AuthenticatedPeer,
        requester_principal_id: PrincipalId,
        session_id: &SessionId,
        fence: &OwnershipFence,
        idempotency_key: &str,
        request_hash: [u8; 32],
        kind: ActionKind,
        feature: Option<BuiltinFeature>,
        page_id: Option<PageId>,
        payload: Vec<u8>,
        approval: Option<ActionApprovalRequirement>,
        now: SessionTime,
    ) -> Result<ActionId, WorkerError> {
        self.authorize(peer)?;
        let executor = self.session(session_id)?;
        let mut session = executor
            .state
            .lock()
            .map_err(|_| WorkerError::StateUnavailable)?;
        validate_fence(&session, fence)?;
        let approval_binding = approval.as_ref().map(|requirement| {
            (
                requirement.proposal.hash(),
                requirement.action_type.clone(),
                requirement.require_four_eyes,
            )
        });
        if let Some((existing_hash, existing_requester, existing_approval_binding, action_id)) =
            session.action_idempotency.get(idempotency_key)
        {
            return if *existing_hash == request_hash
                && existing_requester == &requester_principal_id
                && existing_approval_binding == &approval_binding
            {
                Ok(action_id.clone())
            } else {
                Err(WorkerError::IdempotencyConflict)
            };
        }
        if session.action_queue.len() >= self.config.action_queue_capacity {
            return Err(WorkerError::QueueFull);
        }
        if let Some(page_id) = &page_id {
            if !session.pages.contains(page_id) {
                return Err(WorkerError::PageNotFound);
            }
            if session.closing_pages.contains(page_id) {
                return Err(WorkerError::InvalidActionTransition);
            }
        }
        let (approval_expires_at, approval_evidence) = match approval {
            Some(requirement) => {
                let expires_at = SessionTime::new(
                    now.get()
                        .checked_add(self.config.approval_timeout_millis)
                        .ok_or(WorkerError::InvalidConfiguration)?,
                );
                let ActionApprovalRequirement {
                    proposal,
                    action_type,
                    require_four_eyes,
                } = requirement;
                let expected_arguments = proposal
                    .clone()
                    .with_arguments_hash(ActionArgumentsHash::digest(&payload));
                let expected_action = proposal.clone().with_action_type(action_type.clone());
                if proposal.tenant_id() != &session.tenant_id
                    || proposal.requester_principal_id() != &requester_principal_id
                    || proposal.session_id() != session_id
                    || proposal.session_incarnation() != fence.session_incarnation()
                    || page_id.as_ref() != Some(proposal.page_id())
                    || proposal.expires_at_unix_ms() != expires_at.get()
                    || expected_arguments.hash() != proposal.hash()
                    || expected_action.hash() != proposal.hash()
                {
                    return Err(WorkerError::ApprovalEvidenceMismatch);
                }
                let feature = match action_type {
                    ActionType::Click => "browser:click".to_owned(),
                    ActionType::Fill => "browser:fill".to_owned(),
                    ActionType::Navigate => "browser:navigate".to_owned(),
                    ActionType::Evaluate => "browser:evaluate".to_owned(),
                    ActionType::Upload => "browser:upload".to_owned(),
                    ActionType::Download => "browser:download".to_owned(),
                    ActionType::Custom(feature) => feature,
                };
                (
                    Some(expires_at),
                    Some((proposal, feature, require_four_eyes)),
                )
            }
            None => (None, None),
        };
        let requires_approval = approval_evidence.is_some();
        session
            .machine
            .record_activity(fence, now)
            .map_err(map_session_error)?;
        let ledger_fence = fence.as_placement_fence();
        let durable_request_hash = durable_action_request_hash(
            request_hash,
            &requester_principal_id,
            approval_binding
                .as_ref()
                .map(|(proposal_hash, _, require_four_eyes)| (proposal_hash, *require_four_eyes)),
        );
        let request = ActionRequest::new(
            ActionIdempotencyKey::new(idempotency_key),
            ActionRequestHash::new(durable_request_hash),
            kind,
        );
        let acceptance = session
            .action_ledger
            .accept(ledger_fence, request)
            .map_err(map_action_ledger_error)?;
        let action_id = acceptance.snapshot().action_id().clone();
        let action_sequence = acceptance.snapshot().action_sequence();
        if matches!(acceptance, AcceptDecision::Existing(_))
            && session.actions.contains_key(&action_id)
        {
            return Ok(action_id);
        }
        let progression = (|| {
            let mut durable_state = acceptance.snapshot().state();
            if durable_state == ActionState::Accepted {
                durable_state = session
                    .action_ledger
                    .enqueue(ledger_fence, &action_id)?
                    .state();
            }
            if durable_state == ActionState::Queued {
                durable_state = if requires_approval {
                    session
                        .action_ledger
                        .require_approval(ledger_fence, &action_id)
                } else {
                    session.action_ledger.mark_ready(ledger_fence, &action_id)
                }?
                .state();
            }
            Ok::<_, ActionLedgerError>(durable_state)
        })();
        let durable_state = match progression {
            Ok(state) => state,
            Err(error) => {
                if let Err(compensation_error) = session
                    .action_ledger
                    .cancel_before_dispatch(ledger_fence, &action_id)
                {
                    return Err(map_action_ledger_error(compensation_error));
                }
                session.action_idempotency.insert(
                    idempotency_key.to_owned(),
                    (
                        request_hash,
                        requester_principal_id.clone(),
                        approval_binding.clone(),
                        action_id.clone(),
                    ),
                );
                session.actions.insert(
                    action_id.clone(),
                    ActionRecord {
                        snapshot: WorkerActionSnapshot {
                            action_id,
                            action_sequence,
                            idempotency_key: idempotency_key.to_owned(),
                            canonical_request_hash: request_hash,
                            status: ActionStatus::CancelledBeforeDispatch,
                            kind,
                            dispatch_acknowledged: false,
                            approval_decision: None,
                            terminal_detail: Some(TerminalDetail::CancelledBeforeDispatch),
                            feature,
                            result: None,
                            resolution: None,
                        },
                        requester_principal_id,
                        page_id,
                        payload,
                        approval_id: None,
                        dispatch_permit: None,
                    },
                );
                return Err(map_action_ledger_error(error));
            }
        };
        let expected_state = if requires_approval {
            ActionState::PendingApproval
        } else {
            ActionState::ReadyToDispatch
        };
        if durable_state != expected_state {
            return Err(WorkerError::InvalidActionTransition);
        }
        let status = if requires_approval {
            ActionStatus::PendingApproval
        } else {
            ActionStatus::Queued
        };
        let approval_id = requires_approval.then(ApprovalId::new);
        session.action_idempotency.insert(
            idempotency_key.to_owned(),
            (
                request_hash,
                requester_principal_id.clone(),
                approval_binding,
                action_id.clone(),
            ),
        );
        session.actions.insert(
            action_id.clone(),
            ActionRecord {
                snapshot: WorkerActionSnapshot {
                    action_id: action_id.clone(),
                    action_sequence,
                    idempotency_key: idempotency_key.to_owned(),
                    canonical_request_hash: request_hash,
                    status,
                    kind,
                    dispatch_acknowledged: false,
                    approval_decision: None,
                    terminal_detail: None,
                    feature,
                    result: None,
                    resolution: None,
                },
                requester_principal_id,
                page_id,
                payload,
                approval_id: approval_id.clone(),
                dispatch_permit: None,
            },
        );
        if let Some(approval_id) = approval_id {
            let (proposal, feature, require_four_eyes) =
                approval_evidence.ok_or(WorkerError::StateUnavailable)?;
            session.approvals.insert(
                approval_id,
                ApprovalRecord {
                    action_id: action_id.clone(),
                    state: ApprovalState::Pending,
                    expires_at: approval_expires_at.ok_or(WorkerError::StateUnavailable)?,
                    proposal,
                    feature,
                    require_four_eyes,
                    request: None,
                },
            );
        }
        session.action_queue.push_back(action_id.clone());
        Ok(action_id)
    }

    pub fn get_action(
        &self,
        peer: &AuthenticatedPeer,
        session_id: &SessionId,
        action_id: &ActionId,
        fence: &OwnershipFence,
    ) -> Result<WorkerActionSnapshot, WorkerError> {
        self.authorize(peer)?;
        let executor = self.session(session_id)?;
        let session = executor
            .state
            .lock()
            .map_err(|_| WorkerError::StateUnavailable)?;
        validate_fence(&session, fence)?;
        let action = session
            .actions
            .get(action_id)
            .ok_or(WorkerError::ActionNotFound)?;
        let durable = session
            .action_ledger
            .snapshot(fence.as_placement_fence(), action_id)
            .map_err(map_action_ledger_error)?;
        let expected_status = match durable.state() {
            ActionState::Accepted | ActionState::Queued | ActionState::ReadyToDispatch => {
                ActionStatus::Queued
            }
            ActionState::PendingApproval => ActionStatus::PendingApproval,
            ActionState::MayHaveExecuted => ActionStatus::Running,
            ActionState::Succeeded => ActionStatus::Succeeded,
            ActionState::FailedKnown => ActionStatus::FailedKnown,
            ActionState::CancelledBeforeDispatch => ActionStatus::CancelledBeforeDispatch,
            ActionState::CancelledConfirmed => ActionStatus::CancelledConfirmed,
            ActionState::OutcomeUnknown => ActionStatus::OutcomeUnknown,
        };
        let approval_binding = action
            .approval_id
            .as_ref()
            .map(|approval_id| {
                session
                    .approvals
                    .get(approval_id)
                    .map(|approval| (approval.proposal.hash(), approval.require_four_eyes))
                    .ok_or(WorkerError::StateUnavailable)
            })
            .transpose()?;
        let expected_request_hash = durable_action_request_hash(
            action.snapshot.canonical_request_hash,
            &action.requester_principal_id,
            approval_binding
                .as_ref()
                .map(|(proposal_hash, require_four_eyes)| (proposal_hash, *require_four_eyes)),
        );
        if action.snapshot.status != expected_status
            || action.snapshot.idempotency_key != durable.request().idempotency_key().as_str()
            || expected_request_hash != *durable.request().canonical_request_hash().as_bytes()
            || action.snapshot.kind != durable.request().kind()
        {
            return Err(WorkerError::StateUnavailable);
        }
        let mut snapshot = action.snapshot.clone();
        snapshot.dispatch_acknowledged = durable.dispatch_acknowledged();
        snapshot.approval_decision = durable.approval_decision();
        snapshot.terminal_detail = durable.terminal_detail();
        snapshot.resolution = durable.resolution().cloned();
        Ok(snapshot)
    }

    pub fn run_next_action(
        &self,
        peer: &AuthenticatedPeer,
        session_id: &SessionId,
        fence: &OwnershipFence,
        now: SessionTime,
    ) -> Result<Option<WorkerActionSnapshot>, WorkerError> {
        self.authorize(peer)?;
        let executor = self.session(session_id)?;
        let _owner = ActionOwner::claim(&executor.action_owner)?;
        let (action_id, page_id, payload, permit, approval_request) = {
            let mut session = executor
                .state
                .lock()
                .map_err(|_| WorkerError::StateUnavailable)?;
            validate_fence(&session, fence)?;
            let Some(action_id) = session.action_queue.front().cloned() else {
                return Ok(None);
            };
            if session
                .actions
                .get(&action_id)
                .is_some_and(|action| action.snapshot.status == ActionStatus::PendingApproval)
            {
                return Ok(None);
            }
            let (page_id, payload, approval_id, requester_principal_id) = session
                .actions
                .get(&action_id)
                .filter(|action| action.snapshot.status == ActionStatus::Queued)
                .map(|action| {
                    (
                        action.page_id.clone(),
                        action.payload.clone(),
                        action.approval_id.clone(),
                        action.requester_principal_id.clone(),
                    )
                })
                .ok_or(WorkerError::InvalidActionTransition)?;
            let approval_request = approval_id
                .as_ref()
                .map(|approval_id| {
                    let approval = session
                        .approvals
                        .get(approval_id)
                        .ok_or(WorkerError::ApprovalNotFound)?;
                    if !matches!(approval.state, ApprovalState::Approved { .. }) {
                        return Err(WorkerError::InvalidApprovalTransition);
                    }
                    let request = approval
                        .request
                        .as_ref()
                        .map(Arc::clone)
                        .ok_or(WorkerError::StateUnavailable)?;
                    Ok((
                        request,
                        approval.feature.clone(),
                        requester_principal_id.clone(),
                    ))
                })
                .transpose()?;
            session
                .machine
                .begin_action(fence, action_id.clone(), now)
                .map_err(map_session_error)?;
            let permit = match session
                .action_ledger
                .prepare_dispatch(fence.as_placement_fence(), &action_id)
            {
                Ok(DispatchDecision::Dispatch(permit)) => permit,
                Ok(DispatchDecision::DoNotReplay(_)) => {
                    session
                        .machine
                        .finish_action(fence, &action_id, now)
                        .map_err(map_session_error)?;
                    return Err(WorkerError::InvalidActionTransition);
                }
                Err(error) => {
                    session
                        .machine
                        .finish_action(fence, &action_id, now)
                        .map_err(map_session_error)?;
                    return Err(map_action_ledger_error(error));
                }
            };
            if session.action_queue.pop_front().as_ref() != Some(&action_id) {
                return Err(WorkerError::StateUnavailable);
            }
            let action = session
                .actions
                .get_mut(&action_id)
                .ok_or(WorkerError::ActionNotFound)?;
            action.snapshot.status = ActionStatus::Running;
            action.dispatch_permit = Some(permit.clone());
            executor.approved_dispatch_phase.store(
                if approval_request.is_some() {
                    APPROVED_DISPATCH_INSPECTING
                } else {
                    APPROVED_DISPATCH_IDLE
                },
                Ordering::Release,
            );
            (action_id, page_id, payload, permit, approval_request)
        };
        let (outcome, response_error, known_failure_reason) =
            if let Some((request, feature, requester_principal_id)) = approval_request {
                let proposal = request.proposal().clone();
                let inspected = page_id
                    .as_ref()
                    .ok_or(WorkerError::StateUnavailable)
                    .and_then(|page_id| {
                        self.driver
                            .inspect_approval_context(session_id, page_id, &proposal)
                            .map_err(|_| WorkerError::DependencyUnavailable)
                    });
                match inspected {
                    Ok(live) => {
                        let page_id = page_id.as_ref().ok_or(WorkerError::StateUnavailable)?;
                        let mut admission_error = None;
                        let driver_entered = executor
                            .approved_dispatch_phase
                            .compare_exchange(
                                APPROVED_DISPATCH_INSPECTING,
                                APPROVED_DISPATCH_DRIVER_PENDING,
                                Ordering::AcqRel,
                                Ordering::Acquire,
                            )
                            .is_ok();
                        let execution = if driver_entered {
                            self.driver.execute_approved_action(
                                session_id,
                                page_id,
                                &payload,
                                &proposal,
                                &live,
                                &mut |observed| {
                                    if executor
                                        .approved_dispatch_phase
                                        .compare_exchange(
                                            APPROVED_DISPATCH_DRIVER_PENDING,
                                            APPROVED_DISPATCH_AUTHORIZING,
                                            Ordering::AcqRel,
                                            Ordering::Acquire,
                                        )
                                        .is_err()
                                    {
                                        return Err(ApprovedActionError::DispatchRevoked);
                                    }
                                    let admission = (|| {
                                        let session = executor
                                            .state
                                            .lock()
                                            .map_err(|_| WorkerError::StateUnavailable)?;
                                        validate_fence(&session, fence)?;
                                        if session.machine.lifecycle() != SessionLifecycle::Ready
                                            || session.machine.snapshot().execution
                                                != SessionExecution::Running(action_id.clone())
                                        {
                                            return Err(WorkerError::InvalidActionTransition);
                                        }
                                        let action = session
                                            .actions
                                            .get(&action_id)
                                            .ok_or(WorkerError::ActionNotFound)?;
                                        if action.snapshot.status != ActionStatus::Running
                                            || action.dispatch_permit.as_ref() != Some(&permit)
                                        {
                                            return Err(WorkerError::InvalidActionTransition);
                                        }
                                        let mut context = ExecutionContext {
                                            tenant_id: proposal.tenant_id().clone(),
                                            requester_principal_id: requester_principal_id.clone(),
                                            session_id: proposal.session_id().clone(),
                                            session_incarnation: proposal.session_incarnation(),
                                            page_id: proposal.page_id().clone(),
                                            target_incarnation: observed.target_incarnation,
                                            frame_document_epoch: observed.frame_document_epoch,
                                            current_origin: observed.current_origin.clone(),
                                            url_revision: observed.url_revision,
                                            node_ref: observed.node_ref.clone(),
                                            node_valid: observed.node_valid,
                                            placement_owned: true,
                                            resolved_ips: observed.resolved_ips.clone(),
                                            credential_refs: observed.credential_refs.clone(),
                                            feature: feature.clone(),
                                            chromium_build: observed.chromium_build.clone(),
                                            effective_isolation: observed.effective_isolation,
                                        };
                                        let authorization_floor =
                                            now.max(session.machine.last_observed_at());
                                        let authorization = request
                                            .authorize_and_dispatch_with_clock(
                                                &self.emergency_policy,
                                                &context,
                                                || {
                                                    let authorization_now = self
                                                        .clock
                                                        .now()
                                                        .map_err(ApprovalAdmissionClockError::Clock)
                                                        .map(|trusted_now| {
                                                            authorization_floor.max(trusted_now)
                                                        })?;
                                                    let snapshot = session.machine.snapshot();
                                                    let deadline_elapsed = [
                                                        snapshot.lease_expires_at,
                                                        snapshot.session_expires_at,
                                                        snapshot.idle_expires_at,
                                                    ]
                                                    .into_iter()
                                                    .flatten()
                                                    .any(|deadline| authorization_now >= deadline);
                                                    if snapshot.owner_fence != *fence
                                                        || snapshot.lifecycle
                                                            != SessionLifecycle::Ready
                                                        || snapshot.execution
                                                            != SessionExecution::Running(
                                                                action_id.clone(),
                                                            )
                                                        || !session.occupies_capacity
                                                        || deadline_elapsed
                                                    {
                                                        return Err(
                                                            ApprovalAdmissionClockError::
                                                                PlacementOwnershipInvalid(
                                                                    authorization_now,
                                                                ),
                                                        );
                                                    }
                                                    Ok(authorization_now.get())
                                                },
                                                || {},
                                            );
                                        match authorization {
                                        Ok(()) => Ok(()),
                                        Err(ApprovalAuthorizationError::Approval(error)) => {
                                            Err(WorkerError::ApprovalPolicy(error))
                                        }
                                        Err(ApprovalAuthorizationError::Clock(
                                            ApprovalAdmissionClockError::Clock(error),
                                        )) => Err(error),
                                        Err(ApprovalAuthorizationError::Clock(
                                            ApprovalAdmissionClockError::PlacementOwnershipInvalid(
                                                authorization_now,
                                            ),
                                        )) => {
                                            context.placement_owned = false;
                                            match request.authorize_and_dispatch_with_clock(
                                                &self.emergency_policy,
                                                &context,
                                                || {
                                                    Ok::<_, std::convert::Infallible>(
                                                        authorization_now.get(),
                                                    )
                                                },
                                                || {},
                                            ) {
                                                Ok(()) => Err(WorkerError::StateUnavailable),
                                                Err(ApprovalAuthorizationError::Approval(
                                                    error,
                                                )) => Err(WorkerError::ApprovalPolicy(error)),
                                                Err(ApprovalAuthorizationError::Clock(never)) => {
                                                    match never {}
                                                }
                                            }
                                        }
                                    }
                                    })();
                                    match admission {
                                        Ok(()) => {
                                            executor.approved_dispatch_phase.store(
                                                APPROVED_DISPATCH_STARTED,
                                                Ordering::Release,
                                            );
                                            Ok(())
                                        }
                                        Err(error) => {
                                            executor.approved_dispatch_phase.store(
                                                APPROVED_DISPATCH_AUTHORIZATION_REJECTED,
                                                Ordering::Release,
                                            );
                                            admission_error = Some(error);
                                            Err(ApprovedActionError::DispatchRevoked)
                                        }
                                    }
                                },
                            )
                        } else {
                            Err(ApprovedActionError::DispatchRevoked)
                        };
                        let dispatch_phase =
                            executor.approved_dispatch_phase.load(Ordering::Acquire);
                        let effect_started = dispatch_phase == APPROVED_DISPATCH_STARTED;
                        if driver_entered {
                            let returned_phase = if !effect_started
                                && matches!(
                                    &execution,
                                    Err(ApprovedActionError::ApprovalStale(_)
                                        | ApprovedActionError::DispatchRevoked)
                                ) {
                                APPROVED_DISPATCH_STOPPED
                            } else {
                                APPROVED_DISPATCH_RETURNED_UNCERTAIN
                            };
                            let completion_guard = executor.approved_dispatch_wait.lock().ok();
                            executor
                                .approved_dispatch_phase
                                .store(returned_phase, Ordering::Release);
                            executor.approved_dispatch_changed.notify_all();
                            drop(completion_guard);
                        }
                        match execution {
                            Ok(outcome) if effect_started => (outcome, None, None),
                            Ok(_) => (ActionExecutionResult::OutcomeUnknown, None, None),
                            Err(_) if effect_started => {
                                (ActionExecutionResult::OutcomeUnknown, None, None)
                            }
                            Err(ApprovedActionError::ApprovalStale(reason)) => {
                                let error = ApprovalError::ApprovalStale(reason);
                                (
                                    ActionExecutionResult::FailedKnown(format!(
                                        "approval policy: {error:?}"
                                    )),
                                    Some(WorkerError::ApprovalPolicy(error)),
                                    Some(KnownFailureReason::PolicyDenied),
                                )
                            }
                            Err(ApprovedActionError::DispatchRevoked) => match admission_error {
                                Some(WorkerError::ApprovalPolicy(error)) => (
                                    ActionExecutionResult::FailedKnown(format!(
                                        "approval policy: {error:?}"
                                    )),
                                    Some(WorkerError::ApprovalPolicy(error)),
                                    Some(KnownFailureReason::PolicyDenied),
                                ),
                                Some(error) => (
                                    ActionExecutionResult::FailedKnown(format!(
                                        "approval dispatch admission failed: {error:?}"
                                    )),
                                    Some(error),
                                    Some(KnownFailureReason::NotDispatched),
                                ),
                                None => (
                                    ActionExecutionResult::FailedKnown(
                                        "approval dispatch revoked before authorization".to_owned(),
                                    ),
                                    Some(WorkerError::InvalidActionTransition),
                                    Some(KnownFailureReason::NotDispatched),
                                ),
                            },
                            Err(
                                ApprovedActionError::Unavailable
                                | ApprovedActionError::OutcomeUncertain,
                            ) => (ActionExecutionResult::OutcomeUnknown, None, None),
                        }
                    }
                    Err(error) => (
                        ActionExecutionResult::FailedKnown(
                            "approval context inspection failed".to_owned(),
                        ),
                        Some(error),
                        Some(KnownFailureReason::NotDispatched),
                    ),
                }
            } else {
                (
                    self.driver
                        .execute_action(session_id, page_id.as_ref(), &payload),
                    None,
                    None,
                )
            };
        let mut session = executor
            .state
            .lock()
            .map_err(|_| WorkerError::StateUnavailable)?;
        validate_fence(&session, fence)?;
        if !session
            .actions
            .get(&action_id)
            .is_some_and(|action| action.snapshot.status == ActionStatus::Running)
        {
            executor
                .approved_dispatch_phase
                .store(APPROVED_DISPATCH_IDLE, Ordering::Release);
            return Err(WorkerError::InvalidActionTransition);
        }
        let completion_now = now.max(session.machine.last_observed_at());
        let mut completed_machine = session.machine.clone();
        match &outcome {
            ActionExecutionResult::Succeeded(_) | ActionExecutionResult::FailedKnown(_) => {
                completed_machine
                    .finish_action(fence, &action_id, completion_now)
                    .map_err(map_session_error)?;
            }
            ActionExecutionResult::OutcomeUnknown => {
                completed_machine
                    .mark_action_outcome_unknown(fence, &action_id, completion_now)
                    .map_err(map_session_error)?;
            }
        }
        let durable_result = match &outcome {
            ActionExecutionResult::Succeeded(result) => {
                let digest = Sha256::digest(result);
                session.action_ledger.record_result(
                    fence.as_placement_fence(),
                    &permit,
                    BrowserResult::Succeeded(ResultDigest::new(digest.into())),
                )
            }
            ActionExecutionResult::FailedKnown(_) => {
                let reason = known_failure_reason.unwrap_or(KnownFailureReason::BrowserRejected);
                session.action_ledger.record_result(
                    fence.as_placement_fence(),
                    &permit,
                    BrowserResult::FailedKnown(reason),
                )
            }
            ActionExecutionResult::OutcomeUnknown => session.action_ledger.record_transport_loss(
                fence.as_placement_fence(),
                &permit,
                TransportLoss::Ambiguous(OutcomeUnknownReason::AmbiguousTransportLoss),
            ),
        };
        if let Err(error) = durable_result {
            session.durability_degraded = true;
            let still_running = session
                .actions
                .get(&action_id)
                .is_some_and(|action| action.snapshot.status == ActionStatus::Running);
            if still_running {
                let _ =
                    session
                        .machine
                        .mark_action_outcome_unknown(fence, &action_id, completion_now);
            }
            if let Some(action) = session.actions.get_mut(&action_id)
                && still_running
            {
                action.snapshot.status = ActionStatus::OutcomeUnknown;
            }
            executor
                .approved_dispatch_phase
                .store(APPROVED_DISPATCH_IDLE, Ordering::Release);
            return Err(map_action_ledger_error(error));
        }
        session.machine = completed_machine;
        match outcome {
            ActionExecutionResult::Succeeded(result) => {
                let action = session
                    .actions
                    .get_mut(&action_id)
                    .ok_or(WorkerError::ActionNotFound)?;
                action.snapshot.status = ActionStatus::Succeeded;
                action.snapshot.result = Some(result);
            }
            ActionExecutionResult::FailedKnown(reason) => {
                let action = session
                    .actions
                    .get_mut(&action_id)
                    .ok_or(WorkerError::ActionNotFound)?;
                action.snapshot.status = ActionStatus::FailedKnown;
                action.snapshot.result = Some(reason.into_bytes());
            }
            ActionExecutionResult::OutcomeUnknown => {
                let action = session
                    .actions
                    .get_mut(&action_id)
                    .ok_or(WorkerError::ActionNotFound)?;
                action.snapshot.status = ActionStatus::OutcomeUnknown;
            }
        }
        let snapshot = session
            .actions
            .get(&action_id)
            .map(|action| action.snapshot.clone())
            .ok_or(WorkerError::ActionNotFound)?;
        executor
            .approved_dispatch_phase
            .store(APPROVED_DISPATCH_IDLE, Ordering::Release);
        if let Some(error) = response_error {
            Err(error)
        } else {
            Ok(Some(snapshot))
        }
    }

    pub fn cancel_action(
        &self,
        peer: &AuthenticatedPeer,
        session_id: &SessionId,
        action_id: &ActionId,
        fence: &OwnershipFence,
        now: SessionTime,
    ) -> Result<WorkerActionSnapshot, WorkerError> {
        self.authorize(peer)?;
        let executor = self.session(session_id)?;
        let (mut session, status, approved_dispatch_phase, approved_action) = loop {
            let session = executor
                .state
                .lock()
                .map_err(|_| WorkerError::StateUnavailable)?;
            validate_fence(&session, fence)?;
            let (status, approved_action) = session
                .actions
                .get(action_id)
                .map(|action| (action.snapshot.status, action.approval_id.is_some()))
                .ok_or(WorkerError::ActionNotFound)?;
            if status != ActionStatus::Running {
                break (
                    session,
                    status,
                    executor.approved_dispatch_phase.load(Ordering::Acquire),
                    approved_action,
                );
            }
            match executor.approved_dispatch_phase.load(Ordering::Acquire) {
                APPROVED_DISPATCH_INSPECTING
                | APPROVED_DISPATCH_DRIVER_PENDING
                | APPROVED_DISPATCH_AUTHORIZING => {
                    drop(session);
                    stop_or_observe_approved_dispatch(&executor);
                }
                phase => break (session, status, phase, approved_action),
            }
        };
        match status {
            ActionStatus::PendingApproval | ActionStatus::Queued => {
                let mut next_machine = session.machine.clone();
                next_machine
                    .record_activity(fence, now)
                    .map_err(map_session_error)?;
                session
                    .action_ledger
                    .cancel_before_dispatch(fence.as_placement_fence(), action_id)
                    .map_err(map_action_ledger_error)?;
                session.machine = next_machine;
                session.action_queue.retain(|queued| queued != action_id);
                let action = session
                    .actions
                    .get_mut(action_id)
                    .ok_or(WorkerError::ActionNotFound)?;
                action.snapshot.status = ActionStatus::CancelledBeforeDispatch;
                let approval_id = action.approval_id.clone();
                let snapshot = action.snapshot.clone();
                if let Some(approval_id) = approval_id
                    && let Some(approval) = session.approvals.get_mut(&approval_id)
                {
                    approval.state = ApprovalState::Expired;
                }
                Ok(snapshot)
            }
            ActionStatus::Running => {
                let mut completed_dispatch_phase = approved_dispatch_phase;
                let confirmed = if approved_action
                    && approved_dispatch_phase == APPROVED_DISPATCH_STOPPED
                {
                    true
                } else {
                    drop(session);
                    let driver_confirmed = self
                        .driver
                        .cancel_action(session_id, action_id)
                        .map_err(|_| WorkerError::DependencyUnavailable)?;
                    if approved_action && driver_confirmed {
                        let mut completion = executor
                            .approved_dispatch_wait
                            .lock()
                            .map_err(|_| WorkerError::StateUnavailable)?;
                        loop {
                            completed_dispatch_phase =
                                executor.approved_dispatch_phase.load(Ordering::Acquire);
                            if !matches!(
                                completed_dispatch_phase,
                                APPROVED_DISPATCH_INSPECTING
                                    | APPROVED_DISPATCH_DRIVER_PENDING
                                    | APPROVED_DISPATCH_AUTHORIZING
                                    | APPROVED_DISPATCH_STARTED
                                    | APPROVED_DISPATCH_REVOKE_REQUESTED
                                    | APPROVED_DISPATCH_AUTHORIZATION_REJECTED
                            ) {
                                break;
                            }
                            completion = executor
                                .approved_dispatch_changed
                                .wait(completion)
                                .map_err(|_| WorkerError::StateUnavailable)?;
                        }
                    }
                    session = executor
                        .state
                        .lock()
                        .map_err(|_| WorkerError::StateUnavailable)?;
                    validate_fence(&session, fence)?;
                    let current = session
                        .actions
                        .get(action_id)
                        .ok_or(WorkerError::ActionNotFound)?;
                    if current.snapshot.status != ActionStatus::Running {
                        return Ok(current.snapshot.clone());
                    }
                    if approved_action {
                        driver_confirmed && completed_dispatch_phase == APPROVED_DISPATCH_STOPPED
                    } else {
                        driver_confirmed
                    }
                };
                if !confirmed {
                    return Err(WorkerError::InvalidActionTransition);
                }
                let completion_now = now.max(session.machine.last_observed_at());
                let mut completed_machine = session.machine.clone();
                completed_machine
                    .finish_action(fence, action_id, completion_now)
                    .map_err(map_session_error)?;
                let permit = session
                    .actions
                    .get(action_id)
                    .and_then(|action| action.dispatch_permit.clone())
                    .ok_or(WorkerError::StateUnavailable)?;
                if let Err(error) = session.action_ledger.record_result(
                    fence.as_placement_fence(),
                    &permit,
                    BrowserResult::CancellationConfirmed,
                ) {
                    session.durability_degraded = true;
                    let _ = session.machine.mark_action_outcome_unknown(
                        fence,
                        action_id,
                        completion_now,
                    );
                    if let Some(action) = session.actions.get_mut(action_id) {
                        action.snapshot.status = ActionStatus::OutcomeUnknown;
                    }
                    return Err(map_action_ledger_error(error));
                }
                session.machine = completed_machine;
                let action = session
                    .actions
                    .get_mut(action_id)
                    .ok_or(WorkerError::ActionNotFound)?;
                action.snapshot.status = ActionStatus::CancelledConfirmed;
                Ok(action.snapshot.clone())
            }
            _ => session
                .actions
                .get(action_id)
                .map(|action| action.snapshot.clone())
                .ok_or(WorkerError::ActionNotFound),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn resolve_action(
        &self,
        peer: &AuthenticatedPeer,
        session_id: &SessionId,
        action_id: &ActionId,
        fence: &OwnershipFence,
        resolution: ResolutionKind,
        resolved_by: PrincipalId,
        basis: &str,
        now: SessionTime,
    ) -> Result<WorkerActionSnapshot, WorkerError> {
        self.authorize(peer)?;
        if basis.trim().is_empty() || basis.len() > 4_096 {
            return Err(WorkerError::InvalidActionTransition);
        }
        let executor = self.session(session_id)?;
        let mut session = executor
            .state
            .lock()
            .map_err(|_| WorkerError::StateUnavailable)?;
        validate_fence(&session, fence)?;
        let action = session
            .actions
            .get(action_id)
            .ok_or(WorkerError::ActionNotFound)?;
        if let Some(existing) = &action.snapshot.resolution {
            return if existing.kind() == resolution
                && existing.resolved_by() == &resolved_by
                && existing.basis() == basis
            {
                Ok(action.snapshot.clone())
            } else {
                Err(WorkerError::InvalidActionTransition)
            };
        }
        if action.snapshot.status != ActionStatus::OutcomeUnknown {
            return Err(WorkerError::InvalidActionTransition);
        }
        let annotation = ResolutionAnnotation::new(resolution, resolved_by, now.get(), basis);
        let mut next_machine = session.machine.clone();
        next_machine
            .resolve_action(fence, action_id, now)
            .map_err(map_session_error)?;
        let durable_resolution = session
            .action_ledger
            .resolve(
                fence.as_placement_fence(),
                action_id,
                annotation.clone(),
                ResolutionPolicy::new(true),
            )
            .map_err(map_action_ledger_error)?;
        let durable_annotation = match durable_resolution {
            ResolutionOutcome::Recorded(snapshot)
            | ResolutionOutcome::AlreadyRecorded(snapshot) => snapshot
                .resolution()
                .cloned()
                .ok_or(WorkerError::StateUnavailable)?,
        };
        session.machine = next_machine;
        let action = session
            .actions
            .get_mut(action_id)
            .ok_or(WorkerError::ActionNotFound)?;
        action.snapshot.resolution = Some(durable_annotation);
        Ok(action.snapshot.clone())
    }

    pub fn upload_artifact(
        &self,
        peer: &AuthenticatedPeer,
        session_id: &SessionId,
        fence: &OwnershipFence,
        upload: ArtifactUpload,
        now: SessionTime,
    ) -> Result<ArtifactId, WorkerError> {
        self.authorize(peer)?;
        let executor = self.session(session_id)?;
        let _cleanup_owner = executor
            .cleanup_owner
            .lock()
            .map_err(|_| WorkerError::StateUnavailable)?;
        let size_bytes =
            u64::try_from(upload.bytes.len()).map_err(|_| WorkerError::CapacityExceeded)?;
        if size_bytes > self.config.artifact_limits.max_file_bytes
            || size_bytes > self.config.artifact_limits.max_in_flight_bytes
        {
            return Err(WorkerError::CapacityExceeded);
        }
        let checksum = ArtifactChecksum::new(Sha256::digest(&upload.bytes).into());
        ArtifactContentMetadata::new(
            size_bytes,
            checksum,
            upload.content_type.clone(),
            ArtifactContentSource::ClientUpload,
            "browserd-worker-upload",
        )
        .map_err(|_| WorkerError::InvalidConfiguration)?;
        let tenant_id = {
            let mut session = executor
                .state
                .lock()
                .map_err(|_| WorkerError::StateUnavailable)?;
            validate_fence(&session, fence)?;
            let projected_committed = session
                .artifact_committed_bytes
                .checked_add(size_bytes)
                .ok_or(WorkerError::CapacityExceeded)?;
            if projected_committed > self.config.artifact_limits.max_committed_bytes {
                return Err(WorkerError::CapacityExceeded);
            }
            session
                .machine
                .record_activity(fence, now)
                .map_err(map_session_error)?;
            session.tenant_id.clone()
        };
        let artifact_id = ArtifactId::new();
        let key = ArtifactKey::new(tenant_id, session_id.clone(), artifact_id.clone());
        let request = ArtifactStoreRequest {
            key: key.clone(),
            fence: fence.clone(),
            bytes: upload.bytes,
            declared_content_type: upload.content_type,
            expected_size_bytes: size_bytes,
            expected_checksum: checksum,
            max_bytes: self.config.artifact_limits.max_file_bytes,
        };
        let receipt = self
            .sandbox
            .store_artifact(&request)
            .map_err(|_| WorkerError::DependencyUnavailable)?;
        if receipt.key() != &key
            || receipt.size_bytes() != size_bytes
            || receipt.checksum() != &checksum
        {
            return Err(WorkerError::DependencyUnavailable);
        }
        let metadata = ArtifactContentMetadata::new(
            receipt.size_bytes(),
            *receipt.checksum(),
            receipt.detected_content_type(),
            ArtifactContentSource::ClientUpload,
            "browserd-worker-upload",
        )
        .map_err(|_| WorkerError::DependencyUnavailable)?;
        let mut artifact = Artifact::new_upload(key);
        artifact
            .apply_materialized(ArtifactEvent::UploadStored, metadata)
            .and_then(|_| artifact.apply(ArtifactEvent::ScanStarted))
            .and_then(|_| {
                artifact.apply(match receipt.scan_verdict() {
                    ArtifactScanVerdict::Clean => ArtifactEvent::ScanPassed,
                    ArtifactScanVerdict::Quarantined => ArtifactEvent::ScanQuarantined,
                    ArtifactScanVerdict::Rejected => ArtifactEvent::ScanRejected,
                })
            })
            .map_err(|_| WorkerError::DependencyUnavailable)?;
        let mut session = executor
            .state
            .lock()
            .map_err(|_| WorkerError::StateUnavailable)?;
        validate_fence(&session, fence)?;
        let projected_committed = session
            .artifact_committed_bytes
            .checked_add(size_bytes)
            .ok_or(WorkerError::CapacityExceeded)?;
        if projected_committed > self.config.artifact_limits.max_committed_bytes {
            return Err(WorkerError::CapacityExceeded);
        }
        session.artifact_committed_bytes = projected_committed;
        session.artifacts.insert(
            artifact_id.clone(),
            ArtifactRecord {
                artifact,
                object_generation: receipt.object_generation(),
            },
        );
        Ok(artifact_id)
    }

    pub fn get_artifact(
        &self,
        peer: &AuthenticatedPeer,
        session_id: &SessionId,
        artifact_id: &ArtifactId,
        fence: &OwnershipFence,
    ) -> Result<WorkerArtifactSnapshot, WorkerError> {
        self.authorize(peer)?;
        let executor = self.session(session_id)?;
        let session = executor
            .state
            .lock()
            .map_err(|_| WorkerError::StateUnavailable)?;
        validate_fence(&session, fence)?;
        let artifact = session
            .artifacts
            .get(artifact_id)
            .ok_or(WorkerError::ArtifactNotFound)?;
        let metadata = artifact
            .artifact
            .content_metadata()
            .ok_or(WorkerError::StateUnavailable)?;
        Ok(WorkerArtifactSnapshot {
            artifact_id: artifact.artifact.key().artifact_id().clone(),
            state: artifact.artifact.state(),
            size_bytes: metadata.size_bytes(),
            checksum_sha256: *metadata.checksum().as_bytes(),
            content_type: metadata.content_type().to_owned(),
            source: metadata.source(),
            origin: metadata.origin().to_owned(),
            object_generation: artifact.object_generation,
        })
    }

    pub fn approval_for_action(
        &self,
        peer: &AuthenticatedPeer,
        session_id: &SessionId,
        action_id: &ActionId,
        fence: &OwnershipFence,
    ) -> Result<ApprovalId, WorkerError> {
        self.authorize(peer)?;
        let executor = self.session(session_id)?;
        let session = executor
            .state
            .lock()
            .map_err(|_| WorkerError::StateUnavailable)?;
        validate_fence(&session, fence)?;
        session
            .actions
            .get(action_id)
            .and_then(|action| action.approval_id.clone())
            .ok_or(WorkerError::ApprovalNotFound)
    }

    pub fn get_approval(
        &self,
        peer: &AuthenticatedPeer,
        session_id: &SessionId,
        approval_id: &ApprovalId,
        fence: &OwnershipFence,
    ) -> Result<WorkerApprovalSnapshot, WorkerError> {
        self.authorize(peer)?;
        let executor = self.session(session_id)?;
        let session = executor
            .state
            .lock()
            .map_err(|_| WorkerError::StateUnavailable)?;
        validate_fence(&session, fence)?;
        let approval = session
            .approvals
            .get(approval_id)
            .ok_or(WorkerError::ApprovalNotFound)?;
        Ok(worker_approval_snapshot(approval_id, approval))
    }

    pub fn list_approvals(
        &self,
        peer: &AuthenticatedPeer,
        session_id: &SessionId,
        fence: &OwnershipFence,
    ) -> Result<Vec<WorkerApprovalSnapshot>, WorkerError> {
        self.authorize(peer)?;
        let executor = self.session(session_id)?;
        let session = executor
            .state
            .lock()
            .map_err(|_| WorkerError::StateUnavailable)?;
        validate_fence(&session, fence)?;
        let mut approvals = session
            .approvals
            .iter()
            .map(|(approval_id, approval)| worker_approval_snapshot(approval_id, approval))
            .collect::<Vec<_>>();
        approvals.sort_by(|left, right| left.approval_id.cmp(&right.approval_id));
        Ok(approvals)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn decide_approval(
        &self,
        peer: &AuthenticatedPeer,
        session_id: &SessionId,
        approval_id: &ApprovalId,
        fence: &OwnershipFence,
        decision: ApprovalDecision,
        principal_id: PrincipalId,
        now: SessionTime,
    ) -> Result<WorkerApprovalSnapshot, WorkerError> {
        self.authorize(peer)?;
        let executor = self.session(session_id)?;
        let mut session = executor
            .state
            .lock()
            .map_err(|_| WorkerError::StateUnavailable)?;
        validate_fence(&session, fence)?;
        let decision_now = now.max(self.clock.now()?);
        expire_pending_approvals(&mut session, fence, decision_now)?;
        let action_id = session
            .approvals
            .get(approval_id)
            .map(|approval| approval.action_id.clone())
            .ok_or(WorkerError::ApprovalNotFound)?;
        let (current, proposal, require_four_eyes) = session
            .approvals
            .get(approval_id)
            .map(|approval| {
                (
                    approval.state.clone(),
                    approval.proposal.clone(),
                    approval.require_four_eyes,
                )
            })
            .ok_or(WorkerError::ApprovalNotFound)?;
        if current != ApprovalState::Pending {
            if current == ApprovalState::Expired {
                return Err(WorkerError::ApprovalPolicy(ApprovalError::ApprovalExpired));
            }
            let same_decision = match (&current, decision) {
                (ApprovalState::Approved { by }, ApprovalDecision::Approve)
                | (ApprovalState::Denied { by }, ApprovalDecision::Deny) => by == &principal_id,
                _ => false,
            };
            if !same_decision {
                return Err(WorkerError::InvalidApprovalTransition);
            }
            let approval = session
                .approvals
                .get(approval_id)
                .ok_or(WorkerError::ApprovalNotFound)?;
            return Ok(worker_approval_snapshot(approval_id, approval));
        }
        if require_four_eyes && principal_id == *proposal.requester_principal_id() {
            return Err(WorkerError::ApprovalPolicy(
                ApprovalError::FourEyesViolation,
            ));
        }
        let mut next_machine = session.machine.clone();
        next_machine
            .record_activity(fence, decision_now)
            .map_err(map_session_error)?;
        let request = Arc::new(ApprovalRequest::new(proposal, require_four_eyes));
        match decision {
            ApprovalDecision::Approve => {
                session
                    .action_ledger
                    .grant_approval(fence.as_placement_fence(), &action_id)
                    .map_err(map_action_ledger_error)?;
            }
            ApprovalDecision::Deny => {
                session
                    .action_ledger
                    .deny_approval(fence.as_placement_fence(), &action_id)
                    .map_err(map_action_ledger_error)?;
            }
        }
        request
            .decide(principal_id, decision, decision_now.get())
            .map_err(|_| WorkerError::StateUnavailable)?;
        let state = request.state().map_err(|_| WorkerError::StateUnavailable)?;
        match decision {
            ApprovalDecision::Approve => {
                let action = session
                    .actions
                    .get_mut(&action_id)
                    .ok_or(WorkerError::ActionNotFound)?;
                action.snapshot.status = ActionStatus::Queued;
            }
            ApprovalDecision::Deny => {
                session.action_queue.retain(|queued| queued != &action_id);
                let action = session
                    .actions
                    .get_mut(&action_id)
                    .ok_or(WorkerError::ActionNotFound)?;
                action.snapshot.status = ActionStatus::FailedKnown;
            }
        }
        session.machine = next_machine;
        let approval = session
            .approvals
            .get_mut(approval_id)
            .ok_or(WorkerError::ApprovalNotFound)?;
        approval.state = state.clone();
        approval.request = Some(Arc::clone(&request));
        Ok(worker_approval_snapshot(approval_id, approval))
    }

    pub fn issue_viewer_ticket(
        &self,
        peer: &AuthenticatedPeer,
        session_id: &SessionId,
        fence: &OwnershipFence,
        scopes: ViewerScopes,
        ttl: Duration,
        now: SessionTime,
    ) -> Result<ViewerTicket, WorkerError> {
        self.authorize(peer)?;
        let executor = self.session(session_id)?;
        let mut session = executor
            .state
            .lock()
            .map_err(|_| WorkerError::StateUnavailable)?;
        validate_fence(&session, fence)?;
        session
            .machine
            .record_activity(fence, now)
            .map_err(map_session_error)?;
        self.viewer_tickets
            .as_ref()
            .ok_or(WorkerError::NotReady)?
            .issue(
                session.tenant_id.clone(),
                session_id.clone(),
                fence.session_incarnation(),
                scopes,
                now.get(),
                ttl,
            )
            .map_err(|_| WorkerError::DependencyUnavailable)
    }

    pub fn heartbeat(&self, peer: &AuthenticatedPeer, now: SessionTime) -> Result<(), WorkerError> {
        self.authorize(peer)?;
        self.sandbox
            .heartbeat(&self.config.worker_id, self.config.worker_epoch)
            .map_err(|_| WorkerError::DependencyUnavailable)?;
        let mut worker = self.lock_worker()?;
        if worker.stopped {
            return Err(WorkerError::Stopped);
        }
        for executor in worker.sessions.values() {
            let mut session = executor
                .state
                .lock()
                .map_err(|_| WorkerError::StateUnavailable)?;
            let fence = session.machine.snapshot().owner_fence;
            if session.machine.lifecycle() == SessionLifecycle::Ready {
                session
                    .machine
                    .renew_lease(&fence, now)
                    .map_err(map_session_error)?;
            }
        }
        refresh_heartbeat_deadline(&mut worker)?;
        Ok(())
    }

    pub fn expire_due(
        &self,
        peer: &AuthenticatedPeer,
        now: SessionTime,
    ) -> Result<usize, WorkerError> {
        self.authorize(peer)?;
        let worker = self.lock_worker()?;
        let sessions = worker.sessions.values().cloned().collect::<Vec<_>>();
        drop(worker);
        let mut expired = 0usize;
        let mut ownership_lost = false;
        let mut cleanup_failed = false;
        let mut durability_failed = false;
        'sessions: for executor in sessions {
            let _cleanup_owner = executor
                .cleanup_owner
                .lock()
                .map_err(|_| WorkerError::StateUnavailable)?;
            let (mut session, approved_dispatch_phase, expiration_due) = loop {
                let session = executor
                    .state
                    .lock()
                    .map_err(|_| WorkerError::StateUnavailable)?;
                if !matches!(
                    session.machine.lifecycle(),
                    SessionLifecycle::Creating | SessionLifecycle::Ready
                ) {
                    continue 'sessions;
                }
                let snapshot = session.machine.snapshot();
                let expiration_due = [
                    snapshot.lease_expires_at,
                    snapshot.session_expires_at,
                    snapshot.idle_expires_at,
                ]
                .into_iter()
                .flatten()
                .any(|deadline| now >= deadline);
                if !expiration_due {
                    break (
                        session,
                        executor.approved_dispatch_phase.load(Ordering::Acquire),
                        false,
                    );
                }
                match executor.approved_dispatch_phase.load(Ordering::Acquire) {
                    APPROVED_DISPATCH_INSPECTING
                    | APPROVED_DISPATCH_DRIVER_PENDING
                    | APPROVED_DISPATCH_AUTHORIZING => {
                        drop(session);
                        stop_or_observe_approved_dispatch(&executor);
                    }
                    phase => break (session, phase, true),
                }
            };
            let fence = session.machine.snapshot().owner_fence;
            if expire_pending_approvals(&mut session, &fence, now).is_err() {
                durability_failed = true;
            }
            if expiration_due
                && approved_dispatch_phase == APPROVED_DISPATCH_STOPPED
                && terminalize_stopped_approved_dispatch(
                    &mut session,
                    &fence,
                    now,
                    &*self.stopped_dispatch_terminalization_hook,
                )
                .is_err()
            {
                durability_failed = true;
            }
            match session
                .machine
                .expire_due(&fence, now)
                .map_err(map_session_error)?
            {
                ExpireDecision::NotDue { .. } => {}
                ExpireDecision::BeganExpiring => {
                    if terminalize_actions_for_shutdown(&mut session).is_err() {
                        durability_failed = true;
                    }
                    let session_id = session.machine.session_id().clone();
                    let mut cleanup_machine = session.machine.clone();
                    drop(session);
                    let mut cleanup = WorkerCleanup {
                        driver: &*self.driver,
                        sandbox: &*self.sandbox,
                        session_id: &session_id,
                        fence: &fence,
                    };
                    let cleanup_result = cleanup_machine.run_cleanup(&fence, &mut cleanup);
                    let mut session = executor
                        .state
                        .lock()
                        .map_err(|_| WorkerError::StateUnavailable)?;
                    validate_fence(&session, &fence)?;
                    session.machine = cleanup_machine;
                    if cleanup_result.is_ok() {
                        session.occupies_capacity = false;
                        expired = expired.saturating_add(1);
                    } else {
                        cleanup_failed = true;
                    }
                }
                ExpireDecision::OwnershipLost => {
                    ownership_lost = true;
                    if terminalize_actions_for_shutdown(&mut session).is_err() {
                        durability_failed = true;
                    }
                    let session_id = session.machine.session_id().clone();
                    drop(session);
                    let cleanup_result = if self.driver.shard_managed_contexts() {
                        self.driver.close_context_fenced(&session_id, &fence)
                    } else {
                        self.sandbox
                            .cleanup(&session_id, CleanupReason::WorkerLeaseExpired)
                    };
                    let mut session = executor
                        .state
                        .lock()
                        .map_err(|_| WorkerError::StateUnavailable)?;
                    if cleanup_result.is_ok() {
                        session.occupies_capacity = false;
                        expired = expired.saturating_add(1);
                    } else {
                        cleanup_failed = true;
                    }
                }
            }
        }
        let mut worker = self.lock_worker()?;
        if ownership_lost {
            worker.draining = true;
        }
        refresh_heartbeat_deadline(&mut worker)?;
        if cleanup_failed {
            Err(WorkerError::CleanupFailed)
        } else if durability_failed {
            Err(WorkerError::DurabilityUnavailable)
        } else {
            Ok(expired)
        }
    }

    pub fn heartbeat_deadline(
        &self,
        peer: &AuthenticatedPeer,
    ) -> Result<Option<SessionTime>, WorkerError> {
        self.authorize(peer)?;
        Ok(self.lock_worker()?.heartbeat_expires_at)
    }

    pub fn begin_drain(&self, peer: &AuthenticatedPeer) -> Result<(), WorkerError> {
        self.authorize(peer)?;
        let mut worker = self.lock_worker()?;
        if worker.stopped {
            return Err(WorkerError::Stopped);
        }
        worker.draining = true;
        Ok(())
    }

    pub fn graceful_shutdown(
        &self,
        peer: &AuthenticatedPeer,
        now: SessionTime,
    ) -> Result<(), WorkerError> {
        self.begin_drain(peer)?;
        let (sessions, create_cleanup_failed) = {
            let mut worker = self.lock_worker()?;
            while worker.creating_sessions != 0 {
                worker = self
                    .create_idle
                    .wait(worker)
                    .map_err(|_| WorkerError::StateUnavailable)?;
            }
            (
                worker.sessions.keys().cloned().collect::<Vec<_>>(),
                worker.create_cleanup_failed,
            )
        };
        for session_id in sessions {
            let executor = self.session(&session_id)?;
            let (fence, lifecycle, occupies_capacity) = {
                let session = executor
                    .state
                    .lock()
                    .map_err(|_| WorkerError::StateUnavailable)?;
                (
                    session.machine.snapshot().owner_fence,
                    session.machine.lifecycle(),
                    session.occupies_capacity,
                )
            };
            match lifecycle {
                SessionLifecycle::Closed => {}
                SessionLifecycle::Failed => {
                    if occupies_capacity {
                        if !self.driver.shard_managed_contexts() {
                            self.sandbox
                                .cleanup(&session_id, CleanupReason::WorkerLeaseExpired)
                                .map_err(|_| WorkerError::CleanupFailed)?;
                        }
                        executor
                            .state
                            .lock()
                            .map_err(|_| WorkerError::StateUnavailable)?
                            .occupies_capacity = false;
                    }
                }
                _ => {
                    let _ = self.close_session(peer, &session_id, &fence, now)?;
                }
            }
        }
        if create_cleanup_failed {
            return Err(WorkerError::CleanupFailed);
        }
        self.lock_worker()?.stopped = true;
        Ok(())
    }

    fn authorize(&self, peer: &AuthenticatedPeer) -> Result<(), WorkerError> {
        if peer == &self.config.trusted_peer {
            Ok(())
        } else {
            Err(WorkerError::UnauthorizedPeer)
        }
    }

    fn lock_worker(&self) -> Result<MutexGuard<'_, WorkerState>, WorkerError> {
        self.state.lock().map_err(|_| WorkerError::StateUnavailable)
    }

    fn session(&self, session_id: &SessionId) -> Result<Arc<SessionExecutor>, WorkerError> {
        self.lock_worker()?
            .sessions
            .get(session_id)
            .cloned()
            .ok_or(WorkerError::SessionNotFound)
    }
}

struct ActionOwner<'a>(&'a AtomicBool);

impl<'a> ActionOwner<'a> {
    fn claim(owner: &'a AtomicBool) -> Result<Self, WorkerError> {
        owner
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| WorkerError::QueueFull)?;
        Ok(Self(owner))
    }
}

impl Drop for ActionOwner<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

fn stop_or_observe_approved_dispatch(executor: &SessionExecutor) -> u8 {
    loop {
        let phase = executor.approved_dispatch_phase.load(Ordering::Acquire);
        match phase {
            APPROVED_DISPATCH_INSPECTING => {
                if executor
                    .approved_dispatch_phase
                    .compare_exchange(
                        APPROVED_DISPATCH_INSPECTING,
                        APPROVED_DISPATCH_STOPPED,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_ok()
                {
                    return APPROVED_DISPATCH_STOPPED;
                }
            }
            APPROVED_DISPATCH_DRIVER_PENDING => {
                if executor
                    .approved_dispatch_phase
                    .compare_exchange(
                        APPROVED_DISPATCH_DRIVER_PENDING,
                        APPROVED_DISPATCH_REVOKE_REQUESTED,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_ok()
                {
                    return APPROVED_DISPATCH_REVOKE_REQUESTED;
                }
            }
            APPROVED_DISPATCH_AUTHORIZING => std::thread::yield_now(),
            _ => return phase,
        }
    }
}

struct WorkerCleanup<'a, D, S> {
    driver: &'a D,
    sandbox: &'a S,
    session_id: &'a SessionId,
    fence: &'a OwnershipFence,
}

impl<D: ChromiumDriver, S: SandboxClient> CleanupBackend for WorkerCleanup<'_, D, S> {
    fn run_stage(
        &mut self,
        stage: CleanupStage,
        _active_targets: &[TargetId],
    ) -> Result<(), CleanupFailure> {
        let result = match stage {
            CleanupStage::ForceCloseTargets | CleanupStage::DisposeBrowserContext => {
                if stage == CleanupStage::DisposeBrowserContext {
                    self.driver
                        .close_context_fenced(self.session_id, self.fence)
                } else {
                    Ok(())
                }
            }
            CleanupStage::RevokeProxyRoute => {
                if self.driver.shard_managed_contexts() {
                    Ok(())
                } else {
                    self.sandbox
                        .cleanup(self.session_id, CleanupReason::Administrative)
                }
            }
            _ => Ok(()),
        };
        result.map_err(|_| CleanupFailure::Injected)
    }
}

fn validate_fence(session: &SessionState, fence: &OwnershipFence) -> Result<(), WorkerError> {
    if session.machine.snapshot().owner_fence == *fence {
        Ok(())
    } else {
        Err(WorkerError::StaleFence)
    }
}

fn page_snapshot(
    session: &SessionState,
    page_id: &PageId,
) -> Result<WorkerPageSnapshot, WorkerError> {
    if !session.pages.contains(page_id) && !session.closed_pages.contains(page_id) {
        return Err(WorkerError::PageNotFound);
    }
    Ok(WorkerPageSnapshot {
        page_id: page_id.clone(),
        active: session.pages.contains(page_id) && session.active_page_id == *page_id,
        target_incarnation: 1,
        document_epoch: 1,
        url_revision: 0,
    })
}

fn worker_approval_snapshot(
    approval_id: &ApprovalId,
    approval: &ApprovalRecord,
) -> WorkerApprovalSnapshot {
    WorkerApprovalSnapshot {
        approval_id: approval_id.clone(),
        action_id: approval.action_id.clone(),
        state: approval.state.clone(),
        proposal_hash: approval.proposal.hash(),
        proposal: approval.proposal.clone(),
    }
}

fn expire_pending_approvals(
    session: &mut SessionState,
    fence: &OwnershipFence,
    now: SessionTime,
) -> Result<usize, WorkerError> {
    let due = session
        .approvals
        .iter()
        .filter(|(_, approval)| {
            approval.state == ApprovalState::Pending && now >= approval.expires_at
        })
        .map(|(approval_id, approval)| (approval_id.clone(), approval.action_id.clone()))
        .collect::<Vec<_>>();
    for (_, action_id) in &due {
        if !session
            .actions
            .get(action_id)
            .is_some_and(|action| action.snapshot.status == ActionStatus::PendingApproval)
        {
            return Err(WorkerError::StateUnavailable);
        }
    }
    for (approval_id, action_id) in &due {
        if let Err(error) = session
            .action_ledger
            .expire_approval(fence.as_placement_fence(), action_id)
        {
            session.durability_degraded = true;
            return Err(map_action_ledger_error(error));
        }
        session.action_queue.retain(|queued| queued != action_id);
        session
            .actions
            .get_mut(action_id)
            .ok_or(WorkerError::StateUnavailable)?
            .snapshot
            .status = ActionStatus::FailedKnown;
        session
            .approvals
            .get_mut(approval_id)
            .ok_or(WorkerError::StateUnavailable)?
            .state = ApprovalState::Expired;
    }
    Ok(due.len())
}

fn terminalize_stopped_approved_dispatch(
    session: &mut SessionState,
    fence: &OwnershipFence,
    now: SessionTime,
    terminalization_hook: &(dyn Fn() -> Result<(), WorkerError> + Send + Sync),
) -> Result<(), WorkerError> {
    let SessionExecution::Running(action_id) = session.machine.snapshot().execution else {
        return Ok(());
    };
    let Some(permit) = session.actions.get(&action_id).and_then(|action| {
        (action.snapshot.status == ActionStatus::Running)
            .then(|| action.dispatch_permit.clone())
            .flatten()
    }) else {
        return Ok(());
    };
    let completion_now = now.max(session.machine.last_observed_at());
    let mut completed_machine = session.machine.clone();
    completed_machine
        .finish_action(fence, &action_id, completion_now)
        .map_err(map_session_error)?;
    let terminalization = terminalization_hook().and_then(|()| {
        session
            .action_ledger
            .record_result(
                fence.as_placement_fence(),
                &permit,
                BrowserResult::FailedKnown(KnownFailureReason::NotDispatched),
            )
            .map(|_| ())
            .map_err(map_action_ledger_error)
    });
    if let Err(error) = terminalization {
        session.durability_degraded = true;
        let _ = session
            .machine
            .mark_action_outcome_unknown(fence, &action_id, completion_now);
        if let Some(action) = session.actions.get_mut(&action_id) {
            action.snapshot.status = ActionStatus::OutcomeUnknown;
        }
        return Err(error);
    }
    session.machine = completed_machine;
    let action = session
        .actions
        .get_mut(&action_id)
        .ok_or(WorkerError::ActionNotFound)?;
    action.snapshot.status = ActionStatus::FailedKnown;
    action.snapshot.result = Some(b"browser effect not started before session shutdown".to_vec());
    Ok(())
}

fn terminalize_actions_for_shutdown(session: &mut SessionState) -> Result<(), WorkerError> {
    let fence = session.machine.snapshot().owner_fence.as_placement_fence();
    let mut first_error = None;
    let uncertain = session
        .actions
        .iter()
        .filter(|(_, action)| {
            action.dispatch_permit.is_some()
                && matches!(
                    action.snapshot.status,
                    ActionStatus::Running | ActionStatus::OutcomeUnknown
                )
        })
        .map(|(action_id, action)| {
            (
                action_id.clone(),
                action
                    .dispatch_permit
                    .clone()
                    .ok_or(WorkerError::StateUnavailable),
            )
        })
        .collect::<Vec<_>>();
    for (action_id, permit) in uncertain {
        let transition = permit.and_then(|permit| {
            let snapshot = session
                .action_ledger
                .snapshot(fence, &action_id)
                .map_err(map_action_ledger_error)?;
            if snapshot.state() == ActionState::MayHaveExecuted {
                session
                    .action_ledger
                    .record_transport_loss(
                        fence,
                        &permit,
                        TransportLoss::Ambiguous(OutcomeUnknownReason::WorkerLost),
                    )
                    .map(|_| ())
                    .map_err(map_action_ledger_error)
            } else if snapshot.state().is_terminal() {
                Ok(())
            } else {
                Err(WorkerError::StateUnavailable)
            }
        });
        if let Err(error) = transition
            && first_error.is_none()
        {
            first_error = Some(error);
        }
        if let Some(action) = session.actions.get_mut(&action_id) {
            action.snapshot.status = ActionStatus::OutcomeUnknown;
        }
    }
    let queued = session.action_queue.iter().cloned().collect::<Vec<_>>();
    let mut terminalized = BTreeSet::new();
    for action_id in queued {
        let status = session
            .actions
            .get(&action_id)
            .map(|action| action.snapshot.status);
        let transition = match status {
            Some(ActionStatus::Queued) => session
                .action_ledger
                .cancel_before_dispatch(fence, &action_id),
            Some(ActionStatus::PendingApproval) => {
                session.action_ledger.expire_approval(fence, &action_id)
            }
            _ => continue,
        };
        match transition {
            Ok(_) => {
                terminalized.insert(action_id.clone());
                if let Some(action) = session.actions.get_mut(&action_id) {
                    action.snapshot.status = match status {
                        Some(ActionStatus::PendingApproval) => ActionStatus::FailedKnown,
                        _ => ActionStatus::CancelledBeforeDispatch,
                    };
                }
            }
            Err(error) if first_error.is_none() => {
                first_error = Some(map_action_ledger_error(error));
            }
            Err(_) => {}
        }
    }
    session
        .action_queue
        .retain(|action_id| !terminalized.contains(action_id));
    for approval in session.approvals.values_mut() {
        if approval.state == ApprovalState::Pending && terminalized.contains(&approval.action_id) {
            approval.state = ApprovalState::Expired;
        }
    }
    session.durability_degraded = first_error.is_some();
    first_error.map_or(Ok(()), Err)
}

fn refresh_heartbeat_deadline(worker: &mut WorkerState) -> Result<(), WorkerError> {
    let mut heartbeat_expires_at = None;
    for executor in worker.sessions.values() {
        let session = executor
            .state
            .lock()
            .map_err(|_| WorkerError::StateUnavailable)?;
        if matches!(
            session.machine.lifecycle(),
            SessionLifecycle::Creating | SessionLifecycle::Ready
        ) && let Some(deadline) = session.machine.lease_expires_at()
        {
            heartbeat_expires_at = Some(
                heartbeat_expires_at.map_or(deadline, |current: SessionTime| current.min(deadline)),
            );
        }
    }
    worker.heartbeat_expires_at = heartbeat_expires_at;
    Ok(())
}

fn map_session_error(error: SessionError) -> WorkerError {
    match error {
        SessionError::StaleWorkerId
        | SessionError::WorkerEpochMismatch { .. }
        | SessionError::PlacementVersionMismatch { .. }
        | SessionError::SessionIncarnationMismatch { .. } => WorkerError::StaleFence,
        SessionError::StateUnavailable => WorkerError::StateUnavailable,
        _ => WorkerError::InvalidActionTransition,
    }
}

fn durable_action_request_hash(
    request_hash: [u8; 32],
    requester_principal_id: &PrincipalId,
    approval_binding: Option<(&ProposalHash, bool)>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"browserd-worker-action-request-v2\0");
    hasher.update(request_hash);
    hasher.update(requester_principal_id.as_bytes());
    match approval_binding {
        Some((proposal_hash, require_four_eyes)) => {
            hasher.update([1]);
            hasher.update(proposal_hash.as_bytes());
            hasher.update([u8::from(require_four_eyes)]);
        }
        None => hasher.update([0]),
    }
    hasher.finalize().into()
}

fn map_action_ledger_error(error: ActionLedgerError) -> WorkerError {
    match error {
        ActionLedgerError::JournalUnavailable(_) | ActionLedgerError::RecoveryInvalid(_) => {
            WorkerError::DurabilityUnavailable
        }
        ActionLedgerError::StateUnavailable => WorkerError::StateUnavailable,
        ActionLedgerError::StaleFence { .. } => WorkerError::StaleFence,
        ActionLedgerError::IdempotencyConflict { .. } => WorkerError::IdempotencyConflict,
        ActionLedgerError::ActionNotFound => WorkerError::ActionNotFound,
        ActionLedgerError::ApprovalDecisionConflict { .. } => {
            WorkerError::InvalidApprovalTransition
        }
        _ => WorkerError::InvalidActionTransition,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkerEpochError {
    Io,
    Corrupt,
    Overflow,
}

pub struct DurableWorkerEpoch;

impl DurableWorkerEpoch {
    pub fn increment(path: impl AsRef<Path>) -> Result<u64, WorkerEpochError> {
        let path = path.as_ref();
        let parent = path.parent().ok_or(WorkerEpochError::Io)?;
        let file_name = path.file_name().ok_or(WorkerEpochError::Io)?;
        let mut lock_name = file_name.to_os_string();
        lock_name.push(".lock");
        let lock_path = parent.join(lock_name);
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(lock_path)
            .map_err(|_| WorkerEpochError::Io)?;
        lock.lock().map_err(|_| WorkerEpochError::Io)?;

        let previous = match File::open(path) {
            Ok(mut current) => {
                let mut contents = String::new();
                current
                    .read_to_string(&mut contents)
                    .map_err(|_| WorkerEpochError::Io)?;
                contents
                    .trim_end_matches('\n')
                    .parse::<u64>()
                    .map_err(|_| WorkerEpochError::Corrupt)?
            }
            Err(error) if error.kind() == ErrorKind::NotFound => 0,
            Err(_) => return Err(WorkerEpochError::Io),
        };
        let next = previous.checked_add(1).ok_or(WorkerEpochError::Overflow)?;
        let mut temporary_name = file_name.to_os_string();
        temporary_name.push(format!(".{}.tmp", Uuid::new_v4()));
        let temporary_path = parent.join(temporary_name);
        let mut temporary = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary_path)
            .map_err(|_| WorkerEpochError::Io)?;
        writeln!(temporary, "{next}").map_err(|_| WorkerEpochError::Io)?;
        temporary.sync_all().map_err(|_| WorkerEpochError::Io)?;
        std::fs::rename(&temporary_path, path).map_err(|_| WorkerEpochError::Io)?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| WorkerEpochError::Io)?;
        Ok(next)
    }
}

#[derive(Default)]
pub struct UnavailableChromiumDriver;

impl ChromiumDriver for UnavailableChromiumDriver {
    fn qualify(&self) -> Result<(), DependencyError> {
        Err(DependencyError::Unavailable)
    }
    fn create_context(&self, _session_id: &SessionId) -> Result<PageId, DependencyError> {
        Err(DependencyError::Unavailable)
    }
    fn close_context(&self, _session_id: &SessionId) -> Result<(), DependencyError> {
        Err(DependencyError::Unavailable)
    }
    fn create_page(&self, _session_id: &SessionId) -> Result<PageId, DependencyError> {
        Err(DependencyError::Unavailable)
    }
    fn close_page(
        &self,
        _session_id: &SessionId,
        _page_id: &PageId,
    ) -> Result<(), DependencyError> {
        Err(DependencyError::Unavailable)
    }
    fn activate_page(
        &self,
        _session_id: &SessionId,
        _page_id: &PageId,
    ) -> Result<(), DependencyError> {
        Err(DependencyError::Unavailable)
    }
    fn execute_action(
        &self,
        _session_id: &SessionId,
        _page_id: Option<&PageId>,
        _payload: &[u8],
    ) -> ActionExecutionResult {
        ActionExecutionResult::OutcomeUnknown
    }
    fn inspect_approval_context(
        &self,
        _session_id: &SessionId,
        _page_id: &PageId,
        _proposal: &CanonicalActionProposal,
    ) -> Result<LiveApprovalContext, DependencyError> {
        Err(DependencyError::Unavailable)
    }
    fn execute_approved_action(
        &self,
        _session_id: &SessionId,
        _page_id: &PageId,
        _payload: &[u8],
        _proposal: &CanonicalActionProposal,
        _inspected: &LiveApprovalContext,
        _authorize_and_commit: &mut dyn FnMut(
            &LiveApprovalContext,
        ) -> Result<(), ApprovedActionError>,
    ) -> Result<ActionExecutionResult, ApprovedActionError> {
        Err(ApprovedActionError::Unavailable)
    }
    fn cancel_action(
        &self,
        _session_id: &SessionId,
        _action_id: &ActionId,
    ) -> Result<bool, DependencyError> {
        Err(DependencyError::Unavailable)
    }
}

#[derive(Default)]
pub struct UnavailableSandboxClient;

impl SandboxClient for UnavailableSandboxClient {
    fn qualify(&self) -> Result<(), DependencyError> {
        Err(DependencyError::Unavailable)
    }
    fn provision(
        &self,
        _session_id: &SessionId,
        _fence: &OwnershipFence,
    ) -> Result<(), DependencyError> {
        Err(DependencyError::Unavailable)
    }
    fn cleanup(
        &self,
        _session_id: &SessionId,
        _reason: CleanupReason,
    ) -> Result<(), DependencyError> {
        Err(DependencyError::Unavailable)
    }
    fn heartbeat(&self, _worker_id: &WorkerId, _worker_epoch: u64) -> Result<(), DependencyError> {
        Err(DependencyError::Unavailable)
    }
    fn store_artifact(
        &self,
        _request: &ArtifactStoreRequest,
    ) -> Result<ArtifactStoreReceipt, DependencyError> {
        Err(DependencyError::Unavailable)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::AtomicU64;
    use std::sync::mpsc;
    use std::thread;

    use browserd_policy::CredentialRefsHash;

    #[derive(Default)]
    struct DecisionDriver;

    impl ChromiumDriver for DecisionDriver {
        fn qualify(&self) -> Result<(), DependencyError> {
            Ok(())
        }

        fn create_context(&self, _session_id: &SessionId) -> Result<PageId, DependencyError> {
            Ok(PageId::new())
        }

        fn close_context(&self, _session_id: &SessionId) -> Result<(), DependencyError> {
            Ok(())
        }

        fn create_page(&self, _session_id: &SessionId) -> Result<PageId, DependencyError> {
            Ok(PageId::new())
        }

        fn close_page(
            &self,
            _session_id: &SessionId,
            _page_id: &PageId,
        ) -> Result<(), DependencyError> {
            Ok(())
        }

        fn activate_page(
            &self,
            _session_id: &SessionId,
            _page_id: &PageId,
        ) -> Result<(), DependencyError> {
            Ok(())
        }

        fn execute_action(
            &self,
            _session_id: &SessionId,
            _page_id: Option<&PageId>,
            _payload: &[u8],
        ) -> ActionExecutionResult {
            ActionExecutionResult::OutcomeUnknown
        }

        fn inspect_approval_context(
            &self,
            _session_id: &SessionId,
            _page_id: &PageId,
            _proposal: &CanonicalActionProposal,
        ) -> Result<LiveApprovalContext, DependencyError> {
            Err(DependencyError::Unavailable)
        }

        fn execute_approved_action(
            &self,
            _session_id: &SessionId,
            _page_id: &PageId,
            _payload: &[u8],
            _proposal: &CanonicalActionProposal,
            _inspected: &LiveApprovalContext,
            _authorize_and_commit: &mut dyn FnMut(
                &LiveApprovalContext,
            ) -> Result<(), ApprovedActionError>,
        ) -> Result<ActionExecutionResult, ApprovedActionError> {
            Err(ApprovedActionError::Unavailable)
        }

        fn cancel_action(
            &self,
            _session_id: &SessionId,
            _action_id: &ActionId,
        ) -> Result<bool, DependencyError> {
            Ok(false)
        }
    }

    #[derive(Default)]
    struct DecisionSandbox;

    impl SandboxClient for DecisionSandbox {
        fn qualify(&self) -> Result<(), DependencyError> {
            Ok(())
        }

        fn provision(
            &self,
            _session_id: &SessionId,
            _fence: &OwnershipFence,
        ) -> Result<(), DependencyError> {
            Ok(())
        }

        fn cleanup(
            &self,
            _session_id: &SessionId,
            _reason: CleanupReason,
        ) -> Result<(), DependencyError> {
            Ok(())
        }

        fn heartbeat(
            &self,
            _worker_id: &WorkerId,
            _worker_epoch: u64,
        ) -> Result<(), DependencyError> {
            Ok(())
        }

        fn store_artifact(
            &self,
            request: &ArtifactStoreRequest,
        ) -> Result<ArtifactStoreReceipt, DependencyError> {
            ArtifactStoreReceipt::new(
                request.key().clone(),
                request.expected_size_bytes(),
                *request.expected_checksum(),
                request.declared_content_type(),
                ArtifactObjectGeneration::new([1; ArtifactObjectGeneration::LENGTH]),
                ArtifactScanVerdict::Clean,
            )
            .map_err(|_| DependencyError::Rejected)
        }
    }

    struct SignallingClock {
        now: AtomicU64,
        sampled: mpsc::Sender<()>,
    }

    impl WorkerClock for SignallingClock {
        fn now(&self) -> Result<SessionTime, WorkerError> {
            let _ = self.sampled.send(());
            Ok(SessionTime::new(self.now.load(Ordering::Acquire)))
        }
    }

    #[test]
    fn approval_decision_samples_trusted_time_after_acquiring_the_session_lock() {
        let journal = tempfile::tempdir().expect("journal directory should be created");
        let peer = AuthenticatedPeer::new("gateway-internal").expect("peer should be valid");
        let config = WorkerConfig::new(
            WorkerId::new("decision-clock-worker").expect("worker id should be valid"),
            1,
            InternalEndpoint::loopback(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9018))
                .expect("endpoint should be valid"),
            peer.clone(),
            1,
            2,
            LeasePolicy::new(Duration::from_secs(30), Duration::from_secs(1))
                .expect("lease policy should be valid"),
            SessionTimeoutPolicy::new(Duration::from_secs(60), Duration::from_secs(30))
                .expect("timeout policy should be valid"),
            Duration::from_millis(10),
            ActionJournalConfig::new(journal.path(), ActionJournalLimits::default())
                .expect("journal should be valid"),
        )
        .expect("worker config should be valid");
        let (sampled_tx, sampled_rx) = mpsc::channel();
        let clock = Arc::new(SignallingClock {
            now: AtomicU64::new(2),
            sampled: sampled_tx,
        });
        let worker = Arc::new(WorkerControlPlane::new_with_clock(
            config,
            Arc::new(DecisionDriver),
            Arc::new(DecisionSandbox),
            Arc::clone(&clock),
        ));
        let tenant_id = TenantId::new();
        let requester = PrincipalId::new();
        let created = worker
            .create_session(
                &peer,
                CreateSessionCommand {
                    tenant_id: tenant_id.clone(),
                    idempotency_key: "decision-clock-create".to_owned(),
                    canonical_request_hash: [1; 32],
                    placement_version: 1,
                    session_incarnation: 1,
                },
                SessionTime::new(0),
            )
            .expect("session should be created");
        let payload = b"click";
        let proposal = CanonicalActionProposal::new(
            tenant_id,
            requester.clone(),
            created.session_id.clone(),
            created.fence.session_incarnation(),
            created.primary_page_id.clone(),
            1,
            1,
            Origin::parse("https://example.test/").expect("origin should be valid"),
            1,
            ActionType::Click,
            ActionArgumentsHash::digest(payload),
            None,
            CredentialRefsHash::digest(std::iter::empty()),
            11,
        );
        let action_id = worker
            .submit_action(
                &peer,
                requester,
                &created.session_id,
                &created.fence,
                "decision-clock-action",
                [2; 32],
                ActionKind::Mutating,
                None,
                Some(created.primary_page_id.clone()),
                payload.to_vec(),
                Some(ActionApprovalRequirement::new(
                    proposal,
                    ActionType::Click,
                    true,
                )),
                SessionTime::new(1),
            )
            .expect("approval action should be accepted");
        let approval_id = worker
            .approval_for_action(&peer, &created.session_id, &action_id, &created.fence)
            .expect("approval should exist");
        let executor = worker
            .session(&created.session_id)
            .expect("session executor should exist");
        let state = executor.state.lock().expect("session lock should work");

        let decision_worker = Arc::clone(&worker);
        let decision_peer = peer.clone();
        let decision_session_id = created.session_id.clone();
        let decision_fence = created.fence.clone();
        let decision = thread::spawn(move || {
            decision_worker.decide_approval(
                &decision_peer,
                &decision_session_id,
                &approval_id,
                &decision_fence,
                ApprovalDecision::Approve,
                PrincipalId::new(),
                SessionTime::new(2),
            )
        });
        let sampled_before_session_lock =
            sampled_rx.recv_timeout(Duration::from_millis(100)).is_ok();
        clock.now.store(12, Ordering::Release);
        drop(state);

        assert!(
            !sampled_before_session_lock,
            "trusted time must be sampled at the decision linearization point"
        );
        assert_eq!(
            decision.join().expect("decision thread should not panic"),
            Err(WorkerError::ApprovalPolicy(ApprovalError::ApprovalExpired))
        );
    }

    #[test]
    fn action_lookup_rejects_an_in_memory_hash_that_disagrees_with_the_durable_ledger() {
        let journal = tempfile::tempdir().expect("journal directory should be created");
        let peer =
            AuthenticatedPeer::new("gateway-action-hash").expect("peer identity should be valid");
        let config = WorkerConfig::new(
            WorkerId::new("action-hash-worker").expect("worker id should be valid"),
            1,
            InternalEndpoint::loopback(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9019))
                .expect("endpoint should be valid"),
            peer.clone(),
            1,
            2,
            LeasePolicy::new(Duration::from_secs(30), Duration::from_secs(1))
                .expect("lease policy should be valid"),
            SessionTimeoutPolicy::new(Duration::from_secs(60), Duration::from_secs(30))
                .expect("timeout policy should be valid"),
            Duration::from_millis(10),
            ActionJournalConfig::new(journal.path(), ActionJournalLimits::default())
                .expect("journal should be valid"),
        )
        .expect("worker config should be valid");
        let worker =
            WorkerControlPlane::new(config, Arc::new(DecisionDriver), Arc::new(DecisionSandbox));
        let created = worker
            .create_session(
                &peer,
                CreateSessionCommand {
                    tenant_id: TenantId::new(),
                    idempotency_key: "action-hash-create".to_owned(),
                    canonical_request_hash: [1; 32],
                    placement_version: 1,
                    session_incarnation: 1,
                },
                SessionTime::new(0),
            )
            .expect("session should be created");
        let action_id = worker
            .submit_action(
                &peer,
                PrincipalId::new(),
                &created.session_id,
                &created.fence,
                "action-hash-key",
                [2; 32],
                ActionKind::ReadOnly,
                None,
                Some(created.primary_page_id.clone()),
                b"get-title".to_vec(),
                None,
                SessionTime::new(1),
            )
            .expect("action should be accepted");
        let executor = worker
            .session(&created.session_id)
            .expect("session executor should exist");
        executor
            .state
            .lock()
            .expect("session lock should work")
            .actions
            .get_mut(&action_id)
            .expect("action should exist")
            .snapshot
            .canonical_request_hash = [9; 32];

        assert!(matches!(
            worker.get_action(&peer, &created.session_id, &action_id, &created.fence),
            Err(WorkerError::StateUnavailable)
        ));
    }
}
