//! Fenced, transport-neutral browser worker control plane.

#![forbid(unsafe_code)]

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::net::SocketAddr;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use browserd_actions::{
    AcceptDecision, ActionJournalLimits, ActionKind, ActionLedger, ActionLedgerError,
    ActionRequest, ActionSequence, BrowserResult, CanonicalRequestHash as ActionRequestHash,
    DispatchDecision, DispatchPermit, FileActionJournal, IdempotencyKey as ActionIdempotencyKey,
    KnownFailureReason, LedgerSession, OutcomeUnknownReason, ResolutionAnnotation, ResolutionKind,
    ResolutionOutcome, ResolutionPolicy, ResultDigest, TransportLoss,
};
use browserd_artifacts::{Artifact, ArtifactEvent, ArtifactKey, ArtifactState};
use browserd_core::{
    ActionId, ActionState, ArtifactId, LeaseId, OperationId, PageId, PrincipalId, SessionId,
    TenantId, WorkerId,
};
use browserd_features::{BuiltinFeature, FeatureRegistry};
use browserd_fleet::WorkerEpochRegistry;
use browserd_operations::{
    CanonicalRequestHash, IdempotencyClaim, IdempotencyKey, IdempotencyRegistry,
};
use browserd_policy::{ApprovalDecision, ApprovalState};
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
    ArtifactNotFound,
    InvalidActionTransition,
    InvalidApprovalTransition,
    DurabilityUnavailable,
    DependencyUnavailable,
    CleanupFailed,
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

pub trait ChromiumDriver: Send + Sync + 'static {
    fn qualify(&self) -> Result<(), DependencyError>;
    fn create_context(&self, session_id: &SessionId) -> Result<PageId, DependencyError>;
    fn close_context(&self, session_id: &SessionId) -> Result<(), DependencyError>;
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
        session_id: &SessionId,
        upload: &ArtifactUpload,
    ) -> Result<(), DependencyError>;
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
        })
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
    pub status: ActionStatus,
    pub kind: ActionKind,
    pub feature: Option<BuiltinFeature>,
    pub result: Option<Vec<u8>>,
    pub resolution: Option<ResolutionAnnotation>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactUpload {
    pub bytes: Vec<u8>,
    pub content_type: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerArtifactSnapshot {
    pub artifact_id: ArtifactId,
    pub state: ArtifactState,
    pub size_bytes: u64,
    pub content_type: String,
}

pub type ApprovalId = LeaseId;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerApprovalSnapshot {
    pub approval_id: ApprovalId,
    pub action_id: ActionId,
    pub state: ApprovalState,
}

struct ActionRecord {
    snapshot: WorkerActionSnapshot,
    page_id: Option<PageId>,
    payload: Vec<u8>,
    approval_id: Option<ApprovalId>,
    dispatch_permit: Option<DispatchPermit>,
}

struct ArtifactRecord {
    artifact: Artifact,
    size_bytes: u64,
    content_type: String,
}

struct ApprovalRecord {
    action_id: ActionId,
    state: ApprovalState,
    expires_at: SessionTime,
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

struct SessionState {
    tenant_id: TenantId,
    machine: SessionMachine,
    occupies_capacity: bool,
    primary_page_id: PageId,
    pages: BTreeSet<PageId>,
    closed_pages: BTreeSet<PageId>,
    action_idempotency: HashMap<String, ([u8; 32], ActionId)>,
    actions: HashMap<ActionId, ActionRecord>,
    action_queue: VecDeque<ActionId>,
    artifacts: HashMap<ArtifactId, ArtifactRecord>,
    approvals: HashMap<ApprovalId, ApprovalRecord>,
    action_ledger: ActionLedger<FileActionJournal>,
    durability_degraded: bool,
}

struct SessionExecutor {
    state: Mutex<SessionState>,
    action_owner: AtomicBool,
}

#[derive(Clone)]
enum CreateOperationResult {
    Succeeded(CreateSessionOutcome),
    Failed(WorkerError),
}

struct WorkerState {
    sessions: HashMap<SessionId, Arc<SessionExecutor>>,
    create_operations: HashMap<OperationId, CreateOperationResult>,
    draining: bool,
    stopped: bool,
    heartbeat_expires_at: Option<SessionTime>,
}

pub struct WorkerControlPlane<D, S> {
    config: WorkerConfig,
    driver: Arc<D>,
    sandbox: Arc<S>,
    state: Mutex<WorkerState>,
    create_idempotency: IdempotencyRegistry,
    viewer_tickets: Option<TicketRegistry>,
    _fleet_epochs: WorkerEpochRegistry,
    _features: FeatureRegistry,
}

impl<D: ChromiumDriver, S: SandboxClient> WorkerControlPlane<D, S> {
    #[must_use]
    pub fn new(config: WorkerConfig, driver: Arc<D>, sandbox: Arc<S>) -> Self {
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
                draining: false,
                stopped: false,
                heartbeat_expires_at: None,
            }),
            create_idempotency: IdempotencyRegistry::default(),
            viewer_tickets,
            _fleet_epochs: fleet_epochs,
            _features: FeatureRegistry::builtin(),
        }
    }

    #[must_use]
    pub fn is_ready(&self) -> bool {
        let Ok(state) = self.state.lock() else {
            return false;
        };
        !state.draining
            && !state.stopped
            && state.sessions.values().all(|executor| {
                executor
                    .state
                    .lock()
                    .is_ok_and(|session| !session.durability_degraded)
            })
            && self.config.action_journal.qualify()
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
        let mut worker = self.lock_worker()?;
        if worker.stopped {
            return Err(WorkerError::Stopped);
        }
        if worker.draining {
            return Err(WorkerError::Draining);
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
            return match worker
                .create_operations
                .get(operation_id)
                .cloned()
                .ok_or(WorkerError::StateUnavailable)?
            {
                CreateOperationResult::Succeeded(mut outcome) => {
                    outcome.existing = true;
                    Ok(outcome)
                }
                CreateOperationResult::Failed(error) => Err(error),
            };
        }
        let operation_id = claim.operation_id().clone();
        let creation = (|| {
            let occupied = worker
                .sessions
                .values()
                .try_fold(0usize, |count, executor| {
                    let session = executor
                        .state
                        .lock()
                        .map_err(|_| WorkerError::StateUnavailable)?;
                    Ok::<_, WorkerError>(
                        count.saturating_add(usize::from(session.occupies_capacity)),
                    )
                })?;
            if occupied >= self.config.max_sessions {
                return Err(WorkerError::CapacityExceeded);
            }
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
            let mut journal_guard = SessionJournalGuard {
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
            self.sandbox
                .provision(&session_id, &fence)
                .map_err(|_| WorkerError::DependencyUnavailable)?;
            let primary_page_id = match self.driver.create_context(&session_id) {
                Ok(page_id) => page_id,
                Err(_) => {
                    let _ = self
                        .sandbox
                        .cleanup(&session_id, CleanupReason::BrowserFailure);
                    return Err(WorkerError::DependencyUnavailable);
                }
            };
            if let Err(error) = machine
                .register_target(&fence, TargetId::new(primary_page_id.to_string()))
                .map_err(map_session_error)
            {
                let _ = self.driver.close_context(&session_id);
                let _ = self
                    .sandbox
                    .cleanup(&session_id, CleanupReason::BrowserFailure);
                return Err(error);
            }
            let mut pages = BTreeSet::new();
            pages.insert(primary_page_id.clone());
            worker.sessions.insert(
                session_id.clone(),
                Arc::new(SessionExecutor {
                    state: Mutex::new(SessionState {
                        tenant_id: command.tenant_id,
                        machine,
                        occupies_capacity: true,
                        primary_page_id: primary_page_id.clone(),
                        pages,
                        closed_pages: BTreeSet::new(),
                        action_idempotency: HashMap::new(),
                        actions: HashMap::new(),
                        action_queue: VecDeque::new(),
                        artifacts: HashMap::new(),
                        approvals: HashMap::new(),
                        action_ledger,
                        durability_degraded: false,
                    }),
                    action_owner: AtomicBool::new(false),
                }),
            );
            journal_guard.committed = true;
            Ok(CreateSessionOutcome {
                operation_id: operation_id.clone(),
                session_id,
                primary_page_id,
                fence,
                existing: false,
            })
        })();
        worker.create_operations.insert(
            operation_id,
            match &creation {
                Ok(outcome) => CreateOperationResult::Succeeded(outcome.clone()),
                Err(error) => CreateOperationResult::Failed(error.clone()),
            },
        );
        creation
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
        let mut session = executor
            .state
            .lock()
            .map_err(|_| WorkerError::StateUnavailable)?;
        validate_fence(&session, fence)?;
        let lifecycle = session
            .machine
            .begin_close(fence, now)
            .map_err(map_session_error)?;
        let terminalization = terminalize_actions_for_shutdown(&mut session);
        if lifecycle != SessionLifecycle::Closed {
            let mut cleanup = WorkerCleanup {
                driver: &*self.driver,
                sandbox: &*self.sandbox,
                session_id,
                reason: CleanupReason::Administrative,
            };
            session
                .machine
                .run_cleanup(fence, &mut cleanup)
                .map_err(|_| WorkerError::CleanupFailed)?;
            session.occupies_capacity = false;
        }
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
        let mut session = executor
            .state
            .lock()
            .map_err(|_| WorkerError::StateUnavailable)?;
        validate_fence(&session, fence)?;
        session
            .machine
            .record_activity(fence, now)
            .map_err(map_session_error)?;
        let page_id = self
            .driver
            .create_page(session_id)
            .map_err(|_| WorkerError::DependencyUnavailable)?;
        session
            .machine
            .register_target(fence, TargetId::new(page_id.to_string()))
            .map_err(map_session_error)?;
        session.pages.insert(page_id.clone());
        Ok(page_id)
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
        let mut session = executor
            .state
            .lock()
            .map_err(|_| WorkerError::StateUnavailable)?;
        validate_fence(&session, fence)?;
        if !session.pages.contains(page_id) {
            return Err(WorkerError::PageNotFound);
        }
        session
            .machine
            .record_activity(fence, now)
            .map_err(map_session_error)?;
        self.driver
            .activate_page(session_id, page_id)
            .map_err(|_| WorkerError::DependencyUnavailable)
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
        if session.actions.values().any(|action| {
            action.page_id.as_ref() == Some(page_id)
                && matches!(
                    action.snapshot.status,
                    ActionStatus::PendingApproval | ActionStatus::Queued | ActionStatus::Running
                )
        }) {
            return Err(WorkerError::InvalidActionTransition);
        }
        let closing_primary = session.primary_page_id == *page_id;
        session
            .machine
            .record_activity(fence, now)
            .map_err(map_session_error)?;
        if closing_primary && session.pages.len() == 1 {
            let replacement = self
                .driver
                .create_page(session_id)
                .map_err(|_| WorkerError::DependencyUnavailable)?;
            if session.pages.contains(&replacement) || session.closed_pages.contains(&replacement) {
                let _ = self.driver.close_page(session_id, &replacement);
                return Err(WorkerError::StateUnavailable);
            }
            if let Err(error) = session
                .machine
                .register_target(fence, TargetId::new(replacement.to_string()))
                .map_err(map_session_error)
            {
                let _ = self.driver.close_page(session_id, &replacement);
                return Err(error);
            }
            session.pages.insert(replacement);
        }
        self.driver
            .close_page(session_id, page_id)
            .map_err(|_| WorkerError::DependencyUnavailable)?;
        session
            .machine
            .unregister_target(fence, &TargetId::new(page_id.to_string()))
            .map_err(map_session_error)?;
        session.pages.remove(page_id);
        session.closed_pages.insert(page_id.clone());
        if closing_primary {
            session.primary_page_id = session
                .pages
                .first()
                .cloned()
                .ok_or(WorkerError::StateUnavailable)?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn submit_action(
        &self,
        peer: &AuthenticatedPeer,
        session_id: &SessionId,
        fence: &OwnershipFence,
        idempotency_key: &str,
        request_hash: [u8; 32],
        kind: ActionKind,
        feature: Option<BuiltinFeature>,
        page_id: Option<PageId>,
        payload: Vec<u8>,
        requires_approval: bool,
        now: SessionTime,
    ) -> Result<ActionId, WorkerError> {
        self.authorize(peer)?;
        let executor = self.session(session_id)?;
        let mut session = executor
            .state
            .lock()
            .map_err(|_| WorkerError::StateUnavailable)?;
        validate_fence(&session, fence)?;
        if let Some((existing_hash, action_id)) = session.action_idempotency.get(idempotency_key) {
            return if *existing_hash == request_hash {
                Ok(action_id.clone())
            } else {
                Err(WorkerError::IdempotencyConflict)
            };
        }
        if session.action_queue.len() >= self.config.action_queue_capacity {
            return Err(WorkerError::QueueFull);
        }
        if let Some(page_id) = &page_id
            && !session.pages.contains(page_id)
        {
            return Err(WorkerError::PageNotFound);
        }
        let approval_expires_at = if requires_approval {
            Some(SessionTime::new(
                now.get()
                    .checked_add(self.config.approval_timeout_millis)
                    .ok_or(WorkerError::InvalidConfiguration)?,
            ))
        } else {
            None
        };
        session
            .machine
            .record_activity(fence, now)
            .map_err(map_session_error)?;
        let ledger_fence = fence.as_placement_fence();
        let request = ActionRequest::new(
            ActionIdempotencyKey::new(idempotency_key),
            ActionRequestHash::new(request_hash),
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
                    (request_hash, action_id.clone()),
                );
                session.actions.insert(
                    action_id.clone(),
                    ActionRecord {
                        snapshot: WorkerActionSnapshot {
                            action_id,
                            action_sequence,
                            status: ActionStatus::CancelledBeforeDispatch,
                            kind,
                            feature,
                            result: None,
                            resolution: None,
                        },
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
        let approval_id = requires_approval.then(LeaseId::new);
        session.action_idempotency.insert(
            idempotency_key.to_owned(),
            (request_hash, action_id.clone()),
        );
        session.actions.insert(
            action_id.clone(),
            ActionRecord {
                snapshot: WorkerActionSnapshot {
                    action_id: action_id.clone(),
                    action_sequence,
                    status,
                    kind,
                    feature,
                    result: None,
                    resolution: None,
                },
                page_id,
                payload,
                approval_id: approval_id.clone(),
                dispatch_permit: None,
            },
        );
        if let Some(approval_id) = approval_id {
            session.approvals.insert(
                approval_id,
                ApprovalRecord {
                    action_id: action_id.clone(),
                    state: ApprovalState::Pending,
                    expires_at: approval_expires_at.ok_or(WorkerError::StateUnavailable)?,
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
        session
            .actions
            .get(action_id)
            .map(|action| action.snapshot.clone())
            .ok_or(WorkerError::ActionNotFound)
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
        let (action_id, page_id, payload, permit) = {
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
            let (page_id, payload) = session
                .actions
                .get(&action_id)
                .filter(|action| action.snapshot.status == ActionStatus::Queued)
                .map(|action| (action.page_id.clone(), action.payload.clone()))
                .ok_or(WorkerError::InvalidActionTransition)?;
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
            (action_id, page_id, payload, permit)
        };
        let outcome = self
            .driver
            .execute_action(session_id, page_id.as_ref(), &payload);
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
            ActionExecutionResult::FailedKnown(_) => session.action_ledger.record_result(
                fence.as_placement_fence(),
                &permit,
                BrowserResult::FailedKnown(KnownFailureReason::BrowserRejected),
            ),
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
        session
            .actions
            .get(&action_id)
            .map(|action| action.snapshot.clone())
            .ok_or(WorkerError::ActionNotFound)
            .map(Some)
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
        let mut session = executor
            .state
            .lock()
            .map_err(|_| WorkerError::StateUnavailable)?;
        validate_fence(&session, fence)?;
        let status = session
            .actions
            .get(action_id)
            .map(|action| action.snapshot.status)
            .ok_or(WorkerError::ActionNotFound)?;
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
                let completion_now = now.max(session.machine.last_observed_at());
                let mut completed_machine = session.machine.clone();
                completed_machine
                    .finish_action(fence, action_id, completion_now)
                    .map_err(map_session_error)?;
                let confirmed = self
                    .driver
                    .cancel_action(session_id, action_id)
                    .map_err(|_| WorkerError::DependencyUnavailable)?;
                if !confirmed {
                    return Err(WorkerError::InvalidActionTransition);
                }
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
        let mut session = executor
            .state
            .lock()
            .map_err(|_| WorkerError::StateUnavailable)?;
        validate_fence(&session, fence)?;
        session
            .machine
            .record_activity(fence, now)
            .map_err(map_session_error)?;
        self.sandbox
            .store_artifact(session_id, &upload)
            .map_err(|_| WorkerError::DependencyUnavailable)?;
        let artifact_id = ArtifactId::new();
        let key = ArtifactKey::new(
            session.tenant_id.clone(),
            session_id.clone(),
            artifact_id.clone(),
        );
        let mut artifact = Artifact::new_upload(key);
        artifact
            .apply(ArtifactEvent::UploadStored)
            .and_then(|_| artifact.apply(ArtifactEvent::ScanStarted))
            .and_then(|_| artifact.apply(ArtifactEvent::ScanPassed))
            .map_err(|_| WorkerError::DependencyUnavailable)?;
        let size_bytes =
            u64::try_from(upload.bytes.len()).map_err(|_| WorkerError::CapacityExceeded)?;
        session.artifacts.insert(
            artifact_id.clone(),
            ArtifactRecord {
                artifact,
                size_bytes,
                content_type: upload.content_type,
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
        Ok(WorkerArtifactSnapshot {
            artifact_id: artifact.artifact.key().artifact_id().clone(),
            state: artifact.artifact.state(),
            size_bytes: artifact.size_bytes,
            content_type: artifact.content_type.clone(),
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
        expire_pending_approvals(&mut session, fence, now)?;
        let action_id = session
            .approvals
            .get(approval_id)
            .map(|approval| approval.action_id.clone())
            .ok_or(WorkerError::ApprovalNotFound)?;
        let current = session
            .approvals
            .get(approval_id)
            .map(|approval| approval.state.clone())
            .ok_or(WorkerError::ApprovalNotFound)?;
        if current != ApprovalState::Pending {
            return Err(WorkerError::InvalidApprovalTransition);
        }
        let mut next_machine = session.machine.clone();
        next_machine
            .record_activity(fence, now)
            .map_err(map_session_error)?;
        let state = match decision {
            ApprovalDecision::Approve => {
                session
                    .action_ledger
                    .grant_approval(fence.as_placement_fence(), &action_id)
                    .map_err(map_action_ledger_error)?;
                let action = session
                    .actions
                    .get_mut(&action_id)
                    .ok_or(WorkerError::ActionNotFound)?;
                action.snapshot.status = ActionStatus::Queued;
                ApprovalState::Approved { by: principal_id }
            }
            ApprovalDecision::Deny => {
                session
                    .action_ledger
                    .deny_approval(fence.as_placement_fence(), &action_id)
                    .map_err(map_action_ledger_error)?;
                session.action_queue.retain(|queued| queued != &action_id);
                let action = session
                    .actions
                    .get_mut(&action_id)
                    .ok_or(WorkerError::ActionNotFound)?;
                action.snapshot.status = ActionStatus::FailedKnown;
                ApprovalState::Denied { by: principal_id }
            }
        };
        session.machine = next_machine;
        let approval = session
            .approvals
            .get_mut(approval_id)
            .ok_or(WorkerError::ApprovalNotFound)?;
        approval.state = state.clone();
        Ok(WorkerApprovalSnapshot {
            approval_id: approval_id.clone(),
            action_id,
            state,
        })
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
        for executor in sessions {
            let mut session = executor
                .state
                .lock()
                .map_err(|_| WorkerError::StateUnavailable)?;
            if !matches!(
                session.machine.lifecycle(),
                SessionLifecycle::Creating | SessionLifecycle::Ready
            ) {
                continue;
            }
            let fence = session.machine.snapshot().owner_fence;
            if expire_pending_approvals(&mut session, &fence, now).is_err() {
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
                    let mut cleanup = WorkerCleanup {
                        driver: &*self.driver,
                        sandbox: &*self.sandbox,
                        session_id: &session_id,
                        reason: CleanupReason::Administrative,
                    };
                    session
                        .machine
                        .run_cleanup(&fence, &mut cleanup)
                        .map_or_else(
                            |_| cleanup_failed = true,
                            |_| {
                                session.occupies_capacity = false;
                                expired = expired.saturating_add(1);
                            },
                        );
                }
                ExpireDecision::OwnershipLost => {
                    ownership_lost = true;
                    if terminalize_actions_for_shutdown(&mut session).is_err() {
                        durability_failed = true;
                    }
                    let session_id = session.machine.session_id().clone();
                    match self
                        .sandbox
                        .cleanup(&session_id, CleanupReason::WorkerLeaseExpired)
                    {
                        Ok(()) => {
                            session.occupies_capacity = false;
                            expired = expired.saturating_add(1);
                        }
                        Err(_) => cleanup_failed = true,
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
        let sessions = {
            let worker = self.lock_worker()?;
            worker.sessions.keys().cloned().collect::<Vec<_>>()
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
                        self.sandbox
                            .cleanup(&session_id, CleanupReason::WorkerLeaseExpired)
                            .map_err(|_| WorkerError::CleanupFailed)?;
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

struct WorkerCleanup<'a, D, S> {
    driver: &'a D,
    sandbox: &'a S,
    session_id: &'a SessionId,
    reason: CleanupReason,
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
                    self.driver.close_context(self.session_id)
                } else {
                    Ok(())
                }
            }
            CleanupStage::RevokeProxyRoute => self.sandbox.cleanup(self.session_id, self.reason),
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
        _session_id: &SessionId,
        _upload: &ArtifactUpload,
    ) -> Result<(), DependencyError> {
        Err(DependencyError::Unavailable)
    }
}
