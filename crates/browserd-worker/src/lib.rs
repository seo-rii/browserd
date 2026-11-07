//! Fenced, transport-neutral browser worker control plane.

#![forbid(unsafe_code)]

#[cfg(test)]
extern crate self as browserd_worker;

mod action_approval;
mod action_journal_retention;
mod artifact_publications;
#[cfg(test)]
mod artifact_publications_tests;
mod artifact_scan_evidence;
mod cdp_driver;
mod checkpoint_control;
pub mod checkpoints;
mod chromium_owner;
mod control_event_journal;
mod download_publication;
#[cfg(test)]
mod download_publication_tests;
mod evaluate_control;
pub mod evaluate_policy;
mod file_attachments;
#[cfg(test)]
mod file_attachments_tests;
mod notifications;
mod production_sandbox;
mod rpc;
mod runtime_safety;
pub mod secrets;
mod session_event_journal;
mod shard_actor;
mod shard_driver;
mod target_manager;
#[cfg(test)]
mod typed_approval_tests;
mod viewer;
mod worker_admission;
pub use worker_admission::*;

pub use artifact_publications::{
    ARTIFACT_PUBLICATION_TTL_MILLIS, ArtifactPublication, MAX_RETAINED_ARTIFACT_PAGE,
};
pub use artifact_scan_evidence::{ArtifactScanAttestation, ArtifactScannerObservation};
pub use browserd_actions::{ActionJournalPool, ActionJournalPoolConfig, ActionJournalPoolLimits};
pub use cdp_driver::CdpChromiumDriver;
pub use checkpoints::{
    CheckpointCookie, CheckpointError, CheckpointOriginStorage, CheckpointRestoreReceipt,
    CheckpointSnapshot, CheckpointStorageEntry, CheckpointStore, FileCheckpointStore,
    LoadedCheckpoint,
};
pub use chromium_owner::{
    BrowserDownloadCompletion, BrowserDownloadFile, ChromiumConnectionOwner, ChromiumTargetManager,
    ChromiumTargetManagerBackend, ChromiumTargetRoute, OwnerContextPolicy,
};
pub use control_event_journal::ControlEventJournal;
pub use evaluate_policy::{
    PrivilegedEvaluateGrant, PrivilegedEvaluatePolicy, PrivilegedEvaluatePolicyError,
};
pub use notifications::{
    MAX_NOTIFICATION_PAGE_DESCRIPTORS, MAX_NOTIFICATION_SCOPES_PER_PAGE, WorkerNotificationPage,
};
pub use production_sandbox::{
    CdpPipeAcceptor, ExactSandboxTermination, ProductionSandboxShardRuntime, SandboxShardRpc,
    SandboxTerminationProof, ShardLaunchDescriptor,
};
pub use rpc::{
    ArtifactPublicationWire, MAX_CONTROL_EVENT_PAGE, MAX_VIEWER_JPEG_BYTES,
    MAX_VIEWER_METADATA_BYTES, MAX_VIEWER_SAFE_INTEGER, MAX_WORKER_ACTION_RPC_FRAME_BYTES,
    PendingWorkerRpc, ViewerClientMessage, ViewerKeyPhase, ViewerMouseButton, ViewerMousePhase,
    WORKER_RPC_PROTOCOL_VERSION, WORKER_SESSION_OPTIONS_VERSION, WorkerActionApprovalRequirement,
    WorkerActionCommand, WorkerActionExecutionTimeout, WorkerActionReceipt, WorkerActionStatus,
    WorkerApprovalActionType, WorkerApprovalDecision, WorkerApprovalReceipt, WorkerApprovalState,
    WorkerArtifactReceipt, WorkerArtifactScanVerdict, WorkerArtifactSource, WorkerArtifactState,
    WorkerCanonicalActionProposal, WorkerCheckpointRestoreReceipt, WorkerControlEvent,
    WorkerControlPlaneRpcHandler, WorkerCreateSessionReceipt, WorkerCreateSessionRequest,
    WorkerIsolationProfile, WorkerNavigateWaitUntil, WorkerPageReceipt, WorkerProbeReceipt,
    WorkerRetainedArtifactReceipt, WorkerRetainedArtifactScope, WorkerRpcBlockingClient,
    WorkerRpcClient, WorkerRpcCompletionError, WorkerRpcConfig, WorkerRpcEnqueueError,
    WorkerRpcError, WorkerRpcFailure, WorkerRpcFailureCode, WorkerRpcHandler, WorkerRpcRequest,
    WorkerRpcResponse, WorkerRpcServer, WorkerSessionFence, WorkerSessionLifecycle,
    WorkerSessionOptionsV1, WorkerSessionOwnershipReceipt, WorkerSessionReceipt,
    WorkerTerminalCustodyAck, WorkerTerminalCustodyReceipt, WorkerViewerCloseRequest,
    WorkerViewerControl, WorkerViewerController, WorkerViewerFrame, WorkerViewerMessageRequest,
    WorkerViewerOpenRequest, WorkerViewerPollRequest, WorkerViewerSnapshot, WorkerViewport,
    WorkerWaitCondition,
};
pub use secrets::{
    FileSecretResolver, ResolvedSecret, SecretFillError, SecretFillTarget, SecretGrant,
    SecretResolver,
};
pub use session_event_journal::SessionEventJournal;
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
    IdempotencyKey as ActionIdempotencyKey, JournalSessionScope, KnownFailureReason, LedgerSession,
    ManagedActionJournal, OutcomeUnknownReason, ResolutionAnnotation, ResolutionKind,
    ResolutionOutcome, ResolutionPolicy, ResultDigest, TerminalCustodyReceipt, TerminalDetail,
    TransportLoss,
};
use browserd_artifacts::{
    Artifact, ArtifactChecksum, ArtifactContentMetadata, ArtifactContentSource, ArtifactEvent,
    ArtifactKey, ArtifactObjectGeneration, ArtifactReadLimits, ArtifactState,
};
use browserd_core::{
    ActionId, ActionState, ArtifactId, IsolationProfile, OperationId, PageId, PrincipalId,
    SessionExecution, SessionId, TenantId, WorkerId,
};
use browserd_features::{BuiltinFeature, FeatureProfile, FeatureRegistry};
use browserd_fleet::WorkerEpochRegistry;
use browserd_observability::{AppendOutcome, AuditEvent, AuditEventId, AuditWal, AuditWalError};
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

/// The actual placement returned by the trusted context factory, fixed for this session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreatedSessionContext {
    pub primary_page_id: PageId,
    pub effective_isolation: WorkerIsolationProfile,
}

/// Derives the session's effective feature profile from the trusted create options.
///
/// Only the exact `privileged` profile grants privileged features; every other value, and the
/// absence of options, is `Standard`. Production factories reject non-standard profiles at
/// creation, so production sessions are always `Standard` and cannot run `evaluate`.
fn feature_profile_from_options(options: Option<&WorkerSessionOptionsV1>) -> FeatureProfile {
    match options.map(|options| options.feature_profile.as_str()) {
        Some("privileged") => FeatureProfile::Privileged,
        _ => FeatureProfile::Standard,
    }
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
    DeadlineBeforeDispatch,
    Unavailable,
    OutcomeUncertain,
}

/// An observation of an owned target. Digests include private actor guards, never browser data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TypedApprovalObservation {
    pub tenant_id: TenantId,
    pub session_id: SessionId,
    pub page_id: Option<PageId>,
    pub fence: OwnershipFence,
    pub context_scope: browserd_policy::ApprovalContextScope,
    pub target_binding_sha256: [u8; 32],
    pub node_binding: Option<browserd_policy::ApprovalNodeBinding>,
    pub build_identity_sha256: [u8; 32],
    pub live: LiveApprovalContext,
}

enum ApprovalAdmissionClockError {
    Clock(WorkerError),
    PlacementOwnershipInvalid(SessionTime),
}

pub trait ChromiumDriver: Send + Sync + 'static {
    #[allow(clippy::too_many_arguments)]
    fn inspect_typed_approval_until(
        &self,
        _tenant_id: &TenantId,
        _session_id: &SessionId,
        _page_id: Option<&PageId>,
        _fence: &OwnershipFence,
        _action: &WorkerActionCommand,
        _deadline: Instant,
    ) -> Result<TypedApprovalObservation, ApprovedActionError> {
        Err(ApprovedActionError::DispatchRevoked)
    }

    fn execute_typed_browser_until(
        &self,
        _expected: &TypedApprovalObservation,
        _payload: &[u8],
        _deadline: Instant,
        _authorize_and_commit: &mut dyn FnMut(
            &TypedApprovalObservation,
        ) -> Result<(), ApprovedActionError>,
    ) -> Result<ActionExecutionResult, ApprovedActionError> {
        Err(ApprovedActionError::DispatchRevoked)
    }

    fn execute_typed_secret_until(
        &self,
        _expected: &TypedApprovalObservation,
        _secret: ResolvedSecret,
        _deadline: Instant,
        _authorize_and_commit: &mut dyn FnMut(
            &TypedApprovalObservation,
        ) -> Result<(), ApprovedActionError>,
    ) -> Result<ActionExecutionResult, ApprovedActionError> {
        Err(ApprovedActionError::DispatchRevoked)
    }

    fn execute_typed_files_until(
        &self,
        _expected: &TypedApprovalObservation,
        _files: Vec<BrowserFileAttachment>,
        _deadline: Instant,
        _authorize_and_commit: &mut dyn FnMut(
            &TypedApprovalObservation,
        ) -> Result<(), ApprovedActionError>,
    ) -> Result<ActionExecutionResult, ApprovedActionError> {
        Err(ApprovedActionError::DispatchRevoked)
    }

    fn capture_typed_checkpoint_until(
        &self,
        _expected: &TypedApprovalObservation,
        _origins: &[String],
        _deadline: Instant,
        _authorize_and_commit: &mut dyn FnMut(
            &TypedApprovalObservation,
        ) -> Result<(), ApprovedActionError>,
    ) -> Result<CheckpointSnapshot, ApprovedActionError> {
        Err(ApprovedActionError::DispatchRevoked)
    }

    #[allow(clippy::too_many_arguments)]
    fn execute_typed_capture_until(
        &self,
        _expected: &TypedApprovalObservation,
        _command: browserd_features::CaptureCommand,
        _request: GeneratedArtifactRequest,
        _store: Arc<dyn SandboxClient>,
        _deadline: Instant,
        _authorize_and_commit: &mut dyn FnMut(
            &TypedApprovalObservation,
        ) -> Result<(), ApprovedActionError>,
    ) -> Result<GeneratedCaptureResult, ApprovedActionError> {
        Err(ApprovedActionError::DispatchRevoked)
    }

    /// Observes the exact owned page under the effect gate and commits admission immediately
    /// before arbitrary JavaScript starts. Implementations must never execute after a rejected
    /// callback or replay an uncertain effect. The default implementation denies this lane.
    #[allow(clippy::too_many_arguments)]
    fn execute_privileged_evaluate_until(
        &self,
        _tenant_id: &TenantId,
        _session_id: &SessionId,
        _page_id: &PageId,
        _fence: &OwnershipFence,
        _payload: &[u8],
        _deadline: Instant,
        _authorize_and_commit: &mut dyn FnMut(
            &LiveApprovalContext,
        ) -> Result<(), ApprovedActionError>,
    ) -> Result<ActionExecutionResult, ApprovedActionError> {
        Err(ApprovedActionError::DispatchRevoked)
    }

    fn capture_checkpoint_until(
        &self,
        _tenant_id: &TenantId,
        _session_id: &SessionId,
        _fence: &OwnershipFence,
        _origins: &[String],
        _deadline: Instant,
    ) -> Result<CheckpointSnapshot, CheckpointError> {
        Err(CheckpointError::Rejected)
    }

    #[allow(clippy::too_many_arguments)]
    fn restore_checkpoint_until(
        &self,
        _tenant_id: &TenantId,
        _session_id: &SessionId,
        _primary_page: &PageId,
        _fence: &OwnershipFence,
        _snapshot: CheckpointSnapshot,
        _deadline: Instant,
    ) -> Result<(), CheckpointError> {
        Err(CheckpointError::Rejected)
    }

    #[allow(clippy::too_many_arguments)]
    fn inspect_secret_fill_target_until(
        &self,
        _tenant_id: &TenantId,
        _session_id: &SessionId,
        _page_id: &PageId,
        _fence: &OwnershipFence,
        _node_ref: &str,
        _deadline: Instant,
    ) -> Result<SecretFillTarget, SecretFillError> {
        Err(SecretFillError::Rejected)
    }

    fn execute_secret_fill_until(
        &self,
        _target: &SecretFillTarget,
        _secret: ResolvedSecret,
        _deadline: Instant,
        _authorize_and_commit: &mut dyn FnMut(&SecretFillTarget) -> Result<(), SecretFillError>,
    ) -> Result<ActionExecutionResult, SecretFillError> {
        Err(SecretFillError::Rejected)
    }

    fn execute_file_attachment_until(
        &self,
        _session_id: &SessionId,
        _page_id: &PageId,
        _fence: &OwnershipFence,
        _node_ref: &str,
        _files: Vec<BrowserFileAttachment>,
        _deadline: Instant,
    ) -> ActionExecutionResult {
        ActionExecutionResult::FailedKnown("files_unsupported".to_owned())
    }

    fn pending_browser_downloads(
        &self,
        _session_id: &SessionId,
        _fence: &OwnershipFence,
        _limit: usize,
    ) -> Result<Vec<BrowserDownloadCompletion>, DependencyError> {
        Ok(Vec::new())
    }

    fn open_browser_download(
        &self,
        _completion: &BrowserDownloadCompletion,
    ) -> Result<BrowserDownloadFile, DependencyError> {
        Err(DependencyError::Rejected)
    }

    fn ack_browser_download(
        &self,
        _completion: &BrowserDownloadCompletion,
    ) -> Result<(), DependencyError> {
        Err(DependencyError::Rejected)
    }

    fn reject_browser_download(
        &self,
        _completion: &BrowserDownloadCompletion,
    ) -> Result<(), DependencyError> {
        Err(DependencyError::Rejected)
    }

    fn viewer_rebind(
        &self,
        _session_id: &SessionId,
        _page_id: &PageId,
        _fence: &OwnershipFence,
    ) -> Result<u64, DependencyError> {
        Err(DependencyError::Rejected)
    }
    fn viewer_start(
        &self,
        _session_id: &SessionId,
        _page_id: &PageId,
        _fence: &OwnershipFence,
    ) -> Result<(), DependencyError> {
        Err(DependencyError::Rejected)
    }
    fn viewer_stop(
        &self,
        _session_id: &SessionId,
        _page_id: &PageId,
        _fence: &OwnershipFence,
    ) -> Result<(), DependencyError> {
        Err(DependencyError::Rejected)
    }
    fn viewer_frame(
        &self,
        _session_id: &SessionId,
        _page_id: &PageId,
        _fence: &OwnershipFence,
    ) -> Result<Option<crate::WorkerViewerFrame>, DependencyError> {
        Err(DependencyError::Rejected)
    }
    fn viewer_input(
        &self,
        _session_id: &SessionId,
        _page_id: &PageId,
        _fence: &OwnershipFence,
        _transform_epoch: u64,
        _message: &crate::ViewerClientMessage,
    ) -> Result<(), DependencyError> {
        Err(DependencyError::Rejected)
    }
    fn viewer_cleanup(
        &self,
        _session_id: &SessionId,
        _page_id: &PageId,
        _fence: &OwnershipFence,
        _cleanup: &browserd_viewer::InputCleanup,
    ) -> Result<(), DependencyError> {
        Err(DependencyError::Rejected)
    }
    #[allow(clippy::too_many_arguments)]
    fn execute_capture_until(
        &self,
        _session_id: &SessionId,
        _page_id: &PageId,
        _command: browserd_features::CaptureCommand,
        _request: GeneratedArtifactRequest,
        _store: Arc<dyn SandboxClient>,
        _deadline: Instant,
    ) -> Result<GeneratedCaptureResult, DependencyError> {
        Err(DependencyError::Rejected)
    }
    fn qualify(&self) -> Result<(), DependencyError>;
    fn effective_isolation(&self) -> WorkerIsolationProfile {
        WorkerIsolationProfile::SharedContext
    }
    fn supports_requested_isolation(&self, requested: WorkerIsolationProfile) -> bool {
        requested.satisfied_by(self.effective_isolation())
    }
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
    fn create_context_owned_with_options(
        &self,
        _tenant_id: &TenantId,
        _session_id: &SessionId,
        _fence: &OwnershipFence,
        _options: &WorkerSessionOptionsV1,
    ) -> Result<PageId, DependencyError> {
        Err(DependencyError::Rejected)
    }
    fn create_context_owned_with_placement(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        fence: &OwnershipFence,
        options: Option<&WorkerSessionOptionsV1>,
        requested: WorkerIsolationProfile,
    ) -> Result<CreatedSessionContext, DependencyError> {
        let effective_isolation = self.effective_isolation();
        if !requested.satisfied_by(effective_isolation) {
            return Err(DependencyError::Rejected);
        }
        let primary_page_id = match options {
            Some(options) => {
                self.create_context_owned_with_options(tenant_id, session_id, fence, options)?
            }
            None => self.create_context_owned(tenant_id, session_id, fence)?,
        };
        Ok(CreatedSessionContext {
            primary_page_id,
            effective_isolation,
        })
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
    fn execute_action_until(
        &self,
        session_id: &SessionId,
        page_id: Option<&PageId>,
        payload: &[u8],
        deadline: Instant,
    ) -> ActionExecutionResult {
        if Instant::now() >= deadline {
            ActionExecutionResult::FailedKnown("action_timeout".to_owned())
        } else {
            self.execute_action(session_id, page_id, payload)
        }
    }
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
    #[allow(clippy::too_many_arguments)]
    fn execute_approved_action_until(
        &self,
        session_id: &SessionId,
        page_id: &PageId,
        payload: &[u8],
        proposal: &CanonicalActionProposal,
        inspected: &LiveApprovalContext,
        deadline: Instant,
        authorize_and_commit: &mut dyn FnMut(
            &LiveApprovalContext,
        ) -> Result<(), ApprovedActionError>,
    ) -> Result<ActionExecutionResult, ApprovedActionError> {
        if Instant::now() >= deadline {
            Err(ApprovedActionError::DeadlineBeforeDispatch)
        } else {
            self.execute_approved_action(
                session_id,
                page_id,
                payload,
                proposal,
                inspected,
                authorize_and_commit,
            )
        }
    }
    fn cancel_action(
        &self,
        session_id: &SessionId,
        action_id: &ActionId,
    ) -> Result<bool, DependencyError>;
}

pub trait SandboxClient: Send + Sync + 'static {
    fn pending_artifact_notifications(
        &self,
        _cursor: Option<&str>,
        _max_scopes: usize,
        _max_descriptors: usize,
    ) -> Result<WorkerNotificationPage, DependencyError> {
        Ok(WorkerNotificationPage::empty())
    }
    fn ack_artifact_notification(
        &self,
        _ack: &browserd_core::NotificationAck,
    ) -> Result<(), DependencyError> {
        Err(DependencyError::Rejected)
    }
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

    /// Legacy nonpersistent fixtures may accept publication without retaining it. Production
    /// providers override this with durable metadata persistence before success.
    fn publish_artifact(&self, _publication: &ArtifactPublication) -> Result<(), DependencyError> {
        Ok(())
    }
    fn withdraw_artifact(&self, _publication: &ArtifactPublication) -> Result<(), DependencyError> {
        Err(DependencyError::Rejected)
    }
    fn get_retained_artifact(
        &self,
        _key: &ArtifactKey,
        _now_unix_millis: u64,
    ) -> Result<Option<ArtifactPublication>, DependencyError> {
        Err(DependencyError::Rejected)
    }
    fn list_retained_artifacts(
        &self,
        _tenant: &TenantId,
        _session: &SessionId,
        _after: Option<&ArtifactId>,
        _limit: usize,
        _now_unix_millis: u64,
    ) -> Result<Vec<ArtifactPublication>, DependencyError> {
        Err(DependencyError::Rejected)
    }
    fn open_retained_artifact(
        &self,
        _publication: &ArtifactPublication,
        _limits: ArtifactReadLimits,
        _now_unix_millis: u64,
    ) -> Result<Box<dyn ArtifactReadStream>, DependencyError> {
        Err(DependencyError::Rejected)
    }

    fn discard_artifact(
        &self,
        _receipt: &ArtifactStoreReceipt,
        _fence: &OwnershipFence,
    ) -> Result<(), DependencyError> {
        Err(DependencyError::Rejected)
    }

    fn open_artifact(
        &self,
        _request: &ArtifactReadRequest,
    ) -> Result<Box<dyn ArtifactReadStream>, DependencyError> {
        Err(DependencyError::Rejected)
    }

    fn begin_generated_artifact(
        &self,
        _request: &GeneratedArtifactRequest,
    ) -> Result<Box<dyn GeneratedArtifactSink>, DependencyError> {
        Err(DependencyError::Rejected)
    }
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

/// The set of session-option values a worker actually supports, so a create request carrying an
/// unsupported option is rejected early with a precise reason instead of failing opaquely deep in
/// the factory after resources have been touched (BRD-022).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionOptionSupport {
    network_classes: BTreeSet<String>,
    dialog_policies: BTreeSet<String>,
    feature_profiles: BTreeSet<String>,
    supports_checkpoint: bool,
}

impl SessionOptionSupport {
    #[must_use]
    pub fn new(
        network_classes: impl IntoIterator<Item = String>,
        dialog_policies: impl IntoIterator<Item = String>,
        feature_profiles: impl IntoIterator<Item = String>,
        supports_checkpoint: bool,
    ) -> Self {
        Self {
            network_classes: network_classes.into_iter().collect(),
            dialog_policies: dialog_policies.into_iter().collect(),
            feature_profiles: feature_profiles.into_iter().collect(),
            supports_checkpoint,
        }
    }

    /// The single-host production capability: public network, auto-dismiss dialogs, the standard
    /// feature profile, and no checkpoint restore.
    #[must_use]
    pub fn single_host_default() -> Self {
        Self::new(
            ["public".to_owned()],
            ["auto_dismiss".to_owned()],
            ["standard".to_owned()],
            false,
        )
    }

    /// The name of the first option in `options` this worker does not support, if any.
    #[must_use]
    pub fn unsupported_option(&self, options: &WorkerSessionOptionsV1) -> Option<&'static str> {
        if !self.network_classes.contains(&options.network_class) {
            Some("network_class")
        } else if !self.dialog_policies.contains(&options.dialog_policy) {
            Some("dialog_policy")
        } else if !self.feature_profiles.contains(&options.feature_profile) {
            Some("feature_profile")
        } else if options.checkpoint_ref.is_some() && !self.supports_checkpoint {
            Some("checkpoint_ref")
        } else {
            None
        }
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
    session_option_support: Option<SessionOptionSupport>,
    /// Retention for a fully-closed session's in-memory state before it is reclaimed (BRD-018).
    session_retention: Duration,
    /// Upper bound on the sessions one tenant may have retained in the worker at once — active plus
    /// terminal-not-yet-reclaimed — so a single tenant churning create/close cannot accumulate
    /// unbounded session state ahead of reclamation (BRD-018).
    max_sessions_per_tenant: usize,
    admission_policy: Option<WorkerAdmissionPolicy>,
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
    /// Default closed-session retention (24 hours), matching the durable idempotency/action
    /// retention floor so a late retry that the durable layer still honors finds the worker's
    /// terminal session too.
    pub const DEFAULT_SESSION_RETENTION: Duration = Duration::from_secs(24 * 60 * 60);

    /// Default per-tenant retained-session cap. Generous enough not to constrain normal create/close
    /// churn within the retention window, while still bounding a single tenant's accumulation.
    pub const DEFAULT_MAX_SESSIONS_PER_TENANT: usize = 4096;

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
            session_option_support: None,
            session_retention: Self::DEFAULT_SESSION_RETENTION,
            max_sessions_per_tenant: Self::DEFAULT_MAX_SESSIONS_PER_TENANT,
            admission_policy: None,
        })
    }

    #[must_use]
    pub const fn with_artifact_limits(mut self, limits: WorkerArtifactLimits) -> Self {
        self.artifact_limits = limits;
        self
    }

    /// How long a fully-closed session's in-memory state is retained before it is reclaimed
    /// (BRD-018). A closed session stays queryable for at least this long after cleanup so a late
    /// read still sees its terminal snapshot; after it, the entry is dropped so retained memory and
    /// the per-maintenance scan stay bounded under churn. The durable action authority — not this
    /// in-memory copy — preserves unresolved-action evidence, so reclamation never loses it.
    #[must_use]
    pub fn with_session_retention(mut self, retention: Duration) -> Self {
        if !retention.is_zero() {
            self.session_retention = retention;
        }
        self
    }

    /// Bounds the sessions one tenant may have retained at once (active plus terminal-not-yet-
    /// reclaimed); a create beyond it is rejected with retryable backpressure (BRD-018). A zero
    /// limit is ignored.
    #[must_use]
    pub const fn with_max_sessions_per_tenant(mut self, limit: usize) -> Self {
        if limit != 0 {
            self.max_sessions_per_tenant = limit;
        }
        self
    }

    /// Declares which session-option values this worker supports. When set, a create request
    /// carrying an unsupported option is rejected before any session resource is allocated
    /// (BRD-022). Left unset, option support is validated only by the driver/factory.
    #[must_use]
    pub fn with_session_option_support(mut self, support: SessionOptionSupport) -> Self {
        self.session_option_support = Some(support);
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

    pub fn with_fleet_admission_policy(
        mut self,
        policy: WorkerAdmissionPolicy,
    ) -> Result<Self, WorkerError> {
        policy.validate(&self.worker_id, self.max_sessions)?;
        self.admission_policy = Some(policy);
        Ok(self)
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
    pub restored_checkpoint: Option<CheckpointRestoreReceipt>,
    pub effective_isolation: WorkerIsolationProfile,
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

/// Verified artifact content prepared by the control plane for an owned browser input.
/// Filesystem paths cannot be supplied through this contract.
#[derive(Clone)]
pub struct BrowserFileAttachment {
    key: ArtifactKey,
    fence: OwnershipFence,
    generation: ArtifactObjectGeneration,
    checksum: ArtifactChecksum,
    display_filename: String,
    bytes: Arc<[u8]>,
}

impl std::fmt::Debug for BrowserFileAttachment {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrowserFileAttachment")
            .field("key", &self.key)
            .field("fence", &self.fence)
            .field("generation", &self.generation)
            .field("display_filename", &self.display_filename)
            .field("size_bytes", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

impl BrowserFileAttachment {
    pub(crate) fn verified(
        key: ArtifactKey,
        fence: OwnershipFence,
        generation: ArtifactObjectGeneration,
        checksum: ArtifactChecksum,
        display_filename: String,
        bytes: Arc<[u8]>,
    ) -> Self {
        Self {
            key,
            fence,
            generation,
            checksum,
            display_filename,
            bytes,
        }
    }

    #[must_use]
    pub const fn key(&self) -> &ArtifactKey {
        &self.key
    }
    #[must_use]
    pub const fn fence(&self) -> &OwnershipFence {
        &self.fence
    }
    #[must_use]
    pub const fn generation(&self) -> ArtifactObjectGeneration {
        self.generation
    }
    #[must_use]
    pub const fn checksum(&self) -> &ArtifactChecksum {
        &self.checksum
    }
    #[must_use]
    pub fn display_filename(&self) -> &str {
        &self.display_filename
    }
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

pub(crate) fn valid_artifact_display_filename(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value != "."
        && value != ".."
        && !value
            .chars()
            .any(|character| character.is_control() || matches!(character, '/' | '\\'))
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
    source: ArtifactContentSource,
    origin: String,
}

impl ArtifactStoreRequest {
    pub fn new(
        tenant_id: TenantId,
        session_id: SessionId,
        artifact_id: ArtifactId,
        fence: OwnershipFence,
        bytes: Vec<u8>,
        declared_content_type: impl Into<String>,
        max_bytes: u64,
    ) -> Result<Self, WorkerError> {
        let declared_content_type = declared_content_type.into();
        let expected_size_bytes =
            u64::try_from(bytes.len()).map_err(|_| WorkerError::CapacityExceeded)?;
        if max_bytes == 0 || expected_size_bytes > max_bytes {
            return Err(WorkerError::CapacityExceeded);
        }
        let expected_checksum = ArtifactChecksum::new(Sha256::digest(&bytes).into());
        ArtifactContentMetadata::new(
            expected_size_bytes,
            expected_checksum,
            declared_content_type.clone(),
            ArtifactContentSource::ClientUpload,
            "browserd-worker-upload",
        )
        .map_err(|_| WorkerError::InvalidConfiguration)?;
        Ok(Self {
            key: ArtifactKey::new(tenant_id, session_id, artifact_id),
            fence,
            bytes,
            declared_content_type,
            expected_size_bytes,
            expected_checksum,
            max_bytes,
            source: ArtifactContentSource::ClientUpload,
            origin: "browserd-worker-upload".to_owned(),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_generated(
        tenant_id: TenantId,
        session_id: SessionId,
        artifact_id: ArtifactId,
        fence: OwnershipFence,
        bytes: Vec<u8>,
        content_type: impl Into<String>,
        max_bytes: u64,
        origin: impl Into<String>,
    ) -> Result<Self, WorkerError> {
        let mut request = Self::new(
            tenant_id,
            session_id,
            artifact_id,
            fence,
            bytes,
            content_type,
            max_bytes,
        )?;
        request.source = ArtifactContentSource::Generated;
        request.origin = origin.into();
        ArtifactContentMetadata::new(
            request.expected_size_bytes,
            request.expected_checksum,
            request.declared_content_type.clone(),
            request.source,
            request.origin.clone(),
        )
        .map_err(|_| WorkerError::InvalidConfiguration)?;
        Ok(request)
    }

    /// Browser-originated bytes admitted by the owner after exact frame/session attribution.
    /// Local paths and Chromium-supplied names are deliberately absent from this contract.
    pub fn new_browser_download(
        tenant_id: TenantId,
        session_id: SessionId,
        artifact_id: ArtifactId,
        fence: OwnershipFence,
        bytes: Vec<u8>,
        content_type: impl Into<String>,
        max_bytes: u64,
    ) -> Result<Self, WorkerError> {
        let mut request = Self::new(
            tenant_id,
            session_id,
            artifact_id,
            fence,
            bytes,
            content_type,
            max_bytes,
        )?;
        request.source = ArtifactContentSource::BrowserDownload;
        request.origin = "browserd-worker-download".to_owned();
        Ok(request)
    }

    #[must_use]
    pub const fn source(&self) -> ArtifactContentSource {
        self.source
    }

    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }

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
    scan_verdict: Option<ArtifactScanVerdict>,
    source: ArtifactContentSource,
    scan_attestation: Option<ArtifactScanAttestation>,
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
            scan_verdict: Some(scan_verdict),
            source: ArtifactContentSource::ClientUpload,
            scan_attestation: None,
        })
    }

    pub fn new_generated(
        key: ArtifactKey,
        size_bytes: u64,
        checksum: ArtifactChecksum,
        content_type: impl Into<String>,
        object_generation: ArtifactObjectGeneration,
    ) -> Result<Self, WorkerError> {
        let mut receipt = Self::new(
            key,
            size_bytes,
            checksum,
            content_type,
            object_generation,
            ArtifactScanVerdict::Quarantined,
        )?;
        receipt.source = ArtifactContentSource::Generated;
        receipt.scan_verdict = None;
        Ok(receipt)
    }

    pub fn new_browser_download(
        key: ArtifactKey,
        size_bytes: u64,
        checksum: ArtifactChecksum,
        content_type: impl Into<String>,
        object_generation: ArtifactObjectGeneration,
        scan_verdict: ArtifactScanVerdict,
    ) -> Result<Self, WorkerError> {
        let mut receipt = Self::new(
            key,
            size_bytes,
            checksum,
            content_type,
            object_generation,
            scan_verdict,
        )?;
        receipt.source = ArtifactContentSource::BrowserDownload;
        Ok(receipt)
    }

    #[must_use]
    pub const fn source(&self) -> ArtifactContentSource {
        self.source
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
    pub const fn scan_verdict(&self) -> Option<ArtifactScanVerdict> {
        self.scan_verdict
    }

    pub fn with_scan_attestation(
        mut self,
        attestation: ArtifactScanAttestation,
    ) -> Result<Self, WorkerError> {
        if self.scan_verdict != Some(ArtifactScanVerdict::Clean) {
            return Err(WorkerError::InvalidConfiguration);
        }
        attestation.validate_receipt(
            &self.key,
            self.source,
            self.object_generation,
            self.size_bytes,
            self.checksum,
        )?;
        self.scan_attestation = Some(attestation);
        Ok(self)
    }

    pub const fn scan_attestation(&self) -> Option<&ArtifactScanAttestation> {
        self.scan_attestation.as_ref()
    }
}

/// A verified, namespace-bound read. This conveys no caller-provided filesystem path.
#[derive(Clone, Debug)]
pub struct ArtifactReadRequest {
    key: ArtifactKey,
    fence: OwnershipFence,
    metadata: ArtifactContentMetadata,
    generation: ArtifactObjectGeneration,
    limits: ArtifactReadLimits,
}

impl ArtifactReadRequest {
    pub fn new(
        key: ArtifactKey,
        fence: OwnershipFence,
        metadata: ArtifactContentMetadata,
        generation: ArtifactObjectGeneration,
        max_chunk_bytes: usize,
    ) -> Result<Self, WorkerError> {
        let limits = ArtifactReadLimits::new(max_chunk_bytes)
            .map_err(|_| WorkerError::InvalidConfiguration)?;
        Ok(Self {
            key,
            fence,
            metadata,
            generation,
            limits,
        })
    }
    #[must_use]
    pub const fn key(&self) -> &ArtifactKey {
        &self.key
    }
    #[must_use]
    pub const fn fence(&self) -> &OwnershipFence {
        &self.fence
    }
    #[must_use]
    pub const fn metadata(&self) -> &ArtifactContentMetadata {
        &self.metadata
    }
    #[must_use]
    pub const fn generation(&self) -> ArtifactObjectGeneration {
        self.generation
    }
    #[must_use]
    pub const fn limits(&self) -> ArtifactReadLimits {
        self.limits
    }
}

pub trait ArtifactReadStream: Send {
    fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, DependencyError>;
}

/// Trusted capture reservation. The byte ceiling is reserved before Chromium produces data.
#[derive(Clone, Debug)]
pub struct GeneratedArtifactRequest {
    key: ArtifactKey,
    fence: OwnershipFence,
    content_type: String,
    origin: String,
    max_bytes: u64,
}

impl GeneratedArtifactRequest {
    pub fn new(
        key: ArtifactKey,
        fence: OwnershipFence,
        content_type: impl Into<String>,
        origin: impl Into<String>,
        max_bytes: u64,
    ) -> Result<Self, WorkerError> {
        let content_type = content_type.into();
        let origin = origin.into();
        if max_bytes == 0 {
            return Err(WorkerError::InvalidConfiguration);
        }
        ArtifactContentMetadata::new(
            0,
            ArtifactChecksum::new([0; 32]),
            content_type.clone(),
            ArtifactContentSource::Generated,
            origin.clone(),
        )
        .map_err(|_| WorkerError::InvalidConfiguration)?;
        Ok(Self {
            key,
            fence,
            content_type,
            origin,
            max_bytes,
        })
    }
    #[must_use]
    pub const fn key(&self) -> &ArtifactKey {
        &self.key
    }
    #[must_use]
    pub const fn fence(&self) -> &OwnershipFence {
        &self.fence
    }
    #[must_use]
    pub fn content_type(&self) -> &str {
        &self.content_type
    }
    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }
    #[must_use]
    pub const fn max_bytes(&self) -> u64 {
        self.max_bytes
    }
}

#[async_trait::async_trait]
pub trait GeneratedArtifactSink: Send {
    /// Maximum bytes accepted by one write; producers must split bounded chunks accordingly.
    fn max_chunk_bytes(&self) -> usize {
        64 * 1024
    }
    async fn write_chunk(&mut self, chunk: &[u8]) -> Result<(), DependencyError>;
    async fn finish(&mut self) -> Result<ArtifactStoreReceipt, DependencyError>;
    async fn abort(&mut self) -> Result<(), DependencyError>;
}

/// Completed capture plus an exact-generation rollback handle until metadata registration commits.
pub struct GeneratedCaptureResult {
    pub result: Vec<u8>,
    pub receipt: Option<ArtifactStoreReceipt>,
    pub cleanup: Option<Box<dyn GeneratedArtifactSink>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerArtifactSnapshot {
    pub display_filename: Option<String>,
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
    execution_timeout: Duration,
    approval_id: Option<ApprovalId>,
    submission_approval_binding: Option<(ProposalHash, bool)>,
    policy_admission: Option<action_approval::TypedActionAdmission>,
    policy_failure: Option<&'static str>,
    dispatch_permit: Option<DispatchPermit>,
}

struct ArtifactRecord {
    publication: Option<ArtifactPublication>,
    artifact: Artifact,
    object_generation: ArtifactObjectGeneration,
    display_filename: Option<String>,
}

#[derive(Clone)]
struct PendingDownloadRollback {
    completion: BrowserDownloadCompletion,
    receipt: ArtifactStoreReceipt,
    object_discarded: bool,
    publication: Option<ArtifactPublication>,
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
    pool: Option<Arc<ActionJournalPool>>,
    scope: JournalSessionScope,
    committed: bool,
    notification_journal: Option<Arc<SessionEventJournal>>,
}

impl Drop for SessionJournalGuard {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        if let Some(journal) = &self.notification_journal {
            let _ = journal.record(
                &self.scope,
                browserd_core::NotificationSessionLifecycleState::Failed,
                browserd_core::NotificationSessionExecutionState::Idle,
                None,
            );
        }
        if let Some(pool) = &self.pool {
            // The ledger has dropped before this guard. The pool independently proves that
            // no action was accepted and that no WAL handle is pinned before exact deletion.
            let _ = pool.discard_unadmitted(&self.scope);
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
    effective_isolation: WorkerIsolationProfile,
    /// Effective feature profile fixed at session creation from the trusted create options.
    ///
    /// This gates privileged features (notably `evaluate`) at dispatch so a caller cannot enable
    /// them by placing a profile string on a per-action RPC. See SPEC D-18.
    feature_profile: FeatureProfile,
    machine: SessionMachine,
    notification_journal: Option<Arc<SessionEventJournal>>,
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
    artifact_reserved_bytes: u64,
    pending_download_rollbacks: HashMap<ArtifactId, PendingDownloadRollback>,
    approvals: HashMap<ApprovalId, ApprovalRecord>,
    action_ledger: ActionLedger<ManagedActionJournal>,
    durability_degraded: bool,
    /// When a fully-closed session's in-memory state becomes eligible for reclamation (BRD-018):
    /// set to `now + session_retention` the first maintenance pass that observes the session
    /// terminal-and-cleaned, and the entry is dropped once the clock reaches it. `None` while the
    /// session is active or not yet observed terminal.
    reclaim_at: Option<SessionTime>,
}

struct SessionExecutor {
    state: Mutex<SessionState>,
    action_owner: AtomicBool,
    approved_dispatch_phase: AtomicU8,
    approved_dispatch_wait: Mutex<()>,
    approved_dispatch_changed: Condvar,
    cleanup_owner: Mutex<()>,
    viewer: Mutex<Option<viewer::ViewerSession>>,
}

/// Commit notification state before installing the new live machine. A failed durable
/// write keeps the previous machine and charges its capacity for reconciliation.
fn install_session_machine(
    session: &mut SessionState,
    machine: SessionMachine,
) -> Result<(), WorkerError> {
    if let Some(journal) = &session.notification_journal {
        let fence = machine.snapshot().owner_fence;
        let scope = JournalSessionScope::new(
            session.tenant_id.clone(),
            machine.session_id().clone(),
            fence.worker_id().clone(),
            fence.as_placement_fence(),
        )
        .map_err(|_| WorkerError::DurabilityUnavailable)?;
        if let Err(error) = journal.record_machine(&scope, &machine) {
            session.durability_degraded = true;
            return Err(error);
        }
    }
    session.machine = machine;
    Ok(())
}

fn transition_session_machine<T>(
    session: &mut SessionState,
    transition: impl FnOnce(&mut SessionMachine) -> Result<T, SessionError>,
) -> Result<T, WorkerError> {
    let mut machine = session.machine.clone();
    let result = transition(&mut machine).map_err(map_session_error)?;
    install_session_machine(session, machine)?;
    Ok(result)
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
    admission: worker_admission::WorkerAdmissionState,
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
    runtime_safety: Option<runtime_safety::WorkerRuntimeSafety>,
    clock: Arc<dyn WorkerClock>,
    stopped_dispatch_terminalization_hook: Arc<dyn Fn() -> Result<(), WorkerError> + Send + Sync>,
    _fleet_epochs: WorkerEpochRegistry,
    _features: FeatureRegistry,
    capture_admission: browserd_features::FeatureAdmission,
    /// When set, a critical audit intent is written before any action effect is dispatched; a
    /// full WAL or sink failure fails the dispatch closed so no browser effect occurs without a
    /// durable audit record (BRD-020). `None` leaves dispatch unaudited (the default for tests and
    /// deployments that have not wired an audit sink).
    audit_wal: Option<Arc<AuditWal>>,
    privileged_evaluate_policy: PrivilegedEvaluatePolicy,
    action_approval_policy: Option<browserd_policy::ActionApprovalPolicy>,
    action_journal_pool: Option<Arc<ActionJournalPool>>,
    journal_seal_cursor: Mutex<Option<SessionId>>,
    secret_resolver: Option<Arc<dyn SecretResolver>>,
    checkpoint_store: Option<Arc<dyn CheckpointStore>>,
    checkpoint_cleanup_at: Mutex<Option<Instant>>,
    checkpoint_cleanup_degraded: Arc<AtomicBool>,
    control_event_journal: Arc<ControlEventJournal>,
    session_event_journal: Option<Arc<SessionEventJournal>>,
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
                admission: worker_admission::WorkerAdmissionState::new(),
            }),
            create_idle: Condvar::new(),
            create_idempotency: IdempotencyRegistry::default(),
            viewer_tickets,
            emergency_policy,
            runtime_safety: None,
            clock,
            stopped_dispatch_terminalization_hook,
            _fleet_epochs: fleet_epochs,
            _features: FeatureRegistry::builtin(),
            capture_admission: browserd_features::FeatureAdmission::new(
                browserd_features::FeatureConcurrencyLimits {
                    pdf: 1,
                    full_page_screenshot: 1,
                    large_snapshot: 2,
                    scrape: 1,
                },
            ),
            audit_wal: None,
            privileged_evaluate_policy: PrivilegedEvaluatePolicy::default(),
            action_approval_policy: None,
            action_journal_pool: None,
            journal_seal_cursor: Mutex::new(None),
            secret_resolver: None,
            checkpoint_store: None,
            checkpoint_cleanup_at: Mutex::new(None),
            checkpoint_cleanup_degraded: Arc::new(AtomicBool::new(false)),
            control_event_journal: Arc::new(ControlEventJournal::memory()),
            session_event_journal: None,
        }
    }

    /// Requires a critical audit intent to be durably recorded before any action effect dispatches.
    ///
    /// Once set, a full WAL (for the critical event) or an audit sink failure blocks the dispatch
    /// fail-closed rather than letting an un-audited effect run (BRD-020).
    #[must_use]
    pub fn with_audit_wal(mut self, audit_wal: Arc<AuditWal>) -> Self {
        self.audit_wal = Some(audit_wal);
        self
    }

    /// Enables privileged sessions for configured tenants and checks the exact principal grant
    /// on every evaluate action. A durable audit WAL is independently required at dispatch.
    #[must_use]
    pub fn with_privileged_evaluate_policy(mut self, policy: PrivilegedEvaluatePolicy) -> Self {
        if let Some(support) = &mut self.config.session_option_support {
            if policy.is_enabled() {
                support.feature_profiles.insert("privileged".to_owned());
            } else {
                support.feature_profiles.remove("privileged");
            }
        }
        self.privileged_evaluate_policy = policy;
        self
    }

    /// Installs the worker-authoritative action policy. Production always installs a snapshot;
    /// sensitive and mutating actions without an exact allow rule require external approval.
    #[must_use]
    pub fn with_action_approval_policy(
        mut self,
        policy: browserd_policy::ActionApprovalPolicy,
    ) -> Self {
        self.action_approval_policy = Some(policy);
        self
    }

    /// Installs aggregate WAL accounting and durable terminal-custody retention.
    #[must_use]
    pub fn with_action_journal_pool(mut self, pool: Arc<ActionJournalPool>) -> Self {
        self.action_journal_pool = Some(pool);
        self
    }

    #[must_use]
    pub fn with_secret_resolver(mut self, resolver: Arc<dyn SecretResolver>) -> Self {
        self.secret_resolver = Some(resolver);
        self
    }

    #[must_use]
    pub fn with_checkpoint_store(mut self, store: Arc<dyn CheckpointStore>) -> Self {
        if let Some(support) = &mut self.config.session_option_support {
            support.supports_checkpoint = true;
        }
        self.checkpoint_store = Some(store);
        self
    }

    #[must_use]
    pub fn with_control_event_journal(mut self, journal: Arc<ControlEventJournal>) -> Self {
        self.control_event_journal = journal;
        self
    }

    #[must_use]
    pub fn with_session_event_journal(mut self, journal: Arc<SessionEventJournal>) -> Self {
        self.session_event_journal = Some(journal);
        self
    }

    pub fn pending_control_events(
        &self,
        peer: &AuthenticatedPeer,
        limit: usize,
    ) -> Result<Vec<WorkerControlEvent>, WorkerError> {
        self.authorize(peer)?;
        self.control_event_journal.pending(limit)
    }

    pub fn ack_control_event(
        &self,
        peer: &AuthenticatedPeer,
        event: &WorkerControlEvent,
    ) -> Result<(), WorkerError> {
        self.authorize(peer)?;
        self.control_event_journal.ack(event)
    }

    /// Records the mandatory pre-dispatch audit intent for an action about to cause a browser
    /// effect. A no-op when no audit WAL is configured; otherwise a critical event that, if it
    /// cannot be made durable (WAL full or sink error), returns an error so the caller fails the
    /// dispatch closed (BRD-020). The event id is the action id, so a dispatch retry is idempotent.
    fn audit_dispatch_intent(
        &self,
        session_id: &SessionId,
        action_id: &ActionId,
        requester_principal_id: &PrincipalId,
    ) -> Result<(), AuditWalError> {
        let Some(audit_wal) = self.audit_wal.as_ref() else {
            return Ok(());
        };
        let event_id = AuditEventId::new(format!("action-dispatch:{action_id}"))?;
        let payload = serde_json::to_vec(&serde_json::json!({
            "session_id": session_id,
            "action_id": action_id,
            "principal_id": requester_principal_id,
        }))
        .unwrap_or_default();
        let event = AuditEvent::new(event_id, "action.dispatch", payload, true);
        match audit_wal.append(event)? {
            AppendOutcome::Durable(_) | AppendOutcome::Existing(_) => Ok(()),
            // A critical event is never silently dropped (the WAL returns `FullCritical`); treat any
            // non-durable outcome as a failure so a missing record can never precede an effect.
            AppendOutcome::DroppedNonCritical => Err(AuditWalError::FullCritical),
        }
    }

    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.control_plane_qualified() && self.runtime_safety_ready()
    }

    /// Startup qualification permits authenticated metadata/cleanup while safety is uninitialized.
    /// Actual create/effect admissions independently require fresh runtime authority.
    #[must_use]
    pub fn control_plane_qualified(&self) -> bool {
        let Ok(worker) = self.state.lock() else {
            return false;
        };
        if worker.draining
            || worker.stopped
            || worker.create_cleanup_failed
            || self.checkpoint_cleanup_degraded.load(Ordering::Acquire)
        {
            return false;
        }
        let sessions = worker.sessions.values().cloned().collect::<Vec<_>>();
        drop(worker);
        sessions.iter().all(|executor| {
            executor.state.lock().is_ok_and(|session| {
                !session.durability_degraded && session.pending_download_rollbacks.is_empty()
            })
        }) && self.config.action_journal.qualify()
            && self
                .session_event_journal
                .as_ref()
                .is_none_or(|journal| journal.qualify())
            && self.driver.qualify().is_ok()
            && self.sandbox.qualify().is_ok()
    }

    pub fn create_session(
        &self,
        peer: &AuthenticatedPeer,
        command: CreateSessionCommand,
        now: SessionTime,
    ) -> Result<CreateSessionOutcome, WorkerError> {
        self.create_session_internal(peer, command, None, None, now, None)
    }

    pub fn create_session_with_options(
        &self,
        peer: &AuthenticatedPeer,
        command: CreateSessionCommand,
        options: &WorkerSessionOptionsV1,
        now: SessionTime,
    ) -> Result<CreateSessionOutcome, WorkerError> {
        self.create_session_internal(peer, command, Some(options), None, now, None)
    }

    pub fn create_session_with_placement(
        &self,
        peer: &AuthenticatedPeer,
        command: CreateSessionCommand,
        options: &WorkerSessionOptionsV1,
        requested: WorkerIsolationProfile,
        now: SessionTime,
    ) -> Result<CreateSessionOutcome, WorkerError> {
        self.create_session_internal(peer, command, Some(options), Some(requested), now, None)
    }

    fn create_session_internal(
        &self,
        peer: &AuthenticatedPeer,
        command: CreateSessionCommand,
        options: Option<&WorkerSessionOptionsV1>,
        requested: Option<WorkerIsolationProfile>,
        now: SessionTime,
        mut reservation: Option<worker_admission::WorkerCreateReservation<'_>>,
    ) -> Result<CreateSessionOutcome, WorkerError> {
        self.authorize(peer)?;
        if self.config.admission_policy.is_some() != reservation.is_some() {
            return Err(WorkerError::InvalidConfiguration);
        }
        if let Some(assignment) = self
            .config
            .admission_policy
            .as_ref()
            .and_then(WorkerAdmissionPolicy::exclusive_assignment)
            && assignment.tenant_id() != &command.tenant_id
        {
            return Err(WorkerError::InvalidConfiguration);
        }
        let requested = match &reservation {
            Some(reservation) => {
                if requested != Some(reservation.token.request.request.requested_isolation) {
                    return Err(WorkerError::InvalidConfiguration);
                }
                Some(self.reserved_create_isolation(&reservation.token.request)?)
            }
            None => requested,
        };
        let requested = match &self.runtime_safety {
            Some(_) => {
                let effective =
                    self.runtime_create_isolation(&command.tenant_id, options, requested)?;
                if reservation.is_some() && requested != Some(effective) {
                    return Err(WorkerError::InvalidConfiguration);
                }
                Some(effective)
            }
            None => requested,
        };
        if requested.is_some_and(|profile| !self.driver.supports_requested_isolation(profile)) {
            return Err(WorkerError::InvalidConfiguration);
        }
        let feature_profile = feature_profile_from_options(options);
        if feature_profile == FeatureProfile::Privileged
            && !self
                .privileged_evaluate_policy
                .allows_tenant(&command.tenant_id)
        {
            return Err(WorkerError::InvalidConfiguration);
        }
        let timeout_policy = match options {
            Some(options) if options.is_valid() => SessionTimeoutPolicy::new(
                Duration::from_secs(options.ttl_seconds),
                Duration::from_secs(options.idle_timeout_seconds),
            )
            .map_err(|_| WorkerError::InvalidConfiguration)?,
            Some(_) => return Err(WorkerError::InvalidConfiguration),
            None => self.config.timeout_policy,
        };
        if options.is_some_and(|options| options.checkpoint_ref.is_some())
            && self.checkpoint_store.is_none()
        {
            return Err(WorkerError::InvalidConfiguration);
        }
        if self.driver.qualify().is_err()
            || self.sandbox.qualify().is_err()
            || self
                .session_event_journal
                .as_ref()
                .is_some_and(|journal| !journal.qualify())
        {
            return Err(WorkerError::NotReady);
        }
        if command.placement_version == 0 || command.session_incarnation == 0 {
            return Err(WorkerError::InvalidConfiguration);
        }
        let key = IdempotencyKey::new(command.idempotency_key.clone())
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
            if worker.create_cleanup_failed
                || self.checkpoint_cleanup_degraded.load(Ordering::Acquire)
            {
                return Err(WorkerError::NotReady);
            }
            if let Some(reservation) = &reservation {
                worker
                    .admission
                    .validate_creating(reservation.token, &command)?;
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
            // One scan tallies both the global occupied slots and this tenant's retained sessions
            // (any lifecycle, so terminal-not-yet-reclaimed entries count toward its bound).
            let mut tenant_retained = 0usize;
            let occupied = worker.sessions.values().try_fold(
                worker.creating_sessions.saturating_add(
                    worker
                        .admission
                        .pending_slots_except(reservation.as_ref().map(|r| r.token)),
                ),
                |count, executor| {
                    let session = executor
                        .state
                        .lock()
                        .map_err(|_| WorkerError::StateUnavailable)?;
                    if session.tenant_id == command.tenant_id {
                        tenant_retained = tenant_retained.saturating_add(1);
                    }
                    Ok::<_, WorkerError>(
                        count.saturating_add(usize::from(session.occupies_capacity)),
                    )
                },
            )?;
            if occupied >= self.config.max_sessions
                || tenant_retained >= self.config.max_sessions_per_tenant
            {
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
            if let Some(reservation) = &reservation {
                worker.admission.begin_transfer(reservation.token)?;
            }
            worker.creating_sessions = worker.creating_sessions.saturating_add(1);
            worker.create_operations.insert(
                operation_id.clone(),
                CreateOperationResult::Pending(Arc::clone(&waiter)),
            );
            (operation_id, waiter)
        };

        let create_tenant = command.tenant_id.clone();
        let creation = (|| {
            let session_id = SessionId::new();
            let fence = OwnershipFence::new(
                self.config.worker_id.clone(),
                self.config.worker_epoch,
                command.placement_version,
                command.session_incarnation,
            );
            let restore_deadline = Instant::now() + Duration::from_secs(30);
            let checkpoint = options
                .and_then(|options| options.checkpoint_ref.as_ref())
                .map(|reference| {
                    self.admit_runtime_operation(
                        &command.tenant_id,
                        &session_id,
                        "browser:checkpoint_restore",
                    )?;
                    self.audit_checkpoint_restore_intent(
                        &command.tenant_id,
                        &session_id,
                        reference,
                    )?;
                    let checkpoint = self
                        .checkpoint_store
                        .as_ref()
                        .ok_or(WorkerError::InvalidConfiguration)?
                        .load(
                            &command.tenant_id,
                            reference,
                            self.clock.now()?.get(),
                            restore_deadline,
                        )
                        .map_err(|_| WorkerError::DependencyUnavailable)?;
                    if checkpoint.receipt.checkpoint_ref != *reference
                        || checkpoint.receipt.source_session_id == session_id
                    {
                        return Err(WorkerError::DependencyUnavailable);
                    }
                    checkpoint
                        .snapshot
                        .validate()
                        .map_err(|_| WorkerError::DependencyUnavailable)?;
                    Ok(checkpoint)
                })
                .transpose()?;
            let journal_path = self.config.action_journal.session_path(&session_id);
            let journal_scope = JournalSessionScope::new(
                command.tenant_id.clone(),
                session_id.clone(),
                self.config.worker_id.clone(),
                fence.as_placement_fence(),
            )
            .map_err(|_| WorkerError::DurabilityUnavailable)?;
            let journal = match &self.action_journal_pool {
                Some(pool) if self.session_event_journal.is_some() => {
                    pool.create_notifying_session(&journal_scope)
                }
                Some(pool) => pool.create_session(&journal_scope),
                None => {
                    FileActionJournal::create_new(&journal_path, self.config.action_journal.limits)
                        .and_then(|journal| match &self.session_event_journal {
                            Some(_) => journal.with_notification_source(
                                browserd_core::NotificationSourceScope::new(
                                    command.tenant_id.clone(),
                                    self.config.worker_id.clone(),
                                    *session_id.as_uuid(),
                                    browserd_core::NotificationSourceFamily::ActionJournal,
                                )
                                .map_err(|_| {
                                    browserd_actions::JournalError::new(
                                        "invalid notification source",
                                    )
                                })?,
                            ),
                            None => Ok(journal),
                        })
                        .map(ManagedActionJournal::unmanaged)
                        .map(Arc::new)
                }
            }
            .map_err(|_| WorkerError::DurabilityUnavailable)?;
            let journal_guard = SessionJournalGuard {
                path: journal_path,
                pool: self.action_journal_pool.clone(),
                scope: journal_scope,
                committed: false,
                notification_journal: self.session_event_journal.clone(),
            };
            if let Some(journal) = &self.session_event_journal {
                journal.record(
                    &journal_guard.scope,
                    browserd_core::NotificationSessionLifecycleState::Creating,
                    browserd_core::NotificationSessionExecutionState::Idle,
                    None,
                )?;
            }
            let action_ledger = ActionLedger::new(
                LedgerSession::new(
                    command.tenant_id.clone(),
                    session_id.clone(),
                    fence.as_placement_fence(),
                ),
                journal,
            );
            let (mut machine, _) = SessionMachine::create_with_timeouts(
                session_id.clone(),
                fence.clone(),
                self.config.lease_policy,
                timeout_policy,
                now,
            );
            machine
                .start(&fence, now)
                .and_then(|_| machine.mark_running(&fence, now))
                .map_err(map_session_error)?;
            let effective =
                self.runtime_create_isolation(&command.tenant_id, options, requested)?;
            if reservation.is_some() && requested != Some(effective) {
                return Err(WorkerError::InvalidConfiguration);
            }
            let requested = effective;
            if !self.driver.shard_managed_contexts() {
                if let Some(reservation) = &mut reservation {
                    reservation.progress.exposure_possible = true;
                }
                if self.sandbox.provision(&session_id, &fence).is_err() {
                    return if self
                        .sandbox
                        .cleanup(&session_id, CleanupReason::BrowserFailure)
                        .is_ok()
                    {
                        if let Some(reservation) = &mut reservation {
                            reservation.confirm_disposed(&create_tenant, &session_id, &fence);
                        }
                        Err(WorkerError::DependencyUnavailable)
                    } else {
                        Err(WorkerError::CleanupFailed)
                    };
                }
            }
            // The original request hash includes the reference. Only browser creation receives
            // a copy with it removed; the typed restore completes before any Ready receipt.
            let driver_options = options.cloned().map(|mut options| {
                options.checkpoint_ref = None;
                options
            });
            if let Some(reservation) = &mut reservation {
                reservation.progress.exposure_possible = true;
            }
            let context = self.driver.create_context_owned_with_placement(
                &command.tenant_id,
                &session_id,
                &fence,
                driver_options.as_ref(),
                requested,
            );
            let context = match context {
                Ok(context) => context,
                Err(_) => {
                    let sandbox_clean = self.driver.shard_managed_contexts()
                        || self
                            .sandbox
                            .cleanup(&session_id, CleanupReason::BrowserFailure)
                            .is_ok();
                    let driver_clean = reservation.is_none()
                        || self
                            .driver
                            .close_context_fenced(&session_id, &fence)
                            .is_ok();
                    return if sandbox_clean && driver_clean {
                        if let Some(reservation) = &mut reservation {
                            reservation.confirm_disposed(&create_tenant, &session_id, &fence);
                        }
                        Err(WorkerError::DependencyUnavailable)
                    } else {
                        Err(WorkerError::CleanupFailed)
                    };
                }
            };
            if !requested.satisfied_by(context.effective_isolation)
                || self
                    .runtime_verify_create(&command.tenant_id, options, context.effective_isolation)
                    .is_err()
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
                return Err(if driver_clean && sandbox_clean {
                    if let Some(reservation) = &mut reservation {
                        reservation.confirm_disposed(&create_tenant, &session_id, &fence);
                    }
                    WorkerError::DependencyUnavailable
                } else {
                    WorkerError::CleanupFailed
                });
            }
            let effective_isolation = context.effective_isolation;
            let primary_page_id = context.primary_page_id;
            let restored_checkpoint = if let Some(checkpoint) = checkpoint {
                let restored = self
                    .admit_runtime_operation(
                        &command.tenant_id,
                        &session_id,
                        "browser:checkpoint_restore",
                    )
                    .map_err(|_| CheckpointError::Rejected)
                    .and_then(|()| {
                        self.driver.restore_checkpoint_until(
                            &command.tenant_id,
                            &session_id,
                            &primary_page_id,
                            &fence,
                            checkpoint.snapshot,
                            restore_deadline,
                        )
                    })
                    .and_then(|()| {
                        let ready_at = self
                            .clock
                            .now()
                            .map_err(|_| CheckpointError::Unavailable)?
                            .max(machine.last_observed_at());
                        machine
                            .renew_lease(&fence, ready_at)
                            .map(|_| ())
                            .map_err(|_| CheckpointError::Rejected)
                    });
                if restored.is_err() {
                    let driver_clean = self
                        .driver
                        .close_context_fenced(&session_id, &fence)
                        .is_ok();
                    let sandbox_clean = self.driver.shard_managed_contexts()
                        || self
                            .sandbox
                            .cleanup(&session_id, CleanupReason::BrowserFailure)
                            .is_ok();
                    return Err(if driver_clean && sandbox_clean {
                        if let Some(reservation) = &mut reservation {
                            reservation.confirm_disposed(&create_tenant, &session_id, &fence);
                        }
                        WorkerError::DependencyUnavailable
                    } else {
                        WorkerError::CleanupFailed
                    });
                }
                Some(checkpoint.receipt)
            } else {
                None
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
                    if let Some(reservation) = &mut reservation {
                        reservation.confirm_disposed(&create_tenant, &session_id, &fence);
                    }
                    Err(error)
                } else {
                    Err(WorkerError::CleanupFailed)
                };
            }
            let mut pages = BTreeSet::new();
            pages.insert(primary_page_id.clone());
            let executor = Arc::new(SessionExecutor {
                viewer: Mutex::new(None),
                state: Mutex::new(SessionState {
                    tenant_id: command.tenant_id,
                    effective_isolation,
                    feature_profile,
                    machine,
                    notification_journal: self.session_event_journal.clone(),
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
                    artifact_reserved_bytes: 0,
                    pending_download_rollbacks: HashMap::new(),
                    approvals: HashMap::new(),
                    action_ledger,
                    durability_degraded: false,
                    reclaim_at: None,
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
                    restored_checkpoint,
                    effective_isolation,
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
                    match &journal_guard.notification_journal {
                        Some(journal) => executor
                            .state
                            .lock()
                            .map_err(|_| WorkerError::StateUnavailable)
                            .and_then(|state| {
                                journal.record_machine(&journal_guard.scope, &state.machine)
                            })
                            .err(),
                        None => None,
                    }
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
                        if let Some(reservation) = &mut reservation {
                            reservation.confirm_disposed(
                                &create_tenant,
                                &outcome.session_id,
                                &outcome.fence,
                            );
                        }
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

    pub fn session_effective_isolation(
        &self,
        peer: &AuthenticatedPeer,
        session_id: &SessionId,
        fence: &OwnershipFence,
    ) -> Result<WorkerIsolationProfile, WorkerError> {
        self.authorize(peer)?;
        let executor = self.session(session_id)?;
        let session = executor
            .state
            .lock()
            .map_err(|_| WorkerError::StateUnavailable)?;
        validate_fence(&session, fence)?;
        Ok(session.effective_isolation)
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
        let lifecycle =
            transition_session_machine(&mut session, |machine| machine.begin_close(fence, now))?;
        let remaining_terminalization = terminalize_actions_for_shutdown(&mut session);
        let terminalization = match stopped_dispatch_terminalization {
            Ok(()) => remaining_terminalization,
            Err(first_error) => Err(first_error),
        };
        if lifecycle == SessionLifecycle::Closed {
            terminalization?;
            let snapshot = session.machine.snapshot();
            drop(session);
            let _ = self.seal_idle_action_journal(&executor);
            return Ok(snapshot);
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
        install_session_machine(&mut session, cleanup_machine)?;
        if cleanup_result.is_ok() {
            session.occupies_capacity = false;
        }
        cleanup_result.map_err(|_| WorkerError::CleanupFailed)?;
        terminalization?;
        let snapshot = session.machine.snapshot();
        drop(session);
        let _ = self.seal_idle_action_journal(&executor);
        Ok(snapshot)
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
            self.admit_runtime_operation(&session.tenant_id, session_id, "browser:create_page")?;
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
        self.submit_action_inner(
            peer,
            requester_principal_id,
            session_id,
            fence,
            None,
            idempotency_key,
            request_hash,
            kind,
            feature,
            page_id,
            payload,
            approval,
            Duration::from_secs(30),
            now,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn submit_action_with_identity(
        &self,
        peer: &AuthenticatedPeer,
        requester_principal_id: PrincipalId,
        session_id: &SessionId,
        fence: &OwnershipFence,
        action_id: ActionId,
        action_sequence: ActionSequence,
        idempotency_key: &str,
        request_hash: [u8; 32],
        kind: ActionKind,
        feature: Option<BuiltinFeature>,
        page_id: Option<PageId>,
        payload: Vec<u8>,
        approval: Option<ActionApprovalRequirement>,
        now: SessionTime,
    ) -> Result<ActionId, WorkerError> {
        self.submit_action_inner(
            peer,
            requester_principal_id,
            session_id,
            fence,
            Some((action_id, action_sequence)),
            idempotency_key,
            request_hash,
            kind,
            feature,
            page_id,
            payload,
            approval,
            Duration::from_secs(30),
            now,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn submit_and_run_action_with_identity(
        &self,
        peer: &AuthenticatedPeer,
        requester_principal_id: PrincipalId,
        session_id: &SessionId,
        fence: &OwnershipFence,
        action_id: ActionId,
        action_sequence: ActionSequence,
        idempotency_key: &str,
        request_hash: [u8; 32],
        kind: ActionKind,
        feature: Option<BuiltinFeature>,
        page_id: Option<PageId>,
        payload: Vec<u8>,
        approval: Option<ActionApprovalRequirement>,
        execution_timeout: Duration,
        now: SessionTime,
    ) -> Result<ActionId, WorkerError> {
        self.authorize(peer)?;
        let executor = self.session(session_id)?;
        let _owner = ActionOwner::claim(&executor.action_owner)?;
        let action_id = self.submit_action_inner(
            peer,
            requester_principal_id,
            session_id,
            fence,
            Some((action_id, action_sequence)),
            idempotency_key,
            request_hash,
            kind,
            feature,
            page_id,
            payload,
            approval,
            execution_timeout,
            now,
        )?;
        while self
            .run_next_action_owned(session_id, fence, now, &executor)?
            .is_some()
        {}
        Ok(action_id)
    }

    #[allow(clippy::too_many_arguments)]
    fn submit_action_inner(
        &self,
        peer: &AuthenticatedPeer,
        requester_principal_id: PrincipalId,
        session_id: &SessionId,
        fence: &OwnershipFence,
        action_identity: Option<(ActionId, ActionSequence)>,
        idempotency_key: &str,
        request_hash: [u8; 32],
        kind: ActionKind,
        feature: Option<BuiltinFeature>,
        page_id: Option<PageId>,
        payload: Vec<u8>,
        approval: Option<ActionApprovalRequirement>,
        execution_timeout: Duration,
        now: SessionTime,
    ) -> Result<ActionId, WorkerError> {
        self.authorize(peer)?;
        let executor = self.session(session_id)?;
        let mut session = executor
            .state
            .lock()
            .map_err(|_| WorkerError::StateUnavailable)?;
        validate_fence(&session, fence)?;
        if execution_timeout.is_zero() || execution_timeout > Duration::from_secs(300) {
            return Err(WorkerError::InvalidConfiguration);
        }
        // A gateway cannot supply target evidence or pre-approve an action. The configured
        // worker derives it at the queue head from its owned browser and immutable policy.
        if self.action_approval_policy.is_some() && approval.is_some() {
            return Err(WorkerError::ApprovalEvidenceMismatch);
        }
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
                if let Some((provided_action_id, provided_sequence)) = &action_identity {
                    let existing = session
                        .actions
                        .get(action_id)
                        .ok_or(WorkerError::StateUnavailable)?;
                    if action_id != provided_action_id
                        || existing.snapshot.action_sequence != *provided_sequence
                    {
                        return Err(WorkerError::IdempotencyConflict);
                    }
                }
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
        let approval_id = requires_approval.then(ApprovalId::new);
        let policy_pending = self.action_approval_policy.is_some();
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
        )
        .with_result_budget(
            if matches!(
                serde_json::from_slice::<WorkerActionCommand>(&payload),
                Ok(WorkerActionCommand::Snapshot)
            ) {
                browserd_actions::ActionResultBudget::Snapshot
            } else {
                browserd_actions::ActionResultBudget::Standard
            },
        );
        let acceptance = match action_identity {
            Some((action_id, action_sequence)) => session.action_ledger.accept_with_identity(
                ledger_fence,
                action_id,
                action_sequence,
                request,
            ),
            None => session.action_ledger.accept(ledger_fence, request),
        }
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
                    session.action_ledger.require_approval_with_identity(
                        ledger_fence,
                        &action_id,
                        approval_id
                            .clone()
                            .ok_or(ActionLedgerError::JournalUnavailable(
                                browserd_actions::JournalError::new("approval identity missing"),
                            ))?,
                    )
                } else if policy_pending {
                    return Ok(ActionState::Queued);
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
                        execution_timeout,
                        approval_id: None,
                        submission_approval_binding: approval_binding
                            .as_ref()
                            .map(|(hash, _, four_eyes)| (*hash, *four_eyes)),
                        policy_admission: None,
                        policy_failure: None,
                        dispatch_permit: None,
                    },
                );
                return Err(map_action_ledger_error(error));
            }
        };
        let expected_state = if requires_approval {
            ActionState::PendingApproval
        } else if policy_pending {
            ActionState::Queued
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
                execution_timeout,
                approval_id: approval_id.clone(),
                submission_approval_binding: approval_binding
                    .as_ref()
                    .map(|(hash, _, four_eyes)| (*hash, *four_eyes)),
                policy_admission: None,
                policy_failure: None,
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
        let expected_request_hash = durable_action_request_hash(
            action.snapshot.canonical_request_hash,
            &action.requester_principal_id,
            action
                .submission_approval_binding
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
        self.run_next_action_owned(session_id, fence, now, &executor)
    }

    fn run_next_action_owned(
        &self,
        session_id: &SessionId,
        fence: &OwnershipFence,
        now: SessionTime,
        executor: &Arc<SessionExecutor>,
    ) -> Result<Option<WorkerActionSnapshot>, WorkerError> {
        self.prepare_action_policy(session_id, fence, executor)?;
        let (
            action_id,
            page_id,
            payload,
            execution_timeout,
            permit,
            approval_request,
            action_feature,
            feature_profile,
            requester_principal_id,
            policy_admission,
            policy_failure,
        ) = {
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
            let feature_profile = session.feature_profile;
            let (
                page_id,
                payload,
                execution_timeout,
                approval_id,
                requester_principal_id,
                action_feature,
            ) = session
                .actions
                .get(&action_id)
                .filter(|action| action.snapshot.status == ActionStatus::Queued)
                .map(|action| {
                    (
                        action.page_id.clone(),
                        action.payload.clone(),
                        action.execution_timeout,
                        action.approval_id.clone(),
                        action.requester_principal_id.clone(),
                        action.snapshot.feature,
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
            let dispatch_now = now.max(session.machine.last_observed_at());
            transition_session_machine(&mut session, |machine| {
                machine.begin_action(fence, action_id.clone(), dispatch_now)
            })?;
            let permit = match session
                .action_ledger
                .prepare_dispatch(fence.as_placement_fence(), &action_id)
            {
                Ok(DispatchDecision::Dispatch(permit)) => permit,
                Ok(DispatchDecision::DoNotReplay(_)) => {
                    transition_session_machine(&mut session, |machine| {
                        machine.finish_action(fence, &action_id, dispatch_now)
                    })?;
                    return Err(WorkerError::InvalidActionTransition);
                }
                Err(error) => {
                    transition_session_machine(&mut session, |machine| {
                        machine.finish_action(fence, &action_id, dispatch_now)
                    })?;
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
            let policy_admission = action.policy_admission.clone();
            let policy_failure = action.policy_failure;
            executor.approved_dispatch_phase.store(
                if policy_admission.is_some()
                    || approval_request.is_some()
                    || matches!(
                        serde_json::from_slice::<WorkerActionCommand>(&payload),
                        Ok(WorkerActionCommand::FillSecret { .. }
                            | WorkerActionCommand::Evaluate { .. })
                    )
                {
                    APPROVED_DISPATCH_INSPECTING
                } else {
                    APPROVED_DISPATCH_IDLE
                },
                Ordering::Release,
            );
            (
                action_id,
                page_id,
                payload,
                execution_timeout,
                permit,
                approval_request,
                action_feature,
                feature_profile,
                requester_principal_id,
                policy_admission,
                policy_failure,
            )
        };
        let execution_deadline = Instant::now()
            .checked_add(execution_timeout)
            .ok_or(WorkerError::InvalidConfiguration)?;
        let command = serde_json::from_slice::<WorkerActionCommand>(&payload).ok();
        let mut checkpoint_publication = None;
        let is_evaluate = action_feature == Some(BuiltinFeature::PrivilegedEvaluate)
            || matches!(command, Some(WorkerActionCommand::Evaluate { .. }));
        let evaluate_admission = if is_evaluate {
            self.admit_privileged_evaluate(session_id, fence, &action_id, executor)
        } else {
            Ok(())
        };
        let (mut outcome, response_error, mut known_failure_reason) = if let Some(reason) =
            policy_failure
        {
            (
                ActionExecutionResult::FailedKnown(reason.to_owned()),
                None,
                Some(KnownFailureReason::PolicyDenied),
            )
        } else if action_feature == Some(BuiltinFeature::PrivilegedEvaluate)
            && feature_profile != FeatureProfile::Privileged
        {
            // BRD-004 / SPEC D-18: a standard-profile session must not run `evaluate`. Deny it
            // before any dispatch as a deterministic policy failure with no browser effect,
            // never as an ambiguous outcome, and regardless of whether approval was attached.
            // The dispatch phase may have been armed to inspecting for an approval-bound action;
            // reset it since no approved dispatch will run.
            executor
                .approved_dispatch_phase
                .store(APPROVED_DISPATCH_IDLE, Ordering::Release);
            (
                ActionExecutionResult::FailedKnown(
                    "policy: evaluate requires the privileged feature profile".to_owned(),
                ),
                None,
                Some(KnownFailureReason::PolicyDenied),
            )
        } else if let Err(reason) = evaluate_admission {
            executor
                .approved_dispatch_phase
                .store(APPROVED_DISPATCH_IDLE, Ordering::Release);
            (
                ActionExecutionResult::FailedKnown("evaluate_admission_rejected".to_owned()),
                None,
                Some(reason),
            )
        } else if policy_admission.is_none()
            && approval_request.is_some()
            && matches!(
                command,
                Some(
                    WorkerActionCommand::FillSecret { .. } | WorkerActionCommand::Checkpoint { .. }
                )
            )
        {
            executor
                .approved_dispatch_phase
                .store(APPROVED_DISPATCH_IDLE, Ordering::Release);
            (
                ActionExecutionResult::FailedKnown("prepared_approval_unsupported".to_owned()),
                None,
                Some(KnownFailureReason::NotDispatched),
            )
        } else if let Err(audit_error) =
            self.audit_dispatch_intent(session_id, &action_id, &requester_principal_id)
        {
            // Fail closed: no browser effect runs without a durable audit intent (BRD-020). Reset
            // the dispatch phase (it may have been armed to inspecting for an approval-bound action)
            // and finalize as a non-dispatched known failure, which releases the dispatch permit via
            // the shared completion path below.
            executor
                .approved_dispatch_phase
                .store(APPROVED_DISPATCH_IDLE, Ordering::Release);
            (
                ActionExecutionResult::FailedKnown(format!(
                    "audit: dispatch intent could not be recorded: {audit_error:?}"
                )),
                None,
                Some(KnownFailureReason::NotDispatched),
            )
        } else if self.runtime_safety.is_some()
            && self
                .admit_runtime_action(session_id, fence, executor)
                .is_err()
        {
            executor
                .approved_dispatch_phase
                .store(APPROVED_DISPATCH_IDLE, Ordering::Release);
            (
                ActionExecutionResult::FailedKnown(
                    "runtime_safety_unavailable_or_denied".to_owned(),
                ),
                None,
                Some(KnownFailureReason::NotDispatched),
            )
        } else if let Some(admission) = policy_admission.as_ref() {
            let (outcome, publication) = self.execute_typed_policy_action(
                admission,
                approval_request
                    .as_ref()
                    .map(|(request, _, _)| request.as_ref()),
                &action_id,
                &requester_principal_id,
                &payload,
                execution_deadline,
                executor,
            );
            checkpoint_publication = publication;
            let known = match &outcome {
                ActionExecutionResult::FailedKnown(reason) if reason == "action_timeout" => {
                    Some(KnownFailureReason::ExecutionTimedOut)
                }
                ActionExecutionResult::FailedKnown(_) => Some(KnownFailureReason::PolicyDenied),
                _ => None,
            };
            (outcome, None, known)
        } else if let Some((request, feature, requester_principal_id)) = approval_request {
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
                        self.driver.execute_approved_action_until(
                            session_id,
                            page_id,
                            &payload,
                            &proposal,
                            &live,
                            execution_deadline,
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
                                    let authorization = request.authorize_and_dispatch_with_clock(
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
                                                || snapshot.lifecycle != SessionLifecycle::Ready
                                                || snapshot.execution
                                                    != SessionExecution::Running(action_id.clone())
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
                                        executor
                                            .approved_dispatch_phase
                                            .store(APPROVED_DISPATCH_STARTED, Ordering::Release);
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
                    let dispatch_phase = executor.approved_dispatch_phase.load(Ordering::Acquire);
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
                        Err(ApprovedActionError::DeadlineBeforeDispatch) => (
                            ActionExecutionResult::FailedKnown("action_timeout".to_owned()),
                            None,
                            Some(KnownFailureReason::ExecutionTimedOut),
                        ),
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
            let capture = command
                .as_ref()
                .and_then(|command| command.capture_command());
            let outcome = if is_evaluate {
                match page_id.as_ref() {
                    Some(page) => self.execute_privileged_evaluate(
                        session_id,
                        page,
                        fence,
                        &action_id,
                        &requester_principal_id,
                        &payload,
                        execution_deadline,
                        executor,
                    ),
                    None => ActionExecutionResult::FailedKnown("page_required".to_owned()),
                }
            } else if let Some(WorkerActionCommand::SetFiles {
                node_ref,
                artifact_ids,
            }) = command.as_ref()
            {
                match page_id.as_ref() {
                    Some(page) => self.execute_file_attachments(
                        session_id,
                        page,
                        fence,
                        node_ref,
                        artifact_ids,
                        execution_deadline,
                        executor,
                    ),
                    None => ActionExecutionResult::FailedKnown("files_rejected".to_owned()),
                }
            } else if let Some(WorkerActionCommand::FillSecret {
                node_ref,
                secret_ref,
            }) = command.as_ref()
            {
                match page_id.as_ref() {
                    Some(page) => self.execute_secret_fill(
                        session_id,
                        page,
                        fence,
                        node_ref,
                        secret_ref,
                        &action_id,
                        &requester_principal_id,
                        execution_deadline,
                        executor,
                    ),
                    None => ActionExecutionResult::FailedKnown("secret_rejected".to_owned()),
                }
            } else if let Some(WorkerActionCommand::Checkpoint { origins }) = command.as_ref() {
                let (outcome, publication) = self.execute_checkpoint(
                    session_id,
                    fence,
                    origins,
                    &action_id,
                    &requester_principal_id,
                    execution_deadline,
                    executor,
                    None,
                );
                checkpoint_publication = publication;
                outcome
            } else if let Some(capture) = capture {
                match page_id
                    .as_ref()
                    .ok_or(WorkerError::InvalidConfiguration)
                    .and_then(|page| {
                        self.execute_capture(
                            session_id,
                            page,
                            fence,
                            capture,
                            &action_id,
                            execution_deadline,
                            executor,
                            None,
                        )
                    }) {
                    Ok(result) => ActionExecutionResult::Succeeded(result),
                    Err(_) => ActionExecutionResult::FailedKnown(
                        "capture_rejected_or_artifact_failed".to_owned(),
                    ),
                }
            } else if self.runtime_safety.is_some() {
                ActionExecutionResult::FailedKnown(
                    "runtime_safety_typed_action_required".to_owned(),
                )
            } else {
                self.driver.execute_action_until(
                    session_id,
                    page_id.as_ref(),
                    &payload,
                    execution_deadline,
                )
            };
            let known_failure_reason = matches!(
                &outcome,
                ActionExecutionResult::FailedKnown(reason)
                    if reason == "action_timeout" || reason == "navigation_timeout"
            )
            .then_some(KnownFailureReason::ExecutionTimedOut);
            (outcome, None, known_failure_reason)
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
        let result_budget = session
            .action_ledger
            .snapshot(fence.as_placement_fence(), &action_id)
            .map_err(map_action_ledger_error)?
            .request()
            .result_budget();
        if matches!(&outcome, ActionExecutionResult::Succeeded(bytes) if bytes.len() > result_budget.max_bytes())
        {
            outcome = if result_budget == browserd_actions::ActionResultBudget::Snapshot {
                ActionExecutionResult::FailedKnown("snapshot_too_large".to_owned())
            } else {
                ActionExecutionResult::OutcomeUnknown
            };
        }
        if let ActionExecutionResult::FailedKnown(reason) = &outcome {
            known_failure_reason = match reason.as_str() {
                "snapshot_too_large" => Some(KnownFailureReason::SnapshotTooLarge),
                "document_changed" => Some(KnownFailureReason::DocumentChanged),
                _ => known_failure_reason,
            };
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
                let _ = transition_session_machine(&mut session, |machine| {
                    machine.mark_action_outcome_unknown(fence, &action_id, completion_now)
                });
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
        install_session_machine(&mut session, completed_machine)?;
        match outcome {
            ActionExecutionResult::Succeeded(result) => {
                let action = session
                    .actions
                    .get_mut(&action_id)
                    .ok_or(WorkerError::ActionNotFound)?;
                action.snapshot.status = ActionStatus::Succeeded;
                action.snapshot.result = Some(result);
            }
            ActionExecutionResult::FailedKnown(_) => {
                let action = session
                    .actions
                    .get_mut(&action_id)
                    .ok_or(WorkerError::ActionNotFound)?;
                action.snapshot.status = ActionStatus::FailedKnown;
                action.snapshot.result = None;
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
        if snapshot.status == ActionStatus::Succeeded
            && let Some(publication) = &mut checkpoint_publication
        {
            publication.commit();
        }
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
                .map(|action| {
                    (
                        action.snapshot.status,
                        action.approval_id.is_some()
                            || action.policy_admission.is_some()
                            || matches!(
                                serde_json::from_slice::<WorkerActionCommand>(&action.payload),
                                Ok(WorkerActionCommand::FillSecret { .. }
                                    | WorkerActionCommand::Evaluate { .. })
                            ),
                    )
                })
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
                install_session_machine(&mut session, next_machine)?;
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
                    let _ = transition_session_machine(&mut session, |machine| {
                        machine.mark_action_outcome_unknown(fence, action_id, completion_now)
                    });
                    if let Some(action) = session.actions.get_mut(action_id) {
                        action.snapshot.status = ActionStatus::OutcomeUnknown;
                    }
                    return Err(map_action_ledger_error(error));
                }
                install_session_machine(&mut session, completed_machine)?;
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
        install_session_machine(&mut session, next_machine)?;
        let action = session
            .actions
            .get_mut(action_id)
            .ok_or(WorkerError::ActionNotFound)?;
        action.snapshot.resolution = Some(durable_annotation);
        Ok(action.snapshot.clone())
    }

    #[allow(clippy::too_many_arguments)]
    fn execute_capture(
        &self,
        session_id: &SessionId,
        page_id: &PageId,
        fence: &OwnershipFence,
        command: browserd_features::CaptureCommand,
        action_id: &ActionId,
        deadline: Instant,
        executor: &SessionExecutor,
        typed: Option<(
            &action_approval::TypedActionAdmission,
            Option<&ApprovalRequest>,
        )>,
    ) -> Result<Vec<u8>, WorkerError> {
        if !command.validate() || Instant::now() >= deadline {
            return Err(WorkerError::InvalidConfiguration);
        }
        let _admission = self
            .capture_admission
            .acquire(command.admission_class())
            .map_err(|_| WorkerError::CapacityExceeded)?;
        let _cleanup_owner = executor
            .cleanup_owner
            .lock()
            .map_err(|_| WorkerError::StateUnavailable)?;
        let maximum = command
            .maximum_bytes()
            .min(self.config.artifact_limits.max_file_bytes)
            .min(self.config.artifact_limits.max_in_flight_bytes);
        let (key, request) = {
            let mut session = executor
                .state
                .lock()
                .map_err(|_| WorkerError::StateUnavailable)?;
            validate_fence(&session, fence)?;
            let reserved = session
                .artifact_reserved_bytes
                .checked_add(maximum)
                .ok_or(WorkerError::CapacityExceeded)?;
            let total = reserved
                .checked_add(session.artifact_committed_bytes)
                .ok_or(WorkerError::CapacityExceeded)?;
            if reserved > self.config.artifact_limits.max_in_flight_bytes
                || total > self.config.artifact_limits.max_committed_bytes
            {
                return Err(WorkerError::CapacityExceeded);
            }
            let key = ArtifactKey::new(
                session.tenant_id.clone(),
                session_id.clone(),
                ArtifactId::new(),
            );
            let request = GeneratedArtifactRequest::new(
                key.clone(),
                fence.clone(),
                command.content_type(),
                "browserd-capture",
                maximum,
            )?;
            session.artifact_reserved_bytes = reserved;
            (key, request)
        };
        let expected_content_type = request.content_type().to_owned();
        let store: Arc<dyn SandboxClient> = self.sandbox.clone();
        let mut captured = if let Some((admission, approval)) = typed {
            action_approval::begin_typed_driver(executor)
                .and_then(|()| {
                    self.driver.execute_typed_capture_until(
                        &admission.observation,
                        command,
                        request,
                        store,
                        deadline,
                        &mut |observed| {
                            self.admit_typed_effect(
                                admission, approval, observed, action_id, deadline, executor,
                            )
                        },
                    )
                })
                .map_err(|_| DependencyError::Rejected)
        } else {
            self.driver
                .execute_capture_until(session_id, page_id, command, request, store, deadline)
        };
        let mut attempted_publication = None;
        let finalized = (|| {
            let capture = captured
                .as_mut()
                .map_err(|_| WorkerError::DependencyUnavailable)?;
            if capture.result.len() > 64 * 1024 {
                return Err(WorkerError::DependencyUnavailable);
            }
            let mut session = executor
                .state
                .lock()
                .map_err(|_| WorkerError::StateUnavailable)?;
            validate_fence(&session, fence)?;
            if session.machine.snapshot().lifecycle != SessionLifecycle::Ready
                || session.machine.snapshot().execution
                    != SessionExecution::Running(action_id.clone())
                || session
                    .actions
                    .get(action_id)
                    .is_none_or(|action| action.snapshot.status != ActionStatus::Running)
                || Instant::now() >= deadline
            {
                return Err(WorkerError::DependencyUnavailable);
            }
            if let Some(receipt) = &capture.receipt {
                if receipt.key() != &key
                    || receipt.source() != ArtifactContentSource::Generated
                    || receipt.scan_attestation().is_some()
                    || receipt.scan_verdict().is_some()
                    || receipt.size_bytes() == 0
                    || receipt.size_bytes() > maximum
                    || receipt.detected_content_type() != expected_content_type
                    || capture.cleanup.is_none()
                    || receipt
                        .object_generation()
                        .as_bytes()
                        .iter()
                        .all(|byte| *byte == 0)
                {
                    return Err(WorkerError::DependencyUnavailable);
                }
                let metadata = ArtifactContentMetadata::new(
                    receipt.size_bytes(),
                    *receipt.checksum(),
                    receipt.detected_content_type(),
                    ArtifactContentSource::Generated,
                    "browserd-capture",
                )
                .map_err(|_| WorkerError::DependencyUnavailable)?;
                let mut artifact = Artifact::new_generated(key.clone());
                artifact
                    .apply_materialized(ArtifactEvent::GenerationCompleted, metadata.clone())
                    .and_then(|_| artifact.apply(ArtifactEvent::FinalizationSucceeded))
                    .map_err(|_| WorkerError::DependencyUnavailable)?;
                let committed = session
                    .artifact_committed_bytes
                    .checked_add(receipt.size_bytes())
                    .ok_or(WorkerError::CapacityExceeded)?;
                let publication = self.new_artifact_publication(
                    key.clone(),
                    fence.clone(),
                    metadata,
                    receipt.object_generation(),
                    None,
                    None,
                    None,
                )?;
                attempted_publication = Some(publication.clone());
                self.publish_authorized_artifact(&publication)?;
                session.artifacts.insert(
                    key.artifact_id().clone(),
                    ArtifactRecord {
                        publication: Some(publication),
                        artifact,
                        object_generation: receipt.object_generation(),
                        display_filename: None,
                    },
                );
                session.artifact_committed_bytes = committed;
            } else if capture.cleanup.is_some() {
                return Err(WorkerError::DependencyUnavailable);
            }
            Ok(std::mem::take(&mut capture.result))
        })();
        let mut release_reservation = finalized.is_ok() || captured.is_err();
        if finalized.is_err() {
            let withdrawal_confirmed = attempted_publication
                .as_ref()
                .is_none_or(|publication| self.sandbox.withdraw_artifact(publication).is_ok());
            if withdrawal_confirmed && let Ok(capture) = &mut captured {
                if let Some(mut sink) = capture.cleanup.take() {
                    if let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                    {
                        release_reservation = matches!(
                            runtime.block_on(async {
                                tokio::time::timeout(Duration::from_secs(2), sink.abort()).await
                            }),
                            Ok(Ok(()))
                        );
                    }
                } else {
                    release_reservation = true;
                }
            }
        }
        let mut session = executor
            .state
            .lock()
            .map_err(|_| WorkerError::StateUnavailable)?;
        if release_reservation {
            session.artifact_reserved_bytes =
                session.artifact_reserved_bytes.saturating_sub(maximum);
        } else {
            session.durability_degraded = true;
        }
        finalized
    }

    pub fn upload_artifact(
        &self,
        peer: &AuthenticatedPeer,
        session_id: &SessionId,
        fence: &OwnershipFence,
        upload: ArtifactUpload,
        now: SessionTime,
    ) -> Result<ArtifactId, WorkerError> {
        self.upload_artifact_with_name(peer, session_id, fence, upload, None, now)
    }

    pub fn upload_artifact_named(
        &self,
        peer: &AuthenticatedPeer,
        session_id: &SessionId,
        fence: &OwnershipFence,
        upload: ArtifactUpload,
        display_filename: String,
        now: SessionTime,
    ) -> Result<ArtifactId, WorkerError> {
        if !valid_artifact_display_filename(&display_filename) {
            return Err(WorkerError::InvalidConfiguration);
        }
        self.upload_artifact_with_name(peer, session_id, fence, upload, Some(display_filename), now)
    }

    fn upload_artifact_with_name(
        &self,
        peer: &AuthenticatedPeer,
        session_id: &SessionId,
        fence: &OwnershipFence,
        upload: ArtifactUpload,
        display_filename: Option<String>,
        now: SessionTime,
    ) -> Result<ArtifactId, WorkerError> {
        self.authorize(peer)?;
        let executor = self.session(session_id)?;
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
            let projected_reserved = session
                .artifact_reserved_bytes
                .checked_add(size_bytes)
                .ok_or(WorkerError::CapacityExceeded)?;
            let projected_total = session
                .artifact_committed_bytes
                .checked_add(projected_reserved)
                .ok_or(WorkerError::CapacityExceeded)?;
            if projected_reserved > self.config.artifact_limits.max_in_flight_bytes
                || projected_total > self.config.artifact_limits.max_committed_bytes
            {
                return Err(WorkerError::CapacityExceeded);
            }
            session
                .machine
                .record_activity(fence, now)
                .map_err(map_session_error)?;
            session.artifact_reserved_bytes = projected_reserved;
            session.tenant_id.clone()
        };
        let mut stored_receipt = None;
        let mut attempted_publication = None;
        let mut store_uncertain = false;
        let result = (|| {
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
            let artifact_id = ArtifactId::new();
            let request = ArtifactStoreRequest::new(
                tenant_id,
                session_id.clone(),
                artifact_id.clone(),
                fence.clone(),
                upload.bytes,
                upload.content_type,
                self.config.artifact_limits.max_file_bytes,
            )?;
            let key = request.key().clone();
            let receipt = self.sandbox.store_artifact(&request).map_err(|error| {
                store_uncertain = error == DependencyError::OutcomeUncertain;
                WorkerError::DependencyUnavailable
            })?;
            if receipt.key() == &key {
                stored_receipt = Some(receipt.clone());
            } else {
                store_uncertain = true;
            }
            if receipt.key() != &key
                || receipt.source() != ArtifactContentSource::ClientUpload
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
            if receipt.scan_verdict() == Some(ArtifactScanVerdict::Clean) {
                let evidence = receipt
                    .scan_attestation()
                    .ok_or(WorkerError::DependencyUnavailable)?;
                evidence
                    .validate_for(&key, fence, &metadata, receipt.object_generation())
                    .and_then(|()| evidence.validate_at(self.clock.now()?.get()))
                    .map_err(|_| WorkerError::DependencyUnavailable)?;
            }
            let mut artifact = Artifact::new_upload(key.clone());
            artifact
                .apply_materialized(ArtifactEvent::UploadStored, metadata.clone())
                .and_then(|_| artifact.apply(ArtifactEvent::ScanStarted))
                .and_then(|_| {
                    artifact.apply(match receipt.scan_verdict() {
                        Some(ArtifactScanVerdict::Clean) => ArtifactEvent::ScanPassed,
                        Some(ArtifactScanVerdict::Quarantined) => ArtifactEvent::ScanQuarantined,
                        Some(ArtifactScanVerdict::Rejected) => ArtifactEvent::ScanRejected,
                        None => {
                            return Err(browserd_artifacts::ArtifactError::MetadataSourceMismatch);
                        }
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
                .ok_or(WorkerError::StateUnavailable)?;
            let remaining_reserved = session
                .artifact_reserved_bytes
                .checked_sub(size_bytes)
                .ok_or(WorkerError::StateUnavailable)?;
            if session.machine.snapshot().lifecycle != SessionLifecycle::Ready {
                return Err(WorkerError::DependencyUnavailable);
            }
            if artifact.state() == ArtifactState::Available {
                let publication = self.new_artifact_publication(
                    key,
                    fence.clone(),
                    metadata,
                    receipt.object_generation(),
                    receipt.scan_verdict(),
                    display_filename.clone(),
                    receipt.scan_attestation().cloned(),
                )?;
                attempted_publication = Some(publication.clone());
                self.publish_authorized_artifact(&publication)?;
            }
            session.artifact_reserved_bytes = remaining_reserved;
            session.artifact_committed_bytes = projected_committed;
            session.artifacts.insert(
                artifact_id.clone(),
                ArtifactRecord {
                    publication: attempted_publication.clone(),
                    artifact,
                    object_generation: receipt.object_generation(),
                    display_filename,
                },
            );
            Ok(artifact_id)
        })();
        if result.is_err() {
            let withdrawal_confirmed = attempted_publication
                .as_ref()
                .is_none_or(|publication| self.sandbox.withdraw_artifact(publication).is_ok());
            let cleanup_confirmed = withdrawal_confirmed
                && !store_uncertain
                && stored_receipt
                    .as_ref()
                    .is_none_or(|receipt| self.sandbox.discard_artifact(receipt, fence).is_ok());
            let mut session = match executor.state.lock() {
                Ok(session) => session,
                Err(poisoned) => poisoned.into_inner(),
            };
            if cleanup_confirmed {
                session.artifact_reserved_bytes =
                    session.artifact_reserved_bytes.saturating_sub(size_bytes);
            } else {
                session.durability_degraded = true;
            }
        }
        result
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
        self.validate_artifact_record_publication(artifact, fence)?;
        let metadata = artifact
            .artifact
            .content_metadata()
            .ok_or(WorkerError::StateUnavailable)?;
        Ok(WorkerArtifactSnapshot {
            display_filename: artifact.display_filename.clone(),
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

    pub fn open_artifact(
        &self,
        peer: &AuthenticatedPeer,
        session_id: &SessionId,
        artifact_id: &ArtifactId,
        fence: &OwnershipFence,
        max_chunk_bytes: usize,
    ) -> Result<Box<dyn ArtifactReadStream>, WorkerError> {
        self.authorize(peer)?;
        let executor = self.session(session_id)?;
        let (request, publication) = {
            let session = executor
                .state
                .lock()
                .map_err(|_| WorkerError::StateUnavailable)?;
            validate_fence(&session, fence)?;
            if session.machine.snapshot().lifecycle != SessionLifecycle::Ready {
                return Err(WorkerError::DependencyUnavailable);
            }
            let record = session
                .artifacts
                .get(artifact_id)
                .ok_or(WorkerError::ArtifactNotFound)?;
            if record.artifact.state() != ArtifactState::Available {
                return Err(WorkerError::DependencyUnavailable);
            }
            self.validate_artifact_record_publication(record, fence)?;
            let publication = record
                .publication
                .clone()
                .ok_or(WorkerError::ArtifactNotFound)?;
            let request = ArtifactReadRequest::new(
                record.artifact.key().clone(),
                fence.clone(),
                record
                    .artifact
                    .content_metadata()
                    .cloned()
                    .ok_or(WorkerError::StateUnavailable)?,
                record.object_generation,
                max_chunk_bytes,
            )?;
            (request, publication)
        };
        // Storage verification can perform I/O; never hold the session mutex across it.
        let reader = self
            .sandbox
            .open_artifact(&request)
            .map_err(|_| WorkerError::DependencyUnavailable)?;
        self.get_session(peer, session_id, fence)?;
        Ok(self.expiring_artifact_reader(reader, &publication))
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
        self.expire_action_approvals(&mut session, fence, decision_now)?;
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
        if proposal.typed_binding().is_some() {
            self.audit_approval_event(
                match decision {
                    ApprovalDecision::Approve => "approve",
                    ApprovalDecision::Deny => "deny",
                },
                &proposal,
                Some(&principal_id),
                serde_json::json!({}),
            )?;
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
        install_session_machine(&mut session, next_machine)?;
        let approval = session
            .approvals
            .get_mut(approval_id)
            .ok_or(WorkerError::ApprovalNotFound)?;
        approval.state = state.clone();
        approval.request = Some(Arc::clone(&request));
        Ok(worker_approval_snapshot(approval_id, approval))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn decide_approval_and_run_ready_actions(
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
        let _owner = ActionOwner::claim(&executor.action_owner)?;
        let snapshot = self.decide_approval(
            peer,
            session_id,
            approval_id,
            fence,
            decision,
            principal_id,
            now,
        )?;
        while self
            .run_next_action_owned(session_id, fence, now, &executor)?
            .is_some()
        {}
        Ok(snapshot)
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
        // Backend renewal can wait behind exact native ownership operations.
        // Renew local leases from its completion, preserving caller/session monotonicity.
        let now = now.max(self.clock.now()?);
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
                let renewal_now = now.max(session.machine.last_observed_at());
                match session.machine.renew_lease(&fence, renewal_now) {
                    Ok(_) | Err(SessionError::SessionDeadlineElapsed { .. }) => {}
                    Err(error) => return Err(map_session_error(error)),
                }
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
        let viewer_cleanup_failed = self.expire_viewers(peer, now).is_err();
        let checkpoint_cleanup_failed = self.cleanup_expired_checkpoints(now).is_err();
        let worker = self.lock_worker()?;
        let sessions = worker.sessions.values().cloned().collect::<Vec<_>>();
        drop(worker);
        let mut expired = 0usize;
        let mut ownership_lost = false;
        let mut cleanup_failed = viewer_cleanup_failed;
        let mut durability_failed = checkpoint_cleanup_failed;
        'sessions: for executor in sessions {
            {
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
                let snapshot = session.machine.snapshot();
                let observed_now = now.max(session.machine.last_observed_at());
                let due = [
                    snapshot.lease_expires_at,
                    snapshot.session_expires_at,
                    snapshot.idle_expires_at,
                ]
                .into_iter()
                .flatten()
                .any(|deadline| observed_now >= deadline);
                if !due {
                    // Approval expiry does not need the artifact cleanup guard.
                    if self
                        .expire_action_approvals(&mut session, &snapshot.owner_fence, observed_now)
                        .is_err()
                    {
                        durability_failed = true;
                    }
                    if !matches!(
                        session
                            .machine
                            .expire_due(&snapshot.owner_fence, observed_now)
                            .map_err(map_session_error)?,
                        ExpireDecision::NotDue { .. }
                    ) {
                        return Err(WorkerError::StateUnavailable);
                    }
                    continue;
                }
            }
            let _cleanup_owner = executor
                .cleanup_owner
                .lock()
                .map_err(|_| WorkerError::StateUnavailable)?;
            let (mut session, approved_dispatch_phase, expiration_due, now) = loop {
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
                let observed_now = now.max(session.machine.last_observed_at());
                let expiration_due = [
                    snapshot.lease_expires_at,
                    snapshot.session_expires_at,
                    snapshot.idle_expires_at,
                ]
                .into_iter()
                .flatten()
                .any(|deadline| observed_now >= deadline);
                if !expiration_due {
                    break (
                        session,
                        executor.approved_dispatch_phase.load(Ordering::Acquire),
                        false,
                        observed_now,
                    );
                }
                match executor.approved_dispatch_phase.load(Ordering::Acquire) {
                    APPROVED_DISPATCH_INSPECTING
                    | APPROVED_DISPATCH_DRIVER_PENDING
                    | APPROVED_DISPATCH_AUTHORIZING => {
                        drop(session);
                        stop_or_observe_approved_dispatch(&executor);
                    }
                    phase => break (session, phase, true, observed_now),
                }
            };
            let fence = session.machine.snapshot().owner_fence;
            if self
                .expire_action_approvals(&mut session, &fence, now)
                .is_err()
            {
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
            match transition_session_machine(&mut session, |machine| {
                machine.expire_due(&fence, now)
            })? {
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
                    install_session_machine(&mut session, cleanup_machine)?;
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
        drop(worker);
        // Reclaim fully-closed sessions past their retention watermark on the same maintenance
        // cadence, so retained memory and the next scan stay bounded under churn (BRD-018).
        self.reclaim_retired(now);
        if cleanup_failed {
            Err(WorkerError::CleanupFailed)
        } else if durability_failed {
            Err(WorkerError::DurabilityUnavailable)
        } else {
            Ok(expired)
        }
    }

    /// Drop the in-memory state of fully-closed sessions once their retention watermark has passed,
    /// keeping retained memory and the maintenance scan bounded under session churn (BRD-018).
    ///
    /// A session becomes eligible only when its lifecycle is terminal (`Closed`/`Failed`) and its
    /// cleanup receipt is in (`!occupies_capacity`). The first eligible pass stamps a watermark of
    /// `now + session_retention`; the entry is dropped only once the clock reaches it, so a closed
    /// session stays queryable for the retention window and a late in-flight caller keeps its own
    /// `Arc` alive until done. Unresolved-action evidence is preserved by the durable action
    /// authority, not this in-memory copy, so dropping the entry never loses it. Returns the number
    /// of sessions reclaimed.
    pub fn reclaim_retired_sessions(
        &self,
        peer: &AuthenticatedPeer,
        now: SessionTime,
    ) -> Result<usize, WorkerError> {
        self.authorize(peer)?;
        Ok(self.reclaim_retired(now))
    }

    fn reclaim_retired(&self, now: SessionTime) -> usize {
        // Bound the per-create maps alongside session reclamation. Pruning the idempotency registry
        // is behavior-neutral (claim already treats an elapsed entry as absent); the returned
        // operation ids are exactly those whose create-operation result can be dropped too, since a
        // later claim for that key mints a new operation and never revisits them.
        let pruned_operations = self
            .create_idempotency
            .prune(Instant::now())
            .unwrap_or_default();

        let retention_millis =
            u64::try_from(self.config.session_retention.as_millis()).unwrap_or(u64::MAX);
        let Ok(mut worker) = self.lock_worker() else {
            return 0;
        };
        if self.config.admission_policy.is_some()
            && self
                .refresh_admissions(&mut worker, Instant::now())
                .is_err()
        {
            return 0;
        }
        let candidates = worker
            .sessions
            .iter()
            .map(|(session_id, executor)| (session_id.clone(), Arc::clone(executor)))
            .collect::<Vec<_>>();
        drop(worker);

        let mut reclaimable = Vec::new();
        for (session_id, executor) in candidates {
            if self.action_journal_pool.is_some()
                && !self.seal_idle_action_journal(&executor).unwrap_or(false)
            {
                continue;
            }
            let Ok(mut session) = executor.state.lock() else {
                continue;
            };
            let terminal = matches!(
                session.machine.lifecycle(),
                SessionLifecycle::Closed | SessionLifecycle::Failed
            ) && !session.occupies_capacity
                && session.pending_download_rollbacks.is_empty();
            if !terminal {
                // Not eligible (still active, or cleanup receipt not yet in): reset any watermark.
                session.reclaim_at = None;
                continue;
            }
            match session.reclaim_at {
                None => {
                    session.reclaim_at =
                        Some(SessionTime::new(now.get().saturating_add(retention_millis)));
                }
                Some(reclaim_at) if now >= reclaim_at => reclaimable.push(session_id),
                Some(_) => {}
            }
        }

        if reclaimable.is_empty() && pruned_operations.is_empty() {
            return 0;
        }
        let Ok(mut worker) = self.lock_worker() else {
            return 0;
        };
        // Drop the create-operation results whose idempotency entries just elapsed, bounding that
        // map the same way (a fresh claim never revisits a pruned operation id).
        for operation_id in pruned_operations {
            worker.create_operations.remove(&operation_id);
        }
        let mut reclaimed = 0usize;
        for session_id in reclaimable {
            // Re-verify under the worker lock that the entry is still the terminal one we observed;
            // a terminal lifecycle never reverts, so a present entry is safe to drop.
            if let Some(executor) = worker.sessions.get(&session_id) {
                let still_terminal = executor.state.lock().is_ok_and(|session| {
                    matches!(
                        session.machine.lifecycle(),
                        SessionLifecycle::Closed | SessionLifecycle::Failed
                    ) && !session.occupies_capacity
                        && session.pending_download_rollbacks.is_empty()
                });
                if still_terminal {
                    worker.sessions.remove(&session_id);
                    reclaimed = reclaimed.saturating_add(1);
                }
            }
        }
        reclaimed
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
            let _ = self.seal_idle_action_journal(&executor);
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
        let _ = transition_session_machine(session, |machine| {
            machine.mark_action_outcome_unknown(fence, &action_id, completion_now)
        });
        if let Some(action) = session.actions.get_mut(&action_id) {
            action.snapshot.status = ActionStatus::OutcomeUnknown;
        }
        return Err(error);
    }
    install_session_machine(session, completed_machine)?;
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
        ActionLedgerError::IdempotencyConflict { .. }
        | ActionLedgerError::ActionIdentityConflict { .. } => WorkerError::IdempotencyConflict,
        ActionLedgerError::ActionSequenceConflict { .. } => WorkerError::InvalidActionTransition,
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
            .and_then(|receipt| {
                artifact_scan_evidence::attest_test_receipt(receipt, request.fence(), 0)
            })
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
