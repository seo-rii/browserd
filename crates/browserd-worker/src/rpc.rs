use std::collections::{BTreeMap, HashMap};
use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::mpsc as std_mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use browserd_actions::{
    ActionKind, ActionSequence, ActionSnapshot, ActionSnapshotFacts,
    ApprovalDecision as ActionApprovalDecision, CanonicalRequestHash as ActionCanonicalRequestHash,
    IdempotencyKey as ActionIdempotencyKey, KnownFailureReason, ResolutionAnnotation,
    ResolutionKind, TerminalDetail,
};
use browserd_artifacts::{ArtifactContentSource, ArtifactState};
use browserd_core::{
    ActionId, ApprovalId, ArtifactId, LeaseId, OperationId, PageId, PrincipalId, SessionId,
    TenantId, WorkerId,
};
use browserd_operations::CanonicalRequestHash as CreateCanonicalRequestHash;
use browserd_policy::{
    ActionArgumentsHash, ActionType, ApprovalDecision, ApprovalState, CanonicalActionProposal,
    CredentialRefsHash, NodeReference, Origin,
};
use browserd_session::{OwnershipFence, SessionLifecycle, SessionTime};
use nix::fcntl::{Flock, FlockArg, OFlag, open};
use nix::sys::stat::{Mode, SFlag, fchmod, fstat};
use nix::unistd::Uid;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::{
    ActionApprovalRequirement, ActionStatus, ArtifactUpload, AuthenticatedPeer, ChromiumDriver,
    CreateSessionCommand, SandboxClient, WorkerActionSnapshot, WorkerApprovalSnapshot,
    WorkerArtifactSnapshot, WorkerControlPlane, WorkerError, WorkerPageSnapshot,
};

pub const WORKER_RPC_PROTOCOL_VERSION: u16 = 10;
pub const WORKER_SESSION_OPTIONS_VERSION: u16 = 1;

const MAX_WORKER_ACTION_URL_BYTES: usize = 8 * 1024;
const MAX_WORKER_ACTION_TEXT_BYTES: usize = 16 * 1024;
const MAX_WORKER_POINTER_COORDINATE: u64 = 1_000_000;
const MAX_WORKER_KEY_BYTES: usize = 64;
const MAX_WORKER_SCROLL_DELTA: u64 = 1_000_000;
const MAX_WORKER_ACTION_EXECUTION_TIMEOUT_MS: u64 = 300_000;
const MAX_SESSION_VIEWPORT_PIXELS: u64 = 67_108_864;
const MAX_SESSION_METADATA_ENTRIES: usize = 64;
const MAX_SESSION_METADATA_KEY_BYTES: usize = 128;
const MAX_SESSION_METADATA_VALUE_BYTES: usize = 4 * 1024;
const MAX_SESSION_METADATA_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct WorkerActionExecutionTimeout(u64);

impl WorkerActionExecutionTimeout {
    pub const DEFAULT: Self = Self(30_000);

    #[must_use]
    pub const fn new(milliseconds: u64) -> Option<Self> {
        if milliseconds == 0 || milliseconds > MAX_WORKER_ACTION_EXECUTION_TIMEOUT_MS {
            None
        } else {
            Some(Self(milliseconds))
        }
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    #[must_use]
    pub const fn duration(self) -> Duration {
        Duration::from_millis(self.0)
    }
}

impl<'de> Deserialize<'de> for WorkerActionExecutionTimeout {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let milliseconds = u64::deserialize(deserializer)?;
        Self::new(milliseconds)
            .ok_or_else(|| serde::de::Error::custom("invalid action execution timeout"))
    }
}

/// Main-frame document lifecycle a navigate action observes before it completes.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerNavigateWaitUntil {
    Domcontentloaded,
    Load,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkerActionCommand {
    Navigate {
        url: String,
        wait_until: WorkerNavigateWaitUntil,
    },
    Reload,
    GoBack,
    GoForward,
    Click {
        x: i64,
        y: i64,
    },
    TypeText {
        text: String,
    },
    PressKey {
        key: String,
    },
    Scroll {
        delta_x: i64,
        delta_y: i64,
    },
    GetUrl,
    GetTitle,
}

impl WorkerActionCommand {
    #[must_use]
    pub fn is_valid(&self) -> bool {
        match self {
            Self::Navigate { url, .. } => {
                !url.is_empty()
                    && url.len() <= MAX_WORKER_ACTION_URL_BYTES
                    && !url.chars().any(char::is_control)
                    && (url.starts_with("https://") || url.starts_with("http://"))
            }
            Self::Click { x, y } => {
                x.unsigned_abs() <= MAX_WORKER_POINTER_COORDINATE
                    && y.unsigned_abs() <= MAX_WORKER_POINTER_COORDINATE
            }
            Self::TypeText { text } => {
                !text.is_empty() && text.len() <= MAX_WORKER_ACTION_TEXT_BYTES
            }
            Self::PressKey { key } => {
                !key.is_empty()
                    && key.len() <= MAX_WORKER_KEY_BYTES
                    && !key.chars().any(char::is_control)
            }
            Self::Scroll { delta_x, delta_y } => {
                delta_x.unsigned_abs() <= MAX_WORKER_SCROLL_DELTA
                    && delta_y.unsigned_abs() <= MAX_WORKER_SCROLL_DELTA
            }
            Self::Reload | Self::GoBack | Self::GoForward | Self::GetUrl | Self::GetTitle => true,
        }
    }

    #[must_use]
    pub const fn kind(&self) -> ActionKind {
        match self {
            Self::GetUrl | Self::GetTitle => ActionKind::ReadOnly,
            Self::Navigate { .. }
            | Self::Reload
            | Self::GoBack
            | Self::GoForward
            | Self::Click { .. }
            | Self::TypeText { .. }
            | Self::PressKey { .. }
            | Self::Scroll { .. } => ActionKind::Mutating,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerIsolationProfile {
    SharedContext,
    TenantDedicatedShard,
    DedicatedProcess,
    DedicatedWorker,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerViewport {
    pub width: u32,
    pub height: u32,
    pub device_scale_factor: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerSessionOptionsV1 {
    pub workload_class_hint: String,
    pub viewport: WorkerViewport,
    pub locale: String,
    pub timezone: String,
    pub user_agent: Option<String>,
    pub network_policy_id: String,
    pub network_class: String,
    pub checkpoint_ref: Option<String>,
    pub dialog_policy: String,
    pub feature_profile: String,
    pub ttl_seconds: u64,
    pub idle_timeout_seconds: u64,
    pub metadata: BTreeMap<String, String>,
}

impl WorkerSessionOptionsV1 {
    #[must_use]
    pub fn is_valid(&self) -> bool {
        let metadata_bytes = self
            .metadata
            .iter()
            .try_fold(0_usize, |total, (key, value)| {
                total.checked_add(key.len())?.checked_add(value.len())
            });
        let viewport_pixels =
            u64::from(self.viewport.width).checked_mul(u64::from(self.viewport.height));
        self.viewport.width != 0
            && self.viewport.height != 0
            && self.viewport.width <= 16_384
            && self.viewport.height <= 16_384
            && viewport_pixels.is_some_and(|pixels| pixels <= MAX_SESSION_VIEWPORT_PIXELS)
            && (1..=8).contains(&self.viewport.device_scale_factor)
            && self.ttl_seconds != 0
            && self.idle_timeout_seconds != 0
            && self.idle_timeout_seconds <= self.ttl_seconds
            && !self.workload_class_hint.trim().is_empty()
            && self.workload_class_hint.len() <= 128
            && !self.workload_class_hint.chars().any(char::is_control)
            && !self.locale.trim().is_empty()
            && self.locale.len() <= 64
            && !self.locale.chars().any(char::is_control)
            && !self.timezone.trim().is_empty()
            && self.timezone.len() <= 128
            && !self.timezone.chars().any(char::is_control)
            && !self.network_policy_id.trim().is_empty()
            && self.network_policy_id.len() <= 256
            && !self.network_policy_id.chars().any(char::is_control)
            && !self.network_class.trim().is_empty()
            && self.network_class.len() <= 64
            && !self.network_class.chars().any(char::is_control)
            && !self.feature_profile.trim().is_empty()
            && self.feature_profile.len() <= 128
            && !self.feature_profile.chars().any(char::is_control)
            && self.user_agent.as_ref().is_none_or(|value| {
                !value.trim().is_empty()
                    && value.len() <= 4_096
                    && !value.chars().any(char::is_control)
            })
            && self.checkpoint_ref.as_ref().is_none_or(|value| {
                !value.trim().is_empty()
                    && value.len() <= 1_024
                    && !value.chars().any(char::is_control)
            })
            && matches!(self.dialog_policy.as_str(), "auto_dismiss" | "hold")
            && self.metadata.len() <= MAX_SESSION_METADATA_ENTRIES
            && self.metadata.keys().all(|key| {
                !key.is_empty()
                    && key.len() <= MAX_SESSION_METADATA_KEY_BYTES
                    && key.trim() == key
                    && !key.chars().any(char::is_control)
            })
            && self.metadata.values().all(|value| {
                value.len() <= MAX_SESSION_METADATA_VALUE_BYTES
                    && !value.chars().any(char::is_control)
            })
            && metadata_bytes.is_some_and(|bytes| bytes <= MAX_SESSION_METADATA_BYTES)
    }

    #[must_use]
    pub fn canonical_request_hash(&self, requested_isolation: WorkerIsolationProfile) -> [u8; 32] {
        let request = serde_json::json!({
            "isolation": requested_isolation,
            "workload_class_hint": self.workload_class_hint,
            "viewport": self.viewport,
            "locale": self.locale,
            "timezone": self.timezone,
            "user_agent": self.user_agent,
            "network_policy_id": self.network_policy_id,
            "network_class": self.network_class,
            "checkpoint_ref": self.checkpoint_ref,
            "dialog_policy": self.dialog_policy,
            "feature_profile": self.feature_profile,
            "ttl_seconds": self.ttl_seconds,
            "idle_timeout_seconds": self.idle_timeout_seconds,
            "metadata": self.metadata,
        });
        *CreateCanonicalRequestHash::from_json(&request).as_bytes()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerSessionFence {
    pub tenant_id: TenantId,
    pub session_id: SessionId,
    pub worker_epoch: u64,
    pub placement_version: u64,
    pub session_incarnation: u64,
}

impl WorkerSessionFence {
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.worker_epoch != 0 && self.placement_version != 0 && self.session_incarnation != 0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerCreateSessionRequest {
    pub operation_id: OperationId,
    pub tenant_id: TenantId,
    pub idempotency_key: String,
    pub canonical_request_hash: [u8; 32],
    pub expected_worker_epoch: u64,
    pub placement_version: u64,
    pub session_incarnation: u64,
    pub requested_isolation: WorkerIsolationProfile,
    pub options_version: u16,
    pub options: WorkerSessionOptionsV1,
    pub now_unix_millis: u64,
}

impl WorkerCreateSessionRequest {
    #[must_use]
    pub fn is_valid(&self) -> bool {
        !self.idempotency_key.is_empty()
            && self.idempotency_key.len() <= 255
            && self.idempotency_key.trim() == self.idempotency_key
            && !self.idempotency_key.chars().any(char::is_control)
            && self.expected_worker_epoch != 0
            && self.placement_version != 0
            && self.session_incarnation != 0
            && self.options_version == WORKER_SESSION_OPTIONS_VERSION
            && self.options.is_valid()
            && self.canonical_request_hash
                == self
                    .options
                    .canonical_request_hash(self.requested_isolation)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerCreateSessionReceipt {
    pub operation_id: OperationId,
    pub tenant_id: TenantId,
    pub session_id: SessionId,
    pub session_incarnation: u64,
    pub effective_isolation: WorkerIsolationProfile,
    pub primary_page_id: PageId,
    pub worker_epoch: u64,
    pub placement_version: u64,
    pub existing: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerProbeReceipt {
    pub worker_id: WorkerId,
    pub worker_epoch: u64,
    pub ready: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerSessionLifecycle {
    Creating,
    Ready,
    Closing,
    Closed,
    Failed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerSessionReceipt {
    pub fence: WorkerSessionFence,
    pub lifecycle: WorkerSessionLifecycle,
    pub primary_page_id: PageId,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerActionStatus {
    PendingApproval,
    Queued,
    Running,
    Succeeded,
    FailedKnown,
    CancelledBeforeDispatch,
    CancelledConfirmed,
    OutcomeUnknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerActionReceipt {
    pub fence: WorkerSessionFence,
    pub action_id: ActionId,
    pub action_sequence: ActionSequence,
    pub idempotency_key: String,
    pub canonical_request_hash: [u8; 32],
    pub kind: ActionKind,
    pub status: WorkerActionStatus,
    pub dispatch_acknowledged: bool,
    pub approval_decision: Option<ActionApprovalDecision>,
    pub terminal_detail: Option<TerminalDetail>,
    pub result: Option<Vec<u8>>,
    pub resolution: Option<ResolutionAnnotation>,
}

impl WorkerActionReceipt {
    pub fn to_action_snapshot(&self) -> Result<ActionSnapshot, WorkerRpcError> {
        let state = match self.status {
            WorkerActionStatus::PendingApproval => browserd_core::ActionState::PendingApproval,
            WorkerActionStatus::Queued => browserd_core::ActionState::ReadyToDispatch,
            WorkerActionStatus::Running => browserd_core::ActionState::MayHaveExecuted,
            WorkerActionStatus::Succeeded => browserd_core::ActionState::Succeeded,
            WorkerActionStatus::FailedKnown => browserd_core::ActionState::FailedKnown,
            WorkerActionStatus::CancelledBeforeDispatch => {
                browserd_core::ActionState::CancelledBeforeDispatch
            }
            WorkerActionStatus::CancelledConfirmed => {
                browserd_core::ActionState::CancelledConfirmed
            }
            WorkerActionStatus::OutcomeUnknown => browserd_core::ActionState::OutcomeUnknown,
        };
        let contradicts_dispatch_acknowledgement = self.dispatch_acknowledged
            && matches!(
                (self.status, self.terminal_detail),
                (
                    WorkerActionStatus::PendingApproval
                        | WorkerActionStatus::Queued
                        | WorkerActionStatus::CancelledBeforeDispatch,
                    _
                ) | (
                    WorkerActionStatus::FailedKnown,
                    Some(TerminalDetail::FailedKnown(
                        KnownFailureReason::NotDispatched
                            | KnownFailureReason::PolicyDenied
                            | KnownFailureReason::ApprovalDenied
                            | KnownFailureReason::ApprovalTimedOut
                    ))
                )
            );
        if contradicts_dispatch_acknowledgement
            || match (self.status, &self.result, self.terminal_detail) {
                (
                    WorkerActionStatus::Succeeded,
                    Some(result),
                    Some(TerminalDetail::Succeeded(expected)),
                ) => {
                    let actual: [u8; 32] = Sha256::digest(result).into();
                    actual != *expected.as_bytes()
                }
                (WorkerActionStatus::Succeeded, _, _) => true,
                (
                    WorkerActionStatus::PendingApproval
                    | WorkerActionStatus::Queued
                    | WorkerActionStatus::Running
                    | WorkerActionStatus::CancelledBeforeDispatch
                    | WorkerActionStatus::CancelledConfirmed
                    | WorkerActionStatus::OutcomeUnknown,
                    Some(_),
                    _,
                ) => true,
                (WorkerActionStatus::FailedKnown, Some(_), _) => true,
                (WorkerActionStatus::FailedKnown, None, _) => false,
                (_, None, _) => false,
            }
        {
            return Err(WorkerRpcError::Protocol);
        }
        ActionSnapshot::from_facts(ActionSnapshotFacts {
            action_id: self.action_id.clone(),
            action_sequence: self.action_sequence,
            idempotency_key: ActionIdempotencyKey::new(self.idempotency_key.clone()),
            canonical_request_hash: ActionCanonicalRequestHash::new(self.canonical_request_hash),
            kind: self.kind,
            state,
            dispatch_acknowledged: self.dispatch_acknowledged,
            approval_decision: self.approval_decision,
            terminal_detail: self.terminal_detail,
            resolution: self.resolution.clone(),
        })
        .map_err(|_| WorkerRpcError::Protocol)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerPageReceipt {
    pub fence: WorkerSessionFence,
    pub page_id: PageId,
    pub active: bool,
    pub target_incarnation: u64,
    pub document_epoch: u64,
    pub url_revision: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerApprovalActionType {
    Click,
    Fill,
    Navigate,
    Evaluate,
    Upload,
    Download,
    Custom(String),
}

impl From<WorkerApprovalActionType> for ActionType {
    fn from(value: WorkerApprovalActionType) -> Self {
        match value {
            WorkerApprovalActionType::Click => Self::Click,
            WorkerApprovalActionType::Fill => Self::Fill,
            WorkerApprovalActionType::Navigate => Self::Navigate,
            WorkerApprovalActionType::Evaluate => Self::Evaluate,
            WorkerApprovalActionType::Upload => Self::Upload,
            WorkerApprovalActionType::Download => Self::Download,
            WorkerApprovalActionType::Custom(value) => Self::Custom(value),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerActionApprovalRequirement {
    pub target_incarnation: u64,
    pub frame_document_epoch: u64,
    pub current_origin: String,
    pub url_revision: u64,
    pub action_type: WorkerApprovalActionType,
    pub node_ref: Option<String>,
    pub credential_refs: Vec<String>,
    pub require_four_eyes: bool,
}

impl WorkerActionApprovalRequirement {
    #[allow(clippy::too_many_arguments)]
    fn into_requirement(
        self,
        tenant_id: TenantId,
        requester_principal_id: PrincipalId,
        session_id: SessionId,
        session_incarnation: u64,
        page_id: PageId,
        payload: &[u8],
        expires_at_unix_millis: u64,
    ) -> Result<ActionApprovalRequirement, WorkerRpcFailure> {
        if self.target_incarnation == 0
            || self.frame_document_epoch == 0
            || self.credential_refs.len() > 128
            || self.credential_refs.iter().any(|credential_ref| {
                credential_ref.is_empty()
                    || credential_ref.len() > 1_024
                    || credential_ref.trim() != credential_ref
                    || credential_ref.chars().any(char::is_control)
            })
        {
            return Err(WorkerRpcFailure::new(
                WorkerRpcFailureCode::InvalidRequest,
                "invalid approval evidence",
            ));
        }
        let origin = Origin::parse(&self.current_origin).map_err(|_| {
            WorkerRpcFailure::new(
                WorkerRpcFailureCode::InvalidRequest,
                "invalid approval origin",
            )
        })?;
        let node_ref = self
            .node_ref
            .map(NodeReference::new)
            .transpose()
            .map_err(|_| {
                WorkerRpcFailure::new(
                    WorkerRpcFailureCode::InvalidRequest,
                    "invalid approval node reference",
                )
            })?;
        let action_type: ActionType = self.action_type.into();
        if matches!(&action_type, ActionType::Custom(value) if value.is_empty() || value.len() > 255 || value.chars().any(char::is_control))
        {
            return Err(WorkerRpcFailure::new(
                WorkerRpcFailureCode::InvalidRequest,
                "invalid approval action type",
            ));
        }
        let credential_refs_hash =
            CredentialRefsHash::digest(self.credential_refs.iter().map(String::as_str));
        Ok(ActionApprovalRequirement::new(
            CanonicalActionProposal::new(
                tenant_id,
                requester_principal_id,
                session_id,
                session_incarnation,
                page_id,
                self.target_incarnation,
                self.frame_document_epoch,
                origin,
                self.url_revision,
                action_type.clone(),
                ActionArgumentsHash::digest(payload),
                node_ref,
                credential_refs_hash,
                expires_at_unix_millis,
            ),
            action_type,
            self.require_four_eyes,
        ))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerArtifactState {
    Uploading,
    Stored,
    Scanning,
    Available,
    Quarantined,
    Rejected,
    Generating,
    Finalizing,
    Failed,
    Deleting,
    Deleted,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerArtifactSource {
    ClientUpload,
    BrowserDownload,
    Generated,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerArtifactReceipt {
    pub fence: WorkerSessionFence,
    pub artifact_id: ArtifactId,
    pub state: WorkerArtifactState,
    pub size_bytes: u64,
    pub checksum_sha256: [u8; 32],
    pub content_type: String,
    pub source: WorkerArtifactSource,
    pub origin: String,
    pub object_generation: [u8; 32],
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerApprovalDecision {
    Approve,
    Deny,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkerApprovalState {
    Pending,
    Approved { by: PrincipalId },
    Denied { by: PrincipalId },
    Expired,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerCanonicalActionProposal {
    pub tenant_id: TenantId,
    pub requester_principal_id: PrincipalId,
    pub session_id: SessionId,
    pub session_incarnation: u64,
    pub page_id: PageId,
    pub target_incarnation: u64,
    pub frame_document_epoch: u64,
    pub current_origin: String,
    pub url_revision: u64,
    pub action_type: WorkerApprovalActionType,
    pub canonical_arguments_hash: [u8; 32],
    pub node_ref: Option<String>,
    pub credential_refs_hash: [u8; 32],
    pub expires_at_unix_millis: u64,
}

impl WorkerCanonicalActionProposal {
    fn from_canonical(proposal: &CanonicalActionProposal) -> Self {
        let action_type = match proposal.action_type() {
            ActionType::Click => WorkerApprovalActionType::Click,
            ActionType::Fill => WorkerApprovalActionType::Fill,
            ActionType::Navigate => WorkerApprovalActionType::Navigate,
            ActionType::Evaluate => WorkerApprovalActionType::Evaluate,
            ActionType::Upload => WorkerApprovalActionType::Upload,
            ActionType::Download => WorkerApprovalActionType::Download,
            ActionType::Custom(value) => WorkerApprovalActionType::Custom(value.clone()),
        };
        Self {
            tenant_id: proposal.tenant_id().clone(),
            requester_principal_id: proposal.requester_principal_id().clone(),
            session_id: proposal.session_id().clone(),
            session_incarnation: proposal.session_incarnation(),
            page_id: proposal.page_id().clone(),
            target_incarnation: proposal.target_incarnation(),
            frame_document_epoch: proposal.frame_document_epoch(),
            current_origin: proposal.current_origin().as_str().to_owned(),
            url_revision: proposal.url_revision(),
            action_type,
            canonical_arguments_hash: *proposal.canonical_arguments_hash().as_bytes(),
            node_ref: proposal
                .node_ref()
                .map(|node_ref| node_ref.as_str().to_owned()),
            credential_refs_hash: *proposal.credential_refs_hash().as_bytes(),
            expires_at_unix_millis: proposal.expires_at_unix_ms(),
        }
    }

    pub fn to_canonical(&self) -> Result<CanonicalActionProposal, WorkerRpcError> {
        if self.session_incarnation == 0
            || self.target_incarnation == 0
            || self.frame_document_epoch == 0
            || self.expires_at_unix_millis == 0
        {
            return Err(WorkerRpcError::Protocol);
        }
        let current_origin =
            Origin::parse(&self.current_origin).map_err(|_| WorkerRpcError::Protocol)?;
        let action_type = match &self.action_type {
            WorkerApprovalActionType::Click => ActionType::Click,
            WorkerApprovalActionType::Fill => ActionType::Fill,
            WorkerApprovalActionType::Navigate => ActionType::Navigate,
            WorkerApprovalActionType::Evaluate => ActionType::Evaluate,
            WorkerApprovalActionType::Upload => ActionType::Upload,
            WorkerApprovalActionType::Download => ActionType::Download,
            WorkerApprovalActionType::Custom(value)
                if !value.is_empty()
                    && value.len() <= 255
                    && value.trim() == value
                    && !value.chars().any(char::is_control) =>
            {
                ActionType::Custom(value.clone())
            }
            WorkerApprovalActionType::Custom(_) => return Err(WorkerRpcError::Protocol),
        };
        let node_ref = self
            .node_ref
            .clone()
            .map(NodeReference::new)
            .transpose()
            .map_err(|_| WorkerRpcError::Protocol)?;
        let canonical_arguments_hash =
            ActionArgumentsHash::from_bytes(&self.canonical_arguments_hash)
                .map_err(|_| WorkerRpcError::Protocol)?;
        let credential_refs_hash = CredentialRefsHash::from_bytes(&self.credential_refs_hash)
            .map_err(|_| WorkerRpcError::Protocol)?;
        Ok(CanonicalActionProposal::new(
            self.tenant_id.clone(),
            self.requester_principal_id.clone(),
            self.session_id.clone(),
            self.session_incarnation,
            self.page_id.clone(),
            self.target_incarnation,
            self.frame_document_epoch,
            current_origin,
            self.url_revision,
            action_type,
            canonical_arguments_hash,
            node_ref,
            credential_refs_hash,
            self.expires_at_unix_millis,
        ))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerApprovalReceipt {
    pub fence: WorkerSessionFence,
    pub approval_id: ApprovalId,
    pub action_id: ActionId,
    pub state: WorkerApprovalState,
    pub proposal: WorkerCanonicalActionProposal,
    pub proposal_hash: [u8; 32],
}

impl WorkerApprovalReceipt {
    pub fn canonical_proposal(&self) -> Result<CanonicalActionProposal, WorkerRpcError> {
        let proposal = self.proposal.to_canonical()?;
        if proposal.tenant_id() != &self.fence.tenant_id
            || proposal.session_id() != &self.fence.session_id
            || proposal.session_incarnation() != self.fence.session_incarnation
            || proposal.hash().as_bytes() != &self.proposal_hash
        {
            return Err(WorkerRpcError::Protocol);
        }
        Ok(proposal)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "method",
    content = "params",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum WorkerRpcRequest {
    Probe {
        expected_worker_epoch: u64,
    },
    CreateSession(WorkerCreateSessionRequest),
    GetSession {
        fence: WorkerSessionFence,
    },
    CloseSession {
        fence: WorkerSessionFence,
        now_unix_millis: u64,
    },
    CreatePage {
        fence: WorkerSessionFence,
        now_unix_millis: u64,
    },
    ListPages {
        fence: WorkerSessionFence,
    },
    ActivatePage {
        fence: WorkerSessionFence,
        page_id: PageId,
        now_unix_millis: u64,
    },
    ClosePage {
        fence: WorkerSessionFence,
        page_id: PageId,
        now_unix_millis: u64,
    },
    SubmitAction {
        fence: WorkerSessionFence,
        action_id: ActionId,
        action_sequence: ActionSequence,
        requester_principal_id: PrincipalId,
        idempotency_key: String,
        canonical_request_hash: [u8; 32],
        kind: ActionKind,
        page_id: Option<PageId>,
        action: WorkerActionCommand,
        execution_timeout_ms: WorkerActionExecutionTimeout,
        approval: Option<Box<WorkerActionApprovalRequirement>>,
        now_unix_millis: u64,
    },
    GetAction {
        fence: WorkerSessionFence,
        action_id: ActionId,
    },
    CancelAction {
        fence: WorkerSessionFence,
        action_id: ActionId,
        now_unix_millis: u64,
    },
    ResolveAction {
        fence: WorkerSessionFence,
        action_id: ActionId,
        resolution: ResolutionKind,
        resolved_by: PrincipalId,
        basis: String,
        now_unix_millis: u64,
    },
    StoreArtifact {
        fence: WorkerSessionFence,
        bytes: Vec<u8>,
        content_type: String,
        now_unix_millis: u64,
    },
    GetArtifact {
        fence: WorkerSessionFence,
        artifact_id: ArtifactId,
    },
    GetApproval {
        fence: WorkerSessionFence,
        approval_id: ApprovalId,
    },
    ListApprovals {
        fence: WorkerSessionFence,
    },
    DecideApproval {
        fence: WorkerSessionFence,
        approval_id: ApprovalId,
        decision: WorkerApprovalDecision,
        principal_id: PrincipalId,
        reason: String,
        now_unix_millis: u64,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerRpcFailureCode {
    InvalidRequest,
    Unauthorized,
    FenceMismatch,
    NotFound,
    Conflict,
    Capacity,
    NotReady,
    Dependency,
    Durability,
    Timeout,
    Internal,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerRpcFailure {
    pub code: WorkerRpcFailureCode,
    pub message: String,
}

impl WorkerRpcFailure {
    #[must_use]
    pub fn new(code: WorkerRpcFailureCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "result",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum WorkerRpcResponse {
    Probe(WorkerProbeReceipt),
    SessionCreated(WorkerCreateSessionReceipt),
    Session(WorkerSessionReceipt),
    SessionClosed(WorkerSessionReceipt),
    Pages(Vec<WorkerPageReceipt>),
    Page(WorkerPageReceipt),
    PageClosed(WorkerPageReceipt),
    Action(WorkerActionReceipt),
    ArtifactStored(WorkerArtifactReceipt),
    Artifact(WorkerArtifactReceipt),
    Approvals(Vec<WorkerApprovalReceipt>),
    Approval(WorkerApprovalReceipt),
    Empty,
    Failure(WorkerRpcFailure),
}

#[derive(Clone, Debug)]
pub struct WorkerRpcConfig {
    socket_path: PathBuf,
    max_frame_bytes: usize,
    max_connections: usize,
    request_timeout: Duration,
    allowed_uid: u32,
}

impl WorkerRpcConfig {
    pub fn new(
        socket_path: impl Into<PathBuf>,
        max_frame_bytes: usize,
        max_connections: usize,
        request_timeout: Duration,
        allowed_uid: Option<u32>,
    ) -> Result<Self, WorkerRpcError> {
        let socket_path = socket_path.into();
        let Some(allowed_uid) = allowed_uid else {
            return Err(WorkerRpcError::InvalidConfig);
        };
        if !socket_path.is_absolute()
            || socket_path.as_os_str().is_empty()
            || max_frame_bytes == 0
            || max_frame_bytes > u32::MAX as usize
            || max_connections == 0
            || request_timeout.is_zero()
        {
            return Err(WorkerRpcError::InvalidConfig);
        }
        Ok(Self {
            socket_path,
            max_frame_bytes,
            max_connections,
            request_timeout,
            allowed_uid,
        })
    }

    #[must_use]
    pub const fn max_frame_bytes(&self) -> usize {
        self.max_frame_bytes
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RequestEnvelope {
    protocol_version: u16,
    request_id: LeaseId,
    request: WorkerRpcRequest,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ResponseEnvelope {
    protocol_version: u16,
    request_id: LeaseId,
    response: WorkerRpcResponse,
}

#[async_trait]
pub trait WorkerRpcHandler: Send + Sync + 'static {
    async fn handle(&self, request: WorkerRpcRequest) -> WorkerRpcResponse;
}

const CREATE_BINDING_RETENTION: Duration = Duration::from_secs(24 * 60 * 60);

struct OperationBinding {
    canonical_request_hash: [u8; 32],
    operation_id: OperationId,
    expected_worker_epoch: u64,
    placement_version: u64,
    session_incarnation: u64,
    requested_isolation: WorkerIsolationProfile,
    completed_at: Option<Instant>,
    receipt: Option<WorkerCreateSessionReceipt>,
}

pub struct WorkerControlPlaneRpcHandler<D, S> {
    worker: Arc<WorkerControlPlane<D, S>>,
    peer: AuthenticatedPeer,
    operation_bindings: Arc<Mutex<HashMap<(TenantId, String), OperationBinding>>>,
    operation_binding_capacity: usize,
}

impl<D: ChromiumDriver, S: SandboxClient> WorkerControlPlaneRpcHandler<D, S> {
    #[must_use]
    pub fn new(worker: Arc<WorkerControlPlane<D, S>>, peer: AuthenticatedPeer) -> Self {
        let capacity = worker
            .config
            .max_sessions
            .saturating_mul(64)
            .clamp(256, 65_536);
        Self::with_binding_capacity(worker, peer, capacity)
    }

    pub fn new_with_binding_capacity(
        worker: Arc<WorkerControlPlane<D, S>>,
        peer: AuthenticatedPeer,
        capacity: usize,
    ) -> Result<Self, WorkerRpcError> {
        if capacity == 0 || capacity > 65_536 {
            return Err(WorkerRpcError::InvalidConfig);
        }
        Ok(Self::with_binding_capacity(worker, peer, capacity))
    }

    fn with_binding_capacity(
        worker: Arc<WorkerControlPlane<D, S>>,
        peer: AuthenticatedPeer,
        capacity: usize,
    ) -> Self {
        Self {
            worker,
            peer,
            operation_bindings: Arc::new(Mutex::new(HashMap::new())),
            operation_binding_capacity: capacity,
        }
    }

    fn ownership_fence(
        &self,
        fence: &WorkerSessionFence,
    ) -> Result<OwnershipFence, WorkerRpcFailure> {
        if !fence.is_valid() || fence.worker_epoch != self.worker.config.worker_epoch {
            return Err(WorkerRpcFailure::new(
                WorkerRpcFailureCode::FenceMismatch,
                "session ownership fence does not match this worker epoch",
            ));
        }
        let executor = self
            .worker
            .session(&fence.session_id)
            .map_err(worker_failure)?;
        let session = executor
            .state
            .lock()
            .map_err(|_| worker_failure(WorkerError::StateUnavailable))?;
        if session.tenant_id != fence.tenant_id {
            return Err(WorkerRpcFailure::new(
                WorkerRpcFailureCode::FenceMismatch,
                "session ownership fence does not match this tenant",
            ));
        }
        Ok(OwnershipFence::new(
            self.worker.config.worker_id.clone(),
            fence.worker_epoch,
            fence.placement_version,
            fence.session_incarnation,
        ))
    }

    fn session_receipt(
        &self,
        fence: &WorkerSessionFence,
        lifecycle: SessionLifecycle,
    ) -> Result<WorkerSessionReceipt, WorkerRpcFailure> {
        let executor = self
            .worker
            .session(&fence.session_id)
            .map_err(worker_failure)?;
        let session = executor
            .state
            .lock()
            .map_err(|_| worker_failure(WorkerError::StateUnavailable))?;
        let expected_ownership = OwnershipFence::new(
            self.worker.config.worker_id.clone(),
            fence.worker_epoch,
            fence.placement_version,
            fence.session_incarnation,
        );
        if session.tenant_id != fence.tenant_id
            || session.machine.snapshot().owner_fence != expected_ownership
        {
            return Err(WorkerRpcFailure::new(
                WorkerRpcFailureCode::FenceMismatch,
                "session changed ownership while producing the RPC response",
            ));
        }
        Ok(WorkerSessionReceipt {
            fence: fence.clone(),
            lifecycle: session_lifecycle(lifecycle),
            primary_page_id: session.primary_page_id.clone(),
        })
    }

    fn bind_operation(
        &self,
        request: &WorkerCreateSessionRequest,
    ) -> Result<Option<WorkerCreateSessionReceipt>, WorkerRpcFailure> {
        let mut bindings = self.operation_bindings.lock().map_err(|_| {
            WorkerRpcFailure::new(
                WorkerRpcFailureCode::Internal,
                "operation binding unavailable",
            )
        })?;
        let now = Instant::now();
        bindings.retain(|_, binding| {
            binding.completed_at.is_none_or(|completed_at| {
                now.saturating_duration_since(completed_at) < CREATE_BINDING_RETENTION
            })
        });
        let key = (request.tenant_id.clone(), request.idempotency_key.clone());
        if let Some(existing) = bindings.get(&key) {
            return if existing.canonical_request_hash == request.canonical_request_hash
                && existing.operation_id == request.operation_id
                && existing.expected_worker_epoch == request.expected_worker_epoch
                && existing.placement_version == request.placement_version
                && existing.session_incarnation == request.session_incarnation
                && existing.requested_isolation == request.requested_isolation
            {
                Ok(existing.receipt.clone().map(|mut receipt| {
                    receipt.existing = true;
                    receipt
                }))
            } else {
                Err(WorkerRpcFailure::new(
                    WorkerRpcFailureCode::Conflict,
                    "create operation binding conflicts with an existing request",
                ))
            };
        }
        if bindings.len() >= self.operation_binding_capacity {
            return Err(WorkerRpcFailure::new(
                WorkerRpcFailureCode::Capacity,
                "create operation binding capacity is exhausted",
            ));
        }
        bindings.insert(
            key,
            OperationBinding {
                canonical_request_hash: request.canonical_request_hash,
                operation_id: request.operation_id.clone(),
                expected_worker_epoch: request.expected_worker_epoch,
                placement_version: request.placement_version,
                session_incarnation: request.session_incarnation,
                requested_isolation: request.requested_isolation,
                completed_at: None,
                receipt: None,
            },
        );
        Ok(None)
    }
}

#[async_trait]
impl<D: ChromiumDriver, S: SandboxClient> WorkerRpcHandler for WorkerControlPlaneRpcHandler<D, S> {
    async fn handle(&self, request: WorkerRpcRequest) -> WorkerRpcResponse {
        let handler = Self {
            worker: self.worker.clone(),
            peer: self.peer.clone(),
            operation_bindings: self.operation_bindings.clone(),
            operation_binding_capacity: self.operation_binding_capacity,
        };
        let result = tokio::task::spawn_blocking(move || handler.handle_request(request)).await;
        match result {
            Err(_) => WorkerRpcResponse::Failure(WorkerRpcFailure::new(
                WorkerRpcFailureCode::Internal,
                "worker control-plane task failed",
            )),
            Ok(Ok(response)) => response,
            Ok(Err(failure)) => WorkerRpcResponse::Failure(failure),
        }
    }
}

impl<D: ChromiumDriver, S: SandboxClient> WorkerControlPlaneRpcHandler<D, S> {
    fn handle_request(
        &self,
        request: WorkerRpcRequest,
    ) -> Result<WorkerRpcResponse, WorkerRpcFailure> {
        match request {
            WorkerRpcRequest::Probe {
                expected_worker_epoch,
            } => {
                if expected_worker_epoch == 0
                    || expected_worker_epoch != self.worker.config.worker_epoch
                {
                    return Err(WorkerRpcFailure::new(
                        WorkerRpcFailureCode::FenceMismatch,
                        "probe does not match this worker epoch",
                    ));
                }
                if !self.worker.is_ready() {
                    return Err(WorkerRpcFailure::new(
                        WorkerRpcFailureCode::NotReady,
                        "worker readiness qualification failed",
                    ));
                }
                Ok(WorkerRpcResponse::Probe(WorkerProbeReceipt {
                    worker_id: self.worker.config.worker_id.clone(),
                    worker_epoch: self.worker.config.worker_epoch,
                    ready: true,
                }))
            }
            WorkerRpcRequest::CreateSession(request) => {
                if !request.is_valid() {
                    return Err(WorkerRpcFailure::new(
                        WorkerRpcFailureCode::InvalidRequest,
                        "create request contains invalid or unbound session options",
                    ));
                }
                if request.expected_worker_epoch != self.worker.config.worker_epoch {
                    return Err(WorkerRpcFailure::new(
                        WorkerRpcFailureCode::FenceMismatch,
                        "create request does not match this worker epoch",
                    ));
                }
                if request.requested_isolation != WorkerIsolationProfile::SharedContext {
                    return Err(WorkerRpcFailure::new(
                        WorkerRpcFailureCode::InvalidRequest,
                        "requested isolation profile is not implemented by this worker",
                    ));
                }
                if let Some(receipt) = self.bind_operation(&request)? {
                    return Ok(WorkerRpcResponse::SessionCreated(receipt));
                }
                let binding_key = (request.tenant_id.clone(), request.idempotency_key.clone());
                let tenant_id = request.tenant_id.clone();
                let options = request.options.clone();
                let outcome = self.worker.create_session_with_options(
                    &self.peer,
                    CreateSessionCommand {
                        tenant_id: request.tenant_id,
                        idempotency_key: request.idempotency_key,
                        canonical_request_hash: request.canonical_request_hash,
                        placement_version: request.placement_version,
                        session_incarnation: request.session_incarnation,
                    },
                    &options,
                    SessionTime::new(request.now_unix_millis),
                );
                let outcome = match outcome {
                    Ok(outcome) => outcome,
                    Err(error) => {
                        if let Ok(mut bindings) = self.operation_bindings.lock()
                            && let Some(binding) = bindings.get_mut(&binding_key)
                            && binding.operation_id == request.operation_id
                        {
                            binding.completed_at = Some(Instant::now());
                        }
                        return Err(worker_failure(error));
                    }
                };
                if outcome.fence.worker_epoch() != request.expected_worker_epoch
                    || outcome.fence.placement_version() != request.placement_version
                    || outcome.fence.session_incarnation() != request.session_incarnation
                {
                    return Err(WorkerRpcFailure::new(
                        WorkerRpcFailureCode::FenceMismatch,
                        "worker returned a session under a different placement fence",
                    ));
                }
                let receipt = WorkerCreateSessionReceipt {
                    operation_id: request.operation_id,
                    tenant_id,
                    session_id: outcome.session_id,
                    session_incarnation: request.session_incarnation,
                    effective_isolation: self.worker.driver.effective_isolation(),
                    primary_page_id: outcome.primary_page_id,
                    worker_epoch: request.expected_worker_epoch,
                    placement_version: request.placement_version,
                    existing: outcome.existing,
                };
                let mut bindings = self.operation_bindings.lock().map_err(|_| {
                    WorkerRpcFailure::new(
                        WorkerRpcFailureCode::Internal,
                        "operation binding unavailable after session creation",
                    )
                })?;
                let binding = bindings.get_mut(&binding_key).ok_or_else(|| {
                    WorkerRpcFailure::new(
                        WorkerRpcFailureCode::Internal,
                        "operation binding disappeared during session creation",
                    )
                })?;
                if binding.operation_id != receipt.operation_id {
                    return Err(WorkerRpcFailure::new(
                        WorkerRpcFailureCode::Conflict,
                        "operation binding changed during session creation",
                    ));
                }
                let mut cached = receipt.clone();
                cached.existing = false;
                if binding
                    .receipt
                    .as_ref()
                    .is_some_and(|existing| existing != &cached)
                {
                    return Err(WorkerRpcFailure::new(
                        WorkerRpcFailureCode::FenceMismatch,
                        "concurrent session creation returned a different receipt",
                    ));
                }
                binding.completed_at = Some(Instant::now());
                binding.receipt = Some(cached);
                Ok(WorkerRpcResponse::SessionCreated(receipt))
            }
            WorkerRpcRequest::GetSession { fence } => {
                let ownership = self.ownership_fence(&fence)?;
                let snapshot = self
                    .worker
                    .get_session(&self.peer, &fence.session_id, &ownership)
                    .map_err(worker_failure)?;
                Ok(WorkerRpcResponse::Session(
                    self.session_receipt(&fence, snapshot.lifecycle)?,
                ))
            }
            WorkerRpcRequest::CloseSession {
                fence,
                now_unix_millis,
            } => {
                let ownership = self.ownership_fence(&fence)?;
                let snapshot = self
                    .worker
                    .close_session(
                        &self.peer,
                        &fence.session_id,
                        &ownership,
                        SessionTime::new(now_unix_millis),
                    )
                    .map_err(worker_failure)?;
                Ok(WorkerRpcResponse::SessionClosed(
                    self.session_receipt(&fence, snapshot.lifecycle)?,
                ))
            }
            WorkerRpcRequest::CreatePage {
                fence,
                now_unix_millis,
            } => {
                let ownership = self.ownership_fence(&fence)?;
                let page_id = self
                    .worker
                    .create_page(
                        &self.peer,
                        &fence.session_id,
                        &ownership,
                        SessionTime::new(now_unix_millis),
                    )
                    .map_err(worker_failure)?;
                let snapshot = self
                    .worker
                    .get_page(&self.peer, &fence.session_id, &page_id, &ownership)
                    .map_err(worker_failure)?;
                Ok(WorkerRpcResponse::Page(page_receipt(&fence, snapshot)))
            }
            WorkerRpcRequest::ListPages { fence } => {
                let ownership = self.ownership_fence(&fence)?;
                let snapshots = self
                    .worker
                    .list_pages(&self.peer, &fence.session_id, &ownership)
                    .map_err(worker_failure)?;
                Ok(WorkerRpcResponse::Pages(
                    snapshots
                        .into_iter()
                        .map(|snapshot| page_receipt(&fence, snapshot))
                        .collect(),
                ))
            }
            WorkerRpcRequest::ActivatePage {
                fence,
                page_id,
                now_unix_millis,
            } => {
                let ownership = self.ownership_fence(&fence)?;
                self.worker
                    .activate_page(
                        &self.peer,
                        &fence.session_id,
                        &page_id,
                        &ownership,
                        SessionTime::new(now_unix_millis),
                    )
                    .map_err(worker_failure)?;
                let snapshot = self
                    .worker
                    .get_page(&self.peer, &fence.session_id, &page_id, &ownership)
                    .map_err(worker_failure)?;
                Ok(WorkerRpcResponse::Page(page_receipt(&fence, snapshot)))
            }
            WorkerRpcRequest::ClosePage {
                fence,
                page_id,
                now_unix_millis,
            } => {
                let ownership = self.ownership_fence(&fence)?;
                let mut snapshot = self
                    .worker
                    .get_page(&self.peer, &fence.session_id, &page_id, &ownership)
                    .map_err(worker_failure)?;
                self.worker
                    .close_page(
                        &self.peer,
                        &fence.session_id,
                        &page_id,
                        &ownership,
                        SessionTime::new(now_unix_millis),
                    )
                    .map_err(worker_failure)?;
                snapshot.active = false;
                Ok(WorkerRpcResponse::PageClosed(page_receipt(
                    &fence, snapshot,
                )))
            }
            WorkerRpcRequest::SubmitAction {
                fence,
                action_id,
                action_sequence,
                requester_principal_id,
                idempotency_key,
                canonical_request_hash,
                kind,
                page_id,
                action,
                execution_timeout_ms,
                approval,
                now_unix_millis,
            } => {
                let ownership = self.ownership_fence(&fence)?;
                let now = SessionTime::new(now_unix_millis);
                if !action.is_valid() || kind != action.kind() {
                    return Err(WorkerRpcFailure::new(
                        WorkerRpcFailureCode::InvalidRequest,
                        "action command is invalid or its kind does not match",
                    ));
                }
                let payload = serde_json::to_vec(&action).map_err(|_| {
                    WorkerRpcFailure::new(
                        WorkerRpcFailureCode::InvalidRequest,
                        "action command cannot be encoded",
                    )
                })?;
                let approval = match approval {
                    Some(approval) => {
                        let page_id = page_id.clone().ok_or_else(|| {
                            WorkerRpcFailure::new(
                                WorkerRpcFailureCode::InvalidRequest,
                                "approval-bound action requires a page",
                            )
                        })?;
                        let expires_at_unix_millis = now_unix_millis
                            .checked_add(self.worker.config.approval_timeout_millis)
                            .ok_or_else(|| {
                                WorkerRpcFailure::new(
                                    WorkerRpcFailureCode::InvalidRequest,
                                    "approval expiry overflows the worker clock",
                                )
                            })?;
                        Some((*approval).into_requirement(
                            fence.tenant_id.clone(),
                            requester_principal_id.clone(),
                            fence.session_id.clone(),
                            fence.session_incarnation,
                            page_id,
                            &payload,
                            expires_at_unix_millis,
                        )?)
                    }
                    None => None,
                };
                let action_id = self
                    .worker
                    .submit_and_run_action_with_identity(
                        &self.peer,
                        requester_principal_id,
                        &fence.session_id,
                        &ownership,
                        action_id,
                        action_sequence,
                        &idempotency_key,
                        canonical_request_hash,
                        kind,
                        None,
                        page_id,
                        payload,
                        approval,
                        execution_timeout_ms.duration(),
                        now,
                    )
                    .map_err(worker_failure)?;
                let snapshot = self
                    .worker
                    .get_action(&self.peer, &fence.session_id, &action_id, &ownership)
                    .map_err(worker_failure)?;
                Ok(WorkerRpcResponse::Action(action_receipt(&fence, snapshot)))
            }
            WorkerRpcRequest::GetAction { fence, action_id } => {
                let ownership = self.ownership_fence(&fence)?;
                let snapshot = self
                    .worker
                    .get_action(&self.peer, &fence.session_id, &action_id, &ownership)
                    .map_err(worker_failure)?;
                Ok(WorkerRpcResponse::Action(action_receipt(&fence, snapshot)))
            }
            WorkerRpcRequest::CancelAction {
                fence,
                action_id,
                now_unix_millis,
            } => {
                let ownership = self.ownership_fence(&fence)?;
                let _cancelled = self
                    .worker
                    .cancel_action(
                        &self.peer,
                        &fence.session_id,
                        &action_id,
                        &ownership,
                        SessionTime::new(now_unix_millis),
                    )
                    .map_err(worker_failure)?;
                let snapshot = self
                    .worker
                    .get_action(&self.peer, &fence.session_id, &action_id, &ownership)
                    .map_err(worker_failure)?;
                Ok(WorkerRpcResponse::Action(action_receipt(&fence, snapshot)))
            }
            WorkerRpcRequest::ResolveAction {
                fence,
                action_id,
                resolution,
                resolved_by,
                basis,
                now_unix_millis,
            } => {
                let ownership = self.ownership_fence(&fence)?;
                let _resolved = self
                    .worker
                    .resolve_action(
                        &self.peer,
                        &fence.session_id,
                        &action_id,
                        &ownership,
                        resolution,
                        resolved_by,
                        &basis,
                        SessionTime::new(now_unix_millis),
                    )
                    .map_err(worker_failure)?;
                let snapshot = self
                    .worker
                    .get_action(&self.peer, &fence.session_id, &action_id, &ownership)
                    .map_err(worker_failure)?;
                Ok(WorkerRpcResponse::Action(action_receipt(&fence, snapshot)))
            }
            WorkerRpcRequest::StoreArtifact {
                fence,
                bytes,
                content_type,
                now_unix_millis,
            } => {
                let ownership = self.ownership_fence(&fence)?;
                let artifact_id = self
                    .worker
                    .upload_artifact(
                        &self.peer,
                        &fence.session_id,
                        &ownership,
                        ArtifactUpload {
                            bytes,
                            content_type,
                        },
                        SessionTime::new(now_unix_millis),
                    )
                    .map_err(worker_failure)?;
                let snapshot = self
                    .worker
                    .get_artifact(&self.peer, &fence.session_id, &artifact_id, &ownership)
                    .map_err(worker_failure)?;
                Ok(WorkerRpcResponse::ArtifactStored(artifact_receipt(
                    &fence, snapshot,
                )))
            }
            WorkerRpcRequest::GetArtifact { fence, artifact_id } => {
                let ownership = self.ownership_fence(&fence)?;
                let snapshot = self
                    .worker
                    .get_artifact(&self.peer, &fence.session_id, &artifact_id, &ownership)
                    .map_err(worker_failure)?;
                Ok(WorkerRpcResponse::Artifact(artifact_receipt(
                    &fence, snapshot,
                )))
            }
            WorkerRpcRequest::GetApproval { fence, approval_id } => {
                let ownership = self.ownership_fence(&fence)?;
                let snapshot = self
                    .worker
                    .get_approval(&self.peer, &fence.session_id, &approval_id, &ownership)
                    .map_err(worker_failure)?;
                Ok(WorkerRpcResponse::Approval(approval_receipt(
                    &fence, snapshot,
                )))
            }
            WorkerRpcRequest::ListApprovals { fence } => {
                let ownership = self.ownership_fence(&fence)?;
                let snapshots = self
                    .worker
                    .list_approvals(&self.peer, &fence.session_id, &ownership)
                    .map_err(worker_failure)?;
                Ok(WorkerRpcResponse::Approvals(
                    snapshots
                        .into_iter()
                        .map(|snapshot| approval_receipt(&fence, snapshot))
                        .collect(),
                ))
            }
            WorkerRpcRequest::DecideApproval {
                fence,
                approval_id,
                decision,
                principal_id,
                reason,
                now_unix_millis,
            } => {
                if reason.trim().is_empty()
                    || reason.len() > 1_024
                    || reason.chars().any(char::is_control)
                {
                    return Err(WorkerRpcFailure::new(
                        WorkerRpcFailureCode::InvalidRequest,
                        "invalid approval decision reason",
                    ));
                }
                let ownership = self.ownership_fence(&fence)?;
                let policy_decision = match decision {
                    WorkerApprovalDecision::Approve => ApprovalDecision::Approve,
                    WorkerApprovalDecision::Deny => ApprovalDecision::Deny,
                };
                let snapshot = self
                    .worker
                    .decide_approval_and_run_ready_actions(
                        &self.peer,
                        &fence.session_id,
                        &approval_id,
                        &ownership,
                        policy_decision,
                        principal_id,
                        SessionTime::new(now_unix_millis),
                    )
                    .map_err(worker_failure)?;
                Ok(WorkerRpcResponse::Approval(approval_receipt(
                    &fence, snapshot,
                )))
            }
        }
    }
}

pub struct WorkerRpcServer<H> {
    listener: UnixListener,
    config: WorkerRpcConfig,
    handler: Arc<H>,
    connection_slots: Arc<Semaphore>,
    _socket_ownership: ServiceSocketOwnership,
}

struct OwnedSocketPath {
    path: PathBuf,
    dev: u64,
    ino: u64,
    _path_pin: OwnedFd,
}

impl Drop for OwnedSocketPath {
    fn drop(&mut self) {
        let Ok(metadata) = std::fs::symlink_metadata(&self.path) else {
            return;
        };
        if metadata.file_type().is_socket()
            && metadata.dev() == self.dev
            && metadata.ino() == self.ino
        {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

struct ServiceSocketOwnership {
    _singleton_lock: Flock<OwnedFd>,
    _socket_path: OwnedSocketPath,
}

impl<H: WorkerRpcHandler> WorkerRpcServer<H> {
    pub async fn bind(config: WorkerRpcConfig, handler: Arc<H>) -> Result<Self, WorkerRpcError> {
        let parent = config
            .socket_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .ok_or(WorkerRpcError::InvalidConfig)?;
        let canonical_parent = parent
            .canonicalize()
            .map_err(|error| WorkerRpcError::Io(error.to_string()))?;
        let parent_metadata = canonical_parent
            .metadata()
            .map_err(|error| WorkerRpcError::Io(error.to_string()))?;
        let effective_uid = Uid::effective().as_raw();
        if canonical_parent != parent
            || !parent_metadata.is_dir()
            || parent_metadata.uid() != effective_uid
            || parent_metadata.mode() & 0o022 != 0
        {
            return Err(WorkerRpcError::InvalidConfig);
        }

        let mut lock_path = config.socket_path.as_os_str().to_os_string();
        lock_path.push(".lock");
        let lock_path = PathBuf::from(lock_path);
        let lock_fd = open(
            &lock_path,
            OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
            Mode::from_bits_truncate(0o600),
        )
        .map_err(|error| WorkerRpcError::Io(error.to_string()))?;
        let lock_metadata =
            fstat(&lock_fd).map_err(|error| WorkerRpcError::Io(error.to_string()))?;
        if !SFlag::from_bits_truncate(lock_metadata.st_mode).contains(SFlag::S_IFREG)
            || lock_metadata.st_uid != effective_uid
            || lock_metadata.st_nlink != 1
        {
            return Err(WorkerRpcError::InvalidConfig);
        }
        fchmod(&lock_fd, Mode::from_bits_truncate(0o600))
            .map_err(|error| WorkerRpcError::Io(error.to_string()))?;
        let singleton_lock = Flock::lock(lock_fd, FlockArg::LockExclusiveNonblock)
            .map_err(|(_, error)| WorkerRpcError::Io(error.to_string()))?;
        let locked_metadata =
            fstat(&*singleton_lock).map_err(|error| WorkerRpcError::Io(error.to_string()))?;
        let lock_path_metadata = std::fs::symlink_metadata(&lock_path)
            .map_err(|error| WorkerRpcError::Io(error.to_string()))?;
        if !lock_path_metadata.file_type().is_file()
            || lock_path_metadata.uid() != effective_uid
            || lock_path_metadata.mode() & 0o777 != 0o600
            || lock_path_metadata.dev() != locked_metadata.st_dev
            || lock_path_metadata.ino() != locked_metadata.st_ino
        {
            return Err(WorkerRpcError::InvalidConfig);
        }

        match std::fs::symlink_metadata(&config.socket_path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(WorkerRpcError::Io(error.to_string())),
            Ok(metadata) => {
                if !metadata.file_type().is_socket()
                    || metadata.uid() != effective_uid
                    || metadata.mode() & 0o777 != 0o600
                {
                    return Err(WorkerRpcError::InvalidConfig);
                }
                match std::os::unix::net::UnixStream::connect(&config.socket_path) {
                    Ok(_) => {
                        return Err(WorkerRpcError::Io(
                            "another worker RPC server is already listening".to_owned(),
                        ));
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
                        ) => {}
                    Err(error) => return Err(WorkerRpcError::Io(error.to_string())),
                }
                std::fs::remove_file(&config.socket_path)
                    .map_err(|error| WorkerRpcError::Io(error.to_string()))?;
            }
        }

        let listener = std::os::unix::net::UnixListener::bind(&config.socket_path)
            .map_err(|error| WorkerRpcError::Io(error.to_string()))?;
        let metadata = std::fs::symlink_metadata(&config.socket_path)
            .map_err(|error| WorkerRpcError::Io(error.to_string()))?;
        if !metadata.file_type().is_socket() {
            return Err(WorkerRpcError::Protocol);
        }
        let path_pin = open(
            &config.socket_path,
            OFlag::O_PATH | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|error| WorkerRpcError::Io(error.to_string()))?;
        let pinned_metadata =
            fstat(&path_pin).map_err(|error| WorkerRpcError::Io(error.to_string()))?;
        if pinned_metadata.st_dev != metadata.dev() || pinned_metadata.st_ino != metadata.ino() {
            return Err(WorkerRpcError::Protocol);
        }
        let socket_path = OwnedSocketPath {
            path: config.socket_path.clone(),
            dev: metadata.dev(),
            ino: metadata.ino(),
            _path_pin: path_pin,
        };
        std::fs::set_permissions(&config.socket_path, std::fs::Permissions::from_mode(0o600))
            .map_err(|error| WorkerRpcError::Io(error.to_string()))?;
        let private_metadata = std::fs::symlink_metadata(&config.socket_path)
            .map_err(|error| WorkerRpcError::Io(error.to_string()))?;
        if !private_metadata.file_type().is_socket()
            || private_metadata.mode() & 0o777 != 0o600
            || private_metadata.dev() != metadata.dev()
            || private_metadata.ino() != metadata.ino()
        {
            return Err(WorkerRpcError::Protocol);
        }
        listener
            .set_nonblocking(true)
            .map_err(|error| WorkerRpcError::Io(error.to_string()))?;
        let listener = UnixListener::from_std(listener)
            .map_err(|error| WorkerRpcError::Io(error.to_string()))?;
        Ok(Self {
            listener,
            connection_slots: Arc::new(Semaphore::new(config.max_connections)),
            config,
            handler,
            _socket_ownership: ServiceSocketOwnership {
                _singleton_lock: singleton_lock,
                _socket_path: socket_path,
            },
        })
    }

    pub async fn serve(self, shutdown: CancellationToken) -> Result<(), WorkerRpcError> {
        let mut connections = JoinSet::new();
        let primary_error = loop {
            let accepted = tokio::select! {
                biased;
                () = shutdown.cancelled() => break None,
                joined = connections.join_next(), if !connections.is_empty() => {
                    if joined.is_some_and(|result| result.is_err()) {
                        break Some(WorkerRpcError::Runtime);
                    }
                    continue;
                }
                accepted = self.listener.accept() => accepted,
            };
            let (stream, _) = match accepted {
                Ok(accepted) => accepted,
                Err(error) => break Some(WorkerRpcError::Io(error.to_string())),
            };
            let Ok(slot) = self.connection_slots.clone().try_acquire_owned() else {
                drop(stream);
                continue;
            };
            let config = self.config.clone();
            let handler = self.handler.clone();
            connections.spawn(async move {
                let _slot = slot;
                let _ = handle_connection(stream, config, handler).await;
            });
        };
        let mut drain_failed = false;
        while let Some(result) = connections.join_next().await {
            drain_failed |= result.is_err();
        }
        match primary_error {
            Some(error) => Err(error),
            None if drain_failed => Err(WorkerRpcError::Runtime),
            None => Ok(()),
        }
    }
}

#[derive(Clone, Debug)]
pub struct WorkerRpcClient {
    socket_path: PathBuf,
    max_frame_bytes: usize,
    request_timeout: Duration,
    expected_uid: u32,
}

impl WorkerRpcClient {
    pub fn new(
        socket_path: impl Into<PathBuf>,
        max_frame_bytes: usize,
        request_timeout: Duration,
        expected_uid: Option<u32>,
    ) -> Result<Self, WorkerRpcError> {
        let socket_path = socket_path.into();
        let Some(expected_uid) = expected_uid else {
            return Err(WorkerRpcError::InvalidConfig);
        };
        if !socket_path.is_absolute()
            || socket_path.as_os_str().is_empty()
            || max_frame_bytes == 0
            || max_frame_bytes > u32::MAX as usize
            || request_timeout.is_zero()
        {
            return Err(WorkerRpcError::InvalidConfig);
        }
        Ok(Self {
            socket_path,
            max_frame_bytes,
            request_timeout,
            expected_uid,
        })
    }

    pub fn blocking(
        &self,
        queue_capacity: usize,
    ) -> Result<WorkerRpcBlockingClient, WorkerRpcError> {
        WorkerRpcBlockingClient::spawn(self.clone(), queue_capacity, queue_capacity.min(32))
    }

    pub fn blocking_with_limits(
        &self,
        queue_capacity: usize,
        max_in_flight: usize,
    ) -> Result<WorkerRpcBlockingClient, WorkerRpcError> {
        WorkerRpcBlockingClient::spawn(self.clone(), queue_capacity, max_in_flight)
    }

    pub async fn exchange(
        &self,
        request: WorkerRpcRequest,
    ) -> Result<WorkerRpcResponse, WorkerRpcError> {
        let request_id = LeaseId::new();
        let operation = async {
            let mut stream = UnixStream::connect(&self.socket_path)
                .await
                .map_err(|error| WorkerRpcError::Io(error.to_string()))?;
            authenticate_peer(&stream, self.expected_uid)?;
            let encoded = serde_json::to_vec(&RequestEnvelope {
                protocol_version: WORKER_RPC_PROTOCOL_VERSION,
                request_id: request_id.clone(),
                request,
            })
            .map_err(|error| WorkerRpcError::Serialization(error.to_string()))?;
            write_frame(&mut stream, &encoded, self.max_frame_bytes).await?;
            let response = read_frame(&mut stream, self.max_frame_bytes).await?;
            let response: ResponseEnvelope =
                serde_json::from_slice(&response).map_err(|_| WorkerRpcError::Protocol)?;
            if response.protocol_version != WORKER_RPC_PROTOCOL_VERSION
                || response.request_id != request_id
            {
                return Err(WorkerRpcError::Protocol);
            }
            Ok(response.response)
        };
        tokio::time::timeout(self.request_timeout, operation)
            .await
            .map_err(|_| WorkerRpcError::Timeout)?
    }

    pub async fn probe(
        &self,
        expected_worker_epoch: u64,
    ) -> Result<WorkerProbeReceipt, WorkerRpcError> {
        if expected_worker_epoch == 0 {
            return Err(WorkerRpcError::InvalidRequest);
        }
        match self
            .exchange(WorkerRpcRequest::Probe {
                expected_worker_epoch,
            })
            .await?
        {
            WorkerRpcResponse::Probe(receipt)
                if receipt.ready && receipt.worker_epoch == expected_worker_epoch =>
            {
                Ok(receipt)
            }
            WorkerRpcResponse::Probe(_) => Err(WorkerRpcError::Protocol),
            WorkerRpcResponse::Failure(failure) => Err(WorkerRpcError::Remote(failure)),
            _ => Err(WorkerRpcError::Protocol),
        }
    }

    pub async fn create_session(
        &self,
        request: WorkerCreateSessionRequest,
    ) -> Result<WorkerCreateSessionReceipt, WorkerRpcError> {
        match self
            .exchange(WorkerRpcRequest::CreateSession(request))
            .await?
        {
            WorkerRpcResponse::SessionCreated(receipt) => Ok(receipt),
            WorkerRpcResponse::Failure(failure) => Err(WorkerRpcError::Remote(failure)),
            _ => Err(WorkerRpcError::Protocol),
        }
    }

    pub async fn get_session(
        &self,
        fence: WorkerSessionFence,
    ) -> Result<WorkerSessionReceipt, WorkerRpcError> {
        match self
            .exchange(WorkerRpcRequest::GetSession { fence })
            .await?
        {
            WorkerRpcResponse::Session(receipt) => Ok(receipt),
            WorkerRpcResponse::Failure(failure) => Err(WorkerRpcError::Remote(failure)),
            _ => Err(WorkerRpcError::Protocol),
        }
    }

    pub async fn close_session(
        &self,
        fence: WorkerSessionFence,
        now_unix_millis: u64,
    ) -> Result<WorkerSessionReceipt, WorkerRpcError> {
        match self
            .exchange(WorkerRpcRequest::CloseSession {
                fence,
                now_unix_millis,
            })
            .await?
        {
            WorkerRpcResponse::SessionClosed(receipt) => Ok(receipt),
            WorkerRpcResponse::Failure(failure) => Err(WorkerRpcError::Remote(failure)),
            _ => Err(WorkerRpcError::Protocol),
        }
    }

    pub async fn create_page(
        &self,
        fence: WorkerSessionFence,
        now_unix_millis: u64,
    ) -> Result<WorkerPageReceipt, WorkerRpcError> {
        match self
            .exchange(WorkerRpcRequest::CreatePage {
                fence,
                now_unix_millis,
            })
            .await?
        {
            WorkerRpcResponse::Page(receipt) => Ok(receipt),
            WorkerRpcResponse::Failure(failure) => Err(WorkerRpcError::Remote(failure)),
            _ => Err(WorkerRpcError::Protocol),
        }
    }

    pub async fn list_pages(
        &self,
        fence: WorkerSessionFence,
    ) -> Result<Vec<WorkerPageReceipt>, WorkerRpcError> {
        match self.exchange(WorkerRpcRequest::ListPages { fence }).await? {
            WorkerRpcResponse::Pages(receipts) => Ok(receipts),
            WorkerRpcResponse::Failure(failure) => Err(WorkerRpcError::Remote(failure)),
            _ => Err(WorkerRpcError::Protocol),
        }
    }

    pub async fn activate_page(
        &self,
        fence: WorkerSessionFence,
        page_id: PageId,
        now_unix_millis: u64,
    ) -> Result<WorkerPageReceipt, WorkerRpcError> {
        match self
            .exchange(WorkerRpcRequest::ActivatePage {
                fence,
                page_id,
                now_unix_millis,
            })
            .await?
        {
            WorkerRpcResponse::Page(receipt) => Ok(receipt),
            WorkerRpcResponse::Failure(failure) => Err(WorkerRpcError::Remote(failure)),
            _ => Err(WorkerRpcError::Protocol),
        }
    }

    pub async fn close_page(
        &self,
        fence: WorkerSessionFence,
        page_id: PageId,
        now_unix_millis: u64,
    ) -> Result<WorkerPageReceipt, WorkerRpcError> {
        match self
            .exchange(WorkerRpcRequest::ClosePage {
                fence,
                page_id,
                now_unix_millis,
            })
            .await?
        {
            WorkerRpcResponse::PageClosed(receipt) => Ok(receipt),
            WorkerRpcResponse::Failure(failure) => Err(WorkerRpcError::Remote(failure)),
            _ => Err(WorkerRpcError::Protocol),
        }
    }

    pub async fn execute_action(
        &self,
        request: WorkerRpcRequest,
    ) -> Result<WorkerActionReceipt, WorkerRpcError> {
        let expected = match &request {
            WorkerRpcRequest::SubmitAction {
                fence,
                action_id,
                action_sequence,
                idempotency_key,
                canonical_request_hash,
                kind,
                ..
            } => (
                fence.clone(),
                action_id.clone(),
                *action_sequence,
                idempotency_key.clone(),
                *canonical_request_hash,
                *kind,
            ),
            _ => return Err(WorkerRpcError::InvalidRequest),
        };
        match self.exchange(request).await? {
            WorkerRpcResponse::Action(receipt)
                if (
                    receipt.fence.clone(),
                    receipt.action_id.clone(),
                    receipt.action_sequence,
                    receipt.idempotency_key.clone(),
                    receipt.canonical_request_hash,
                    receipt.kind,
                ) == expected =>
            {
                Ok(receipt)
            }
            WorkerRpcResponse::Action(_) => Err(WorkerRpcError::Protocol),
            WorkerRpcResponse::Failure(failure) => Err(WorkerRpcError::Remote(failure)),
            _ => Err(WorkerRpcError::Protocol),
        }
    }

    pub async fn get_action(
        &self,
        fence: WorkerSessionFence,
        action_id: ActionId,
    ) -> Result<WorkerActionReceipt, WorkerRpcError> {
        match self
            .exchange(WorkerRpcRequest::GetAction { fence, action_id })
            .await?
        {
            WorkerRpcResponse::Action(receipt) => Ok(receipt),
            WorkerRpcResponse::Failure(failure) => Err(WorkerRpcError::Remote(failure)),
            _ => Err(WorkerRpcError::Protocol),
        }
    }

    pub async fn cancel_action(
        &self,
        fence: WorkerSessionFence,
        action_id: ActionId,
        now_unix_millis: u64,
    ) -> Result<WorkerActionReceipt, WorkerRpcError> {
        match self
            .exchange(WorkerRpcRequest::CancelAction {
                fence,
                action_id,
                now_unix_millis,
            })
            .await?
        {
            WorkerRpcResponse::Action(receipt) => Ok(receipt),
            WorkerRpcResponse::Failure(failure) => Err(WorkerRpcError::Remote(failure)),
            _ => Err(WorkerRpcError::Protocol),
        }
    }

    pub async fn resolve_action(
        &self,
        fence: WorkerSessionFence,
        action_id: ActionId,
        resolution: ResolutionKind,
        resolved_by: PrincipalId,
        basis: String,
        now_unix_millis: u64,
    ) -> Result<WorkerActionReceipt, WorkerRpcError> {
        match self
            .exchange(WorkerRpcRequest::ResolveAction {
                fence,
                action_id,
                resolution,
                resolved_by,
                basis,
                now_unix_millis,
            })
            .await?
        {
            WorkerRpcResponse::Action(receipt) => Ok(receipt),
            WorkerRpcResponse::Failure(failure) => Err(WorkerRpcError::Remote(failure)),
            _ => Err(WorkerRpcError::Protocol),
        }
    }

    pub async fn store_artifact(
        &self,
        request: WorkerRpcRequest,
    ) -> Result<WorkerArtifactReceipt, WorkerRpcError> {
        if !matches!(request, WorkerRpcRequest::StoreArtifact { .. }) {
            return Err(WorkerRpcError::InvalidRequest);
        }
        match self.exchange(request).await? {
            WorkerRpcResponse::ArtifactStored(receipt) => Ok(receipt),
            WorkerRpcResponse::Failure(failure) => Err(WorkerRpcError::Remote(failure)),
            _ => Err(WorkerRpcError::Protocol),
        }
    }

    pub async fn get_artifact(
        &self,
        fence: WorkerSessionFence,
        artifact_id: ArtifactId,
    ) -> Result<WorkerArtifactReceipt, WorkerRpcError> {
        match self
            .exchange(WorkerRpcRequest::GetArtifact { fence, artifact_id })
            .await?
        {
            WorkerRpcResponse::Artifact(receipt) => Ok(receipt),
            WorkerRpcResponse::Failure(failure) => Err(WorkerRpcError::Remote(failure)),
            _ => Err(WorkerRpcError::Protocol),
        }
    }

    pub async fn decide_approval(
        &self,
        request: WorkerRpcRequest,
    ) -> Result<WorkerApprovalReceipt, WorkerRpcError> {
        if !matches!(request, WorkerRpcRequest::DecideApproval { .. }) {
            return Err(WorkerRpcError::InvalidRequest);
        }
        match self.exchange(request).await? {
            WorkerRpcResponse::Approval(receipt) => Ok(receipt),
            WorkerRpcResponse::Failure(failure) => Err(WorkerRpcError::Remote(failure)),
            _ => Err(WorkerRpcError::Protocol),
        }
    }

    pub async fn get_approval(
        &self,
        fence: WorkerSessionFence,
        approval_id: ApprovalId,
    ) -> Result<WorkerApprovalReceipt, WorkerRpcError> {
        match self
            .exchange(WorkerRpcRequest::GetApproval { fence, approval_id })
            .await?
        {
            WorkerRpcResponse::Approval(receipt) => Ok(receipt),
            WorkerRpcResponse::Failure(failure) => Err(WorkerRpcError::Remote(failure)),
            _ => Err(WorkerRpcError::Protocol),
        }
    }

    pub async fn list_approvals(
        &self,
        fence: WorkerSessionFence,
    ) -> Result<Vec<WorkerApprovalReceipt>, WorkerRpcError> {
        match self
            .exchange(WorkerRpcRequest::ListApprovals { fence })
            .await?
        {
            WorkerRpcResponse::Approvals(receipts) => Ok(receipts),
            WorkerRpcResponse::Failure(failure) => Err(WorkerRpcError::Remote(failure)),
            _ => Err(WorkerRpcError::Protocol),
        }
    }
}

struct BlockingRequest {
    request: WorkerRpcRequest,
    response: std_mpsc::SyncSender<Result<WorkerRpcResponse, WorkerRpcError>>,
}

#[derive(Debug, Eq, PartialEq)]
pub enum WorkerRpcEnqueueError {
    Full(Box<WorkerRpcRequest>),
    Closed(Box<WorkerRpcRequest>),
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum WorkerRpcCompletionError {
    #[error("worker RPC exchange failed after queue handoff: {0}")]
    Exchange(WorkerRpcError),
    #[error("worker RPC response timed out after queue handoff")]
    Timeout,
    #[error("worker RPC response channel disconnected after queue handoff")]
    Disconnected,
}

pub struct PendingWorkerRpc {
    receiver: std_mpsc::Receiver<Result<WorkerRpcResponse, WorkerRpcError>>,
    response_timeout: Duration,
}

impl PendingWorkerRpc {
    pub fn wait(self) -> Result<WorkerRpcResponse, WorkerRpcCompletionError> {
        self.receiver
            .recv_timeout(self.response_timeout)
            .map_err(|error| match error {
                std_mpsc::RecvTimeoutError::Timeout => WorkerRpcCompletionError::Timeout,
                std_mpsc::RecvTimeoutError::Disconnected => WorkerRpcCompletionError::Disconnected,
            })?
            .map_err(WorkerRpcCompletionError::Exchange)
    }
}

#[derive(Clone)]
pub struct WorkerRpcBlockingClient {
    sender: mpsc::Sender<BlockingRequest>,
    response_timeout: Duration,
}

impl WorkerRpcBlockingClient {
    fn spawn(
        client: WorkerRpcClient,
        queue_capacity: usize,
        max_in_flight: usize,
    ) -> Result<Self, WorkerRpcError> {
        if queue_capacity == 0
            || queue_capacity > 65_536
            || max_in_flight == 0
            || max_in_flight > 1_024
        {
            return Err(WorkerRpcError::InvalidConfig);
        }
        let response_timeout = client.request_timeout.saturating_mul(2);
        let (sender, mut receiver) = mpsc::channel::<BlockingRequest>(queue_capacity);
        std::thread::Builder::new()
            .name("browserd-worker-rpc-io".to_owned())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build();
                let Ok(runtime) = runtime else {
                    while let Some(request) = receiver.blocking_recv() {
                        let _ = request.response.send(Err(WorkerRpcError::Runtime));
                    }
                    return;
                };
                runtime.block_on(async move {
                    let mut exchanges = JoinSet::new();
                    loop {
                        if exchanges.len() >= max_in_flight {
                            let _completed = exchanges.join_next().await;
                            continue;
                        }
                        tokio::select! {
                            biased;
                            completed = exchanges.join_next(), if !exchanges.is_empty() => {
                                let _completed = completed;
                            }
                            request = receiver.recv() => {
                                let Some(request) = request else {
                                    break;
                                };
                                let client = client.clone();
                                exchanges.spawn(async move {
                                    let result = client.exchange(request.request).await;
                                    let _ = request.response.send(result);
                                });
                            }
                        }
                    }
                    while exchanges.join_next().await.is_some() {}
                });
            })
            .map_err(|error| WorkerRpcError::Io(error.to_string()))?;
        Ok(Self {
            sender,
            response_timeout,
        })
    }

    pub fn request_blocking(
        &self,
        request: WorkerRpcRequest,
    ) -> Result<WorkerRpcResponse, WorkerRpcError> {
        let pending = self.enqueue(request).map_err(|error| match error {
            WorkerRpcEnqueueError::Full(_) => WorkerRpcError::QueueFull,
            WorkerRpcEnqueueError::Closed(_) => WorkerRpcError::Runtime,
        })?;
        pending.wait().map_err(|error| match error {
            WorkerRpcCompletionError::Exchange(error) => error,
            WorkerRpcCompletionError::Timeout => WorkerRpcError::Timeout,
            WorkerRpcCompletionError::Disconnected => WorkerRpcError::Runtime,
        })
    }

    pub fn enqueue(
        &self,
        request: WorkerRpcRequest,
    ) -> Result<PendingWorkerRpc, WorkerRpcEnqueueError> {
        let (response, receiver) = std_mpsc::sync_channel(1);
        self.sender
            .try_send(BlockingRequest { request, response })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(request) => {
                    WorkerRpcEnqueueError::Full(Box::new(request.request))
                }
                mpsc::error::TrySendError::Closed(request) => {
                    WorkerRpcEnqueueError::Closed(Box::new(request.request))
                }
            })?;
        Ok(PendingWorkerRpc {
            receiver,
            response_timeout: self.response_timeout,
        })
    }

    pub fn create_session(
        &self,
        request: WorkerCreateSessionRequest,
    ) -> Result<WorkerCreateSessionReceipt, WorkerRpcError> {
        match self.request_blocking(WorkerRpcRequest::CreateSession(request))? {
            WorkerRpcResponse::SessionCreated(receipt) => Ok(receipt),
            WorkerRpcResponse::Failure(failure) => Err(WorkerRpcError::Remote(failure)),
            _ => Err(WorkerRpcError::Protocol),
        }
    }

    pub fn probe(&self, expected_worker_epoch: u64) -> Result<WorkerProbeReceipt, WorkerRpcError> {
        if expected_worker_epoch == 0 {
            return Err(WorkerRpcError::InvalidRequest);
        }
        match self.request_blocking(WorkerRpcRequest::Probe {
            expected_worker_epoch,
        })? {
            WorkerRpcResponse::Probe(receipt)
                if receipt.ready && receipt.worker_epoch == expected_worker_epoch =>
            {
                Ok(receipt)
            }
            WorkerRpcResponse::Probe(_) => Err(WorkerRpcError::Protocol),
            WorkerRpcResponse::Failure(failure) => Err(WorkerRpcError::Remote(failure)),
            _ => Err(WorkerRpcError::Protocol),
        }
    }
}

async fn handle_connection<H: WorkerRpcHandler>(
    mut stream: UnixStream,
    config: WorkerRpcConfig,
    handler: Arc<H>,
) -> Result<(), WorkerRpcError> {
    authenticate_peer(&stream, config.allowed_uid)?;
    let request = tokio::time::timeout(
        config.request_timeout,
        read_frame(&mut stream, config.max_frame_bytes),
    )
    .await
    .map_err(|_| WorkerRpcError::Timeout)??;
    let request: RequestEnvelope = serde_json::from_slice(&request)
        .map_err(|error| WorkerRpcError::Serialization(error.to_string()))?;
    if request.protocol_version != WORKER_RPC_PROTOCOL_VERSION {
        return Err(WorkerRpcError::Protocol);
    }
    let request_id = request.request_id;
    let handler_task = tokio::spawn(async move { handler.handle(request.request).await });
    let response = match tokio::time::timeout(config.request_timeout, handler_task).await {
        Ok(Ok(response)) => response,
        Ok(Err(_)) => WorkerRpcResponse::Failure(WorkerRpcFailure::new(
            WorkerRpcFailureCode::Internal,
            "worker RPC handler failed",
        )),
        Err(_) => WorkerRpcResponse::Failure(WorkerRpcFailure::new(
            WorkerRpcFailureCode::Timeout,
            "worker RPC handler continues asynchronously",
        )),
    };
    let encoded = serde_json::to_vec(&ResponseEnvelope {
        protocol_version: WORKER_RPC_PROTOCOL_VERSION,
        request_id,
        response,
    })
    .map_err(|error| WorkerRpcError::Serialization(error.to_string()))?;
    tokio::time::timeout(
        config.request_timeout,
        write_frame(&mut stream, &encoded, config.max_frame_bytes),
    )
    .await
    .map_err(|_| WorkerRpcError::Timeout)?
}

fn authenticate_peer(stream: &UnixStream, expected_uid: u32) -> Result<(), WorkerRpcError> {
    let credentials = stream
        .peer_cred()
        .map_err(|error| WorkerRpcError::Io(error.to_string()))?;
    if credentials.uid() == expected_uid {
        Ok(())
    } else {
        Err(WorkerRpcError::UnauthorizedPeer)
    }
}

async fn read_frame(
    stream: &mut UnixStream,
    max_frame_bytes: usize,
) -> Result<Vec<u8>, WorkerRpcError> {
    let mut length = [0_u8; 4];
    stream
        .read_exact(&mut length)
        .await
        .map_err(|error| WorkerRpcError::Io(error.to_string()))?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > max_frame_bytes {
        return Err(WorkerRpcError::FrameTooLarge);
    }
    let mut frame = vec![0_u8; length];
    stream
        .read_exact(&mut frame)
        .await
        .map_err(|error| WorkerRpcError::Io(error.to_string()))?;
    Ok(frame)
}

async fn write_frame(
    stream: &mut UnixStream,
    frame: &[u8],
    max_frame_bytes: usize,
) -> Result<(), WorkerRpcError> {
    if frame.is_empty() || frame.len() > max_frame_bytes {
        return Err(WorkerRpcError::FrameTooLarge);
    }
    let length = u32::try_from(frame.len()).map_err(|_| WorkerRpcError::FrameTooLarge)?;
    stream
        .write_all(&length.to_be_bytes())
        .await
        .map_err(|error| WorkerRpcError::Io(error.to_string()))?;
    stream
        .write_all(frame)
        .await
        .map_err(|error| WorkerRpcError::Io(error.to_string()))
}

const fn session_lifecycle(lifecycle: SessionLifecycle) -> WorkerSessionLifecycle {
    match lifecycle {
        SessionLifecycle::Creating => WorkerSessionLifecycle::Creating,
        SessionLifecycle::Ready => WorkerSessionLifecycle::Ready,
        SessionLifecycle::Closing => WorkerSessionLifecycle::Closing,
        SessionLifecycle::Closed => WorkerSessionLifecycle::Closed,
        SessionLifecycle::Failed => WorkerSessionLifecycle::Failed,
    }
}

const fn action_status(status: ActionStatus) -> WorkerActionStatus {
    match status {
        ActionStatus::PendingApproval => WorkerActionStatus::PendingApproval,
        ActionStatus::Queued => WorkerActionStatus::Queued,
        ActionStatus::Running => WorkerActionStatus::Running,
        ActionStatus::Succeeded => WorkerActionStatus::Succeeded,
        ActionStatus::FailedKnown => WorkerActionStatus::FailedKnown,
        ActionStatus::CancelledBeforeDispatch => WorkerActionStatus::CancelledBeforeDispatch,
        ActionStatus::CancelledConfirmed => WorkerActionStatus::CancelledConfirmed,
        ActionStatus::OutcomeUnknown => WorkerActionStatus::OutcomeUnknown,
    }
}

fn page_receipt(fence: &WorkerSessionFence, snapshot: WorkerPageSnapshot) -> WorkerPageReceipt {
    WorkerPageReceipt {
        fence: fence.clone(),
        page_id: snapshot.page_id,
        active: snapshot.active,
        target_incarnation: snapshot.target_incarnation,
        document_epoch: snapshot.document_epoch,
        url_revision: snapshot.url_revision,
    }
}

fn action_receipt(
    fence: &WorkerSessionFence,
    snapshot: WorkerActionSnapshot,
) -> WorkerActionReceipt {
    WorkerActionReceipt {
        fence: fence.clone(),
        action_id: snapshot.action_id,
        action_sequence: snapshot.action_sequence,
        idempotency_key: snapshot.idempotency_key,
        canonical_request_hash: snapshot.canonical_request_hash,
        kind: snapshot.kind,
        status: action_status(snapshot.status),
        dispatch_acknowledged: snapshot.dispatch_acknowledged,
        approval_decision: snapshot.approval_decision,
        terminal_detail: snapshot.terminal_detail,
        result: snapshot.result,
        resolution: snapshot.resolution,
    }
}

const fn artifact_state(state: ArtifactState) -> WorkerArtifactState {
    match state {
        ArtifactState::Uploading => WorkerArtifactState::Uploading,
        ArtifactState::Stored => WorkerArtifactState::Stored,
        ArtifactState::Scanning => WorkerArtifactState::Scanning,
        ArtifactState::Available => WorkerArtifactState::Available,
        ArtifactState::Quarantined => WorkerArtifactState::Quarantined,
        ArtifactState::Rejected => WorkerArtifactState::Rejected,
        ArtifactState::Generating => WorkerArtifactState::Generating,
        ArtifactState::Finalizing => WorkerArtifactState::Finalizing,
        ArtifactState::Failed => WorkerArtifactState::Failed,
        ArtifactState::Deleting => WorkerArtifactState::Deleting,
        ArtifactState::Deleted => WorkerArtifactState::Deleted,
    }
}

const fn artifact_source(source: ArtifactContentSource) -> WorkerArtifactSource {
    match source {
        ArtifactContentSource::ClientUpload => WorkerArtifactSource::ClientUpload,
        ArtifactContentSource::BrowserDownload => WorkerArtifactSource::BrowserDownload,
        ArtifactContentSource::Generated => WorkerArtifactSource::Generated,
    }
}

fn artifact_receipt(
    fence: &WorkerSessionFence,
    snapshot: WorkerArtifactSnapshot,
) -> WorkerArtifactReceipt {
    WorkerArtifactReceipt {
        fence: fence.clone(),
        artifact_id: snapshot.artifact_id,
        state: artifact_state(snapshot.state),
        size_bytes: snapshot.size_bytes,
        checksum_sha256: snapshot.checksum_sha256,
        content_type: snapshot.content_type,
        source: artifact_source(snapshot.source),
        origin: snapshot.origin,
        object_generation: *snapshot.object_generation.as_bytes(),
    }
}

fn approval_receipt(
    fence: &WorkerSessionFence,
    snapshot: WorkerApprovalSnapshot,
) -> WorkerApprovalReceipt {
    let state = match snapshot.state {
        ApprovalState::Pending => WorkerApprovalState::Pending,
        ApprovalState::Approved { by } => WorkerApprovalState::Approved { by },
        ApprovalState::Denied { by } => WorkerApprovalState::Denied { by },
        ApprovalState::Expired => WorkerApprovalState::Expired,
    };
    WorkerApprovalReceipt {
        fence: fence.clone(),
        approval_id: snapshot.approval_id,
        action_id: snapshot.action_id,
        state,
        proposal: WorkerCanonicalActionProposal::from_canonical(&snapshot.proposal),
        proposal_hash: *snapshot.proposal_hash.as_bytes(),
    }
}

fn worker_failure(error: WorkerError) -> WorkerRpcFailure {
    let code = match error {
        WorkerError::UnauthorizedPeer => WorkerRpcFailureCode::Unauthorized,
        WorkerError::StaleFence => WorkerRpcFailureCode::FenceMismatch,
        WorkerError::SessionNotFound
        | WorkerError::PageNotFound
        | WorkerError::ActionNotFound
        | WorkerError::ApprovalNotFound
        | WorkerError::ArtifactNotFound => WorkerRpcFailureCode::NotFound,
        WorkerError::IdempotencyConflict
        | WorkerError::InvalidActionTransition
        | WorkerError::InvalidApprovalTransition
        | WorkerError::ApprovalEvidenceMismatch
        | WorkerError::ApprovalPolicy(_) => WorkerRpcFailureCode::Conflict,
        WorkerError::CapacityExceeded | WorkerError::QueueFull => WorkerRpcFailureCode::Capacity,
        WorkerError::NotReady | WorkerError::Draining | WorkerError::Stopped => {
            WorkerRpcFailureCode::NotReady
        }
        WorkerError::DurabilityUnavailable => WorkerRpcFailureCode::Durability,
        WorkerError::DependencyUnavailable | WorkerError::CleanupFailed => {
            WorkerRpcFailureCode::Dependency
        }
        WorkerError::InvalidConfiguration => WorkerRpcFailureCode::InvalidRequest,
        WorkerError::StateUnavailable => WorkerRpcFailureCode::Internal,
    };
    WorkerRpcFailure::new(code, format!("{error:?}"))
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum WorkerRpcError {
    #[error("invalid worker RPC configuration")]
    InvalidConfig,
    #[error("worker RPC peer is unauthorized")]
    UnauthorizedPeer,
    #[error("worker RPC frame exceeds the configured bound")]
    FrameTooLarge,
    #[error("worker RPC request is invalid")]
    InvalidRequest,
    #[error("worker RPC protocol violation")]
    Protocol,
    #[error("worker RPC request timed out")]
    Timeout,
    #[error("worker RPC blocking queue is full")]
    QueueFull,
    #[error("worker RPC I/O runtime is unavailable")]
    Runtime,
    #[error("worker RPC I/O error: {0}")]
    Io(String),
    #[error("worker RPC serialization error: {0}")]
    Serialization(String),
    #[error("worker RPC remote failure: {0:?}")]
    Remote(WorkerRpcFailure),
}

#[cfg(test)]
mod blocking_client_tests {
    use super::*;

    #[test]
    fn closed_ingress_returns_the_original_unhanded_request() {
        let (sender, receiver) = mpsc::channel(1);
        drop(receiver);
        let client = WorkerRpcBlockingClient {
            sender,
            response_timeout: Duration::from_secs(1),
        };
        let request = WorkerRpcRequest::Probe {
            expected_worker_epoch: 41,
        };

        assert!(matches!(
            client.enqueue(request.clone()),
            Err(WorkerRpcEnqueueError::Closed(returned)) if *returned == request
        ));
    }
}
