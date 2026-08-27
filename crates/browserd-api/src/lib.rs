//! Transport-neutral v1 API contracts and an in-memory coordination surface.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration as StdDuration, Instant};

use base64::Engine as _;
use browserd_actions::{
    AcceptDecision, ActionKind, ActionLedger, ActionLedgerError, ActionRequest, ActionSnapshot,
    CanonicalRequestHash as ActionCanonicalRequestHash, DurableActionJournal,
    IdempotencyKey as ActionIdempotencyKey, ResolutionKind,
};
use browserd_artifacts::{ArtifactKey, ArtifactState, DownloadToken};
use browserd_auth::AuthenticatedPrincipal;
use browserd_coordination::{
    CanonicalRequestHash as DurableRequestHash, ClaimCreateOperation, ClaimOutcome,
    CoordinationBlockingClient, CoordinationError, CreateOperationError, CreateOperationResult,
    CreateOperationSnapshot as DurableOperationSnapshot, DispatchLeaseToken, DownstreamDedupeKey,
    OperationMutation, RecoverableCreateIntent,
};
use browserd_core::{
    ActionId, ApprovalId, ArtifactId, CreateOperationState, ErrorCode, IsolationProfile,
    OperationId, PageId, SessionId, SessionLifecycle, TenantId, WorkerId,
};
use browserd_operations::{
    CanonicalRequestHash, CreateSessionOperation, IdempotencyClaim, IdempotencyKey,
    IdempotencyRegistry,
};
use browserd_policy::{ApprovalDecision, ApprovalState, CanonicalActionProposal};
use browserd_session::{ClientBinding, OwnershipFence, ReconnectToken, SessionTime};
use browserd_viewer::{ViewerScopes, ViewerTicket};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;
use uuid::{Uuid, Version};

pub use browserd_core::{ResponseRepresentation, RetryClass};

pub const PUBLIC_ROUTES: &[&str] = &[
    "POST /v1/sessions",
    "GET /v1/sessions",
    "GET /v1/operations/{operation_id}",
    "DELETE /v1/operations/{operation_id}",
    "GET /v1/sessions/{session_id}",
    "DELETE /v1/sessions/{session_id}",
    "POST /v1/sessions/{session_id}/reconnect",
    "POST /v1/sessions/{session_id}/transfer",
    "GET /v1/sessions/{session_id}/pages",
    "POST /v1/sessions/{session_id}/pages",
    "DELETE /v1/sessions/{session_id}/pages/{page_id}",
    "POST /v1/sessions/{session_id}/pages/{page_id}/activate",
    "POST /v1/sessions/{session_id}/actions",
    "GET /v1/sessions/{session_id}/actions/{action_id}",
    "DELETE /v1/sessions/{session_id}/actions/{action_id}",
    "POST /v1/sessions/{session_id}/actions/{action_id}/resolve",
    "GET /v1/events",
    "POST /v1/sessions/{session_id}/viewer-ticket",
    "POST /v1/sessions/{session_id}/artifacts/uploads",
    "GET /v1/sessions/{session_id}/artifacts/{artifact_id}",
    "POST /v1/sessions/{session_id}/artifacts/{artifact_id}/download",
    "GET /v1/approvals",
    "GET /v1/approvals/{approval_id}",
    "POST /v1/approvals/{approval_id}/decision",
];
pub const PUBLIC_V1_ROUTES: &[&str] = PUBLIC_ROUTES;

pub const MAX_SESSION_METADATA_ENTRIES: usize = 32;
pub const MAX_SESSION_METADATA_KEY_BYTES: usize = 64;
pub const MAX_SESSION_METADATA_VALUE_BYTES: usize = 256;
pub const MAX_SESSION_METADATA_BYTES: usize = 4_096;
pub const MAX_SESSION_VIEWPORT_PIXELS: u64 = 16_777_216;
pub const MAX_ACTION_BODY_BYTES: usize = 131_072;
pub const MAX_ACTION_SELECTOR_BYTES: usize = 8_192;
pub const MAX_EVALUATE_SOURCE_BYTES: usize = 65_536;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApiVersion {
    V1,
}

impl ApiVersion {
    pub fn parse(value: &str) -> Result<Self, ApiError> {
        match value {
            "/v1" => Ok(Self::V1),
            _ => Err(ApiError::invalid_request("unsupported API version")),
        }
    }
}

pub fn validate_idempotency_key(value: &str) -> Result<Uuid, ApiError> {
    let key = Uuid::parse_str(value)
        .map_err(|_| ApiError::invalid_request("Idempotency-Key must be a UUID"))?;
    if key.is_nil() || value != key.hyphenated().to_string() {
        return Err(ApiError::invalid_request(
            "Idempotency-Key must be a canonical non-nil UUID",
        ));
    }
    Ok(key)
}

pub fn validate_last_event_id(value: &str) -> Result<Uuid, ApiError> {
    let event_id = Uuid::parse_str(value)
        .map_err(|_| ApiError::invalid_request("Last-Event-ID must be a UUIDv7"))?;
    if event_id.get_version() != Some(Version::SortRand)
        || value != event_id.hyphenated().to_string()
    {
        return Err(ApiError::invalid_request("Last-Event-ID must be a UUIDv7"));
    }
    Ok(event_id)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ViewportRequest {
    pub width: u32,
    pub height: u32,
    pub device_scale_factor: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IsolationRequest {
    SharedContext,
    TenantDedicatedShard,
    DedicatedProcess,
    DedicatedWorker,
}

impl From<IsolationRequest> for IsolationProfile {
    fn from(value: IsolationRequest) -> Self {
        match value {
            IsolationRequest::SharedContext => Self::SharedContext,
            IsolationRequest::TenantDedicatedShard => Self::TenantDedicatedShard,
            IsolationRequest::DedicatedProcess => Self::DedicatedProcess,
            IsolationRequest::DedicatedWorker => Self::DedicatedWorker,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionCreateRequest {
    pub isolation: IsolationRequest,
    pub workload_class_hint: String,
    pub viewport: ViewportRequest,
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
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}

#[derive(Clone, Debug)]
pub struct SessionCreateDispatch {
    operation_id: OperationId,
    downstream_dedupe_key: DownstreamDedupeKey,
    canonical_request_hash: [u8; 32],
    accepted_at: DateTime<Utc>,
    admission_deadline: DateTime<Utc>,
    dispatch_generation: u64,
    runtime_timeout: StdDuration,
}

impl SessionCreateDispatch {
    #[must_use]
    pub const fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    #[must_use]
    pub const fn downstream_dedupe_key(&self) -> DownstreamDedupeKey {
        self.downstream_dedupe_key
    }

    #[must_use]
    pub const fn canonical_request_hash(&self) -> &[u8; 32] {
        &self.canonical_request_hash
    }

    #[must_use]
    pub const fn accepted_at(&self) -> DateTime<Utc> {
        self.accepted_at
    }

    #[must_use]
    pub const fn admission_deadline(&self) -> DateTime<Utc> {
        self.admission_deadline
    }

    #[must_use]
    pub const fn dispatch_generation(&self) -> u64 {
        self.dispatch_generation
    }
    #[must_use]
    pub const fn runtime_timeout(&self) -> StdDuration {
        self.runtime_timeout
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateAuthority {
    tenant_id: TenantId,
    principal_id: browserd_core::PrincipalId,
}

impl CreateAuthority {
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }
    #[must_use]
    pub const fn principal_id(&self) -> &browserd_core::PrincipalId {
        &self.principal_id
    }
}

impl SessionCreateRequest {
    pub fn validate(&self) -> Result<(), ApiError> {
        let metadata_bytes = self
            .metadata
            .iter()
            .try_fold(0_usize, |total, (key, value)| {
                total.checked_add(key.len())?.checked_add(value.len())
            });
        let viewport_pixels =
            u64::from(self.viewport.width).checked_mul(u64::from(self.viewport.height));
        if self.viewport.width == 0
            || self.viewport.height == 0
            || self.viewport.width > 16_384
            || self.viewport.height > 16_384
            || viewport_pixels.is_none_or(|pixels| pixels > MAX_SESSION_VIEWPORT_PIXELS)
            || !(1..=8).contains(&self.viewport.device_scale_factor)
            || self.ttl_seconds == 0
            || self.idle_timeout_seconds == 0
            || self.idle_timeout_seconds > self.ttl_seconds
            || self.workload_class_hint.trim().is_empty()
            || self.workload_class_hint.len() > 128
            || self.workload_class_hint.chars().any(char::is_control)
            || self.locale.trim().is_empty()
            || self.locale.len() > 64
            || self.locale.chars().any(char::is_control)
            || self.timezone.trim().is_empty()
            || self.timezone.len() > 128
            || self.timezone.chars().any(char::is_control)
            || self.network_policy_id.trim().is_empty()
            || self.network_policy_id.len() > 256
            || self.network_policy_id.chars().any(char::is_control)
            || self.network_class.trim().is_empty()
            || self.network_class.len() > 64
            || self.network_class.chars().any(char::is_control)
            || self.feature_profile.trim().is_empty()
            || self.feature_profile.len() > 128
            || self.feature_profile.chars().any(char::is_control)
            || self.user_agent.as_ref().is_some_and(|value| {
                value.trim().is_empty()
                    || value.len() > 4_096
                    || value.chars().any(char::is_control)
            })
            || self.checkpoint_ref.as_ref().is_some_and(|value| {
                value.trim().is_empty()
                    || value.len() > 1_024
                    || value.chars().any(char::is_control)
            })
            || !matches!(self.dialog_policy.as_str(), "auto_dismiss" | "hold")
            || self.metadata.len() > MAX_SESSION_METADATA_ENTRIES
            || self.metadata.keys().any(|key| {
                key.is_empty()
                    || key.len() > MAX_SESSION_METADATA_KEY_BYTES
                    || key.trim() != key
                    || key.chars().any(char::is_control)
            })
            || self.metadata.values().any(|value| {
                value.len() > MAX_SESSION_METADATA_VALUE_BYTES
                    || value.chars().any(char::is_control)
            })
            || metadata_bytes.is_none_or(|bytes| bytes > MAX_SESSION_METADATA_BYTES)
        {
            return Err(ApiError::invalid_request(
                "session create request violates v1 bounds",
            ));
        }
        Ok(())
    }
}

pub fn decode_session_create(json: &str) -> Result<SessionCreateRequest, ApiError> {
    let request: SessionCreateRequest = serde_json::from_str(json)
        .map_err(|_| ApiError::invalid_request("invalid session create body"))?;
    request.validate()?;
    Ok(request)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ActionPayload {
    Navigate {
        url: String,
        wait_until: WaitUntil,
    },
    Reload,
    GoBack,
    GoForward,
    Click {
        node_ref: String,
    },
    DoubleClick {
        node_ref: String,
    },
    Hover {
        node_ref: String,
    },
    Fill {
        node_ref: String,
        value: String,
    },
    FillSecret {
        node_ref: String,
        secret_ref: String,
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
    SelectOption {
        node_ref: String,
        values: Vec<String>,
    },
    SetFiles {
        node_ref: String,
        artifact_ids: Vec<ArtifactId>,
    },
    Focus {
        node_ref: String,
    },
    Blur {
        node_ref: String,
    },
    Check {
        node_ref: String,
    },
    Uncheck {
        node_ref: String,
    },
    HandleDialog {
        accept: bool,
        prompt_text: Option<String>,
    },
    Snapshot,
    GetText {
        node_ref: String,
    },
    GetHtml {
        node_ref: Option<String>,
    },
    GetUrl,
    GetTitle,
    GetAttribute {
        node_ref: String,
        name: String,
    },
    GetProperties {
        node_ref: String,
    },
    GetComputedStyle {
        node_ref: String,
    },
    QueryAll {
        selector: String,
    },
    ExtractTable {
        node_ref: String,
    },
    NewPage {
        url: Option<String>,
    },
    ClosePage,
    ActivatePage,
    WaitFor {
        condition: WaitCondition,
    },
    Evaluate {
        expression: String,
    },
    Screenshot,
    Pdf,
    Scrape,
    Checkpoint,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WaitUntil {
    Domcontentloaded,
    Load,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum WaitCondition {
    SelectorAttached { selector: String },
    SelectorVisible { selector: String },
    SelectorHidden { selector: String },
    UrlMatches { pattern: String },
    LoadState { state: WaitUntil },
    NetworkQuiet { quiet_ms: u64 },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionSubmitRequest {
    pub page_id: PageId,
    pub if_session_incarnation: u64,
    pub execution_timeout_ms: u64,
    pub action: ActionPayload,
}

impl ActionSubmitRequest {
    pub fn validate(&self) -> Result<(), ApiError> {
        let canonical_size = serde_json::to_vec(self)
            .map_err(|_| ApiError::invalid_request("action request violates v1 bounds"))?
            .len();
        if self.if_session_incarnation == 0
            || self.execution_timeout_ms == 0
            || self.execution_timeout_ms > 300_000
            || canonical_size > MAX_ACTION_BODY_BYTES
        {
            return Err(ApiError::invalid_request(
                "action request violates v1 bounds",
            ));
        }
        let valid_node_ref = |value: &str| {
            !value.is_empty()
                && value.trim() == value
                && value.len() <= 1_024
                && !value.chars().any(char::is_control)
        };
        let valid_selector = |value: &str| {
            !value.is_empty()
                && value.len() <= MAX_ACTION_SELECTOR_BYTES
                && !value.chars().any(char::is_control)
        };
        let valid_url = |value: &str| {
            value.len() <= MAX_ACTION_SELECTOR_BYTES
                && (value == "about:blank"
                    || Url::parse(value)
                        .map(|url| matches!(url.scheme(), "http" | "https"))
                        .unwrap_or(false))
        };
        let invalid = match &self.action {
            ActionPayload::Navigate { url, .. } => !valid_url(url),
            ActionPayload::Click { node_ref }
            | ActionPayload::DoubleClick { node_ref }
            | ActionPayload::Hover { node_ref }
            | ActionPayload::Focus { node_ref }
            | ActionPayload::Blur { node_ref }
            | ActionPayload::Check { node_ref }
            | ActionPayload::Uncheck { node_ref }
            | ActionPayload::GetText { node_ref }
            | ActionPayload::GetProperties { node_ref }
            | ActionPayload::GetComputedStyle { node_ref }
            | ActionPayload::ExtractTable { node_ref } => !valid_node_ref(node_ref),
            ActionPayload::Fill { node_ref, value } => {
                !valid_node_ref(node_ref) || value.len() > 65_536
            }
            ActionPayload::FillSecret {
                node_ref,
                secret_ref,
            } => {
                !valid_node_ref(node_ref)
                    || secret_ref.is_empty()
                    || secret_ref.trim() != secret_ref
                    || secret_ref.len() > 1_024
                    || secret_ref.chars().any(char::is_control)
            }
            ActionPayload::TypeText { text } => text.is_empty() || text.len() > 65_536,
            ActionPayload::PressKey { key } => {
                key.is_empty() || key.len() > 256 || key.chars().any(char::is_control)
            }
            ActionPayload::Scroll { delta_x, delta_y } => {
                delta_x.unsigned_abs() > 1_000_000 || delta_y.unsigned_abs() > 1_000_000
            }
            ActionPayload::SelectOption { node_ref, values } => {
                !valid_node_ref(node_ref)
                    || values.is_empty()
                    || values.len() > 128
                    || values.iter().any(|value| value.len() > 4_096)
            }
            ActionPayload::SetFiles {
                node_ref,
                artifact_ids,
            } => !valid_node_ref(node_ref) || artifact_ids.is_empty() || artifact_ids.len() > 128,
            ActionPayload::HandleDialog { prompt_text, .. } => prompt_text
                .as_ref()
                .is_some_and(|prompt| prompt.len() > 65_536),
            ActionPayload::GetHtml { node_ref } => node_ref
                .as_ref()
                .is_some_and(|node_ref| !valid_node_ref(node_ref)),
            ActionPayload::GetAttribute { node_ref, name } => {
                !valid_node_ref(node_ref)
                    || name.is_empty()
                    || name.len() > 256
                    || name.chars().any(char::is_control)
            }
            ActionPayload::QueryAll { selector } => !valid_selector(selector),
            ActionPayload::NewPage { url } => url.as_ref().is_some_and(|url| !valid_url(url)),
            ActionPayload::WaitFor { condition } => match condition {
                WaitCondition::SelectorAttached { selector }
                | WaitCondition::SelectorVisible { selector }
                | WaitCondition::SelectorHidden { selector } => !valid_selector(selector),
                WaitCondition::UrlMatches { pattern } => !valid_selector(pattern),
                WaitCondition::LoadState { .. } => false,
                WaitCondition::NetworkQuiet { quiet_ms } => {
                    *quiet_ms == 0 || *quiet_ms > 30_000 || *quiet_ms > self.execution_timeout_ms
                }
            },
            ActionPayload::Evaluate { expression } => {
                expression.trim().is_empty() || expression.len() > MAX_EVALUATE_SOURCE_BYTES
            }
            ActionPayload::Reload
            | ActionPayload::GoBack
            | ActionPayload::GoForward
            | ActionPayload::Snapshot
            | ActionPayload::GetUrl
            | ActionPayload::GetTitle
            | ActionPayload::ClosePage
            | ActionPayload::ActivatePage
            | ActionPayload::Screenshot
            | ActionPayload::Pdf
            | ActionPayload::Scrape
            | ActionPayload::Checkpoint => false,
        };
        if invalid {
            return Err(ApiError::invalid_request(
                "action request violates v1 bounds",
            ));
        }
        Ok(())
    }
}

pub fn decode_action_submit(json: &str) -> Result<ActionSubmitRequest, ApiError> {
    if json.len() > MAX_ACTION_BODY_BYTES {
        return Err(ApiError::invalid_request("invalid action submit body"));
    }
    let request: ActionSubmitRequest = serde_json::from_str(json)
        .map_err(|_| ApiError::invalid_request("invalid action submit body"))?;
    request.validate()?;
    Ok(request)
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionRequestKind {
    ConfirmedExecuted,
    ConfirmedNotExecuted,
    Abandoned,
}

impl From<ResolutionRequestKind> for ResolutionKind {
    fn from(value: ResolutionRequestKind) -> Self {
        match value {
            ResolutionRequestKind::ConfirmedExecuted => Self::ConfirmedExecuted,
            ResolutionRequestKind::ConfirmedNotExecuted => Self::ConfirmedNotExecuted,
            ResolutionRequestKind::Abandoned => Self::Abandoned,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActionResolveBody {
    pub resolution: ResolutionRequestKind,
    pub basis: String,
    pub note: Option<String>,
}

pub fn decode_action_resolve(json: &str) -> Result<ActionResolveBody, ApiError> {
    let request: ActionResolveBody = serde_json::from_str(json)
        .map_err(|_| ApiError::invalid_request("invalid action resolution body"))?;
    if request.basis.trim().is_empty() || request.basis.len() > 4_096 {
        return Err(ApiError::invalid_request("resolution basis is invalid"));
    }
    Ok(request)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GrpcCode {
    Ok,
    InvalidArgument,
    Unauthenticated,
    PermissionDenied,
    NotFound,
    AlreadyExists,
    FailedPrecondition,
    ResourceExhausted,
    Unavailable,
    DeadlineExceeded,
    Internal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApiErrorCode(ErrorCode);

impl From<ErrorCode> for ApiErrorCode {
    fn from(value: ErrorCode) -> Self {
        Self(value)
    }
}

impl ApiErrorCode {
    #[must_use]
    pub const fn core(self) -> ErrorCode {
        self.0
    }

    #[must_use]
    pub fn mapping(self) -> ErrorMapping {
        let semantics = self.0.semantics();
        let grpc_code = match self.0 {
            ErrorCode::InvalidRequest => GrpcCode::InvalidArgument,
            ErrorCode::Unauthenticated => GrpcCode::Unauthenticated,
            ErrorCode::PermissionDenied | ErrorCode::NetworkPolicyDenied => {
                GrpcCode::PermissionDenied
            }
            ErrorCode::SessionNotFound | ErrorCode::OperationNotFound | ErrorCode::PageNotFound => {
                GrpcCode::NotFound
            }
            ErrorCode::IdempotencyConflict => GrpcCode::AlreadyExists,
            ErrorCode::ActionTimeout => GrpcCode::DeadlineExceeded,
            ErrorCode::TenantQuotaExceeded
            | ErrorCode::RateLimited
            | ErrorCode::NetworkBudgetExceeded
            | ErrorCode::ArtifactTooLarge
            | ErrorCode::SnapshotTooLarge
            | ErrorCode::TargetLimitExceeded => GrpcCode::ResourceExhausted,
            ErrorCode::ActionOutcomeUnknown => GrpcCode::Ok,
            ErrorCode::Internal => GrpcCode::Internal,
            ErrorCode::QueueTimeout
            | ErrorCode::GlobalCapacityExceeded
            | ErrorCode::BrowserStartFailed
            | ErrorCode::ContextCreateFailed
            | ErrorCode::TargetBootstrapFailed
            | ErrorCode::BrowserCrashed
            | ErrorCode::WorkerLost
            | ErrorCode::WorkerUnavailable
            | ErrorCode::AuditUnavailable
            | ErrorCode::ActionAdmissionTimeout => GrpcCode::Unavailable,
            ErrorCode::StaleNodeRef
            | ErrorCode::StaleDocumentRef
            | ErrorCode::SnapshotStale
            | ErrorCode::GenerationMismatch
            | ErrorCode::PlacementMismatch
            | ErrorCode::ApprovalStale
            | ErrorCode::SessionControlledByHuman
            | ErrorCode::ReconciliationRequired
            | ErrorCode::ActionResolutionInvalid
            | ErrorCode::SessionExpired => GrpcCode::FailedPrecondition,
        };
        ErrorMapping {
            http_status: semantics.http_statuses()[0],
            grpc_code,
            retry_class: semantics.retry_class(),
            representation: semantics.response_representation(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErrorMapping {
    http_status: u16,
    grpc_code: GrpcCode,
    retry_class: RetryClass,
    representation: ResponseRepresentation,
}

impl ErrorMapping {
    #[must_use]
    pub const fn http_status(self) -> u16 {
        self.http_status
    }

    #[must_use]
    pub const fn grpc_code(self) -> GrpcCode {
        self.grpc_code
    }

    #[must_use]
    pub const fn retry_class(self) -> RetryClass {
        self.retry_class
    }

    #[must_use]
    pub const fn representation(self) -> ResponseRepresentation {
        self.representation
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApiError {
    code: ErrorCode,
    message: String,
    details: BTreeMap<String, String>,
    retryable: bool,
    trace_id: Uuid,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OperationFailure {
    pub code: String,
    pub message: String,
    pub retryable: bool,
    pub details: BTreeMap<String, String>,
}

impl ApiError {
    #[must_use]
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        let retryable = code.semantics().retry_class() != RetryClass::Never;
        Self {
            code,
            message: message.into(),
            details: BTreeMap::new(),
            retryable,
            trace_id: Uuid::now_v7(),
        }
    }

    #[must_use]
    pub fn invalid_request(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidRequest, message)
    }

    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        self.code
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    #[must_use]
    pub const fn details(&self) -> &BTreeMap<String, String> {
        &self.details
    }

    #[must_use]
    pub fn with_failure_metadata(
        mut self,
        retryable: bool,
        details: BTreeMap<String, String>,
    ) -> Self {
        self.retryable = retryable;
        self.details = details;
        self
    }

    #[must_use]
    pub const fn retryable(&self) -> bool {
        self.retryable
    }

    #[must_use]
    pub const fn trace_id(&self) -> Uuid {
        self.trace_id
    }

    #[must_use]
    pub fn mapping(&self) -> ErrorMapping {
        ApiErrorCode::from(self.code).mapping()
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for ApiError {}

#[derive(Clone, Debug)]
pub struct ApiEnvelope<T> {
    data: T,
    trace_id: Uuid,
}

impl<T> ApiEnvelope<T> {
    #[must_use]
    pub fn new(data: T) -> Self {
        Self {
            data,
            trace_id: Uuid::now_v7(),
        }
    }

    #[must_use]
    pub const fn data(&self) -> &T {
        &self.data
    }

    #[must_use]
    pub const fn trace_id(&self) -> Uuid {
        self.trace_id
    }
}

#[derive(Clone, Debug)]
pub struct OperationEnvelope {
    id: OperationId,
    state: CreateOperationState,
    poll_url: String,
    session: Option<SessionResource>,
    failure: Option<OperationFailure>,
}

impl OperationEnvelope {
    #[must_use]
    pub const fn id(&self) -> &OperationId {
        &self.id
    }

    #[must_use]
    pub const fn state(&self) -> CreateOperationState {
        self.state
    }

    #[must_use]
    pub fn poll_url(&self) -> &str {
        &self.poll_url
    }

    #[must_use]
    pub const fn session(&self) -> Option<&SessionResource> {
        self.session.as_ref()
    }

    #[must_use]
    pub const fn failure(&self) -> Option<&OperationFailure> {
        self.failure.as_ref()
    }

    #[must_use]
    pub fn public_value(&self) -> serde_json::Value {
        let state = match self.state {
            CreateOperationState::Accepted => "accepted",
            CreateOperationState::Queued => "queued",
            CreateOperationState::Reserving => "reserving",
            CreateOperationState::Creating => "creating",
            CreateOperationState::Succeeded => "succeeded",
            CreateOperationState::TimedOut => "timed_out",
            CreateOperationState::Cancelled => "cancelled",
            CreateOperationState::Failed => "failed",
        };
        let session = self.session.as_ref().map(|session| {
            serde_json::json!({
                "id": session.id,
                "lifecycle": format!("{:?}", session.lifecycle).to_ascii_lowercase(),
                "incarnation": session.incarnation,
                "requested_isolation": match session.requested_isolation {
                    IsolationProfile::SharedContext => "shared_context",
                    IsolationProfile::TenantDedicatedShard => "tenant_dedicated_shard",
                    IsolationProfile::DedicatedProcess => "dedicated_process",
                    IsolationProfile::DedicatedWorker => "dedicated_worker",
                },
                "effective_isolation": match session.effective_isolation {
                    IsolationProfile::SharedContext => "shared_context",
                    IsolationProfile::TenantDedicatedShard => "tenant_dedicated_shard",
                    IsolationProfile::DedicatedProcess => "dedicated_process",
                    IsolationProfile::DedicatedWorker => "dedicated_worker",
                },
                "metadata": session.metadata,
            })
        });
        serde_json::json!({ "id": self.id, "state": state, "poll_url": self.poll_url, "session": session, "failure": self.failure })
    }
}

#[derive(Clone, Debug)]
pub struct SessionCreateResponse {
    operation: OperationEnvelope,
}

impl SessionCreateResponse {
    #[must_use]
    pub const fn operation(&self) -> &OperationEnvelope {
        &self.operation
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionResource {
    pub id: SessionId,
    pub lifecycle: SessionLifecycle,
    pub incarnation: u64,
    pub requested_isolation: IsolationProfile,
    pub effective_isolation: IsolationProfile,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Clone, Debug)]
pub struct SessionListQuery {
    pub lifecycle: Option<SessionLifecycle>,
    pub isolation: Option<IsolationProfile>,
    pub metadata_key: Option<String>,
    pub limit: usize,
    pub page_token: Option<String>,
}

impl Default for SessionListQuery {
    fn default() -> Self {
        Self {
            lifecycle: None,
            isolation: None,
            metadata_key: None,
            limit: 50,
            page_token: None,
        }
    }
}

impl SessionListQuery {
    pub fn validate(&self) -> Result<(), ApiError> {
        if !(1..=100).contains(&self.limit)
            || self.metadata_key.as_ref().is_some_and(|key| {
                key.is_empty()
                    || key.len() > MAX_SESSION_METADATA_KEY_BYTES
                    || key.trim() != key
                    || key.chars().any(char::is_control)
            })
            || self
                .page_token
                .as_ref()
                .is_some_and(|token| token.is_empty() || token.len() > 256)
        {
            return Err(ApiError::invalid_request("invalid session list query"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct SessionListPage {
    items: Vec<SessionResource>,
    next_page_token: Option<String>,
}

impl SessionListPage {
    #[must_use]
    pub fn items(&self) -> &[SessionResource] {
        &self.items
    }

    #[must_use]
    pub fn next_page_token(&self) -> Option<&str> {
        self.next_page_token.as_deref()
    }
}

#[derive(Default)]
pub struct SessionCatalog {
    sessions: Mutex<HashMap<(TenantId, SessionId), SessionResource>>,
}

impl SessionCatalog {
    pub fn upsert(&self, tenant_id: TenantId, session: SessionResource) -> Result<(), ApiError> {
        self.sessions
            .lock()
            .map_err(|_| {
                ApiError::new(ErrorCode::WorkerUnavailable, "session catalog unavailable")
            })?
            .insert((tenant_id, session.id.clone()), session);
        Ok(())
    }

    pub fn list(
        &self,
        tenant_id: &TenantId,
        query: &SessionListQuery,
    ) -> Result<SessionListPage, ApiError> {
        query.validate()?;
        let mut hash = Sha256::new();
        hash.update(b"browserd-session-list-v1\0");
        hash.update(tenant_id.as_bytes());
        hash.update([match query.lifecycle {
            None => 0,
            Some(SessionLifecycle::Creating) => 1,
            Some(SessionLifecycle::Ready) => 2,
            Some(SessionLifecycle::Closing) => 3,
            Some(SessionLifecycle::Closed) => 4,
            Some(SessionLifecycle::Failed) => 5,
        }]);
        hash.update([match query.isolation {
            None => 0,
            Some(IsolationProfile::SharedContext) => 1,
            Some(IsolationProfile::TenantDedicatedShard) => 2,
            Some(IsolationProfile::DedicatedProcess) => 3,
            Some(IsolationProfile::DedicatedWorker) => 4,
        }]);
        if let Some(metadata_key) = &query.metadata_key {
            hash.update((metadata_key.len() as u64).to_be_bytes());
            hash.update(metadata_key.as_bytes());
        }
        let filter_hash: [u8; 32] = hash.finalize().into();

        let (after, ceiling) = if let Some(token) = &query.page_token {
            let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(token)
                .map_err(|_| ApiError::invalid_request("invalid session page token"))?;
            if raw.len() != 65 || raw[0] != 1 || raw[33..] != filter_hash {
                return Err(ApiError::invalid_request("invalid session page token"));
            }
            let after = SessionId::from_uuid(Uuid::from_bytes(
                raw[1..17]
                    .try_into()
                    .map_err(|_| ApiError::invalid_request("invalid session page token"))?,
            ))
            .map_err(|_| ApiError::invalid_request("invalid session page token"))?;
            let ceiling = SessionId::from_uuid(Uuid::from_bytes(
                raw[17..33]
                    .try_into()
                    .map_err(|_| ApiError::invalid_request("invalid session page token"))?,
            ))
            .map_err(|_| ApiError::invalid_request("invalid session page token"))?;
            (Some(after), Some(ceiling))
        } else {
            (None, None)
        };

        let sessions = self.sessions.lock().map_err(|_| {
            ApiError::new(ErrorCode::WorkerUnavailable, "session catalog unavailable")
        })?;
        let mut matching = sessions
            .iter()
            .filter(|((stored_tenant, _), session)| {
                stored_tenant == tenant_id
                    && query
                        .lifecycle
                        .is_none_or(|state| session.lifecycle == state)
                    && query
                        .isolation
                        .is_none_or(|isolation| session.effective_isolation == isolation)
                    && query
                        .metadata_key
                        .as_ref()
                        .is_none_or(|key| session.metadata.contains_key(key))
            })
            .map(|(_, session)| session.clone())
            .collect::<Vec<_>>();
        matching.sort_by(|left, right| left.id.cmp(&right.id));
        let ceiling = ceiling.or_else(|| matching.last().map(|session| session.id.clone()));
        let mut eligible = matching
            .into_iter()
            .filter(|session| {
                after.as_ref().is_none_or(|cursor| session.id > *cursor)
                    && ceiling.as_ref().is_none_or(|last| session.id <= *last)
            })
            .collect::<Vec<_>>();
        let has_more = eligible.len() > query.limit;
        eligible.truncate(query.limit);
        let next_page_token = if has_more {
            let last = eligible
                .last()
                .ok_or_else(|| ApiError::new(ErrorCode::Internal, "pagination invariant failed"))?;
            let ceiling = ceiling
                .as_ref()
                .ok_or_else(|| ApiError::new(ErrorCode::Internal, "pagination invariant failed"))?;
            let mut raw = Vec::with_capacity(65);
            raw.push(1);
            raw.extend_from_slice(last.id.as_bytes());
            raw.extend_from_slice(ceiling.as_bytes());
            raw.extend_from_slice(&filter_hash);
            Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw))
        } else {
            None
        };
        Ok(SessionListPage {
            items: eligible,
            next_page_token,
        })
    }
}

#[derive(Clone, Debug)]
pub struct PageListRequest {
    pub session_id: SessionId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageCreateBody {
    pub url: Option<String>,
}

impl PageCreateBody {
    pub fn validate(&self) -> Result<(), ApiError> {
        if let Some(value) = &self.url
            && (value.len() > 2_048
                || (value != "about:blank"
                    && Url::parse(value)
                        .map(|url| !matches!(url.scheme(), "http" | "https"))
                        .unwrap_or(true)))
        {
            return Err(ApiError::invalid_request("invalid initial page URL"));
        }
        Ok(())
    }
}

pub fn decode_page_create(json: &str) -> Result<PageCreateBody, ApiError> {
    let body: PageCreateBody = serde_json::from_str(json)
        .map_err(|_| ApiError::invalid_request("invalid page create body"))?;
    body.validate()?;
    Ok(body)
}

#[derive(Clone, Debug)]
pub struct PageCreateRequest {
    pub session_id: SessionId,
    pub body: PageCreateBody,
}

#[derive(Clone, Debug)]
pub struct PageDeleteRequest {
    pub session_id: SessionId,
    pub page_id: PageId,
}

#[derive(Clone, Debug)]
pub struct PageActivateRequest {
    pub session_id: SessionId,
    pub page_id: PageId,
}

#[derive(Clone, Debug)]
pub struct PageResource {
    pub session_id: SessionId,
    pub page_id: PageId,
    pub active: bool,
    pub target_incarnation: u64,
    pub document_epoch: u64,
    pub url_revision: u64,
}

#[derive(Clone, Debug)]
pub struct SessionReconnectRequest {
    pub session_id: SessionId,
    pub token: ReconnectToken,
    pub binding: ClientBinding,
    pub now: SessionTime,
}

#[derive(Clone, Debug)]
pub struct SessionTransferRequest {
    pub session_id: SessionId,
    pub current_fence: OwnershipFence,
    pub new_worker_id: WorkerId,
    pub new_worker_epoch: u64,
    pub now: SessionTime,
}

#[derive(Clone, Debug)]
pub struct ActionSubmitCommand {
    pub session_id: SessionId,
    pub idempotency_key: Uuid,
    pub body: ActionSubmitRequest,
}

pub struct ActionSubmissionAdapter<J> {
    ledger: Arc<ActionLedger<J>>,
}

impl<J> ActionSubmissionAdapter<J>
where
    J: DurableActionJournal,
{
    #[must_use]
    pub const fn new(ledger: Arc<ActionLedger<J>>) -> Self {
        Self { ledger }
    }

    pub fn submit(
        &self,
        fence: browserd_core::PlacementFence,
        command: ActionSubmitCommand,
    ) -> Result<AcceptDecision, ApiError> {
        command.body.validate()?;
        if command.idempotency_key.is_nil() {
            return Err(ApiError::invalid_request(
                "Idempotency-Key must not be the nil UUID",
            ));
        }
        if self.ledger.session().session_id() != &command.session_id {
            return Err(ApiError::new(
                ErrorCode::SessionNotFound,
                "session does not own this action ledger",
            ));
        }
        if fence.session_incarnation != command.body.if_session_incarnation {
            return Err(ApiError::new(
                ErrorCode::GenerationMismatch,
                "session incarnation precondition failed",
            ));
        }
        let canonical = serde_json::to_value(&command.body)
            .map_err(|_| ApiError::new(ErrorCode::Internal, "request canonicalization failed"))?;
        let canonical = CanonicalRequestHash::from_json(&canonical);
        let kind = if matches!(
            command.body.action,
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
        self.ledger
            .accept(
                fence,
                ActionRequest::new(
                    ActionIdempotencyKey::new(command.idempotency_key.to_string()),
                    ActionCanonicalRequestHash::new(*canonical.as_bytes()),
                    kind,
                ),
            )
            .map_err(|error| match error {
                ActionLedgerError::IdempotencyConflict { .. } => {
                    ApiError::new(ErrorCode::IdempotencyConflict, "idempotency body conflict")
                }
                ActionLedgerError::StaleFence { .. } => {
                    ApiError::new(ErrorCode::PlacementMismatch, "stale placement fence")
                }
                ActionLedgerError::ActionNotFound => {
                    ApiError::new(ErrorCode::SessionNotFound, "action ledger not found")
                }
                ActionLedgerError::JournalUnavailable(_) | ActionLedgerError::StateUnavailable => {
                    ApiError::new(ErrorCode::WorkerUnavailable, "action state unavailable")
                }
                _ => ApiError::new(ErrorCode::Internal, "action submission failed"),
            })
    }
}

#[derive(Clone, Debug)]
pub struct ActionGetRequest {
    pub session_id: SessionId,
    pub action_id: ActionId,
}

#[derive(Clone, Debug)]
pub struct ActionResolveRequest {
    pub session_id: SessionId,
    pub action_id: ActionId,
    pub body: ActionResolveBody,
}

#[derive(Clone, Debug)]
pub struct ViewerTicketRequest {
    pub session_id: SessionId,
    pub session_incarnation: u64,
    pub scopes: ViewerScopes,
    pub ttl: StdDuration,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ViewerScopeRequest {
    pub read: bool,
    pub control: bool,
    pub admin: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ViewerTicketBody {
    pub scopes: ViewerScopeRequest,
    pub ttl_seconds: u64,
}

impl ViewerTicketBody {
    pub fn into_request(
        self,
        session_id: SessionId,
        session_incarnation: u64,
    ) -> Result<ViewerTicketRequest, ApiError> {
        if session_incarnation == 0
            || self.ttl_seconds == 0
            || !self.scopes.read
            || (self.scopes.admin && !self.scopes.control)
        {
            return Err(ApiError::invalid_request(
                "viewer ticket requires incarnation, TTL, and read scope",
            ));
        }
        Ok(ViewerTicketRequest {
            session_id,
            session_incarnation,
            scopes: ViewerScopes::new(self.scopes.read, self.scopes.control, self.scopes.admin),
            ttl: StdDuration::from_secs(self.ttl_seconds),
        })
    }
}

pub fn decode_viewer_ticket(json: &str) -> Result<ViewerTicketBody, ApiError> {
    serde_json::from_str(json).map_err(|_| ApiError::invalid_request("invalid viewer ticket body"))
}

#[derive(Clone, Debug)]
pub struct ArtifactMetadata {
    pub key: ArtifactKey,
    pub state: ArtifactState,
    pub checksum_sha256: Option<[u8; 32]>,
    pub size_bytes: Option<u64>,
    pub content_type: Option<String>,
    pub source_origin: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ArtifactRequest {
    pub session_id: SessionId,
    pub artifact_id: ArtifactId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactUploadBody {
    pub display_filename: String,
    pub declared_content_type: Option<String>,
    pub expected_size_bytes: u64,
}

impl ArtifactUploadBody {
    pub fn validate(&self) -> Result<(), ApiError> {
        if self.display_filename.is_empty()
            || self.display_filename.len() > 255
            || self.display_filename.chars().any(char::is_control)
            || self.expected_size_bytes == 0
            || self.declared_content_type.as_ref().is_some_and(|value| {
                value.is_empty() || value.len() > 255 || value.chars().any(char::is_control)
            })
        {
            return Err(ApiError::invalid_request("invalid artifact upload body"));
        }
        Ok(())
    }
}

pub fn decode_artifact_upload(json: &str) -> Result<ArtifactUploadBody, ApiError> {
    let body: ArtifactUploadBody = serde_json::from_str(json)
        .map_err(|_| ApiError::invalid_request("invalid artifact upload body"))?;
    body.validate()?;
    Ok(body)
}

#[derive(Clone, Debug)]
pub struct ArtifactUploadRequest {
    pub session_id: SessionId,
    pub body: ArtifactUploadBody,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStateFilter {
    Pending,
    Approved,
    Denied,
    Expired,
}

#[derive(Clone, Debug)]
pub struct ApprovalListQuery {
    pub state: Option<ApprovalStateFilter>,
    pub session_id: Option<SessionId>,
    pub limit: usize,
    pub page_token: Option<String>,
}

impl Default for ApprovalListQuery {
    fn default() -> Self {
        Self {
            state: None,
            session_id: None,
            limit: 50,
            page_token: None,
        }
    }
}

impl ApprovalListQuery {
    pub fn validate(&self) -> Result<(), ApiError> {
        if !(1..=100).contains(&self.limit)
            || self
                .page_token
                .as_ref()
                .is_some_and(|token| token.is_empty() || token.len() > 256)
        {
            return Err(ApiError::invalid_request("invalid approval list query"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalDecisionRequest {
    Approve,
    Deny,
}

impl From<ApprovalDecisionRequest> for ApprovalDecision {
    fn from(value: ApprovalDecisionRequest) -> Self {
        match value {
            ApprovalDecisionRequest::Approve => Self::Approve,
            ApprovalDecisionRequest::Deny => Self::Deny,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalDecisionBody {
    pub decision: ApprovalDecisionRequest,
    pub reason: String,
}

impl ApprovalDecisionBody {
    pub fn validate(&self) -> Result<(), ApiError> {
        if self.reason.trim().is_empty()
            || self.reason.len() > 1_024
            || self.reason.chars().any(char::is_control)
        {
            return Err(ApiError::invalid_request(
                "invalid approval decision reason",
            ));
        }
        Ok(())
    }
}

pub fn decode_approval_decision(json: &str) -> Result<ApprovalDecisionBody, ApiError> {
    let body: ApprovalDecisionBody = serde_json::from_str(json)
        .map_err(|_| ApiError::invalid_request("invalid approval decision body"))?;
    body.validate()?;
    Ok(body)
}

pub fn public_approval_id(value: Uuid) -> Result<ApprovalId, ApiError> {
    ApprovalId::from_uuid(value)
        .map_err(|_| ApiError::invalid_request("approval ID must be a UUIDv7"))
}

#[derive(Clone, Debug)]
pub struct ApprovalDecisionCommand {
    pub approval_id: Uuid,
    pub body: ApprovalDecisionBody,
}

pub type ApprovalDecisionRequestCommand = ApprovalDecisionCommand;

#[derive(Clone, Debug)]
pub struct ApprovalResource {
    pub approval_id: Uuid,
    pub tenant_id: TenantId,
    pub session_id: SessionId,
    pub action_id: ActionId,
    pub state: ApprovalState,
    pub proposal: CanonicalActionProposal,
}

#[derive(Clone, Debug)]
pub struct ApprovalListPage {
    items: Vec<ApprovalResource>,
    next_page_token: Option<String>,
}

impl ApprovalListPage {
    #[must_use]
    pub fn items(&self) -> &[ApprovalResource] {
        &self.items
    }

    #[must_use]
    pub fn next_page_token(&self) -> Option<&str> {
        self.next_page_token.as_deref()
    }
}

#[derive(Default)]
pub struct ApprovalCatalog {
    approvals: Mutex<HashMap<(TenantId, Uuid), ApprovalResource>>,
}

impl ApprovalCatalog {
    pub fn upsert(&self, approval: ApprovalResource) -> Result<(), ApiError> {
        if public_approval_id(approval.approval_id).is_err()
            || approval.proposal.tenant_id() != &approval.tenant_id
            || approval.proposal.session_id() != &approval.session_id
        {
            return Err(ApiError::invalid_request(
                "approval identity does not match its proposal",
            ));
        }
        self.approvals
            .lock()
            .map_err(|_| {
                ApiError::new(ErrorCode::WorkerUnavailable, "approval catalog unavailable")
            })?
            .insert((approval.tenant_id.clone(), approval.approval_id), approval);
        Ok(())
    }

    pub fn get(
        &self,
        tenant_id: &TenantId,
        approval_id: Uuid,
    ) -> Result<ApprovalResource, ApiError> {
        self.approvals
            .lock()
            .map_err(|_| {
                ApiError::new(ErrorCode::WorkerUnavailable, "approval catalog unavailable")
            })?
            .get(&(tenant_id.clone(), approval_id))
            .cloned()
            .ok_or_else(|| ApiError::new(ErrorCode::OperationNotFound, "approval not found"))
    }

    pub fn list(
        &self,
        tenant_id: &TenantId,
        query: &ApprovalListQuery,
    ) -> Result<ApprovalListPage, ApiError> {
        query.validate()?;
        let mut hash = Sha256::new();
        hash.update(b"browserd-approval-list-v1\0");
        hash.update(tenant_id.as_bytes());
        hash.update([match query.state {
            None => 0,
            Some(ApprovalStateFilter::Pending) => 1,
            Some(ApprovalStateFilter::Approved) => 2,
            Some(ApprovalStateFilter::Denied) => 3,
            Some(ApprovalStateFilter::Expired) => 4,
        }]);
        if let Some(session_id) = &query.session_id {
            hash.update([1]);
            hash.update(session_id.as_bytes());
        } else {
            hash.update([0]);
        }
        let filter_hash: [u8; 32] = hash.finalize().into();

        let (after, ceiling) = if let Some(token) = &query.page_token {
            let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(token)
                .map_err(|_| ApiError::invalid_request("invalid approval page token"))?;
            if raw.len() != 65 || raw[0] != 1 || raw[33..] != filter_hash {
                return Err(ApiError::invalid_request("invalid approval page token"));
            }
            let after = Uuid::from_bytes(
                raw[1..17]
                    .try_into()
                    .map_err(|_| ApiError::invalid_request("invalid approval page token"))?,
            );
            let ceiling = Uuid::from_bytes(
                raw[17..33]
                    .try_into()
                    .map_err(|_| ApiError::invalid_request("invalid approval page token"))?,
            );
            if after.get_version() != Some(Version::SortRand)
                || ceiling.get_version() != Some(Version::SortRand)
            {
                return Err(ApiError::invalid_request("invalid approval page token"));
            }
            (Some(after), Some(ceiling))
        } else {
            (None, None)
        };

        let approvals = self.approvals.lock().map_err(|_| {
            ApiError::new(ErrorCode::WorkerUnavailable, "approval catalog unavailable")
        })?;
        let mut matching = approvals
            .iter()
            .filter(|((stored_tenant, _), approval)| {
                stored_tenant == tenant_id
                    && query
                        .session_id
                        .as_ref()
                        .is_none_or(|session_id| &approval.session_id == session_id)
                    && query.state.is_none_or(|state| match state {
                        ApprovalStateFilter::Pending => {
                            matches!(approval.state, ApprovalState::Pending)
                        }
                        ApprovalStateFilter::Approved => {
                            matches!(approval.state, ApprovalState::Approved { .. })
                        }
                        ApprovalStateFilter::Denied => {
                            matches!(approval.state, ApprovalState::Denied { .. })
                        }
                        ApprovalStateFilter::Expired => {
                            matches!(approval.state, ApprovalState::Expired)
                        }
                    })
            })
            .map(|(_, approval)| approval.clone())
            .collect::<Vec<_>>();
        matching.sort_by_key(|approval| approval.approval_id);
        let ceiling = ceiling.or_else(|| matching.last().map(|approval| approval.approval_id));
        let mut eligible = matching
            .into_iter()
            .filter(|approval| {
                after.is_none_or(|cursor| approval.approval_id > cursor)
                    && ceiling.is_none_or(|last| approval.approval_id <= last)
            })
            .collect::<Vec<_>>();
        let has_more = eligible.len() > query.limit;
        eligible.truncate(query.limit);
        let next_page_token = if has_more {
            let last = eligible
                .last()
                .ok_or_else(|| ApiError::new(ErrorCode::Internal, "pagination invariant failed"))?;
            let ceiling = ceiling
                .ok_or_else(|| ApiError::new(ErrorCode::Internal, "pagination invariant failed"))?;
            let mut raw = Vec::with_capacity(65);
            raw.push(1);
            raw.extend_from_slice(last.approval_id.as_bytes());
            raw.extend_from_slice(ceiling.as_bytes());
            raw.extend_from_slice(&filter_hash);
            Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw))
        } else {
            None
        };
        Ok(ApprovalListPage {
            items: eligible,
            next_page_token,
        })
    }
}

#[derive(Debug)]
pub enum ApiRequest {
    CreateSession {
        body: SessionCreateRequest,
        idempotency_key: String,
        received_at: Instant,
    },
    GetOperation(OperationId),
    CancelOperation(OperationId),
    ListSessions(SessionListQuery),
    GetSession(SessionId),
    DeleteSession(SessionId),
    ReconnectSession(SessionReconnectRequest),
    TransferSession(SessionTransferRequest),
    ListPages(PageListRequest),
    CreatePage(PageCreateRequest),
    DeletePage(PageDeleteRequest),
    ActivatePage(PageActivateRequest),
    SubmitAction(ActionSubmitCommand),
    GetAction(ActionGetRequest),
    CancelAction(ActionGetRequest),
    ResolveAction(ActionResolveRequest),
    ResumeEvents {
        last_event_id: Option<Uuid>,
        limit: usize,
        now: DateTime<Utc>,
    },
    IssueViewerTicket(ViewerTicketRequest),
    UploadArtifact(ArtifactUploadRequest),
    GetArtifact(ArtifactRequest),
    DownloadArtifact(ArtifactRequest),
    ListApprovals(ApprovalListQuery),
    GetApproval(Uuid),
    DecideApproval {
        approval_id: Uuid,
        body: ApprovalDecisionBody,
    },
}

impl ApiRequest {
    pub fn authorize(&self, principal: &AuthenticatedPrincipal) -> Result<(), ApiError> {
        let required_scope = match self {
            Self::CreateSession { .. } | Self::CancelOperation(_) => "session:create",
            Self::GetOperation(_)
            | Self::ListSessions(_)
            | Self::GetSession(_)
            | Self::ReconnectSession(_)
            | Self::GetAction(_)
            | Self::ListPages(_) => "session:read",
            Self::DeleteSession(_) => "session:close",
            Self::TransferSession(_) => "admin:force-close",
            Self::SubmitAction(_)
            | Self::CancelAction(_)
            | Self::ResolveAction(_)
            | Self::CreatePage(_)
            | Self::DeletePage(_)
            | Self::ActivatePage(_) => "browser:act",
            Self::ResumeEvents { .. } => "events:read",
            Self::IssueViewerTicket(_) => "viewer:read",
            Self::UploadArtifact(_) => "artifact:upload",
            Self::GetArtifact(_) | Self::DownloadArtifact(_) => "artifact:read",
            Self::ListApprovals(_) | Self::GetApproval(_) => "approval:read",
            Self::DecideApproval { .. } => "approval:decide",
        };
        principal.require_scope(required_scope).map_err(|_| {
            ApiError::new(
                ErrorCode::PermissionDenied,
                "request scope is not granted to this principal",
            )
        })?;
        if let Self::SubmitAction(command) = self {
            let conditional_scope = match &command.body.action {
                ActionPayload::Evaluate { .. } => Some("browser:evaluate"),
                ActionPayload::FillSecret { .. } => Some("secret:use"),
                ActionPayload::Checkpoint => Some("checkpoint:create"),
                ActionPayload::SetFiles { .. } => Some("artifact:read"),
                _ => None,
            };
            if let Some(scope) = conditional_scope {
                principal.require_scope(scope).map_err(|_| {
                    ApiError::new(
                        ErrorCode::PermissionDenied,
                        "request scope is not granted to this principal",
                    )
                })?;
            }
        }
        if let Self::IssueViewerTicket(command) = self {
            if command.scopes.can_control() {
                principal.require_scope("viewer:control").map_err(|_| {
                    ApiError::new(
                        ErrorCode::PermissionDenied,
                        "request scope is not granted to this principal",
                    )
                })?;
            }
            if command.scopes.can_admin() {
                principal
                    .require_scope("admin:force-control")
                    .map_err(|_| {
                        ApiError::new(
                            ErrorCode::PermissionDenied,
                            "request scope is not granted to this principal",
                        )
                    })?;
            }
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), ApiError> {
        match self {
            Self::CreateSession {
                body,
                idempotency_key,
                ..
            } => {
                body.validate()?;
                validate_idempotency_key(idempotency_key)?;
            }
            Self::SubmitAction(command) => {
                if command.idempotency_key.is_nil() {
                    return Err(ApiError::invalid_request(
                        "Idempotency-Key must not be the nil UUID",
                    ));
                }
                command.body.validate()?;
            }
            Self::ListSessions(query) => query.validate()?,
            Self::CreatePage(command) => command.body.validate()?,
            Self::UploadArtifact(command) => command.body.validate()?,
            Self::ListApprovals(query) => query.validate()?,
            Self::GetApproval(approval_id) if public_approval_id(*approval_id).is_err() => {
                return Err(ApiError::invalid_request("approval ID must be a UUIDv7"));
            }
            Self::DecideApproval { approval_id, body } => {
                public_approval_id(*approval_id)?;
                body.validate()?;
            }
            Self::ResolveAction(command) => {
                if command.body.basis.trim().is_empty() || command.body.basis.len() > 4_096 {
                    return Err(ApiError::invalid_request("resolution basis is invalid"));
                }
            }
            Self::ResumeEvents {
                last_event_id,
                limit,
                ..
            } => {
                if !(1..=100).contains(limit) {
                    return Err(ApiError::invalid_request("event limit must be 1..=100"));
                }
                if last_event_id
                    .is_some_and(|event_id| event_id.get_version() != Some(Version::SortRand))
                {
                    return Err(ApiError::invalid_request("Last-Event-ID must be a UUIDv7"));
                }
            }
            Self::TransferSession(command) if command.new_worker_epoch == 0 => {
                return Err(ApiError::invalid_request(
                    "new worker epoch must be non-zero",
                ));
            }
            Self::IssueViewerTicket(command)
                if command.session_incarnation == 0
                    || command.ttl.is_zero()
                    || !command.scopes.can_read()
                    || (command.scopes.can_admin() && !command.scopes.can_control()) =>
            {
                return Err(ApiError::invalid_request(
                    "viewer ticket requires incarnation, TTL, and read scope",
                ));
            }
            Self::GetOperation(_)
            | Self::CancelOperation(_)
            | Self::GetSession(_)
            | Self::DeleteSession(_)
            | Self::ReconnectSession(_)
            | Self::TransferSession(_)
            | Self::ListPages(_)
            | Self::DeletePage(_)
            | Self::ActivatePage(_)
            | Self::GetAction(_)
            | Self::CancelAction(_)
            | Self::GetArtifact(_)
            | Self::DownloadArtifact(_)
            | Self::GetApproval(_)
            | Self::IssueViewerTicket(_) => {}
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum ApiResponse {
    SessionCreate(ApiEnvelope<SessionCreateResponse>),
    Operation(ApiEnvelope<OperationEnvelope>),
    Sessions(ApiEnvelope<SessionListPage>),
    Session(ApiEnvelope<SessionResource>),
    SessionClosed(ApiEnvelope<SessionResource>),
    Reconnected(ApiEnvelope<OwnershipFence>),
    Transferred(ApiEnvelope<OwnershipFence>),
    Pages(ApiEnvelope<Vec<PageResource>>),
    Page(ApiEnvelope<PageResource>),
    PageDeleted(ApiEnvelope<PageResource>),
    Action(ApiEnvelope<ActionSnapshot>),
    Events(ApiEnvelope<EventPage>),
    ViewerTicket(ApiEnvelope<ViewerTicket>),
    ArtifactUpload(ApiEnvelope<ArtifactMetadata>),
    Artifact(ApiEnvelope<ArtifactMetadata>),
    ArtifactDownload(ApiEnvelope<DownloadToken>),
    Approvals(ApiEnvelope<ApprovalListPage>),
    Approval(ApiEnvelope<ApprovalResource>),
}

pub trait ApiService: Send + Sync {
    fn execute(
        &self,
        principal: &AuthenticatedPrincipal,
        request: ApiRequest,
    ) -> Result<ApiResponse, ApiError>;
}

/// Runtime-dependent endpoint adapter. A gateway binary can connect its
/// session/action/viewer/artifact implementation without coupling it to HTTP.
pub trait RuntimeApiBackend: Send + Sync {
    fn create_session(
        &self,
        authority: &CreateAuthority,
        dispatch: &SessionCreateDispatch,
        request: &SessionCreateRequest,
    ) -> RuntimeCreateResult;

    fn execute_runtime(
        &self,
        principal: &AuthenticatedPrincipal,
        request: ApiRequest,
    ) -> Result<ApiResponse, ApiError>;
}

#[derive(Clone, Debug)]
pub enum RuntimeCreateResult {
    Succeeded(SessionResource),
    ConfirmedFailure(ApiError),
    OutcomeUnknown(ApiError),
}

pub struct ApiRouter<B> {
    coordination: InMemoryApiService,
    runtime: Arc<B>,
}

impl<B> ApiRouter<B> {
    #[must_use]
    pub fn new(runtime: Arc<B>) -> Self {
        Self::with_coordination(runtime, InMemoryApiService::default())
    }

    #[must_use]
    pub const fn with_coordination(runtime: Arc<B>, coordination: InMemoryApiService) -> Self {
        Self {
            coordination,
            runtime,
        }
    }

    #[must_use]
    pub const fn coordination(&self) -> &InMemoryApiService {
        &self.coordination
    }
}

impl<B> ApiService for ApiRouter<B>
where
    B: RuntimeApiBackend,
{
    fn execute(
        &self,
        principal: &AuthenticatedPrincipal,
        request: ApiRequest,
    ) -> Result<ApiResponse, ApiError> {
        request.authorize(principal)?;
        request.validate()?;
        match request {
            ApiRequest::CreateSession {
                body,
                idempotency_key,
                received_at,
            } => self
                .coordination
                .create_session_for_tenant_with_runtime(
                    principal.tenant_id().clone(),
                    body,
                    &idempotency_key,
                    received_at,
                    |dispatch, request| match self.runtime.create_session(
                        &CreateAuthority {
                            tenant_id: principal.tenant_id().clone(),
                            principal_id: principal.principal_id().clone(),
                        },
                        dispatch,
                        request,
                    ) {
                        RuntimeCreateResult::Succeeded(session) => Ok(session),
                        RuntimeCreateResult::ConfirmedFailure(error)
                        | RuntimeCreateResult::OutcomeUnknown(error) => Err(error),
                    },
                )
                .map(ApiResponse::SessionCreate),
            coordination_request @ (ApiRequest::GetOperation(_)
            | ApiRequest::CancelOperation(_)
            | ApiRequest::ResumeEvents { .. }) => {
                self.coordination.execute(principal, coordination_request)
            }
            runtime_request => self.runtime.execute_runtime(principal, runtime_request),
        }
    }
}

pub struct DurableApiRouter<B> {
    coordination: CoordinationBlockingClient,
    runtime: Arc<B>,
    auxiliary: InMemoryApiService,
    dispatch_lease_duration: StdDuration,
    runtime_create_timeout: StdDuration,
    dispatch_slots: Arc<AtomicUsize>,
}

struct DispatchSlotGuard(Arc<AtomicUsize>);

impl Drop for DispatchSlotGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

impl<B> DurableApiRouter<B>
where
    B: RuntimeApiBackend + 'static,
{
    #[must_use]
    pub fn new(runtime: Arc<B>, coordination: CoordinationBlockingClient) -> Self {
        Self {
            coordination,
            runtime,
            auxiliary: InMemoryApiService::default(),
            dispatch_lease_duration: StdDuration::from_secs(30),
            runtime_create_timeout: StdDuration::from_secs(25),
            dispatch_slots: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn with_dispatch_lease_duration(
        runtime: Arc<B>,
        coordination: CoordinationBlockingClient,
        duration: StdDuration,
    ) -> Result<Self, ApiError> {
        if duration < StdDuration::from_millis(1) || duration > StdDuration::from_secs(5 * 60) {
            return Err(ApiError::invalid_request(
                "dispatch lease duration must be 1ms..=5m",
            ));
        }
        let runtime_create_timeout = duration
            .checked_sub(StdDuration::from_millis(1))
            .ok_or_else(|| {
                ApiError::invalid_request("dispatch lease must exceed runtime deadline")
            })?;
        Ok(Self {
            coordination,
            runtime,
            auxiliary: InMemoryApiService::default(),
            dispatch_lease_duration: duration,
            runtime_create_timeout,
            dispatch_slots: Arc::new(AtomicUsize::new(0)),
        })
    }

    pub fn create_session_for_principal(
        &self,
        principal: &AuthenticatedPrincipal,
        body: SessionCreateRequest,
        idempotency_key: &str,
        _received_at: Instant,
    ) -> Result<ApiEnvelope<SessionCreateResponse>, ApiError> {
        body.validate()?;
        let parsed_key = validate_idempotency_key(idempotency_key)?;
        let request_json = serde_json::to_value(&body)
            .map_err(|_| ApiError::new(ErrorCode::Internal, "request canonicalization failed"))?;
        let request_hash = CanonicalRequestHash::from_json(&request_json);
        let now = Utc::now();
        let deadline = now
            .checked_add_signed(ChronoDuration::seconds(30))
            .ok_or_else(|| ApiError::new(ErrorCode::Internal, "admission deadline overflow"))?;
        let operation_id = OperationId::new();
        let intent = RecoverableCreateIntent::new(
            &operation_id,
            request_json,
            now,
            deadline,
            serde_json::json!({}),
        )
        .map_err(Self::map_coordination_error)?;
        let claim = ClaimCreateOperation::new(
            principal.tenant_id().clone(),
            principal.principal_id().clone(),
            operation_id.clone(),
            parsed_key.to_string(),
            DurableRequestHash::new(*request_hash.as_bytes()),
            intent,
        )
        .map_err(Self::map_coordination_error)?;
        let claimed = match self.coordination.claim_create(claim, now) {
            Ok(outcome) => outcome,
            Err(CoordinationError::ActorMutationTimeout | CoordinationError::ActorTimeout) => {
                let snapshot = self
                    .coordination
                    .get(principal.tenant_id(), &operation_id)
                    .map_err(Self::map_coordination_error)?
                    .ok_or_else(|| {
                        ApiError::new(
                            ErrorCode::WorkerUnavailable,
                            "create admission outcome unknown",
                        )
                    })?;
                ClaimOutcome::Existing(snapshot)
            }
            Err(error) => return Err(Self::map_coordination_error(error)),
        };
        let mut snapshot = match claimed {
            ClaimOutcome::Created(snapshot) | ClaimOutcome::Existing(snapshot) => snapshot,
        };
        snapshot = self.drive_pending(snapshot)?;
        let operation = self.operation_envelope(snapshot)?;
        Ok(ApiEnvelope::new(SessionCreateResponse { operation }))
    }

    fn drive_pending(
        &self,
        mut snapshot: DurableOperationSnapshot,
    ) -> Result<DurableOperationSnapshot, ApiError> {
        loop {
            let transition_now = Utc::now();
            if transition_now >= snapshot.intent().admission_deadline()
                && matches!(
                    snapshot.state(),
                    CreateOperationState::Accepted
                        | CreateOperationState::Queued
                        | CreateOperationState::Reserving
                )
            {
                let error = CreateOperationError::new(
                    "admission_timeout",
                    "create admission deadline elapsed",
                    false,
                    serde_json::json!({}),
                );
                match self.coordination.compare_and_set(
                    snapshot.tenant_id(),
                    snapshot.operation_id(),
                    snapshot.revision(),
                    snapshot.state(),
                    OperationMutation::timeout(error),
                    transition_now,
                ) {
                    Ok(updated) => return Ok(updated),
                    Err(CoordinationError::StaleWrite(current)) => {
                        snapshot = *current;
                        continue;
                    }
                    Err(error) => return Err(Self::map_coordination_error(error)),
                }
            }
            let mutation = match snapshot.state() {
                CreateOperationState::Accepted => {
                    OperationMutation::transition(CreateOperationState::Queued)
                }
                CreateOperationState::Queued => {
                    OperationMutation::transition(CreateOperationState::Reserving)
                }
                CreateOperationState::Reserving | CreateOperationState::Creating => {
                    let token = DispatchLeaseToken::new();
                    match self.coordination.acquire_dispatch_lease(
                        snapshot.tenant_id(),
                        snapshot.operation_id(),
                        snapshot.revision(),
                        token.clone(),
                        self.dispatch_lease_duration,
                        transition_now,
                    ) {
                        Ok(leased) => return self.dispatch_owned(leased, token),
                        Err(CoordinationError::DispatchLeaseActive(current)) => {
                            return Ok(*current);
                        }
                        Err(CoordinationError::StaleWrite(current)) => {
                            snapshot = *current;
                            continue;
                        }
                        Err(CoordinationError::ActorMutationTimeout) => {
                            snapshot = self
                                .coordination
                                .get(snapshot.tenant_id(), snapshot.operation_id())
                                .map_err(Self::map_coordination_error)?
                                .ok_or_else(|| {
                                    ApiError::new(
                                        ErrorCode::WorkerUnavailable,
                                        "lease acquisition outcome unknown",
                                    )
                                })?;
                            if snapshot
                                .dispatch_lease()
                                .is_some_and(|lease| lease.token() == &token)
                            {
                                return self.dispatch_owned(snapshot, token);
                            }
                            return Ok(snapshot);
                        }
                        Err(error) => return Err(Self::map_coordination_error(error)),
                    }
                }
                CreateOperationState::Succeeded
                | CreateOperationState::TimedOut
                | CreateOperationState::Cancelled
                | CreateOperationState::Failed => break,
            };
            match self.coordination.compare_and_set(
                snapshot.tenant_id(),
                snapshot.operation_id(),
                snapshot.revision(),
                snapshot.state(),
                mutation,
                transition_now,
            ) {
                Ok(updated) => {
                    snapshot = updated;
                }
                Err(CoordinationError::StaleWrite(current)) => snapshot = *current,
                Err(error) => return Err(Self::map_coordination_error(error)),
            }
        }
        Ok(snapshot)
    }

    fn dispatch_owned(
        &self,
        snapshot: DurableOperationSnapshot,
        dispatch_token: DispatchLeaseToken,
    ) -> Result<DurableOperationSnapshot, ApiError> {
        let dispatch_slots = Arc::clone(&self.dispatch_slots);
        dispatch_slots
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current < 64).then_some(current + 1)
            })
            .map_err(|_| {
                ApiError::new(
                    ErrorCode::WorkerUnavailable,
                    "runtime create capacity exhausted",
                )
            })?;
        let _slot = DispatchSlotGuard(dispatch_slots);
        if Utc::now() >= snapshot.intent().admission_deadline() {
            return self
                .coordination
                .compare_and_set(
                    snapshot.tenant_id(),
                    snapshot.operation_id(),
                    snapshot.revision(),
                    CreateOperationState::Creating,
                    OperationMutation::timeout_with_lease(
                        dispatch_token,
                        CreateOperationError::new(
                            "admission_timeout",
                            "create admission deadline elapsed",
                            false,
                            serde_json::json!({}),
                        ),
                    ),
                    Utc::now(),
                )
                .map_err(Self::map_coordination_error);
        }
        let body: SessionCreateRequest = serde_json::from_value(
            snapshot.intent().canonical_request().clone(),
        )
        .map_err(|_| ApiError::new(ErrorCode::Internal, "stored create intent is invalid"))?;
        let authority = CreateAuthority {
            tenant_id: snapshot.tenant_id().clone(),
            principal_id: snapshot.principal_id().clone(),
        };
        let dispatch = SessionCreateDispatch {
            operation_id: snapshot.operation_id().clone(),
            downstream_dedupe_key: snapshot.intent().downstream_dedupe_key(),
            canonical_request_hash: snapshot.request_hash().as_bytes(),
            accepted_at: snapshot.intent().accepted_at(),
            admission_deadline: snapshot.intent().admission_deadline(),
            dispatch_generation: snapshot.dispatch_generation(),
            runtime_timeout: self.runtime_create_timeout,
        };
        let coordination = self.coordination.clone();
        let tenant_id = snapshot.tenant_id().clone();
        let operation_id = snapshot.operation_id().clone();
        let renewal_token = dispatch_token.clone();
        let lease_ttl = self.dispatch_lease_duration;
        let renewal_interval = std::cmp::max(StdDuration::from_millis(1), lease_ttl / 3);
        let initial_revision = snapshot.revision();
        let (stop_sender, stop_receiver) = std::sync::mpsc::sync_channel(1);
        let renewer = std::thread::Builder::new()
            .name("browserd-dispatch-lease".to_owned())
            .spawn(move || {
                let mut revision = initial_revision;
                while matches!(
                    stop_receiver.recv_timeout(renewal_interval),
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout)
                ) {
                    match coordination.renew_dispatch_lease(
                        &tenant_id,
                        &operation_id,
                        revision,
                        renewal_token.clone(),
                        lease_ttl,
                        Utc::now(),
                    ) {
                        Ok(updated) => revision = updated.revision(),
                        Err(CoordinationError::ActorMutationTimeout) => {
                            match coordination.get(&tenant_id, &operation_id) {
                                Ok(Some(current))
                                    if current
                                        .dispatch_lease()
                                        .is_some_and(|lease| lease.token() == &renewal_token) =>
                                {
                                    revision = current.revision()
                                }
                                _ => break,
                            }
                        }
                        Err(_) => break,
                    }
                }
            })
            .map_err(|_| {
                ApiError::new(
                    ErrorCode::WorkerUnavailable,
                    "dispatch lease renewer unavailable",
                )
            })?;
        let runtime_result = self.runtime.create_session(&authority, &dispatch, &body);
        let _ = stop_sender.send(());
        let _ = renewer.join();
        let snapshot = self
            .coordination
            .get(snapshot.tenant_id(), snapshot.operation_id())
            .map_err(Self::map_coordination_error)?
            .ok_or_else(|| {
                ApiError::new(
                    ErrorCode::WorkerUnavailable,
                    "operation disappeared during dispatch",
                )
            })?;
        if snapshot
            .dispatch_lease()
            .is_none_or(|lease| lease.token() != &dispatch_token)
        {
            return Err(ApiError::new(
                ErrorCode::WorkerUnavailable,
                "dispatch ownership changed before completion",
            ));
        }
        match runtime_result {
            RuntimeCreateResult::Succeeded(session) => {
                let lifecycle = match session.lifecycle {
                    SessionLifecycle::Creating => "creating",
                    SessionLifecycle::Ready => "ready",
                    SessionLifecycle::Closing => "closing",
                    SessionLifecycle::Closed => "closed",
                    SessionLifecycle::Failed => "failed",
                };
                let requested_isolation = match session.requested_isolation {
                    IsolationProfile::SharedContext => "shared_context",
                    IsolationProfile::TenantDedicatedShard => "tenant_dedicated_shard",
                    IsolationProfile::DedicatedProcess => "dedicated_process",
                    IsolationProfile::DedicatedWorker => "dedicated_worker",
                };
                let effective_isolation = match session.effective_isolation {
                    IsolationProfile::SharedContext => "shared_context",
                    IsolationProfile::TenantDedicatedShard => "tenant_dedicated_shard",
                    IsolationProfile::DedicatedProcess => "dedicated_process",
                    IsolationProfile::DedicatedWorker => "dedicated_worker",
                };
                let value = serde_json::json!({
                    "id": session.id,
                    "lifecycle": lifecycle,
                    "incarnation": session.incarnation,
                    "requested_isolation": requested_isolation,
                    "effective_isolation": effective_isolation,
                    "metadata": session.metadata,
                });
                self.coordination
                    .compare_and_set(
                        snapshot.tenant_id(),
                        snapshot.operation_id(),
                        snapshot.revision(),
                        CreateOperationState::Creating,
                        OperationMutation::succeed_with_lease(
                            dispatch_token,
                            CreateOperationResult::new(session.id, value),
                        ),
                        Utc::now(),
                    )
                    .or_else(|error| {
                        self.reconcile_completion(
                            snapshot.tenant_id(),
                            snapshot.operation_id(),
                            error,
                        )
                    })
                    .map_err(Self::map_coordination_error)
            }
            RuntimeCreateResult::OutcomeUnknown(error) => Err(error),
            RuntimeCreateResult::ConfirmedFailure(error) => self
                .coordination
                .compare_and_set(
                    snapshot.tenant_id(),
                    snapshot.operation_id(),
                    snapshot.revision(),
                    CreateOperationState::Creating,
                    OperationMutation::fail_with_lease(
                        dispatch_token,
                        CreateOperationError::new(
                            error.code().to_string(),
                            error.message(),
                            error.retryable(),
                            serde_json::to_value(error.details())
                                .unwrap_or_else(|_| serde_json::json!({})),
                        ),
                    ),
                    Utc::now(),
                )
                .or_else(|store_error| {
                    self.reconcile_completion(
                        snapshot.tenant_id(),
                        snapshot.operation_id(),
                        store_error,
                    )
                })
                .map_err(Self::map_coordination_error),
        }
    }

    fn reconcile_completion(
        &self,
        tenant: &TenantId,
        operation: &OperationId,
        error: CoordinationError,
    ) -> Result<DurableOperationSnapshot, CoordinationError> {
        if matches!(
            error,
            CoordinationError::ActorMutationTimeout | CoordinationError::StaleWrite(_)
        ) {
            self.coordination
                .get(tenant, operation)?
                .ok_or(CoordinationError::NotFound)
        } else {
            Err(error)
        }
    }

    pub fn get_operation_for_tenant(
        &self,
        tenant_id: &TenantId,
        operation_id: &OperationId,
    ) -> Result<ApiEnvelope<OperationEnvelope>, ApiError> {
        let snapshot = self
            .coordination
            .get(tenant_id, operation_id)
            .map_err(Self::map_coordination_error)?
            .ok_or_else(|| ApiError::new(ErrorCode::OperationNotFound, "operation not found"))?;
        self.drive_pending(snapshot)
            .and_then(|snapshot| self.operation_envelope(snapshot))
            .map(ApiEnvelope::new)
    }

    pub fn reconcile_pending(&self, limit: usize) -> Result<Vec<OperationEnvelope>, ApiError> {
        self.coordination
            .scan_reconcilable(limit, Utc::now())
            .map_err(Self::map_coordination_error)?
            .into_iter()
            .map(|snapshot| {
                self.drive_pending(snapshot)
                    .and_then(|snapshot| self.operation_envelope(snapshot))
            })
            .collect()
    }

    pub fn cancel_operation_for_tenant(
        &self,
        tenant_id: &TenantId,
        operation_id: &OperationId,
    ) -> Result<ApiEnvelope<OperationEnvelope>, ApiError> {
        let mut snapshot = self
            .coordination
            .get(tenant_id, operation_id)
            .map_err(Self::map_coordination_error)?
            .ok_or_else(|| ApiError::new(ErrorCode::OperationNotFound, "operation not found"))?;
        while let CreateOperationState::Accepted
        | CreateOperationState::Queued
        | CreateOperationState::Reserving = snapshot.state()
        {
            match self.coordination.compare_and_set(
                tenant_id,
                operation_id,
                snapshot.revision(),
                snapshot.state(),
                OperationMutation::transition(CreateOperationState::Cancelled),
                Utc::now(),
            ) {
                Ok(updated) => {
                    snapshot = updated;
                    break;
                }
                Err(CoordinationError::StaleWrite(current)) => snapshot = *current,
                Err(error) => return Err(Self::map_coordination_error(error)),
            }
        }
        self.operation_envelope(snapshot).map(ApiEnvelope::new)
    }

    fn operation_envelope(
        &self,
        snapshot: DurableOperationSnapshot,
    ) -> Result<OperationEnvelope, ApiError> {
        let session = if snapshot.state() == CreateOperationState::Succeeded {
            let result = snapshot.result().ok_or_else(|| {
                ApiError::new(ErrorCode::Internal, "completed operation has no result")
            })?;
            let value = result.value();
            let object = value
                .as_object()
                .ok_or_else(|| ApiError::new(ErrorCode::Internal, "operation result is invalid"))?;
            let stored_id = object
                .get("id")
                .cloned()
                .ok_or_else(|| ApiError::new(ErrorCode::Internal, "session ID is missing"))
                .and_then(|value| {
                    serde_json::from_value::<SessionId>(value).map_err(|_| {
                        ApiError::new(ErrorCode::Internal, "stored session ID is invalid")
                    })
                })?;
            if &stored_id != result.session_id() {
                return Err(ApiError::new(
                    ErrorCode::Internal,
                    "stored session ID does not match operation result",
                ));
            }
            let lifecycle = match object.get("lifecycle").and_then(serde_json::Value::as_str) {
                Some("creating") => SessionLifecycle::Creating,
                Some("ready") => SessionLifecycle::Ready,
                Some("closing") => SessionLifecycle::Closing,
                Some("closed") => SessionLifecycle::Closed,
                Some("failed") => SessionLifecycle::Failed,
                _ => {
                    return Err(ApiError::new(
                        ErrorCode::Internal,
                        "stored session lifecycle is invalid",
                    ));
                }
            };
            let requested_isolation = match object
                .get("requested_isolation")
                .and_then(serde_json::Value::as_str)
            {
                Some("shared_context") => IsolationProfile::SharedContext,
                Some("tenant_dedicated_shard") => IsolationProfile::TenantDedicatedShard,
                Some("dedicated_process") => IsolationProfile::DedicatedProcess,
                Some("dedicated_worker") => IsolationProfile::DedicatedWorker,
                _ => {
                    return Err(ApiError::new(
                        ErrorCode::Internal,
                        "stored requested isolation is invalid",
                    ));
                }
            };
            let effective_isolation = match object
                .get("effective_isolation")
                .and_then(serde_json::Value::as_str)
            {
                Some("shared_context") => IsolationProfile::SharedContext,
                Some("tenant_dedicated_shard") => IsolationProfile::TenantDedicatedShard,
                Some("dedicated_process") => IsolationProfile::DedicatedProcess,
                Some("dedicated_worker") => IsolationProfile::DedicatedWorker,
                _ => {
                    return Err(ApiError::new(
                        ErrorCode::Internal,
                        "stored effective isolation is invalid",
                    ));
                }
            };
            let incarnation = object
                .get("incarnation")
                .and_then(serde_json::Value::as_u64)
                .filter(|incarnation| *incarnation > 0)
                .ok_or_else(|| {
                    ApiError::new(ErrorCode::Internal, "stored incarnation is invalid")
                })?;
            let metadata = object
                .get("metadata")
                .cloned()
                .ok_or_else(|| ApiError::new(ErrorCode::Internal, "metadata is missing"))
                .and_then(|value| {
                    serde_json::from_value::<BTreeMap<String, String>>(value).map_err(|_| {
                        ApiError::new(ErrorCode::Internal, "stored metadata is invalid")
                    })
                })?;
            Some(SessionResource {
                id: stored_id,
                lifecycle,
                incarnation,
                requested_isolation,
                effective_isolation,
                metadata,
            })
        } else {
            None
        };
        let failure = snapshot.error().map(|error| OperationFailure {
            code: error.code().to_owned(),
            message: error.message().to_owned(),
            retryable: error.retryable(),
            details: serde_json::from_value(error.details().clone()).unwrap_or_default(),
        });
        Ok(OperationEnvelope {
            id: snapshot.operation_id().clone(),
            state: snapshot.state(),
            poll_url: format!("/v1/operations/{}", snapshot.operation_id()),
            session,
            failure,
        })
    }

    fn map_coordination_error(error: CoordinationError) -> ApiError {
        match error {
            CoordinationError::IdempotencyConflict { .. } => {
                ApiError::new(ErrorCode::IdempotencyConflict, "idempotency body conflict")
            }
            CoordinationError::NotFound => {
                ApiError::new(ErrorCode::OperationNotFound, "operation not found")
            }
            _ => ApiError::new(
                ErrorCode::WorkerUnavailable,
                "durable coordination unavailable",
            ),
        }
    }
}

impl<B> ApiService for DurableApiRouter<B>
where
    B: RuntimeApiBackend + 'static,
{
    fn execute(
        &self,
        principal: &AuthenticatedPrincipal,
        request: ApiRequest,
    ) -> Result<ApiResponse, ApiError> {
        request.authorize(principal)?;
        request.validate()?;
        match request {
            ApiRequest::CreateSession {
                body,
                idempotency_key,
                received_at,
            } => self
                .create_session_for_principal(principal, body, &idempotency_key, received_at)
                .map(ApiResponse::SessionCreate),
            ApiRequest::GetOperation(operation_id) => self
                .get_operation_for_tenant(principal.tenant_id(), &operation_id)
                .map(ApiResponse::Operation),
            ApiRequest::CancelOperation(operation_id) => self
                .cancel_operation_for_tenant(principal.tenant_id(), &operation_id)
                .map(ApiResponse::Operation),
            resume @ ApiRequest::ResumeEvents { .. } => self.auxiliary.execute(principal, resume),
            runtime_request => self.runtime.execute_runtime(principal, runtime_request),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventKind {
    OperationStateChanged,
    SessionLifecycleChanged,
    SessionExecutionChanged,
    ActionStateChanged,
    ActionApprovalRequired,
    ApprovalDecided,
    BrowserControlChanged,
    DownloadCompleted,
    ArtifactStateChanged,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EventResource {
    Operation(OperationId),
    Session(SessionId),
    Action(ActionId),
    Artifact(ArtifactId),
}

#[derive(Clone, Debug)]
pub struct EventRecord {
    event_id: Uuid,
    tenant_id: TenantId,
    kind: EventKind,
    resource: EventResource,
    created_at: DateTime<Utc>,
}

impl EventRecord {
    #[must_use]
    pub const fn event_id(&self) -> Uuid {
        self.event_id
    }

    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    #[must_use]
    pub const fn kind(&self) -> EventKind {
        self.kind
    }

    #[must_use]
    pub const fn resource(&self) -> &EventResource {
        &self.resource
    }

    #[must_use]
    pub const fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
}

#[derive(Clone, Debug)]
pub struct EventPage {
    events: Vec<EventRecord>,
    gap: bool,
    next_cursor: Option<Uuid>,
}

impl EventPage {
    #[must_use]
    pub fn events(&self) -> &[EventRecord] {
        &self.events
    }

    #[must_use]
    pub const fn gap(&self) -> bool {
        self.gap
    }

    #[must_use]
    pub const fn next_cursor(&self) -> Option<Uuid> {
        self.next_cursor
    }
}

struct EventStoreState {
    by_tenant: HashMap<TenantId, VecDeque<EventRecord>>,
}

pub struct EventStore {
    retention: ChronoDuration,
    state: Mutex<EventStoreState>,
}

impl EventStore {
    pub fn new(retention: ChronoDuration) -> Result<Self, ApiError> {
        if retention < ChronoDuration::hours(24) {
            return Err(ApiError::invalid_request(
                "event retention must be at least 24 hours",
            ));
        }
        Ok(Self {
            retention,
            state: Mutex::new(EventStoreState {
                by_tenant: HashMap::new(),
            }),
        })
    }

    pub fn publish(
        &self,
        tenant_id: TenantId,
        kind: EventKind,
        resource: EventResource,
        now: DateTime<Utc>,
    ) -> Result<EventRecord, ApiError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ApiError::new(ErrorCode::Internal, "event store unavailable"))?;
        let events = state.by_tenant.entry(tenant_id.clone()).or_default();
        events.retain(|event| {
            now.signed_duration_since(event.created_at)
                .to_std()
                .map_or(true, |age| {
                    age < self.retention.to_std().unwrap_or(StdDuration::MAX)
                })
        });
        let record = EventRecord {
            event_id: Uuid::now_v7(),
            tenant_id,
            kind,
            resource,
            created_at: now,
        };
        events.push_back(record.clone());
        Ok(record)
    }

    pub fn resume(
        &self,
        tenant_id: &TenantId,
        last_event_id: Option<Uuid>,
        limit: usize,
        now: DateTime<Utc>,
    ) -> Result<EventPage, ApiError> {
        if !(1..=100).contains(&limit) {
            return Err(ApiError::invalid_request("event limit must be 1..=100"));
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| ApiError::new(ErrorCode::Internal, "event store unavailable"))?;
        let events = state.by_tenant.entry(tenant_id.clone()).or_default();
        events.retain(|event| {
            now.signed_duration_since(event.created_at)
                .to_std()
                .map_or(true, |age| {
                    age < self.retention.to_std().unwrap_or(StdDuration::MAX)
                })
        });

        let (start, gap) = match last_event_id {
            None => (0, false),
            Some(cursor) => match events.iter().position(|event| event.event_id == cursor) {
                Some(index) => (index + 1, false),
                None => (events.len(), true),
            },
        };
        let page_events = events
            .iter()
            .skip(start)
            .take(limit)
            .cloned()
            .collect::<Vec<_>>();
        let next_cursor = page_events
            .last()
            .map(EventRecord::event_id)
            .or_else(|| {
                gap.then(|| events.back().map(EventRecord::event_id))
                    .flatten()
            })
            .or(last_event_id);
        Ok(EventPage {
            events: page_events,
            gap,
            next_cursor,
        })
    }
}

impl Default for EventStore {
    fn default() -> Self {
        Self::new(ChronoDuration::hours(24)).unwrap_or_else(|_| Self {
            retention: ChronoDuration::hours(24),
            state: Mutex::new(EventStoreState {
                by_tenant: HashMap::new(),
            }),
        })
    }
}

pub struct InMemoryApiService {
    create_coordination: Mutex<()>,
    idempotency: IdempotencyRegistry,
    operations: Mutex<HashMap<OperationId, Arc<CreateSessionOperation>>>,
    operation_sessions: Mutex<HashMap<OperationId, SessionResource>>,
    events: EventStore,
}

impl Default for InMemoryApiService {
    fn default() -> Self {
        Self {
            create_coordination: Mutex::new(()),
            idempotency: IdempotencyRegistry::default(),
            operations: Mutex::new(HashMap::new()),
            operation_sessions: Mutex::new(HashMap::new()),
            events: EventStore::default(),
        }
    }
}

impl InMemoryApiService {
    pub fn create_session_for_tenant(
        &self,
        tenant_id: TenantId,
        request: SessionCreateRequest,
        idempotency_key: &str,
        now: Instant,
    ) -> Result<ApiEnvelope<SessionCreateResponse>, ApiError> {
        request.validate()?;
        let (operation, dispatch, _) =
            self.claim_session_creation(tenant_id, &request, idempotency_key, now)?;
        let operation = self.operation_envelope(dispatch.operation_id(), &operation)?;
        Ok(ApiEnvelope::new(SessionCreateResponse { operation }))
    }

    pub fn create_session_for_tenant_with_runtime<F>(
        &self,
        tenant_id: TenantId,
        request: SessionCreateRequest,
        idempotency_key: &str,
        now: Instant,
        create: F,
    ) -> Result<ApiEnvelope<SessionCreateResponse>, ApiError>
    where
        F: FnOnce(
            &SessionCreateDispatch,
            &SessionCreateRequest,
        ) -> Result<SessionResource, ApiError>,
    {
        request.validate()?;
        let (operation, dispatch, created) =
            self.claim_session_creation(tenant_id, &request, idempotency_key, now)?;
        if created {
            operation
                .begin_reservation()
                .map_err(|_| ApiError::new(ErrorCode::Internal, "operation reservation failed"))?;
            operation
                .commit_creation()
                .map_err(|_| ApiError::new(ErrorCode::Internal, "operation commit failed"))?;
            match create(&dispatch, &request) {
                Ok(session) => {
                    self.operation_sessions
                        .lock()
                        .map_err(|_| {
                            ApiError::new(
                                ErrorCode::WorkerUnavailable,
                                "operation result store unavailable",
                            )
                        })?
                        .insert(dispatch.operation_id().clone(), session);
                    operation.succeed().map_err(|_| {
                        ApiError::new(ErrorCode::Internal, "operation completion failed")
                    })?;
                }
                Err(_) => {
                    operation.fail().map_err(|_| {
                        ApiError::new(ErrorCode::Internal, "operation failure recording failed")
                    })?;
                }
            }
        }
        let operation = self.operation_envelope(dispatch.operation_id(), &operation)?;
        Ok(ApiEnvelope::new(SessionCreateResponse { operation }))
    }

    fn claim_session_creation(
        &self,
        tenant_id: TenantId,
        request: &SessionCreateRequest,
        idempotency_key: &str,
        now: Instant,
    ) -> Result<(Arc<CreateSessionOperation>, SessionCreateDispatch, bool), ApiError> {
        let parsed_key = validate_idempotency_key(idempotency_key)?;
        let request_json = serde_json::to_value(request)
            .map_err(|_| ApiError::new(ErrorCode::Internal, "request canonicalization failed"))?;
        let request_hash = CanonicalRequestHash::from_json(&request_json);
        let _coordination = self
            .create_coordination
            .lock()
            .map_err(|_| ApiError::new(ErrorCode::WorkerUnavailable, "coordination unavailable"))?;
        let claim = self
            .idempotency
            .claim(
                tenant_id.clone(),
                IdempotencyKey::new(parsed_key.to_string())
                    .map_err(|_| ApiError::invalid_request("invalid Idempotency-Key"))?,
                request_hash,
                now,
            )
            .map_err(|error| match error {
                browserd_operations::IdempotencyError::Conflict { .. } => {
                    ApiError::new(ErrorCode::IdempotencyConflict, "idempotency body conflict")
                }
                browserd_operations::IdempotencyError::CoordinationUnavailable => {
                    ApiError::new(ErrorCode::WorkerUnavailable, "coordination unavailable")
                }
            })?;
        let operation_id = claim.operation_id().clone();
        let created = matches!(&claim, IdempotencyClaim::Created(_));
        let operation = match claim {
            IdempotencyClaim::Created(_) => {
                let operation = Arc::new(CreateSessionOperation::new(
                    operation_id.clone(),
                    tenant_id,
                    request_hash,
                ));
                operation
                    .enqueue()
                    .map_err(|_| ApiError::new(ErrorCode::Internal, "operation enqueue failed"))?;
                self.operations
                    .lock()
                    .map_err(|_| {
                        ApiError::new(ErrorCode::WorkerUnavailable, "operation store unavailable")
                    })?
                    .insert(operation_id.clone(), Arc::clone(&operation));
                operation
            }
            IdempotencyClaim::Existing(_) => self
                .operations
                .lock()
                .map_err(|_| {
                    ApiError::new(ErrorCode::WorkerUnavailable, "operation store unavailable")
                })?
                .get(&operation_id)
                .cloned()
                .ok_or_else(|| {
                    ApiError::new(ErrorCode::Internal, "idempotency mapping has no operation")
                })?,
        };
        Ok((
            operation,
            SessionCreateDispatch {
                downstream_dedupe_key: DownstreamDedupeKey::for_operation(&operation_id),
                operation_id,
                canonical_request_hash: *request_hash.as_bytes(),
                accepted_at: Utc::now(),
                admission_deadline: Utc::now() + ChronoDuration::seconds(30),
                dispatch_generation: 1,
                runtime_timeout: StdDuration::from_secs(25),
            },
            created,
        ))
    }

    fn operation_envelope(
        &self,
        operation_id: &OperationId,
        operation: &CreateSessionOperation,
    ) -> Result<OperationEnvelope, ApiError> {
        let state = operation.state().map_err(|_| {
            ApiError::new(ErrorCode::WorkerUnavailable, "operation state unavailable")
        })?;
        let session = if state == CreateOperationState::Succeeded {
            Some(
                self.operation_sessions
                    .lock()
                    .map_err(|_| {
                        ApiError::new(
                            ErrorCode::WorkerUnavailable,
                            "operation result store unavailable",
                        )
                    })?
                    .get(operation_id)
                    .cloned()
                    .ok_or_else(|| {
                        ApiError::new(ErrorCode::Internal, "completed operation has no session")
                    })?,
            )
        } else {
            None
        };
        Ok(OperationEnvelope {
            id: operation_id.clone(),
            state,
            poll_url: format!("/v1/operations/{operation_id}"),
            session,
            failure: None,
        })
    }

    pub fn operation_count(&self) -> Result<usize, ApiError> {
        Ok(self
            .operations
            .lock()
            .map_err(|_| {
                ApiError::new(ErrorCode::WorkerUnavailable, "operation store unavailable")
            })?
            .len())
    }

    pub fn get_operation_for_tenant(
        &self,
        tenant_id: &TenantId,
        operation_id: &OperationId,
    ) -> Result<ApiEnvelope<OperationEnvelope>, ApiError> {
        let operation = self
            .operations
            .lock()
            .map_err(|_| {
                ApiError::new(ErrorCode::WorkerUnavailable, "operation store unavailable")
            })?
            .get(operation_id)
            .filter(|operation| operation.tenant_id() == tenant_id)
            .cloned()
            .ok_or_else(|| ApiError::new(ErrorCode::OperationNotFound, "operation not found"))?;
        self.operation_envelope(operation_id, &operation)
            .map(ApiEnvelope::new)
    }

    pub fn cancel_operation_for_tenant(
        &self,
        tenant_id: &TenantId,
        operation_id: &OperationId,
    ) -> Result<ApiEnvelope<OperationEnvelope>, ApiError> {
        let operation = self
            .operations
            .lock()
            .map_err(|_| {
                ApiError::new(ErrorCode::WorkerUnavailable, "operation store unavailable")
            })?
            .get(operation_id)
            .filter(|operation| operation.tenant_id() == tenant_id)
            .cloned()
            .ok_or_else(|| ApiError::new(ErrorCode::OperationNotFound, "operation not found"))?;
        operation.request_cancel().map_err(|_| {
            ApiError::new(ErrorCode::WorkerUnavailable, "operation state unavailable")
        })?;
        self.operation_envelope(operation_id, &operation)
            .map(ApiEnvelope::new)
    }

    pub fn publish_event(
        &self,
        tenant_id: TenantId,
        kind: EventKind,
        resource: EventResource,
        now: DateTime<Utc>,
    ) -> Result<EventRecord, ApiError> {
        self.events.publish(tenant_id, kind, resource, now)
    }
}

impl ApiService for InMemoryApiService {
    fn execute(
        &self,
        principal: &AuthenticatedPrincipal,
        request: ApiRequest,
    ) -> Result<ApiResponse, ApiError> {
        request.authorize(principal)?;
        request.validate()?;
        match request {
            ApiRequest::CreateSession {
                body,
                idempotency_key,
                received_at,
            } => self
                .create_session_for_tenant(
                    principal.tenant_id().clone(),
                    body,
                    &idempotency_key,
                    received_at,
                )
                .map(ApiResponse::SessionCreate),
            ApiRequest::GetOperation(operation_id) => self
                .get_operation_for_tenant(principal.tenant_id(), &operation_id)
                .map(ApiResponse::Operation),
            ApiRequest::CancelOperation(operation_id) => self
                .cancel_operation_for_tenant(principal.tenant_id(), &operation_id)
                .map(ApiResponse::Operation),
            ApiRequest::ResumeEvents {
                last_event_id,
                limit,
                now,
            } => self
                .events
                .resume(principal.tenant_id(), last_event_id, limit, now)
                .map(ApiEnvelope::new)
                .map(ApiResponse::Events),
            ApiRequest::GetSession(_)
            | ApiRequest::ListSessions(_)
            | ApiRequest::DeleteSession(_)
            | ApiRequest::ReconnectSession(_)
            | ApiRequest::TransferSession(_)
            | ApiRequest::ListPages(_)
            | ApiRequest::CreatePage(_)
            | ApiRequest::DeletePage(_)
            | ApiRequest::ActivatePage(_)
            | ApiRequest::SubmitAction(_)
            | ApiRequest::GetAction(_)
            | ApiRequest::CancelAction(_)
            | ApiRequest::ResolveAction(_)
            | ApiRequest::IssueViewerTicket(_)
            | ApiRequest::UploadArtifact(_)
            | ApiRequest::GetArtifact(_)
            | ApiRequest::DownloadArtifact(_)
            | ApiRequest::ListApprovals(_)
            | ApiRequest::GetApproval(_)
            | ApiRequest::DecideApproval { .. } => Err(ApiError::new(
                ErrorCode::WorkerUnavailable,
                "endpoint requires a connected runtime backend",
            )),
        }
    }
}
