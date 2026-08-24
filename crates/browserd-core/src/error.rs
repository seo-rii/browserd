use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryClass {
    Never,
    Safe,
    Conditional,
    ReadOnly,
    StatusLookupOnly,
    MutationDisallowed,
    NotForLiveSession,
    PolicyDefined,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponseRepresentation {
    ErrorEnvelope,
    ActionTerminalStatus,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErrorSemantics {
    http_statuses: &'static [u16],
    retry_class: RetryClass,
    response_representation: ResponseRepresentation,
}

impl ErrorSemantics {
    #[must_use]
    pub const fn error(http_statuses: &'static [u16], retry_class: RetryClass) -> Self {
        Self {
            http_statuses,
            retry_class,
            response_representation: ResponseRepresentation::ErrorEnvelope,
        }
    }

    #[must_use]
    pub const fn terminal_action(http_statuses: &'static [u16], retry_class: RetryClass) -> Self {
        Self {
            http_statuses,
            retry_class,
            response_representation: ResponseRepresentation::ActionTerminalStatus,
        }
    }

    #[must_use]
    pub const fn http_statuses(self) -> &'static [u16] {
        self.http_statuses
    }

    #[must_use]
    pub const fn retry_class(self) -> RetryClass {
        self.retry_class
    }

    #[must_use]
    pub const fn response_representation(self) -> ResponseRepresentation {
        self.response_representation
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ErrorCode {
    InvalidRequest,
    Unauthenticated,
    PermissionDenied,
    SessionNotFound,
    OperationNotFound,
    PageNotFound,
    StaleNodeRef,
    StaleDocumentRef,
    SnapshotStale,
    GenerationMismatch,
    PlacementMismatch,
    IdempotencyConflict,
    ApprovalStale,
    SessionControlledByHuman,
    ReconciliationRequired,
    ActionResolutionInvalid,
    ActionOutcomeUnknown,
    ActionTimeout,
    ActionAdmissionTimeout,
    TenantQuotaExceeded,
    RateLimited,
    NetworkPolicyDenied,
    NetworkBudgetExceeded,
    ArtifactTooLarge,
    SnapshotTooLarge,
    TargetLimitExceeded,
    QueueTimeout,
    GlobalCapacityExceeded,
    BrowserStartFailed,
    ContextCreateFailed,
    TargetBootstrapFailed,
    BrowserCrashed,
    WorkerLost,
    WorkerUnavailable,
    SessionExpired,
    AuditUnavailable,
    Internal,
}

impl ErrorCode {
    #[must_use]
    pub const fn semantics(self) -> ErrorSemantics {
        use ErrorCode as Code;
        use RetryClass as Retry;

        match self {
            Code::InvalidRequest => ErrorSemantics::error(&[400], Retry::Never),
            Code::Unauthenticated => ErrorSemantics::error(&[401], Retry::Conditional),
            Code::PermissionDenied => ErrorSemantics::error(&[403], Retry::Never),
            Code::SessionNotFound | Code::OperationNotFound | Code::PageNotFound => {
                ErrorSemantics::error(&[404], Retry::Never)
            }
            Code::StaleNodeRef | Code::StaleDocumentRef | Code::SnapshotStale => {
                ErrorSemantics::error(&[409], Retry::ReadOnly)
            }
            Code::GenerationMismatch => ErrorSemantics::error(&[412], Retry::Never),
            Code::PlacementMismatch => ErrorSemantics::error(&[409, 503], Retry::StatusLookupOnly),
            Code::IdempotencyConflict | Code::ApprovalStale | Code::ActionResolutionInvalid => {
                ErrorSemantics::error(&[409], Retry::Never)
            }
            Code::SessionControlledByHuman => ErrorSemantics::error(&[423], Retry::Safe),
            Code::ReconciliationRequired => {
                ErrorSemantics::error(&[409], Retry::MutationDisallowed)
            }
            Code::ActionOutcomeUnknown => ErrorSemantics::terminal_action(&[200], Retry::Never),
            Code::ActionTimeout => ErrorSemantics::error(&[504], Retry::Conditional),
            Code::ActionAdmissionTimeout => ErrorSemantics::error(&[503], Retry::Safe),
            Code::TenantQuotaExceeded | Code::RateLimited => {
                ErrorSemantics::error(&[429], Retry::Safe)
            }
            Code::NetworkPolicyDenied => ErrorSemantics::error(&[403], Retry::Never),
            Code::NetworkBudgetExceeded => ErrorSemantics::error(&[429], Retry::PolicyDefined),
            Code::ArtifactTooLarge | Code::SnapshotTooLarge => {
                ErrorSemantics::error(&[413], Retry::Never)
            }
            Code::TargetLimitExceeded => ErrorSemantics::error(&[429], Retry::Conditional),
            Code::QueueTimeout
            | Code::GlobalCapacityExceeded
            | Code::BrowserStartFailed
            | Code::ContextCreateFailed
            | Code::AuditUnavailable => ErrorSemantics::error(&[503], Retry::Safe),
            Code::TargetBootstrapFailed => ErrorSemantics::error(&[503], Retry::Conditional),
            Code::BrowserCrashed | Code::WorkerLost => {
                ErrorSemantics::error(&[503], Retry::NotForLiveSession)
            }
            Code::WorkerUnavailable => ErrorSemantics::error(&[503], Retry::StatusLookupOnly),
            Code::SessionExpired => ErrorSemantics::error(&[410], Retry::Never),
            Code::Internal => ErrorSemantics::error(&[500], Retry::Conditional),
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::Unauthenticated => "unauthenticated",
            Self::PermissionDenied => "permission_denied",
            Self::SessionNotFound => "session_not_found",
            Self::OperationNotFound => "operation_not_found",
            Self::PageNotFound => "page_not_found",
            Self::StaleNodeRef => "stale_node_ref",
            Self::StaleDocumentRef => "stale_document_ref",
            Self::SnapshotStale => "snapshot_stale",
            Self::GenerationMismatch => "generation_mismatch",
            Self::PlacementMismatch => "placement_mismatch",
            Self::IdempotencyConflict => "idempotency_conflict",
            Self::ApprovalStale => "approval_stale",
            Self::SessionControlledByHuman => "session_controlled_by_human",
            Self::ReconciliationRequired => "reconciliation_required",
            Self::ActionResolutionInvalid => "action_resolution_invalid",
            Self::ActionOutcomeUnknown => "action_outcome_unknown",
            Self::ActionTimeout => "action_timeout",
            Self::ActionAdmissionTimeout => "action_admission_timeout",
            Self::TenantQuotaExceeded => "tenant_quota_exceeded",
            Self::RateLimited => "rate_limited",
            Self::NetworkPolicyDenied => "network_policy_denied",
            Self::NetworkBudgetExceeded => "network_budget_exceeded",
            Self::ArtifactTooLarge => "artifact_too_large",
            Self::SnapshotTooLarge => "snapshot_too_large",
            Self::TargetLimitExceeded => "target_limit_exceeded",
            Self::QueueTimeout => "queue_timeout",
            Self::GlobalCapacityExceeded => "global_capacity_exceeded",
            Self::BrowserStartFailed => "browser_start_failed",
            Self::ContextCreateFailed => "context_create_failed",
            Self::TargetBootstrapFailed => "target_bootstrap_failed",
            Self::BrowserCrashed => "browser_crashed",
            Self::WorkerLost => "worker_lost",
            Self::WorkerUnavailable => "worker_unavailable",
            Self::SessionExpired => "session_expired",
            Self::AuditUnavailable => "audit_unavailable",
            Self::Internal => "internal",
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}
