//! Immutable public notifications. Values are finite states and typed identifiers, never payloads.
use browserd_core::{
    ActionId, ApprovalId, ArtifactId, CreateOperationState, OperationId, SessionId,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{EventOutboxError, OutboxAggregate, OutboxAppend, OutboxEvent, OutboxEventKind};

pub const MAX_ENCODED_OUTBOX_EVENT_BYTES: usize = 32 * 1024;

macro_rules! states {
    ($name:ident {$($variant:ident),+ $(,)?}) => {
        #[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
        #[serde(rename_all = "snake_case")]
        pub enum $name { $($variant),+ }
    };
}
states!(EventOperationState {
    Accepted,
    Queued,
    Reserving,
    Creating,
    Succeeded,
    TimedOut,
    Cancelled,
    Failed
});
states!(EventSessionLifecycleState {
    Creating,
    Ready,
    Closing,
    Closed,
    Failed
});
states!(EventSessionExecutionState {
    Idle,
    Running,
    PendingApproval,
    ReconciliationRequired
});
states!(EventActionState {
    Accepted,
    Queued,
    PendingApproval,
    ReadyToDispatch,
    MayHaveExecuted,
    Succeeded,
    FailedKnown,
    CancelledBeforeDispatch,
    CancelledConfirmed,
    OutcomeUnknown
});
states!(EventActionResolution {
    ConfirmedExecuted,
    ConfirmedNotExecuted,
    Abandoned
});
states!(EventApprovalDecision {
    Approved,
    Denied,
    Expired
});
states!(EventControlState { Agent, Human });
states!(EventDownloadState { Completed });
states!(EventArtifactState {
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
    Deleted
});

impl From<CreateOperationState> for EventOperationState {
    fn from(state: CreateOperationState) -> Self {
        match state {
            CreateOperationState::Accepted => Self::Accepted,
            CreateOperationState::Queued => Self::Queued,
            CreateOperationState::Reserving => Self::Reserving,
            CreateOperationState::Creating => Self::Creating,
            CreateOperationState::Succeeded => Self::Succeeded,
            CreateOperationState::TimedOut => Self::TimedOut,
            CreateOperationState::Cancelled => Self::Cancelled,
            CreateOperationState::Failed => Self::Failed,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum EventStateSummary {
    Operation {
        state: EventOperationState,
    },
    SessionLifecycle {
        state: EventSessionLifecycleState,
    },
    SessionExecution {
        state: EventSessionExecutionState,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        action_id: Option<ActionId>,
    },
    Action {
        state: EventActionState,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        resolution: Option<EventActionResolution>,
    },
    ApprovalRequired {
        approval_id: ApprovalId,
    },
    Approval {
        state: EventApprovalDecision,
    },
    Control {
        state: EventControlState,
    },
    Download {
        state: EventDownloadState,
    },
    Artifact {
        state: EventArtifactState,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum EventNotificationKind {
    #[serde(rename = "operation.state_changed")]
    OperationStateChanged,
    #[serde(rename = "session.lifecycle_changed")]
    SessionLifecycleChanged,
    #[serde(rename = "session.execution_changed")]
    SessionExecutionChanged,
    #[serde(rename = "action.state_changed")]
    ActionStateChanged,
    #[serde(rename = "action.approval_required")]
    ActionApprovalRequired,
    #[serde(rename = "approval.decided")]
    ApprovalDecided,
    #[serde(rename = "browser.control.changed")]
    BrowserControlChanged,
    #[serde(rename = "download.completed")]
    DownloadCompleted,
    #[serde(rename = "artifact.state_changed")]
    ArtifactStateChanged,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "type",
    content = "id",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum EventNotificationResource {
    Operation(OperationId),
    Session(SessionId),
    Action(ActionId),
    Approval(ApprovalId),
    Artifact(ArtifactId),
}

/// Shared polling/webhook shape, in deterministic declaration order.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OutboxEventWire {
    pub event_id: Uuid,
    pub kind: EventNotificationKind,
    pub created_at: DateTime<Utc>,
    pub resource: EventNotificationResource,
    /// Parent namespace needed by canonical action, artifact, and approval GET routes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<SessionId>,
    pub aggregate_revision: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<EventStateSummary>,
}

impl OutboxEventKind {
    pub(super) const fn storage_name(self) -> &'static str {
        match self {
            Self::ActionTerminal => "action_terminal",
            Self::SessionLost => "session_lost",
            Self::ControlChanged => "control_changed",
            Self::OperationStateChanged => "operation_state_changed",
            Self::SessionLifecycleChanged => "session_lifecycle_changed",
            Self::SessionExecutionChanged => "session_execution_changed",
            Self::ActionStateChanged => "action_state_changed",
            Self::ActionApprovalRequired => "action_approval_required",
            Self::ApprovalDecided => "approval_decided",
            Self::BrowserControlChanged => "browser_control_changed",
            Self::DownloadCompleted => "download_completed",
            Self::ArtifactStateChanged => "artifact_state_changed",
        }
    }
    pub(super) fn from_storage_name(name: &str) -> Option<Self> {
        Some(match name {
            "action_terminal" => Self::ActionTerminal,
            "session_lost" => Self::SessionLost,
            "control_changed" => Self::ControlChanged,
            "operation_state_changed" => Self::OperationStateChanged,
            "session_lifecycle_changed" => Self::SessionLifecycleChanged,
            "session_execution_changed" => Self::SessionExecutionChanged,
            "action_state_changed" => Self::ActionStateChanged,
            "action_approval_required" => Self::ActionApprovalRequired,
            "approval_decided" => Self::ApprovalDecided,
            "browser_control_changed" => Self::BrowserControlChanged,
            "download_completed" => Self::DownloadCompleted,
            "artifact_state_changed" => Self::ArtifactStateChanged,
            _ => return None,
        })
    }
    #[must_use]
    pub const fn public_kind(self) -> EventNotificationKind {
        match self {
            Self::ActionTerminal | Self::ActionStateChanged => {
                EventNotificationKind::ActionStateChanged
            }
            Self::SessionLost | Self::SessionLifecycleChanged => {
                EventNotificationKind::SessionLifecycleChanged
            }
            Self::ControlChanged | Self::BrowserControlChanged => {
                EventNotificationKind::BrowserControlChanged
            }
            Self::OperationStateChanged => EventNotificationKind::OperationStateChanged,
            Self::SessionExecutionChanged => EventNotificationKind::SessionExecutionChanged,
            Self::ActionApprovalRequired => EventNotificationKind::ActionApprovalRequired,
            Self::ApprovalDecided => EventNotificationKind::ApprovalDecided,
            Self::DownloadCompleted => EventNotificationKind::DownloadCompleted,
            Self::ArtifactStateChanged => EventNotificationKind::ArtifactStateChanged,
        }
    }
}

pub(super) fn dedup_key(
    aggregate: &OutboxAggregate,
    revision: u64,
    kind: OutboxEventKind,
) -> String {
    let aggregate = match aggregate {
        OutboxAggregate::Action {
            session_id,
            action_id,
        } => format!("A:{session_id}:{action_id}"),
        OutboxAggregate::Session { session_id } => format!("S:{session_id}"),
        OutboxAggregate::Operation { operation_id } => format!("O:{operation_id}"),
        OutboxAggregate::Approval {
            session_id,
            action_id,
            approval_id,
        } => format!("P:{session_id}:{action_id}:{approval_id}"),
        OutboxAggregate::Artifact {
            session_id,
            artifact_id,
        } => format!("F:{session_id}:{artifact_id}"),
    };
    let kind = match kind {
        OutboxEventKind::ActionTerminal => "t",
        OutboxEventKind::SessionLost => "l",
        OutboxEventKind::ControlChanged => "c",
        other => other.storage_name(),
    };
    format!("{aggregate}:{revision}:{kind}")
}

impl OutboxAppend {
    pub fn state_changed(
        tenant_id: browserd_core::TenantId,
        aggregate: OutboxAggregate,
        aggregate_revision: u64,
        kind: OutboxEventKind,
        summary: EventStateSummary,
    ) -> Result<Self, EventOutboxError> {
        let value = Self {
            tenant_id,
            aggregate,
            aggregate_revision,
            kind,
            summary: Some(summary),
        };
        value.validate()?;
        Ok(value)
    }
    #[must_use]
    pub const fn summary(&self) -> Option<&EventStateSummary> {
        self.summary.as_ref()
    }
    #[must_use]
    pub const fn aggregate(&self) -> &OutboxAggregate {
        &self.aggregate
    }
    pub fn validate(&self) -> Result<(), EventOutboxError> {
        use EventStateSummary as S;
        use OutboxAggregate as A;
        use OutboxEventKind as K;
        let valid = match (&self.kind, &self.aggregate, &self.summary) {
            (K::ActionTerminal, A::Action { .. }, None)
            | (K::SessionLost | K::ControlChanged, A::Session { .. }, None) => true,
            (K::OperationStateChanged, A::Operation { .. }, Some(S::Operation { state })) => {
                (self.aggregate_revision == 0) == (*state == EventOperationState::Accepted)
            }
            (K::SessionLifecycleChanged, A::Session { .. }, Some(S::SessionLifecycle { .. }))
            | (K::ActionApprovalRequired, A::Action { .. }, Some(S::ApprovalRequired { .. }))
            | (K::ApprovalDecided, A::Approval { .. }, Some(S::Approval { .. }))
            | (K::BrowserControlChanged, A::Session { .. }, Some(S::Control { .. }))
            | (K::DownloadCompleted, A::Artifact { .. }, Some(S::Download { .. }))
            | (K::ArtifactStateChanged, A::Artifact { .. }, Some(S::Artifact { .. })) => {
                self.aggregate_revision > 0
            }
            (
                K::SessionExecutionChanged,
                A::Session { .. },
                Some(S::SessionExecution { state, action_id }),
            ) => {
                self.aggregate_revision > 0
                    && (*state == EventSessionExecutionState::Idle) == action_id.is_none()
            }
            (K::ActionStateChanged, A::Action { .. }, Some(S::Action { state, resolution })) => {
                self.aggregate_revision > 0
                    && (resolution.is_none() || *state == EventActionState::OutcomeUnknown)
            }
            _ => false,
        };
        if valid && self.aggregate_revision <= i64::MAX as u64 {
            Ok(())
        } else {
            Err(EventOutboxError::InvalidEvent)
        }
    }
}

impl OutboxEvent {
    #[must_use]
    pub const fn summary(&self) -> Option<&EventStateSummary> {
        self.summary.as_ref()
    }
    #[must_use]
    pub fn public_wire(&self) -> OutboxEventWire {
        let resource = match &self.aggregate {
            OutboxAggregate::Operation { operation_id } => {
                EventNotificationResource::Operation(operation_id.clone())
            }
            OutboxAggregate::Session { session_id } => {
                EventNotificationResource::Session(session_id.clone())
            }
            OutboxAggregate::Action { action_id, .. } => {
                EventNotificationResource::Action(action_id.clone())
            }
            OutboxAggregate::Approval { approval_id, .. } => {
                EventNotificationResource::Approval(approval_id.clone())
            }
            OutboxAggregate::Artifact { artifact_id, .. } => {
                EventNotificationResource::Artifact(artifact_id.clone())
            }
        };
        let session_id = match &self.aggregate {
            OutboxAggregate::Action { session_id, .. }
            | OutboxAggregate::Approval { session_id, .. }
            | OutboxAggregate::Artifact { session_id, .. } => Some(session_id.clone()),
            OutboxAggregate::Operation { .. } | OutboxAggregate::Session { .. } => None,
        };
        OutboxEventWire {
            event_id: self.event_id,
            kind: self.kind.public_kind(),
            created_at: self.created_at,
            resource,
            session_id,
            aggregate_revision: self.aggregate_revision,
            summary: self.summary.clone(),
        }
    }
    pub(super) fn validate(&self) -> Result<(), EventOutboxError> {
        if self.event_id.get_version() != Some(uuid::Version::SortRand) || self.tenant_seq == 0 {
            return Err(EventOutboxError::InvalidEvent);
        }
        OutboxAppend {
            tenant_id: self.tenant_id.clone(),
            aggregate: self.aggregate.clone(),
            aggregate_revision: self.aggregate_revision,
            kind: self.kind,
            summary: self.summary.clone(),
        }
        .validate()
    }
    pub(super) fn matches_append(&self, append: &OutboxAppend) -> bool {
        self.tenant_id == append.tenant_id
            && self.aggregate == append.aggregate
            && self.aggregate_revision == append.aggregate_revision
            && self.kind == append.kind
            && self.summary == append.summary
    }
}

pub fn encode_outbox_event(event: &OutboxEvent) -> Result<Vec<u8>, EventOutboxError> {
    event.validate()?;
    let bytes =
        serde_json::to_vec(&event.public_wire()).map_err(|_| EventOutboxError::InvalidEvent)?;
    if bytes.len() > MAX_ENCODED_OUTBOX_EVENT_BYTES {
        return Err(EventOutboxError::InvalidEvent);
    }
    Ok(bytes)
}
