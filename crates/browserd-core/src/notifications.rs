//! Bounded, immutable metadata committed by the original worker state authority.
//! This is notification transfer evidence, never browser replay authority.
use std::collections::HashSet;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use uuid::{Uuid, Version};

use crate::{
    ActionId, ActionState, ApprovalId, ArtifactId, PlacementFence, SessionId, TenantId, WorkerId,
};

pub const MAX_NOTIFICATION_DESCRIPTORS: usize = 8;
pub const MAX_NOTIFICATION_COMMIT_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NotificationError {
    InvalidScope,
    InvalidDescriptor,
    InvalidSequence,
    InvalidTimestamp,
    InvalidBatch,
    InvalidDigest,
    EncodingBound,
}
impl fmt::Display for NotificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid worker notification metadata: {self:?}")
    }
}
impl std::error::Error for NotificationError {}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationSourceFamily {
    ActionJournal,
    ArtifactRegistry,
    SessionLifecycle,
    ControlJournal,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationSourceScope {
    tenant_id: TenantId,
    original_worker_id: WorkerId,
    source_id: Uuid,
    family: NotificationSourceFamily,
}
impl NotificationSourceScope {
    pub fn new(
        tenant_id: TenantId,
        original_worker_id: WorkerId,
        source_id: Uuid,
        family: NotificationSourceFamily,
    ) -> Result<Self, NotificationError> {
        let value = Self {
            tenant_id,
            original_worker_id,
            source_id,
            family,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<(), NotificationError> {
        if self.source_id.is_nil()
            || !matches!(
                self.source_id.get_version(),
                Some(Version::Random | Version::SortRand)
            )
        {
            return Err(NotificationError::InvalidScope);
        }
        Ok(())
    }
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }
    #[must_use]
    pub const fn original_worker_id(&self) -> &WorkerId {
        &self.original_worker_id
    }
    #[must_use]
    pub const fn source_id(&self) -> Uuid {
        self.source_id
    }
    #[must_use]
    pub const fn family(&self) -> NotificationSourceFamily {
        self.family
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationSessionScope {
    session_id: SessionId,
    worker_epoch: u64,
    placement_version: u64,
    session_incarnation: u64,
}
impl NotificationSessionScope {
    pub fn new(session_id: SessionId, fence: PlacementFence) -> Result<Self, NotificationError> {
        let value = Self {
            session_id,
            worker_epoch: fence.worker_epoch,
            placement_version: fence.placement_version,
            session_incarnation: fence.session_incarnation,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<(), NotificationError> {
        if self.worker_epoch == 0 || self.placement_version == 0 || self.session_incarnation == 0 {
            return Err(NotificationError::InvalidScope);
        }
        Ok(())
    }
    #[must_use]
    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
    }
    #[must_use]
    pub const fn fence(&self) -> PlacementFence {
        PlacementFence::new(
            self.worker_epoch,
            self.placement_version,
            self.session_incarnation,
        )
    }
}

macro_rules! states {
    ($name:ident {$($variant:ident),+ $(,)?}) => {
        #[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
        #[serde(rename_all = "snake_case")]
        pub enum $name { $($variant),+ }
    };
}
states!(NotificationSessionLifecycleState {
    Creating,
    Ready,
    Closing,
    Closed,
    Failed
});
states!(NotificationSessionExecutionState {
    Idle,
    Running,
    PendingApproval,
    ReconciliationRequired
});
states!(NotificationActionState {
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
states!(NotificationActionResolution {
    ConfirmedExecuted,
    ConfirmedNotExecuted,
    Abandoned
});
states!(NotificationApprovalDecision {
    Approved,
    Denied,
    Expired
});
states!(NotificationControlState { Agent, Human });
states!(NotificationArtifactState {
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

impl From<ActionState> for NotificationActionState {
    fn from(state: ActionState) -> Self {
        match state {
            ActionState::Accepted => Self::Accepted,
            ActionState::Queued => Self::Queued,
            ActionState::PendingApproval => Self::PendingApproval,
            ActionState::ReadyToDispatch => Self::ReadyToDispatch,
            ActionState::MayHaveExecuted => Self::MayHaveExecuted,
            ActionState::Succeeded => Self::Succeeded,
            ActionState::FailedKnown => Self::FailedKnown,
            ActionState::CancelledBeforeDispatch => Self::CancelledBeforeDispatch,
            ActionState::CancelledConfirmed => Self::CancelledConfirmed,
            ActionState::OutcomeUnknown => Self::OutcomeUnknown,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkerNotificationEvent {
    SessionLifecycleChanged {
        state: NotificationSessionLifecycleState,
    },
    SessionExecutionChanged {
        state: NotificationSessionExecutionState,
        action_id: Option<ActionId>,
    },
    ActionStateChanged {
        action_id: ActionId,
        state: NotificationActionState,
        resolution: Option<NotificationActionResolution>,
    },
    ActionApprovalRequired {
        action_id: ActionId,
        approval_id: ApprovalId,
    },
    ApprovalDecided {
        action_id: ActionId,
        approval_id: ApprovalId,
        state: NotificationApprovalDecision,
    },
    BrowserControlChanged {
        state: NotificationControlState,
    },
    DownloadCompleted {
        artifact_id: ArtifactId,
    },
    ArtifactStateChanged {
        artifact_id: ArtifactId,
        state: NotificationArtifactState,
    },
}
impl WorkerNotificationEvent {
    fn validate(&self) -> Result<(), NotificationError> {
        if matches!(
            self,
            Self::SessionExecutionChanged {
                state: NotificationSessionExecutionState::Idle,
                action_id: Some(_)
            }
        ) || matches!(
            self,
            Self::SessionExecutionChanged {
                state: NotificationSessionExecutionState::Running
                    | NotificationSessionExecutionState::PendingApproval
                    | NotificationSessionExecutionState::ReconciliationRequired,
                action_id: None
            }
        ) || matches!(self, Self::ActionStateChanged { state, resolution: Some(_), .. } if *state != NotificationActionState::OutcomeUnknown)
        {
            return Err(NotificationError::InvalidDescriptor);
        }
        Ok(())
    }
    fn family(&self) -> NotificationSourceFamily {
        match self {
            Self::SessionLifecycleChanged { .. } | Self::SessionExecutionChanged { .. } => {
                NotificationSourceFamily::SessionLifecycle
            }
            Self::ActionStateChanged { .. }
            | Self::ActionApprovalRequired { .. }
            | Self::ApprovalDecided { .. } => NotificationSourceFamily::ActionJournal,
            Self::BrowserControlChanged { .. } => NotificationSourceFamily::ControlJournal,
            Self::DownloadCompleted { .. } | Self::ArtifactStateChanged { .. } => {
                NotificationSourceFamily::ArtifactRegistry
            }
        }
    }

    fn public_identity(&self, session_id: &SessionId) -> (u8, Uuid) {
        match self {
            Self::SessionLifecycleChanged { .. } => (1, *session_id.as_uuid()),
            Self::SessionExecutionChanged { .. } => (2, *session_id.as_uuid()),
            Self::ActionStateChanged { action_id, .. } => (3, *action_id.as_uuid()),
            Self::ActionApprovalRequired { action_id, .. } => (4, *action_id.as_uuid()),
            Self::ApprovalDecided { approval_id, .. } => (5, *approval_id.as_uuid()),
            Self::BrowserControlChanged { .. } => (6, *session_id.as_uuid()),
            Self::DownloadCompleted { artifact_id } => (7, *artifact_id.as_uuid()),
            Self::ArtifactStateChanged { artifact_id, .. } => (8, *artifact_id.as_uuid()),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationDescriptor {
    event_id: Uuid,
    session_scope: NotificationSessionScope,
    event: WorkerNotificationEvent,
}
impl NotificationDescriptor {
    pub fn new(
        event_id: Uuid,
        session_scope: NotificationSessionScope,
        event: WorkerNotificationEvent,
    ) -> Result<Self, NotificationError> {
        let value = Self {
            event_id,
            session_scope,
            event,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn fresh(
        session_scope: NotificationSessionScope,
        event: WorkerNotificationEvent,
    ) -> Result<Self, NotificationError> {
        Self::new(Uuid::now_v7(), session_scope, event)
    }
    pub fn validate(&self) -> Result<(), NotificationError> {
        if self.event_id.get_version() != Some(Version::SortRand) {
            return Err(NotificationError::InvalidDescriptor);
        }
        self.session_scope.validate()?;
        self.event.validate()
    }
    #[must_use]
    pub const fn event_id(&self) -> Uuid {
        self.event_id
    }
    #[must_use]
    pub const fn session_scope(&self) -> &NotificationSessionScope {
        &self.session_scope
    }
    #[must_use]
    pub const fn event(&self) -> &WorkerNotificationEvent {
        &self.event
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct NotificationCommit {
    schema_version: u8,
    scope: NotificationSourceScope,
    source_sequence: u64,
    occurred_at_unix_ms: u64,
    descriptors: Vec<NotificationDescriptor>,
    digest: [u8; 32],
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CommitWire {
    schema_version: u8,
    scope: NotificationSourceScope,
    source_sequence: u64,
    occurred_at_unix_ms: u64,
    descriptors: Vec<NotificationDescriptor>,
    digest: [u8; 32],
}
impl<'de> Deserialize<'de> for NotificationCommit {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let w = CommitWire::deserialize(deserializer)?;
        let value = Self {
            schema_version: w.schema_version,
            scope: w.scope,
            source_sequence: w.source_sequence,
            occurred_at_unix_ms: w.occurred_at_unix_ms,
            descriptors: w.descriptors,
            digest: w.digest,
        };
        value.validate().map_err(serde::de::Error::custom)?;
        Ok(value)
    }
}
impl NotificationCommit {
    pub fn new(
        scope: NotificationSourceScope,
        source_sequence: u64,
        occurred_at_unix_ms: u64,
        descriptors: Vec<NotificationDescriptor>,
    ) -> Result<Self, NotificationError> {
        let mut value = Self {
            schema_version: 1,
            scope,
            source_sequence,
            occurred_at_unix_ms,
            descriptors,
            digest: [0; 32],
        };
        value.validate_fields()?;
        value.digest = value.compute_digest()?;
        Ok(value)
    }
    fn validate_fields(&self) -> Result<(), NotificationError> {
        self.scope.validate()?;
        if self.schema_version != 1
            || self.source_sequence == 0
            || self.source_sequence > i64::MAX as u64
        {
            return Err(NotificationError::InvalidSequence);
        }
        if self.occurred_at_unix_ms > i64::MAX as u64 {
            return Err(NotificationError::InvalidTimestamp);
        }
        if self.descriptors.is_empty() || self.descriptors.len() > MAX_NOTIFICATION_DESCRIPTORS {
            return Err(NotificationError::InvalidBatch);
        }
        let mut ids = HashSet::new();
        let mut resources = HashSet::new();
        for d in &self.descriptors {
            d.validate()?;
            if !ids.insert(d.event_id)
                || d.event.family() != self.scope.family
                || !resources.insert(d.event.public_identity(d.session_scope.session_id()))
            {
                return Err(NotificationError::InvalidBatch);
            }
        }
        Ok(())
    }
    fn compute_digest(&self) -> Result<[u8; 32], NotificationError> {
        let encoded = serde_json::to_vec(&(
            self.schema_version,
            &self.scope,
            self.source_sequence,
            self.occurred_at_unix_ms,
            &self.descriptors,
        ))
        .map_err(|_| NotificationError::EncodingBound)?;
        if encoded.len() > MAX_NOTIFICATION_COMMIT_BYTES {
            return Err(NotificationError::EncodingBound);
        }
        let mut hash = Sha256::new();
        hash.update(b"browserd-worker-notification-commit-v1\0");
        hash.update((encoded.len() as u64).to_be_bytes());
        hash.update(encoded);
        Ok(hash.finalize().into())
    }
    pub fn validate(&self) -> Result<(), NotificationError> {
        self.validate_fields()?;
        if self.digest != self.compute_digest()? {
            return Err(NotificationError::InvalidDigest);
        }
        Ok(())
    }
    #[must_use]
    pub const fn scope(&self) -> &NotificationSourceScope {
        &self.scope
    }
    #[must_use]
    pub const fn source_sequence(&self) -> u64 {
        self.source_sequence
    }
    #[must_use]
    pub const fn occurred_at_unix_ms(&self) -> u64 {
        self.occurred_at_unix_ms
    }
    #[must_use]
    pub fn descriptors(&self) -> &[NotificationDescriptor] {
        &self.descriptors
    }
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }
    #[must_use]
    pub fn ack(&self) -> NotificationAck {
        NotificationAck {
            scope: self.scope.clone(),
            source_sequence: self.source_sequence,
            digest: self.digest,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct NotificationAck {
    scope: NotificationSourceScope,
    source_sequence: u64,
    digest: [u8; 32],
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AckWire {
    scope: NotificationSourceScope,
    source_sequence: u64,
    digest: [u8; 32],
}
impl<'de> Deserialize<'de> for NotificationAck {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let w = AckWire::deserialize(deserializer)?;
        let v = Self {
            scope: w.scope,
            source_sequence: w.source_sequence,
            digest: w.digest,
        };
        v.validate().map_err(serde::de::Error::custom)?;
        Ok(v)
    }
}
impl NotificationAck {
    pub fn validate(&self) -> Result<(), NotificationError> {
        self.scope.validate()?;
        if self.source_sequence == 0
            || self.source_sequence > i64::MAX as u64
            || self.digest == [0; 32]
        {
            return Err(NotificationError::InvalidDigest);
        }
        Ok(())
    }
    #[must_use]
    pub const fn scope(&self) -> &NotificationSourceScope {
        &self.scope
    }
    #[must_use]
    pub const fn source_sequence(&self) -> u64 {
        self.source_sequence
    }
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

#[cfg(test)]
mod tests;
