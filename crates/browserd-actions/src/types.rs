use std::fmt;

use browserd_core::{
    ActionId, ActionState, LeaseId, PlacementFence, PrincipalId, SessionId, TenantId,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct IdempotencyKey(String);

impl IdempotencyKey {
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct CanonicalRequestHash([u8; 32]);

impl CanonicalRequestHash {
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct ResultDigest([u8; 32]);

impl ResultDigest {
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct ActionSequence(u64);

impl ActionSequence {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ActionKind {
    ReadOnly,
    Mutating,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionRequest {
    idempotency_key: IdempotencyKey,
    canonical_request_hash: CanonicalRequestHash,
    kind: ActionKind,
}

impl ActionRequest {
    #[must_use]
    pub const fn new(
        idempotency_key: IdempotencyKey,
        canonical_request_hash: CanonicalRequestHash,
        kind: ActionKind,
    ) -> Self {
        Self {
            idempotency_key,
            canonical_request_hash,
            kind,
        }
    }

    #[must_use]
    pub const fn idempotency_key(&self) -> &IdempotencyKey {
        &self.idempotency_key
    }

    #[must_use]
    pub const fn canonical_request_hash(&self) -> CanonicalRequestHash {
        self.canonical_request_hash
    }

    #[must_use]
    pub const fn kind(&self) -> ActionKind {
        self.kind
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LedgerSession {
    tenant_id: TenantId,
    session_id: SessionId,
    fence: PlacementFence,
}

impl LedgerSession {
    #[must_use]
    pub const fn new(tenant_id: TenantId, session_id: SessionId, fence: PlacementFence) -> Self {
        Self {
            tenant_id,
            session_id,
            fence,
        }
    }

    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    #[must_use]
    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    #[must_use]
    pub const fn fence(&self) -> PlacementFence {
        self.fence
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct DispatchId(pub(crate) LeaseId);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DispatchPermit {
    pub(crate) action_id: ActionId,
    pub(crate) action_sequence: ActionSequence,
    pub(crate) dispatch_id: DispatchId,
}

impl DispatchPermit {
    #[must_use]
    pub const fn action_id(&self) -> &ActionId {
        &self.action_id
    }

    #[must_use]
    pub const fn action_sequence(&self) -> ActionSequence {
        self.action_sequence
    }

    #[must_use]
    pub const fn dispatch_id(&self) -> &DispatchId {
        &self.dispatch_id
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum KnownFailureReason {
    NotDispatched,
    BrowserRejected,
    PolicyDenied,
    ApprovalDenied,
    ApprovalTimedOut,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum OutcomeUnknownReason {
    AmbiguousTransportLoss,
    WorkerLost,
    TimeoutAfterDispatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrowserResult {
    Succeeded(ResultDigest),
    FailedKnown(KnownFailureReason),
    CancellationConfirmed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportLoss {
    ConfirmedNotWritten,
    Ambiguous(OutcomeUnknownReason),
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ApprovalDecision {
    Granted,
    Denied,
    TimedOut,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum TerminalDetail {
    Succeeded(ResultDigest),
    FailedKnown(KnownFailureReason),
    CancelledBeforeDispatch,
    CancelledConfirmed,
    OutcomeUnknown(OutcomeUnknownReason),
}

impl TerminalDetail {
    #[must_use]
    pub const fn state(self) -> ActionState {
        match self {
            Self::Succeeded(_) => ActionState::Succeeded,
            Self::FailedKnown(_) => ActionState::FailedKnown,
            Self::CancelledBeforeDispatch => ActionState::CancelledBeforeDispatch,
            Self::CancelledConfirmed => ActionState::CancelledConfirmed,
            Self::OutcomeUnknown(_) => ActionState::OutcomeUnknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ResolutionKind {
    ConfirmedExecuted,
    ConfirmedNotExecuted,
    Abandoned,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ResolutionAnnotation {
    kind: ResolutionKind,
    resolved_by: PrincipalId,
    resolved_at_millis: u64,
    basis: String,
}

impl ResolutionAnnotation {
    #[must_use]
    pub fn new(
        kind: ResolutionKind,
        resolved_by: PrincipalId,
        resolved_at_millis: u64,
        basis: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            resolved_by,
            resolved_at_millis,
            basis: basis.into(),
        }
    }

    #[must_use]
    pub const fn kind(&self) -> ResolutionKind {
        self.kind
    }

    #[must_use]
    pub const fn resolved_by(&self) -> &PrincipalId {
        &self.resolved_by
    }

    #[must_use]
    pub const fn resolved_at_millis(&self) -> u64 {
        self.resolved_at_millis
    }

    #[must_use]
    pub fn basis(&self) -> &str {
        &self.basis
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResolutionPolicy {
    allow_abandoned: bool,
}

impl ResolutionPolicy {
    #[must_use]
    pub const fn new(allow_abandoned: bool) -> Self {
        Self { allow_abandoned }
    }

    #[must_use]
    pub const fn allow_abandoned(self) -> bool {
        self.allow_abandoned
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionSnapshotFacts {
    pub action_id: ActionId,
    pub action_sequence: ActionSequence,
    pub idempotency_key: IdempotencyKey,
    pub canonical_request_hash: CanonicalRequestHash,
    pub kind: ActionKind,
    pub state: ActionState,
    pub dispatch_acknowledged: bool,
    pub approval_decision: Option<ApprovalDecision>,
    pub terminal_detail: Option<TerminalDetail>,
    pub resolution: Option<ResolutionAnnotation>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActionSnapshotReconstructionError;

impl fmt::Display for ActionSnapshotReconstructionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("action snapshot facts are contradictory or out of bounds")
    }
}

impl std::error::Error for ActionSnapshotReconstructionError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionSnapshot {
    pub(crate) action_id: ActionId,
    pub(crate) action_sequence: ActionSequence,
    pub(crate) request: ActionRequest,
    pub(crate) state: ActionState,
    pub(crate) dispatch_permit: Option<DispatchPermit>,
    pub(crate) dispatch_acknowledged: bool,
    pub(crate) approval_decision: Option<ApprovalDecision>,
    pub(crate) terminal_detail: Option<TerminalDetail>,
    pub(crate) resolution: Option<ResolutionAnnotation>,
}

impl ActionSnapshot {
    pub fn from_facts(
        facts: ActionSnapshotFacts,
    ) -> Result<Self, ActionSnapshotReconstructionError> {
        let idempotency_key = facts.idempotency_key.as_str();
        if facts.action_sequence.get() == 0
            || idempotency_key.is_empty()
            || idempotency_key.len() > 255
            || idempotency_key.trim() != idempotency_key
            || idempotency_key.chars().any(char::is_control)
            || if facts.state.is_terminal() {
                !facts
                    .terminal_detail
                    .is_some_and(|detail| detail.state() == facts.state)
            } else {
                facts.terminal_detail.is_some()
            }
            || (facts.resolution.is_some() && facts.state != ActionState::OutcomeUnknown)
            || matches!(
                (facts.approval_decision, facts.terminal_detail),
                (
                    Some(ApprovalDecision::Denied),
                    Some(TerminalDetail::FailedKnown(reason))
                ) if reason != KnownFailureReason::ApprovalDenied
            )
            || matches!(
                (facts.approval_decision, facts.terminal_detail),
                (
                    Some(ApprovalDecision::TimedOut),
                    Some(TerminalDetail::FailedKnown(reason))
                ) if reason != KnownFailureReason::ApprovalTimedOut
            )
            || matches!(
                facts.terminal_detail,
                Some(TerminalDetail::FailedKnown(
                    KnownFailureReason::ApprovalDenied
                ))
            ) && facts.approval_decision != Some(ApprovalDecision::Denied)
            || matches!(
                facts.terminal_detail,
                Some(TerminalDetail::FailedKnown(
                    KnownFailureReason::ApprovalTimedOut
                ))
            ) && facts.approval_decision != Some(ApprovalDecision::TimedOut)
            || (matches!(
                facts.approval_decision,
                Some(ApprovalDecision::Denied | ApprovalDecision::TimedOut)
            ) && facts.state != ActionState::FailedKnown)
            || (facts.approval_decision == Some(ApprovalDecision::Granted)
                && matches!(
                    facts.state,
                    ActionState::Accepted | ActionState::Queued | ActionState::PendingApproval
                ))
        {
            return Err(ActionSnapshotReconstructionError);
        }
        Ok(Self {
            action_id: facts.action_id,
            action_sequence: facts.action_sequence,
            request: ActionRequest::new(
                facts.idempotency_key,
                facts.canonical_request_hash,
                facts.kind,
            ),
            state: facts.state,
            dispatch_permit: None,
            dispatch_acknowledged: facts.dispatch_acknowledged,
            approval_decision: facts.approval_decision,
            terminal_detail: facts.terminal_detail,
            resolution: facts.resolution,
        })
    }

    #[must_use]
    pub const fn action_id(&self) -> &ActionId {
        &self.action_id
    }

    #[must_use]
    pub const fn action_sequence(&self) -> ActionSequence {
        self.action_sequence
    }

    #[must_use]
    pub const fn request(&self) -> &ActionRequest {
        &self.request
    }

    #[must_use]
    pub const fn state(&self) -> ActionState {
        self.state
    }

    #[must_use]
    pub const fn dispatch_permit(&self) -> Option<&DispatchPermit> {
        self.dispatch_permit.as_ref()
    }

    #[must_use]
    pub const fn dispatch_acknowledged(&self) -> bool {
        self.dispatch_acknowledged
    }

    #[must_use]
    pub const fn approval_decision(&self) -> Option<ApprovalDecision> {
        self.approval_decision
    }

    #[must_use]
    pub const fn terminal_detail(&self) -> Option<TerminalDetail> {
        self.terminal_detail
    }

    #[must_use]
    pub const fn resolution(&self) -> Option<&ResolutionAnnotation> {
        self.resolution.as_ref()
    }

    #[must_use]
    pub const fn automatic_replay_allowed(&self) -> bool {
        matches!(
            self.state,
            ActionState::Accepted
                | ActionState::Queued
                | ActionState::PendingApproval
                | ActionState::ReadyToDispatch
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AcceptDecision {
    Created(ActionSnapshot),
    Existing(ActionSnapshot),
}

impl AcceptDecision {
    #[must_use]
    pub const fn snapshot(&self) -> &ActionSnapshot {
        match self {
            Self::Created(snapshot) | Self::Existing(snapshot) => snapshot,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DispatchDecision {
    Dispatch(DispatchPermit),
    DoNotReplay(ActionSnapshot),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordOutcome {
    Recorded,
    AlreadyRecorded,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResolutionOutcome {
    Recorded(ActionSnapshot),
    AlreadyRecorded(ActionSnapshot),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JournalEntryType {
    Accepted,
    Enqueued,
    ApprovalRequired,
    ApprovalGranted,
    ReadyToDispatch,
    DispatchIntent,
    DispatchAcknowledged,
    Terminal,
    Resolved,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum JournalEntryKind {
    Accepted {
        idempotency_key: IdempotencyKey,
        canonical_request_hash: CanonicalRequestHash,
        action_kind: ActionKind,
    },
    Enqueued,
    ApprovalRequired,
    ApprovalGranted,
    ReadyToDispatch,
    DispatchIntent {
        dispatch_id: DispatchId,
    },
    DispatchAcknowledged {
        dispatch_id: DispatchId,
    },
    Terminal {
        detail: TerminalDetail,
    },
    Resolved {
        annotation: ResolutionAnnotation,
    },
}

impl JournalEntryKind {
    #[must_use]
    pub const fn entry_type(&self) -> JournalEntryType {
        match self {
            Self::Accepted { .. } => JournalEntryType::Accepted,
            Self::Enqueued => JournalEntryType::Enqueued,
            Self::ApprovalRequired => JournalEntryType::ApprovalRequired,
            Self::ApprovalGranted => JournalEntryType::ApprovalGranted,
            Self::ReadyToDispatch => JournalEntryType::ReadyToDispatch,
            Self::DispatchIntent { .. } => JournalEntryType::DispatchIntent,
            Self::DispatchAcknowledged { .. } => JournalEntryType::DispatchAcknowledged,
            Self::Terminal { .. } => JournalEntryType::Terminal,
            Self::Resolved { .. } => JournalEntryType::Resolved,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct JournalFence {
    worker_epoch: u64,
    placement_version: u64,
    session_incarnation: u64,
}

impl From<PlacementFence> for JournalFence {
    fn from(value: PlacementFence) -> Self {
        Self {
            worker_epoch: value.worker_epoch,
            placement_version: value.placement_version,
            session_incarnation: value.session_incarnation,
        }
    }
}

impl From<JournalFence> for PlacementFence {
    fn from(value: JournalFence) -> Self {
        Self::new(
            value.worker_epoch,
            value.placement_version,
            value.session_incarnation,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct JournalEntry {
    tenant_id: TenantId,
    pub(crate) session_id: SessionId,
    fence: JournalFence,
    pub(crate) action_id: ActionId,
    pub(crate) action_sequence: ActionSequence,
    pub(crate) kind: JournalEntryKind,
}

impl JournalEntry {
    pub(crate) fn new(
        session: &LedgerSession,
        action_id: ActionId,
        action_sequence: ActionSequence,
        kind: JournalEntryKind,
    ) -> Self {
        Self {
            tenant_id: session.tenant_id().clone(),
            session_id: session.session_id().clone(),
            fence: session.fence().into(),
            action_id,
            action_sequence,
            kind,
        }
    }

    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    #[must_use]
    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    #[must_use]
    pub fn fence(&self) -> PlacementFence {
        self.fence.into()
    }

    #[must_use]
    pub const fn action_id(&self) -> &ActionId {
        &self.action_id
    }

    #[must_use]
    pub const fn action_sequence(&self) -> ActionSequence {
        self.action_sequence
    }

    #[must_use]
    pub const fn kind(&self) -> &JournalEntryKind {
        &self.kind
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalError {
    message: String,
}

impl JournalError {
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for JournalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for JournalError {}

pub trait DurableActionJournal: Send + Sync {
    /// Returns only after the entry is durably committed.
    fn append(&self, entry: &JournalEntry) -> Result<(), JournalError>;
}

pub trait ReplayableActionJournal: DurableActionJournal {
    /// Returns the complete ordered durable prefix or fails without repairing it.
    fn replay(&self) -> Result<Vec<JournalEntry>, JournalError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ActionLedgerError {
    JournalUnavailable(JournalError),
    RecoveryInvalid(JournalError),
    StateUnavailable,
    StaleFence {
        expected: PlacementFence,
        received: PlacementFence,
    },
    IdempotencyConflict {
        existing_action_id: ActionId,
    },
    ActionNotFound,
    InvalidTransition {
        state: ActionState,
    },
    ApprovalDecisionConflict {
        current: ApprovalDecision,
        attempted: ApprovalDecision,
    },
    CorrelationMismatch,
    DeliveryEvidenceConflict,
    TerminalStateConflict {
        current: TerminalDetail,
        attempted: TerminalDetail,
    },
    ResolutionInvalid,
    ResolutionConflict,
    AbandonedResolutionDenied,
    SequenceExhausted,
}

impl fmt::Display for ActionLedgerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "action ledger error: {self:?}")
    }
}

impl std::error::Error for ActionLedgerError {}
