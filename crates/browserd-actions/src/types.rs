use std::fmt;

use browserd_core::{
    ActionId, ActionState, LeaseId, PlacementFence, PrincipalId, SessionId, TenantId,
};

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
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

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
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

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
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

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KnownFailureReason {
    NotDispatched,
    BrowserRejected,
    PolicyDenied,
    ApprovalDenied,
    ApprovalTimedOut,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolutionKind {
    ConfirmedExecuted,
    ConfirmedNotExecuted,
    Abandoned,
}

#[derive(Clone, Debug, Eq, PartialEq)]
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
pub struct ActionSnapshot {
    pub(crate) action_id: ActionId,
    pub(crate) action_sequence: ActionSequence,
    pub(crate) request: ActionRequest,
    pub(crate) state: ActionState,
    pub(crate) dispatch_permit: Option<DispatchPermit>,
    pub(crate) dispatch_acknowledged: bool,
    pub(crate) terminal_detail: Option<TerminalDetail>,
    pub(crate) resolution: Option<ResolutionAnnotation>,
}

impl ActionSnapshot {
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
    ReadyToDispatch,
    DispatchIntent,
    DispatchAcknowledged,
    Terminal,
    Resolved,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JournalEntryKind {
    Accepted {
        idempotency_key: IdempotencyKey,
        canonical_request_hash: CanonicalRequestHash,
        action_kind: ActionKind,
    },
    Enqueued,
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
            Self::ReadyToDispatch => JournalEntryType::ReadyToDispatch,
            Self::DispatchIntent { .. } => JournalEntryType::DispatchIntent,
            Self::DispatchAcknowledged { .. } => JournalEntryType::DispatchAcknowledged,
            Self::Terminal { .. } => JournalEntryType::Terminal,
            Self::Resolved { .. } => JournalEntryType::Resolved,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalEntry {
    pub(crate) session_id: SessionId,
    pub(crate) action_id: ActionId,
    pub(crate) action_sequence: ActionSequence,
    pub(crate) kind: JournalEntryKind,
}

impl JournalEntry {
    #[must_use]
    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ActionLedgerError {
    JournalUnavailable(JournalError),
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
