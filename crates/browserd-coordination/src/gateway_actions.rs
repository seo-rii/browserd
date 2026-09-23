use std::collections::HashMap;

use async_trait::async_trait;
use browserd_actions::{
    ActionDeliveryEvidence, ActionEvidence, ActionEvidenceError, ActionEvidenceMutation,
    ActionKind, ActionSequence, ActionTerminalEvidence, BrowserResult, CanonicalRequestHash,
    DispatchId, IdempotencyKey, ResolutionAnnotation, TerminalDetail, TransportLoss,
};
use browserd_core::{ActionId, ActionState, SessionId, TenantId};
use chrono::{DateTime, Utc};
use thiserror::Error;
use uuid::{Uuid, Version};

use crate::{DirectoryFence, MemoryCoordinationDatabase, OutboxAppend, StoreConfig};

mod redis;

pub use redis::{RedisGatewayActionConfig, RedisGatewayActionStore};

const MAX_MATERIALIZATION_LIMIT: usize = 1_000;

/// Upper bound on the durable result body persisted with a succeeded action, matching the
/// worker's action result cap. Bodies larger than this are not produced by the current result
/// set; capture artifacts are stored by reference rather than inlined here.
pub const MAX_DURABLE_RESULT_CONTENT_BYTES: usize = 64 * 1024;

/// Validates that a durable result body is paired only with a succeeded action and stays within
/// [`MAX_DURABLE_RESULT_CONTENT_BYTES`]. Bodies are validated against the digest upstream (on the
/// worker receipt), so this is a fail-closed boundary guard, not the primary integrity check.
fn validate_durable_result_body(
    result: BrowserResult,
    result_body: &Option<Vec<u8>>,
) -> Result<(), GatewayActionCoordinationError> {
    match result_body {
        None => Ok(()),
        Some(body) => {
            if !matches!(result, BrowserResult::Succeeded(_))
                || body.is_empty()
                || body.len() > MAX_DURABLE_RESULT_CONTENT_BYTES
            {
                Err(GatewayActionCoordinationError::CorruptState)
            } else {
                Ok(())
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayActionPlacement {
    directory_fence: DirectoryFence,
    directory_revision: u64,
}

impl GatewayActionPlacement {
    pub fn new(
        directory_fence: DirectoryFence,
        directory_revision: u64,
    ) -> Result<Self, GatewayActionCoordinationError> {
        if directory_revision == 0 {
            return Err(GatewayActionCoordinationError::InvalidPlacement);
        }
        Ok(Self {
            directory_fence,
            directory_revision,
        })
    }

    #[must_use]
    pub const fn directory_fence(&self) -> &DirectoryFence {
        &self.directory_fence
    }

    #[must_use]
    pub const fn directory_revision(&self) -> u64 {
        self.directory_revision
    }
}

fn validated_idempotency_key(
    value: impl Into<String>,
) -> Result<IdempotencyKey, GatewayActionCoordinationError> {
    let value = value.into();
    if value.is_empty()
        || value.len() > 255
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(GatewayActionCoordinationError::InvalidIdempotencyKey);
    }
    Ok(IdempotencyKey::new(value))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimGatewayAction {
    tenant_id: TenantId,
    session_id: SessionId,
    proposed_action_id: ActionId,
    idempotency_key: IdempotencyKey,
    request_hash: CanonicalRequestHash,
    kind: ActionKind,
    placement: GatewayActionPlacement,
}

impl ClaimGatewayAction {
    pub fn new(
        tenant_id: TenantId,
        session_id: SessionId,
        proposed_action_id: ActionId,
        idempotency_key: impl Into<String>,
        request_hash: CanonicalRequestHash,
        kind: ActionKind,
        placement: GatewayActionPlacement,
    ) -> Result<Self, GatewayActionCoordinationError> {
        Ok(Self {
            tenant_id,
            session_id,
            proposed_action_id,
            idempotency_key: validated_idempotency_key(idempotency_key)?,
            request_hash,
            kind,
            placement,
        })
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
    pub const fn proposed_action_id(&self) -> &ActionId {
        &self.proposed_action_id
    }

    #[must_use]
    pub fn idempotency_key(&self) -> &str {
        self.idempotency_key.as_str()
    }

    #[must_use]
    pub const fn request_hash(&self) -> CanonicalRequestHash {
        self.request_hash
    }

    #[must_use]
    pub const fn kind(&self) -> ActionKind {
        self.kind
    }

    #[must_use]
    pub const fn placement(&self) -> &GatewayActionPlacement {
        &self.placement
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayActionSnapshot {
    tenant_id: TenantId,
    session_id: SessionId,
    action_id: ActionId,
    idempotency_key: IdempotencyKey,
    request_hash: CanonicalRequestHash,
    kind: ActionKind,
    placement: GatewayActionPlacement,
    evidence: ActionEvidence,
    resolution: Option<ResolutionAnnotation>,
    result_content: Option<Vec<u8>>,
    action_sequence: ActionSequence,
    revision: u64,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    retain_until: DateTime<Utc>,
}

impl GatewayActionSnapshot {
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    #[must_use]
    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    #[must_use]
    pub const fn action_id(&self) -> &ActionId {
        &self.action_id
    }

    #[must_use]
    pub fn idempotency_key(&self) -> &str {
        self.idempotency_key.as_str()
    }

    #[must_use]
    pub const fn request_hash(&self) -> CanonicalRequestHash {
        self.request_hash
    }

    #[must_use]
    pub const fn kind(&self) -> ActionKind {
        self.kind
    }

    #[must_use]
    pub const fn placement(&self) -> &GatewayActionPlacement {
        &self.placement
    }

    #[must_use]
    pub const fn delivery(&self) -> &ActionDeliveryEvidence {
        self.evidence.delivery()
    }

    #[must_use]
    pub fn terminal(&self) -> Option<ActionTerminalEvidence> {
        self.evidence.terminal().copied()
    }

    #[must_use]
    pub fn state(&self) -> ActionState {
        self.evidence.state()
    }

    #[must_use]
    pub const fn resolution(&self) -> Option<&ResolutionAnnotation> {
        self.resolution.as_ref()
    }

    /// Durable copy of a succeeded action's result body.
    ///
    /// Persisted alongside the terminal evidence so that GET, same-key resubmission, and
    /// gateway/worker restart all return the same result bytes the completing receipt carried,
    /// not just the `ResultDigest`. Bounded by [`MAX_DURABLE_RESULT_CONTENT_BYTES`].
    #[must_use]
    pub fn result_content(&self) -> Option<&[u8]> {
        self.result_content.as_deref()
    }

    #[must_use]
    pub const fn action_sequence(&self) -> ActionSequence {
        self.action_sequence
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    #[must_use]
    pub const fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    #[must_use]
    pub const fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }

    #[must_use]
    pub const fn retain_until(&self) -> DateTime<Utc> {
        self.retain_until
    }

    /// Project this snapshot into the event-outbox append that records its terminal transition, or
    /// `None` while the action has not yet reached a terminal outcome.
    ///
    /// The append carries the durable [`GatewayActionSnapshot::revision`] as the aggregate
    /// revision, so re-projecting the same terminal snapshot — as the gateway's reconcile pass
    /// does when recovering an append that a crash dropped between the durable commit and the
    /// outbox write — appends the same event idempotently rather than a duplicate.
    #[must_use]
    pub fn terminal_outbox_append(&self) -> Option<OutboxAppend> {
        self.terminal().map(|_| {
            OutboxAppend::action_terminal(
                self.tenant_id.clone(),
                self.session_id.clone(),
                self.action_id.clone(),
                self.revision,
            )
        })
    }

    fn derive_worker_loss(&mut self) -> Result<(), GatewayActionCoordinationError> {
        self.evidence.materialize_worker_loss()?;
        Ok(())
    }

    fn requires_reconciliation(&self) -> bool {
        self.kind == ActionKind::Mutating
            && self.resolution.is_none()
            && matches!(
                self.terminal().map(|terminal| terminal.detail()),
                Some(TerminalDetail::OutcomeUnknown(_))
            )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GatewayActionClaimOutcome {
    Created(GatewayActionSnapshot),
    Existing(GatewayActionSnapshot),
}

impl GatewayActionClaimOutcome {
    #[must_use]
    pub const fn snapshot(&self) -> &GatewayActionSnapshot {
        match self {
            Self::Created(snapshot) | Self::Existing(snapshot) => snapshot,
        }
    }

    #[must_use]
    pub fn into_snapshot(self) -> GatewayActionSnapshot {
        match self {
            Self::Created(snapshot) | Self::Existing(snapshot) => snapshot,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionLossClaim {
    tenant_id: TenantId,
    session_id: SessionId,
    placement: GatewayActionPlacement,
    loss_id: Uuid,
}

impl SessionLossClaim {
    #[must_use]
    pub const fn new(
        tenant_id: TenantId,
        session_id: SessionId,
        placement: GatewayActionPlacement,
        loss_id: Uuid,
    ) -> Self {
        Self {
            tenant_id,
            session_id,
            placement,
            loss_id,
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
    pub const fn placement(&self) -> &GatewayActionPlacement {
        &self.placement
    }

    #[must_use]
    pub const fn loss_id(&self) -> &Uuid {
        &self.loss_id
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionLossOutcome {
    Recorded,
    AlreadyRecorded,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum GatewayActionCoordinationError {
    #[error("gateway action idempotency key must be 1-255 trimmed printable characters")]
    InvalidIdempotencyKey,
    #[error("gateway action placement must have a non-zero directory revision")]
    InvalidPlacement,
    #[error("session loss identifier must be a UUIDv7")]
    InvalidSessionLossId,
    #[error("gateway action idempotency key belongs to a different request")]
    IdempotencyConflict { existing_action_id: ActionId },
    #[error("gateway action identifier already belongs to another request")]
    ActionIdentityConflict { action_id: ActionId },
    #[error("gateway action placement does not match the session placement")]
    PlacementMismatch,
    #[error("another mutating action owns the session dispatch lane")]
    MutationInFlight { action_id: ActionId },
    #[error("session mutation is blocked until an uncertain action is reconciled")]
    ReconciliationRequired { action_id: ActionId },
    #[error("session has been fenced as lost")]
    SessionLost,
    #[error("session loss has not been recorded")]
    SessionLossNotRecorded,
    #[error("session loss identifier does not match the recorded loss")]
    SessionLossIdentityConflict,
    #[error("gateway action was not found")]
    NotFound,
    #[error("gateway action was concurrently changed")]
    StaleWrite(Box<GatewayActionSnapshot>),
    #[error("gateway action sequence conflicts with the immutable worker result")]
    ActionSequenceConflict,
    #[error("gateway action sequence must be non-zero")]
    InvalidActionSequence,
    #[error("only an outcome-unknown action may be explicitly resolved")]
    ResolutionNotAllowed,
    #[error("gateway action resolution conflicts with its durable annotation")]
    ResolutionConflict,
    #[error("gateway action sequence overflowed")]
    ActionSequenceOverflow,
    #[error("session loss materialization limit must be between 1 and 1000")]
    InvalidMaterializationLimit,
    #[error("gateway action retention timestamp is outside the supported range")]
    RetentionTimestampOverflow,
    #[error("gateway action revision overflowed")]
    RevisionOverflow,
    #[error("gateway action coordination state is internally inconsistent")]
    CorruptState,
    #[error("gateway action coordination state lock is unavailable")]
    LockUnavailable,
    #[error("Redis gateway action configuration is invalid")]
    InvalidRedisConfig,
    #[error("Redis gateway action coordination is unavailable")]
    RedisUnavailable,
    #[error("Redis gateway action coordination timed out")]
    RedisTimedOut,
    #[error("Redis gateway action coordination returned invalid state")]
    InvalidRedisResponse,
    #[error("gateway action coordination actor could not start")]
    ActorSpawn,
    #[error("gateway action coordination actor queue is full")]
    ActorQueueFull,
    #[error("gateway action coordination actor is disconnected")]
    ActorDisconnected,
    #[error("gateway action coordination query timed out")]
    ActorQueryTimedOut,
    #[error("gateway action coordination mutation timed out after admission")]
    ActorMutationTimedOut,
    #[error(transparent)]
    Evidence(#[from] ActionEvidenceError),
}

#[allow(clippy::too_many_arguments)]
#[async_trait]
pub trait GatewayActionCoordination: Send + Sync {
    async fn claim_action(
        &self,
        claim: ClaimGatewayAction,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionClaimOutcome, GatewayActionCoordinationError>;

    async fn get_effective_action(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
    ) -> Result<Option<GatewayActionSnapshot>, GatewayActionCoordinationError>;

    async fn arm_dispatch(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        dispatch_id: DispatchId,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError>;

    async fn mark_exposure_possible(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        dispatch_id: &DispatchId,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError>;

    async fn record_worker_result(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        dispatch_id: &DispatchId,
        action_sequence: ActionSequence,
        result: BrowserResult,
        result_body: Option<Vec<u8>>,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError>;

    async fn record_worker_terminal(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        dispatch_id: &DispatchId,
        action_sequence: ActionSequence,
        detail: TerminalDetail,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError>;

    async fn record_transport_loss(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        dispatch_id: &DispatchId,
        loss: TransportLoss,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError>;

    async fn cancel_before_dispatch(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError>;

    async fn resolve_unknown(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        annotation: ResolutionAnnotation,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError>;

    async fn mark_session_lost(
        &self,
        claim: &SessionLossClaim,
        now: DateTime<Utc>,
    ) -> Result<SessionLossOutcome, GatewayActionCoordinationError>;

    async fn materialize_session_loss(
        &self,
        claim: &SessionLossClaim,
        limit: usize,
        now: DateTime<Utc>,
    ) -> Result<usize, GatewayActionCoordinationError>;
}

#[derive(Clone)]
struct RecordedSessionLoss {
    loss_id: Uuid,
}

#[derive(Clone)]
struct GatewayActionSessionState {
    placement: GatewayActionPlacement,
    loss: Option<RecordedSessionLoss>,
    active_mutation: Option<ActionId>,
    unresolved_mutation: Option<ActionId>,
    last_action_sequence: u64,
    idempotency: HashMap<IdempotencyKey, ActionId>,
    actions: HashMap<ActionId, GatewayActionSnapshot>,
}

impl GatewayActionSessionState {
    fn new(placement: GatewayActionPlacement) -> Self {
        Self {
            placement,
            loss: None,
            active_mutation: None,
            unresolved_mutation: None,
            last_action_sequence: 0,
            idempotency: HashMap::new(),
            actions: HashMap::new(),
        }
    }
}

#[derive(Default)]
pub(crate) struct GatewayActionMemoryState {
    sessions: HashMap<(TenantId, SessionId), GatewayActionSessionState>,
    action_owners: HashMap<ActionId, (TenantId, SessionId, IdempotencyKey)>,
}

#[derive(Clone)]
pub struct MemoryGatewayActionStore {
    database: MemoryCoordinationDatabase,
    config: StoreConfig,
}

impl MemoryGatewayActionStore {
    #[must_use]
    pub const fn attach(database: MemoryCoordinationDatabase, config: StoreConfig) -> Self {
        Self { database, config }
    }

    #[allow(clippy::too_many_arguments)]
    fn mutate_action(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        now: DateTime<Utc>,
        allow_session_loss: bool,
        mutation: impl FnOnce(
            &mut GatewayActionSnapshot,
        ) -> Result<ActionEvidenceMutation, GatewayActionCoordinationError>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        let mut state = self
            .database
            .gateway_actions
            .lock()
            .map_err(|_| GatewayActionCoordinationError::LockUnavailable)?;
        let session = state
            .sessions
            .get_mut(&(tenant_id.clone(), session_id.clone()))
            .ok_or(GatewayActionCoordinationError::NotFound)?;
        if session.placement != *placement {
            return Err(GatewayActionCoordinationError::PlacementMismatch);
        }
        let session_lost = session.loss.is_some();
        if session_lost && !allow_session_loss {
            return Err(GatewayActionCoordinationError::SessionLost);
        }
        let current = session
            .actions
            .get_mut(action_id)
            .ok_or(GatewayActionCoordinationError::NotFound)?;
        if current.placement != *placement {
            return Err(GatewayActionCoordinationError::PlacementMismatch);
        }

        let mut candidate = current.clone();
        match mutation(&mut candidate) {
            Ok(ActionEvidenceMutation::AlreadyRecorded) => Ok(current.clone()),
            Ok(ActionEvidenceMutation::Recorded) => {
                if current.revision != expected_revision {
                    return Err(GatewayActionCoordinationError::StaleWrite(Box::new(
                        current.clone(),
                    )));
                }
                let arms_mutation = current.kind == ActionKind::Mutating
                    && matches!(current.delivery(), ActionDeliveryEvidence::NotAttempted)
                    && matches!(
                        candidate.delivery(),
                        ActionDeliveryEvidence::DispatchArmed(_)
                    );
                if arms_mutation {
                    if let Some(unresolved) = &session.unresolved_mutation {
                        return Err(GatewayActionCoordinationError::ReconciliationRequired {
                            action_id: unresolved.clone(),
                        });
                    }
                    if let Some(active) = &session.active_mutation
                        && active != action_id
                    {
                        return Err(GatewayActionCoordinationError::MutationInFlight {
                            action_id: active.clone(),
                        });
                    }
                }
                let finishes_dispatched_mutation = current.kind == ActionKind::Mutating
                    && !matches!(current.delivery(), ActionDeliveryEvidence::NotAttempted)
                    && current.terminal().is_none()
                    && candidate.terminal().is_some();
                let resolves_mutation = current.kind == ActionKind::Mutating
                    && current.resolution.is_none()
                    && candidate.resolution.is_some();
                let invalid_resolution_lane = if session_lost {
                    session
                        .active_mutation
                        .as_ref()
                        .is_some_and(|active| active != action_id)
                        || session
                            .unresolved_mutation
                            .as_ref()
                            .is_some_and(|unresolved| unresolved != action_id)
                } else {
                    session.unresolved_mutation.as_ref() != Some(action_id)
                };
                if (finishes_dispatched_mutation
                    && session.active_mutation.as_ref() != Some(action_id))
                    || (resolves_mutation && invalid_resolution_lane)
                {
                    return Err(GatewayActionCoordinationError::CorruptState);
                }
                candidate.revision = candidate
                    .revision
                    .checked_add(1)
                    .ok_or(GatewayActionCoordinationError::RevisionOverflow)?;
                candidate.updated_at = now;
                *current = candidate.clone();
                if arms_mutation {
                    session.active_mutation = Some(action_id.clone());
                }
                if finishes_dispatched_mutation {
                    session.active_mutation = None;
                    if candidate.requires_reconciliation() {
                        session.unresolved_mutation = Some(action_id.clone());
                    }
                }
                if resolves_mutation {
                    if session.unresolved_mutation.as_ref() == Some(action_id) {
                        session.unresolved_mutation = None;
                    }
                    if session_lost && session.active_mutation.as_ref() == Some(action_id) {
                        session.active_mutation = None;
                    }
                }
                Ok(candidate)
            }
            Err(_) if current.revision != expected_revision => Err(
                GatewayActionCoordinationError::StaleWrite(Box::new(current.clone())),
            ),
            Err(error) => Err(error),
        }
    }

    fn validate_loss_claim(claim: &SessionLossClaim) -> Result<(), GatewayActionCoordinationError> {
        if claim.loss_id.get_version() != Some(Version::SortRand) {
            return Err(GatewayActionCoordinationError::InvalidSessionLossId);
        }
        Ok(())
    }
}

impl Default for MemoryGatewayActionStore {
    fn default() -> Self {
        Self::attach(
            MemoryCoordinationDatabase::default(),
            StoreConfig::default(),
        )
    }
}

#[allow(clippy::too_many_arguments)]
#[async_trait]
impl GatewayActionCoordination for MemoryGatewayActionStore {
    async fn claim_action(
        &self,
        claim: ClaimGatewayAction,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionClaimOutcome, GatewayActionCoordinationError> {
        let mut state = self
            .database
            .gateway_actions
            .lock()
            .map_err(|_| GatewayActionCoordinationError::LockUnavailable)?;
        let session_key = (claim.tenant_id.clone(), claim.session_id.clone());

        if let Some(session) = state.sessions.get(&session_key) {
            if session.placement != claim.placement {
                return Err(GatewayActionCoordinationError::PlacementMismatch);
            }
            if let Some(existing_action_id) = session.idempotency.get(&claim.idempotency_key) {
                let existing = session
                    .actions
                    .get(existing_action_id)
                    .ok_or(GatewayActionCoordinationError::CorruptState)?;
                if existing.request_hash != claim.request_hash || existing.kind != claim.kind {
                    return Err(GatewayActionCoordinationError::IdempotencyConflict {
                        existing_action_id: existing.action_id.clone(),
                    });
                }
                let mut effective = existing.clone();
                if session.loss.is_some() && effective.terminal().is_none() {
                    effective.derive_worker_loss()?;
                }
                return Ok(GatewayActionClaimOutcome::Existing(effective));
            }
            if session.loss.is_some() {
                return Err(GatewayActionCoordinationError::SessionLost);
            }
            if claim.kind == ActionKind::Mutating
                && let Some(action_id) = &session.unresolved_mutation
            {
                return Err(GatewayActionCoordinationError::ReconciliationRequired {
                    action_id: action_id.clone(),
                });
            }
        }

        if state.action_owners.contains_key(&claim.proposed_action_id) {
            return Err(GatewayActionCoordinationError::ActionIdentityConflict {
                action_id: claim.proposed_action_id,
            });
        }

        let retention = chrono::Duration::from_std(self.config.retention())
            .map_err(|_| GatewayActionCoordinationError::RetentionTimestampOverflow)?;
        let retain_until = now
            .checked_add_signed(retention)
            .ok_or(GatewayActionCoordinationError::RetentionTimestampOverflow)?;
        let action_sequence = state.sessions.get(&session_key).map_or(Ok(1), |session| {
            session
                .last_action_sequence
                .checked_add(1)
                .ok_or(GatewayActionCoordinationError::ActionSequenceOverflow)
        })?;
        let snapshot = GatewayActionSnapshot {
            tenant_id: claim.tenant_id.clone(),
            session_id: claim.session_id.clone(),
            action_id: claim.proposed_action_id.clone(),
            idempotency_key: claim.idempotency_key.clone(),
            request_hash: claim.request_hash,
            kind: claim.kind,
            placement: claim.placement.clone(),
            evidence: ActionEvidence::new(),
            resolution: None,
            result_content: None,
            action_sequence: ActionSequence::new(action_sequence),
            revision: 0,
            created_at: now,
            updated_at: now,
            retain_until,
        };
        state.action_owners.insert(
            claim.proposed_action_id.clone(),
            (
                claim.tenant_id.clone(),
                claim.session_id.clone(),
                claim.idempotency_key.clone(),
            ),
        );
        let session = state
            .sessions
            .entry(session_key)
            .or_insert_with(|| GatewayActionSessionState::new(claim.placement));
        session.last_action_sequence = action_sequence;
        session
            .idempotency
            .insert(claim.idempotency_key, claim.proposed_action_id.clone());
        session
            .actions
            .insert(claim.proposed_action_id, snapshot.clone());
        Ok(GatewayActionClaimOutcome::Created(snapshot))
    }

    async fn get_effective_action(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
    ) -> Result<Option<GatewayActionSnapshot>, GatewayActionCoordinationError> {
        let state = self
            .database
            .gateway_actions
            .lock()
            .map_err(|_| GatewayActionCoordinationError::LockUnavailable)?;
        let Some(session) = state.sessions.get(&(tenant_id.clone(), session_id.clone())) else {
            return Ok(None);
        };
        let Some(mut snapshot) = session.actions.get(action_id).cloned() else {
            return Ok(None);
        };
        if session.loss.is_some() && snapshot.terminal().is_none() {
            snapshot.derive_worker_loss()?;
        }
        Ok(Some(snapshot))
    }

    async fn arm_dispatch(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        dispatch_id: DispatchId,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        self.mutate_action(
            tenant_id,
            session_id,
            action_id,
            expected_revision,
            placement,
            now,
            false,
            move |snapshot| Ok(snapshot.evidence.arm_dispatch(dispatch_id)?),
        )
    }

    async fn mark_exposure_possible(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        dispatch_id: &DispatchId,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        self.mutate_action(
            tenant_id,
            session_id,
            action_id,
            expected_revision,
            placement,
            now,
            false,
            |snapshot| Ok(snapshot.evidence.mark_exposure_possible(dispatch_id)?),
        )
    }

    async fn record_worker_result(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        dispatch_id: &DispatchId,
        action_sequence: ActionSequence,
        result: BrowserResult,
        result_body: Option<Vec<u8>>,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        validate_durable_result_body(result, &result_body)?;
        self.mutate_action(
            tenant_id,
            session_id,
            action_id,
            expected_revision,
            placement,
            now,
            false,
            move |snapshot| {
                if action_sequence.get() == 0 {
                    return Err(GatewayActionCoordinationError::InvalidActionSequence);
                }
                if snapshot.action_sequence != action_sequence {
                    return Err(GatewayActionCoordinationError::ActionSequenceConflict);
                }
                let mutation = snapshot
                    .evidence
                    .record_worker_result(dispatch_id, result)?;
                if matches!(mutation, ActionEvidenceMutation::Recorded) {
                    snapshot.result_content = result_body;
                }
                Ok(mutation)
            },
        )
    }

    async fn record_worker_terminal(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        dispatch_id: &DispatchId,
        action_sequence: ActionSequence,
        detail: TerminalDetail,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        self.mutate_action(
            tenant_id,
            session_id,
            action_id,
            expected_revision,
            placement,
            now,
            false,
            |snapshot| {
                if action_sequence.get() == 0 {
                    return Err(GatewayActionCoordinationError::InvalidActionSequence);
                }
                if snapshot.action_sequence != action_sequence {
                    return Err(GatewayActionCoordinationError::ActionSequenceConflict);
                }
                Ok(snapshot
                    .evidence
                    .record_worker_terminal(dispatch_id, detail)?)
            },
        )
    }

    async fn record_transport_loss(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        dispatch_id: &DispatchId,
        loss: TransportLoss,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        self.mutate_action(
            tenant_id,
            session_id,
            action_id,
            expected_revision,
            placement,
            now,
            false,
            |snapshot| Ok(snapshot.evidence.record_transport_loss(dispatch_id, loss)?),
        )
    }

    async fn cancel_before_dispatch(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        self.mutate_action(
            tenant_id,
            session_id,
            action_id,
            expected_revision,
            placement,
            now,
            false,
            |snapshot| Ok(snapshot.evidence.cancel_before_dispatch()?),
        )
    }

    async fn resolve_unknown(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        annotation: ResolutionAnnotation,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        self.mutate_action(
            tenant_id,
            session_id,
            action_id,
            expected_revision,
            placement,
            now,
            true,
            |snapshot| {
                if let Some(existing) = &snapshot.resolution {
                    return if existing == &annotation {
                        Ok(ActionEvidenceMutation::AlreadyRecorded)
                    } else {
                        Err(GatewayActionCoordinationError::ResolutionConflict)
                    };
                }
                if !matches!(
                    snapshot.terminal().map(|terminal| terminal.detail()),
                    Some(TerminalDetail::OutcomeUnknown(_))
                ) {
                    return Err(GatewayActionCoordinationError::ResolutionNotAllowed);
                }
                snapshot.resolution = Some(annotation);
                Ok(ActionEvidenceMutation::Recorded)
            },
        )
    }

    async fn mark_session_lost(
        &self,
        claim: &SessionLossClaim,
        _now: DateTime<Utc>,
    ) -> Result<SessionLossOutcome, GatewayActionCoordinationError> {
        Self::validate_loss_claim(claim)?;
        let mut state = self
            .database
            .gateway_actions
            .lock()
            .map_err(|_| GatewayActionCoordinationError::LockUnavailable)?;
        let key = (claim.tenant_id.clone(), claim.session_id.clone());
        let session = state
            .sessions
            .entry(key)
            .or_insert_with(|| GatewayActionSessionState::new(claim.placement.clone()));
        if session.placement != claim.placement {
            return Err(GatewayActionCoordinationError::PlacementMismatch);
        }
        if let Some(recorded_loss) = &session.loss {
            return if recorded_loss.loss_id == claim.loss_id {
                Ok(SessionLossOutcome::AlreadyRecorded)
            } else {
                Err(GatewayActionCoordinationError::SessionLossIdentityConflict)
            };
        }
        session.loss = Some(RecordedSessionLoss {
            loss_id: claim.loss_id,
        });
        Ok(SessionLossOutcome::Recorded)
    }

    async fn materialize_session_loss(
        &self,
        claim: &SessionLossClaim,
        limit: usize,
        now: DateTime<Utc>,
    ) -> Result<usize, GatewayActionCoordinationError> {
        Self::validate_loss_claim(claim)?;
        if !(1..=MAX_MATERIALIZATION_LIMIT).contains(&limit) {
            return Err(GatewayActionCoordinationError::InvalidMaterializationLimit);
        }
        let mut state = self
            .database
            .gateway_actions
            .lock()
            .map_err(|_| GatewayActionCoordinationError::LockUnavailable)?;
        let key = (claim.tenant_id.clone(), claim.session_id.clone());
        let session = state
            .sessions
            .get(&key)
            .ok_or(GatewayActionCoordinationError::SessionLossNotRecorded)?;
        if session.placement != claim.placement {
            return Err(GatewayActionCoordinationError::PlacementMismatch);
        }
        let recorded_loss = session
            .loss
            .as_ref()
            .ok_or(GatewayActionCoordinationError::SessionLossNotRecorded)?;
        if recorded_loss.loss_id != claim.loss_id {
            return Err(GatewayActionCoordinationError::SessionLossIdentityConflict);
        }
        let mut candidate = session.clone();
        let mut pending: Vec<_> = candidate
            .actions
            .values()
            .filter(|snapshot| snapshot.terminal().is_none())
            .map(|snapshot| (snapshot.created_at, snapshot.action_id.clone()))
            .collect();
        pending.sort();
        pending.truncate(limit);
        let materialized = pending.len();
        for (_, action_id) in pending {
            let snapshot = candidate
                .actions
                .get_mut(&action_id)
                .ok_or(GatewayActionCoordinationError::CorruptState)?;
            snapshot.derive_worker_loss()?;
            snapshot.revision = snapshot
                .revision
                .checked_add(1)
                .ok_or(GatewayActionCoordinationError::RevisionOverflow)?;
            snapshot.updated_at = now;
        }
        state.sessions.insert(key, candidate);
        Ok(materialized)
    }
}
