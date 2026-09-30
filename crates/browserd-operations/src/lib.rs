use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use browserd_core::{ActionId, CreateOperationState, OperationId, TenantId};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const IDEMPOTENCY_RETENTION: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CanonicalRequestHash([u8; 32]);

impl CanonicalRequestHash {
    #[must_use]
    pub fn from_json(value: &Value) -> Self {
        enum Token<'a> {
            Value(&'a Value),
            Text(String),
            Punctuation(char),
        }

        let mut canonical = String::new();
        let mut pending = vec![Token::Value(value)];
        while let Some(token) = pending.pop() {
            match token {
                Token::Text(text) => canonical.push_str(&text),
                Token::Punctuation(character) => canonical.push(character),
                Token::Value(Value::Null) => canonical.push_str("null"),
                Token::Value(Value::Bool(value)) => {
                    canonical.push_str(if *value { "true" } else { "false" });
                }
                Token::Value(Value::Number(value)) => canonical.push_str(&value.to_string()),
                Token::Value(Value::String(value)) => {
                    canonical.push_str(&Value::String(value.clone()).to_string());
                }
                Token::Value(Value::Array(values)) => {
                    canonical.push('[');
                    pending.push(Token::Punctuation(']'));
                    for (index, value) in values.iter().enumerate().rev() {
                        pending.push(Token::Value(value));
                        if index > 0 {
                            pending.push(Token::Punctuation(','));
                        }
                    }
                }
                Token::Value(Value::Object(values)) => {
                    canonical.push('{');
                    pending.push(Token::Punctuation('}'));
                    let mut entries = values.iter().collect::<Vec<_>>();
                    entries.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));
                    for (index, (key, value)) in entries.into_iter().enumerate().rev() {
                        pending.push(Token::Value(value));
                        pending.push(Token::Punctuation(':'));
                        pending.push(Token::Text(Value::String(key.clone()).to_string()));
                        if index > 0 {
                            pending.push(Token::Punctuation(','));
                        }
                    }
                }
            }
        }
        Self(Sha256::digest(canonical.as_bytes()).into())
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct IdempotencyKey(String);

impl IdempotencyKey {
    pub fn new(value: impl Into<String>) -> Result<Self, InvalidIdempotencyKey> {
        let value = value.into();
        if value.is_empty()
            || value.trim() != value
            || value.len() > 255
            || value.chars().any(char::is_control)
        {
            return Err(InvalidIdempotencyKey);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidIdempotencyKey;

impl fmt::Display for InvalidIdempotencyKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("idempotency key must be 1-255 trimmed, printable characters")
    }
}

impl std::error::Error for InvalidIdempotencyKey {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegistryConfigError {
    RetentionBelowMinimum,
}

impl fmt::Display for RegistryConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RetentionBelowMinimum => {
                formatter.write_str("idempotency retention must be at least 24 hours")
            }
        }
    }
}

impl std::error::Error for RegistryConfigError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IdempotencyError {
    Conflict { existing_operation_id: OperationId },
    CoordinationUnavailable,
}

impl fmt::Display for IdempotencyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Conflict { .. } => formatter.write_str("idempotency key has a different request"),
            Self::CoordinationUnavailable => {
                formatter.write_str("idempotency coordination state is unavailable")
            }
        }
    }
}

impl std::error::Error for IdempotencyError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IdempotencyClaim {
    Created(OperationId),
    Existing(OperationId),
}

impl IdempotencyClaim {
    #[must_use]
    pub const fn operation_id(&self) -> &OperationId {
        match self {
            Self::Created(operation_id) | Self::Existing(operation_id) => operation_id,
        }
    }
}

#[derive(Clone)]
struct IdempotencyEntry {
    request_hash: CanonicalRequestHash,
    operation_id: OperationId,
    created_at: Instant,
}

pub struct IdempotencyRegistry {
    retention: Duration,
    entries: Mutex<HashMap<(TenantId, IdempotencyKey), IdempotencyEntry>>,
}

impl IdempotencyRegistry {
    pub fn new(retention: Duration) -> Result<Self, RegistryConfigError> {
        if retention < IDEMPOTENCY_RETENTION {
            return Err(RegistryConfigError::RetentionBelowMinimum);
        }
        Ok(Self {
            retention,
            entries: Mutex::new(HashMap::new()),
        })
    }

    pub fn claim(
        &self,
        tenant_id: TenantId,
        key: IdempotencyKey,
        request_hash: CanonicalRequestHash,
        now: Instant,
    ) -> Result<IdempotencyClaim, IdempotencyError> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| IdempotencyError::CoordinationUnavailable)?;
        let lookup_key = (tenant_id, key);
        if let Some(existing) = entries.get(&lookup_key) {
            let expired = now
                .checked_duration_since(existing.created_at)
                .is_some_and(|elapsed| elapsed >= self.retention);
            if !expired {
                if existing.request_hash == request_hash {
                    return Ok(IdempotencyClaim::Existing(existing.operation_id.clone()));
                }
                return Err(IdempotencyError::Conflict {
                    existing_operation_id: existing.operation_id.clone(),
                });
            }
        }

        let operation_id = OperationId::new();
        entries.insert(
            lookup_key,
            IdempotencyEntry {
                request_hash,
                operation_id: operation_id.clone(),
                created_at: now,
            },
        );
        Ok(IdempotencyClaim::Created(operation_id))
    }

    /// Remove entries whose retention window has elapsed, bounding the registry under one-shot-key
    /// churn (each unique key otherwise leaves an entry that is never revisited).
    ///
    /// This is behavior-neutral: [`Self::claim`] already treats an elapsed entry as absent — a
    /// re-claim mints a fresh operation and overwrites it — so pruning only reclaims memory.
    ///
    /// Returns the operation ids of the removed entries, so a caller can reclaim the matching
    /// per-operation state it keyed on them (for example the worker's create-operation results).
    /// This is safe precisely because the entry has elapsed: a later claim for that key mints a new
    /// operation and never revisits the returned id.
    pub fn prune(&self, now: Instant) -> Result<Vec<OperationId>, IdempotencyError> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| IdempotencyError::CoordinationUnavailable)?;
        let mut pruned = Vec::new();
        entries.retain(|_, entry| {
            let elapsed = now
                .checked_duration_since(entry.created_at)
                .is_some_and(|elapsed| elapsed >= self.retention);
            if elapsed {
                pruned.push(entry.operation_id.clone());
            }
            !elapsed
        });
        Ok(pruned)
    }
}

impl Default for IdempotencyRegistry {
    fn default() -> Self {
        Self {
            retention: IDEMPOTENCY_RETENTION,
            entries: Mutex::new(HashMap::new()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OperationTransitionError {
    Terminal(CreateOperationState),
    ActionTerminal(GatewayActionState),
    InvalidCreateTransition {
        state: CreateOperationState,
        attempted: &'static str,
    },
    InvalidActionTransition {
        state: GatewayActionState,
        attempted: &'static str,
    },
    CoordinationUnavailable,
}

impl fmt::Display for OperationTransitionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Terminal(state) => write!(formatter, "create operation is terminal: {state:?}"),
            Self::ActionTerminal(state) => write!(formatter, "action is terminal: {state:?}"),
            Self::InvalidCreateTransition { state, attempted } => {
                write!(
                    formatter,
                    "cannot {attempted} create operation in {state:?}"
                )
            }
            Self::InvalidActionTransition { state, attempted } => {
                write!(formatter, "cannot {attempted} action in {state:?}")
            }
            Self::CoordinationUnavailable => {
                formatter.write_str("operation coordination state is unavailable")
            }
        }
    }
}

impl std::error::Error for OperationTransitionError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CancelDecision {
    Cancelled,
    CancelPending,
    Terminal(CreateOperationState),
}

struct CreateOperationInner {
    state: CreateOperationState,
    creation_committed: bool,
    cancellation_requested: bool,
}

pub struct CreateSessionOperation {
    id: OperationId,
    tenant_id: TenantId,
    request_hash: CanonicalRequestHash,
    inner: Mutex<CreateOperationInner>,
}

impl CreateSessionOperation {
    #[must_use]
    pub fn new(id: OperationId, tenant_id: TenantId, request_hash: CanonicalRequestHash) -> Self {
        Self {
            id,
            tenant_id,
            request_hash,
            inner: Mutex::new(CreateOperationInner {
                state: CreateOperationState::Accepted,
                creation_committed: false,
                cancellation_requested: false,
            }),
        }
    }

    #[must_use]
    pub const fn id(&self) -> &OperationId {
        &self.id
    }

    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    #[must_use]
    pub const fn request_hash(&self) -> CanonicalRequestHash {
        self.request_hash
    }

    pub fn state(&self) -> Result<CreateOperationState, OperationTransitionError> {
        Ok(self
            .inner
            .lock()
            .map_err(|_| OperationTransitionError::CoordinationUnavailable)?
            .state)
    }

    pub fn enqueue(&self) -> Result<CreateOperationState, OperationTransitionError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| OperationTransitionError::CoordinationUnavailable)?;
        if inner.state != CreateOperationState::Accepted {
            return Err(
                if matches!(
                    inner.state,
                    CreateOperationState::Succeeded
                        | CreateOperationState::TimedOut
                        | CreateOperationState::Cancelled
                        | CreateOperationState::Failed
                ) {
                    OperationTransitionError::Terminal(inner.state)
                } else {
                    OperationTransitionError::InvalidCreateTransition {
                        state: inner.state,
                        attempted: "enqueue",
                    }
                },
            );
        }
        inner.state = CreateOperationState::Queued;
        Ok(inner.state)
    }

    pub fn begin_reservation(&self) -> Result<CreateOperationState, OperationTransitionError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| OperationTransitionError::CoordinationUnavailable)?;
        if inner.state != CreateOperationState::Queued {
            return Err(
                if matches!(
                    inner.state,
                    CreateOperationState::Succeeded
                        | CreateOperationState::TimedOut
                        | CreateOperationState::Cancelled
                        | CreateOperationState::Failed
                ) {
                    OperationTransitionError::Terminal(inner.state)
                } else {
                    OperationTransitionError::InvalidCreateTransition {
                        state: inner.state,
                        attempted: "begin reservation for",
                    }
                },
            );
        }
        inner.state = CreateOperationState::Reserving;
        Ok(inner.state)
    }

    pub fn capacity_race(&self) -> Result<CreateOperationState, OperationTransitionError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| OperationTransitionError::CoordinationUnavailable)?;
        if inner.state != CreateOperationState::Reserving || inner.creation_committed {
            return Err(
                if matches!(
                    inner.state,
                    CreateOperationState::Succeeded
                        | CreateOperationState::TimedOut
                        | CreateOperationState::Cancelled
                        | CreateOperationState::Failed
                ) {
                    OperationTransitionError::Terminal(inner.state)
                } else {
                    OperationTransitionError::InvalidCreateTransition {
                        state: inner.state,
                        attempted: "requeue",
                    }
                },
            );
        }
        inner.state = CreateOperationState::Queued;
        Ok(inner.state)
    }

    pub fn commit_creation(&self) -> Result<CreateOperationState, OperationTransitionError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| OperationTransitionError::CoordinationUnavailable)?;
        if inner.state != CreateOperationState::Reserving {
            return Err(
                if matches!(
                    inner.state,
                    CreateOperationState::Succeeded
                        | CreateOperationState::TimedOut
                        | CreateOperationState::Cancelled
                        | CreateOperationState::Failed
                ) {
                    OperationTransitionError::Terminal(inner.state)
                } else {
                    OperationTransitionError::InvalidCreateTransition {
                        state: inner.state,
                        attempted: "commit",
                    }
                },
            );
        }
        inner.creation_committed = true;
        inner.state = CreateOperationState::Creating;
        Ok(inner.state)
    }

    pub fn succeed(&self) -> Result<CreateOperationState, OperationTransitionError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| OperationTransitionError::CoordinationUnavailable)?;
        if inner.state != CreateOperationState::Creating {
            return Err(
                if matches!(
                    inner.state,
                    CreateOperationState::Succeeded
                        | CreateOperationState::TimedOut
                        | CreateOperationState::Cancelled
                        | CreateOperationState::Failed
                ) {
                    OperationTransitionError::Terminal(inner.state)
                } else {
                    OperationTransitionError::InvalidCreateTransition {
                        state: inner.state,
                        attempted: "succeed",
                    }
                },
            );
        }
        inner.state = CreateOperationState::Succeeded;
        Ok(inner.state)
    }

    pub fn fail(&self) -> Result<CreateOperationState, OperationTransitionError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| OperationTransitionError::CoordinationUnavailable)?;
        if matches!(
            inner.state,
            CreateOperationState::Succeeded
                | CreateOperationState::TimedOut
                | CreateOperationState::Cancelled
                | CreateOperationState::Failed
        ) {
            return Err(OperationTransitionError::Terminal(inner.state));
        }
        inner.state = CreateOperationState::Failed;
        Ok(inner.state)
    }

    pub fn time_out(&self) -> Result<CreateOperationState, OperationTransitionError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| OperationTransitionError::CoordinationUnavailable)?;
        if matches!(
            inner.state,
            CreateOperationState::Succeeded
                | CreateOperationState::TimedOut
                | CreateOperationState::Cancelled
                | CreateOperationState::Failed
        ) {
            return Err(OperationTransitionError::Terminal(inner.state));
        }
        inner.state = CreateOperationState::TimedOut;
        Ok(inner.state)
    }

    pub fn request_cancel(&self) -> Result<CancelDecision, OperationTransitionError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| OperationTransitionError::CoordinationUnavailable)?;
        if matches!(
            inner.state,
            CreateOperationState::Succeeded
                | CreateOperationState::TimedOut
                | CreateOperationState::Cancelled
                | CreateOperationState::Failed
        ) {
            return Ok(CancelDecision::Terminal(inner.state));
        }
        if inner.creation_committed {
            inner.cancellation_requested = true;
            return Ok(CancelDecision::CancelPending);
        }
        inner.cancellation_requested = true;
        inner.state = CreateOperationState::Cancelled;
        Ok(CancelDecision::Cancelled)
    }

    pub fn confirm_cancelled(&self) -> Result<CreateOperationState, OperationTransitionError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| OperationTransitionError::CoordinationUnavailable)?;
        if inner.state != CreateOperationState::Creating || !inner.cancellation_requested {
            return Err(
                if matches!(
                    inner.state,
                    CreateOperationState::Succeeded
                        | CreateOperationState::TimedOut
                        | CreateOperationState::Cancelled
                        | CreateOperationState::Failed
                ) {
                    OperationTransitionError::Terminal(inner.state)
                } else {
                    OperationTransitionError::InvalidCreateTransition {
                        state: inner.state,
                        attempted: "confirm cancellation of",
                    }
                },
            );
        }
        inner.state = CreateOperationState::Cancelled;
        Ok(inner.state)
    }

    pub fn creation_committed(&self) -> Result<bool, OperationTransitionError> {
        Ok(self
            .inner
            .lock()
            .map_err(|_| OperationTransitionError::CoordinationUnavailable)?
            .creation_committed)
    }

    pub fn cancellation_requested(&self) -> Result<bool, OperationTransitionError> {
        Ok(self
            .inner
            .lock()
            .map_err(|_| OperationTransitionError::CoordinationUnavailable)?
            .cancellation_requested)
    }
}

#[derive(Default)]
struct QueueState {
    by_tenant: HashMap<TenantId, VecDeque<Arc<CreateSessionOperation>>>,
    tenant_order: VecDeque<TenantId>,
    enqueued: HashSet<OperationId>,
}

#[derive(Default)]
pub struct TenantFairQueue {
    state: Mutex<QueueState>,
}

impl TenantFairQueue {
    pub fn enqueue(
        &self,
        operation: Arc<CreateSessionOperation>,
    ) -> Result<(), OperationTransitionError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| OperationTransitionError::CoordinationUnavailable)?;
        if state.enqueued.contains(operation.id()) {
            return Ok(());
        }
        match operation.state()? {
            CreateOperationState::Accepted => {
                operation.enqueue()?;
            }
            CreateOperationState::Queued => {}
            state @ (CreateOperationState::Succeeded
            | CreateOperationState::TimedOut
            | CreateOperationState::Cancelled
            | CreateOperationState::Failed) => {
                return Err(OperationTransitionError::Terminal(state));
            }
            state => {
                return Err(OperationTransitionError::InvalidCreateTransition {
                    state,
                    attempted: "enqueue",
                });
            }
        }
        let tenant_id = operation.tenant_id().clone();
        if !state.by_tenant.contains_key(&tenant_id) {
            state.tenant_order.push_back(tenant_id.clone());
        }
        state.enqueued.insert(operation.id().clone());
        state
            .by_tenant
            .entry(tenant_id)
            .or_default()
            .push_back(operation);
        Ok(())
    }

    pub fn pop_next(
        &self,
    ) -> Result<Option<Arc<CreateSessionOperation>>, OperationTransitionError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| OperationTransitionError::CoordinationUnavailable)?;
        while let Some(tenant_id) = state.tenant_order.pop_front() {
            loop {
                let operation = state
                    .by_tenant
                    .get_mut(&tenant_id)
                    .and_then(VecDeque::pop_front);
                let Some(operation) = operation else {
                    state.by_tenant.remove(&tenant_id);
                    break;
                };
                state.enqueued.remove(operation.id());
                let has_more = state
                    .by_tenant
                    .get(&tenant_id)
                    .is_some_and(|queue| !queue.is_empty());
                if has_more {
                    state.tenant_order.push_back(tenant_id.clone());
                } else {
                    state.by_tenant.remove(&tenant_id);
                }
                if operation.state()? == CreateOperationState::Queued {
                    return Ok(Some(operation));
                }
                if !has_more {
                    break;
                }
                let Some(next_tenant) = state.tenant_order.pop_back() else {
                    break;
                };
                debug_assert_eq!(next_tenant, tenant_id);
            }
        }
        Ok(None)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KnownActionFailure {
    NotDispatched,
    WorkerRejected,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UncertaintyReason {
    WorkerLost,
    AmbiguousTransportLoss,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GatewayActionState {
    Accepted,
    Queued,
    PendingApproval,
    ReadyToDispatch,
    DispatchIntentRecorded,
    MayHaveExecuted,
    Succeeded,
    FailedKnown(KnownActionFailure),
    CancelledBeforeDispatch,
    CancelledConfirmed,
    OutcomeUnknown(UncertaintyReason),
}

impl GatewayActionState {
    fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Succeeded
                | Self::FailedKnown(_)
                | Self::CancelledBeforeDispatch
                | Self::CancelledConfirmed
                | Self::OutcomeUnknown(_)
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ActionCancelDecision {
    CancelledBeforeDispatch,
    CancelPending,
    Terminal(GatewayActionState),
}

struct ActionTrackerInner {
    state: GatewayActionState,
    cancellation_requested: bool,
}

pub struct ActionTracker {
    id: ActionId,
    inner: Mutex<ActionTrackerInner>,
}

impl ActionTracker {
    #[must_use]
    pub fn from_state(id: ActionId, state: GatewayActionState) -> Self {
        let cancellation_requested = matches!(
            state,
            GatewayActionState::CancelledBeforeDispatch | GatewayActionState::CancelledConfirmed
        );
        Self {
            id,
            inner: Mutex::new(ActionTrackerInner {
                state,
                cancellation_requested,
            }),
        }
    }

    #[must_use]
    pub const fn id(&self) -> &ActionId {
        &self.id
    }

    pub fn state(&self) -> Result<GatewayActionState, OperationTransitionError> {
        Ok(self
            .inner
            .lock()
            .map_err(|_| OperationTransitionError::CoordinationUnavailable)?
            .state
            .clone())
    }

    pub fn record_dispatch_intent(&self) -> Result<GatewayActionState, OperationTransitionError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| OperationTransitionError::CoordinationUnavailable)?;
        if inner.state != GatewayActionState::ReadyToDispatch {
            return Err(if inner.state.is_terminal() {
                OperationTransitionError::ActionTerminal(inner.state.clone())
            } else {
                OperationTransitionError::InvalidActionTransition {
                    state: inner.state.clone(),
                    attempted: "record dispatch intent for",
                }
            });
        }
        inner.state = GatewayActionState::DispatchIntentRecorded;
        Ok(inner.state.clone())
    }

    pub fn mark_may_have_executed(&self) -> Result<GatewayActionState, OperationTransitionError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| OperationTransitionError::CoordinationUnavailable)?;
        if inner.state != GatewayActionState::DispatchIntentRecorded {
            return Err(if inner.state.is_terminal() {
                OperationTransitionError::ActionTerminal(inner.state.clone())
            } else {
                OperationTransitionError::InvalidActionTransition {
                    state: inner.state.clone(),
                    attempted: "mark possibly executed",
                }
            });
        }
        inner.state = GatewayActionState::MayHaveExecuted;
        Ok(inner.state.clone())
    }

    pub fn record_proven_delivery_failure(
        &self,
    ) -> Result<GatewayActionState, OperationTransitionError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| OperationTransitionError::CoordinationUnavailable)?;
        if !matches!(
            inner.state,
            GatewayActionState::ReadyToDispatch | GatewayActionState::DispatchIntentRecorded
        ) {
            return Err(if inner.state.is_terminal() {
                OperationTransitionError::ActionTerminal(inner.state.clone())
            } else {
                OperationTransitionError::InvalidActionTransition {
                    state: inner.state.clone(),
                    attempted: "record proven delivery failure for",
                }
            });
        }
        inner.state = GatewayActionState::FailedKnown(KnownActionFailure::NotDispatched);
        Ok(inner.state.clone())
    }

    pub fn succeed(&self) -> Result<GatewayActionState, OperationTransitionError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| OperationTransitionError::CoordinationUnavailable)?;
        if inner.state.is_terminal() {
            return Err(OperationTransitionError::ActionTerminal(
                inner.state.clone(),
            ));
        }
        if !matches!(
            inner.state,
            GatewayActionState::DispatchIntentRecorded | GatewayActionState::MayHaveExecuted
        ) {
            return Err(OperationTransitionError::InvalidActionTransition {
                state: inner.state.clone(),
                attempted: "succeed",
            });
        }
        inner.state = GatewayActionState::Succeeded;
        Ok(inner.state.clone())
    }

    pub fn request_cancel(&self) -> Result<ActionCancelDecision, OperationTransitionError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| OperationTransitionError::CoordinationUnavailable)?;
        if inner.state.is_terminal() {
            return Ok(ActionCancelDecision::Terminal(inner.state.clone()));
        }
        inner.cancellation_requested = true;
        if matches!(
            inner.state,
            GatewayActionState::Accepted
                | GatewayActionState::Queued
                | GatewayActionState::PendingApproval
                | GatewayActionState::ReadyToDispatch
        ) {
            inner.state = GatewayActionState::CancelledBeforeDispatch;
            return Ok(ActionCancelDecision::CancelledBeforeDispatch);
        }
        Ok(ActionCancelDecision::CancelPending)
    }

    pub fn confirm_cancelled(&self) -> Result<GatewayActionState, OperationTransitionError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| OperationTransitionError::CoordinationUnavailable)?;
        if inner.state.is_terminal() {
            return Err(OperationTransitionError::ActionTerminal(
                inner.state.clone(),
            ));
        }
        if !inner.cancellation_requested
            || !matches!(
                inner.state,
                GatewayActionState::DispatchIntentRecorded | GatewayActionState::MayHaveExecuted
            )
        {
            return Err(OperationTransitionError::InvalidActionTransition {
                state: inner.state.clone(),
                attempted: "confirm cancellation of",
            });
        }
        inner.state = GatewayActionState::CancelledConfirmed;
        Ok(inner.state.clone())
    }

    pub fn cancellation_requested(&self) -> Result<bool, OperationTransitionError> {
        Ok(self
            .inner
            .lock()
            .map_err(|_| OperationTransitionError::CoordinationUnavailable)?
            .cancellation_requested)
    }

    pub fn on_ambiguous_transport_loss(
        &self,
    ) -> Result<GatewayActionState, OperationTransitionError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| OperationTransitionError::CoordinationUnavailable)?;
        inner.state = match &inner.state {
            GatewayActionState::Accepted
            | GatewayActionState::Queued
            | GatewayActionState::PendingApproval
            | GatewayActionState::ReadyToDispatch => {
                GatewayActionState::FailedKnown(KnownActionFailure::NotDispatched)
            }
            GatewayActionState::DispatchIntentRecorded | GatewayActionState::MayHaveExecuted => {
                GatewayActionState::OutcomeUnknown(UncertaintyReason::AmbiguousTransportLoss)
            }
            terminal => terminal.clone(),
        };
        Ok(inner.state.clone())
    }

    pub fn on_worker_loss(&self) -> Result<GatewayActionState, OperationTransitionError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| OperationTransitionError::CoordinationUnavailable)?;
        inner.state = match &inner.state {
            GatewayActionState::Accepted
            | GatewayActionState::Queued
            | GatewayActionState::PendingApproval
            | GatewayActionState::ReadyToDispatch => {
                GatewayActionState::FailedKnown(KnownActionFailure::NotDispatched)
            }
            GatewayActionState::DispatchIntentRecorded | GatewayActionState::MayHaveExecuted => {
                GatewayActionState::OutcomeUnknown(UncertaintyReason::WorkerLost)
            }
            terminal @ (GatewayActionState::Succeeded
            | GatewayActionState::FailedKnown(_)
            | GatewayActionState::CancelledBeforeDispatch
            | GatewayActionState::CancelledConfirmed
            | GatewayActionState::OutcomeUnknown(_)) => terminal.clone(),
        };
        Ok(inner.state.clone())
    }
}
