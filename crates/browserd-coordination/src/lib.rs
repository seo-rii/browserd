mod actor;
mod ephemeral;
mod gateway_action_actor;
mod gateway_actions;
mod memory;
mod memory_ephemeral;
mod postgres;
mod redis;

use std::fmt;
use std::time::Duration;

use async_trait::async_trait;
use browserd_core::{CreateOperationState, OperationId, PrincipalId, SessionId, TenantId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::{Uuid, Version};

pub use actor::{CoordinationActorConfig, CoordinationBlockingClient};
pub use ephemeral::{
    DirectoryEntry, DirectoryFence, DirectoryKey, DirectoryMutation, DirectorySnapshot,
    EphemeralCoordinationError, EphemeralCoordinationStore, OneTimeCapability, OneTimeConsume,
    OneTimeIssue, WorkerCapacity, WorkerHeartbeat, WorkerLeaseMutation, WorkerLeaseStore,
    WorkerReadiness, WorkerRegistration, WorkerRegistrationQuery, WorkerRegistrationSnapshot,
    WorkerReservationGrant, WorkerReservationMutation, WorkerReservationOutcome,
    WorkerReservationRequest, WorkerReservationSnapshot, WorkerReservationStore,
};
pub use gateway_action_actor::GatewayActionBlockingClient;
pub use gateway_actions::{
    ClaimGatewayAction, GatewayActionClaimOutcome, GatewayActionCoordination,
    GatewayActionCoordinationError, GatewayActionPlacement, GatewayActionSnapshot,
    MAX_DURABLE_RESULT_CONTENT_BYTES, MemoryGatewayActionStore, RedisGatewayActionConfig,
    RedisGatewayActionStore, SessionLossClaim, SessionLossOutcome,
};
pub use memory::{MemoryCoordinationDatabase, MemoryCreateSessionStore};
pub use memory_ephemeral::{ManualCoordinationClock, MemoryEphemeralCoordinationStore};
pub use postgres::PostgresCreateSessionStore;
pub use redis::{RedisEphemeralConfig, RedisEphemeralCoordinationStore};

pub const MINIMUM_IDEMPOTENCY_RETENTION: Duration = Duration::from_secs(24 * 60 * 60);
pub const MINIMUM_DISPATCH_LEASE_TTL: Duration = Duration::from_millis(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoreConfig {
    retention: Duration,
}

impl StoreConfig {
    pub fn new(retention: Duration) -> Result<Self, CoordinationError> {
        if retention < MINIMUM_IDEMPOTENCY_RETENTION {
            return Err(CoordinationError::RetentionBelowMinimum);
        }
        Ok(Self { retention })
    }

    #[must_use]
    pub const fn retention(self) -> Duration {
        self.retention
    }
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            retention: MINIMUM_IDEMPOTENCY_RETENTION,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CanonicalRequestHash([u8; 32]);

impl CanonicalRequestHash {
    #[must_use]
    pub const fn new(value: [u8; 32]) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DownstreamDedupeKey([u8; 32]);

impl DownstreamDedupeKey {
    #[must_use]
    pub fn for_operation(operation_id: &OperationId) -> Self {
        let mut digest = Sha256::new();
        digest.update(b"browserd:create-session:v1\0");
        digest.update(operation_id.as_bytes());
        Self(digest.finalize().into())
    }

    #[must_use]
    pub const fn from_bytes(value: [u8; 32]) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoverableCreateIntent {
    canonical_request: Value,
    downstream_dedupe_key: DownstreamDedupeKey,
    accepted_at: DateTime<Utc>,
    admission_deadline: DateTime<Utc>,
    policy_context: Value,
}

impl RecoverableCreateIntent {
    pub fn new(
        operation_id: &OperationId,
        canonical_request: Value,
        accepted_at: DateTime<Utc>,
        admission_deadline: DateTime<Utc>,
        policy_context: Value,
    ) -> Result<Self, CoordinationError> {
        if admission_deadline <= accepted_at
            || !canonical_request.is_object()
            || !policy_context.is_object()
        {
            return Err(CoordinationError::InvalidCreateIntent);
        }
        Ok(Self {
            canonical_request,
            downstream_dedupe_key: DownstreamDedupeKey::for_operation(operation_id),
            accepted_at,
            admission_deadline,
            policy_context,
        })
    }

    #[must_use]
    pub const fn canonical_request(&self) -> &Value {
        &self.canonical_request
    }

    #[must_use]
    pub const fn downstream_dedupe_key(&self) -> DownstreamDedupeKey {
        self.downstream_dedupe_key
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
    pub const fn policy_context(&self) -> &Value {
        &self.policy_context
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DispatchLeaseToken(Uuid);

impl DispatchLeaseToken {
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    pub fn from_uuid(value: Uuid) -> Result<Self, CoordinationError> {
        if value.get_version() != Some(Version::Random) {
            return Err(CoordinationError::CorruptData(
                "dispatch lease token is not UUIDv4",
            ));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub const fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl Default for DispatchLeaseToken {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DispatchLease {
    token: DispatchLeaseToken,
    expires_at: DateTime<Utc>,
}

impl DispatchLease {
    pub fn new(
        token: DispatchLeaseToken,
        expires_at: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<Self, CoordinationError> {
        if expires_at <= now {
            return Err(CoordinationError::InvalidDispatchLease);
        }
        Ok(Self { token, expires_at })
    }

    #[must_use]
    pub const fn token(&self) -> &DispatchLeaseToken {
        &self.token
    }

    #[must_use]
    pub const fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    #[must_use]
    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        self.expires_at <= now
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct IdempotencyKey(String);

impl IdempotencyKey {
    fn new(value: impl Into<String>) -> Result<Self, CoordinationError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 255
            || value.trim() != value
            || value.chars().any(char::is_control)
        {
            return Err(CoordinationError::InvalidIdempotencyKey);
        }
        Ok(Self(value))
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimCreateOperation {
    tenant_id: TenantId,
    principal_id: PrincipalId,
    operation_id: OperationId,
    idempotency_key: IdempotencyKey,
    request_hash: CanonicalRequestHash,
    intent: RecoverableCreateIntent,
}

impl ClaimCreateOperation {
    pub fn new(
        tenant_id: TenantId,
        principal_id: PrincipalId,
        operation_id: OperationId,
        idempotency_key: impl Into<String>,
        request_hash: CanonicalRequestHash,
        intent: RecoverableCreateIntent,
    ) -> Result<Self, CoordinationError> {
        Ok(Self {
            tenant_id,
            principal_id,
            operation_id,
            idempotency_key: IdempotencyKey::new(idempotency_key)?,
            request_hash,
            intent,
        })
    }

    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    #[must_use]
    pub const fn principal_id(&self) -> &PrincipalId {
        &self.principal_id
    }

    #[must_use]
    pub const fn operation_id(&self) -> &OperationId {
        &self.operation_id
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
    pub const fn intent(&self) -> &RecoverableCreateIntent {
        &self.intent
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CreateOperationResult {
    session_id: SessionId,
    value: Value,
}

impl CreateOperationResult {
    #[must_use]
    pub const fn new(session_id: SessionId, value: Value) -> Self {
        Self { session_id, value }
    }

    #[must_use]
    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    #[must_use]
    pub const fn value(&self) -> &Value {
        &self.value
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CreateOperationError {
    code: String,
    message: String,
    retryable: bool,
    details: Value,
}

impl CreateOperationError {
    #[must_use]
    pub fn new(
        code: impl Into<String>,
        message: impl Into<String>,
        retryable: bool,
        details: Value,
    ) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            retryable,
            details,
        }
    }

    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    #[must_use]
    pub const fn retryable(&self) -> bool {
        self.retryable
    }

    #[must_use]
    pub const fn details(&self) -> &Value {
        &self.details
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateOperationSnapshot {
    tenant_id: TenantId,
    principal_id: PrincipalId,
    operation_id: OperationId,
    request_hash: CanonicalRequestHash,
    state: CreateOperationState,
    revision: u64,
    result: Option<CreateOperationResult>,
    error: Option<CreateOperationError>,
    dispatch_lease: Option<DispatchLease>,
    dispatch_generation: u64,
    intent: RecoverableCreateIntent,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    retain_until: DateTime<Utc>,
}

impl CreateOperationSnapshot {
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    #[must_use]
    pub const fn principal_id(&self) -> &PrincipalId {
        &self.principal_id
    }

    #[must_use]
    pub const fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    #[must_use]
    pub const fn request_hash(&self) -> CanonicalRequestHash {
        self.request_hash
    }

    #[must_use]
    pub const fn state(&self) -> CreateOperationState {
        self.state
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    #[must_use]
    pub const fn result(&self) -> Option<&CreateOperationResult> {
        self.result.as_ref()
    }

    #[must_use]
    pub const fn error(&self) -> Option<&CreateOperationError> {
        self.error.as_ref()
    }

    #[must_use]
    pub const fn dispatch_lease(&self) -> Option<&DispatchLease> {
        self.dispatch_lease.as_ref()
    }

    #[must_use]
    pub const fn dispatch_generation(&self) -> u64 {
        self.dispatch_generation
    }

    #[must_use]
    pub const fn intent(&self) -> &RecoverableCreateIntent {
        &self.intent
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
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClaimOutcome {
    Created(CreateOperationSnapshot),
    Existing(CreateOperationSnapshot),
}

impl ClaimOutcome {
    #[must_use]
    pub const fn snapshot(&self) -> &CreateOperationSnapshot {
        match self {
            Self::Created(snapshot) | Self::Existing(snapshot) => snapshot,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationMutation {
    next_state: CreateOperationState,
    result: Option<CreateOperationResult>,
    error: Option<CreateOperationError>,
    required_dispatch_token: Option<DispatchLeaseToken>,
    dispatch_lease: Option<DispatchLease>,
}

impl OperationMutation {
    #[must_use]
    pub const fn transition(next_state: CreateOperationState) -> Self {
        Self {
            next_state,
            result: None,
            error: None,
            required_dispatch_token: None,
            dispatch_lease: None,
        }
    }

    #[must_use]
    pub const fn succeed(result: CreateOperationResult) -> Self {
        Self {
            next_state: CreateOperationState::Succeeded,
            result: Some(result),
            error: None,
            required_dispatch_token: None,
            dispatch_lease: None,
        }
    }

    #[must_use]
    pub const fn fail(error: CreateOperationError) -> Self {
        Self {
            next_state: CreateOperationState::Failed,
            result: None,
            error: Some(error),
            required_dispatch_token: None,
            dispatch_lease: None,
        }
    }

    #[must_use]
    pub const fn timeout(error: CreateOperationError) -> Self {
        Self {
            next_state: CreateOperationState::TimedOut,
            result: None,
            error: Some(error),
            required_dispatch_token: None,
            dispatch_lease: None,
        }
    }

    #[must_use]
    pub const fn begin_dispatch(lease: DispatchLease) -> Self {
        Self {
            next_state: CreateOperationState::Creating,
            result: None,
            error: None,
            required_dispatch_token: None,
            dispatch_lease: Some(lease),
        }
    }

    #[must_use]
    pub const fn recover_dispatch(lease: DispatchLease) -> Self {
        Self {
            next_state: CreateOperationState::Creating,
            result: None,
            error: None,
            required_dispatch_token: None,
            dispatch_lease: Some(lease),
        }
    }

    #[must_use]
    pub const fn succeed_with_lease(
        token: DispatchLeaseToken,
        result: CreateOperationResult,
    ) -> Self {
        Self {
            next_state: CreateOperationState::Succeeded,
            result: Some(result),
            error: None,
            required_dispatch_token: Some(token),
            dispatch_lease: None,
        }
    }

    #[must_use]
    pub const fn fail_with_lease(token: DispatchLeaseToken, error: CreateOperationError) -> Self {
        Self {
            next_state: CreateOperationState::Failed,
            result: None,
            error: Some(error),
            required_dispatch_token: Some(token),
            dispatch_lease: None,
        }
    }

    #[must_use]
    pub const fn timeout_with_lease(
        token: DispatchLeaseToken,
        error: CreateOperationError,
    ) -> Self {
        Self {
            next_state: CreateOperationState::TimedOut,
            result: None,
            error: Some(error),
            required_dispatch_token: Some(token),
            dispatch_lease: None,
        }
    }

    #[must_use]
    pub const fn next_state(&self) -> CreateOperationState {
        self.next_state
    }
}

#[derive(Debug, Error)]
pub enum CoordinationError {
    #[error("idempotency retention must be at least 24 hours")]
    RetentionBelowMinimum,
    #[error("idempotency key must be 1-255 trimmed printable characters")]
    InvalidIdempotencyKey,
    #[error("idempotency key belongs to a different canonical request")]
    IdempotencyConflict { existing_operation_id: OperationId },
    #[error("create operation was not found")]
    NotFound,
    #[error("create operation was concurrently changed")]
    StaleWrite(Box<CreateOperationSnapshot>),
    #[error("terminal create operation {0:?} is immutable")]
    TerminalImmutable(CreateOperationState),
    #[error("invalid create operation transition from {from:?} to {to:?}")]
    InvalidTransition {
        from: CreateOperationState,
        to: CreateOperationState,
    },
    #[error("result/error payload does not match terminal state")]
    InvalidTerminalPayload,
    #[error("dispatch lease must expire in the future")]
    InvalidDispatchLease,
    #[error("dispatch lease does not match the current owner")]
    DispatchLeaseMismatch,
    #[error("dispatch lease has not expired")]
    DispatchLeaseActive(Box<CreateOperationSnapshot>),
    #[error("recoverable create intent is invalid")]
    InvalidCreateIntent,
    #[error("coordination scan limit is invalid")]
    InvalidScanLimit,
    #[error("coordination database is unavailable: {0}")]
    Database(#[from] sqlx::Error),
    #[error("coordination database migration failed: {0}")]
    Migration(#[from] sqlx::migrate::MigrateError),
    #[error("coordination state lock is unavailable")]
    LockUnavailable,
    #[error("coordination actor configuration is invalid")]
    InvalidActorConfig,
    #[error("coordination actor could not be started")]
    ActorSpawn,
    #[error("coordination actor queue is full")]
    ActorQueueFull,
    #[error("coordination actor is unavailable")]
    ActorDisconnected,
    #[error("coordination actor query timed out")]
    ActorTimeout,
    #[error("coordination actor mutation result is unknown after timeout")]
    ActorMutationTimeout,
    #[error("stored coordination row is invalid: {0}")]
    CorruptData(&'static str),
}

#[async_trait]
pub trait CreateSessionCoordination: Send + Sync {
    async fn claim_create(
        &self,
        claim: ClaimCreateOperation,
        now: DateTime<Utc>,
    ) -> Result<ClaimOutcome, CoordinationError>;

    async fn get(
        &self,
        tenant_id: &TenantId,
        operation_id: &OperationId,
    ) -> Result<Option<CreateOperationSnapshot>, CoordinationError>;

    async fn compare_and_set(
        &self,
        tenant_id: &TenantId,
        operation_id: &OperationId,
        expected_revision: u64,
        expected_state: CreateOperationState,
        mutation: OperationMutation,
        now: DateTime<Utc>,
    ) -> Result<CreateOperationSnapshot, CoordinationError>;

    async fn acquire_dispatch_lease(
        &self,
        _tenant_id: &TenantId,
        _operation_id: &OperationId,
        _expected_revision: u64,
        _token: DispatchLeaseToken,
        _ttl: Duration,
        _now: DateTime<Utc>,
    ) -> Result<CreateOperationSnapshot, CoordinationError> {
        Err(CoordinationError::Database(sqlx::Error::Protocol(
            "dispatch leases unsupported".into(),
        )))
    }

    async fn scan_reconcilable(
        &self,
        _limit: usize,
        _now: DateTime<Utc>,
    ) -> Result<Vec<CreateOperationSnapshot>, CoordinationError> {
        Err(CoordinationError::Database(sqlx::Error::Protocol(
            "reconciliation scan unsupported".into(),
        )))
    }

    async fn renew_dispatch_lease(
        &self,
        _tenant_id: &TenantId,
        _operation_id: &OperationId,
        _expected_revision: u64,
        _token: DispatchLeaseToken,
        _ttl: Duration,
        _now: DateTime<Utc>,
    ) -> Result<CreateOperationSnapshot, CoordinationError> {
        Err(CoordinationError::Database(sqlx::Error::Protocol(
            "dispatch lease renewal unsupported".into(),
        )))
    }

    async fn purge_expired(&self, now: DateTime<Utc>) -> Result<u64, CoordinationError>;
}

fn is_terminal(state: CreateOperationState) -> bool {
    matches!(
        state,
        CreateOperationState::Succeeded
            | CreateOperationState::TimedOut
            | CreateOperationState::Cancelled
            | CreateOperationState::Failed
    )
}

fn validate_mutation(
    current: &CreateOperationSnapshot,
    mutation: &OperationMutation,
    _now: DateTime<Utc>,
) -> Result<(), CoordinationError> {
    if is_terminal(current.state) {
        return Err(CoordinationError::TerminalImmutable(current.state));
    }
    let valid_transition = matches!(
        (current.state, mutation.next_state),
        (CreateOperationState::Accepted, CreateOperationState::Queued)
            | (
                CreateOperationState::Accepted,
                CreateOperationState::TimedOut
            )
            | (
                CreateOperationState::Accepted,
                CreateOperationState::Cancelled
            )
            | (CreateOperationState::Accepted, CreateOperationState::Failed)
            | (
                CreateOperationState::Queued,
                CreateOperationState::Reserving
            )
            | (CreateOperationState::Queued, CreateOperationState::TimedOut)
            | (
                CreateOperationState::Queued,
                CreateOperationState::Cancelled
            )
            | (CreateOperationState::Queued, CreateOperationState::Failed)
            | (
                CreateOperationState::Reserving,
                CreateOperationState::Queued
            )
            | (
                CreateOperationState::Reserving,
                CreateOperationState::TimedOut
            )
            | (
                CreateOperationState::Reserving,
                CreateOperationState::Cancelled
            )
            | (
                CreateOperationState::Reserving,
                CreateOperationState::Failed
            )
            | (
                CreateOperationState::Creating,
                CreateOperationState::Succeeded
            )
            | (
                CreateOperationState::Creating,
                CreateOperationState::TimedOut
            )
            | (CreateOperationState::Creating, CreateOperationState::Failed)
    );
    if !valid_transition {
        return Err(CoordinationError::InvalidTransition {
            from: current.state,
            to: mutation.next_state,
        });
    }
    if mutation.dispatch_lease.is_some() {
        return Err(CoordinationError::InvalidDispatchLease);
    }
    let terminal_completion = matches!(
        mutation.next_state,
        CreateOperationState::Succeeded
            | CreateOperationState::Failed
            | CreateOperationState::TimedOut
    );
    if terminal_completion && current.dispatch_lease.is_some() {
        let required = mutation
            .required_dispatch_token
            .as_ref()
            .ok_or(CoordinationError::DispatchLeaseMismatch)?;
        if current.dispatch_lease.as_ref().map(DispatchLease::token) != Some(required) {
            return Err(CoordinationError::DispatchLeaseMismatch);
        }
    } else if mutation.required_dispatch_token.is_some() {
        return Err(CoordinationError::DispatchLeaseMismatch);
    }
    let payload_is_valid = match mutation.next_state {
        CreateOperationState::Succeeded => mutation.result.is_some() && mutation.error.is_none(),
        CreateOperationState::Failed | CreateOperationState::TimedOut => {
            mutation.result.is_none() && mutation.error.is_some()
        }
        _ => mutation.result.is_none() && mutation.error.is_none(),
    };
    if !payload_is_valid {
        return Err(CoordinationError::InvalidTerminalPayload);
    }
    Ok(())
}

fn state_name(state: CreateOperationState) -> &'static str {
    match state {
        CreateOperationState::Accepted => "accepted",
        CreateOperationState::Queued => "queued",
        CreateOperationState::Reserving => "reserving",
        CreateOperationState::Creating => "creating",
        CreateOperationState::Succeeded => "succeeded",
        CreateOperationState::TimedOut => "timed_out",
        CreateOperationState::Cancelled => "cancelled",
        CreateOperationState::Failed => "failed",
    }
}

fn parse_state(value: &str) -> Result<CreateOperationState, CoordinationError> {
    match value {
        "accepted" => Ok(CreateOperationState::Accepted),
        "queued" => Ok(CreateOperationState::Queued),
        "reserving" => Ok(CreateOperationState::Reserving),
        "creating" => Ok(CreateOperationState::Creating),
        "succeeded" => Ok(CreateOperationState::Succeeded),
        "timed_out" => Ok(CreateOperationState::TimedOut),
        "cancelled" => Ok(CreateOperationState::Cancelled),
        "failed" => Ok(CreateOperationState::Failed),
        _ => Err(CoordinationError::CorruptData("unknown operation state")),
    }
}

impl fmt::Display for CanonicalRequestHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}
