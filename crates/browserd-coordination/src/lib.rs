mod memory;
mod postgres;

use std::fmt;
use std::time::Duration;

use async_trait::async_trait;
use browserd_core::{CreateOperationState, OperationId, PrincipalId, SessionId, TenantId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

pub use memory::{MemoryCoordinationDatabase, MemoryCreateSessionStore};
pub use postgres::PostgresCreateSessionStore;

pub const MINIMUM_IDEMPOTENCY_RETENTION: Duration = Duration::from_secs(24 * 60 * 60);

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
}

impl ClaimCreateOperation {
    pub fn new(
        tenant_id: TenantId,
        principal_id: PrincipalId,
        operation_id: OperationId,
        idempotency_key: impl Into<String>,
        request_hash: CanonicalRequestHash,
    ) -> Result<Self, CoordinationError> {
        Ok(Self {
            tenant_id,
            principal_id,
            operation_id,
            idempotency_key: IdempotencyKey::new(idempotency_key)?,
            request_hash,
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
}

impl OperationMutation {
    #[must_use]
    pub const fn transition(next_state: CreateOperationState) -> Self {
        Self {
            next_state,
            result: None,
            error: None,
        }
    }

    #[must_use]
    pub const fn succeed(result: CreateOperationResult) -> Self {
        Self {
            next_state: CreateOperationState::Succeeded,
            result: Some(result),
            error: None,
        }
    }

    #[must_use]
    pub const fn fail(error: CreateOperationError) -> Self {
        Self {
            next_state: CreateOperationState::Failed,
            result: None,
            error: Some(error),
        }
    }

    #[must_use]
    pub const fn timeout(error: CreateOperationError) -> Self {
        Self {
            next_state: CreateOperationState::TimedOut,
            result: None,
            error: Some(error),
        }
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
    #[error("coordination database is unavailable: {0}")]
    Database(#[from] sqlx::Error),
    #[error("coordination database migration failed: {0}")]
    Migration(#[from] sqlx::migrate::MigrateError),
    #[error("coordination state lock is unavailable")]
    LockUnavailable,
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
    current: CreateOperationState,
    mutation: &OperationMutation,
) -> Result<(), CoordinationError> {
    if is_terminal(current) {
        return Err(CoordinationError::TerminalImmutable(current));
    }
    let valid_transition = matches!(
        (current, mutation.next_state),
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
                CreateOperationState::Creating
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
            from: current,
            to: mutation.next_state,
        });
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
