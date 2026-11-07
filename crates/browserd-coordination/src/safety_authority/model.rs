use std::time::Duration;

use browserd_core::{SafetySwitchMutation, SafetySwitchSnapshot, TenantId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::{Uuid, Version};

const MIN_RETENTION_MS: u64 = 24 * 60 * 60 * 1_000;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SafetyAuthorityError {
    #[error("runtime safety authority is not initialized")]
    MissingAuthority,
    #[error("runtime safety authority is already initialized")]
    AlreadyInitialized,
    #[error("invalid runtime safety request")]
    InvalidInput,
    #[error("invalid runtime safety authority configuration")]
    InvalidConfig,
    #[error("runtime safety authority configuration differs from its immutable configuration")]
    ConfigMismatch,
    #[error("invalid runtime safety snapshot")]
    InvalidSnapshot,
    #[error("runtime safety idempotency key was used for a different request")]
    IdempotencyConflict,
    #[error("runtime safety version conflict: expected {expected}, current {current}")]
    VersionConflict { expected: u64, current: u64 },
    #[error("runtime safety pending audit or receipt capacity is exhausted")]
    Capacity,
    #[error("runtime safety audit acknowledgement is not the exact oldest intent")]
    InvalidAck,
    #[error("runtime safety authority state is corrupt")]
    CorruptState,
    #[error("runtime safety authority is unavailable")]
    Unavailable,
    #[error("runtime safety operation timed out; an admitted mutation may still complete")]
    TimedOut,
    #[error("runtime safety actor queue is full")]
    QueueFull,
    #[error("runtime safety actor is disconnected")]
    ActorDisconnected,
    #[error("runtime safety actor could not start")]
    ActorSpawn,
    #[error("runtime safety namespace differs from the durable observer pin")]
    NamespaceMismatch,
    #[error("runtime safety version is older than the durable observer pin")]
    Rollback,
    #[error("runtime safety snapshot differs at the same version")]
    Equivocation,
    #[error("runtime safety observer durability is unavailable")]
    DurabilityUnavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SafetyAuthorityConfig {
    max_receipts: usize,
    max_receipts_per_actor: usize,
    max_pending_audits: usize,
    max_encoded_bytes: usize,
    retention_ms: u64,
}

impl SafetyAuthorityConfig {
    pub fn new(
        max_receipts: usize,
        max_receipts_per_actor: usize,
        max_pending_audits: usize,
        max_encoded_bytes: usize,
        receipt_retention: Duration,
    ) -> Result<Self, SafetyAuthorityError> {
        let retention_ms = u64::try_from(receipt_retention.as_millis())
            .map_err(|_| SafetyAuthorityError::InvalidConfig)?;
        if !(1..=65_536).contains(&max_receipts)
            || !(1..=max_receipts).contains(&max_receipts_per_actor)
            || !(1..=4_096).contains(&max_pending_audits)
            || max_pending_audits > max_receipts
            || !(4_096..=64 * 1024 * 1024).contains(&max_encoded_bytes)
            || !(MIN_RETENTION_MS..=365 * MIN_RETENTION_MS).contains(&retention_ms)
            || !receipt_retention.subsec_nanos().is_multiple_of(1_000_000)
        {
            return Err(SafetyAuthorityError::InvalidConfig);
        }
        Ok(Self {
            max_receipts,
            max_receipts_per_actor,
            max_pending_audits,
            max_encoded_bytes,
            retention_ms,
        })
    }
    pub const fn max_receipts(self) -> usize {
        self.max_receipts
    }
    pub const fn max_receipts_per_actor(self) -> usize {
        self.max_receipts_per_actor
    }
    pub const fn max_pending_audits(self) -> usize {
        self.max_pending_audits
    }
    pub const fn max_encoded_bytes(self) -> usize {
        self.max_encoded_bytes
    }
    pub const fn receipt_retention(self) -> Duration {
        Duration::from_millis(self.retention_ms)
    }
    pub(super) const fn retention_ms(self) -> u64 {
        self.retention_ms
    }
    pub(super) fn digest(self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"browserd:safety-authority-config:v1\0");
        for value in [
            self.max_receipts as u64,
            self.max_receipts_per_actor as u64,
            self.max_pending_audits as u64,
            self.max_encoded_bytes as u64,
            self.retention_ms,
        ] {
            hash.update(value.to_be_bytes());
        }
        hash.finalize().into()
    }
}
impl Default for SafetyAuthorityConfig {
    fn default() -> Self {
        Self {
            max_receipts: 1_024,
            max_receipts_per_actor: 128,
            max_pending_audits: 1_024,
            max_encoded_bytes: 8 * 1024 * 1024,
            retention_ms: MIN_RETENTION_MS,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SafetyActorIdentity {
    tenant_id: TenantId,
    principal: String,
}
impl SafetyActorIdentity {
    pub fn new(
        tenant_id: TenantId,
        principal: impl Into<String>,
    ) -> Result<Self, SafetyAuthorityError> {
        let identity = Self {
            tenant_id,
            principal: principal.into(),
        };
        identity.validate()?;
        Ok(identity)
    }
    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }
    pub fn principal(&self) -> &str {
        &self.principal
    }
    pub(super) fn validate(&self) -> Result<(), SafetyAuthorityError> {
        if self.principal.is_empty()
            || self.principal.len() > 256
            || self.principal.trim() != self.principal
            || self.principal.chars().any(char::is_control)
        {
            return Err(SafetyAuthorityError::InvalidInput);
        }
        Ok(())
    }
}

fn validate_binding(
    identity: &SafetyActorIdentity,
    key: Uuid,
    reason: &str,
) -> Result<(), SafetyAuthorityError> {
    identity.validate()?;
    if key.is_nil()
        || reason.is_empty()
        || reason.len() > 2_048
        || reason.trim() != reason
        || reason.chars().any(char::is_control)
    {
        return Err(SafetyAuthorityError::InvalidInput);
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SafetyInitializeRequest {
    identity: SafetyActorIdentity,
    idempotency_key: Uuid,
    reason: String,
}
impl SafetyInitializeRequest {
    pub fn new(
        identity: SafetyActorIdentity,
        idempotency_key: Uuid,
        reason: impl Into<String>,
    ) -> Result<Self, SafetyAuthorityError> {
        let request = Self {
            identity,
            idempotency_key,
            reason: reason.into().trim().to_owned(),
        };
        request.validate()?;
        Ok(request)
    }
    pub fn identity(&self) -> &SafetyActorIdentity {
        &self.identity
    }
    pub const fn idempotency_key(&self) -> Uuid {
        self.idempotency_key
    }
    pub fn reason(&self) -> &str {
        &self.reason
    }
    pub(super) fn validate(&self) -> Result<(), SafetyAuthorityError> {
        validate_binding(&self.identity, self.idempotency_key, &self.reason)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SafetyMutationRequest {
    identity: SafetyActorIdentity,
    idempotency_key: Uuid,
    expected_version: u64,
    mutation: SafetySwitchMutation,
    reason: String,
}
impl SafetyMutationRequest {
    pub fn new(
        identity: SafetyActorIdentity,
        idempotency_key: Uuid,
        expected_version: u64,
        mutation: SafetySwitchMutation,
        reason: impl Into<String>,
    ) -> Result<Self, SafetyAuthorityError> {
        let request = Self {
            identity,
            idempotency_key,
            expected_version,
            mutation: mutation
                .canonicalized()
                .map_err(|_| SafetyAuthorityError::InvalidInput)?,
            reason: reason.into().trim().to_owned(),
        };
        request.validate()?;
        Ok(request)
    }
    pub fn identity(&self) -> &SafetyActorIdentity {
        &self.identity
    }
    pub const fn idempotency_key(&self) -> Uuid {
        self.idempotency_key
    }
    pub const fn expected_version(&self) -> u64 {
        self.expected_version
    }
    pub fn mutation(&self) -> &SafetySwitchMutation {
        &self.mutation
    }
    pub fn reason(&self) -> &str {
        &self.reason
    }
    pub(super) fn validate(&self) -> Result<(), SafetyAuthorityError> {
        validate_binding(&self.identity, self.idempotency_key, &self.reason)?;
        if self.expected_version > i64::MAX as u64
            || matches!(
                self.mutation,
                SafetySwitchMutation::SetSharedAdmission { .. }
            )
            || self
                .mutation
                .canonicalized()
                .map_err(|_| SafetyAuthorityError::InvalidInput)?
                != self.mutation
        {
            return Err(SafetyAuthorityError::InvalidInput);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SafetyAuthoritySnapshot {
    namespace_id: Uuid,
    snapshot: SafetySwitchSnapshot,
    snapshot_digest: [u8; 32],
}
impl SafetyAuthoritySnapshot {
    pub fn new(
        namespace_id: Uuid,
        snapshot: SafetySwitchSnapshot,
    ) -> Result<Self, SafetyAuthorityError> {
        if namespace_id.is_nil() {
            return Err(SafetyAuthorityError::InvalidSnapshot);
        }
        let snapshot_digest = snapshot
            .digest()
            .map_err(|_| SafetyAuthorityError::InvalidSnapshot)?;
        Ok(Self {
            namespace_id,
            snapshot,
            snapshot_digest,
        })
    }
    pub const fn namespace_id(&self) -> Uuid {
        self.namespace_id
    }
    pub fn snapshot(&self) -> &SafetySwitchSnapshot {
        &self.snapshot
    }
    pub const fn snapshot_digest(&self) -> [u8; 32] {
        self.snapshot_digest
    }
    pub(super) fn validate(&self) -> Result<(), SafetyAuthorityError> {
        if self.namespace_id.is_nil()
            || self
                .snapshot
                .digest()
                .map_err(|_| SafetyAuthorityError::InvalidSnapshot)?
                != self.snapshot_digest
        {
            return Err(SafetyAuthorityError::InvalidSnapshot);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SafetyMutationReceipt {
    pub(super) namespace_id: Uuid,
    pub(super) idempotency_key: Uuid,
    pub(super) previous_version: Option<u64>,
    pub(super) version: u64,
    pub(super) audit_sequence: u64,
    pub(super) audit_event_id: Uuid,
    pub(super) request_digest: [u8; 32],
    pub(super) snapshot_digest: [u8; 32],
    pub(super) occurred_at_unix_ms: u64,
}
impl SafetyMutationReceipt {
    pub const fn namespace_id(&self) -> Uuid {
        self.namespace_id
    }
    pub const fn idempotency_key(&self) -> Uuid {
        self.idempotency_key
    }
    pub const fn previous_version(&self) -> Option<u64> {
        self.previous_version
    }
    pub const fn version(&self) -> u64 {
        self.version
    }
    pub const fn audit_sequence(&self) -> u64 {
        self.audit_sequence
    }
    pub const fn audit_event_id(&self) -> Uuid {
        self.audit_event_id
    }
    pub const fn request_digest(&self) -> [u8; 32] {
        self.request_digest
    }
    pub const fn snapshot_digest(&self) -> [u8; 32] {
        self.snapshot_digest
    }
    pub const fn occurred_at_unix_ms(&self) -> u64 {
        self.occurred_at_unix_ms
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "kind",
    content = "request",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub(super) enum AuditRequest {
    Initialize(SafetyInitializeRequest),
    Mutate(SafetyMutationRequest),
}
impl AuditRequest {
    pub(super) fn identity(&self) -> &SafetyActorIdentity {
        match self {
            Self::Initialize(r) => r.identity(),
            Self::Mutate(r) => r.identity(),
        }
    }
    pub(super) fn key(&self) -> Uuid {
        match self {
            Self::Initialize(r) => r.idempotency_key(),
            Self::Mutate(r) => r.idempotency_key(),
        }
    }
    pub(super) fn validate(&self) -> Result<(), SafetyAuthorityError> {
        match self {
            Self::Initialize(r) => r.validate(),
            Self::Mutate(r) => r.validate(),
        }
    }
    pub(super) fn digest(&self, namespace: Uuid) -> Result<[u8; 32], SafetyAuthorityError> {
        let mut hash = Sha256::new();
        hash.update(b"browserd:safety-request:v1\0");
        hash.update(namespace.as_bytes());
        hash.update(serde_json::to_vec(self).map_err(|_| SafetyAuthorityError::InvalidInput)?);
        Ok(hash.finalize().into())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SafetyAuditIntent {
    pub(super) receipt: SafetyMutationReceipt,
    pub(super) request: AuditRequest,
    pub(super) digest: [u8; 32],
}
impl SafetyAuditIntent {
    pub fn receipt(&self) -> &SafetyMutationReceipt {
        &self.receipt
    }
    pub fn identity(&self) -> &SafetyActorIdentity {
        self.request.identity()
    }
    pub fn reason(&self) -> &str {
        match &self.request {
            AuditRequest::Initialize(r) => r.reason(),
            AuditRequest::Mutate(r) => r.reason(),
        }
    }
    pub fn mutation(&self) -> Option<&SafetySwitchMutation> {
        match &self.request {
            AuditRequest::Initialize(_) => None,
            AuditRequest::Mutate(r) => Some(r.mutation()),
        }
    }
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }
    pub fn ack(&self) -> SafetyAuditAck {
        SafetyAuditAck {
            namespace_id: self.receipt.namespace_id,
            audit_sequence: self.receipt.audit_sequence,
            event_id: self.receipt.audit_event_id,
            digest: self.digest,
        }
    }
    pub(super) fn computed_digest(&self) -> Result<[u8; 32], SafetyAuthorityError> {
        let mut hash = Sha256::new();
        hash.update(b"browserd:safety-audit:v1\0");
        hash.update(
            serde_json::to_vec(&(&self.receipt, &self.request))
                .map_err(|_| SafetyAuthorityError::CorruptState)?,
        );
        Ok(hash.finalize().into())
    }
    pub(super) fn validate(&self) -> Result<(), SafetyAuthorityError> {
        self.request
            .validate()
            .map_err(|_| SafetyAuthorityError::CorruptState)?;
        let r = &self.receipt;
        let version_valid = match &self.request {
            AuditRequest::Initialize(_) => r.previous_version.is_none() && r.version == 0,
            AuditRequest::Mutate(request) => {
                r.previous_version == Some(request.expected_version())
                    && request.expected_version().checked_add(1) == Some(r.version)
            }
        };
        if !version_valid
            || r.namespace_id.is_nil()
            || r.version > i64::MAX as u64
            || r.audit_sequence != r.version + 1
            || r.audit_event_id.get_version() != Some(Version::SortRand)
            || r.idempotency_key != self.request.key()
            || r.occurred_at_unix_ms > i64::MAX as u64
            || r.request_digest != self.request.digest(r.namespace_id)?
            || self.digest != self.computed_digest()?
        {
            return Err(SafetyAuthorityError::CorruptState);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SafetyAuditAck {
    namespace_id: Uuid,
    audit_sequence: u64,
    event_id: Uuid,
    digest: [u8; 32],
}
impl SafetyAuditAck {
    pub fn new(
        namespace_id: Uuid,
        audit_sequence: u64,
        event_id: Uuid,
        digest: [u8; 32],
    ) -> Result<Self, SafetyAuthorityError> {
        if namespace_id.is_nil()
            || audit_sequence == 0
            || audit_sequence > i64::MAX as u64 + 1
            || event_id.get_version() != Some(Version::SortRand)
        {
            return Err(SafetyAuthorityError::InvalidAck);
        }
        Ok(Self {
            namespace_id,
            audit_sequence,
            event_id,
            digest,
        })
    }
    pub const fn namespace_id(&self) -> Uuid {
        self.namespace_id
    }
    pub const fn audit_sequence(&self) -> u64 {
        self.audit_sequence
    }
    pub const fn event_id(&self) -> Uuid {
        self.event_id
    }
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }
}
