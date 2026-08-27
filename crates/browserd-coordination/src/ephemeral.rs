use std::fmt;
use std::time::Duration;

use async_trait::async_trait;
use browserd_core::{SessionId, TenantId, WorkerId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub(crate) const MAX_EPHEMERAL_TTL_MILLIS: u64 = 5 * 60 * 1000;

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct DirectoryKey {
    tenant_id: TenantId,
    session_id: SessionId,
}

impl DirectoryKey {
    #[must_use]
    pub const fn new(tenant_id: TenantId, session_id: SessionId) -> Self {
        Self {
            tenant_id,
            session_id,
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
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DirectoryFence {
    worker_id: WorkerId,
    worker_epoch: u64,
    placement_version: u64,
    session_incarnation: u64,
}

impl DirectoryFence {
    pub fn new(
        worker_id: WorkerId,
        worker_epoch: u64,
        placement_version: u64,
        session_incarnation: u64,
    ) -> Result<Self, EphemeralCoordinationError> {
        if worker_epoch == 0 || placement_version == 0 || session_incarnation == 0 {
            return Err(EphemeralCoordinationError::InvalidInput);
        }
        Ok(Self {
            worker_id,
            worker_epoch,
            placement_version,
            session_incarnation,
        })
    }
    #[must_use]
    pub const fn worker_id(&self) -> &WorkerId {
        &self.worker_id
    }
    #[must_use]
    pub const fn worker_epoch(&self) -> u64 {
        self.worker_epoch
    }
    #[must_use]
    pub const fn placement_version(&self) -> u64 {
        self.placement_version
    }
    #[must_use]
    pub const fn session_incarnation(&self) -> u64 {
        self.session_incarnation
    }
}

#[derive(Deserialize)]
struct DirectoryFenceWire {
    worker_id: WorkerId,
    worker_epoch: u64,
    placement_version: u64,
    session_incarnation: u64,
}

impl<'de> Deserialize<'de> for DirectoryFence {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = DirectoryFenceWire::deserialize(deserializer)?;
        Self::new(
            wire.worker_id,
            wire.worker_epoch,
            wire.placement_version,
            wire.session_incarnation,
        )
        .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DirectoryEntry {
    key: DirectoryKey,
    fence: DirectoryFence,
    endpoint: String,
}

impl DirectoryEntry {
    pub fn new(
        key: DirectoryKey,
        fence: DirectoryFence,
        endpoint: impl Into<String>,
    ) -> Result<Self, EphemeralCoordinationError> {
        let endpoint = endpoint.into();
        if endpoint.is_empty()
            || endpoint.len() > 2048
            || endpoint.trim() != endpoint
            || endpoint.chars().any(char::is_control)
        {
            return Err(EphemeralCoordinationError::InvalidInput);
        }
        Ok(Self {
            key,
            fence,
            endpoint,
        })
    }
    #[must_use]
    pub const fn key(&self) -> &DirectoryKey {
        &self.key
    }
    #[must_use]
    pub const fn fence(&self) -> &DirectoryFence {
        &self.fence
    }
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }
}

#[derive(Deserialize)]
struct DirectoryEntryWire {
    key: DirectoryKey,
    fence: DirectoryFence,
    endpoint: String,
}

impl<'de> Deserialize<'de> for DirectoryEntry {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = DirectoryEntryWire::deserialize(deserializer)?;
        Self::new(wire.key, wire.fence, wire.endpoint).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DirectorySnapshot {
    entry: DirectoryEntry,
    revision: u64,
    expires_at_millis: u64,
}

impl DirectorySnapshot {
    pub(crate) const fn new(entry: DirectoryEntry, revision: u64, expires_at_millis: u64) -> Self {
        Self {
            entry,
            revision,
            expires_at_millis,
        }
    }
    pub fn from_persisted(
        entry: DirectoryEntry,
        revision: u64,
        expires_at_millis: u64,
    ) -> Result<Self, EphemeralCoordinationError> {
        if revision == 0 || expires_at_millis == 0 {
            return Err(EphemeralCoordinationError::InvalidInput);
        }
        let fence = DirectoryFence::new(
            entry.fence.worker_id,
            entry.fence.worker_epoch,
            entry.fence.placement_version,
            entry.fence.session_incarnation,
        )?;
        let entry = DirectoryEntry::new(entry.key, fence, entry.endpoint)?;
        Ok(Self::new(entry, revision, expires_at_millis))
    }
    #[must_use]
    pub const fn entry(&self) -> &DirectoryEntry {
        &self.entry
    }
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }
    #[must_use]
    pub const fn expires_at_millis(&self) -> u64 {
        self.expires_at_millis
    }
}

#[derive(Deserialize)]
struct DirectorySnapshotWire {
    entry: DirectoryEntry,
    revision: u64,
    expires_at_millis: u64,
}

impl<'de> Deserialize<'de> for DirectorySnapshot {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = DirectorySnapshotWire::deserialize(deserializer)?;
        Self::from_persisted(wire.entry, wire.revision, wire.expires_at_millis)
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod typed_boundary_tests {
    #![allow(clippy::expect_used)]

    use super::*;

    fn valid_entry() -> DirectoryEntry {
        DirectoryEntry::new(
            DirectoryKey::new(TenantId::new(), SessionId::new()),
            DirectoryFence::new(WorkerId::new("worker-1").expect("valid worker id"), 1, 1, 1)
                .expect("valid fence"),
            "worker-rpc://worker-1",
        )
        .expect("valid entry")
    }

    #[test]
    fn directory_json_deserialization_cannot_bypass_constructor_invariants() {
        let entry = valid_entry();

        let mut fence = serde_json::to_value(entry.fence()).expect("serialize fence");
        fence["worker_epoch"] = serde_json::json!(0);
        assert!(serde_json::from_value::<DirectoryFence>(fence).is_err());

        let mut invalid_entry = serde_json::to_value(&entry).expect("serialize entry");
        invalid_entry["endpoint"] = serde_json::json!("worker-rpc://bad\nendpoint");
        assert!(serde_json::from_value::<DirectoryEntry>(invalid_entry).is_err());

        let snapshot = DirectorySnapshot::from_persisted(entry, 1, 1).expect("valid snapshot");
        let mut zero_revision = serde_json::to_value(&snapshot).expect("serialize snapshot");
        zero_revision["revision"] = serde_json::json!(0);
        assert!(serde_json::from_value::<DirectorySnapshot>(zero_revision).is_err());

        let mut zero_expiry = serde_json::to_value(snapshot).expect("serialize snapshot");
        zero_expiry["expires_at_millis"] = serde_json::json!(0);
        assert!(serde_json::from_value::<DirectorySnapshot>(zero_expiry).is_err());
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectoryMutation {
    Applied,
    AlreadyApplied,
    FenceMismatch,
    CasMismatch,
    Expired,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OneTimeCapability {
    tenant_id: TenantId,
    session_id: SessionId,
    secret_hash: [u8; 32],
}

impl OneTimeCapability {
    pub fn new(
        tenant_id: TenantId,
        session_id: SessionId,
        secret: impl AsRef<str>,
    ) -> Result<Self, EphemeralCoordinationError> {
        let secret = secret.as_ref();
        if !(16..=4096).contains(&secret.len()) {
            return Err(EphemeralCoordinationError::InvalidInput);
        }
        let mut hasher = Sha256::new();
        hasher.update(b"browserd:one-time-capability:v1\0");
        hasher.update(secret.as_bytes());
        Ok(Self {
            tenant_id,
            session_id,
            secret_hash: hasher.finalize().into(),
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
    pub const fn secret_hash(&self) -> &[u8; 32] {
        &self.secret_hash
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OneTimeConsume {
    Consumed,
    AlreadyConsumed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OneTimeIssue {
    Issued,
    AlreadyIssued,
    AlreadyConsumed,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum EphemeralCoordinationError {
    #[error("ephemeral coordination is unavailable")]
    Unavailable,
    #[error("ephemeral coordination input is invalid")]
    InvalidInput,
    #[error("ephemeral coordination operation timed out")]
    TimedOut,
    #[error("ephemeral coordination response was invalid")]
    InvalidResponse,
    #[error("ephemeral coordination revision is exhausted")]
    RevisionExhausted,
}

pub(crate) fn ttl_millis(ttl: Duration) -> Result<u64, EphemeralCoordinationError> {
    let value =
        u64::try_from(ttl.as_millis()).map_err(|_| EphemeralCoordinationError::InvalidInput)?;
    if value == 0 || value > MAX_EPHEMERAL_TTL_MILLIS {
        Err(EphemeralCoordinationError::InvalidInput)
    } else {
        Ok(value)
    }
}

#[async_trait]
pub trait EphemeralCoordinationStore: Send + Sync {
    async fn register_directory(
        &self,
        entry: DirectoryEntry,
        ttl: Duration,
    ) -> Result<DirectoryMutation, EphemeralCoordinationError>;
    async fn resolve_directory(
        &self,
        key: &DirectoryKey,
    ) -> Result<Option<DirectorySnapshot>, EphemeralCoordinationError>;
    async fn renew_directory(
        &self,
        snapshot: &DirectorySnapshot,
        ttl: Duration,
    ) -> Result<DirectoryMutation, EphemeralCoordinationError>;
    async fn remove_directory(
        &self,
        snapshot: &DirectorySnapshot,
    ) -> Result<DirectoryMutation, EphemeralCoordinationError>;
    async fn issue_one_time(
        &self,
        capability: OneTimeCapability,
        ttl: Duration,
    ) -> Result<OneTimeIssue, EphemeralCoordinationError>;
    async fn consume_one_time(
        &self,
        capability: &OneTimeCapability,
    ) -> Result<OneTimeConsume, EphemeralCoordinationError>;
}

impl fmt::Display for DirectoryKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}:{}", self.tenant_id, self.session_id)
    }
}
