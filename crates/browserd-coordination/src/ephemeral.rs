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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerReadiness {
    Ready,
    Draining,
    Unready,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct WorkerCapacity {
    memory_bytes: u64,
    cpu_millis: u64,
    pids: u64,
    disk_bytes: u64,
    contexts: u64,
    targets: u64,
}

impl WorkerCapacity {
    pub fn new(
        memory_bytes: u64,
        cpu_millis: u64,
        pids: u64,
        disk_bytes: u64,
        contexts: u64,
        targets: u64,
    ) -> Self {
        Self {
            memory_bytes,
            cpu_millis,
            pids,
            disk_bytes,
            contexts,
            targets,
        }
    }

    #[must_use]
    pub const fn fits_within(self, capacity: Self) -> bool {
        self.memory_bytes <= capacity.memory_bytes
            && self.cpu_millis <= capacity.cpu_millis
            && self.pids <= capacity.pids
            && self.disk_bytes <= capacity.disk_bytes
            && self.contexts <= capacity.contexts
            && self.targets <= capacity.targets
    }
    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.memory_bytes == 0
            && self.cpu_millis == 0
            && self.pids == 0
            && self.disk_bytes == 0
            && self.contexts == 0
            && self.targets == 0
    }
    pub(crate) fn checked_add(self, other: Self) -> Option<Self> {
        Some(Self {
            memory_bytes: self.memory_bytes.checked_add(other.memory_bytes)?,
            cpu_millis: self.cpu_millis.checked_add(other.cpu_millis)?,
            pids: self.pids.checked_add(other.pids)?,
            disk_bytes: self.disk_bytes.checked_add(other.disk_bytes)?,
            contexts: self.contexts.checked_add(other.contexts)?,
            targets: self.targets.checked_add(other.targets)?,
        })
    }
    pub(crate) fn checked_sub(self, other: Self) -> Option<Self> {
        Some(Self {
            memory_bytes: self.memory_bytes.checked_sub(other.memory_bytes)?,
            cpu_millis: self.cpu_millis.checked_sub(other.cpu_millis)?,
            pids: self.pids.checked_sub(other.pids)?,
            disk_bytes: self.disk_bytes.checked_sub(other.disk_bytes)?,
            contexts: self.contexts.checked_sub(other.contexts)?,
            targets: self.targets.checked_sub(other.targets)?,
        })
    }
    pub(crate) const fn components(self) -> [u64; 6] {
        [
            self.memory_bytes,
            self.cpu_millis,
            self.pids,
            self.disk_bytes,
            self.contexts,
            self.targets,
        ]
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerCapacityWire {
    memory_bytes: u64,
    cpu_millis: u64,
    pids: u64,
    disk_bytes: u64,
    contexts: u64,
    targets: u64,
}

impl<'de> Deserialize<'de> for WorkerCapacity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = WorkerCapacityWire::deserialize(deserializer)?;
        Ok(Self::new(
            value.memory_bytes,
            value.cpu_millis,
            value.pids,
            value.disk_bytes,
            value.contexts,
            value.targets,
        ))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WorkerRegistration {
    worker_id: WorkerId,
    worker_epoch: u64,
    region: String,
    release: String,
    compatibility: Vec<String>,
    capacity: WorkerCapacity,
    endpoint: String,
}

impl WorkerRegistration {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        worker_id: WorkerId,
        worker_epoch: u64,
        region: impl Into<String>,
        release: impl Into<String>,
        mut compatibility: Vec<String>,
        capacity: WorkerCapacity,
        endpoint: impl Into<String>,
    ) -> Result<Self, EphemeralCoordinationError> {
        let region = region.into();
        let release = release.into();
        let endpoint = endpoint.into();
        let valid_field = |value: &str, maximum: usize| {
            !value.is_empty()
                && value.len() <= maximum
                && value.trim() == value
                && !value.chars().any(char::is_control)
        };
        if worker_epoch == 0
            || capacity.is_zero()
            || !valid_field(&region, 255)
            || !valid_field(&release, 255)
            || !valid_field(&endpoint, 2_048)
            || compatibility.is_empty()
            || compatibility.len() > 128
            || compatibility.iter().any(|value| !valid_field(value, 1_024))
        {
            return Err(EphemeralCoordinationError::InvalidInput);
        }
        compatibility.sort();
        compatibility.dedup();
        Ok(Self {
            worker_id,
            worker_epoch,
            region,
            release,
            compatibility,
            capacity,
            endpoint,
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
    pub fn region(&self) -> &str {
        &self.region
    }
    #[must_use]
    pub fn compatibility(&self) -> &[String] {
        &self.compatibility
    }
    #[must_use]
    pub const fn capacity(&self) -> WorkerCapacity {
        self.capacity
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerRegistrationWire {
    worker_id: WorkerId,
    worker_epoch: u64,
    region: String,
    release: String,
    compatibility: Vec<String>,
    capacity: WorkerCapacity,
    endpoint: String,
}

impl<'de> Deserialize<'de> for WorkerRegistration {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = WorkerRegistrationWire::deserialize(deserializer)?;
        Self::new(
            value.worker_id,
            value.worker_epoch,
            value.region,
            value.release,
            value.compatibility,
            value.capacity,
            value.endpoint,
        )
        .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WorkerHeartbeat {
    free: WorkerCapacity,
    queue_depth: usize,
    active_shards: usize,
    readiness: WorkerReadiness,
}

impl WorkerHeartbeat {
    /// `free` is the worker's advertised free resources before coordination reservations.
    pub fn new(
        free: WorkerCapacity,
        queue_depth: usize,
        active_shards: usize,
        readiness: WorkerReadiness,
    ) -> Result<Self, EphemeralCoordinationError> {
        if queue_depth > 65_536 || active_shards > 65_536 {
            return Err(EphemeralCoordinationError::InvalidInput);
        }
        Ok(Self {
            free,
            queue_depth,
            active_shards,
            readiness,
        })
    }
    #[must_use]
    pub const fn free(&self) -> WorkerCapacity {
        self.free
    }
    #[must_use]
    pub const fn readiness(&self) -> WorkerReadiness {
        self.readiness
    }
    #[must_use]
    pub const fn queue_depth(&self) -> usize {
        self.queue_depth
    }
    #[must_use]
    pub const fn active_shards(&self) -> usize {
        self.active_shards
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerHeartbeatWire {
    free: WorkerCapacity,
    queue_depth: usize,
    active_shards: usize,
    readiness: WorkerReadiness,
}

impl<'de> Deserialize<'de> for WorkerHeartbeat {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = WorkerHeartbeatWire::deserialize(deserializer)?;
        Self::new(
            value.free,
            value.queue_depth,
            value.active_shards,
            value.readiness,
        )
        .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WorkerRegistrationSnapshot {
    registration: WorkerRegistration,
    heartbeat: WorkerHeartbeat,
    revision: u64,
    expires_at_millis: u64,
}

impl WorkerRegistrationSnapshot {
    pub fn from_persisted(
        registration: WorkerRegistration,
        heartbeat: WorkerHeartbeat,
        revision: u64,
        expires_at_millis: u64,
    ) -> Result<Self, EphemeralCoordinationError> {
        if revision == 0
            || expires_at_millis == 0
            || !heartbeat.free.fits_within(registration.capacity)
        {
            return Err(EphemeralCoordinationError::InvalidInput);
        }
        Ok(Self {
            registration,
            heartbeat,
            revision,
            expires_at_millis,
        })
    }
    #[must_use]
    pub const fn worker_epoch(&self) -> u64 {
        self.registration.worker_epoch
    }
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }
    #[must_use]
    pub const fn registration(&self) -> &WorkerRegistration {
        &self.registration
    }
    #[must_use]
    pub const fn heartbeat(&self) -> &WorkerHeartbeat {
        &self.heartbeat
    }
    #[must_use]
    pub const fn expires_at_millis(&self) -> u64 {
        self.expires_at_millis
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerRegistrationSnapshotWire {
    registration: WorkerRegistration,
    heartbeat: WorkerHeartbeat,
    revision: u64,
    expires_at_millis: u64,
}

impl<'de> Deserialize<'de> for WorkerRegistrationSnapshot {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = WorkerRegistrationSnapshotWire::deserialize(deserializer)?;
        Self::from_persisted(
            value.registration,
            value.heartbeat,
            value.revision,
            value.expires_at_millis,
        )
        .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkerLeaseMutation {
    Applied(Box<WorkerRegistrationSnapshot>),
    AlreadyApplied,
    FenceMismatch,
    CasMismatch,
    Expired,
}

impl WorkerLeaseMutation {
    pub fn into_snapshot(self) -> Result<WorkerRegistrationSnapshot, EphemeralCoordinationError> {
        match self {
            Self::Applied(snapshot) => Ok(*snapshot),
            _ => Err(EphemeralCoordinationError::InvalidResponse),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerRegistrationQuery {
    region: String,
    compatibility: String,
    limit: usize,
}

impl WorkerRegistrationQuery {
    pub fn new(
        region: impl Into<String>,
        compatibility: impl Into<String>,
        limit: usize,
    ) -> Result<Self, EphemeralCoordinationError> {
        let region = region.into();
        let compatibility = compatibility.into();
        if limit == 0
            || limit > 1_024
            || region.is_empty()
            || region.len() > 255
            || region.trim() != region
            || region.chars().any(char::is_control)
            || compatibility.is_empty()
            || compatibility.len() > 1_024
            || compatibility.trim() != compatibility
            || compatibility.chars().any(char::is_control)
        {
            return Err(EphemeralCoordinationError::InvalidInput);
        }
        Ok(Self {
            region,
            compatibility,
            limit,
        })
    }
    #[must_use]
    pub fn region(&self) -> &str {
        &self.region
    }
    #[must_use]
    pub fn compatibility(&self) -> &str {
        &self.compatibility
    }
    #[must_use]
    pub const fn limit(&self) -> usize {
        self.limit
    }
}

#[async_trait]
pub trait WorkerLeaseStore: Send + Sync {
    async fn register_worker(
        &self,
        registration: WorkerRegistration,
        heartbeat: WorkerHeartbeat,
        ttl: Duration,
    ) -> Result<WorkerLeaseMutation, EphemeralCoordinationError>;
    async fn heartbeat_worker(
        &self,
        expected: &WorkerRegistrationSnapshot,
        heartbeat: WorkerHeartbeat,
        ttl: Duration,
    ) -> Result<WorkerLeaseMutation, EphemeralCoordinationError>;
    async fn query_ready_workers(
        &self,
        query: &WorkerRegistrationQuery,
    ) -> Result<Vec<WorkerRegistrationSnapshot>, EphemeralCoordinationError>;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WorkerReservationRequest {
    operation_id: browserd_core::OperationId,
    tenant_id: TenantId,
    resources: WorkerCapacity,
}

impl WorkerReservationRequest {
    pub fn new(
        operation_id: browserd_core::OperationId,
        tenant_id: TenantId,
        resources: WorkerCapacity,
    ) -> Result<Self, EphemeralCoordinationError> {
        if resources.is_zero() {
            return Err(EphemeralCoordinationError::InvalidInput);
        }
        Ok(Self {
            operation_id,
            tenant_id,
            resources,
        })
    }
    #[must_use]
    pub const fn operation_id(&self) -> &browserd_core::OperationId {
        &self.operation_id
    }
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }
    #[must_use]
    pub const fn resources(&self) -> WorkerCapacity {
        self.resources
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerReservationRequestWire {
    operation_id: browserd_core::OperationId,
    tenant_id: TenantId,
    resources: WorkerCapacity,
}

impl<'de> Deserialize<'de> for WorkerReservationRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = WorkerReservationRequestWire::deserialize(deserializer)?;
        Self::new(value.operation_id, value.tenant_id, value.resources)
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WorkerReservationSnapshot {
    request: WorkerReservationRequest,
    worker: WorkerRegistrationSnapshot,
    expires_at_millis: u64,
}

impl WorkerReservationSnapshot {
    pub fn from_persisted(
        request: WorkerReservationRequest,
        worker: WorkerRegistrationSnapshot,
        expires_at_millis: u64,
    ) -> Result<Self, EphemeralCoordinationError> {
        if expires_at_millis == 0 {
            return Err(EphemeralCoordinationError::InvalidInput);
        }
        Ok(Self {
            request,
            worker,
            expires_at_millis,
        })
    }
    #[must_use]
    pub const fn operation_id(&self) -> &browserd_core::OperationId {
        self.request.operation_id()
    }
    #[must_use]
    pub const fn resources(&self) -> WorkerCapacity {
        self.request.resources()
    }
    #[must_use]
    pub const fn request(&self) -> &WorkerReservationRequest {
        &self.request
    }
    #[must_use]
    pub const fn worker_id(&self) -> &WorkerId {
        self.worker.registration().worker_id()
    }
    #[must_use]
    pub const fn worker_epoch(&self) -> u64 {
        self.worker.worker_epoch()
    }
    #[must_use]
    pub const fn worker_revision(&self) -> u64 {
        self.worker.revision()
    }
    #[must_use]
    pub const fn expires_at_millis(&self) -> u64 {
        self.expires_at_millis
    }
    #[must_use]
    pub const fn worker(&self) -> &WorkerRegistrationSnapshot {
        &self.worker
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerReservationSnapshotWire {
    request: WorkerReservationRequest,
    worker: WorkerRegistrationSnapshot,
    expires_at_millis: u64,
}

impl<'de> Deserialize<'de> for WorkerReservationSnapshot {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = WorkerReservationSnapshotWire::deserialize(deserializer)?;
        Self::from_persisted(value.request, value.worker, value.expires_at_millis)
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerReservationGrant {
    reservation: WorkerReservationSnapshot,
    worker: WorkerRegistrationSnapshot,
}

impl WorkerReservationGrant {
    pub(crate) const fn new(
        reservation: WorkerReservationSnapshot,
        worker: WorkerRegistrationSnapshot,
    ) -> Self {
        Self {
            reservation,
            worker,
        }
    }
    #[must_use]
    pub const fn reservation(&self) -> &WorkerReservationSnapshot {
        &self.reservation
    }
    #[must_use]
    pub const fn worker(&self) -> &WorkerRegistrationSnapshot {
        &self.worker
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkerReservationOutcome {
    Acquired(Box<WorkerReservationGrant>),
    Existing(Box<WorkerReservationGrant>),
    Conflict,
    FenceMismatch,
    CasMismatch,
    CapacityExhausted,
    WorkerUnavailable,
    Expired,
}

impl WorkerReservationOutcome {
    pub fn into_grant(self) -> Result<WorkerReservationGrant, EphemeralCoordinationError> {
        match self {
            Self::Acquired(grant) | Self::Existing(grant) => Ok(*grant),
            _ => Err(EphemeralCoordinationError::InvalidResponse),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkerReservationMutation {
    Released(Box<WorkerRegistrationSnapshot>),
    AlreadyReleased,
    FenceMismatch,
    CasMismatch,
    Expired,
}

impl WorkerReservationMutation {
    pub fn into_worker(self) -> Result<WorkerRegistrationSnapshot, EphemeralCoordinationError> {
        match self {
            Self::Released(worker) => Ok(*worker),
            _ => Err(EphemeralCoordinationError::InvalidResponse),
        }
    }
}

#[async_trait]
pub trait WorkerReservationStore: Send + Sync {
    async fn reserve_worker(
        &self,
        expected_worker: &WorkerRegistrationSnapshot,
        request: WorkerReservationRequest,
        ttl: Duration,
    ) -> Result<WorkerReservationOutcome, EphemeralCoordinationError>;
    async fn release_worker_reservation(
        &self,
        expected: &WorkerReservationSnapshot,
    ) -> Result<WorkerReservationMutation, EphemeralCoordinationError>;
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
