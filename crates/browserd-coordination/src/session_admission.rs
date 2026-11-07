//! Typed, immutable fleet admission policy and provider-independent transitions.

use std::io::{self, Write};
use std::time::Duration;

use browserd_core::{LeaseId, OperationId, PageId, PrincipalId, SessionId, TenantId, WorkerId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    DirectoryEntry, DirectoryFence, DirectoryKey, GatewayActionCoordinationError as Error,
    GatewayActionPlacement, WorkerCapacity, WorkerReadiness,
};

pub const MAX_SESSION_ADMISSION_SCAN: usize = 64;
pub const MAX_FLEET_WORKER_CANDIDATES: usize = 32;
pub const MAX_FLEET_CONFIG_BYTES: usize = 1024 * 1024;
pub(crate) const MAX_FLEET_TTL_MILLIS: u64 = 5 * 60 * 1000;

macro_rules! validated {
    ($name:ident { $($field:ident : $ty:ty),* $(,)? }) => {
        #[derive(Clone, Debug, Eq, PartialEq, Serialize)]
        pub struct $name { $(pub(crate) $field: $ty),* }
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self,D::Error> {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Wire { $($field: $ty),* }
                let wire = Wire::deserialize(d)?;
                let value = Self { $($field: wire.$field),* };
                value.validate().map_err(serde::de::Error::custom)?;
                Ok(value)
            }
        }
    };
}
macro_rules! getters {
    ($name:ident; refs {$($rf:ident:$rt:ty),* $(,)?} copies {$($cf:ident:$ct:ty),* $(,)?}) => {
        impl $name {
            $(#[must_use] pub const fn $rf(&self)->&$rt { &self.$rf })*
            $(#[must_use] pub const fn $cf(&self)->$ct { self.$cf })*
        }
    };
}

fn printable(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.trim() == value
        && !value.chars().any(char::is_control)
}
fn digest_valid(digest: &[u8; 32]) -> bool {
    *digest != [0; 32]
}
fn resources_valid(resources: WorkerCapacity) -> bool {
    resources.components()[4] > 0
}
pub(crate) fn millis(now: DateTime<Utc>) -> Result<u64, Error> {
    u64::try_from(now.timestamp_millis()).map_err(|_| Error::InvalidSessionAdmission)
}
pub(crate) fn ttl_millis(ttl: Duration) -> Result<u64, Error> {
    let value = u64::try_from(ttl.as_millis()).map_err(|_| Error::InvalidSessionAdmission)?;
    if value == 0 || value > MAX_FLEET_TTL_MILLIS {
        return Err(Error::InvalidSessionAdmission);
    }
    Ok(value)
}
pub(crate) fn deadline(now: u64, ttl: u64) -> Result<u64, Error> {
    now.checked_add(ttl).ok_or(Error::RevisionOverflow)
}
fn next(revision: u64) -> Result<u64, Error> {
    revision.checked_add(1).ok_or(Error::RevisionOverflow)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GatewaySessionIsolation {
    SharedContext,
    TenantDedicatedShard,
    DedicatedProcess,
    DedicatedWorker,
}
impl GatewaySessionIsolation {
    #[must_use]
    pub const fn satisfied_by(self, effective: Self) -> bool {
        (self as u8) <= (effective as u8)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GatewaySessionWorkload {
    Light,
    Interactive,
    Heavy,
}

validated!(GatewayFleetExclusiveTenant {
    tenant_id: TenantId,
    assignment_digest: [u8; 32]
});
impl GatewayFleetExclusiveTenant {
    pub fn new(tenant_id: TenantId, assignment_digest: [u8; 32]) -> Result<Self, Error> {
        let value = Self {
            tenant_id,
            assignment_digest,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<(), Error> {
        if digest_valid(&self.assignment_digest) {
            Ok(())
        } else {
            Err(Error::InvalidSessionAdmission)
        }
    }
}
getters!(GatewayFleetExclusiveTenant; refs {tenant_id:TenantId} copies {assignment_digest:[u8;32]});

validated!(GatewayFleetWorker { worker_id:WorkerId, endpoint:String, region:String,
    compatibility_digests:Vec<[u8;32]>,profile_digests:Vec<[u8;32]>,capacity_ceiling:WorkerCapacity,
    exclusive_tenant:Option<GatewayFleetExclusiveTenant> });
impl GatewayFleetWorker {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        worker_id: WorkerId,
        endpoint: impl Into<String>,
        region: impl Into<String>,
        mut compatibility_digests: Vec<[u8; 32]>,
        mut profile_digests: Vec<[u8; 32]>,
        capacity_ceiling: WorkerCapacity,
        exclusive_tenant: Option<GatewayFleetExclusiveTenant>,
    ) -> Result<Self, Error> {
        compatibility_digests.sort();
        profile_digests.sort();
        let value = Self {
            worker_id,
            endpoint: endpoint.into(),
            region: region.into(),
            compatibility_digests,
            profile_digests,
            capacity_ceiling,
            exclusive_tenant,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<(), Error> {
        if !printable(&self.endpoint, 2048)
            || !printable(&self.region, 255)
            || !resources_valid(self.capacity_ceiling)
            || !valid_digests(&self.compatibility_digests)
            || !valid_digests(&self.profile_digests)
        {
            return Err(Error::InvalidSessionAdmission);
        }
        if let Some(assignment) = &self.exclusive_tenant {
            assignment.validate()?;
        }
        Ok(())
    }
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }
    #[must_use]
    pub fn region(&self) -> &str {
        &self.region
    }
    #[must_use]
    pub fn compatibility_digests(&self) -> &[[u8; 32]] {
        &self.compatibility_digests
    }
    #[must_use]
    pub fn profile_digests(&self) -> &[[u8; 32]] {
        &self.profile_digests
    }
    #[must_use]
    pub fn exclusive_tenant(&self) -> Option<&GatewayFleetExclusiveTenant> {
        self.exclusive_tenant.as_ref()
    }
}
getters!(GatewayFleetWorker; refs {worker_id:WorkerId} copies {capacity_ceiling:WorkerCapacity});
fn valid_digests(values: &[[u8; 32]]) -> bool {
    !values.is_empty()
        && values.len() <= 32
        && values.iter().all(digest_valid)
        && values.windows(2).all(|pair| pair[0] < pair[1])
}

validated!(GatewayFleetProfile {
    profile_digest: [u8; 32],
    compatibility_digest: [u8; 32],
    isolation: GatewaySessionIsolation,
    workload: GatewaySessionWorkload,
    resources: WorkerCapacity,
    drr_cost: u16
});
impl GatewayFleetProfile {
    pub fn new(
        profile_digest: [u8; 32],
        compatibility_digest: [u8; 32],
        isolation: GatewaySessionIsolation,
        workload: GatewaySessionWorkload,
        resources: WorkerCapacity,
        drr_cost: u16,
    ) -> Result<Self, Error> {
        let value = Self {
            profile_digest,
            compatibility_digest,
            isolation,
            workload,
            resources,
            drr_cost,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<(), Error> {
        if !digest_valid(&self.profile_digest)
            || !digest_valid(&self.compatibility_digest)
            || !resources_valid(self.resources)
            || !(1..=64).contains(&self.drr_cost)
        {
            return Err(Error::InvalidSessionAdmission);
        }
        Ok(())
    }
}
getters!(GatewayFleetProfile; refs {} copies {profile_digest:[u8;32],compatibility_digest:[u8;32],isolation:GatewaySessionIsolation,workload:GatewaySessionWorkload,resources:WorkerCapacity,drr_cost:u16});

validated!(GatewayFleetTenantPolicy {
    weight: u16,
    resource_limit: WorkerCapacity,
    live_sessions: usize,
    queued_operations: usize,
    retained_operations: usize
});
impl GatewayFleetTenantPolicy {
    pub fn new(
        weight: u16,
        resource_limit: WorkerCapacity,
        live_sessions: usize,
        queued_operations: usize,
        retained_operations: usize,
    ) -> Result<Self, Error> {
        let value = Self {
            weight,
            resource_limit,
            live_sessions,
            queued_operations,
            retained_operations,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<(), Error> {
        if !(1..=16).contains(&self.weight)
            || !resources_valid(self.resource_limit)
            || self.live_sessions == 0
            || self.queued_operations == 0
            || self.retained_operations == 0
            || self.retained_operations > 1_048_576
            || self.live_sessions > self.retained_operations
            || self.queued_operations > self.retained_operations
        {
            return Err(Error::InvalidSessionAdmission);
        }
        Ok(())
    }
}
getters!(GatewayFleetTenantPolicy; refs {} copies {weight:u16,resource_limit:WorkerCapacity,live_sessions:usize,queued_operations:usize,retained_operations:usize});
validated!(GatewayFleetTenantRule {
    tenant_id: TenantId,
    policy: GatewayFleetTenantPolicy
});
impl GatewayFleetTenantRule {
    pub fn new(tenant_id: TenantId, policy: GatewayFleetTenantPolicy) -> Result<Self, Error> {
        let value = Self { tenant_id, policy };
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<(), Error> {
        self.policy.validate()
    }
}
getters!(GatewayFleetTenantRule; refs {tenant_id:TenantId,policy:GatewayFleetTenantPolicy} copies {});
validated!(GatewayFleetAdmissionLimits {
    namespace_records: usize,
    namespace_queued: usize,
    namespace_live: usize,
    queued_tenants: usize,
    fleet_resource_limit: WorkerCapacity
});
impl GatewayFleetAdmissionLimits {
    pub fn new(
        namespace_records: usize,
        namespace_queued: usize,
        namespace_live: usize,
        queued_tenants: usize,
        fleet_resource_limit: WorkerCapacity,
    ) -> Result<Self, Error> {
        let value = Self {
            namespace_records,
            namespace_queued,
            namespace_live,
            queued_tenants,
            fleet_resource_limit,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<(), Error> {
        if self.namespace_records == 0
            || self.namespace_records > 1_048_576
            || self.namespace_queued == 0
            || self.namespace_queued > self.namespace_records
            || self.namespace_live == 0
            || self.namespace_live > self.namespace_records
            || self.queued_tenants == 0
            || self.queued_tenants > 1024
            || !resources_valid(self.fleet_resource_limit)
        {
            return Err(Error::InvalidSessionAdmission);
        }
        Ok(())
    }
}
getters!(GatewayFleetAdmissionLimits; refs {} copies {namespace_records:usize,namespace_queued:usize,namespace_live:usize,queued_tenants:usize,fleet_resource_limit:WorkerCapacity});

validated!(GatewayFleetAdmissionConfig {region:String,workers:Vec<GatewayFleetWorker>,profiles:Vec<GatewayFleetProfile>,
    default_tenant_policy:GatewayFleetTenantPolicy,tenant_overrides:Vec<GatewayFleetTenantRule>,limits:GatewayFleetAdmissionLimits});
impl GatewayFleetAdmissionConfig {
    pub fn new(
        region: impl Into<String>,
        mut workers: Vec<GatewayFleetWorker>,
        mut profiles: Vec<GatewayFleetProfile>,
        default_tenant_policy: GatewayFleetTenantPolicy,
        mut tenant_overrides: Vec<GatewayFleetTenantRule>,
        limits: GatewayFleetAdmissionLimits,
    ) -> Result<Self, Error> {
        workers.sort_by(|a, b| a.worker_id.cmp(&b.worker_id));
        profiles.sort_by_key(|p| p.profile_digest);
        tenant_overrides.sort_by(|a, b| a.tenant_id.cmp(&b.tenant_id));
        let value = Self {
            region: region.into(),
            workers,
            profiles,
            default_tenant_policy,
            tenant_overrides,
            limits,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<(), Error> {
        self.limits.validate()?;
        self.default_tenant_policy.validate()?;
        if !printable(&self.region, 255)
            || self.workers.is_empty()
            || self.workers.len() > 256
            || self.profiles.is_empty()
            || self.profiles.len() > 128
            || self.tenant_overrides.len() > 1024
            || !self
                .workers
                .windows(2)
                .all(|w| w[0].worker_id < w[1].worker_id)
            || !self
                .profiles
                .windows(2)
                .all(|w| w[0].profile_digest < w[1].profile_digest)
            || !self
                .tenant_overrides
                .windows(2)
                .all(|w| w[0].tenant_id < w[1].tenant_id)
        {
            return Err(Error::InvalidSessionAdmission);
        }
        for worker in &self.workers {
            worker.validate()?;
            if worker.region != self.region {
                return Err(Error::InvalidSessionAdmission);
            }
        }
        for profile in &self.profiles {
            profile.validate()?;
            if !profile
                .resources
                .fits_within(self.limits.fleet_resource_limit)
                || !self.workers.iter().any(|w| {
                    w.profile_digests.contains(&profile.profile_digest)
                        && w.compatibility_digests
                            .contains(&profile.compatibility_digest)
                })
            {
                return Err(Error::InvalidSessionAdmission);
            }
        }
        for policy in std::iter::once(&self.default_tenant_policy)
            .chain(self.tenant_overrides.iter().map(|rule| &rule.policy))
        {
            policy.validate()?;
            if !policy
                .resource_limit
                .fits_within(self.limits.fleet_resource_limit)
                || policy.live_sessions > self.limits.namespace_live
                || policy.queued_operations > self.limits.namespace_queued
                || policy.retained_operations > self.limits.namespace_records
            {
                return Err(Error::InvalidSessionAdmission);
            }
        }
        let mut writer = BoundedCount { count: 0 };
        serde_json::to_writer(&mut writer, self).map_err(|_| Error::InvalidSessionAdmission)?;
        Ok(())
    }
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(b"browserd:fleet-admission-config:v1\0");
        // Configuration has already passed the fixed encoded-byte bound.
        let mut writer = HashWriter(&mut digest);
        let _ = serde_json::to_writer(&mut writer, self);
        digest.finalize().into()
    }
    #[must_use]
    pub fn region(&self) -> &str {
        &self.region
    }
    #[must_use]
    pub fn workers(&self) -> &[GatewayFleetWorker] {
        &self.workers
    }
    #[must_use]
    pub fn profiles(&self) -> &[GatewayFleetProfile] {
        &self.profiles
    }
    #[must_use]
    pub fn limits(&self) -> &GatewayFleetAdmissionLimits {
        &self.limits
    }
    #[must_use]
    pub fn tenant_policy(&self, tenant: &TenantId) -> &GatewayFleetTenantPolicy {
        self.tenant_overrides
            .binary_search_by(|rule| rule.tenant_id.cmp(tenant))
            .map_or(&self.default_tenant_policy, |index| {
                &self.tenant_overrides[index].policy
            })
    }
    pub(crate) fn worker(&self, id: &WorkerId) -> Result<&GatewayFleetWorker, Error> {
        self.workers
            .binary_search_by(|w| w.worker_id.cmp(id))
            .map(|index| &self.workers[index])
            .map_err(|_| Error::InvalidFleetObservation)
    }
    pub(crate) fn profile(
        &self,
        request: &GatewaySessionAdmissionRequest,
    ) -> Result<&GatewayFleetProfile, Error> {
        let profile = self
            .profiles
            .binary_search_by_key(&request.profile_digest, |p| p.profile_digest)
            .map(|index| &self.profiles[index])
            .map_err(|_| Error::InvalidSessionAdmission)?;
        if profile.compatibility_digest != request.compatibility_digest
            || profile.isolation != request.isolation
            || profile.resources != request.resources
        {
            return Err(Error::InvalidSessionAdmission);
        }
        Ok(profile)
    }
}
struct BoundedCount {
    count: usize,
}
impl Write for BoundedCount {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let count = self
            .count
            .checked_add(bytes.len())
            .filter(|v| *v <= MAX_FLEET_CONFIG_BYTES)
            .ok_or_else(|| io::Error::other("fleet config bound"))?;
        self.count = count;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
struct HashWriter<'a>(&'a mut Sha256);
impl Write for HashWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewaySessionAdmissionKey {
    pub(crate) tenant_id: TenantId,
    pub(crate) operation_id: OperationId,
}
impl GatewaySessionAdmissionKey {
    #[must_use]
    pub const fn new(tenant_id: TenantId, operation_id: OperationId) -> Self {
        Self {
            tenant_id,
            operation_id,
        }
    }
}
getters!(GatewaySessionAdmissionKey; refs {tenant_id:TenantId,operation_id:OperationId} copies {});
validated!(GatewaySessionAdmissionRequest {schema_version:u8,key:GatewaySessionAdmissionKey,principal_id:PrincipalId,canonical_request_hash:[u8;32],profile_digest:[u8;32],
    compatibility_digest:[u8;32],isolation:GatewaySessionIsolation,resources:WorkerCapacity,accepted_at:DateTime<Utc>,admission_deadline:DateTime<Utc>});
impl GatewaySessionAdmissionRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        key: GatewaySessionAdmissionKey,
        principal_id: PrincipalId,
        canonical_request_hash: [u8; 32],
        profile_digest: [u8; 32],
        compatibility_digest: [u8; 32],
        isolation: GatewaySessionIsolation,
        resources: WorkerCapacity,
        accepted_at: DateTime<Utc>,
        admission_deadline: DateTime<Utc>,
    ) -> Result<Self, Error> {
        let value = Self {
            schema_version: 1,
            key,
            principal_id,
            canonical_request_hash,
            profile_digest,
            compatibility_digest,
            isolation,
            resources,
            accepted_at,
            admission_deadline,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<(), Error> {
        if self.schema_version != 1
            || !digest_valid(&self.canonical_request_hash)
            || !digest_valid(&self.profile_digest)
            || !digest_valid(&self.compatibility_digest)
            || !resources_valid(self.resources)
            || millis(self.accepted_at)? >= millis(self.admission_deadline)?
        {
            return Err(Error::InvalidSessionAdmission);
        }
        Ok(())
    }
}
getters!(GatewaySessionAdmissionRequest; refs {key:GatewaySessionAdmissionKey,principal_id:PrincipalId} copies {schema_version:u8,canonical_request_hash:[u8;32],profile_digest:[u8;32],compatibility_digest:[u8;32],isolation:GatewaySessionIsolation,resources:WorkerCapacity,accepted_at:DateTime<Utc>,admission_deadline:DateTime<Utc>});

validated!(GatewayFleetWorkerIdentity {
    worker_id: WorkerId,
    worker_epoch: u64,
    boot_id: LeaseId
});
impl GatewayFleetWorkerIdentity {
    pub fn new(worker_id: WorkerId, worker_epoch: u64, boot_id: LeaseId) -> Result<Self, Error> {
        let value = Self {
            worker_id,
            worker_epoch,
            boot_id,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<(), Error> {
        if self.worker_epoch == 0 {
            Err(Error::InvalidFleetObservation)
        } else {
            Ok(())
        }
    }
}
getters!(GatewayFleetWorkerIdentity; refs {worker_id:WorkerId,boot_id:LeaseId} copies {worker_epoch:u64});
validated!(GatewayFleetWorkerObservation {identity:GatewayFleetWorkerIdentity,capacity_revision:u64,debit_sequence_watermark:u64,capacity:WorkerCapacity,raw_free:WorkerCapacity,
    readiness:WorkerReadiness,compatibility_digest:[u8;32],exclusive_tenant:Option<GatewayFleetExclusiveTenant>});
impl GatewayFleetWorkerObservation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        identity: GatewayFleetWorkerIdentity,
        capacity_revision: u64,
        debit_sequence_watermark: u64,
        capacity: WorkerCapacity,
        raw_free: WorkerCapacity,
        readiness: WorkerReadiness,
        compatibility_digest: [u8; 32],
        exclusive_tenant: Option<GatewayFleetExclusiveTenant>,
    ) -> Result<Self, Error> {
        let value = Self {
            identity,
            capacity_revision,
            debit_sequence_watermark,
            capacity,
            raw_free,
            readiness,
            compatibility_digest,
            exclusive_tenant,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<(), Error> {
        self.identity.validate()?;
        if self.capacity_revision == 0
            || !resources_valid(self.capacity)
            || !self.raw_free.fits_within(self.capacity)
            || !digest_valid(&self.compatibility_digest)
        {
            return Err(Error::InvalidFleetObservation);
        }
        if let Some(assignment) = &self.exclusive_tenant {
            assignment.validate()?;
        }
        Ok(())
    }
    pub(crate) fn validate_config(
        &self,
        config: &GatewayFleetAdmissionConfig,
    ) -> Result<(), Error> {
        self.validate()?;
        let worker = config.worker(&self.identity.worker_id)?;
        if !self.capacity.fits_within(worker.capacity_ceiling)
            || !worker
                .compatibility_digests
                .contains(&self.compatibility_digest)
            || self.exclusive_tenant != worker.exclusive_tenant
        {
            return Err(Error::InvalidFleetObservation);
        }
        Ok(())
    }
    #[must_use]
    pub fn exclusive_tenant(&self) -> Option<&GatewayFleetExclusiveTenant> {
        self.exclusive_tenant.as_ref()
    }
}
getters!(GatewayFleetWorkerObservation; refs {identity:GatewayFleetWorkerIdentity} copies {capacity_revision:u64,debit_sequence_watermark:u64,capacity:WorkerCapacity,raw_free:WorkerCapacity,readiness:WorkerReadiness,compatibility_digest:[u8;32]});

validated!(GatewaySessionReservation {reservation_id:LeaseId,generation:u64,key:GatewaySessionAdmissionKey,worker:GatewayFleetWorkerIdentity,canonical_request_hash:[u8;32],profile_digest:[u8;32],compatibility_digest:[u8;32],resources:WorkerCapacity,directory_fence:DirectoryFence,requested_ttl_millis:u64,
    provider_deadline_millis:u64,worker_reservation_nonce:Option<LeaseId>,worker_debit_sequence:Option<u64>,worker_capacity_revision:Option<u64>});
impl GatewaySessionReservation {
    pub fn validate(&self) -> Result<(), Error> {
        self.worker.validate()?;
        if self.generation == 0
            || self.directory_fence.worker_id() != &self.worker.worker_id
            || self.directory_fence.worker_epoch() != self.worker.worker_epoch
            || self.requested_ttl_millis == 0
            || self.requested_ttl_millis > MAX_FLEET_TTL_MILLIS
            || self.provider_deadline_millis == 0
            || !digest_valid(&self.canonical_request_hash)
            || !digest_valid(&self.profile_digest)
            || !digest_valid(&self.compatibility_digest)
            || !resources_valid(self.resources)
            || (self.worker_reservation_nonce.is_some() != self.worker_debit_sequence.is_some())
            || (self.worker_reservation_nonce.is_some() != self.worker_capacity_revision.is_some())
            || self.worker_debit_sequence == Some(0)
            || self.worker_capacity_revision == Some(0)
        {
            return Err(Error::InvalidSessionAdmission);
        }
        Ok(())
    }
    pub(crate) fn same_basis(&self, other: &Self) -> bool {
        self.reservation_id == other.reservation_id
            && self.generation == other.generation
            && self.key == other.key
            && self.worker == other.worker
            && self.canonical_request_hash == other.canonical_request_hash
            && self.profile_digest == other.profile_digest
            && self.compatibility_digest == other.compatibility_digest
            && self.resources == other.resources
            && self.directory_fence == other.directory_fence
            && self.requested_ttl_millis == other.requested_ttl_millis
            && self.provider_deadline_millis == other.provider_deadline_millis
    }
    #[must_use]
    pub fn worker_reservation_nonce(&self) -> Option<&LeaseId> {
        self.worker_reservation_nonce.as_ref()
    }
}
getters!(GatewaySessionReservation; refs {reservation_id:LeaseId,key:GatewaySessionAdmissionKey,worker:GatewayFleetWorkerIdentity,directory_fence:DirectoryFence} copies {generation:u64,canonical_request_hash:[u8;32],profile_digest:[u8;32],compatibility_digest:[u8;32],resources:WorkerCapacity,requested_ttl_millis:u64,provider_deadline_millis:u64,worker_debit_sequence:Option<u64>,worker_capacity_revision:Option<u64>});

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GatewaySessionAdmissionState {
    Queued,
    Reserved,
    CommitArmed,
    Active,
    Closing,
    Released,
    Expired,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GatewaySessionPlacementStatus {
    Ready,
    Closing,
    Lost,
}
validated!(GatewaySessionAuthorityRef {
    key: DirectoryKey,
    authority_revision: u64,
    directory_fence: DirectoryFence,
    worker_boot_id: LeaseId
});
impl GatewaySessionAuthorityRef {
    pub fn validate(&self) -> Result<(), Error> {
        if self.authority_revision == 0 {
            return Err(Error::InvalidSessionAdmission);
        }
        Ok(())
    }
    pub fn action_placement(&self) -> Result<GatewayActionPlacement, Error> {
        GatewayActionPlacement::new(self.directory_fence.clone(), self.authority_revision)
    }
}
getters!(GatewaySessionAuthorityRef; refs {key:DirectoryKey,directory_fence:DirectoryFence,worker_boot_id:LeaseId} copies {authority_revision:u64});
validated!(GatewaySessionRenewalIntent {
    authority: GatewaySessionAuthorityRef,
    expected_lease_revision: u64,
    renewal_nonce: LeaseId,
    requested_ttl_millis: u64,
    anchored_expires_at_millis: u64
});
impl GatewaySessionRenewalIntent {
    pub fn validate(&self) -> Result<(), Error> {
        self.authority.validate()?;
        if self.expected_lease_revision == 0
            || self.requested_ttl_millis == 0
            || self.requested_ttl_millis > MAX_FLEET_TTL_MILLIS
            || self.anchored_expires_at_millis == 0
        {
            return Err(Error::InvalidSessionAdmission);
        }
        Ok(())
    }
}
getters!(GatewaySessionRenewalIntent; refs {authority:GatewaySessionAuthorityRef,renewal_nonce:LeaseId} copies {expected_lease_revision:u64,requested_ttl_millis:u64,anchored_expires_at_millis:u64});
validated!(GatewaySessionPlacementAuthority {entry:DirectoryEntry,admission_key:GatewaySessionAdmissionKey,authority:GatewaySessionAuthorityRef,lease_revision:u64,expires_at_millis:u64,status:GatewaySessionPlacementStatus,renewal:Option<GatewaySessionRenewalIntent>,completed_renewal:Option<GatewaySessionRenewalIntent>});
impl GatewaySessionPlacementAuthority {
    pub fn validate(&self) -> Result<(), Error> {
        self.authority.validate()?;
        if self.entry.key() != &self.authority.key
            || self.admission_key.tenant_id() != self.entry.key().tenant_id()
            || self.entry.fence() != &self.authority.directory_fence
            || self.lease_revision == 0
            || self.expires_at_millis == 0
        {
            return Err(Error::InvalidSessionAdmission);
        }
        for intent in self.renewal.iter().chain(self.completed_renewal.iter()) {
            intent.validate()?;
            if intent.authority != self.authority {
                return Err(Error::InvalidSessionAdmission);
            }
        }
        Ok(())
    }
    #[must_use]
    pub fn renewal(&self) -> Option<&GatewaySessionRenewalIntent> {
        self.renewal.as_ref()
    }
}

/// A bounded candidate, loaded once by either provider's scheduling pass.
pub(crate) struct FleetWorkerCandidate<'a> {
    pub observation: &'a GatewayFleetWorkerObservation,
    pub expires_at_millis: u64,
    pub shadow: WorkerCapacity,
}
pub(crate) fn eligible_worker(
    config: &GatewayFleetAdmissionConfig,
    request: &GatewaySessionAdmissionRequest,
    candidate: &FleetWorkerCandidate<'_>,
    now: u64,
) -> Result<bool, Error> {
    config.profile(request)?;
    let observation = candidate.observation;
    observation.validate_config(config)?;
    let worker = config.worker(&observation.identity.worker_id)?;
    if candidate.expires_at_millis <= now
        || observation.readiness != WorkerReadiness::Ready
        || observation.compatibility_digest != request.compatibility_digest
        || !worker.profile_digests.contains(&request.profile_digest)
        || worker
            .exclusive_tenant
            .as_ref()
            .is_some_and(|a| a.tenant_id != request.key.tenant_id)
        || (request.isolation == GatewaySessionIsolation::DedicatedWorker
            && worker
                .exclusive_tenant
                .as_ref()
                .is_none_or(|a| a.tenant_id != request.key.tenant_id))
    {
        return Ok(false);
    }
    let Some(free) = observation.raw_free.checked_sub(candidate.shadow) else {
        return Ok(false);
    };
    Ok(request.resources.fits_within(free))
}
/// Compare the bottleneck free/capacity ratio after unacknowledged shadow debits.
/// Candidates must first pass `eligible_worker`; larger headroom wins, exact ties stay equal.
pub(crate) fn compare_worker_headroom(
    left: &FleetWorkerCandidate<'_>,
    right: &FleetWorkerCandidate<'_>,
) -> Result<std::cmp::Ordering, Error> {
    fn minimum(candidate: &FleetWorkerCandidate<'_>) -> Result<(u64, u64), Error> {
        candidate.observation.validate()?;
        let available = candidate
            .observation
            .raw_free
            .checked_sub(candidate.shadow)
            .ok_or(Error::InvalidFleetObservation)?;
        let mut ratio: Option<(u64, u64)> = None;
        for (free, capacity) in available
            .components()
            .into_iter()
            .zip(candidate.observation.capacity.components())
        {
            if capacity == 0 {
                continue;
            }
            if ratio.is_none_or(|(numerator, denominator)| {
                u128::from(free) * u128::from(denominator)
                    < u128::from(numerator) * u128::from(capacity)
            }) {
                ratio = Some((free, capacity));
            }
        }
        ratio.ok_or(Error::InvalidFleetObservation)
    }
    let (left_free, left_capacity) = minimum(left)?;
    let (right_free, right_capacity) = minimum(right)?;
    Ok((u128::from(left_free) * u128::from(right_capacity))
        .cmp(&(u128::from(right_free) * u128::from(left_capacity))))
}

#[cfg(test)]
mod headroom_tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use std::cmp::Ordering;

    fn observation(
        capacity: WorkerCapacity,
        free: WorkerCapacity,
    ) -> GatewayFleetWorkerObservation {
        GatewayFleetWorkerObservation::new(
            GatewayFleetWorkerIdentity::new(
                WorkerId::new("headroom-test-worker").unwrap(),
                1,
                LeaseId::new(),
            )
            .unwrap(),
            1,
            0,
            capacity,
            free,
            WorkerReadiness::Ready,
            [2; 32],
            None,
        )
        .unwrap()
    }

    fn compare(
        left: &GatewayFleetWorkerObservation,
        right: &GatewayFleetWorkerObservation,
        shadow: WorkerCapacity,
    ) -> Result<Ordering, Error> {
        compare_worker_headroom(
            &FleetWorkerCandidate {
                observation: left,
                expires_at_millis: 1,
                shadow,
            },
            &FleetWorkerCandidate {
                observation: right,
                expires_at_millis: 1,
                shadow: WorkerCapacity::default(),
            },
        )
    }

    #[test]
    fn normalized_bottleneck_ignores_zero_dimensions_and_checks_shadow() {
        let left = observation(
            WorkerCapacity::new(0, 8, 0, 0, 8, 0),
            WorkerCapacity::new(0, 6, 0, 0, 8, 0),
        );
        let right = observation(
            WorkerCapacity::new(0, 8, 0, 0, 8, 0),
            WorkerCapacity::new(0, 8, 0, 0, 5, 0),
        );
        assert_eq!(
            compare(&left, &right, WorkerCapacity::default()).unwrap(),
            Ordering::Greater
        );
        assert_eq!(
            compare(&left, &right, WorkerCapacity::new(0, 1, 0, 0, 0, 0)).unwrap(),
            Ordering::Equal
        );
        assert_eq!(
            compare(&left, &right, WorkerCapacity::new(0, 7, 0, 0, 0, 0)).unwrap_err(),
            Error::InvalidFleetObservation
        );
    }

    #[test]
    fn one_unit_headroom_difference_near_u64_max_remains_exact() {
        let maximum = u64::MAX;
        let left = observation(
            WorkerCapacity::new(0, 0, 0, 0, maximum, 0),
            WorkerCapacity::new(0, 0, 0, 0, maximum - 1, 0),
        );
        let right = observation(
            WorkerCapacity::new(0, 0, 0, 0, maximum, 0),
            WorkerCapacity::new(0, 0, 0, 0, maximum - 2, 0),
        );
        assert_eq!(
            compare(&left, &right, WorkerCapacity::default()).unwrap(),
            Ordering::Greater
        );
        assert_eq!(
            compare(&left, &right, WorkerCapacity::new(0, 0, 0, 0, 1, 0)).unwrap(),
            Ordering::Equal
        );
    }
}
getters!(GatewaySessionPlacementAuthority; refs {entry:DirectoryEntry,admission_key:GatewaySessionAdmissionKey,authority:GatewaySessionAuthorityRef} copies {lease_revision:u64,expires_at_millis:u64,status:GatewaySessionPlacementStatus});

validated!(GatewaySessionRestoredCheckpoint {
    checkpoint_ref: String,
    source_session_id: SessionId
});
impl GatewaySessionRestoredCheckpoint {
    pub fn new(
        checkpoint_ref: impl Into<String>,
        source_session_id: SessionId,
    ) -> Result<Self, Error> {
        let value = Self {
            checkpoint_ref: checkpoint_ref.into(),
            source_session_id,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<(), Error> {
        let id =
            Uuid::parse_str(&self.checkpoint_ref).map_err(|_| Error::InvalidSessionAdmission)?;
        if id.get_version() != Some(uuid::Version::Random) || id.to_string() != self.checkpoint_ref
        {
            return Err(Error::InvalidSessionAdmission);
        }
        Ok(())
    }
    #[must_use]
    pub fn checkpoint_ref(&self) -> &str {
        &self.checkpoint_ref
    }
}
getters!(GatewaySessionRestoredCheckpoint; refs {source_session_id:SessionId} copies {});

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewaySessionWorkerReservationProof {
    pub reservation: GatewaySessionReservation,
    pub worker_reservation_nonce: LeaseId,
    pub remaining_ttl_millis: u64,
    pub capacity_revision: u64,
    pub debit_sequence: u64,
}
impl GatewaySessionWorkerReservationProof {
    pub fn validate(&self) -> Result<(), Error> {
        self.reservation.validate()?;
        if self.remaining_ttl_millis == 0
            || self.remaining_ttl_millis > MAX_FLEET_TTL_MILLIS
            || self.capacity_revision == 0
            || self.debit_sequence == 0
        {
            return Err(Error::InvalidSessionAdmission);
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewaySessionWorkerReadyProof {
    pub reservation: GatewaySessionReservation,
    pub entry: DirectoryEntry,
    pub primary_page_id: PageId,
    pub effective_isolation: GatewaySessionIsolation,
    pub remaining_ownership_ttl_millis: u64,
    pub capacity_revision: u64,
    pub debit_sequence: u64,
    #[serde(default)]
    pub restored_checkpoint: Option<GatewaySessionRestoredCheckpoint>,
}
impl GatewaySessionWorkerReadyProof {
    pub fn validate(&self) -> Result<(), Error> {
        self.reservation.validate()?;
        let fence = self.entry.fence();
        if self.reservation.worker_reservation_nonce.is_none()
            || self.remaining_ownership_ttl_millis == 0
            || self.capacity_revision == 0
            || self.reservation.worker_debit_sequence != Some(self.debit_sequence)
            || fence != &self.reservation.directory_fence
            || self.entry.key().tenant_id() != &self.reservation.key.tenant_id
        {
            return Err(Error::InvalidSessionAdmission);
        }
        if let Some(checkpoint) = &self.restored_checkpoint {
            checkpoint.validate()?;
        }
        Ok(())
    }
    pub(crate) fn same_identity(&self, other: &Self) -> bool {
        self.reservation == other.reservation
            && self.entry == other.entry
            && self.primary_page_id == other.primary_page_id
            && self.effective_isolation == other.effective_isolation
            && self.debit_sequence == other.debit_sequence
            && self.restored_checkpoint == other.restored_checkpoint
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewaySessionWorkerRenewalProof {
    pub authority: GatewaySessionAuthorityRef,
    pub worker: GatewayFleetWorkerIdentity,
    pub renewal_nonce: LeaseId,
    pub granted_ttl_millis: u64,
}
impl GatewaySessionWorkerRenewalProof {
    pub fn validate(&self) -> Result<(), Error> {
        self.authority.validate()?;
        self.worker.validate()?;
        if self.granted_ttl_millis == 0
            || self.worker.worker_id != *self.authority.directory_fence.worker_id()
            || self.worker.worker_epoch != self.authority.directory_fence.worker_epoch()
            || self.worker.boot_id != self.authority.worker_boot_id
        {
            return Err(Error::InvalidSessionAdmission);
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum GatewaySessionCleanupProof {
    NoEffectCancelled {
        reservation: GatewaySessionReservation,
        capacity_revision: u64,
    },
    ContextDisposed {
        reservation: GatewaySessionReservation,
        entry: DirectoryEntry,
        capacity_revision: u64,
    },
}
impl GatewaySessionCleanupProof {
    pub fn validate(&self) -> Result<(), Error> {
        self.reservation().validate()?;
        let revision = match self {
            Self::NoEffectCancelled {
                capacity_revision, ..
            }
            | Self::ContextDisposed {
                capacity_revision, ..
            } => *capacity_revision,
        };
        if revision == 0 {
            return Err(Error::InvalidSessionAdmission);
        }
        Ok(())
    }
    #[must_use]
    pub fn reservation(&self) -> &GatewaySessionReservation {
        match self {
            Self::NoEffectCancelled { reservation, .. }
            | Self::ContextDisposed { reservation, .. } => reservation,
        }
    }
}

validated!(GatewaySessionAdmissionSnapshot {request:GatewaySessionAdmissionRequest,revision:u64,queue_sequence:u64,state:GatewaySessionAdmissionState,reservation:Option<GatewaySessionReservation>,placement:Option<GatewaySessionPlacementAuthority>,pending_create_projection:bool,
    generation:u64,dispatch_lease:Option<Uuid>,activation_ttl_millis:Option<u64>,activation_deadline_millis:Option<u64>,ready_proof:Option<Box<GatewaySessionWorkerReadyProof>>,cleanup_proof:Option<Box<GatewaySessionCleanupProof>>});
impl GatewaySessionAdmissionSnapshot {
    pub fn validate(&self) -> Result<(), Error> {
        self.request.validate()?;
        if self.revision == 0
            || self.queue_sequence == 0
            || self
                .dispatch_lease
                .is_some_and(|id| id.get_version() != Some(uuid::Version::Random))
            || self
                .activation_ttl_millis
                .is_some_and(|ttl| ttl == 0 || ttl > MAX_FLEET_TTL_MILLIS)
            || self.activation_ttl_millis.is_some() != self.activation_deadline_millis.is_some()
        {
            return Err(Error::InvalidSessionAdmission);
        }
        if let Some(res) = &self.reservation {
            res.validate()?;
            if res.key != self.request.key
                || res.canonical_request_hash != self.request.canonical_request_hash
                || res.profile_digest != self.request.profile_digest
                || res.compatibility_digest != self.request.compatibility_digest
                || res.resources != self.request.resources
                || res.generation != self.generation
            {
                return Err(Error::InvalidSessionAdmission);
            }
        }
        if let Some(place) = &self.placement {
            place.validate()?;
            if place.entry.key().tenant_id() != &self.request.key.tenant_id
                || place.admission_key != self.request.key
            {
                return Err(Error::InvalidSessionAdmission);
            }
        }
        if let Some(proof) = &self.ready_proof {
            proof.validate()?;
            if self.reservation.as_ref() != Some(&proof.reservation)
                || self
                    .placement
                    .as_ref()
                    .is_none_or(|p| p.entry != proof.entry)
            {
                return Err(Error::InvalidSessionAdmission);
            }
        }
        match self.state {
            GatewaySessionAdmissionState::Queued => {
                if self.reservation.is_some()
                    || self.placement.is_some()
                    || self.ready_proof.is_some()
                    || self.pending_create_projection
                    || self.dispatch_lease.is_some()
                    || self.activation_ttl_millis.is_some()
                {
                    return Err(Error::InvalidSessionAdmission);
                }
            }
            GatewaySessionAdmissionState::Expired => {
                if self.placement.is_some()
                    || self.ready_proof.is_some()
                    || self.pending_create_projection
                {
                    return Err(Error::InvalidSessionAdmission);
                }
            }
            GatewaySessionAdmissionState::Reserved => {
                if self.reservation.is_none()
                    || self.placement.is_some()
                    || self.dispatch_lease.is_some()
                    || self.ready_proof.is_some()
                    || self.pending_create_projection
                    || self.activation_ttl_millis.is_some()
                {
                    return Err(Error::InvalidSessionAdmission);
                }
            }
            GatewaySessionAdmissionState::CommitArmed => {
                if self
                    .reservation
                    .as_ref()
                    .is_none_or(|r| r.worker_reservation_nonce.is_none())
                    || self.dispatch_lease.is_none()
                    || self.activation_ttl_millis.is_none()
                    || self.activation_deadline_millis.is_none()
                    || self.placement.is_some()
                    || self.ready_proof.is_some()
                    || self.pending_create_projection
                {
                    return Err(Error::InvalidSessionAdmission);
                }
            }
            GatewaySessionAdmissionState::Active | GatewaySessionAdmissionState::Closing => {
                if self.ready_proof.is_none() || self.placement.is_none() {
                    return Err(Error::InvalidSessionAdmission);
                }
            }
            GatewaySessionAdmissionState::Released => {
                if self.reservation.is_none() {
                    return Err(Error::InvalidSessionAdmission);
                }
            }
        }
        Ok(())
    }
    pub(crate) fn queued(
        request: GatewaySessionAdmissionRequest,
        queue_sequence: u64,
    ) -> Result<Self, Error> {
        let value = Self {
            request,
            revision: 1,
            queue_sequence,
            state: GatewaySessionAdmissionState::Queued,
            reservation: None,
            placement: None,
            pending_create_projection: false,
            generation: 0,
            dispatch_lease: None,
            activation_ttl_millis: None,
            activation_deadline_millis: None,
            ready_proof: None,
            cleanup_proof: None,
        };
        value.validate()?;
        Ok(value)
    }
    pub(crate) fn check_expected(&self, expected: &Self) -> Result<(), Error> {
        if self != expected {
            return Err(Error::AdmissionRevisionMismatch);
        }
        Ok(())
    }
    pub(crate) fn reserve(
        &self,
        worker: GatewayFleetWorkerIdentity,
        now: u64,
        ttl: u64,
    ) -> Result<Self, Error> {
        if self.state != GatewaySessionAdmissionState::Queued
            || millis(self.request.admission_deadline)? <= now
        {
            return Err(Error::AdmissionConflict);
        }
        let mut value = self.clone();
        value.revision = next(self.revision)?;
        value.generation = next(self.generation)?;
        value.state = GatewaySessionAdmissionState::Reserved;
        value.cleanup_proof = None;
        value.reservation = Some(GatewaySessionReservation {
            reservation_id: LeaseId::new(),
            generation: value.generation,
            key: self.request.key.clone(),
            directory_fence: DirectoryFence::new(
                worker.worker_id.clone(),
                worker.worker_epoch,
                1,
                1,
            )
            .map_err(|_| Error::InvalidSessionAdmission)?,
            worker,
            canonical_request_hash: self.request.canonical_request_hash,
            profile_digest: self.request.profile_digest,
            compatibility_digest: self.request.compatibility_digest,
            resources: self.request.resources,
            requested_ttl_millis: ttl,
            provider_deadline_millis: deadline(now, ttl)?
                .min(millis(self.request.admission_deadline)?),
            worker_reservation_nonce: None,
            worker_debit_sequence: None,
            worker_capacity_revision: None,
        });
        value.validate()?;
        Ok(value)
    }
    pub(crate) fn record_reservation(
        &self,
        expected: &Self,
        proof: &GatewaySessionWorkerReservationProof,
        now: u64,
    ) -> Result<Self, Error> {
        proof.validate()?;
        let res = self.reservation.as_ref().ok_or(Error::AdmissionConflict)?;
        if !res.same_basis(&proof.reservation) {
            return Err(Error::AdmissionConflict);
        }
        if let Some(nonce) = &res.worker_reservation_nonce {
            if nonce == &proof.worker_reservation_nonce
                && res.worker_debit_sequence == Some(proof.debit_sequence)
            {
                return Ok(self.clone());
            }
            return Err(Error::AdmissionConflict);
        }
        self.check_expected(expected)?;
        if self.state != GatewaySessionAdmissionState::Reserved
            || res.provider_deadline_millis <= now
        {
            return Err(Error::AdmissionConflict);
        }
        let mut value = self.clone();
        value.revision = next(self.revision)?;
        let res = value.reservation.as_mut().ok_or(Error::CorruptState)?;
        res.worker_reservation_nonce = Some(proof.worker_reservation_nonce.clone());
        res.worker_debit_sequence = Some(proof.debit_sequence);
        res.worker_capacity_revision = Some(proof.capacity_revision);
        value.validate()?;
        Ok(value)
    }
    pub(crate) fn arm(
        &self,
        expected: &Self,
        dispatch_lease: Uuid,
        now: u64,
        ttl: u64,
    ) -> Result<Self, Error> {
        if self.state == GatewaySessionAdmissionState::CommitArmed
            && self.dispatch_lease == Some(dispatch_lease)
            && self.request == expected.request
            && self.reservation == expected.reservation
        {
            return Ok(self.clone());
        }
        self.check_expected(expected)?;
        let res = self.reservation.as_ref().ok_or(Error::AdmissionConflict)?;
        if self.state != GatewaySessionAdmissionState::Reserved
            || res.worker_reservation_nonce.is_none()
            || res.provider_deadline_millis <= now
        {
            return Err(Error::AdmissionConflict);
        }
        let mut value = self.clone();
        value.revision = next(self.revision)?;
        value.state = GatewaySessionAdmissionState::CommitArmed;
        value.dispatch_lease = Some(dispatch_lease);
        value.activation_ttl_millis = Some(ttl);
        value.activation_deadline_millis =
            Some(deadline(now, ttl)?.min(res.provider_deadline_millis));
        value.validate()?;
        Ok(value)
    }
    pub(crate) fn commit(
        &self,
        expected: &Self,
        proof: &GatewaySessionWorkerReadyProof,
        authority_revision: u64,
        now: u64,
        config: &GatewayFleetAdmissionConfig,
    ) -> Result<Self, Error> {
        proof.validate()?;
        if self
            .ready_proof
            .as_ref()
            .is_some_and(|stored| stored.same_identity(proof))
        {
            return Ok(self.clone());
        }
        self.check_expected(expected)?;
        if self.state == GatewaySessionAdmissionState::CommitArmed
            && self.reservation.as_ref() == Some(&proof.reservation)
            && self
                .activation_deadline_millis
                .is_some_and(|deadline| deadline <= now)
        {
            return Err(Error::SessionActivationExpired);
        }
        if self.state != GatewaySessionAdmissionState::CommitArmed
            || self.reservation.as_ref() != Some(&proof.reservation)
            || !self
                .request
                .isolation
                .satisfied_by(proof.effective_isolation)
            || self.activation_deadline_millis.is_none_or(|at| at <= now)
            || self
                .activation_ttl_millis
                .is_none_or(|ttl| proof.remaining_ownership_ttl_millis < ttl)
            || proof.entry.endpoint()
                != config.worker(&proof.reservation.worker.worker_id)?.endpoint
        {
            return Err(Error::AdmissionConflict);
        }
        if proof.effective_isolation == GatewaySessionIsolation::DedicatedWorker
            && config
                .worker(&proof.reservation.worker.worker_id)?
                .exclusive_tenant
                .as_ref()
                .is_none_or(|a| a.tenant_id != self.request.key.tenant_id)
        {
            return Err(Error::AdmissionConflict);
        }
        let authority = GatewaySessionAuthorityRef {
            key: proof.entry.key().clone(),
            authority_revision,
            directory_fence: proof.entry.fence().clone(),
            worker_boot_id: proof.reservation.worker.boot_id.clone(),
        };
        let mut value = self.clone();
        value.revision = next(self.revision)?;
        value.state = GatewaySessionAdmissionState::Active;
        value.pending_create_projection = true;
        value.ready_proof = Some(Box::new(proof.clone()));
        value.placement = Some(GatewaySessionPlacementAuthority {
            entry: proof.entry.clone(),
            admission_key: self.request.key.clone(),
            authority,
            lease_revision: 1,
            expires_at_millis: self.activation_deadline_millis.ok_or(Error::CorruptState)?,
            status: GatewaySessionPlacementStatus::Ready,
            renewal: None,
            completed_renewal: None,
        });
        value.validate()?;
        Ok(value)
    }
    #[must_use]
    pub fn reservation(&self) -> Option<&GatewaySessionReservation> {
        self.reservation.as_ref()
    }
    #[must_use]
    pub fn placement(&self) -> Option<&GatewaySessionPlacementAuthority> {
        self.placement.as_ref()
    }
    #[must_use]
    pub fn ready_proof(&self) -> Option<&GatewaySessionWorkerReadyProof> {
        self.ready_proof.as_deref()
    }
}
getters!(GatewaySessionAdmissionSnapshot; refs {request:GatewaySessionAdmissionRequest} copies {revision:u64,queue_sequence:u64,state:GatewaySessionAdmissionState,pending_create_projection:bool,generation:u64});

validated!(GatewaySessionAdmissionCursor {schema_version:u8,after:Option<(TenantId,OperationId)>});
impl Default for GatewaySessionAdmissionCursor {
    fn default() -> Self {
        Self {
            schema_version: 1,
            after: None,
        }
    }
}
impl GatewaySessionAdmissionCursor {
    pub fn validate(&self) -> Result<(), Error> {
        if self.schema_version != 1 {
            Err(Error::InvalidSessionAdmission)
        } else {
            Ok(())
        }
    }
    pub(crate) fn after(key: &GatewaySessionAdmissionKey) -> Self {
        Self {
            schema_version: 1,
            after: Some((key.tenant_id.clone(), key.operation_id.clone())),
        }
    }
}
validated!(GatewaySessionAdmissionPage {admissions:Vec<GatewaySessionAdmissionSnapshot>,next_cursor:GatewaySessionAdmissionCursor,complete:bool,examined:usize});
impl GatewaySessionAdmissionPage {
    pub(crate) fn new(
        admissions: Vec<GatewaySessionAdmissionSnapshot>,
        next_cursor: GatewaySessionAdmissionCursor,
        complete: bool,
        examined: usize,
    ) -> Result<Self, Error> {
        let value = Self {
            admissions,
            next_cursor,
            complete,
            examined,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<(), Error> {
        self.next_cursor.validate()?;
        if self.examined > MAX_SESSION_ADMISSION_SCAN || self.admissions.len() > self.examined {
            return Err(Error::InvalidSessionAdmission);
        }
        for item in &self.admissions {
            item.validate()?;
        }
        Ok(())
    }
    #[must_use]
    pub fn admissions(&self) -> &[GatewaySessionAdmissionSnapshot] {
        &self.admissions
    }
    #[must_use]
    pub const fn next_cursor(&self) -> &GatewaySessionAdmissionCursor {
        &self.next_cursor
    }
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.complete
    }
    #[must_use]
    pub const fn examined(&self) -> usize {
        self.examined
    }
}

/// Fast, nonreentrant provider time; the backend persists a nondecreasing floor.
pub trait GatewayFleetAdmissionClock: Send + Sync {
    fn now(&self) -> DateTime<Utc>;
}

impl GatewaySessionAdmissionSnapshot {
    pub(crate) fn expire(&self, now: u64) -> Result<Self, Error> {
        let due = match self.state {
            GatewaySessionAdmissionState::Queued => millis(self.request.admission_deadline)?,
            GatewaySessionAdmissionState::Reserved => {
                self.reservation
                    .as_ref()
                    .ok_or(Error::CorruptState)?
                    .provider_deadline_millis
            }
            _ => return Err(Error::AdmissionConflict),
        };
        if due > now {
            return Err(Error::AdmissionConflict);
        }
        let mut value = self.clone();
        value.revision = next(self.revision)?;
        value.state = GatewaySessionAdmissionState::Expired;
        value.validate()?;
        Ok(value)
    }
    pub(crate) fn release(
        &self,
        expected: &Self,
        proof: &GatewaySessionCleanupProof,
        now: u64,
    ) -> Result<Self, Error> {
        proof.validate()?;
        if self
            .cleanup_proof
            .as_ref()
            .is_some_and(|stored| same_cleanup(stored, proof))
            && self.generation == proof.reservation().generation
        {
            return Ok(self.clone());
        }
        self.check_expected(expected)?;
        let res = self.reservation.as_ref().ok_or(Error::AdmissionConflict)?;
        if res != proof.reservation() {
            return Err(Error::AdmissionConflict);
        }
        let mut value = self.clone();
        value.revision = next(self.revision)?;
        value.cleanup_proof = Some(Box::new(proof.clone()));
        match proof {
            GatewaySessionCleanupProof::NoEffectCancelled { .. } => {
                if !matches!(
                    self.state,
                    GatewaySessionAdmissionState::Reserved
                        | GatewaySessionAdmissionState::CommitArmed
                ) {
                    return Err(Error::AdmissionConflict);
                }
                value.state = if millis(self.request.admission_deadline)? > now {
                    GatewaySessionAdmissionState::Queued
                } else {
                    GatewaySessionAdmissionState::Expired
                };
                value.reservation = None;
                value.dispatch_lease = None;
                value.activation_ttl_millis = None;
                value.activation_deadline_millis = None;
            }
            GatewaySessionCleanupProof::ContextDisposed { entry, .. } => {
                if !matches!(
                    self.state,
                    GatewaySessionAdmissionState::CommitArmed
                        | GatewaySessionAdmissionState::Active
                        | GatewaySessionAdmissionState::Closing
                ) || entry.key().tenant_id() != &self.request.key.tenant_id
                    || entry.fence() != &res.directory_fence
                    || self.placement.as_ref().is_some_and(|p| p.entry != *entry)
                {
                    return Err(Error::AdmissionConflict);
                }
                value.state = GatewaySessionAdmissionState::Released;
                if let Some(place) = value.placement.as_mut() {
                    place.status = GatewaySessionPlacementStatus::Lost;
                    place.renewal = None;
                    place.lease_revision = next(place.lease_revision)?;
                }
            }
        }
        value.validate()?;
        Ok(value)
    }
    pub(crate) fn ack_projection(&self, expected: &Self) -> Result<Self, Error> {
        if self.request != expected.request
            || self.reservation != expected.reservation
            || self
                .ready_proof
                .as_ref()
                .zip(expected.ready_proof.as_ref())
                .is_none_or(|(a, b)| !a.same_identity(b))
        {
            return Err(Error::AdmissionConflict);
        }
        if !self.pending_create_projection {
            return Ok(self.clone());
        }
        self.check_expected(expected)?;
        let mut value = self.clone();
        value.revision = next(value.revision)?;
        value.pending_create_projection = false;
        value.validate()?;
        Ok(value)
    }
}
fn same_cleanup(a: &GatewaySessionCleanupProof, b: &GatewaySessionCleanupProof) -> bool {
    match (a, b) {
        (
            GatewaySessionCleanupProof::NoEffectCancelled { reservation: a, .. },
            GatewaySessionCleanupProof::NoEffectCancelled { reservation: b, .. },
        ) => a == b,
        (
            GatewaySessionCleanupProof::ContextDisposed {
                reservation: a,
                entry: ae,
                ..
            },
            GatewaySessionCleanupProof::ContextDisposed {
                reservation: b,
                entry: be,
                ..
            },
        ) => a == b && ae == be,
        _ => false,
    }
}
impl GatewaySessionPlacementAuthority {
    pub(crate) fn begin_renewal(
        &self,
        expected: &Self,
        nonce: LeaseId,
        now: u64,
        ttl: u64,
    ) -> Result<(Self, GatewaySessionRenewalIntent), Error> {
        if let Some(intent) = self.renewal.as_ref().or(self.completed_renewal.as_ref())
            && intent.renewal_nonce == nonce
            && self.authority == expected.authority
        {
            if intent.requested_ttl_millis != ttl {
                return Err(Error::AdmissionConflict);
            }
            return Ok((self.clone(), intent.clone()));
        }
        if self != expected {
            return Err(Error::AdmissionRevisionMismatch);
        }
        if self.status != GatewaySessionPlacementStatus::Ready
            || self.expires_at_millis <= now
            || self.renewal.is_some()
        {
            return Err(Error::SessionAuthorityUnavailable);
        }
        let intent = GatewaySessionRenewalIntent {
            authority: self.authority.clone(),
            expected_lease_revision: self.lease_revision,
            renewal_nonce: nonce,
            requested_ttl_millis: ttl,
            anchored_expires_at_millis: deadline(now, ttl)?,
        };
        intent.validate()?;
        let mut value = self.clone();
        value.renewal = Some(intent.clone());
        value.validate()?;
        Ok((value, intent))
    }
    pub(crate) fn finish_renewal(
        &self,
        intent: &GatewaySessionRenewalIntent,
        proof: &GatewaySessionWorkerRenewalProof,
        now: u64,
    ) -> Result<Self, Error> {
        intent.validate()?;
        proof.validate()?;
        if proof.authority != intent.authority
            || proof.renewal_nonce != intent.renewal_nonce
            || proof.granted_ttl_millis < intent.requested_ttl_millis
        {
            return Err(Error::AdmissionConflict);
        }
        if self.completed_renewal.as_ref() == Some(intent) {
            return Ok(self.clone());
        }
        if self.renewal.as_ref() != Some(intent)
            || self.authority != intent.authority
            || self.lease_revision != intent.expected_lease_revision
            || self.status != GatewaySessionPlacementStatus::Ready
            || self.expires_at_millis <= now
            || intent.anchored_expires_at_millis <= now
        {
            return Err(Error::SessionAuthorityUnavailable);
        }
        let mut value = self.clone();
        value.lease_revision = next(self.lease_revision)?;
        value.expires_at_millis = intent.anchored_expires_at_millis;
        value.renewal = None;
        value.completed_renewal = Some(intent.clone());
        value.validate()?;
        Ok(value)
    }
    pub(crate) fn close(&self, expected: &Self) -> Result<Self, Error> {
        if self.authority != expected.authority {
            return Err(Error::AdmissionConflict);
        }
        if self.status == GatewaySessionPlacementStatus::Closing {
            return Ok(self.clone());
        }
        if self != expected {
            return Err(Error::AdmissionRevisionMismatch);
        }
        if self.status != GatewaySessionPlacementStatus::Ready {
            return Err(Error::AdmissionConflict);
        }
        let mut value = self.clone();
        value.lease_revision = next(self.lease_revision)?;
        value.status = GatewaySessionPlacementStatus::Closing;
        value.renewal = None;
        value.validate()?;
        Ok(value)
    }
}
