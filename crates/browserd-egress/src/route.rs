use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use browserd_core::{LeaseId, SessionId, ShardId, TenantId};
use tokio_util::sync::CancellationToken;

use crate::{
    CanonicalUrl, ConnectPlan, ConnectionId, ConnectionPlanner, DnsResolution, EgressPolicy,
    MonotonicMillis, PlanError, QuotaError, QuotaLedger, QuotaLimits, QuotaUsage,
};

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RouteEndpoint(u64);

impl RouteEndpoint {
    pub const fn new(value: u64) -> Result<Self, RouteError> {
        if value == 0 {
            Err(RouteError::InvalidEndpoint)
        } else {
            Ok(Self(value))
        }
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Debug)]
pub struct RouteBinding {
    tenant_id: TenantId,
    session_id: SessionId,
    shard_id: ShardId,
    worker_epoch: u64,
    policy: EgressPolicy,
    quota_limits: QuotaLimits,
    expires_at: MonotonicMillis,
}

impl RouteBinding {
    #[must_use]
    pub const fn new(
        tenant_id: TenantId,
        session_id: SessionId,
        shard_id: ShardId,
        worker_epoch: u64,
        policy: EgressPolicy,
        quota_limits: QuotaLimits,
        expires_at: MonotonicMillis,
    ) -> Self {
        Self {
            tenant_id,
            session_id,
            shard_id,
            worker_epoch,
            policy,
            quota_limits,
            expires_at,
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
    pub const fn shard_id(&self) -> &ShardId {
        &self.shard_id
    }

    #[must_use]
    pub const fn worker_epoch(&self) -> u64 {
        self.worker_epoch
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteIdentity {
    tenant_id: TenantId,
    session_id: SessionId,
    shard_id: ShardId,
    worker_epoch: u64,
    expires_at: MonotonicMillis,
}

impl RouteIdentity {
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    #[must_use]
    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    #[must_use]
    pub const fn shard_id(&self) -> &ShardId {
        &self.shard_id
    }

    #[must_use]
    pub const fn worker_epoch(&self) -> u64 {
        self.worker_epoch
    }

    #[must_use]
    pub const fn expires_at(&self) -> MonotonicMillis {
        self.expires_at
    }
}

impl From<&RouteEntry> for RouteIdentity {
    fn from(entry: &RouteEntry) -> Self {
        Self {
            tenant_id: entry.tenant_id.clone(),
            session_id: entry.session_id.clone(),
            shard_id: entry.shard_id.clone(),
            worker_epoch: entry.worker_epoch,
            expires_at: entry.expires_at,
        }
    }
}

#[derive(Debug)]
struct RouteEntry {
    incarnation: LeaseId,
    tenant_id: TenantId,
    session_id: SessionId,
    shard_id: ShardId,
    worker_epoch: u64,
    expires_at: MonotonicMillis,
    planner: ConnectionPlanner,
    quota: QuotaLedger,
    cancellation: CancellationToken,
}

#[derive(Clone, Debug)]
struct RetiredRoute {
    shard_id: ShardId,
    worker_epoch: u64,
}

#[derive(Debug)]
struct ShardRoutes {
    worker_epoch: u64,
    revoked: bool,
    endpoints: HashSet<RouteEndpoint>,
    cancellation: CancellationToken,
}

#[derive(Debug, Default)]
struct RouteState {
    active: HashMap<RouteEndpoint, RouteEntry>,
    retired: HashMap<RouteEndpoint, RetiredRoute>,
    shards: HashMap<ShardId, ShardRoutes>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RouteRegistryLimits {
    max_tracked_routes: usize,
    max_tracked_shards: usize,
}

impl RouteRegistryLimits {
    #[must_use]
    pub const fn new(max_tracked_routes: usize, max_tracked_shards: usize) -> Self {
        Self {
            max_tracked_routes,
            max_tracked_shards,
        }
    }

    #[must_use]
    pub const fn max_tracked_routes(self) -> usize {
        self.max_tracked_routes
    }

    #[must_use]
    pub const fn max_tracked_shards(self) -> usize {
        self.max_tracked_shards
    }

    const fn is_valid(self) -> bool {
        self.max_tracked_routes > 0 && self.max_tracked_shards > 0
    }
}

impl Default for RouteRegistryLimits {
    fn default() -> Self {
        Self::new(65_536, 4_096)
    }
}

#[derive(Clone, Debug)]
pub struct RouteRegistry {
    max_lease_millis: Option<u64>,
    limits: RouteRegistryLimits,
    state: Arc<Mutex<RouteState>>,
}

impl RouteRegistry {
    #[must_use]
    pub fn new(max_lease: Duration) -> Self {
        Self::with_limits(max_lease, RouteRegistryLimits::default())
    }

    #[must_use]
    pub fn with_limits(max_lease: Duration, limits: RouteRegistryLimits) -> Self {
        let millis = max_lease.as_millis();
        Self {
            max_lease_millis: (millis > 0 && millis <= u128::from(u64::MAX))
                .then(|| u64::try_from(millis).ok())
                .flatten(),
            limits,
            state: Arc::new(Mutex::new(RouteState::default())),
        }
    }

    pub fn bind(
        &self,
        endpoint: RouteEndpoint,
        binding: RouteBinding,
        now: MonotonicMillis,
    ) -> Result<RouteIdentity, RouteError> {
        if binding.worker_epoch == 0 {
            return Err(RouteError::InvalidWorkerEpoch);
        }
        if !self.limits.is_valid() {
            return Err(RouteError::InvalidRegistryConfig);
        }
        self.validate_expiry(now, binding.expires_at)?;
        let mut state = self.lock_state();
        if state.retired.contains_key(&endpoint) {
            return Err(RouteError::EndpointRetired);
        }
        if state.active.contains_key(&endpoint) {
            return Err(RouteError::EndpointAlreadyBound);
        }
        if state.active.len().saturating_add(state.retired.len()) >= self.limits.max_tracked_routes
        {
            return Err(RouteError::RouteCapacityExceeded);
        }
        let shard_is_new = !state.shards.contains_key(&binding.shard_id);
        if shard_is_new && state.shards.len() >= self.limits.max_tracked_shards {
            return Err(RouteError::ShardCapacityExceeded);
        }
        if let Some(shard) = state.shards.get(&binding.shard_id) {
            if shard.worker_epoch != binding.worker_epoch {
                if !shard.revoked || binding.worker_epoch < shard.worker_epoch {
                    return Err(RouteError::WorkerEpochMismatch {
                        expected: shard.worker_epoch,
                        actual: binding.worker_epoch,
                    });
                }
            } else if shard.revoked {
                return Err(RouteError::ShardRevoked);
            }
        }

        let shard = state
            .shards
            .entry(binding.shard_id.clone())
            .or_insert_with(|| ShardRoutes {
                worker_epoch: binding.worker_epoch,
                revoked: false,
                endpoints: HashSet::new(),
                cancellation: CancellationToken::new(),
            });
        if shard.worker_epoch != binding.worker_epoch {
            shard.worker_epoch = binding.worker_epoch;
            shard.revoked = false;
            shard.cancellation = CancellationToken::new();
        }
        let cancellation = shard.cancellation.child_token();
        shard.endpoints.insert(endpoint);
        let entry = RouteEntry {
            incarnation: LeaseId::new(),
            tenant_id: binding.tenant_id,
            session_id: binding.session_id,
            shard_id: binding.shard_id,
            worker_epoch: binding.worker_epoch,
            expires_at: binding.expires_at,
            planner: ConnectionPlanner::new(binding.policy),
            quota: QuotaLedger::new(binding.quota_limits),
            cancellation,
        };
        let identity = RouteIdentity::from(&entry);
        state.active.insert(endpoint, entry);
        Ok(identity)
    }

    pub fn binding(
        &self,
        endpoint: RouteEndpoint,
        source_shard: &ShardId,
        now: MonotonicMillis,
    ) -> Result<RouteIdentity, RouteError> {
        let mut state = self.lock_state();
        let entry = Self::active_entry(&mut state, endpoint, now)?;
        if &entry.shard_id != source_shard {
            return Err(RouteError::SourceShardMismatch);
        }
        Ok(RouteIdentity::from(&*entry))
    }

    pub fn renew(
        &self,
        endpoint: RouteEndpoint,
        source_shard: &ShardId,
        worker_epoch: u64,
        now: MonotonicMillis,
        new_expires_at: MonotonicMillis,
    ) -> Result<(), RouteError> {
        self.validate_expiry(now, new_expires_at)?;
        let mut state = self.lock_state();
        let entry = Self::active_entry(&mut state, endpoint, now)?;
        if &entry.shard_id != source_shard {
            return Err(RouteError::SourceShardMismatch);
        }
        if entry.worker_epoch != worker_epoch {
            return Err(RouteError::WorkerEpochMismatch {
                expected: entry.worker_epoch,
                actual: worker_epoch,
            });
        }
        entry.expires_at = new_expires_at;
        Ok(())
    }

    pub fn revoke(
        &self,
        endpoint: RouteEndpoint,
        source_shard: &ShardId,
        worker_epoch: u64,
    ) -> Result<(), RouteError> {
        let mut state = self.lock_state();
        if let Some(retired) = state.retired.get(&endpoint) {
            if &retired.shard_id != source_shard {
                return Err(RouteError::SourceShardMismatch);
            }
            if retired.worker_epoch != worker_epoch {
                return Err(RouteError::WorkerEpochMismatch {
                    expected: retired.worker_epoch,
                    actual: worker_epoch,
                });
            }
            return Ok(());
        }
        let entry = state
            .active
            .get(&endpoint)
            .ok_or(RouteError::RouteNotFound)?;
        if &entry.shard_id != source_shard {
            return Err(RouteError::SourceShardMismatch);
        }
        if entry.worker_epoch != worker_epoch {
            return Err(RouteError::WorkerEpochMismatch {
                expected: entry.worker_epoch,
                actual: worker_epoch,
            });
        }
        Self::retire_route(&mut state, endpoint);
        Ok(())
    }

    pub fn revoke_shard(
        &self,
        source_shard: &ShardId,
        worker_epoch: u64,
    ) -> Result<usize, RouteError> {
        let mut state = self.lock_state();
        let endpoints = {
            let shard = state
                .shards
                .get(source_shard)
                .ok_or(RouteError::RouteNotFound)?;
            if shard.worker_epoch != worker_epoch {
                return Err(RouteError::WorkerEpochMismatch {
                    expected: shard.worker_epoch,
                    actual: worker_epoch,
                });
            }
            if shard.revoked {
                return Ok(0);
            }
            shard.endpoints.iter().copied().collect::<Vec<_>>()
        };

        for endpoint in &endpoints {
            let entry = state
                .active
                .get(endpoint)
                .ok_or(RouteError::InconsistentRegistryState)?;
            if &entry.shard_id != source_shard || entry.worker_epoch != worker_epoch {
                return Err(RouteError::InconsistentRegistryState);
            }
        }

        if let Some(shard) = state.shards.get(source_shard) {
            shard.cancellation.cancel();
        }
        for endpoint in &endpoints {
            Self::retire_route(&mut state, *endpoint);
        }
        if let Some(shard) = state.shards.get_mut(source_shard) {
            shard.revoked = true;
        }
        Ok(endpoints.len())
    }

    pub fn begin_connection(
        &self,
        endpoint: RouteEndpoint,
        source_shard: &ShardId,
        url: &CanonicalUrl,
        resolution: DnsResolution,
        now: MonotonicMillis,
    ) -> Result<RoutePermit, RouteError> {
        self.authorize_dns(endpoint, source_shard, url, now)?
            .finish(resolution, now)
    }

    pub fn authorize_dns(
        &self,
        endpoint: RouteEndpoint,
        source_shard: &ShardId,
        url: &CanonicalUrl,
        now: MonotonicMillis,
    ) -> Result<PreDnsPermit, RouteError> {
        let mut state = self.lock_state();
        let entry = Self::active_entry(&mut state, endpoint, now)?;
        if &entry.shard_id != source_shard {
            return Err(RouteError::SourceShardMismatch);
        }
        entry.planner.authorize(url).map_err(RouteError::Plan)?;
        entry
            .quota
            .record_dns_query(now)
            .map_err(RouteError::Quota)?;
        Ok(PreDnsPermit {
            registry: self.clone(),
            endpoint,
            incarnation: entry.incarnation.clone(),
            url: url.clone(),
            cancellation: entry.cancellation.clone(),
        })
    }

    pub fn expire_routes(&self, now: MonotonicMillis) -> usize {
        let mut state = self.lock_state();
        let expired = state
            .active
            .iter()
            .filter_map(|(endpoint, entry)| (entry.expires_at <= now).then_some(*endpoint))
            .collect::<Vec<_>>();
        for endpoint in &expired {
            Self::retire_route(&mut state, *endpoint);
        }
        expired.len()
    }

    #[must_use]
    pub fn usage(&self, endpoint: RouteEndpoint) -> QuotaUsage {
        self.lock_state()
            .active
            .get(&endpoint)
            .map_or_else(QuotaUsage::default, |entry| entry.quota.usage())
    }

    fn record_egress_bytes(
        &self,
        endpoint: RouteEndpoint,
        incarnation: &LeaseId,
        connection_id: ConnectionId,
        bytes: u64,
        now: MonotonicMillis,
    ) -> Result<(), RouteError> {
        let mut state = self.lock_state();
        let entry = Self::active_entry(&mut state, endpoint, now)?;
        if &entry.incarnation != incarnation {
            return Err(RouteError::RouteRevoked);
        }
        entry
            .quota
            .record_egress(connection_id, bytes, now)
            .map_err(RouteError::Quota)
    }

    fn close_connection(
        &self,
        endpoint: RouteEndpoint,
        incarnation: &LeaseId,
        connection_id: ConnectionId,
    ) {
        let mut state = self.lock_state();
        if let Some(entry) = state.active.get_mut(&endpoint)
            && &entry.incarnation == incarnation
        {
            entry.quota.close_connection(connection_id);
        }
    }

    fn validate_expiry(
        &self,
        now: MonotonicMillis,
        expires_at: MonotonicMillis,
    ) -> Result<(), RouteError> {
        let Some(max_lease_millis) = self.max_lease_millis else {
            return Err(RouteError::InvalidRegistryConfig);
        };
        if expires_at <= now
            || expires_at > MonotonicMillis::new(now.value().saturating_add(max_lease_millis))
        {
            return Err(RouteError::InvalidLeaseExpiry);
        }
        Ok(())
    }

    fn retire_route(state: &mut RouteState, endpoint: RouteEndpoint) {
        let Some(entry) = state.active.remove(&endpoint) else {
            return;
        };
        entry.cancellation.cancel();
        if let Some(shard) = state.shards.get_mut(&entry.shard_id)
            && shard.worker_epoch == entry.worker_epoch
        {
            shard.endpoints.remove(&endpoint);
        }
        state.retired.insert(
            endpoint,
            RetiredRoute {
                shard_id: entry.shard_id,
                worker_epoch: entry.worker_epoch,
            },
        );
    }

    fn active_entry(
        state: &mut RouteState,
        endpoint: RouteEndpoint,
        now: MonotonicMillis,
    ) -> Result<&mut RouteEntry, RouteError> {
        let expired = state
            .active
            .get(&endpoint)
            .is_some_and(|entry| entry.expires_at <= now);
        if expired {
            Self::retire_route(state, endpoint);
            return Err(RouteError::RouteExpired);
        }
        state.active.get_mut(&endpoint).ok_or_else(|| {
            if state.retired.contains_key(&endpoint) {
                RouteError::RouteRevoked
            } else {
                RouteError::RouteNotFound
            }
        })
    }

    fn lock_state(&self) -> MutexGuard<'_, RouteState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[derive(Debug)]
pub struct PreDnsPermit {
    registry: RouteRegistry,
    endpoint: RouteEndpoint,
    incarnation: LeaseId,
    url: CanonicalUrl,
    cancellation: CancellationToken,
}

impl PreDnsPermit {
    #[must_use]
    pub fn cancellation_token(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    pub fn finish(
        self,
        resolution: DnsResolution,
        now: MonotonicMillis,
    ) -> Result<RoutePermit, RouteError> {
        let mut state = self.registry.lock_state();
        let entry = RouteRegistry::active_entry(&mut state, self.endpoint, now)?;
        if entry.incarnation != self.incarnation {
            return Err(RouteError::RouteRevoked);
        }
        let plan = entry
            .planner
            .plan(&self.url, resolution)
            .map_err(RouteError::Plan)?;
        let connection_id = entry
            .quota
            .open_connection(now)
            .map_err(RouteError::Quota)?;
        Ok(RoutePermit {
            registry: self.registry.clone(),
            endpoint: self.endpoint,
            incarnation: entry.incarnation.clone(),
            connection_id,
            plan,
            cancellation: entry.cancellation.clone(),
            open: true,
        })
    }
}

#[derive(Debug)]
pub struct RoutePermit {
    registry: RouteRegistry,
    endpoint: RouteEndpoint,
    incarnation: LeaseId,
    connection_id: ConnectionId,
    plan: ConnectPlan,
    cancellation: CancellationToken,
    open: bool,
}

impl RoutePermit {
    #[must_use]
    pub const fn plan(&self) -> &ConnectPlan {
        &self.plan
    }

    #[must_use]
    pub fn cancellation_token(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    pub fn record_egress_bytes(
        &mut self,
        bytes: u64,
        now: MonotonicMillis,
    ) -> Result<(), RouteError> {
        if !self.open {
            return Err(RouteError::ConnectionClosed);
        }
        self.registry.record_egress_bytes(
            self.endpoint,
            &self.incarnation,
            self.connection_id,
            bytes,
            now,
        )
    }

    pub fn close(&mut self) -> bool {
        if !self.open {
            return false;
        }
        self.registry
            .close_connection(self.endpoint, &self.incarnation, self.connection_id);
        self.open = false;
        true
    }
}

impl Drop for RoutePermit {
    fn drop(&mut self) {
        self.close();
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RouteError {
    InvalidEndpoint,
    InvalidWorkerEpoch,
    InvalidRegistryConfig,
    InvalidLeaseExpiry,
    EndpointAlreadyBound,
    EndpointRetired,
    RouteCapacityExceeded,
    ShardCapacityExceeded,
    ShardRevoked,
    RouteNotFound,
    RouteExpired,
    RouteRevoked,
    SourceShardMismatch,
    WorkerEpochMismatch { expected: u64, actual: u64 },
    InconsistentRegistryState,
    Plan(PlanError),
    Quota(QuotaError),
    ConnectionClosed,
}
