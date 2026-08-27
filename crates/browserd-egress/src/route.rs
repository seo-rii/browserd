use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use browserd_core::{EgressFence, SessionId, ShardFence, ShardId, TenantId, WorkerId};
use tokio_util::sync::CancellationToken;

use crate::{
    CanonicalUrl, ConnectPlan, ConnectionId, ConnectionPlanner, DnsResolution, EgressPolicy,
    MonotonicMillis, PlanError, QuotaError, QuotaLedger, QuotaLimits, QuotaUsage,
};

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RouteEndpoint(u64);

impl RouteEndpoint {
    /// Endpoints are allocated by the egress attachment manager, not callers.
    ///
    /// ```compile_fail
    /// use browserd_egress::RouteEndpoint;
    /// let forged = RouteEndpoint::new(7);
    /// # let _ = forged;
    /// ```
    pub(crate) const fn new(value: u64) -> Result<Self, RouteError> {
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

/// Read-only proof that an allocated endpoint belongs to one exact egress fence.
///
/// ```compile_fail
/// use browserd_core::{
///     EgressFence, LaunchGeneration, OwnerFence, RouteGeneration, SessionId,
///     SessionIncarnation, ShardFence, ShardId, WorkerEpoch, WorkerId,
/// };
/// use browserd_egress::{RouteClaim, RouteEndpoint};
/// # let fence = EgressFence::new(
/// #     ShardFence::new(
/// #         OwnerFence::new(
/// #             WorkerId::new("worker-a").expect("valid worker"),
/// #             WorkerEpoch::new(1).expect("nonzero epoch"),
/// #         ),
/// #         ShardId::new(),
/// #         LaunchGeneration::new(1).expect("nonzero launch generation"),
/// #     ),
/// #     RouteGeneration::new(1).expect("nonzero route generation"),
/// #     SessionId::new(),
/// #     SessionIncarnation::new(1).expect("nonzero session incarnation"),
/// # );
/// # let endpoint: RouteEndpoint = todo!();
/// let forged = RouteClaim::new(endpoint, fence);
/// # let _ = forged;
/// ```
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct RouteClaim {
    endpoint: RouteEndpoint,
    fence: EgressFence,
}

impl RouteClaim {
    #[must_use]
    pub(crate) const fn new(endpoint: RouteEndpoint, fence: EgressFence) -> Self {
        Self { endpoint, fence }
    }

    #[must_use]
    pub const fn endpoint(&self) -> RouteEndpoint {
        self.endpoint
    }

    #[must_use]
    pub const fn fence(&self) -> &EgressFence {
        &self.fence
    }

    #[must_use]
    pub const fn source_shard(&self) -> &ShardId {
        self.fence.shard().shard_id()
    }

    #[must_use]
    pub const fn worker_epoch(&self) -> u64 {
        self.fence.shard().owner().worker_epoch().get()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
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

    #[must_use]
    pub const fn expires_at(&self) -> MonotonicMillis {
        self.expires_at
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteIdentity {
    claim: RouteClaim,
    tenant_id: TenantId,
    session_id: SessionId,
    expires_at: MonotonicMillis,
}

impl RouteIdentity {
    #[must_use]
    pub const fn claim(&self) -> &RouteClaim {
        &self.claim
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
        self.claim.fence().shard().shard_id()
    }

    #[must_use]
    pub const fn worker_epoch(&self) -> u64 {
        self.claim.worker_epoch()
    }

    #[must_use]
    pub const fn expires_at(&self) -> MonotonicMillis {
        self.expires_at
    }
}

impl From<&RouteEntry> for RouteIdentity {
    fn from(entry: &RouteEntry) -> Self {
        Self {
            claim: entry.claim.clone(),
            tenant_id: entry.binding.tenant_id.clone(),
            session_id: entry.binding.session_id.clone(),
            expires_at: entry.binding.expires_at,
        }
    }
}

#[derive(Debug)]
struct RouteEntry {
    claim: RouteClaim,
    binding: RouteBinding,
    planner: ConnectionPlanner,
    quota: QuotaLedger,
    cancellation: CancellationToken,
}

#[derive(Clone, Debug)]
struct RetiredRoute {
    claim: RouteClaim,
    final_usage: QuotaUsage,
}

#[derive(Debug)]
struct ShardRoutes {
    fence: ShardFence,
    lifecycle: ShardRouteLifecycle,
    routes: HashSet<EgressFence>,
    cancellation: CancellationToken,
    active_connections: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ShardRouteLifecycle {
    Prepared,
    Revoked,
    Released,
}

#[derive(Debug, Default)]
struct RouteState {
    active: HashMap<EgressFence, RouteEntry>,
    retired: HashMap<EgressFence, RetiredRoute>,
    session_routes: HashMap<SessionId, EgressFence>,
    shards: HashMap<ShardId, ShardRoutes>,
    worker_epoch_high_watermarks: HashMap<WorkerId, u64>,
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

/// Route ingress accounting is minted only by an attached listener capability.
///
/// ```compile_fail
/// use browserd_egress::{MonotonicMillis, RouteClaim, RouteRegistry};
///
/// fn forge(registry: &RouteRegistry, claim: &RouteClaim) {
///     let forged = registry.begin_ingress(claim, MonotonicMillis::new(1));
///     let _ = forged;
/// }
/// ```
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

    pub fn prepare_shard(&self, fence: &ShardFence) -> Result<(), RouteError> {
        if self.max_lease_millis.is_none() || !self.limits.is_valid() {
            return Err(RouteError::InvalidRegistryConfig);
        }
        let mut state = self.lock_state();
        let worker_id = fence.owner().worker_id();
        let worker_epoch = fence.owner().worker_epoch().get();
        let high_watermark = state.worker_epoch_high_watermarks.get(worker_id).copied();
        if let Some(high_watermark) = high_watermark {
            if worker_epoch < high_watermark {
                return Err(RouteError::WorkerEpochMismatch {
                    expected: high_watermark,
                    actual: worker_epoch,
                });
            }
            if worker_epoch > high_watermark
                && state.shards.values().any(|shard| {
                    shard.fence.owner().worker_id() == worker_id
                        && shard.lifecycle != ShardRouteLifecycle::Released
                })
            {
                return Err(RouteError::ShardNotReleased);
            }
        }
        if high_watermark.is_some_and(|high_watermark| worker_epoch > high_watermark) {
            state.shards.retain(|_, shard| {
                shard.fence.owner().worker_id() != worker_id
                    || shard.lifecycle != ShardRouteLifecycle::Released
            });
        }
        let source_shard = fence.shard_id();
        let Some(shard) = state.shards.get_mut(source_shard) else {
            if state.shards.len() >= self.limits.max_tracked_shards {
                return Err(RouteError::ShardCapacityExceeded);
            }
            state.shards.insert(
                source_shard.clone(),
                ShardRoutes {
                    fence: fence.clone(),
                    lifecycle: ShardRouteLifecycle::Prepared,
                    routes: HashSet::new(),
                    cancellation: CancellationToken::new(),
                    active_connections: 0,
                },
            );
            state
                .worker_epoch_high_watermarks
                .insert(worker_id.clone(), worker_epoch);
            return Ok(());
        };
        if &shard.fence == fence {
            return match shard.lifecycle {
                ShardRouteLifecycle::Prepared => Ok(()),
                ShardRouteLifecycle::Revoked => Err(RouteError::ShardRevoked),
                ShardRouteLifecycle::Released => Err(RouteError::ShardReleased),
            };
        }
        if shard.fence.owner().worker_id() != worker_id {
            return Err(RouteError::ShardFenceMismatch);
        }
        let stored_epoch = shard.fence.owner().worker_epoch().get();
        if worker_epoch < stored_epoch {
            return Err(RouteError::WorkerEpochMismatch {
                expected: stored_epoch,
                actual: worker_epoch,
            });
        }
        if shard.lifecycle != ShardRouteLifecycle::Released {
            return Err(RouteError::ShardNotReleased);
        }
        if !shard.routes.is_empty() {
            return Err(RouteError::InconsistentRegistryState);
        }
        if worker_epoch == stored_epoch
            && fence.launch_generation() <= shard.fence.launch_generation()
        {
            return Err(RouteError::ShardFenceMismatch);
        }
        shard.fence = fence.clone();
        shard.lifecycle = ShardRouteLifecycle::Prepared;
        shard.cancellation = CancellationToken::new();
        shard.active_connections = 0;
        state
            .worker_epoch_high_watermarks
            .insert(worker_id.clone(), worker_epoch);
        Ok(())
    }

    pub fn bind(
        &self,
        claim: &RouteClaim,
        binding: RouteBinding,
        now: MonotonicMillis,
    ) -> Result<RouteIdentity, RouteError> {
        if claim.source_shard() != &binding.shard_id {
            return Err(RouteError::SourceShardMismatch);
        }
        if claim.worker_epoch() != binding.worker_epoch {
            return Err(RouteError::WorkerEpochMismatch {
                expected: claim.worker_epoch(),
                actual: binding.worker_epoch,
            });
        }
        if claim.fence().session_id() != &binding.session_id {
            return Err(RouteError::EgressFenceMismatch);
        }
        if !self.limits.is_valid() {
            return Err(RouteError::InvalidRegistryConfig);
        }
        self.validate_expiry(now, binding.expires_at)?;
        let mut state = self.lock_state();
        let fence = claim.fence().clone();
        if state
            .active
            .get(&fence)
            .is_some_and(|entry| entry.binding.expires_at <= now)
        {
            Self::retire_route(&mut state, &fence);
        }
        if let Some(retired) = state.retired.get(&fence) {
            Self::validate_claim(&retired.claim, claim)?;
            return Err(RouteError::EndpointRetired);
        }
        if let Some(entry) = state.active.get(&fence) {
            Self::validate_claim(&entry.claim, claim)?;
            if entry.binding.tenant_id == binding.tenant_id
                && entry.binding.session_id == binding.session_id
                && entry.binding.shard_id == binding.shard_id
                && entry.binding.worker_epoch == binding.worker_epoch
                && entry.binding.policy == binding.policy
                && entry.binding.quota_limits == binding.quota_limits
            {
                return Ok(RouteIdentity::from(entry));
            }
            return Err(RouteError::BindingConflict);
        }
        if state.session_routes.contains_key(&binding.session_id) {
            return Err(RouteError::SessionAlreadyBound);
        }
        if state.active.len().saturating_add(state.retired.len()) >= self.limits.max_tracked_routes
        {
            return Err(RouteError::RouteCapacityExceeded);
        }
        let shard = state
            .shards
            .get_mut(claim.source_shard())
            .ok_or(RouteError::ShardNotPrepared)?;
        if &shard.fence != claim.fence().shard() {
            return Err(RouteError::ShardFenceMismatch);
        }
        match shard.lifecycle {
            ShardRouteLifecycle::Prepared => {}
            ShardRouteLifecycle::Revoked => return Err(RouteError::ShardRevoked),
            ShardRouteLifecycle::Released => return Err(RouteError::ShardReleased),
        }
        let cancellation = shard.cancellation.child_token();
        shard.routes.insert(fence.clone());
        let session_id = binding.session_id.clone();
        let entry = RouteEntry {
            claim: claim.clone(),
            planner: ConnectionPlanner::new(binding.policy.clone()),
            quota: QuotaLedger::new(binding.quota_limits.clone()),
            binding,
            cancellation,
        };
        let identity = RouteIdentity::from(&entry);
        state.active.insert(fence.clone(), entry);
        state.session_routes.insert(session_id, fence);
        Ok(identity)
    }

    pub fn binding(
        &self,
        claim: &RouteClaim,
        now: MonotonicMillis,
    ) -> Result<RouteIdentity, RouteError> {
        let mut state = self.lock_state();
        let entry = Self::active_entry(&mut state, claim, now)?;
        Ok(RouteIdentity::from(&*entry))
    }

    pub fn renew(
        &self,
        claim: &RouteClaim,
        now: MonotonicMillis,
        new_expires_at: MonotonicMillis,
    ) -> Result<(), RouteError> {
        self.validate_expiry(now, new_expires_at)?;
        let mut state = self.lock_state();
        let entry = Self::active_entry(&mut state, claim, now)?;
        entry.binding.expires_at = new_expires_at;
        Ok(())
    }

    pub fn revoke(&self, claim: &RouteClaim) -> Result<(), RouteError> {
        let mut state = self.lock_state();
        let fence = claim.fence();
        if let Some(retired) = state.retired.get(fence) {
            Self::validate_claim(&retired.claim, claim)?;
            return Ok(());
        }
        let entry = state.active.get(fence).ok_or(RouteError::RouteNotFound)?;
        Self::validate_claim(&entry.claim, claim)?;
        Self::retire_route(&mut state, fence);
        Ok(())
    }

    pub fn revoke_shard(&self, fence: &ShardFence) -> Result<usize, RouteError> {
        let mut state = self.lock_state();
        let routes = {
            let shard = state
                .shards
                .get(fence.shard_id())
                .ok_or(RouteError::RouteNotFound)?;
            if &shard.fence != fence {
                return Err(RouteError::ShardFenceMismatch);
            }
            if matches!(
                shard.lifecycle,
                ShardRouteLifecycle::Revoked | ShardRouteLifecycle::Released
            ) {
                return Ok(0);
            }
            shard.routes.iter().cloned().collect::<Vec<_>>()
        };

        for route_fence in &routes {
            let entry = state
                .active
                .get(route_fence)
                .ok_or(RouteError::InconsistentRegistryState)?;
            if entry.claim.fence().shard() != fence {
                return Err(RouteError::InconsistentRegistryState);
            }
        }

        if let Some(shard) = state.shards.get(fence.shard_id()) {
            shard.cancellation.cancel();
        }
        for route_fence in &routes {
            Self::retire_route(&mut state, route_fence);
        }
        if let Some(shard) = state.shards.get_mut(fence.shard_id()) {
            shard.lifecycle = ShardRouteLifecycle::Revoked;
        }
        Ok(routes.len())
    }

    pub fn release_shard(&self, fence: &ShardFence) -> Result<(), RouteError> {
        let mut state = self.lock_state();
        let Some(shard) = state.shards.get_mut(fence.shard_id()) else {
            return if state
                .worker_epoch_high_watermarks
                .get(fence.owner().worker_id())
                .is_some_and(|high_watermark| fence.owner().worker_epoch().get() < *high_watermark)
            {
                Ok(())
            } else {
                Err(RouteError::ShardNotPrepared)
            };
        };
        if &shard.fence != fence {
            return Err(RouteError::ShardFenceMismatch);
        }
        match shard.lifecycle {
            ShardRouteLifecycle::Prepared => Err(RouteError::ShardNotRevoked),
            ShardRouteLifecycle::Revoked => {
                if !shard.routes.is_empty() {
                    return Err(RouteError::InconsistentRegistryState);
                }
                if shard.active_connections != 0 {
                    return Err(RouteError::ShardNotDrained);
                }
                shard.lifecycle = ShardRouteLifecycle::Released;
                Ok(())
            }
            ShardRouteLifecycle::Released => Ok(()),
        }
    }

    #[cfg(test)]
    pub(crate) fn begin_connection(
        &self,
        claim: &RouteClaim,
        url: &CanonicalUrl,
        resolution: DnsResolution,
        now: MonotonicMillis,
    ) -> Result<RoutePermit, RouteError> {
        self.authorize_dns(claim, url, now)?.finish(resolution, now)
    }

    #[cfg(test)]
    pub(crate) fn authorize_dns(
        &self,
        claim: &RouteClaim,
        url: &CanonicalUrl,
        now: MonotonicMillis,
    ) -> Result<PreDnsPermit, RouteError> {
        self.begin_ingress(claim, now)?.authorize_dns(url, now)
    }

    pub(crate) fn begin_ingress(
        &self,
        claim: &RouteClaim,
        now: MonotonicMillis,
    ) -> Result<RouteIngressGuard, RouteError> {
        let mut state = self.lock_state();
        let (fence, shard_fence, cancellation) = {
            let entry = Self::active_entry(&mut state, claim, now)?;
            (
                entry.claim.fence().clone(),
                entry.claim.fence().shard().clone(),
                entry.cancellation.clone(),
            )
        };
        let next_active_connections = {
            let shard = state
                .shards
                .get(shard_fence.shard_id())
                .ok_or(RouteError::InconsistentRegistryState)?;
            if shard.fence != shard_fence || shard.lifecycle != ShardRouteLifecycle::Prepared {
                return Err(RouteError::InconsistentRegistryState);
            }
            shard
                .active_connections
                .checked_add(1)
                .ok_or(RouteError::InconsistentRegistryState)?
        };
        let entry = Self::active_entry(&mut state, claim, now)?;
        entry
            .quota
            .reserve_connection(now)
            .map_err(RouteError::Quota)?;
        let Some(shard) = state.shards.get_mut(shard_fence.shard_id()) else {
            if let Some(entry) = state.active.get_mut(&fence) {
                entry.quota.cancel_connection_reservation();
            }
            return Err(RouteError::InconsistentRegistryState);
        };
        shard.active_connections = next_active_connections;
        Ok(RouteIngressGuard {
            registry: self.clone(),
            fence: fence.clone(),
            cancellation,
            reservation: ConnectionReservationGuard::new(self.clone(), fence),
            drain_guard: ShardDrainGuard::new(self.clone(), shard_fence),
        })
    }

    pub fn expire_routes(&self, now: MonotonicMillis) -> usize {
        let mut state = self.lock_state();
        let expired = state
            .active
            .iter()
            .filter_map(|(fence, entry)| (entry.binding.expires_at <= now).then_some(fence.clone()))
            .collect::<Vec<_>>();
        for fence in &expired {
            Self::retire_route(&mut state, fence);
        }
        expired.len()
    }

    pub fn usage(&self, claim: &RouteClaim) -> Result<QuotaUsage, RouteError> {
        let state = self.lock_state();
        let entry = state
            .active
            .get(claim.fence())
            .map(|entry| (&entry.claim, entry.quota.usage()))
            .or_else(|| {
                state
                    .retired
                    .get(claim.fence())
                    .map(|entry| (&entry.claim, entry.final_usage))
            })
            .ok_or(RouteError::RouteNotFound)?;
        Self::validate_claim(entry.0, claim)?;
        Ok(entry.1)
    }

    fn record_egress_bytes(
        &self,
        fence: &EgressFence,
        connection_id: ConnectionId,
        bytes: u64,
        now: MonotonicMillis,
    ) -> Result<(), RouteError> {
        let mut state = self.lock_state();
        let entry = Self::active_entry_by_fence(&mut state, fence, now)?;
        entry
            .quota
            .record_egress(connection_id, bytes, now)
            .map_err(RouteError::Quota)
    }

    fn record_request_bytes(
        &self,
        fence: &EgressFence,
        connection_id: ConnectionId,
        bytes: u64,
        now: MonotonicMillis,
    ) -> Result<(), RouteError> {
        let mut state = self.lock_state();
        let entry = Self::active_entry_by_fence(&mut state, fence, now)?;
        entry
            .quota
            .record_request(connection_id, bytes, now)
            .map_err(RouteError::Quota)
    }

    fn close_connection(&self, fence: &EgressFence, connection_id: ConnectionId) {
        let mut state = self.lock_state();
        if let Some(entry) = state.active.get_mut(fence) {
            entry.quota.close_connection(connection_id);
        }
    }

    fn commit_connection_reservation(
        &self,
        fence: &EgressFence,
        now: MonotonicMillis,
    ) -> Result<ConnectionId, RouteError> {
        let mut state = self.lock_state();
        let entry = Self::active_entry_by_fence(&mut state, fence, now)?;
        entry
            .quota
            .open_reserved_connection(now)
            .map_err(RouteError::Quota)
    }

    fn cancel_connection_reservation(&self, fence: &EgressFence) {
        let mut state = self.lock_state();
        if let Some(entry) = state.active.get_mut(fence) {
            entry.quota.cancel_connection_reservation();
        }
    }

    fn close_shard_connection(&self, fence: &ShardFence) {
        let mut state = self.lock_state();
        let Some(shard) = state.shards.get_mut(fence.shard_id()) else {
            return;
        };
        if &shard.fence != fence || shard.active_connections == 0 {
            return;
        }
        shard.active_connections -= 1;
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

    fn retire_route(state: &mut RouteState, fence: &EgressFence) {
        let Some(entry) = state.active.remove(fence) else {
            return;
        };
        entry.cancellation.cancel();
        let mut final_usage = entry.quota.usage();
        final_usage.active_connections = 0;
        if let Some(shard) = state.shards.get_mut(entry.claim.source_shard())
            && &shard.fence == entry.claim.fence().shard()
        {
            shard.routes.remove(fence);
        }
        state.retired.insert(
            fence.clone(),
            RetiredRoute {
                claim: entry.claim,
                final_usage,
            },
        );
    }

    fn validate_claim(stored: &RouteClaim, candidate: &RouteClaim) -> Result<(), RouteError> {
        if stored.fence != candidate.fence {
            return Err(RouteError::EgressFenceMismatch);
        }
        if stored.endpoint != candidate.endpoint {
            return Err(RouteError::BindingConflict);
        }
        Ok(())
    }

    fn active_entry<'state>(
        state: &'state mut RouteState,
        claim: &RouteClaim,
        now: MonotonicMillis,
    ) -> Result<&'state mut RouteEntry, RouteError> {
        let entry = Self::active_entry_by_fence(state, claim.fence(), now)?;
        Self::validate_claim(&entry.claim, claim)?;
        Ok(entry)
    }

    fn active_entry_by_fence<'state>(
        state: &'state mut RouteState,
        fence: &EgressFence,
        now: MonotonicMillis,
    ) -> Result<&'state mut RouteEntry, RouteError> {
        let expired = state
            .active
            .get(fence)
            .is_some_and(|entry| entry.binding.expires_at <= now);
        if expired {
            Self::retire_route(state, fence);
            return Err(RouteError::RouteExpired);
        }
        state.active.get_mut(fence).ok_or_else(|| {
            if state.retired.contains_key(fence) {
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
pub(crate) struct RouteIngressGuard {
    registry: RouteRegistry,
    fence: EgressFence,
    cancellation: CancellationToken,
    reservation: ConnectionReservationGuard,
    drain_guard: ShardDrainGuard,
}

impl RouteIngressGuard {
    #[must_use]
    pub fn cancellation_token(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    pub fn authorize_dns(
        self,
        url: &CanonicalUrl,
        now: MonotonicMillis,
    ) -> Result<PreDnsPermit, RouteError> {
        let Self {
            registry,
            fence,
            cancellation,
            reservation,
            drain_guard,
        } = self;
        let mut state = registry.lock_state();
        let entry = RouteRegistry::active_entry_by_fence(&mut state, &fence, now)?;
        entry.planner.authorize(url).map_err(RouteError::Plan)?;
        entry
            .quota
            .record_dns_query(now)
            .map_err(RouteError::Quota)?;
        drop(state);
        Ok(PreDnsPermit {
            registry,
            fence,
            url: url.clone(),
            cancellation,
            reservation,
            drain_guard,
        })
    }
}

#[derive(Debug)]
pub(crate) struct PreDnsPermit {
    registry: RouteRegistry,
    fence: EgressFence,
    url: CanonicalUrl,
    cancellation: CancellationToken,
    reservation: ConnectionReservationGuard,
    drain_guard: ShardDrainGuard,
}

impl PreDnsPermit {
    #[must_use]
    pub fn cancellation_token(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    pub fn finish(
        mut self,
        resolution: DnsResolution,
        now: MonotonicMillis,
    ) -> Result<RoutePermit, RouteError> {
        let plan = {
            let mut state = self.registry.lock_state();
            let entry = RouteRegistry::active_entry_by_fence(&mut state, &self.fence, now)?;
            entry
                .planner
                .plan(&self.url, resolution)
                .map_err(RouteError::Plan)?
        };
        let connection_id = self.reservation.commit(now)?;
        let Self {
            registry,
            fence,
            url: _,
            cancellation,
            reservation: _,
            drain_guard,
        } = self;
        Ok(RoutePermit {
            registry,
            fence,
            connection_id,
            plan,
            cancellation,
            drain_guard,
            open: true,
        })
    }
}

#[derive(Debug)]
struct ConnectionReservationGuard {
    registry: RouteRegistry,
    fence: EgressFence,
    open: bool,
}

impl ConnectionReservationGuard {
    fn new(registry: RouteRegistry, fence: EgressFence) -> Self {
        Self {
            registry,
            fence,
            open: true,
        }
    }

    fn commit(&mut self, now: MonotonicMillis) -> Result<ConnectionId, RouteError> {
        let connection_id = self
            .registry
            .commit_connection_reservation(&self.fence, now)?;
        self.open = false;
        Ok(connection_id)
    }

    fn close(&mut self) {
        if !self.open {
            return;
        }
        self.registry.cancel_connection_reservation(&self.fence);
        self.open = false;
    }
}

impl Drop for ConnectionReservationGuard {
    fn drop(&mut self) {
        self.close();
    }
}

#[derive(Debug)]
pub(crate) struct RoutePermit {
    registry: RouteRegistry,
    fence: EgressFence,
    connection_id: ConnectionId,
    plan: ConnectPlan,
    cancellation: CancellationToken,
    drain_guard: ShardDrainGuard,
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
        self.registry
            .record_egress_bytes(&self.fence, self.connection_id, bytes, now)
    }

    pub fn record_request_bytes(
        &mut self,
        bytes: u64,
        now: MonotonicMillis,
    ) -> Result<(), RouteError> {
        if !self.open {
            return Err(RouteError::ConnectionClosed);
        }
        self.registry
            .record_request_bytes(&self.fence, self.connection_id, bytes, now)
    }

    pub fn close(&mut self) -> bool {
        if !self.open {
            return false;
        }
        self.registry
            .close_connection(&self.fence, self.connection_id);
        self.drain_guard.close();
        self.open = false;
        true
    }
}

impl Drop for RoutePermit {
    fn drop(&mut self) {
        self.close();
    }
}

#[derive(Debug)]
struct ShardDrainGuard {
    registry: RouteRegistry,
    fence: ShardFence,
    open: bool,
}

impl ShardDrainGuard {
    fn new(registry: RouteRegistry, fence: ShardFence) -> Self {
        Self {
            registry,
            fence,
            open: true,
        }
    }

    fn close(&mut self) {
        if !self.open {
            return;
        }
        self.registry.close_shard_connection(&self.fence);
        self.open = false;
    }
}

impl Drop for ShardDrainGuard {
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
    BindingConflict,
    EgressFenceMismatch,
    GenerationMismatch,
    EndpointAlreadyBound,
    SessionAlreadyBound,
    EndpointRetired,
    RouteCapacityExceeded,
    ShardCapacityExceeded,
    ShardFenceMismatch,
    ShardNotPrepared,
    ShardNotDrained,
    ShardNotReleased,
    ShardNotRevoked,
    ShardRevoked,
    ShardReleased,
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
