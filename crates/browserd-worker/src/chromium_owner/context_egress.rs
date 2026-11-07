//! Immutable owner admission limits and exact, process-local context egress capabilities.

use std::collections::BTreeMap;
use std::time::Instant;

use browserd_core::{IsolationProfile, SessionId, TenantId};
use browserd_sandbox::{
    ContextEgressBinding, ContextEgressReleaseReceipt, ContextEgressRequest,
    DedicatedEgressProxyBinding, LaunchSpec,
};

use super::{
    ContextEntry, ContextLifecycle, ContextOwnership, OwnerActorError, RetiredOwnerTarget,
    TargetRouteEntry, WorkerDisposalSnapshot,
};
use crate::ShardRuntimeError;

const MAX_LIVE_CONTEXTS: usize = 8;
const MAX_LIFETIME_CONTEXTS: u64 = 500;

/// A trusted factory-selected policy for one immutable Chromium launch.
///
/// This is an admission policy, not shared-process security qualification. Production callers
/// must separately qualify the exact Chromium/sandbox profile before selecting a pooled mode.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnerContextPolicy {
    isolation: IsolationProfile,
    tenant_id: Option<TenantId>,
    max_live_contexts: usize,
    max_lifetime_contexts: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CapabilityPhase {
    Registered,
    Creating,
    Active,
    Disposed,
}

struct Capability {
    ownership: ContextOwnership,
    binding: ContextEgressBinding,
    valid_until: Instant,
    phase: CapabilityPhase,
}

/// Retired capabilities remain bounded by the launch lifetime and cannot be resurrected.
pub(super) struct ContextEgressRegistry {
    policy: Option<OwnerContextPolicy>,
    launch: Option<LaunchSpec>,
    initial_proxy: Option<DedicatedEgressProxyBinding>,
    daemon_epochs: Option<(u64, u64)>,
    live: BTreeMap<SessionId, Capability>,
    retired: BTreeMap<SessionId, ContextEgressReleaseReceipt>,
    registered: u64,
}

impl ContextEgressRegistry {
    pub(super) fn new(
        policy: Option<OwnerContextPolicy>,
        launch: Option<LaunchSpec>,
        initial_proxy: Option<DedicatedEgressProxyBinding>,
    ) -> Self {
        Self {
            policy,
            launch,
            initial_proxy,
            daemon_epochs: None,
            live: BTreeMap::new(),
            retired: BTreeMap::new(),
            registered: 0,
        }
    }

    pub(super) fn policy(&self) -> Option<&OwnerContextPolicy> {
        self.policy.as_ref()
    }

    pub(super) fn register(
        &mut self,
        ownership: ContextOwnership,
        binding: ContextEgressBinding,
        valid_until: Instant,
        now: Instant,
    ) -> Result<(), OwnerActorError> {
        let policy = self.policy.as_ref().ok_or(OwnerActorError::Rejected)?;
        let launch = self.launch.as_ref().ok_or(OwnerActorError::Rejected)?;
        let initial = self
            .initial_proxy
            .as_ref()
            .ok_or(OwnerActorError::Rejected)?;
        let request = binding.request();
        let egress = request.egress().egress_fence();
        if valid_until <= now
            || valid_until.saturating_duration_since(now) > binding.granted_ttl()
            || request.tenant_id() != &ownership.tenant_id
            || egress.session_id() != &ownership.session_id
            || egress.session_incarnation().get() != ownership.fence.session_incarnation()
            || request.placement() != ownership.fence.as_placement_fence()
            || egress.shard().owner().worker_id() != ownership.fence.worker_id()
            || !policy.allows_tenant(&ownership.tenant_id)
        {
            return Err(OwnerActorError::UnknownOwnership);
        }
        let sandboxd_epoch = self
            .daemon_epochs
            .map_or(binding.sandboxd_epoch(), |epochs| epochs.0);
        binding
            .validate_for(
                launch,
                request,
                sandboxd_epoch,
                initial.namespace_identity(),
            )
            .map_err(|_| OwnerActorError::UnknownOwnership)?;
        if self
            .daemon_epochs
            .is_some_and(|epochs| epochs.1 != binding.egress_daemon_epoch())
            || self.retired.contains_key(&ownership.session_id)
        {
            return Err(OwnerActorError::UnknownOwnership);
        }
        if let Some(current) = self.live.get(&ownership.session_id) {
            // An attach retry may report less remaining TTL. It never extends this deadline.
            return if current.ownership == ownership
                && same_route(&current.binding, &binding)
                && current.valid_until > now
                && current.phase != CapabilityPhase::Disposed
            {
                Ok(())
            } else {
                Err(OwnerActorError::UnknownOwnership)
            };
        }
        if self.live.len() >= policy.max_live_contexts
            || self.registered >= policy.max_lifetime_contexts
        {
            return Err(OwnerActorError::StateOverflow);
        }
        if self.live.values().any(|current| {
            current.binding.proxy_binding().proxy_address()
                == binding.proxy_binding().proxy_address()
        }) {
            return Err(OwnerActorError::UnknownOwnership);
        }
        if self.daemon_epochs.is_none()
            && (ContextEgressRequest::initial(launch).ok().as_ref() != Some(request)
                || binding.proxy_binding() != initial)
        {
            return Err(OwnerActorError::UnknownOwnership);
        }
        self.registered += 1;
        self.daemon_epochs = Some((binding.sandboxd_epoch(), binding.egress_daemon_epoch()));
        self.live.insert(
            ownership.session_id.clone(),
            Capability {
                ownership,
                binding,
                valid_until,
                phase: CapabilityPhase::Registered,
            },
        );
        Ok(())
    }

    pub(super) fn renew(
        &mut self,
        binding: ContextEgressBinding,
        valid_until: Instant,
        now: Instant,
    ) -> Result<(), OwnerActorError> {
        binding
            .validate()
            .map_err(|_| OwnerActorError::UnknownOwnership)?;
        let session = binding.request().egress().egress_fence().session_id();
        let current = self
            .live
            .get_mut(session)
            .ok_or(OwnerActorError::UnknownOwnership)?;
        if !same_route(&current.binding, &binding)
            || current.valid_until <= now
            || valid_until <= now
            || valid_until.saturating_duration_since(now) > binding.granted_ttl()
            || current.phase == CapabilityPhase::Disposed
        {
            return Err(OwnerActorError::UnknownOwnership);
        }
        current.valid_until = current.valid_until.max(valid_until);
        Ok(())
    }

    pub(super) fn for_create(
        &mut self,
        ownership: &ContextOwnership,
        now: Instant,
    ) -> Result<DedicatedEgressProxyBinding, OwnerActorError> {
        let capability = self
            .live
            .get_mut(&ownership.session_id)
            .ok_or(OwnerActorError::UnknownOwnership)?;
        if &capability.ownership != ownership
            || capability.valid_until <= now
            || capability.phase != CapabilityPhase::Registered
        {
            return Err(OwnerActorError::UnknownOwnership);
        }
        // This phase is set before CDP exposure. An uncertain response cannot free capacity.
        capability.phase = CapabilityPhase::Creating;
        Ok(capability.binding.proxy_binding().clone())
    }

    pub(super) fn activated(
        &mut self,
        ownership: &ContextOwnership,
    ) -> Result<(), OwnerActorError> {
        let capability = self
            .live
            .get_mut(&ownership.session_id)
            .ok_or(OwnerActorError::UnknownOwnership)?;
        if &capability.ownership != ownership || capability.phase != CapabilityPhase::Creating {
            return Err(OwnerActorError::OutcomeUncertain);
        }
        capability.phase = CapabilityPhase::Active;
        Ok(())
    }

    pub(super) fn check_active(
        &self,
        ownership: &ContextOwnership,
        now: Instant,
    ) -> Result<(), OwnerActorError> {
        if self.policy.is_none() {
            return Ok(());
        }
        let capability = self
            .live
            .get(&ownership.session_id)
            .ok_or(OwnerActorError::UnknownOwnership)?;
        if &capability.ownership != ownership
            || capability.valid_until <= now
            || capability.phase != CapabilityPhase::Active
        {
            return Err(OwnerActorError::UnknownOwnership);
        }
        Ok(())
    }

    pub(super) fn disposed(&mut self, ownership: &ContextOwnership) -> Result<(), OwnerActorError> {
        if self.policy.is_none() {
            return Ok(());
        }
        let capability = self
            .live
            .get_mut(&ownership.session_id)
            .ok_or(OwnerActorError::OutcomeUncertain)?;
        if &capability.ownership != ownership || capability.phase != CapabilityPhase::Active {
            return Err(OwnerActorError::OutcomeUncertain);
        }
        capability.phase = CapabilityPhase::Disposed;
        Ok(())
    }

    pub(super) fn confirm_released(
        &mut self,
        receipt: ContextEgressReleaseReceipt,
    ) -> Result<(), OwnerActorError> {
        receipt
            .validate()
            .map_err(|_| OwnerActorError::UnknownOwnership)?;
        let session = receipt.request().egress().egress_fence().session_id();
        if let Some(previous) = self.retired.get(session) {
            return if previous == &receipt {
                Ok(())
            } else {
                Err(OwnerActorError::UnknownOwnership)
            };
        }
        let capability = self
            .live
            .get(session)
            .ok_or(OwnerActorError::UnknownOwnership)?;
        receipt
            .validate_for(
                capability.binding.request(),
                capability.binding.sandboxd_epoch(),
            )
            .map_err(|_| OwnerActorError::UnknownOwnership)?;
        if receipt.egress_daemon_epoch() != capability.binding.egress_daemon_epoch()
            || !matches!(
                capability.phase,
                CapabilityPhase::Registered | CapabilityPhase::Disposed
            )
        {
            return Err(OwnerActorError::OutcomeUncertain);
        }
        let session = session.clone();
        self.live.remove(&session);
        self.retired.insert(session, receipt);
        Ok(())
    }

    pub(super) fn next_expiry(&self) -> Option<Instant> {
        self.live
            .values()
            .filter(|capability| capability.phase != CapabilityPhase::Disposed)
            .map(|capability| capability.valid_until)
            .min()
    }
}

fn same_route(left: &ContextEgressBinding, right: &ContextEgressBinding) -> bool {
    left.request() == right.request()
        && left.proxy_binding() == right.proxy_binding()
        && left.sandboxd_epoch() == right.sandboxd_epoch()
        && left.egress_daemon_epoch() == right.egress_daemon_epoch()
}

/// Separates exact owned cleanup from an unowned bootstrap failure. The full pinned route and
/// ownership survive even after the browser context has been removed from the live registry.
pub(super) fn classify_bootstrap(
    target: &browserd_targets::PausedTarget,
    route: Option<&TargetRouteEntry>,
    context: Option<&ContextEntry>,
    snapshot: Option<&WorkerDisposalSnapshot>,
    retired: Option<&RetiredOwnerTarget>,
    retired_session: Option<&String>,
    shard: &browserd_core::ShardFence,
) -> Result<browserd_targets::BootstrapDisposition, OwnerActorError> {
    use browserd_targets::BootstrapDisposition;
    if let Some(route) = route {
        let context = context.ok_or(OwnerActorError::UnknownOwnership)?;
        if &route.kind != target.kind()
            || route.ownership() != context.ownership
            || context.ownership.fence.worker_id() != shard.owner().worker_id()
            || context.ownership.fence.worker_epoch() != shard.owner().worker_epoch().get()
            || retired.is_some()
        {
            return Err(OwnerActorError::UnknownOwnership);
        }
        if context.lifecycle == ContextLifecycle::Active {
            return Ok(BootstrapDisposition::Completed);
        }
        let snapshot = snapshot.ok_or(OwnerActorError::UnknownOwnership)?;
        if snapshot.ownership != context.ownership
            || snapshot.targets.get(target.target_id())
                != Some(&route.admission_target(target.target_id()))
        {
            return Err(OwnerActorError::UnknownOwnership);
        }
        return Ok(BootstrapDisposition::OwnedClosing);
    }
    let retired = retired.ok_or(OwnerActorError::UnknownOwnership)?;
    if retired.target.target_id != target.target_id()
        || &retired.target.kind != target.kind()
        || retired_session != Some(&retired.target.flattened_session_id)
        || retired.ownership.fence.worker_id() != shard.owner().worker_id()
        || retired.ownership.fence.worker_epoch() != shard.owner().worker_epoch().get()
    {
        return Err(OwnerActorError::UnknownOwnership);
    }
    Ok(BootstrapDisposition::OwnedRetired)
}

impl OwnerContextPolicy {
    pub fn shared(
        max_live_contexts: usize,
        max_lifetime_contexts: u64,
    ) -> Result<Self, ShardRuntimeError> {
        Self::new(
            IsolationProfile::SharedContext,
            max_live_contexts,
            max_lifetime_contexts,
            None,
        )
    }

    pub fn tenant_dedicated(
        tenant_id: TenantId,
        max_live_contexts: usize,
        max_lifetime_contexts: u64,
    ) -> Result<Self, ShardRuntimeError> {
        Self::new(
            IsolationProfile::TenantDedicatedShard,
            max_live_contexts,
            max_lifetime_contexts,
            Some(tenant_id),
        )
    }

    #[must_use]
    pub const fn dedicated() -> Self {
        Self {
            isolation: IsolationProfile::DedicatedProcess,
            tenant_id: None,
            max_live_contexts: 1,
            max_lifetime_contexts: 1,
        }
    }

    pub fn new(
        isolation: IsolationProfile,
        max_live_contexts: usize,
        max_lifetime_contexts: u64,
        tenant_id: Option<TenantId>,
    ) -> Result<Self, ShardRuntimeError> {
        if max_live_contexts == 0
            || max_live_contexts > MAX_LIVE_CONTEXTS
            || max_lifetime_contexts < max_live_contexts as u64
            || max_lifetime_contexts > MAX_LIFETIME_CONTEXTS
            || match isolation {
                IsolationProfile::SharedContext => tenant_id.is_some(),
                IsolationProfile::TenantDedicatedShard => tenant_id.is_none(),
                IsolationProfile::DedicatedProcess => {
                    max_live_contexts != 1 || max_lifetime_contexts != 1
                }
                IsolationProfile::DedicatedWorker => true,
            }
        {
            return Err(ShardRuntimeError::Rejected);
        }
        Ok(Self {
            isolation,
            tenant_id,
            max_live_contexts,
            max_lifetime_contexts,
        })
    }

    #[must_use]
    pub const fn isolation(&self) -> IsolationProfile {
        self.isolation
    }

    #[must_use]
    pub const fn max_live_contexts(&self) -> usize {
        self.max_live_contexts
    }

    #[must_use]
    pub const fn max_lifetime_contexts(&self) -> u64 {
        self.max_lifetime_contexts
    }

    #[must_use]
    pub fn allows_tenant(&self, tenant_id: &TenantId) -> bool {
        self.tenant_id
            .as_ref()
            .is_none_or(|tenant| tenant == tenant_id)
    }

    pub(super) fn is_pooled(&self) -> bool {
        matches!(
            self.isolation,
            IsolationProfile::SharedContext | IsolationProfile::TenantDedicatedShard
        )
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use browserd_core::{
        EgressFence, LaunchGeneration, LeaseId, OwnerFence, PlacementFence, RouteGeneration,
        SessionIncarnation, ShardFence, ShardId, WorkerEpoch, WorkerId,
    };
    use browserd_sandbox::{
        ChromiumBinaryDigest, ContextRoutePolicy, DedicatedEgressSpec, EgressPolicyBinding,
    };
    use browserd_session::OwnershipFence;
    use serde_json::json;
    use std::time::Duration;

    struct Fixture {
        registry: ContextEgressRegistry,
        owner: ContextOwnership,
        binding: ContextEgressBinding,
        launch: LaunchSpec,
    }

    fn proxy(request: &ContextEgressRequest, port: u16) -> DedicatedEgressProxyBinding {
        serde_json::from_value(json!({
            "tenant_id":request.tenant_id(), "egress_fence":request.egress().egress_fence(),
            "policy_binding":request.egress().policy_binding(), "namespace_identity":{"device":7,"inode":42},
            "reservation_generation":LeaseId::new(), "attachment_generation":LeaseId::new(),
            "proxy_address":format!("127.0.0.1:{port}")
        })).expect("synthetic routing metadata for a unit test")
    }

    fn fixture(live: usize, lifetime: u64, tenant_only: bool) -> Fixture {
        let tenant_id = TenantId::new();
        let session_id = SessionId::new();
        let worker = WorkerId::new("context-capability-test").expect("worker");
        let placement = PlacementFence::new(11, 7, 3);
        let shard = ShardFence::new(
            OwnerFence::new(worker.clone(), WorkerEpoch::new(11).expect("epoch")),
            ShardId::new(),
            LaunchGeneration::new(2).expect("launch"),
        );
        let egress = DedicatedEgressSpec::new(
            EgressFence::new(
                shard,
                RouteGeneration::new(1).expect("route"),
                session_id.clone(),
                SessionIncarnation::new(3).expect("incarnation"),
            ),
            EgressPolicyBinding::new("public", [3; 32]).expect("policy"),
            Duration::from_secs(120),
        )
        .expect("egress");
        let launch = LaunchSpec::production(
            tenant_id.clone(),
            egress,
            ChromiumBinaryDigest::new([5; 32]),
        )
        .with_context_route_policy(
            ContextRoutePolicy::new(placement, tenant_only, live as u16, lifetime as u16)
                .expect("route policy"),
        )
        .expect("launch policy");
        let request = ContextEgressRequest::initial(&launch).expect("initial request");
        let binding = ContextEgressBinding::new(
            request.clone(),
            19,
            23,
            proxy(&request, 4101),
            Duration::from_secs(60),
        )
        .expect("binding");
        let policy = OwnerContextPolicy::new(
            if tenant_only {
                IsolationProfile::TenantDedicatedShard
            } else {
                IsolationProfile::SharedContext
            },
            live,
            lifetime,
            tenant_only.then_some(tenant_id.clone()),
        )
        .expect("policy");
        Fixture {
            registry: ContextEgressRegistry::new(
                Some(policy),
                Some(launch.clone()),
                Some(binding.proxy_binding().clone()),
            ),
            owner: ContextOwnership {
                tenant_id,
                session_id,
                fence: OwnershipFence::new(worker, 11, 7, 3),
            },
            binding,
            launch,
        }
    }

    fn sibling(
        fixture: &Fixture,
        tenant: TenantId,
        route: u64,
    ) -> (ContextOwnership, ContextEgressBinding) {
        let session_id = SessionId::new();
        let owner = ContextOwnership {
            tenant_id: tenant.clone(),
            session_id: session_id.clone(),
            fence: OwnershipFence::new(fixture.owner.fence.worker_id().clone(), 11, route + 10, 3),
        };
        let request = ContextEgressRequest::new(
            tenant,
            owner.fence.as_placement_fence(),
            DedicatedEgressSpec::new(
                EgressFence::new(
                    fixture
                        .launch
                        .dedicated_egress()
                        .egress_fence()
                        .shard()
                        .clone(),
                    RouteGeneration::new(route).expect("route"),
                    session_id,
                    SessionIncarnation::new(3).expect("incarnation"),
                ),
                fixture.launch.dedicated_egress().policy_binding().clone(),
                Duration::from_secs(120),
            )
            .expect("egress"),
        )
        .expect("request");
        let binding = ContextEgressBinding::new(
            request.clone(),
            19,
            23,
            proxy(&request, 4100 + route as u16),
            Duration::from_secs(60),
        )
        .expect("binding");
        (owner, binding)
    }

    #[test]
    fn eight_pending_caps_reserve_capacity_and_cross_tenant_dedicated_is_denied() {
        let now = Instant::now();
        let mut fixture = fixture(8, 500, false);
        fixture
            .registry
            .register(
                fixture.owner.clone(),
                fixture.binding.clone(),
                now + Duration::from_secs(30),
                now,
            )
            .expect("first");
        for route in 2..=8 {
            let (owner, binding) = sibling(&fixture, TenantId::new(), route);
            fixture
                .registry
                .register(owner, binding, now + Duration::from_secs(30), now)
                .expect("shared sibling");
        }
        let (owner, binding) = sibling(&fixture, TenantId::new(), 9);
        assert_eq!(
            fixture
                .registry
                .register(owner, binding, now + Duration::from_secs(30), now),
            Err(OwnerActorError::StateOverflow)
        );
        assert_eq!(fixture.registry.live.len(), 8);
        let mut dedicated = self::fixture(8, 500, true);
        dedicated
            .registry
            .register(
                dedicated.owner.clone(),
                dedicated.binding.clone(),
                now + Duration::from_secs(30),
                now,
            )
            .expect("first tenant");
        let (owner, binding) = sibling(&dedicated, TenantId::new(), 2);
        assert_eq!(
            dedicated
                .registry
                .register(owner, binding, now + Duration::from_secs(30), now),
            Err(OwnerActorError::UnknownOwnership)
        );
        assert_eq!(dedicated.registry.live.len(), 1);
    }

    #[test]
    fn duplicate_attach_does_not_extend_but_confirmed_exact_renew_can() {
        let now = Instant::now();
        let mut fixture = fixture(8, 500, false);
        fixture
            .registry
            .register(
                fixture.owner.clone(),
                fixture.binding.clone(),
                now + Duration::from_secs(10),
                now,
            )
            .expect("register");
        fixture
            .registry
            .register(
                fixture.owner.clone(),
                fixture.binding.clone(),
                now + Duration::from_secs(50),
                now,
            )
            .expect("retry");
        assert_eq!(
            fixture.registry.next_expiry(),
            Some(now + Duration::from_secs(10))
        );
        fixture
            .registry
            .renew(
                fixture.binding.clone(),
                now + Duration::from_secs(40),
                now + Duration::from_secs(1),
            )
            .expect("positive renew");
        assert_eq!(
            fixture.registry.next_expiry(),
            Some(now + Duration::from_secs(40))
        );
        let drift = ContextEgressBinding::new(
            fixture.binding.request().clone(),
            19,
            24,
            fixture.binding.proxy_binding().clone(),
            Duration::from_secs(60),
        )
        .expect("different epoch");
        assert_eq!(
            fixture.registry.renew(
                drift,
                now + Duration::from_secs(50),
                now + Duration::from_secs(2)
            ),
            Err(OwnerActorError::UnknownOwnership)
        );
        assert_eq!(
            fixture.registry.renew(
                fixture.binding.clone(),
                now + Duration::from_secs(90),
                now + Duration::from_secs(41)
            ),
            Err(OwnerActorError::UnknownOwnership)
        );
    }

    #[test]
    fn full_scope_and_initial_pipe_authority_are_required_before_registration() {
        let now = Instant::now();
        let mut fixture = fixture(8, 500, false);
        let owner = &fixture.owner;
        let mismatches = [
            ContextOwnership {
                tenant_id: TenantId::new(),
                ..owner.clone()
            },
            ContextOwnership {
                session_id: SessionId::new(),
                ..owner.clone()
            },
            ContextOwnership {
                fence: OwnershipFence::new(WorkerId::new("other").expect("worker"), 11, 7, 3),
                ..owner.clone()
            },
            ContextOwnership {
                fence: OwnershipFence::new(owner.fence.worker_id().clone(), 12, 7, 3),
                ..owner.clone()
            },
            ContextOwnership {
                fence: OwnershipFence::new(owner.fence.worker_id().clone(), 11, 8, 3),
                ..owner.clone()
            },
            ContextOwnership {
                fence: OwnershipFence::new(owner.fence.worker_id().clone(), 11, 7, 4),
                ..owner.clone()
            },
        ];
        for mismatch in mismatches {
            assert!(
                fixture
                    .registry
                    .register(
                        mismatch,
                        fixture.binding.clone(),
                        now + Duration::from_secs(30),
                        now
                    )
                    .is_err()
            );
        }
        let (owner, binding) = sibling(&fixture, TenantId::new(), 2);
        assert!(
            fixture
                .registry
                .register(owner, binding, now + Duration::from_secs(30), now)
                .is_err(),
            "first grant must be launch route"
        );
        assert!(
            fixture
                .registry
                .register(fixture.owner.clone(), fixture.binding.clone(), now, now)
                .is_err()
        );
        assert!(
            fixture
                .registry
                .register(
                    fixture.owner.clone(),
                    fixture.binding.clone(),
                    now + Duration::from_secs(61),
                    now
                )
                .is_err()
        );
        assert!(fixture.registry.live.is_empty());
    }

    #[test]
    fn uncertain_creation_and_unreleased_disposal_hold_capacity_and_identity() {
        let now = Instant::now();
        let mut fixture = fixture(1, 2, false);
        fixture
            .registry
            .register(
                fixture.owner.clone(),
                fixture.binding.clone(),
                now + Duration::from_secs(30),
                now,
            )
            .expect("first");
        fixture
            .registry
            .for_create(&fixture.owner, now)
            .expect("exposure");
        let released = ContextEgressReleaseReceipt::new(fixture.binding.request().clone(), 19, 23)
            .expect("release");
        assert_eq!(
            fixture.registry.confirm_released(released.clone()),
            Err(OwnerActorError::OutcomeUncertain)
        );
        let (second, second_binding) = sibling(&fixture, TenantId::new(), 2);
        assert_eq!(
            fixture.registry.register(
                second.clone(),
                second_binding.clone(),
                now + Duration::from_secs(30),
                now
            ),
            Err(OwnerActorError::StateOverflow)
        );
        fixture.registry.activated(&fixture.owner).expect("active");
        fixture
            .registry
            .disposed(&fixture.owner)
            .expect("Chromium absence proof");
        assert_eq!(
            fixture.registry.register(
                second.clone(),
                second_binding.clone(),
                now + Duration::from_secs(30),
                now
            ),
            Err(OwnerActorError::StateOverflow)
        );
        fixture
            .registry
            .confirm_released(released.clone())
            .expect("drained release");
        fixture
            .registry
            .confirm_released(released)
            .expect("lost reply retry");
        assert!(
            fixture
                .registry
                .register(
                    fixture.owner.clone(),
                    fixture.binding.clone(),
                    now + Duration::from_secs(30),
                    now
                )
                .is_err(),
            "retired ID cannot revive"
        );
        fixture
            .registry
            .register(second, second_binding, now + Duration::from_secs(30), now)
            .expect("capacity only after positive release");
        assert_eq!(fixture.registry.registered, 2);
    }

    #[test]
    fn closing_and_retired_bootstrap_requires_full_pinned_owner_and_route() {
        use crate::chromium_owner::{ChromiumTargetRoute, DocumentLoadState, NetworkActivity};
        use browserd_targets::{BootstrapDisposition, PausedTarget, TargetKind};
        use std::collections::BTreeSet;
        let fixture = fixture(8, 500, false);
        let shard = fixture.launch.dedicated_egress().egress_fence().shard();
        for kind in [
            TargetKind::Iframe,
            TargetKind::SharedWorker,
            TargetKind::ServiceWorker,
        ] {
            let route = TargetRouteEntry {
                route: ChromiumTargetRoute {
                    session_id: "flat-exact".to_owned(),
                    browser_context_id: "context-exact".to_owned(),
                    tenant_id: fixture.owner.tenant_id.clone(),
                    owner_session_id: fixture.owner.session_id.clone(),
                    ownership_fence: fixture.owner.fence.clone(),
                },
                kind: kind.clone(),
                page_id: None,
                target_incarnation: 7,
                frame_document_epoch: 5,
                url_revision: 3,
                document: DocumentLoadState::default(),
                network: NetworkActivity::quiet_at(Instant::now()),
            };
            let mut context = ContextEntry {
                checkpoint_restore_available: false,
                ownership: fixture.owner.clone(),
                options: None,
                emulation_owner_target_id: None,
                lifecycle: ContextLifecycle::DisposeRequested,
                pages: BTreeMap::new(),
                closing_pages: BTreeSet::new(),
            };
            let target = PausedTarget::new("target-exact", kind.clone());
            let mut snapshot = WorkerDisposalSnapshot {
                ownership: fixture.owner.clone(),
                targets: BTreeMap::from([(
                    "target-exact".to_owned(),
                    route.admission_target("target-exact"),
                )]),
                pending_pages: BTreeMap::new(),
            };
            assert_eq!(
                classify_bootstrap(
                    &target,
                    Some(&route),
                    Some(&context),
                    Some(&snapshot),
                    None,
                    None,
                    shard
                ),
                Ok(BootstrapDisposition::OwnedClosing)
            );
            let prior = snapshot.ownership.clone();
            snapshot.ownership.tenant_id = TenantId::new();
            assert_eq!(
                classify_bootstrap(
                    &target,
                    Some(&route),
                    Some(&context),
                    Some(&snapshot),
                    None,
                    None,
                    shard
                ),
                Err(OwnerActorError::UnknownOwnership)
            );
            snapshot.ownership = prior;
            snapshot
                .targets
                .get_mut("target-exact")
                .expect("target")
                .target_incarnation += 1;
            assert!(
                classify_bootstrap(
                    &target,
                    Some(&route),
                    Some(&context),
                    Some(&snapshot),
                    None,
                    None,
                    shard
                )
                .is_err()
            );
            context.lifecycle = ContextLifecycle::Active;
            assert_eq!(
                classify_bootstrap(
                    &target,
                    Some(&route),
                    Some(&context),
                    None,
                    None,
                    None,
                    shard
                ),
                Ok(BootstrapDisposition::Completed)
            );
            let mut retired = RetiredOwnerTarget {
                target: route.admission_target("target-exact"),
                ownership: fixture.owner.clone(),
            };
            let flat = retired.target.flattened_session_id.clone();
            assert_eq!(
                classify_bootstrap(
                    &target,
                    None,
                    None,
                    None,
                    Some(&retired),
                    Some(&flat),
                    shard
                ),
                Ok(BootstrapDisposition::OwnedRetired)
            );
            retired.ownership.fence =
                OwnershipFence::new(fixture.owner.fence.worker_id().clone(), 12, 7, 3);
            assert!(
                classify_bootstrap(
                    &target,
                    None,
                    None,
                    None,
                    Some(&retired),
                    Some(&flat),
                    shard
                )
                .is_err()
            );
            assert!(
                classify_bootstrap(&target, None, None, None, None, Some(&flat), shard).is_err(),
                "bare ID tombstone is not authority"
            );
        }
    }

    #[test]
    fn tenant_policy_is_exact_and_limits_are_bounded() {
        let tenant = TenantId::new();
        let policy = OwnerContextPolicy::tenant_dedicated(tenant.clone(), 8, 32)
            .expect("bounded tenant policy");
        assert!(policy.allows_tenant(&tenant));
        assert!(!policy.allows_tenant(&TenantId::new()));
        assert_eq!(policy.isolation(), IsolationProfile::TenantDedicatedShard);
        assert!(OwnerContextPolicy::shared(9, 32).is_err());
        assert!(OwnerContextPolicy::shared(8, 7).is_err());
        assert!(OwnerContextPolicy::shared(8, MAX_LIFETIME_CONTEXTS + 1).is_err());
        assert_eq!(OwnerContextPolicy::dedicated().max_lifetime_contexts(), 1);
    }
}
