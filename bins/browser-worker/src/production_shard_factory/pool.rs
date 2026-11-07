//! Bounded, worker-local reuse. A session owns a context; the pool owns the Chromium process.

use std::collections::HashMap;

use super::*;
use browserd_core::PageId;

const MAX_SHARDS: usize = 256;
const MAX_ROUTE_LIFETIME: u64 = 500;

#[derive(Clone, Copy)]
pub(super) struct PoolLaunch {
    pub isolation: WorkerIsolationProfile,
    pub max_live: usize,
    pub max_lifetime: u64,
}

impl PoolLaunch {
    pub fn core_isolation(self) -> IsolationProfile {
        match self.isolation {
            WorkerIsolationProfile::TenantDedicatedShard => IsolationProfile::TenantDedicatedShard,
            _ => IsolationProfile::SharedContext,
        }
    }
    pub fn isolation_name(self) -> &'static str {
        match self.isolation {
            WorkerIsolationProfile::TenantDedicatedShard => "tenant_dedicated_shard",
            _ => "shared_context",
        }
    }
    pub fn owner_policy(
        self,
        tenant: &TenantId,
    ) -> Result<browserd_worker::OwnerContextPolicy, DependencyError> {
        browserd_worker::OwnerContextPolicy::new(
            self.core_isolation(),
            self.max_live,
            self.max_lifetime,
            (self.isolation == WorkerIsolationProfile::TenantDedicatedShard)
                .then(|| tenant.clone()),
        )
        .map_err(map_runtime_error)
    }
}

/// A factory's artifact, sandbox and network policy are immutable. This key covers the
/// remaining process-affecting options; viewport/timeouts/metadata remain per context.
#[derive(Clone, Debug, Eq, PartialEq)]
struct CompatibilityKey {
    isolation: WorkerIsolationProfile,
    tenant: Option<TenantId>,
    locale: String,
    timezone: String,
    user_agent: Option<String>,
    network_class: String,
    network_policy: String,
    feature_profile: String,
    dialog_policy: String,
}

impl CompatibilityKey {
    fn new(
        tenant: &TenantId,
        options: &WorkerSessionOptionsV1,
        isolation: WorkerIsolationProfile,
    ) -> Self {
        Self {
            isolation,
            tenant: (isolation == WorkerIsolationProfile::TenantDedicatedShard)
                .then(|| tenant.clone()),
            locale: options.locale.clone(),
            timezone: options.timezone.clone(),
            user_agent: options.user_agent.clone(),
            network_class: options.network_class.clone(),
            network_policy: options.network_policy_id.clone(),
            feature_profile: options.feature_profile.clone(),
            dialog_policy: options.dialog_policy.clone(),
        }
    }
}

pub(super) struct SharedShardPool<B> {
    // Only creation is serialized. Session actions never acquire this gate. Holding it across
    // startup makes concurrent first requests join one shard without a speculative overlaunch.
    create_gate: Mutex<()>,
    state: Mutex<PoolInventory<B>>,
}
struct PoolInventory<B> {
    occupied: usize,
    shards: Vec<Arc<PooledShard<B>>>,
}
impl<B> Default for SharedShardPool<B> {
    fn default() -> Self {
        Self {
            create_gate: Mutex::new(()),
            state: Mutex::new(PoolInventory {
                occupied: 0,
                shards: Vec::new(),
            }),
        }
    }
}

struct PooledShard<B> {
    key: CompatibilityKey,
    limits: PoolLaunch,
    max_age: Duration,
    created_at: Instant,
    common: Arc<ProductionSessionShardLifecycle<B>>,
    driver: Arc<ActorChromiumDriver<CdpChromiumDriver>>,
    backend: ChromiumTargetManagerBackend,
    launch: LaunchSpec,
    expected_sandbox_epoch: u64,
    state: Mutex<PooledState>,
    runtime_safety: Option<Arc<browserd_core::RuntimeSafetyCache>>,
    runtime_generation: Option<browserd_core::RuntimeSafetyGeneration>,
    chromium_digest: String,
}

struct Member {
    tenant: TenantId,
    fence: OwnershipFence,
    request: ContextEgressRequest,
    binding: Option<ContextEgressBinding>,
}

struct PooledState {
    members: HashMap<SessionId, Member>,
    closed: HashMap<SessionId, OwnershipFence>,
    attempts: u64,
    draining: bool,
    terminated: Option<Result<(), DependencyError>>,
}

struct PooledSessionLifecycle<B> {
    shard: Arc<PooledShard<B>>,
    session: SessionId,
    fence: OwnershipFence,
}

impl<B: ProductionSandboxControl> PooledShard<B> {
    fn apply_runtime_policy(&self, state: &mut PooledState) -> Result<(), DependencyError> {
        let Some(cache) = &self.runtime_safety else {
            return Ok(());
        };
        let compatible = self
            .runtime_generation
            .as_ref()
            .is_none_or(|generation| !generation.cancellation_token().is_cancelled())
            && cache
                .with_fresh_snapshot(|snapshot| {
                    !snapshot.force_dedicated_process()
                        && self.limits.max_live <= usize::from(snapshot.max_contexts_per_shard())
                        && !snapshot.chromium_build_disabled(&self.chromium_digest)
                        && !snapshot.network_class_stopped(&self.key.network_class)
                })
                .unwrap_or(false);
        if !compatible && !state.draining && state.terminated.is_none() {
            state.draining = true;
            self.common
                .runtime
                .block_on(self.common.actor.begin_draining(&self.common.shard_fence))
                .map_err(map_actor_error)
                .map_err(map_runtime_error)?;
        }
        Ok(())
    }
    fn stop(&self, state: &mut PooledState) -> Result<(), DependencyError> {
        state.draining = true;
        if let Some(result) = state.terminated {
            return result;
        }
        let result = self.common.terminate(&self.common.expected_fence);
        if result.is_ok() {
            for (session, member) in state.members.drain() {
                state.closed.insert(session, member.fence);
            }
        }
        state.terminated = Some(result);
        result
    }

    fn provision(
        self: &Arc<Self>,
        session: &SessionId,
        fence: &OwnershipFence,
        page: PageId,
    ) -> ProvisionedSessionShard {
        ProvisionedSessionShard::with_isolation(
            page,
            self.driver.clone(),
            Arc::new(PooledSessionLifecycle {
                shard: Arc::clone(self),
                session: session.clone(),
                fence: fence.clone(),
            }),
            self.key.isolation,
        )
    }

    fn attach(
        self: &Arc<Self>,
        tenant: &TenantId,
        session: &SessionId,
        fence: &OwnershipFence,
        options: &WorkerSessionOptionsV1,
    ) -> Result<Option<ProvisionedSessionShard>, DependencyError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| DependencyError::Unavailable)?;
        self.apply_runtime_policy(&mut state)?;
        if state.draining || state.terminated.is_some() {
            return Ok(None);
        }
        if self.created_at.elapsed() >= self.max_age || state.attempts >= self.limits.max_lifetime {
            state.draining = true;
            self.common
                .runtime
                .block_on(self.common.actor.begin_draining(&self.common.shard_fence))
                .map_err(map_actor_error)
                .map_err(map_runtime_error)?;
            return Ok(None);
        }
        if state.members.len() >= self.limits.max_live {
            return Ok(None);
        }
        if state.members.contains_key(session) || state.closed.contains_key(session) {
            return Err(DependencyError::Rejected);
        }
        state.attempts = state
            .attempts
            .checked_add(1)
            .ok_or(DependencyError::OutcomeUncertain)?;
        let egress = EgressFence::new(
            self.common.shard_fence.clone(),
            RouteGeneration::new(state.attempts).ok_or(DependencyError::OutcomeUncertain)?,
            session.clone(),
            SessionIncarnation::new(fence.session_incarnation())
                .ok_or(DependencyError::Rejected)?,
        );
        let request = ContextEgressRequest::new(
            tenant.clone(),
            fence.as_placement_fence(),
            DedicatedEgressSpec::new(
                egress,
                self.launch.dedicated_egress().policy_binding().clone(),
                self.common.lease_ttl,
            )
            .map_err(|_| DependencyError::Rejected)?,
        )
        .map_err(|_| DependencyError::Rejected)?;
        // Ownership is recorded before the first route effect. A failed attach may have installed
        // a listener, so the original request must survive even without its response.
        state.members.insert(
            session.clone(),
            Member {
                tenant: tenant.clone(),
                fence: fence.clone(),
                request: request.clone(),
                binding: None,
            },
        );
        let attempt = (|| {
            let started = Instant::now();
            let binding = self
                .common
                .runtime
                .block_on(self.common.sandbox.attach_context_egress(&request))
                .map_err(map_runtime_error)?;
            if binding.request() != &request
                || binding.sandboxd_epoch() != self.expected_sandbox_epoch
                || binding.validate().is_err()
            {
                return Err(DependencyError::OutcomeUncertain);
            }
            let valid_until = started
                .checked_add(binding.granted_ttl())
                .ok_or(DependencyError::OutcomeUncertain)?;
            state
                .members
                .get_mut(session)
                .ok_or(DependencyError::OutcomeUncertain)?
                .binding = Some(binding.clone());
            self.backend
                .register_context_egress(
                    tenant.clone(),
                    session.clone(),
                    fence.clone(),
                    binding,
                    valid_until,
                )
                .map_err(map_runtime_error)?;
            self.driver
                .create_context_owned_with_options(tenant, session, fence, options)
        })();
        match attempt {
            Ok(page) => {
                if self.apply_runtime_policy(&mut state).is_err() {
                    let _ = self.stop(&mut state);
                    return Err(DependencyError::OutcomeUncertain);
                }
                if state.draining {
                    let cleanup = self.dispose_member(session, fence, &request);
                    if cleanup.is_ok() {
                        state.members.remove(session);
                        state.closed.insert(session.clone(), fence.clone());
                        if state.members.is_empty() {
                            self.stop(&mut state)?;
                        }
                        return Err(DependencyError::Rejected);
                    }
                    let _ = self.stop(&mut state);
                    return Err(DependencyError::OutcomeUncertain);
                }
                if state.attempts >= self.limits.max_lifetime {
                    state.draining = true;
                }
                Ok(Some(self.provision(session, fence, page)))
            }
            Err(error) => {
                // Bootstrap uncertainty can leave an unregistered browser context. Terminating
                // this shard proves cleanup without guessing whether creation took effect.
                let cleanup = self.stop(&mut state);
                Err(if cleanup.is_ok() {
                    error
                } else {
                    DependencyError::OutcomeUncertain
                })
            }
        }
    }

    fn close(&self, session: &SessionId, fence: &OwnershipFence) -> Result<(), DependencyError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| DependencyError::Unavailable)?;
        if let Some(closed) = state.closed.get(session) {
            return if closed == fence {
                Ok(())
            } else {
                Err(DependencyError::Rejected)
            };
        }
        let member = state
            .members
            .get(session)
            .ok_or(DependencyError::Rejected)?;
        if &member.fence != fence {
            return Err(DependencyError::Rejected);
        }
        let request = member.request.clone();
        let closed = self.dispose_member(session, fence, &request);
        if closed.is_err() {
            return self
                .stop(&mut state)
                .map_err(|_| DependencyError::OutcomeUncertain);
        }
        state.members.remove(session);
        state.closed.insert(session.clone(), fence.clone());
        if state.members.is_empty() {
            // The same gate guards attach, so this shard cannot be selected after empty shutdown.
            self.stop(&mut state)?;
        }
        Ok(())
    }

    fn dispose_member(
        &self,
        session: &SessionId,
        fence: &OwnershipFence,
        request: &ContextEgressRequest,
    ) -> Result<(), DependencyError> {
        // Only exact positive context absence and route-release proof frees this member.
        self.driver.close_context_fenced(session, fence)?;
        let receipt = self
            .common
            .runtime
            .block_on(self.common.sandbox.release_context_egress(request))
            .map_err(map_runtime_error)?;
        receipt
            .validate_for(request, self.expected_sandbox_epoch)
            .map_err(|_| DependencyError::OutcomeUncertain)?;
        self.backend
            .confirm_context_egress_released(receipt)
            .map_err(map_runtime_error)
    }

    fn heartbeat(&self) -> Result<(), DependencyError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| DependencyError::Unavailable)?;
        self.apply_runtime_policy(&mut state)?;
        if state.terminated.is_some() {
            return Err(DependencyError::Rejected);
        }
        let started = Instant::now();
        let renewal = self.common.heartbeat().and_then(|()| {
            for member in state.members.values() {
                let binding = member
                    .binding
                    .as_ref()
                    .ok_or(DependencyError::OutcomeUncertain)?;
                let valid_until = started
                    .checked_add(binding.granted_ttl().min(self.common.lease_ttl))
                    .ok_or(DependencyError::OutcomeUncertain)?;
                self.backend
                    .renew_context_egress(binding.clone(), valid_until)
                    .map_err(map_runtime_error)?;
            }
            Ok(())
        });
        if renewal.is_err() {
            let _ = self.stop(&mut state);
            return Err(DependencyError::OutcomeUncertain);
        }
        if self.created_at.elapsed() >= self.max_age && !state.draining {
            state.draining = true;
            self.common
                .runtime
                .block_on(self.common.actor.begin_draining(&self.common.shard_fence))
                .map_err(map_actor_error)
                .map_err(map_runtime_error)?;
        }
        Ok(())
    }
}

impl<B: ProductionSandboxControl> SessionShardLifecycle for PooledSessionLifecycle<B> {
    fn shard_fence(&self) -> Option<ShardFence> {
        Some(self.shard.common.shard_fence.clone())
    }
    fn qualify(&self) -> Result<(), DependencyError> {
        let observe_member = || {
            let state = self
                .shard
                .state
                .lock()
                .map_err(|_| DependencyError::Unavailable)?;
            let member = state
                .members
                .get(&self.session)
                .ok_or(DependencyError::Rejected)?;
            if state.terminated.is_some()
                || member.fence != self.fence
                || member.request.tenant_id() != &member.tenant
            {
                return Err(DependencyError::Rejected);
            }
            Ok((
                member.tenant.clone(),
                member.fence.clone(),
                member.request.clone(),
                member.binding.clone(),
            ))
        };
        let before = observe_member()?;
        // A blocked renderer must not hold the pool state needed by physical lease renewal.
        self.shard.common.qualify()?;
        if observe_member()? != before {
            return Err(DependencyError::Rejected);
        }
        Ok(())
    }
    fn heartbeat(&self) -> Result<(), DependencyError> {
        self.shard.heartbeat()
    }
    fn terminate(&self, fence: &OwnershipFence) -> Result<(), DependencyError> {
        if fence != &self.fence {
            return Err(DependencyError::Rejected);
        }
        self.shard.close(&self.session, fence)
    }
}

impl<B: ProductionSandboxControl> ProductionSessionShardFactory<B> {
    pub(super) fn create_pooled(
        &self,
        tenant: &TenantId,
        session: &SessionId,
        fence: &OwnershipFence,
        options: &WorkerSessionOptionsV1,
        isolation: WorkerIsolationProfile,
    ) -> Result<ProvisionedSessionShard, DependencyError> {
        if !options.is_valid()
            || options.network_policy_id != self.config.egress_policy.profile()
            || self.config.egress_policy.profile() != "public-web-default"
            || options.network_class != "public"
            || options.checkpoint_ref.is_some()
            || options.dialog_policy != "auto_dismiss"
            || !(options.feature_profile == "standard"
                || (options.feature_profile == "privileged" && self.config.privileged_evaluate))
            || fence.worker_id() != &self.config.worker_id
            || fence.worker_epoch() != self.config.worker_epoch
            || fence.placement_version() == 0
            || fence.session_incarnation() == 0
        {
            return Err(DependencyError::Rejected);
        }
        self.config
            .native_profiles
            .as_ref()
            .ok_or(DependencyError::Rejected)?
            .process_profile(&options.locale, &options.timezone)
            .map_err(|_| DependencyError::Rejected)?
            .with_user_agent(options.user_agent.clone())
            .map_err(|_| DependencyError::Rejected)?;
        if !matches!(
            *self
                .qualification
                .phase
                .lock()
                .map_err(|_| DependencyError::Unavailable)?,
            QualificationPhase::Terminal(Ok(()))
        ) {
            return Err(DependencyError::Rejected);
        }
        let policy = self
            .config
            .shared_context_policy
            .as_ref()
            .ok_or(DependencyError::Rejected)?;
        if policy.effective_isolation(tenant, isolation)? != isolation
            || policy.max_contexts_per_shard() <= 1
        {
            return Err(DependencyError::Rejected);
        }
        let runtime = self.runtime_snapshot(&options.network_class)?;
        let max_live = runtime
            .as_ref()
            .map_or(policy.max_contexts_per_shard(), |snapshot| {
                policy
                    .max_contexts_per_shard()
                    .min(usize::from(snapshot.max_contexts_per_shard()))
            });
        if max_live <= 1
            || runtime
                .as_ref()
                .is_some_and(|snapshot| snapshot.force_dedicated_process())
        {
            return Err(DependencyError::Rejected);
        }
        let limits = PoolLaunch {
            isolation,
            max_live,
            max_lifetime: policy
                .max_contexts_created_lifetime()
                .min(MAX_ROUTE_LIFETIME),
        };
        let runtime_generation = self
            .runtime_safety
            .as_ref()
            .map(|cache| cache.generation())
            .transpose()
            .map_err(|_| DependencyError::Unavailable)?;
        let key = CompatibilityKey::new(tenant, options, isolation);
        let _creation = self
            .pool
            .create_gate
            .lock()
            .map_err(|_| DependencyError::Unavailable)?;
        let candidates = {
            let mut inventory = self
                .pool
                .state
                .lock()
                .map_err(|_| DependencyError::Unavailable)?;
            let before = inventory.shards.len();
            inventory.shards.retain(|shard| {
                !shard
                    .state
                    .try_lock()
                    .is_ok_and(|state| state.terminated == Some(Ok(())))
            });
            inventory.occupied = inventory
                .occupied
                .saturating_sub(before - inventory.shards.len());
            inventory
                .shards
                .iter()
                .filter(|shard| shard.key == key)
                .cloned()
                .collect::<Vec<_>>()
        };
        for shard in candidates {
            if let Some(context) = shard.attach(tenant, session, fence, options)? {
                return Ok(context);
            }
        }
        {
            let mut inventory = self
                .pool
                .state
                .lock()
                .map_err(|_| DependencyError::Unavailable)?;
            if inventory.occupied >= MAX_SHARDS {
                return Err(DependencyError::Unavailable);
            }
            inventory.occupied += 1;
        }
        // Count qualification/startup against the process lifetime as well.
        let created_at = Instant::now();
        let started = match self.start_session_shard_with_deadline(
            tenant,
            session,
            fence,
            Some(options),
            None,
            Some(limits),
        ) {
            Ok(started) => started,
            Err(error) => {
                // Unknown cleanup remains charged even if a caller abandons this request.
                if error != DependencyError::OutcomeUncertain {
                    let mut inventory = self
                        .pool
                        .state
                        .lock()
                        .map_err(|_| DependencyError::OutcomeUncertain)?;
                    inventory.occupied = inventory.occupied.saturating_sub(1);
                }
                return Err(error);
            }
        };
        let binding = started
            .context_binding
            .ok_or(DependencyError::OutcomeUncertain)?;
        let mut members = HashMap::new();
        members.insert(
            session.clone(),
            Member {
                tenant: tenant.clone(),
                fence: fence.clone(),
                request: binding.request().clone(),
                binding: Some(binding),
            },
        );
        let page = started.provisioned.primary_page_id().clone();
        let shard = Arc::new(PooledShard {
            key,
            limits,
            max_age: policy.max_shard_age(),
            created_at,
            common: started.lifecycle,
            driver: started.probe_driver,
            backend: started.readiness,
            launch: started.launch_spec,
            expected_sandbox_epoch: self.config.sandbox_daemon_epoch,
            runtime_safety: self.runtime_safety.clone(),
            runtime_generation,
            chromium_digest: self.config.chromium_identity.binary_digest.to_string(),
            state: Mutex::new(PooledState {
                members,
                closed: HashMap::new(),
                attempts: 1,
                draining: false,
                terminated: None,
            }),
        });
        self.pool
            .state
            .lock()
            .map_err(|_| DependencyError::OutcomeUncertain)?
            .shards
            .push(Arc::clone(&shard));
        Ok(shard.provision(session, fence, page))
    }
}
