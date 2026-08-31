use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::Duration;

use async_trait::async_trait;
use browserd_chromium::{ChromiumArtifactIdentity, ChromiumConnectionConfig};
use browserd_core::{
    EgressFence, IsolationProfile, LaunchGeneration, OwnerFence, RouteGeneration, SessionId,
    SessionIncarnation, ShardFence, ShardId, TenantId, WorkerEpoch, WorkerId,
};
use browserd_sandbox::{
    DedicatedEgressSpec, EgressPolicyBinding, LaunchSpec, MAX_DEDICATED_EGRESS_LEASE_TTL,
    SandboxRpcClient, SandboxRpcError,
};
use browserd_session::OwnershipFence;
use browserd_worker::{
    ActorChromiumDriver, BrowserShardActor, BrowserShardActorConfig, ChromiumConnectionOwner,
    ChromiumDriver, ChromiumDriverShardRuntime, DependencyError, ProductionSandboxShardRuntime,
    SandboxShardRpc, ShardActorError, ShardLaunchDescriptor, ShardRuntimeError,
    TargetManagedShardRuntime, TargetManagerDrain,
};
use tokio::runtime::Handle;
use tokio::task::JoinHandle;

use crate::{ProvisionedSessionShard, SessionShardFactory, SessionShardLifecycle};

const TARGET_EVENT_CAPACITY: usize = 256;
const ACTOR_MAILBOX_CAPACITY: usize = 64;

#[async_trait]
pub trait ProductionSandboxControl: SandboxShardRpc {
    async fn probe_daemon_epoch(
        &self,
        worker_id: &WorkerId,
        worker_epoch: u64,
    ) -> Result<u64, ShardRuntimeError>;
}

#[async_trait]
impl ProductionSandboxControl for SandboxRpcClient {
    async fn probe_daemon_epoch(
        &self,
        worker_id: &WorkerId,
        worker_epoch: u64,
    ) -> Result<u64, ShardRuntimeError> {
        SandboxRpcClient::probe_daemon_epoch(self, worker_id, worker_epoch)
            .await
            .map_err(|error| match error {
                SandboxRpcError::InvalidConfig | SandboxRpcError::InvalidLease => {
                    ShardRuntimeError::Rejected
                }
                _ => ShardRuntimeError::OutcomeUncertain,
            })
    }
}

#[derive(Clone)]
pub struct ProductionSessionShardConfig {
    worker_id: WorkerId,
    worker_epoch: u64,
    sandbox_daemon_epoch: u64,
    chromium_identity: ChromiumArtifactIdentity,
    chromium_connection: ChromiumConnectionConfig,
    egress_policy: EgressPolicyBinding,
    owner_lease_ttl: Duration,
}

impl ProductionSessionShardConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        worker_id: WorkerId,
        worker_epoch: u64,
        sandbox_daemon_epoch: u64,
        chromium_identity: ChromiumArtifactIdentity,
        chromium_connection: ChromiumConnectionConfig,
        egress_policy: EgressPolicyBinding,
        owner_lease_ttl: Duration,
    ) -> Result<Self, DependencyError> {
        if worker_epoch == 0
            || sandbox_daemon_epoch == 0
            || owner_lease_ttl.is_zero()
            || owner_lease_ttl > MAX_DEDICATED_EGRESS_LEASE_TTL
            || !chromium_connection.is_valid()
            || chromium_identity.validate().is_err()
        {
            return Err(DependencyError::Rejected);
        }
        Ok(Self {
            worker_id,
            worker_epoch,
            sandbox_daemon_epoch,
            chromium_identity,
            chromium_connection,
            egress_policy,
            owner_lease_ttl,
        })
    }
}

pub struct ProductionSessionShardFactory<B> {
    config: ProductionSessionShardConfig,
    sandbox: Arc<B>,
    runtime: Handle,
    qualification: OnceLock<Result<(), DependencyError>>,
}

impl<B> ProductionSessionShardFactory<B> {
    #[must_use]
    pub fn new(config: ProductionSessionShardConfig, sandbox: Arc<B>, runtime: Handle) -> Self {
        Self {
            config,
            sandbox,
            runtime,
            qualification: OnceLock::new(),
        }
    }
}

struct ShardDrainState(AtomicBool);

impl TargetManagerDrain for ShardDrainState {
    fn begin_drain(&self) {
        self.0.store(true, Ordering::Release);
    }
}

struct ProductionSessionShardLifecycle<B> {
    expected_fence: OwnershipFence,
    shard_fence: ShardFence,
    lease_ttl: Duration,
    sandbox: Arc<B>,
    runtime: Handle,
    actor: BrowserShardActor,
    driver: Arc<dyn ChromiumDriver>,
    drain: Arc<ShardDrainState>,
    ownership: Mutex<LifecycleOwnership>,
    changed: Condvar,
}

struct LifecycleOwnership {
    phase: LifecyclePhase,
    task: Option<JoinHandle<Result<(), ShardRuntimeError>>>,
}

#[derive(Clone, Copy)]
enum LifecyclePhase {
    Active,
    Terminating,
    Terminated(Result<(), DependencyError>),
}

impl<B> SessionShardLifecycle for ProductionSessionShardLifecycle<B>
where
    B: ProductionSandboxControl,
{
    fn qualify(&self) -> Result<(), DependencyError> {
        if self.drain.0.load(Ordering::Acquire) {
            return Err(DependencyError::OutcomeUncertain);
        }
        let ownership = self
            .ownership
            .lock()
            .map_err(|_| DependencyError::Unavailable)?;
        if !matches!(ownership.phase, LifecyclePhase::Active) {
            return Err(DependencyError::Rejected);
        }
        drop(ownership);
        self.driver.qualify()
    }

    fn heartbeat(&self) -> Result<(), DependencyError> {
        self.qualify()?;
        let result = self.runtime.block_on(self.sandbox.renew_owner_lease(
            self.shard_fence.shard_id(),
            self.shard_fence.owner().worker_epoch().get(),
            self.shard_fence.launch_generation(),
            self.lease_ttl,
        ));
        result.map_err(map_runtime_error)
    }

    fn terminate(&self, fence: &OwnershipFence) -> Result<(), DependencyError> {
        if fence != &self.expected_fence {
            return Err(DependencyError::Rejected);
        }
        let task = {
            let mut ownership = self
                .ownership
                .lock()
                .map_err(|_| DependencyError::Unavailable)?;
            loop {
                match ownership.phase {
                    LifecyclePhase::Active => {
                        ownership.phase = LifecyclePhase::Terminating;
                        break ownership.task.take();
                    }
                    LifecyclePhase::Terminating => {
                        ownership = self
                            .changed
                            .wait(ownership)
                            .map_err(|_| DependencyError::Unavailable)?;
                    }
                    LifecyclePhase::Terminated(result) => return result,
                }
            }
        };
        let actor = self.actor.clone();
        let shard_fence = self.shard_fence.clone();
        let result = self.runtime.block_on(async move {
            let shutdown = actor.shutdown(&shard_fence).await.map_err(map_actor_error);
            let joined = match task {
                Some(task) => task
                    .await
                    .map_err(|_| ShardRuntimeError::OutcomeUncertain)
                    .and_then(|result| result),
                None => Err(ShardRuntimeError::OutcomeUncertain),
            };
            shutdown.and(joined)
        });
        let result = result.map_err(map_runtime_error);
        let mut ownership = self
            .ownership
            .lock()
            .map_err(|_| DependencyError::OutcomeUncertain)?;
        ownership.phase = LifecyclePhase::Terminated(result);
        self.changed.notify_all();
        result
    }
}

impl<B> SessionShardFactory for ProductionSessionShardFactory<B>
where
    B: ProductionSandboxControl,
{
    fn qualify_daemon(&self) -> Result<(), DependencyError> {
        *self.qualification.get_or_init(|| {
            self.probe_daemon()?;
            let tenant_id = TenantId::new();
            let session_id = SessionId::new();
            let fence = OwnershipFence::new(
                self.config.worker_id.clone(),
                self.config.worker_epoch,
                1,
                1,
            );
            let shard = self.create_provisioned(&tenant_id, &session_id, &fence)?;
            shard.lifecycle().terminate(&fence)
        })
    }

    fn heartbeat_daemon(
        &self,
        worker_id: &WorkerId,
        worker_epoch: u64,
    ) -> Result<(), DependencyError> {
        if worker_id != &self.config.worker_id || worker_epoch != self.config.worker_epoch {
            return Err(DependencyError::Rejected);
        }
        match self.qualification.get().copied() {
            Some(Ok(())) => {}
            Some(Err(error)) => return Err(error),
            None => return Err(DependencyError::Rejected),
        }
        self.probe_daemon()
    }

    fn create(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        fence: &OwnershipFence,
    ) -> Result<ProvisionedSessionShard, DependencyError> {
        match self.qualification.get().copied() {
            Some(Ok(())) => self.create_provisioned(tenant_id, session_id, fence),
            Some(Err(error)) => Err(error),
            None => Err(DependencyError::Rejected),
        }
    }
}

impl<B> ProductionSessionShardFactory<B>
where
    B: ProductionSandboxControl,
{
    fn create_provisioned(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        fence: &OwnershipFence,
    ) -> Result<ProvisionedSessionShard, DependencyError> {
        if fence.worker_id() != &self.config.worker_id
            || fence.worker_epoch() != self.config.worker_epoch
            || fence.placement_version() == 0
            || fence.session_incarnation() == 0
        {
            return Err(DependencyError::Rejected);
        }
        let worker_epoch =
            WorkerEpoch::new(self.config.worker_epoch).ok_or(DependencyError::Rejected)?;
        let launch_generation = LaunchGeneration::new(1).ok_or(DependencyError::Rejected)?;
        let shard_fence = ShardFence::new(
            OwnerFence::new(self.config.worker_id.clone(), worker_epoch),
            ShardId::new(),
            launch_generation,
        );
        let egress_fence = EgressFence::new(
            shard_fence.clone(),
            RouteGeneration::new(1).ok_or(DependencyError::Rejected)?,
            session_id.clone(),
            SessionIncarnation::new(fence.session_incarnation())
                .ok_or(DependencyError::Rejected)?,
        );
        let dedicated_egress = DedicatedEgressSpec::new(
            egress_fence,
            self.config.egress_policy.clone(),
            self.config.owner_lease_ttl,
        )
        .map_err(|_| DependencyError::Rejected)?;
        let launch_spec = LaunchSpec::production(
            tenant_id.clone(),
            dedicated_egress,
            self.config.chromium_identity.binary_digest.into(),
        );
        let descriptor = ShardLaunchDescriptor::new(
            launch_spec,
            shard_fence.clone(),
            "standard",
            "dedicated_process",
        )
        .map_err(map_runtime_error)?;
        let drain = Arc::new(ShardDrainState(AtomicBool::new(false)));
        let (owner, targets) = ChromiumConnectionOwner::new_bounded(
            self.config.chromium_identity.clone(),
            self.config.chromium_connection.clone(),
            shard_fence.clone(),
            TARGET_EVENT_CAPACITY,
            Arc::clone(&drain),
        )
        .map_err(map_runtime_error)?;
        let cdp_driver = Arc::new(owner.chromium_driver(IsolationProfile::DedicatedProcess));
        let driver_runtime = Arc::new(ChromiumDriverShardRuntime::new(Arc::clone(&cdp_driver)));
        let target_runtime = Arc::new(TargetManagedShardRuntime::new(
            Arc::clone(&driver_runtime),
            targets,
        ));
        let sandbox_runtime = Arc::new(ProductionSandboxShardRuntime::new(
            descriptor,
            self.config.owner_lease_ttl,
            Arc::clone(&self.sandbox),
            owner,
            target_runtime,
        ));
        let actor_config =
            BrowserShardActorConfig::new(shard_fence.clone(), ACTOR_MAILBOX_CAPACITY, 1, 1)
                .map_err(map_actor_error)
                .map_err(map_runtime_error)?;
        let (actor, task) = {
            let _runtime = self.runtime.enter();
            BrowserShardActor::spawn(actor_config, sandbox_runtime)
        };
        let activation = self.runtime.block_on(actor.activate(&shard_fence));
        if let Err(error) = activation {
            let cleanup = self.runtime.block_on(async {
                let shutdown = actor.shutdown(&shard_fence).await;
                let joined = task.await;
                shutdown.map_err(map_actor_error).and(
                    joined
                        .map_err(|_| ShardRuntimeError::OutcomeUncertain)
                        .and_then(|result| result),
                )
            });
            return Err(if cleanup.is_ok() {
                map_runtime_error(map_actor_error(error))
            } else {
                DependencyError::OutcomeUncertain
            });
        }
        let actor_driver = Arc::new(ActorChromiumDriver::new(
            Arc::clone(&driver_runtime),
            actor.clone(),
            shard_fence.clone(),
        ));
        let primary_page_id = match actor_driver.create_context_owned(tenant_id, session_id, fence)
        {
            Ok(page_id) => page_id,
            Err(error) => {
                let cleanup = self.runtime.block_on(async {
                    let shutdown = actor.shutdown(&shard_fence).await;
                    let joined = task.await;
                    shutdown.map_err(map_actor_error).and(
                        joined
                            .map_err(|_| ShardRuntimeError::OutcomeUncertain)
                            .and_then(|result| result),
                    )
                });
                return Err(if cleanup.is_ok() {
                    error
                } else {
                    DependencyError::OutcomeUncertain
                });
            }
        };
        let driver: Arc<dyn ChromiumDriver> = actor_driver;
        let lifecycle: Arc<dyn SessionShardLifecycle> = Arc::new(ProductionSessionShardLifecycle {
            expected_fence: fence.clone(),
            shard_fence,
            lease_ttl: self.config.owner_lease_ttl,
            sandbox: Arc::clone(&self.sandbox),
            runtime: self.runtime.clone(),
            actor,
            driver: Arc::clone(&driver),
            drain,
            ownership: Mutex::new(LifecycleOwnership {
                phase: LifecyclePhase::Active,
                task: Some(task),
            }),
            changed: Condvar::new(),
        });
        Ok(ProvisionedSessionShard::new(
            primary_page_id,
            driver,
            lifecycle,
        ))
    }

    fn probe_daemon(&self) -> Result<(), DependencyError> {
        let observed = self.runtime.block_on(
            self.sandbox
                .probe_daemon_epoch(&self.config.worker_id, self.config.worker_epoch),
        );
        match observed {
            Ok(epoch) if epoch == self.config.sandbox_daemon_epoch => Ok(()),
            Ok(_) => Err(DependencyError::Rejected),
            Err(error) => Err(map_runtime_error(error)),
        }
    }
}

fn map_actor_error(error: ShardActorError) -> ShardRuntimeError {
    match error {
        ShardActorError::Runtime(error) => error,
        ShardActorError::StaleShardFence
        | ShardActorError::StaleSessionFence
        | ShardActorError::InvalidConfiguration
        | ShardActorError::InvalidLifecycle
        | ShardActorError::AdmissionClosed
        | ShardActorError::SessionNotFound => ShardRuntimeError::Rejected,
        ShardActorError::CapacityExceeded
        | ShardActorError::MailboxFull
        | ShardActorError::OwnershipLost
        | ShardActorError::ActorStopped => ShardRuntimeError::OutcomeUncertain,
    }
}

fn map_runtime_error(error: ShardRuntimeError) -> DependencyError {
    match error {
        ShardRuntimeError::Rejected => DependencyError::Rejected,
        ShardRuntimeError::Unavailable | ShardRuntimeError::Cancelled => {
            DependencyError::Unavailable
        }
        ShardRuntimeError::OutcomeUncertain => DependencyError::OutcomeUncertain,
    }
}
