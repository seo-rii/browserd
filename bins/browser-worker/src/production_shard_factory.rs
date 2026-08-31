use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use browserd_chromium::{ChromiumArtifactIdentity, ChromiumConnectionConfig};
use browserd_core::{
    EgressFence, IsolationProfile, LaunchGeneration, OwnerFence, RouteGeneration, SessionId,
    SessionIncarnation, ShardFence, ShardId, TenantId, WorkerEpoch, WorkerId,
};
use browserd_sandbox::{
    CleanupReason, DedicatedEgressSpec, EgressPolicyBinding, LaunchSpec,
    MAX_DEDICATED_EGRESS_LEASE_TTL, SandboxRpcClient, SandboxRpcError,
};
use browserd_session::OwnershipFence;
use browserd_worker::{
    ActorChromiumDriver, BrowserShardActor, BrowserShardActorConfig, CdpChromiumDriver,
    ChromiumConnectionOwner, ChromiumDriver, ChromiumDriverShardRuntime,
    ChromiumTargetManagerBackend, DependencyError, ExactSandboxTermination,
    ProductionSandboxShardRuntime, SandboxShardRpc, ShardActorError, ShardLaunchDescriptor,
    ShardRuntimeError, TargetManagedShardRuntime, TargetManagerDrain, WorkerSessionOptionsV1,
};
use tokio::runtime::{Handle, RuntimeFlavor};
use tokio::task::JoinHandle;

use crate::{ProvisionedSessionShard, SessionShardFactory, SessionShardLifecycle};

const TARGET_EVENT_CAPACITY: usize = 256;
const ACTOR_MAILBOX_CAPACITY: usize = 64;
const DEFAULT_QUALIFICATION_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_QUALIFICATION_CLEANUP_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_QUALIFICATION_PHASE_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProductionQualificationBounds {
    qualification_timeout: Duration,
    cleanup_timeout: Duration,
}

impl ProductionQualificationBounds {
    pub fn new(
        qualification_timeout: Duration,
        cleanup_timeout: Duration,
    ) -> Result<Self, DependencyError> {
        if qualification_timeout.is_zero()
            || qualification_timeout > MAX_QUALIFICATION_PHASE_TIMEOUT
            || cleanup_timeout.is_zero()
            || cleanup_timeout > MAX_QUALIFICATION_PHASE_TIMEOUT
        {
            return Err(DependencyError::Rejected);
        }
        Ok(Self {
            qualification_timeout,
            cleanup_timeout,
        })
    }
}

impl Default for ProductionQualificationBounds {
    fn default() -> Self {
        Self {
            qualification_timeout: DEFAULT_QUALIFICATION_TIMEOUT,
            cleanup_timeout: DEFAULT_QUALIFICATION_CLEANUP_TIMEOUT,
        }
    }
}

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
    qualification_bounds: ProductionQualificationBounds,
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
            qualification_bounds: ProductionQualificationBounds::default(),
        })
    }

    #[must_use]
    pub fn with_qualification_bounds(mut self, bounds: ProductionQualificationBounds) -> Self {
        self.qualification_bounds = bounds;
        self
    }
}

pub struct ProductionSessionShardFactory<B> {
    config: ProductionSessionShardConfig,
    sandbox: Arc<B>,
    runtime: Handle,
    qualification: Arc<QualificationFlight>,
}

struct QualificationFlight {
    phase: Mutex<QualificationPhase>,
    changed: Condvar,
}

#[derive(Clone, Copy)]
enum QualificationPhase {
    Unstarted,
    Running,
    Terminal(Result<(), DependencyError>),
}

impl<B> Clone for ProductionSessionShardFactory<B> {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            sandbox: Arc::clone(&self.sandbox),
            runtime: self.runtime.clone(),
            qualification: Arc::clone(&self.qualification),
        }
    }
}

impl<B> ProductionSessionShardFactory<B> {
    pub fn new(
        config: ProductionSessionShardConfig,
        sandbox: Arc<B>,
        runtime: Handle,
    ) -> Result<Self, DependencyError> {
        if runtime.runtime_flavor() != RuntimeFlavor::MultiThread {
            return Err(DependencyError::Rejected);
        }
        Ok(Self {
            config,
            sandbox,
            runtime,
            qualification: Arc::new(QualificationFlight {
                phase: Mutex::new(QualificationPhase::Unstarted),
                changed: Condvar::new(),
            }),
        })
    }
}

struct StartedSessionShard {
    provisioned: ProvisionedSessionShard,
    probe_driver: Arc<ActorChromiumDriver<CdpChromiumDriver>>,
    readiness: ChromiumTargetManagerBackend,
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
    exact_termination: Arc<ExactSandboxTermination>,
    lease_ttl: Duration,
    sandbox: Arc<B>,
    connection_owner: Arc<ChromiumConnectionOwner<ShardDrainState>>,
    runtime: Handle,
    actor: BrowserShardActor,
    driver: Arc<dyn ChromiumDriver>,
    drain: Arc<ShardDrainState>,
    cleanup_timeout: Duration,
    coordination: Arc<LifecycleCoordination>,
}

struct LifecycleCoordination {
    ownership: Mutex<LifecycleOwnership>,
    changed: Condvar,
}

struct LifecycleOwnership {
    phase: LifecyclePhase,
    task: Option<JoinHandle<Result<(), ShardRuntimeError>>>,
    cleanup_owner: Option<std::thread::JoinHandle<()>>,
}

#[derive(Clone, Copy)]
enum LifecyclePhase {
    Active,
    Terminating,
    Completed(Result<(), DependencyError>),
    Joining,
    Terminated(Result<(), DependencyError>),
}

struct QualificationCleanupGuard {
    lifecycle: Option<Arc<dyn SessionShardLifecycle>>,
    fence: OwnershipFence,
}

type QualificationCleanupTask = (
    std::thread::JoinHandle<()>,
    mpsc::Receiver<Result<(), DependencyError>>,
);

impl QualificationCleanupGuard {
    fn new(lifecycle: Arc<dyn SessionShardLifecycle>, fence: OwnershipFence) -> Self {
        Self {
            lifecycle: Some(lifecycle),
            fence,
        }
    }

    fn finish(mut self, timeout: Duration) -> Result<(), DependencyError> {
        let lifecycle = self
            .lifecycle
            .take()
            .ok_or(DependencyError::OutcomeUncertain)?;
        let (task, receiver) = spawn_qualification_cleanup(lifecycle, self.fence.clone())?;
        match receiver.recv_timeout(timeout) {
            Ok(result) => match task.join() {
                Ok(()) => result,
                Err(_) => Err(DependencyError::OutcomeUncertain),
            },
            Err(_) => Err(DependencyError::OutcomeUncertain),
        }
    }
}

impl Drop for QualificationCleanupGuard {
    fn drop(&mut self) {
        if let Some(lifecycle) = self.lifecycle.take() {
            let _ = spawn_qualification_cleanup(lifecycle, self.fence.clone());
        }
    }
}

fn spawn_qualification_cleanup(
    lifecycle: Arc<dyn SessionShardLifecycle>,
    fence: OwnershipFence,
) -> Result<QualificationCleanupTask, DependencyError> {
    let (sender, receiver) = mpsc::sync_channel(1);
    let task = std::thread::Builder::new()
        .name("browserd-readiness-cleanup".to_owned())
        .spawn(move || {
            let result = lifecycle.terminate(&fence);
            let _ = sender.send(result);
        })
        .map_err(|_| DependencyError::OutcomeUncertain)?;
    Ok((task, receiver))
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
            .coordination
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
        let runtime_flavor = Handle::try_current()
            .ok()
            .map(|runtime| runtime.runtime_flavor());
        let mut ownership = self
            .coordination
            .ownership
            .lock()
            .map_err(|_| DependencyError::Unavailable)?;
        loop {
            match ownership.phase {
                LifecyclePhase::Active => {
                    let actor = self.actor.clone();
                    let shard_fence = self.shard_fence.clone();
                    let exact_termination = Arc::clone(&self.exact_termination);
                    let connection_owner = Arc::clone(&self.connection_owner);
                    let cleanup_timeout = self.cleanup_timeout;
                    let runtime = self.runtime.clone();
                    let coordination = Arc::clone(&self.coordination);
                    let (start_sender, start_receiver) = mpsc::sync_channel(1);
                    let cleanup_owner = std::thread::Builder::new()
                        .name("browserd-session-cleanup".to_owned())
                        .spawn(move || {
                            let Ok(task) = start_receiver.recv() else {
                                return;
                            };
                            let result = match catch_unwind(AssertUnwindSafe(|| {
                                runtime.block_on(async move {
                                    let deadline = tokio::time::Instant::now() + cleanup_timeout;
                                    let coordinated = tokio::time::timeout_at(deadline, async {
                                        let exact = async {
                                            let proof = exact_termination
                                                .terminate(CleanupReason::WorkerLeaseExpired)
                                                .await
                                                .map_err(|_| ShardRuntimeError::OutcomeUncertain);
                                            if let Ok(proof) = proof.as_ref() {
                                                connection_owner.confirm_forced_termination(proof);
                                            }
                                            proof
                                        };
                                        let local = async {
                                            let shutdown = actor
                                                .shutdown(&shard_fence)
                                                .await
                                                .map_err(map_actor_error);
                                            let joined = match task {
                                                Some(task) => Some(task.await),
                                                None => None,
                                            };
                                            (shutdown, joined)
                                        };
                                        tokio::join!(local, exact)
                                    })
                                    .await;
                                    let Ok(((shutdown, joined), exact)) = coordinated else {
                                        return Err(ShardRuntimeError::OutcomeUncertain);
                                    };
                                    if shutdown.is_ok() && matches!(joined, Some(Ok(Ok(())))) {
                                        return Ok(());
                                    }
                                    let Ok(proof) = exact else {
                                        return Err(ShardRuntimeError::OutcomeUncertain);
                                    };
                                    if joined.is_none() {
                                        return Err(ShardRuntimeError::OutcomeUncertain);
                                    }
                                    let remaining = deadline
                                        .saturating_duration_since(tokio::time::Instant::now());
                                    if remaining.is_zero() {
                                        return Err(ShardRuntimeError::OutcomeUncertain);
                                    }
                                    let owner_shutdown =
                                        connection_owner.shutdown_and_join(remaining).await;
                                    if owner_shutdown.is_ok()
                                        && connection_owner.is_terminally_joined_after(&proof)
                                    {
                                        Ok(())
                                    } else {
                                        Err(ShardRuntimeError::OutcomeUncertain)
                                    }
                                })
                            })) {
                                Ok(result) => result.map_err(map_runtime_error),
                                Err(_) => Err(DependencyError::OutcomeUncertain),
                            };
                            let mut ownership = match coordination.ownership.lock() {
                                Ok(ownership) => ownership,
                                Err(poisoned) => poisoned.into_inner(),
                            };
                            ownership.phase = LifecyclePhase::Completed(result);
                            coordination.changed.notify_all();
                        })
                        .map_err(|_| DependencyError::OutcomeUncertain)?;
                    ownership.phase = LifecyclePhase::Terminating;
                    let task = ownership.task.take();
                    if let Err(error) = start_sender.send(task) {
                        ownership.task = error.0;
                        ownership.phase = LifecyclePhase::Active;
                        drop(ownership);
                        let _ = cleanup_owner.join();
                        return Err(DependencyError::OutcomeUncertain);
                    }
                    ownership.cleanup_owner = Some(cleanup_owner);
                }
                LifecyclePhase::Terminating | LifecyclePhase::Joining => {
                    ownership = if matches!(runtime_flavor, Some(RuntimeFlavor::MultiThread)) {
                        tokio::task::block_in_place(|| self.coordination.changed.wait(ownership))
                    } else {
                        self.coordination.changed.wait(ownership)
                    }
                    .map_err(|_| DependencyError::Unavailable)?;
                }
                LifecyclePhase::Completed(result) => {
                    let Some(cleanup_owner) = ownership.cleanup_owner.take() else {
                        let result = Err(DependencyError::OutcomeUncertain);
                        ownership.phase = LifecyclePhase::Terminated(result);
                        self.coordination.changed.notify_all();
                        return result;
                    };
                    ownership.phase = LifecyclePhase::Joining;
                    drop(ownership);
                    let joined = if matches!(runtime_flavor, Some(RuntimeFlavor::MultiThread)) {
                        tokio::task::block_in_place(|| cleanup_owner.join())
                    } else {
                        cleanup_owner.join()
                    };
                    let result = if joined.is_ok() {
                        result
                    } else {
                        Err(DependencyError::OutcomeUncertain)
                    };
                    let mut ownership = match self.coordination.ownership.lock() {
                        Ok(ownership) => ownership,
                        Err(poisoned) => poisoned.into_inner(),
                    };
                    ownership.phase = LifecyclePhase::Terminated(result);
                    self.coordination.changed.notify_all();
                    return result;
                }
                LifecyclePhase::Terminated(result) => return result,
            }
        }
    }
}

impl<B> SessionShardFactory for ProductionSessionShardFactory<B>
where
    B: ProductionSandboxControl,
{
    fn qualify_daemon(&self) -> Result<(), DependencyError> {
        let mut phase = self
            .qualification
            .phase
            .lock()
            .map_err(|_| DependencyError::Unavailable)?;
        loop {
            match *phase {
                QualificationPhase::Terminal(result) => return result,
                QualificationPhase::Running => {
                    phase = self
                        .qualification
                        .changed
                        .wait(phase)
                        .map_err(|_| DependencyError::Unavailable)?;
                }
                QualificationPhase::Unstarted => {
                    *phase = QualificationPhase::Running;
                    let owner = ProductionSessionShardFactory::clone(self);
                    let qualification = Arc::clone(&self.qualification);
                    let task = std::thread::Builder::new()
                        .name("browserd-readiness-qualification".to_owned())
                        .spawn(move || {
                            let result =
                                catch_unwind(AssertUnwindSafe(|| owner.run_qualification()))
                                    .unwrap_or(Err(DependencyError::OutcomeUncertain));
                            let mut phase = match qualification.phase.lock() {
                                Ok(phase) => phase,
                                Err(poisoned) => poisoned.into_inner(),
                            };
                            *phase = QualificationPhase::Terminal(result);
                            qualification.changed.notify_all();
                        });
                    if task.is_err() {
                        *phase = QualificationPhase::Terminal(Err(DependencyError::Unavailable));
                        self.qualification.changed.notify_all();
                    }
                }
            }
        }
    }

    fn heartbeat_daemon(
        &self,
        worker_id: &WorkerId,
        worker_epoch: u64,
    ) -> Result<(), DependencyError> {
        if worker_id != &self.config.worker_id || worker_epoch != self.config.worker_epoch {
            return Err(DependencyError::Rejected);
        }
        let qualification = self
            .qualification
            .phase
            .lock()
            .map_err(|_| DependencyError::Unavailable)?;
        match *qualification {
            QualificationPhase::Terminal(Ok(())) => {}
            QualificationPhase::Terminal(Err(error)) => return Err(error),
            QualificationPhase::Unstarted | QualificationPhase::Running => {
                return Err(DependencyError::Rejected);
            }
        }
        drop(qualification);
        self.probe_daemon()
    }

    fn create(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        fence: &OwnershipFence,
    ) -> Result<ProvisionedSessionShard, DependencyError> {
        let qualification = self
            .qualification
            .phase
            .lock()
            .map_err(|_| DependencyError::Unavailable)?;
        match *qualification {
            QualificationPhase::Terminal(Ok(())) => {
                drop(qualification);
                self.create_provisioned(tenant_id, session_id, fence, None)
            }
            QualificationPhase::Terminal(Err(error)) => Err(error),
            QualificationPhase::Unstarted | QualificationPhase::Running => {
                Err(DependencyError::Rejected)
            }
        }
    }

    fn create_with_options(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        fence: &OwnershipFence,
        options: &WorkerSessionOptionsV1,
    ) -> Result<ProvisionedSessionShard, DependencyError> {
        if !options.is_valid()
            || options.network_policy_id.as_str() != self.config.egress_policy.profile()
            || options.network_class != "public"
            || options.checkpoint_ref.is_some()
            || options.dialog_policy != "auto_dismiss"
            || options.feature_profile != "standard"
        {
            return Err(DependencyError::Rejected);
        }
        let qualification = self
            .qualification
            .phase
            .lock()
            .map_err(|_| DependencyError::Unavailable)?;
        match *qualification {
            QualificationPhase::Terminal(Ok(())) => {
                drop(qualification);
                self.create_provisioned(tenant_id, session_id, fence, Some(options))
            }
            QualificationPhase::Terminal(Err(error)) => Err(error),
            QualificationPhase::Unstarted | QualificationPhase::Running => {
                Err(DependencyError::Rejected)
            }
        }
    }
}

impl<B> ProductionSessionShardFactory<B>
where
    B: ProductionSandboxControl,
{
    fn run_qualification(&self) -> Result<(), DependencyError> {
        let deadline = Instant::now()
            .checked_add(self.config.qualification_bounds.qualification_timeout)
            .ok_or(DependencyError::Rejected)?;
        self.probe_daemon_until(deadline)?;
        let tenant_id = TenantId::new();
        let session_id = SessionId::new();
        let fence = OwnershipFence::new(
            self.config.worker_id.clone(),
            self.config.worker_epoch,
            1,
            1,
        );
        let shard = self.start_session_shard_until(&tenant_id, &session_id, &fence, deadline)?;
        let cleanup = QualificationCleanupGuard::new(shard.provisioned.lifecycle(), fence.clone());
        let dispose = self.runtime.block_on(async {
            tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline),
                shard
                    .probe_driver
                    .close_context_fenced_async(&session_id, &fence),
            )
            .await
        });
        let probe = match dispose {
            Ok(Ok(())) => shard
                .readiness
                .verify_context_disposed_until(&tenant_id, &session_id, &fence, deadline)
                .map_err(map_runtime_error),
            Ok(Err(error)) => Err(error),
            Err(_) => Err(DependencyError::Unavailable),
        };
        let cleanup = cleanup.finish(self.config.qualification_bounds.cleanup_timeout);
        if cleanup.is_err() {
            Err(DependencyError::OutcomeUncertain)
        } else {
            probe
        }
    }

    fn create_provisioned(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        fence: &OwnershipFence,
        options: Option<&WorkerSessionOptionsV1>,
    ) -> Result<ProvisionedSessionShard, DependencyError> {
        match options {
            Some(options) => self.start_session_shard_with_deadline(
                tenant_id,
                session_id,
                fence,
                Some(options),
                None,
            ),
            None => self.start_session_shard(tenant_id, session_id, fence),
        }
        .map(|shard| shard.provisioned)
    }

    fn start_session_shard(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        fence: &OwnershipFence,
    ) -> Result<StartedSessionShard, DependencyError> {
        self.start_session_shard_with_deadline(tenant_id, session_id, fence, None, None)
    }

    fn start_session_shard_until(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        fence: &OwnershipFence,
        deadline: Instant,
    ) -> Result<StartedSessionShard, DependencyError> {
        self.start_session_shard_with_deadline(tenant_id, session_id, fence, None, Some(deadline))
    }

    fn start_session_shard_with_deadline(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        fence: &OwnershipFence,
        options: Option<&WorkerSessionOptionsV1>,
        deadline: Option<Instant>,
    ) -> Result<StartedSessionShard, DependencyError> {
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
        let forced_termination_spec = launch_spec.clone();
        let descriptor = ShardLaunchDescriptor::new(
            launch_spec,
            shard_fence.clone(),
            "standard",
            "dedicated_process",
        )
        .map_err(map_runtime_error)?;
        let drain = Arc::new(ShardDrainState(AtomicBool::new(false)));
        let (owner, targets) = ChromiumConnectionOwner::new_bounded_for_launch(
            self.config.chromium_identity.clone(),
            self.config.chromium_connection.clone(),
            shard_fence.clone(),
            TARGET_EVENT_CAPACITY,
            Arc::clone(&drain),
            forced_termination_spec.clone(),
        )
        .map_err(map_runtime_error)?;
        let readiness = owner.target_manager_backend();
        let cdp_driver = Arc::new(owner.chromium_driver(IsolationProfile::DedicatedProcess));
        let driver_runtime = Arc::new(ChromiumDriverShardRuntime::new_for_launch(
            Arc::clone(&cdp_driver),
            forced_termination_spec,
        ));
        let target_runtime = Arc::new(TargetManagedShardRuntime::new(
            Arc::clone(&driver_runtime),
            targets,
        ));
        let sandbox_runtime = Arc::new(ProductionSandboxShardRuntime::new(
            descriptor,
            self.config.owner_lease_ttl,
            Arc::clone(&self.sandbox),
            Arc::clone(&owner),
            target_runtime,
        ));
        let exact_termination = sandbox_runtime.exact_termination();
        let actor_config =
            BrowserShardActorConfig::new(shard_fence.clone(), ACTOR_MAILBOX_CAPACITY, 1, 1)
                .map_err(map_actor_error)
                .map_err(map_runtime_error)?;
        let (actor, task) = {
            let _runtime = self.runtime.enter();
            BrowserShardActor::spawn(actor_config, sandbox_runtime)
        };
        let activation = match deadline {
            Some(deadline) => self
                .runtime
                .block_on(async {
                    tokio::time::timeout_at(
                        tokio::time::Instant::from_std(deadline),
                        actor.activate(&shard_fence),
                    )
                    .await
                })
                .map_err(|_| ShardActorError::Runtime(ShardRuntimeError::Unavailable))
                .and_then(|result| result),
            None => self.runtime.block_on(actor.activate(&shard_fence)),
        };
        if let Err(error) = activation {
            let cleanup =
                self.cleanup_starting_actor(&actor, &shard_fence, task, deadline.is_some());
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
        let context = match (deadline, options) {
            (Some(deadline), Some(options)) => self.runtime.block_on(async {
                tokio::time::timeout_at(
                    tokio::time::Instant::from_std(deadline),
                    actor_driver.create_context_owned_with_options_async(
                        tenant_id, session_id, fence, options,
                    ),
                )
                .await
                .unwrap_or(Err(DependencyError::Unavailable))
            }),
            (Some(deadline), None) => self.runtime.block_on(async {
                tokio::time::timeout_at(
                    tokio::time::Instant::from_std(deadline),
                    actor_driver.create_context_owned_async(tenant_id, session_id, fence),
                )
                .await
                .unwrap_or(Err(DependencyError::Unavailable))
            }),
            (None, Some(options)) => actor_driver
                .create_context_owned_with_options(tenant_id, session_id, fence, options),
            (None, None) => actor_driver.create_context_owned(tenant_id, session_id, fence),
        };
        let primary_page_id = match context {
            Ok(page_id) => page_id,
            Err(error) => {
                let cleanup =
                    self.cleanup_starting_actor(&actor, &shard_fence, task, deadline.is_some());
                return Err(if cleanup.is_ok() {
                    error
                } else {
                    DependencyError::OutcomeUncertain
                });
            }
        };
        let driver: Arc<dyn ChromiumDriver> = actor_driver.clone();
        let lifecycle: Arc<dyn SessionShardLifecycle> = Arc::new(ProductionSessionShardLifecycle {
            expected_fence: fence.clone(),
            shard_fence,
            exact_termination,
            lease_ttl: self.config.owner_lease_ttl,
            sandbox: Arc::clone(&self.sandbox),
            connection_owner: owner,
            runtime: self.runtime.clone(),
            actor,
            driver: Arc::clone(&driver),
            drain,
            cleanup_timeout: self.config.qualification_bounds.cleanup_timeout,
            coordination: Arc::new(LifecycleCoordination {
                ownership: Mutex::new(LifecycleOwnership {
                    phase: LifecyclePhase::Active,
                    task: Some(task),
                    cleanup_owner: None,
                }),
                changed: Condvar::new(),
            }),
        });
        Ok(StartedSessionShard {
            provisioned: ProvisionedSessionShard::new(
                primary_page_id,
                Arc::clone(&driver),
                lifecycle,
            ),
            probe_driver: actor_driver,
            readiness,
        })
    }

    fn cleanup_starting_actor(
        &self,
        actor: &BrowserShardActor,
        shard_fence: &ShardFence,
        task: JoinHandle<Result<(), ShardRuntimeError>>,
        bounded: bool,
    ) -> Result<(), ShardRuntimeError> {
        let cleanup = async {
            let shutdown = actor.shutdown(shard_fence).await;
            let joined = task.await;
            shutdown.map_err(map_actor_error).and(
                joined
                    .map_err(|_| ShardRuntimeError::OutcomeUncertain)
                    .and_then(|result| result),
            )
        };
        if bounded {
            self.runtime
                .block_on(async {
                    tokio::time::timeout(self.config.qualification_bounds.cleanup_timeout, cleanup)
                        .await
                })
                .unwrap_or(Err(ShardRuntimeError::OutcomeUncertain))
        } else {
            self.runtime.block_on(cleanup)
        }
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

    fn probe_daemon_until(&self, deadline: Instant) -> Result<(), DependencyError> {
        let observed = self.runtime.block_on(async {
            tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline),
                self.sandbox
                    .probe_daemon_epoch(&self.config.worker_id, self.config.worker_epoch),
            )
            .await
        });
        match observed {
            Ok(Ok(epoch)) if epoch == self.config.sandbox_daemon_epoch => Ok(()),
            Ok(Ok(_)) => Err(DependencyError::Rejected),
            Ok(Err(error)) => Err(map_runtime_error(error)),
            Err(_) => Err(DependencyError::Unavailable),
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    struct SignalingLifecycle(mpsc::SyncSender<()>);

    impl SessionShardLifecycle for SignalingLifecycle {
        fn qualify(&self) -> Result<(), DependencyError> {
            Ok(())
        }

        fn heartbeat(&self) -> Result<(), DependencyError> {
            Ok(())
        }

        fn terminate(&self, _fence: &OwnershipFence) -> Result<(), DependencyError> {
            let _ = self.0.send(());
            Ok(())
        }
    }

    #[test]
    fn qualification_panic_starts_owned_lifecycle_cleanup() {
        let worker_id =
            WorkerId::new("qualification-panic-cleanup").expect("worker identity should be valid");
        let fence = OwnershipFence::new(worker_id, 3, 5, 7);
        let (terminated, observed) = mpsc::sync_channel(1);
        let lifecycle: Arc<dyn SessionShardLifecycle> = Arc::new(SignalingLifecycle(terminated));

        let panic = catch_unwind(AssertUnwindSafe(|| {
            let _cleanup = QualificationCleanupGuard::new(lifecycle, fence);
            panic!("qualification panicked after shard launch");
        }));

        assert!(panic.is_err());
        assert_eq!(observed.recv_timeout(Duration::from_secs(1)), Ok(()));
    }
}
