use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use browserd_chromium::{
    ChromiumArtifactIdentity, ChromiumConnectionConfig, VerifiedNativeProfileCatalog,
};
use browserd_core::{
    EgressFence, IsolationProfile, LaunchGeneration, OwnerFence, RouteGeneration, SessionId,
    SessionIncarnation, ShardFence, ShardId, TenantId, WorkerEpoch, WorkerId,
};
use browserd_sandbox::{
    CleanupReason, ContextEgressBinding, ContextEgressRequest, ContextRoutePolicy,
    DedicatedEgressSpec, EgressPolicyBinding, LaunchSpec, MAX_DEDICATED_EGRESS_LEASE_TTL,
    SandboxRpcClient, SandboxRpcError,
};
use browserd_session::OwnershipFence;
use browserd_worker::{
    ActorChromiumDriver, BrowserShardActor, BrowserShardActorConfig, CdpChromiumDriver,
    ChromiumConnectionOwner, ChromiumDriver, ChromiumDriverShardRuntime,
    ChromiumTargetManagerBackend, DependencyError, ExactSandboxTermination,
    ProductionSandboxShardRuntime, SandboxShardRpc, ShardActorError, ShardLaunchDescriptor,
    ShardRuntimeError, TargetManagedShardRuntime, TargetManagerDrain, WorkerIsolationProfile,
    WorkerSessionOptionsV1,
};
use serde_json::{Value, json};
use tokio::runtime::{Handle, RuntimeFlavor};
use tokio::task::JoinHandle;

use crate::{
    ProvisionedSessionShard, SessionShardFactory, SessionShardLifecycle,
    SharedContextPlacementPolicy,
};

mod pool;
use pool::{PoolLaunch, SharedShardPool};

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
    native_profiles: Option<Arc<VerifiedNativeProfileCatalog>>,
    browser_downloads: bool,
    privileged_evaluate: bool,
    shared_context_policy: Option<Arc<SharedContextPlacementPolicy>>,
    worker_tenant_assignment: Option<browserd_worker::WorkerTenantAssignment>,
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
            native_profiles: None,
            browser_downloads: false,
            privileged_evaluate: false,
            shared_context_policy: None,
            worker_tenant_assignment: None,
        })
    }

    #[must_use]
    pub fn with_qualification_bounds(mut self, bounds: ProductionQualificationBounds) -> Self {
        self.qualification_bounds = bounds;
        self
    }

    /// Enables browser downloads only when the caller has configured scanned artifact storage.
    #[must_use]
    pub fn with_browser_downloads(mut self, enabled: bool) -> Self {
        self.browser_downloads = enabled;
        self
    }

    /// Advertises the operator-enabled evaluate capability; per-principal admission belongs to
    /// the worker control plane and is required before every effect.
    #[must_use]
    pub fn with_privileged_evaluate(mut self, enabled: bool) -> Self {
        self.privileged_evaluate = enabled;
        self
    }

    pub fn with_shared_context_policy(
        mut self,
        policy: Arc<SharedContextPlacementPolicy>,
    ) -> Result<Self, DependencyError> {
        if policy.artifact_identity() != &self.chromium_identity {
            return Err(DependencyError::Rejected);
        }
        self.shared_context_policy = Some(policy);
        Ok(self)
    }

    pub fn with_worker_tenant_assignment(
        mut self,
        assignment: browserd_worker::WorkerTenantAssignment,
    ) -> Result<Self, DependencyError> {
        if assignment.worker_id() != &self.worker_id {
            return Err(DependencyError::Rejected);
        }
        self.worker_tenant_assignment = Some(assignment);
        Ok(self)
    }

    pub fn with_native_profiles(
        mut self,
        catalog: VerifiedNativeProfileCatalog,
    ) -> Result<Self, DependencyError> {
        if catalog.binary_digest() != self.chromium_identity.binary_digest
            || catalog.catalog_digest() != self.chromium_identity.launch_profile_digest
        {
            return Err(DependencyError::Rejected);
        }
        self.native_profiles = Some(Arc::new(catalog));
        Ok(self)
    }
}

pub struct ProductionSessionShardFactory<B> {
    config: ProductionSessionShardConfig,
    sandbox: Arc<B>,
    runtime: Handle,
    qualification: Arc<QualificationFlight>,
    pool: Arc<SharedShardPool<B>>,
    runtime_safety: Option<Arc<browserd_core::RuntimeSafetyCache>>,
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
            pool: Arc::clone(&self.pool),
            runtime_safety: self.runtime_safety.clone(),
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
            pool: Arc::new(SharedShardPool::default()),
            runtime_safety: None,
            qualification: Arc::new(QualificationFlight {
                phase: Mutex::new(QualificationPhase::Unstarted),
                changed: Condvar::new(),
            }),
        })
    }

    #[must_use]
    pub fn with_runtime_safety(mut self, cache: Arc<browserd_core::RuntimeSafetyCache>) -> Self {
        self.runtime_safety = Some(cache);
        self
    }

    fn runtime_snapshot(
        &self,
        network_class: &str,
    ) -> Result<Option<browserd_core::SafetySwitchSnapshot>, DependencyError> {
        self.runtime_safety
            .as_ref()
            .map(|cache| {
                cache
                    .with_fresh_snapshot(|snapshot| {
                        if snapshot.network_class_stopped(network_class)
                            || snapshot.chromium_build_disabled(
                                &self.config.chromium_identity.binary_digest.to_string(),
                            )
                        {
                            return Err(DependencyError::Rejected);
                        }
                        Ok(snapshot.clone())
                    })
                    .map_err(|_| DependencyError::Unavailable)?
            })
            .transpose()
    }
}

struct StartedSessionShard<B> {
    provisioned: ProvisionedSessionShard,
    probe_driver: Arc<ActorChromiumDriver<CdpChromiumDriver>>,
    readiness: ChromiumTargetManagerBackend,
    lifecycle: Arc<ProductionSessionShardLifecycle<B>>,
    launch_spec: LaunchSpec,
    context_binding: Option<ContextEgressBinding>,
}

struct ShardDrainState(AtomicBool);

impl TargetManagerDrain for ShardDrainState {
    fn begin_drain(&self) {
        self.0.store(true, Ordering::Release);
    }
}

struct ProductionSessionShardLifecycle<B> {
    expected_tenant: TenantId,
    expected_session: SessionId,
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
    liveness_lease_gate: Mutex<()>,
    ownership: Mutex<LifecycleOwnership>,
    changed: Condvar,
    cleanup_diagnostic: Mutex<CleanupDiagnostic>,
}

#[derive(Clone, Copy, Default)]
enum CleanupStage {
    #[default]
    Idle,
    Coordinated,
    CoordinatedTimeout,
    CoordinatedComplete,
    OwnerVerification,
    OwnerDeadlineElapsed,
    Complete,
    Panicked,
}

#[derive(Clone, Copy)]
enum ActorJoinDiagnostic {
    Success,
    RuntimeError(ShardRuntimeError),
    Panic,
    Cancelled,
    Missing,
}

#[derive(Clone, Default)]
struct CleanupDiagnostic {
    stage: CleanupStage,
    actor_shutdown: Option<Result<(), ShardActorError>>,
    actor_join: Option<ActorJoinDiagnostic>,
    exact: Option<Result<(), ShardRuntimeError>>,
    forced_confirmation: Option<bool>,
    owner_shutdown: Option<Result<(), ShardRuntimeError>>,
    owner_joined_after_exact: Option<bool>,
    final_result: Option<Result<(), DependencyError>>,
}

fn runtime_result_diagnostic(result: Result<(), ShardRuntimeError>) -> Value {
    match result {
        Ok(()) => json!({"outcome":"ok"}),
        Err(error) => json!({"outcome":"error","variant":match error {
            ShardRuntimeError::Rejected => "Rejected",
            ShardRuntimeError::Unavailable => "Unavailable",
            ShardRuntimeError::Cancelled => "Cancelled",
            ShardRuntimeError::OutcomeUncertain => "OutcomeUncertain",
        }}),
    }
}

fn actor_result_diagnostic(result: Result<(), ShardActorError>) -> Value {
    match result {
        Ok(()) => json!({"outcome":"ok"}),
        Err(ShardActorError::Runtime(error)) => {
            let mut value = runtime_result_diagnostic(Err(error));
            value["runtime_variant"] = value["variant"].clone();
            value["variant"] = json!("Runtime");
            value
        }
        Err(error) => json!({"outcome":"error","variant":match error {
            ShardActorError::InvalidConfiguration => "InvalidConfiguration",
            ShardActorError::StaleShardFence => "StaleShardFence",
            ShardActorError::StaleSessionFence => "StaleSessionFence",
            ShardActorError::InvalidLifecycle => "InvalidLifecycle",
            ShardActorError::AdmissionClosed => "AdmissionClosed",
            ShardActorError::CapacityExceeded => "CapacityExceeded",
            ShardActorError::SessionNotFound => "SessionNotFound",
            ShardActorError::MailboxFull => "MailboxFull",
            ShardActorError::OwnershipLost => "OwnershipLost",
            ShardActorError::ActorStopped => "ActorStopped",
            ShardActorError::Runtime(_) => "Runtime",
        }}),
    }
}

impl CleanupDiagnostic {
    fn failure_summary(&self) -> Option<Value> {
        let error = self.final_result?.err()?;
        let stage = match self.stage {
            CleanupStage::Idle => "idle",
            CleanupStage::Coordinated => "coordinated",
            CleanupStage::CoordinatedTimeout => "coordinated_timeout",
            CleanupStage::CoordinatedComplete => "coordinated_complete",
            CleanupStage::OwnerVerification => "owner_verification",
            CleanupStage::OwnerDeadlineElapsed => "owner_deadline_elapsed",
            CleanupStage::Complete => "complete",
            CleanupStage::Panicked => "panicked",
        };
        let mut summary = json!({"stage":stage,"final_error":match error {
            DependencyError::Rejected => "Rejected",
            DependencyError::Unavailable => "Unavailable",
            DependencyError::OutcomeUncertain => "OutcomeUncertain",
        }});
        for (key, result) in [
            ("exact_termination", self.exact),
            ("owner_shutdown", self.owner_shutdown),
        ] {
            if let Some(result) = result {
                summary[key] = runtime_result_diagnostic(result);
            }
        }
        if let Some(result) = self.actor_shutdown {
            summary["actor_shutdown"] = actor_result_diagnostic(result);
        }
        if let Some(join) = self.actor_join {
            summary["actor_join"] = match join {
                ActorJoinDiagnostic::Success => json!({"outcome":"ok"}),
                ActorJoinDiagnostic::RuntimeError(error) => runtime_result_diagnostic(Err(error)),
                ActorJoinDiagnostic::Panic => json!({"outcome":"panic"}),
                ActorJoinDiagnostic::Cancelled => json!({"outcome":"cancelled"}),
                ActorJoinDiagnostic::Missing => json!({"outcome":"missing"}),
            };
        }
        if let Some(confirmed) = self.forced_confirmation {
            summary["forced_confirmation"] = json!(confirmed);
        }
        if let Some(joined) = self.owner_joined_after_exact {
            summary["owner_joined_after_exact"] = json!(joined);
        }
        Some(summary)
    }
}

fn update_cleanup_diagnostic(
    coordination: &LifecycleCoordination,
    update: impl FnOnce(&mut CleanupDiagnostic),
) {
    // Diagnostic publication has no authority to change cleanup or poison its ownership state.
    if let Ok(mut diagnostic) = coordination.cleanup_diagnostic.lock() {
        update(&mut diagnostic);
    }
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

impl<B> ProductionSessionShardLifecycle<B>
where
    B: ProductionSandboxControl,
{
    fn validate_active_ownership(&self) -> Result<(), DependencyError> {
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
        Ok(())
    }

    fn qualify_active(&self) -> Result<(), DependencyError> {
        self.validate_active_ownership()?;
        self.driver.qualify()?;
        self.validate_active_ownership()
    }
}

impl<B> SessionShardLifecycle for ProductionSessionShardLifecycle<B>
where
    B: ProductionSandboxControl,
{
    fn cleanup_failure_summary(&self) -> Option<Value> {
        self.coordination
            .cleanup_diagnostic
            .lock()
            .ok()?
            .failure_summary()
    }

    fn shard_fence(&self) -> Option<ShardFence> {
        Some(self.shard_fence.clone())
    }
    fn qualify(&self) -> Result<(), DependencyError> {
        // Renderer readiness may wait behind a page action. Lease renewal must
        // remain independent, while both observations retain exact active ownership.
        self.qualify_active()
    }

    fn heartbeat(&self) -> Result<(), DependencyError> {
        let _liveness_lease = self
            .coordination
            .liveness_lease_gate
            .lock()
            .map_err(|_| DependencyError::Unavailable)?;
        self.validate_active_ownership()?;
        let result = self.runtime.block_on(self.sandbox.renew_owner_lease(
            self.shard_fence.shard_id(),
            self.shard_fence.owner().worker_epoch().get(),
            self.shard_fence.launch_generation(),
            self.lease_ttl,
        ));
        result.map_err(map_runtime_error)?;
        self.validate_active_ownership()
    }

    fn dispose_context_verified_until(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        fence: &OwnershipFence,
        deadline: Instant,
    ) -> Result<(), DependencyError> {
        if tenant_id != &self.expected_tenant
            || session_id != &self.expected_session
            || fence != &self.expected_fence
            || Instant::now() >= deadline
        {
            return Err(DependencyError::Rejected);
        }
        let _liveness_lease = self
            .coordination
            .liveness_lease_gate
            .lock()
            .map_err(|_| DependencyError::Unavailable)?;
        self.qualify_active()?;
        let detached = self.runtime.block_on(async {
            tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline),
                self.actor
                    .detach_session(&self.shard_fence, session_id.clone(), fence.clone()),
            )
            .await
        });
        match detached {
            Ok(Ok(_)) => self
                .connection_owner
                .target_manager_backend()
                .verify_context_disposed_until(tenant_id, session_id, fence, deadline)
                .map_err(map_runtime_error),
            Ok(Err(error)) => Err(map_runtime_error(map_actor_error(error))),
            Err(_) => Err(DependencyError::OutcomeUncertain),
        }
    }

    fn terminate(&self, fence: &OwnershipFence) -> Result<(), DependencyError> {
        if fence != &self.expected_fence {
            return Err(DependencyError::Rejected);
        }
        let _liveness_lease = self
            .coordination
            .liveness_lease_gate
            .lock()
            .map_err(|_| DependencyError::Unavailable)?;
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
                            update_cleanup_diagnostic(&coordination, |d| {
                                *d = CleanupDiagnostic {
                                    stage: CleanupStage::Coordinated,
                                    ..CleanupDiagnostic::default()
                                };
                            });
                            let result = match catch_unwind(AssertUnwindSafe(|| {
                                let diagnostic_coordination = Arc::clone(&coordination);
                                runtime.block_on(async move {
                                    let coordination = diagnostic_coordination;
                                    let deadline = tokio::time::Instant::now() + cleanup_timeout;
                                    let coordinated = tokio::time::timeout_at(deadline, async {
                                        let exact = async {
                                            let proof = exact_termination
                                                .terminate(CleanupReason::WorkerLeaseExpired)
                                                .await
                                                .map_err(|_| ShardRuntimeError::OutcomeUncertain);
                                            update_cleanup_diagnostic(&coordination, |d| {
                                                d.exact = Some(
                                                    proof
                                                        .as_ref()
                                                        .map(|_| ())
                                                        .map_err(|error| *error),
                                                );
                                            });
                                            if let Ok(proof) = proof.as_ref() {
                                                let confirmed = connection_owner
                                                    .confirm_forced_termination(proof);
                                                update_cleanup_diagnostic(&coordination, |d| {
                                                    d.forced_confirmation = Some(confirmed)
                                                });
                                            }
                                            proof
                                        };
                                        let local = async {
                                            let shutdown = actor.shutdown(&shard_fence).await;
                                            update_cleanup_diagnostic(&coordination, |d| {
                                                d.actor_shutdown = Some(shutdown)
                                            });
                                            let shutdown = shutdown.map_err(map_actor_error);
                                            let joined: Option<
                                                Result<
                                                    Result<(), ShardRuntimeError>,
                                                    tokio::task::JoinError,
                                                >,
                                            > = match task {
                                                Some(task) => Some(task.await),
                                                None => None,
                                            };
                                            update_cleanup_diagnostic(&coordination, |d| {
                                                d.actor_join = Some(match joined.as_ref() {
                                                    Some(Ok(Ok(()))) => {
                                                        ActorJoinDiagnostic::Success
                                                    }
                                                    Some(Ok(Err(error))) => {
                                                        ActorJoinDiagnostic::RuntimeError(*error)
                                                    }
                                                    Some(Err(error)) if error.is_panic() => {
                                                        ActorJoinDiagnostic::Panic
                                                    }
                                                    Some(Err(_)) => ActorJoinDiagnostic::Cancelled,
                                                    None => ActorJoinDiagnostic::Missing,
                                                });
                                            });
                                            (shutdown, joined)
                                        };
                                        tokio::join!(local, exact)
                                    })
                                    .await;
                                    let Ok(((shutdown, joined), exact)) = coordinated else {
                                        update_cleanup_diagnostic(&coordination, |d| {
                                            d.stage = CleanupStage::CoordinatedTimeout
                                        });
                                        return Err(ShardRuntimeError::OutcomeUncertain);
                                    };
                                    update_cleanup_diagnostic(&coordination, |d| {
                                        d.stage = CleanupStage::CoordinatedComplete
                                    });
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
                                        update_cleanup_diagnostic(&coordination, |d| {
                                            d.stage = CleanupStage::OwnerDeadlineElapsed
                                        });
                                        return Err(ShardRuntimeError::OutcomeUncertain);
                                    }
                                    update_cleanup_diagnostic(&coordination, |d| {
                                        d.stage = CleanupStage::OwnerVerification
                                    });
                                    let owner_shutdown =
                                        connection_owner.shutdown_and_join(remaining).await;
                                    update_cleanup_diagnostic(&coordination, |d| {
                                        d.owner_shutdown = Some(owner_shutdown)
                                    });
                                    let terminally_joined = owner_shutdown.is_ok().then(|| {
                                        connection_owner.is_terminally_joined_after(&proof)
                                    });
                                    update_cleanup_diagnostic(&coordination, |d| {
                                        d.owner_joined_after_exact = terminally_joined
                                    });
                                    if owner_shutdown.is_ok() && terminally_joined == Some(true) {
                                        Ok(())
                                    } else {
                                        Err(ShardRuntimeError::OutcomeUncertain)
                                    }
                                })
                            })) {
                                Ok(result) => result.map_err(map_runtime_error),
                                Err(_) => {
                                    update_cleanup_diagnostic(&coordination, |d| {
                                        d.stage = CleanupStage::Panicked
                                    });
                                    Err(DependencyError::OutcomeUncertain)
                                }
                            };
                            update_cleanup_diagnostic(&coordination, |d| {
                                d.final_result = Some(result);
                                if result.is_ok() {
                                    d.stage = CleanupStage::Complete;
                                }
                            });
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
    fn supports_requested_isolation(&self, requested: WorkerIsolationProfile) -> bool {
        requested != WorkerIsolationProfile::DedicatedWorker
            || self.config.worker_tenant_assignment.is_some()
    }

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
            || !(options.feature_profile == "standard"
                || (options.feature_profile == "privileged" && self.config.privileged_evaluate))
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

    fn create_with_placement(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        fence: &OwnershipFence,
        options: Option<&WorkerSessionOptionsV1>,
        requested: WorkerIsolationProfile,
    ) -> Result<ProvisionedSessionShard, DependencyError> {
        if let Some(assignment) = &self.config.worker_tenant_assignment {
            if assignment.tenant_id() != tenant_id {
                return Err(DependencyError::Rejected);
            }
            return match options {
                Some(options) => self.create_with_options(tenant_id, session_id, fence, options),
                None => self.create(tenant_id, session_id, fence),
            };
        }
        let runtime =
            self.runtime_snapshot(options.map_or("public", |options| &options.network_class))?;
        let mut effective = match &self.config.shared_context_policy {
            Some(policy) => policy.effective_isolation(tenant_id, requested)?,
            None if requested.satisfied_by(WorkerIsolationProfile::DedicatedProcess) => {
                WorkerIsolationProfile::DedicatedProcess
            }
            None => return Err(DependencyError::Rejected),
        };
        if let Some(snapshot) = &runtime {
            let core = match effective {
                WorkerIsolationProfile::SharedContext => IsolationProfile::SharedContext,
                WorkerIsolationProfile::TenantDedicatedShard => {
                    IsolationProfile::TenantDedicatedShard
                }
                WorkerIsolationProfile::DedicatedProcess => IsolationProfile::DedicatedProcess,
                WorkerIsolationProfile::DedicatedWorker => IsolationProfile::DedicatedWorker,
            };
            effective = match snapshot.effective_isolation(core) {
                IsolationProfile::SharedContext => WorkerIsolationProfile::SharedContext,
                IsolationProfile::TenantDedicatedShard => {
                    WorkerIsolationProfile::TenantDedicatedShard
                }
                IsolationProfile::DedicatedProcess => WorkerIsolationProfile::DedicatedProcess,
                IsolationProfile::DedicatedWorker => WorkerIsolationProfile::DedicatedWorker,
            };
        }
        if effective == WorkerIsolationProfile::DedicatedProcess {
            return match options {
                Some(options) => self.create_with_options(tenant_id, session_id, fence, options),
                None => self.create(tenant_id, session_id, fence),
            };
        }
        self.create_pooled(
            tenant_id,
            session_id,
            fence,
            options.ok_or(DependencyError::Rejected)?,
            effective,
        )
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
        let tenant_id = self
            .config
            .worker_tenant_assignment
            .as_ref()
            .map_or_else(TenantId::new, |assignment| assignment.tenant_id().clone());
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
    ) -> Result<StartedSessionShard<B>, DependencyError> {
        self.start_session_shard_with_deadline(tenant_id, session_id, fence, None, None, None)
    }

    fn start_session_shard_until(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        fence: &OwnershipFence,
        deadline: Instant,
    ) -> Result<StartedSessionShard<B>, DependencyError> {
        self.start_session_shard_with_deadline(
            tenant_id,
            session_id,
            fence,
            None,
            Some(deadline),
            None,
        )
    }

    fn start_session_shard_with_deadline(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        fence: &OwnershipFence,
        options: Option<&WorkerSessionOptionsV1>,
        deadline: Option<Instant>,
        pooled: Option<PoolLaunch>,
    ) -> Result<StartedSessionShard<B>, DependencyError> {
        // The bounded-deadline caller is structural startup qualification, which exposes
        // no user context and must remain possible before explicit authority initialization.
        let network_class = options.map_or("public", |options| options.network_class.as_str());
        let runtime = if deadline.is_none() {
            self.runtime_snapshot(network_class)?
        } else {
            None
        };
        if pooled.is_some_and(|pool| {
            runtime.as_ref().is_some_and(|snapshot| {
                snapshot.force_dedicated_process()
                    || pool.max_live > usize::from(snapshot.max_contexts_per_shard())
            })
        }) {
            return Err(DependencyError::Rejected);
        }
        if fence.worker_id() != &self.config.worker_id
            || self
                .config
                .worker_tenant_assignment
                .as_ref()
                .is_some_and(|assignment| assignment.tenant_id() != tenant_id)
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
        let mut launch_spec = LaunchSpec::production(
            tenant_id.clone(),
            dedicated_egress,
            self.config.chromium_identity.binary_digest.into(),
        );
        if let Some(options) = options {
            let profile = self
                .config
                .native_profiles
                .as_ref()
                .ok_or(DependencyError::Rejected)?
                .process_profile(&options.locale, &options.timezone)
                .map_err(|_| DependencyError::Rejected)?
                .with_user_agent(options.user_agent.clone())
                .map_err(|_| DependencyError::Rejected)?;
            launch_spec = launch_spec
                .with_process_profile(profile)
                .map_err(|_| DependencyError::Rejected)?;
        }
        if let Some(pool) = &pooled {
            launch_spec = launch_spec
                .with_context_route_policy(
                    ContextRoutePolicy::new(
                        fence.as_placement_fence(),
                        pool.isolation == WorkerIsolationProfile::TenantDedicatedShard,
                        u16::try_from(pool.max_live).map_err(|_| DependencyError::Rejected)?,
                        u16::try_from(pool.max_lifetime).map_err(|_| DependencyError::Rejected)?,
                    )
                    .map_err(|_| DependencyError::Rejected)?,
                )
                .map_err(|_| DependencyError::Rejected)?;
        }
        let forced_termination_spec = launch_spec.clone();
        let descriptor = ShardLaunchDescriptor::new(
            launch_spec,
            shard_fence.clone(),
            "standard",
            pooled
                .as_ref()
                .map_or("dedicated_process", |pool| pool.isolation_name()),
        )
        .map_err(map_runtime_error)?;
        let drain = Arc::new(ShardDrainState(AtomicBool::new(false)));
        let (owner, targets) = if let Some(pool) = &pooled {
            ChromiumConnectionOwner::new_bounded_for_pooled_launch(
                self.config.chromium_identity.clone(),
                self.config.chromium_connection.clone(),
                shard_fence.clone(),
                TARGET_EVENT_CAPACITY,
                Arc::clone(&drain),
                forced_termination_spec.clone(),
                pool.owner_policy(tenant_id)?,
            )
        } else {
            ChromiumConnectionOwner::new_bounded_for_routed_launch(
                self.config.chromium_identity.clone(),
                self.config.chromium_connection.clone(),
                shard_fence.clone(),
                TARGET_EVENT_CAPACITY,
                Arc::clone(&drain),
                forced_termination_spec.clone(),
            )
        }
        .map_err(map_runtime_error)?;
        if deadline.is_none()
            && let Some(cache) = &self.runtime_safety
        {
            owner
                .configure_runtime_safety(Arc::clone(cache))
                .map_err(map_runtime_error)?;
        }
        let readiness = owner.target_manager_backend();
        if self.config.browser_downloads {
            owner.enable_downloads().map_err(map_runtime_error)?;
        }
        let actual_isolation = pooled.as_ref().map_or_else(
            || {
                if self.config.worker_tenant_assignment.is_some() {
                    IsolationProfile::DedicatedWorker
                } else {
                    IsolationProfile::DedicatedProcess
                }
            },
            |pool| pool.core_isolation(),
        );
        let mut cdp_driver = owner
            .chromium_driver(actual_isolation)
            .with_privileged_evaluate(self.config.privileged_evaluate);
        if let Some(assignment) = &self.config.worker_tenant_assignment {
            cdp_driver = cdp_driver.with_worker_tenant_assignment(assignment.clone())?;
        }
        let cdp_driver = Arc::new(cdp_driver);
        let driver_runtime = Arc::new(ChromiumDriverShardRuntime::new_for_launch(
            Arc::clone(&cdp_driver),
            forced_termination_spec.clone(),
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
        let actor_config = BrowserShardActorConfig::new(
            shard_fence.clone(),
            ACTOR_MAILBOX_CAPACITY,
            pooled.as_ref().map_or(1, |pool| pool.max_live),
            pooled.as_ref().map_or(1, |pool| pool.max_lifetime),
        )
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
        let context_binding = if pooled.is_some() {
            let request = ContextEgressRequest::initial(&forced_termination_spec)
                .map_err(|_| DependencyError::OutcomeUncertain)?;
            let started = Instant::now();
            let binding = self
                .runtime
                .block_on(self.sandbox.attach_context_egress(&request))
                .map_err(map_runtime_error);
            let registered = binding.and_then(|binding| {
                if binding.request() != &request
                    || binding.sandboxd_epoch() != self.config.sandbox_daemon_epoch
                {
                    return Err(DependencyError::OutcomeUncertain);
                }
                let valid_until = started
                    .checked_add(binding.granted_ttl())
                    .ok_or(DependencyError::OutcomeUncertain)?;
                readiness
                    .register_context_egress(
                        tenant_id.clone(),
                        session_id.clone(),
                        fence.clone(),
                        binding.clone(),
                        valid_until,
                    )
                    .map_err(map_runtime_error)?;
                Ok(binding)
            });
            match registered {
                Ok(binding) => Some(binding),
                Err(error) => {
                    let cleaned =
                        self.cleanup_starting_actor(&actor, &shard_fence, task, deadline.is_some());
                    return Err(if cleaned.is_ok() {
                        error
                    } else {
                        DependencyError::OutcomeUncertain
                    });
                }
            }
        } else {
            None
        };
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
        if deadline.is_none() {
            let current = self.runtime_snapshot(network_class).and_then(|snapshot| {
                if pooled.is_some_and(|pool| {
                    snapshot.as_ref().is_some_and(|snapshot| {
                        snapshot.force_dedicated_process()
                            || pool.max_live > usize::from(snapshot.max_contexts_per_shard())
                    })
                }) {
                    Err(DependencyError::Rejected)
                } else {
                    Ok(())
                }
            });
            if let Err(error) = current {
                let cleaned = self.cleanup_starting_actor(&actor, &shard_fence, task, false);
                return Err(if cleaned.is_ok() {
                    error
                } else {
                    DependencyError::OutcomeUncertain
                });
            }
        }
        let driver: Arc<dyn ChromiumDriver> = actor_driver.clone();
        let lifecycle = Arc::new(ProductionSessionShardLifecycle {
            expected_tenant: tenant_id.clone(),
            expected_session: session_id.clone(),
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
                liveness_lease_gate: Mutex::new(()),
                ownership: Mutex::new(LifecycleOwnership {
                    phase: LifecyclePhase::Active,
                    task: Some(task),
                    cleanup_owner: None,
                }),
                changed: Condvar::new(),
                cleanup_diagnostic: Mutex::new(CleanupDiagnostic::default()),
            }),
        });
        Ok(StartedSessionShard {
            provisioned: ProvisionedSessionShard::with_isolation(
                primary_page_id,
                Arc::clone(&driver),
                lifecycle.clone(),
                match actual_isolation {
                    IsolationProfile::SharedContext => WorkerIsolationProfile::SharedContext,
                    IsolationProfile::TenantDedicatedShard => {
                        WorkerIsolationProfile::TenantDedicatedShard
                    }
                    IsolationProfile::DedicatedProcess => WorkerIsolationProfile::DedicatedProcess,
                    IsolationProfile::DedicatedWorker => WorkerIsolationProfile::DedicatedWorker,
                },
            ),
            probe_driver: actor_driver,
            readiness,
            lifecycle,
            launch_spec: forced_termination_spec,
            context_binding,
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

    #[test]
    fn cleanup_diagnostic_preserves_distinct_local_exact_and_owner_outcomes() {
        let diagnostic = CleanupDiagnostic {
            stage: CleanupStage::OwnerVerification,
            actor_shutdown: Some(Err(ShardActorError::Runtime(
                ShardRuntimeError::OutcomeUncertain,
            ))),
            actor_join: Some(ActorJoinDiagnostic::RuntimeError(
                ShardRuntimeError::Cancelled,
            )),
            exact: Some(Ok(())),
            forced_confirmation: Some(true),
            owner_shutdown: Some(Err(ShardRuntimeError::OutcomeUncertain)),
            owner_joined_after_exact: None,
            final_result: Some(Err(DependencyError::OutcomeUncertain)),
        };
        let summary = diagnostic.failure_summary().expect("real failure summary");
        assert_eq!(
            summary["actor_shutdown"],
            json!({"outcome":"error","variant":"Runtime","runtime_variant":"OutcomeUncertain"})
        );
        assert_eq!(summary["actor_join"]["variant"], "Cancelled");
        assert_eq!(summary["exact_termination"]["outcome"], "ok");
        assert_eq!(summary["forced_confirmation"], true);
        assert!(summary.get("owner_joined_after_exact").is_none());
        assert_eq!(summary["final_error"], "OutcomeUncertain");
        assert!(
            serde_json::to_vec(&summary)
                .expect("bounded metadata")
                .len()
                < 1024
        );
    }

    #[test]
    fn cleanup_diagnostic_does_not_invent_unobserved_completion_or_publish_success() {
        let mut diagnostic = CleanupDiagnostic::default();
        assert!(diagnostic.failure_summary().is_none());
        diagnostic.stage = CleanupStage::CoordinatedTimeout;
        diagnostic.exact = Some(Ok(()));
        diagnostic.final_result = Some(Err(DependencyError::OutcomeUncertain));
        let summary = diagnostic.failure_summary().expect("timeout summary");
        assert_eq!(summary["stage"], "coordinated_timeout");
        assert!(summary.get("actor_join").is_none());
        assert!(summary.get("actor_shutdown").is_none());
        assert!(summary.get("owner_shutdown").is_none());
        assert!(summary.get("owner_joined_after_exact").is_none());
        diagnostic.final_result = Some(Ok(()));
        assert!(diagnostic.failure_summary().is_none());
    }

    #[test]
    fn actor_cleanup_diagnostic_separates_actor_stopped_from_runtime_failure() {
        assert_eq!(
            actor_result_diagnostic(Err(ShardActorError::ActorStopped)),
            json!({"outcome":"error","variant":"ActorStopped"})
        );
        assert_eq!(
            actor_result_diagnostic(Err(ShardActorError::Runtime(ShardRuntimeError::Rejected))),
            json!({"outcome":"error","variant":"Runtime","runtime_variant":"Rejected"})
        );
        assert_eq!(
            runtime_result_diagnostic(Err(ShardRuntimeError::Unavailable)),
            json!({"outcome":"error","variant":"Unavailable"})
        );
    }

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
