//! Shard sandbox supervisor contract, ownership leases, and cleanup ordering.

mod journal;
mod linux;
mod rpc;

pub use journal::{
    FilePreparedShardJournal, JournalSequence, PreparedShardCleanupFailure,
    PreparedShardCleanupPermit, PreparedShardCleanupProgress, PreparedShardCleanupStage,
    PreparedShardCleanupStageStatus, PreparedShardEffect, PreparedShardEffectPermit,
    PreparedShardJournalError, PreparedShardJournalLimits, PreparedShardJournalRecord,
    PreparedShardRecoveryBackend, PreparedShardRecoveryDisposition, PreparedShardRecoveryError,
    PreparedShardRecoveryLocators, PreparedShardRecoveryRoots, StartupPreparedShardReconciler,
    StartupReconciliationHandle, StartupReconciliationReport,
};
pub use linux::{
    CHROMIUM_CDP_READ_FD, CHROMIUM_CDP_WRITE_FD, CgroupLimits, ChildIdentity, ChromiumRuntime,
    EgressRouteBackend, LaunchGateRuntime, LinuxProcessBackend, LinuxSandboxBackend,
    LinuxSandboxConfig, ProcessSignal, ReadOnlyMount, SandboxFilesystem, ShardEgressFence,
    SpawnRequest, StdLinuxProcessBackend, StdSandboxFilesystem,
};
pub use rpc::{
    RpcFailureCode, SandboxRpcClient, SandboxRpcConfig, SandboxRpcError, SandboxRpcServer,
};

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use browserd_core::{ShardId, WorkerId};
use futures::future::join_all;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::{Mutex, watch};
use tokio::time::{Instant, timeout};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SandboxCapabilities {
    user_namespace: bool,
    pid_namespace: bool,
    mount_namespace: bool,
    network_namespace: bool,
    private_tmp: bool,
    private_shm: bool,
    cgroup_v2: bool,
    cgroup_kill: bool,
    no_new_privs: bool,
    capabilities_dropped: bool,
    deny_all_egress: bool,
}

impl SandboxCapabilities {
    pub const REQUIRED_NAMES: [&'static str; 11] = [
        "user_namespace",
        "pid_namespace",
        "mount_namespace",
        "network_namespace",
        "private_tmp",
        "private_shm",
        "cgroup_v2",
        "cgroup_kill",
        "no_new_privs",
        "capabilities_dropped",
        "deny_all_egress",
    ];

    pub const fn production_required() -> Self {
        Self {
            user_namespace: true,
            pid_namespace: true,
            mount_namespace: true,
            network_namespace: true,
            private_tmp: true,
            private_shm: true,
            cgroup_v2: true,
            cgroup_kill: true,
            no_new_privs: true,
            capabilities_dropped: true,
            deny_all_egress: true,
        }
    }

    pub fn disable(&mut self, name: &str) {
        match name {
            "user_namespace" => self.user_namespace = false,
            "pid_namespace" => self.pid_namespace = false,
            "mount_namespace" => self.mount_namespace = false,
            "network_namespace" => self.network_namespace = false,
            "private_tmp" => self.private_tmp = false,
            "private_shm" => self.private_shm = false,
            "cgroup_v2" => self.cgroup_v2 = false,
            "cgroup_kill" => self.cgroup_kill = false,
            "no_new_privs" => self.no_new_privs = false,
            "capabilities_dropped" => self.capabilities_dropped = false,
            "deny_all_egress" => self.deny_all_egress = false,
            _ => {}
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SupervisorConfig {
    supervisor_lease_ttl: Duration,
    directory_lease_ttl: Duration,
    cleanup_stage_timeout: Duration,
}

impl SupervisorConfig {
    pub fn new(
        supervisor_lease_ttl: Duration,
        directory_lease_ttl: Duration,
    ) -> Result<Self, SandboxError> {
        if supervisor_lease_ttl.is_zero() || directory_lease_ttl.is_zero() {
            return Err(SandboxError::ZeroLeaseTtl);
        }
        if supervisor_lease_ttl > directory_lease_ttl {
            return Err(SandboxError::InvalidLeaseOrdering);
        }
        Ok(Self {
            supervisor_lease_ttl,
            directory_lease_ttl,
            cleanup_stage_timeout: Duration::from_secs(2),
        })
    }

    pub fn with_cleanup_stage_timeout(
        mut self,
        cleanup_stage_timeout: Duration,
    ) -> Result<Self, SandboxError> {
        if cleanup_stage_timeout.is_zero() {
            return Err(SandboxError::ZeroCleanupTimeout);
        }
        self.cleanup_stage_timeout = cleanup_stage_timeout;
        Ok(self)
    }

    pub const fn supervisor_lease_ttl(self) -> Duration {
        self.supervisor_lease_ttl
    }

    pub const fn directory_lease_ttl(self) -> Duration {
        self.directory_lease_ttl
    }

    pub const fn cleanup_stage_timeout(self) -> Duration {
        self.cleanup_stage_timeout
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaunchSpec {
    shard_id: ShardId,
    worker_id: WorkerId,
    worker_epoch: u64,
}

impl LaunchSpec {
    pub const fn production(shard_id: ShardId, worker_id: WorkerId, worker_epoch: u64) -> Self {
        Self {
            shard_id,
            worker_id,
            worker_epoch,
        }
    }

    pub const fn shard_id(&self) -> &ShardId {
        &self.shard_id
    }

    pub const fn worker_epoch(&self) -> u64 {
        self.worker_epoch
    }
}

#[derive(Clone, Debug)]
pub struct WorkerOwnership {
    worker_id: WorkerId,
    worker_epoch: u64,
    expires_at: Instant,
}

impl WorkerOwnership {
    pub const fn new(worker_id: WorkerId, worker_epoch: u64, expires_at: Instant) -> Self {
        Self {
            worker_id,
            worker_epoch,
            expires_at,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxHandle {
    shard_id: ShardId,
    backend_token: String,
}

impl SandboxHandle {
    pub fn new(shard_id: ShardId, backend_token: impl Into<String>) -> Self {
        Self {
            shard_id,
            backend_token: backend_token.into(),
        }
    }

    pub const fn shard_id(&self) -> &ShardId {
        &self.shard_id
    }

    pub fn backend_token(&self) -> &str {
        &self.backend_token
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CleanupReason {
    WorkerLeaseExpired,
    SecurityViolation,
    Administrative,
    BrowserFailure,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CleanupResult {
    pub route_revoked: bool,
    pub cgroup_killed: bool,
    pub namespaces_cleaned: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InspectResources {
    pub memory_current_bytes: u64,
    pub memory_peak_bytes: u64,
    pub process_count: u32,
    pub egress_route_active: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CreateShardOutcome {
    Created,
    AlreadyExists,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KillShardOutcome {
    Terminated(CleanupResult),
    CleanupIncomplete(CleanupResult),
    AlreadyTerminated,
    CancellationRequested,
}

#[async_trait]
pub trait SandboxBackend: Send + Sync + 'static {
    fn capabilities(&self) -> SandboxCapabilities;

    async fn provision(&self, spec: &LaunchSpec) -> Result<SandboxHandle, SandboxError>;

    async fn revoke_egress(
        &self,
        handle: &SandboxHandle,
        reason: CleanupReason,
    ) -> Result<(), SandboxError>;

    async fn kill_cgroup(
        &self,
        handle: &SandboxHandle,
        reason: CleanupReason,
    ) -> Result<(), SandboxError>;

    async fn cleanup_namespaces(&self, handle: &SandboxHandle) -> Result<(), SandboxError>;

    async fn inspect(&self, handle: &SandboxHandle) -> Result<InspectResources, SandboxError>;
}

#[derive(Debug)]
struct ActiveShard {
    ownership: WorkerOwnership,
    handle: SandboxHandle,
}

#[derive(Debug)]
struct ProvisioningShard {
    ownership: WorkerOwnership,
    cancellation: Option<CleanupReason>,
}

#[derive(Debug)]
struct CleaningShard {
    worker_id: WorkerId,
    worker_epoch: u64,
    handle: SandboxHandle,
    reason: CleanupReason,
    progress: CleanupResult,
    in_progress: bool,
    notification_version: u64,
    notifications: watch::Sender<u64>,
}

#[derive(Debug)]
struct TerminatedShard {
    worker_id: WorkerId,
    worker_epoch: u64,
}

#[derive(Debug, Default)]
struct SupervisorState {
    active: HashMap<ShardId, ActiveShard>,
    provisioning: HashMap<ShardId, ProvisioningShard>,
    cleaning: HashMap<ShardId, CleaningShard>,
    terminated: HashMap<ShardId, TerminatedShard>,
}

#[derive(Debug)]
pub struct SandboxSupervisor<B> {
    config: SupervisorConfig,
    backend: Arc<B>,
    state: Arc<Mutex<SupervisorState>>,
}

impl<B> Clone for SandboxSupervisor<B> {
    fn clone(&self) -> Self {
        Self {
            config: self.config,
            backend: Arc::clone(&self.backend),
            state: Arc::clone(&self.state),
        }
    }
}

impl<B> SandboxSupervisor<B>
where
    B: SandboxBackend,
{
    pub fn new(config: SupervisorConfig, backend: B) -> Self {
        Self {
            config,
            backend: Arc::new(backend),
            state: Arc::new(Mutex::new(SupervisorState::default())),
        }
    }

    pub async fn create_shard(
        &self,
        spec: LaunchSpec,
        ownership: WorkerOwnership,
    ) -> Result<CreateShardOutcome, SandboxError> {
        let now = Instant::now();
        if ownership.expires_at <= now
            || ownership.expires_at.saturating_duration_since(now)
                > self.config.supervisor_lease_ttl
        {
            return Err(SandboxError::InvalidOwnerLease);
        }
        let capabilities = self.backend.capabilities();
        if let Some(name) = [
            ("user_namespace", capabilities.user_namespace),
            ("pid_namespace", capabilities.pid_namespace),
            ("mount_namespace", capabilities.mount_namespace),
            ("network_namespace", capabilities.network_namespace),
            ("private_tmp", capabilities.private_tmp),
            ("private_shm", capabilities.private_shm),
            ("cgroup_v2", capabilities.cgroup_v2),
            ("cgroup_kill", capabilities.cgroup_kill),
            ("no_new_privs", capabilities.no_new_privs),
            ("capabilities_dropped", capabilities.capabilities_dropped),
            ("deny_all_egress", capabilities.deny_all_egress),
        ]
        .into_iter()
        .find_map(|(name, available)| (!available).then_some(name))
        {
            return Err(SandboxError::MissingCapability { name });
        }
        if spec.worker_id != ownership.worker_id || spec.worker_epoch != ownership.worker_epoch {
            return Err(SandboxError::OwnershipMismatch);
        }

        {
            let mut state = self.state.lock().await;
            let existing_owner = state
                .active
                .get(&spec.shard_id)
                .map(|active| {
                    (
                        active.ownership.worker_id.clone(),
                        active.ownership.worker_epoch,
                    )
                })
                .or_else(|| {
                    state.provisioning.get(&spec.shard_id).map(|provisioning| {
                        (
                            provisioning.ownership.worker_id.clone(),
                            provisioning.ownership.worker_epoch,
                        )
                    })
                })
                .or_else(|| {
                    state
                        .cleaning
                        .get(&spec.shard_id)
                        .map(|cleaning| (cleaning.worker_id.clone(), cleaning.worker_epoch))
                });
            if let Some((existing_worker_id, existing_worker_epoch)) = existing_owner {
                if existing_worker_id != spec.worker_id {
                    return Err(SandboxError::OwnershipMismatch);
                }
                if existing_worker_epoch != spec.worker_epoch {
                    return Err(SandboxError::WorkerEpochMismatch {
                        expected: existing_worker_epoch,
                        actual: spec.worker_epoch,
                    });
                }
                return Ok(CreateShardOutcome::AlreadyExists);
            }
            if let Some(terminated) = state.terminated.get(&spec.shard_id) {
                if terminated.worker_id != spec.worker_id {
                    return Err(SandboxError::OwnershipMismatch);
                }
                if terminated.worker_epoch != spec.worker_epoch {
                    return Err(SandboxError::WorkerEpochMismatch {
                        expected: terminated.worker_epoch,
                        actual: spec.worker_epoch,
                    });
                }
                return Ok(CreateShardOutcome::AlreadyExists);
            }
            state.provisioning.insert(
                spec.shard_id.clone(),
                ProvisioningShard {
                    ownership: ownership.clone(),
                    cancellation: None,
                },
            );
        }

        let provisioned = self.backend.provision(&spec).await;
        let mut state = self.state.lock().await;
        let provisioning = state
            .provisioning
            .remove(&spec.shard_id)
            .ok_or_else(|| SandboxError::Backend("provisioning state disappeared".into()))?;
        match provisioned {
            Ok(handle) => {
                if let Some(reason) = provisioning.cancellation {
                    let (notifications, _) = watch::channel(0);
                    state.cleaning.insert(
                        spec.shard_id.clone(),
                        CleaningShard {
                            worker_id: ownership.worker_id.clone(),
                            worker_epoch: ownership.worker_epoch,
                            handle,
                            reason,
                            progress: CleanupResult {
                                route_revoked: false,
                                cgroup_killed: false,
                                namespaces_cleaned: false,
                            },
                            in_progress: false,
                            notification_version: 0,
                            notifications,
                        },
                    );
                    drop(state);
                    match self
                        .continue_cleanup(&spec.shard_id, ownership.worker_epoch)
                        .await?
                    {
                        KillShardOutcome::Terminated(_) => Ok(CreateShardOutcome::Cancelled),
                        KillShardOutcome::CleanupIncomplete(result) => {
                            Err(SandboxError::IncompleteCleanup { result })
                        }
                        KillShardOutcome::AlreadyTerminated => Ok(CreateShardOutcome::Cancelled),
                        KillShardOutcome::CancellationRequested => Err(SandboxError::Backend(
                            "cleanup did not acquire the provisioned shard".to_owned(),
                        )),
                    }
                } else {
                    state
                        .active
                        .insert(spec.shard_id, ActiveShard { ownership, handle });
                    Ok(CreateShardOutcome::Created)
                }
            }
            Err(error) => Err(error),
        }
    }

    pub async fn renew_owner_lease(
        &self,
        shard_id: &ShardId,
        worker_epoch: u64,
        now: Instant,
        new_expires_at: Instant,
    ) -> Result<(), RenewLeaseError> {
        let mut state = self.state.lock().await;
        let ownership = if let Some(active) = state.active.get_mut(shard_id) {
            &mut active.ownership
        } else if let Some(provisioning) = state.provisioning.get_mut(shard_id) {
            if provisioning.cancellation.is_some() {
                return Err(RenewLeaseError::ShardNotFound);
            }
            &mut provisioning.ownership
        } else {
            return Err(RenewLeaseError::ShardNotFound);
        };
        if ownership.worker_epoch != worker_epoch {
            return Err(RenewLeaseError::WorkerEpochMismatch {
                expected: ownership.worker_epoch,
                actual: worker_epoch,
            });
        }
        if ownership.expires_at <= now {
            return Err(RenewLeaseError::LeaseExpired);
        }
        if new_expires_at <= now || new_expires_at > now + self.config.supervisor_lease_ttl {
            return Err(RenewLeaseError::InvalidNewExpiry);
        }
        ownership.expires_at = new_expires_at;
        Ok(())
    }

    pub async fn expire_leases(&self, now: Instant) -> Vec<(ShardId, CleanupResult)> {
        let expired = {
            let mut state = self.state.lock().await;
            let expired = state
                .active
                .iter()
                .filter_map(|(shard_id, active)| {
                    (active.ownership.expires_at <= now)
                        .then_some((shard_id.clone(), active.ownership.worker_epoch))
                })
                .collect::<Vec<_>>();
            let expired_provisioning = state
                .provisioning
                .iter()
                .filter_map(|(shard_id, provisioning)| {
                    (provisioning.ownership.expires_at <= now
                        && provisioning.cancellation.is_none())
                    .then_some(shard_id.clone())
                })
                .collect::<Vec<_>>();
            for shard_id in expired_provisioning {
                if let Some(provisioning) = state.provisioning.get_mut(&shard_id) {
                    provisioning.cancellation = Some(CleanupReason::WorkerLeaseExpired);
                }
            }
            expired
        };

        join_all(
            expired
                .into_iter()
                .map(|(shard_id, worker_epoch)| async move {
                    let outcome = self
                        .kill_shard(&shard_id, worker_epoch, CleanupReason::WorkerLeaseExpired)
                        .await;
                    match outcome {
                        Ok(
                            KillShardOutcome::Terminated(result)
                            | KillShardOutcome::CleanupIncomplete(result),
                        ) => Some((shard_id, result)),
                        Ok(
                            KillShardOutcome::AlreadyTerminated
                            | KillShardOutcome::CancellationRequested,
                        )
                        | Err(_) => None,
                    }
                }),
        )
        .await
        .into_iter()
        .flatten()
        .collect()
    }

    pub async fn kill_shard(
        &self,
        shard_id: &ShardId,
        worker_epoch: u64,
        reason: CleanupReason,
    ) -> Result<KillShardOutcome, SandboxError> {
        {
            let mut state = self.state.lock().await;
            if let Some(terminated) = state.terminated.get(shard_id) {
                if terminated.worker_epoch != worker_epoch {
                    return Err(SandboxError::WorkerEpochMismatch {
                        expected: terminated.worker_epoch,
                        actual: worker_epoch,
                    });
                }
                return Ok(KillShardOutcome::AlreadyTerminated);
            }
            if let Some(provisioning) = state.provisioning.get_mut(shard_id) {
                if provisioning.ownership.worker_epoch != worker_epoch {
                    return Err(SandboxError::WorkerEpochMismatch {
                        expected: provisioning.ownership.worker_epoch,
                        actual: worker_epoch,
                    });
                }
                provisioning.cancellation = Some(reason);
                return Ok(KillShardOutcome::CancellationRequested);
            }
            if !state.cleaning.contains_key(shard_id) {
                let active = state
                    .active
                    .get(shard_id)
                    .ok_or(SandboxError::ShardNotFound)?;
                if active.ownership.worker_epoch != worker_epoch {
                    return Err(SandboxError::WorkerEpochMismatch {
                        expected: active.ownership.worker_epoch,
                        actual: worker_epoch,
                    });
                }
                let active = state
                    .active
                    .remove(shard_id)
                    .ok_or(SandboxError::ShardNotFound)?;
                let (notifications, _) = watch::channel(0);
                state.cleaning.insert(
                    shard_id.clone(),
                    CleaningShard {
                        worker_id: active.ownership.worker_id,
                        worker_epoch: active.ownership.worker_epoch,
                        handle: active.handle,
                        reason,
                        progress: CleanupResult {
                            route_revoked: false,
                            cgroup_killed: false,
                            namespaces_cleaned: false,
                        },
                        in_progress: false,
                        notification_version: 0,
                        notifications,
                    },
                );
            }
        }

        self.continue_cleanup(shard_id, worker_epoch).await
    }

    async fn continue_cleanup(
        &self,
        shard_id: &ShardId,
        worker_epoch: u64,
    ) -> Result<KillShardOutcome, SandboxError> {
        enum CleanupStep {
            Run {
                handle: SandboxHandle,
                reason: CleanupReason,
                progress: CleanupResult,
            },
            Wait(watch::Receiver<u64>),
            AlreadyTerminated,
        }

        loop {
            let step = {
                let mut state = self.state.lock().await;
                if let Some(terminated) = state.terminated.get(shard_id) {
                    if terminated.worker_epoch != worker_epoch {
                        return Err(SandboxError::WorkerEpochMismatch {
                            expected: terminated.worker_epoch,
                            actual: worker_epoch,
                        });
                    }
                    CleanupStep::AlreadyTerminated
                } else {
                    let cleaning = state
                        .cleaning
                        .get_mut(shard_id)
                        .ok_or(SandboxError::ShardNotFound)?;
                    if cleaning.worker_epoch != worker_epoch {
                        return Err(SandboxError::WorkerEpochMismatch {
                            expected: cleaning.worker_epoch,
                            actual: worker_epoch,
                        });
                    }
                    if cleaning.in_progress {
                        CleanupStep::Wait(cleaning.notifications.subscribe())
                    } else {
                        cleaning.in_progress = true;
                        CleanupStep::Run {
                            handle: cleaning.handle.clone(),
                            reason: cleaning.reason,
                            progress: cleaning.progress,
                        }
                    }
                }
            };

            match step {
                CleanupStep::AlreadyTerminated => {
                    return Ok(KillShardOutcome::AlreadyTerminated);
                }
                CleanupStep::Wait(mut notifications) => {
                    notifications
                        .changed()
                        .await
                        .map_err(|_| SandboxError::Backend("cleanup owner vanished".to_owned()))?;
                }
                CleanupStep::Run {
                    handle,
                    reason,
                    progress,
                } => {
                    let supervisor = self.clone();
                    let shard_id = shard_id.clone();
                    let cleanup = tokio::spawn(async move {
                        let mut result = progress;
                        if !result.route_revoked {
                            result.route_revoked = timeout(
                                supervisor.config.cleanup_stage_timeout,
                                supervisor.backend.revoke_egress(&handle, reason),
                            )
                            .await
                            .is_ok_and(|stage| stage.is_ok());
                        }
                        if !result.cgroup_killed {
                            result.cgroup_killed = timeout(
                                supervisor.config.cleanup_stage_timeout,
                                supervisor.backend.kill_cgroup(&handle, reason),
                            )
                            .await
                            .is_ok_and(|stage| stage.is_ok());
                        }
                        if !result.namespaces_cleaned {
                            result.namespaces_cleaned = timeout(
                                supervisor.config.cleanup_stage_timeout,
                                supervisor.backend.cleanup_namespaces(&handle),
                            )
                            .await
                            .is_ok_and(|stage| stage.is_ok());
                        }

                        let mut state = supervisor.state.lock().await;
                        let cleaning = state.cleaning.get_mut(&shard_id).ok_or_else(|| {
                            SandboxError::Backend("cleanup state vanished".to_owned())
                        })?;
                        cleaning.progress = result;
                        cleaning.in_progress = false;
                        cleaning.notification_version =
                            cleaning.notification_version.saturating_add(1);
                        cleaning
                            .notifications
                            .send_replace(cleaning.notification_version);
                        if result.route_revoked && result.cgroup_killed && result.namespaces_cleaned
                        {
                            let cleaning = state.cleaning.remove(&shard_id).ok_or_else(|| {
                                SandboxError::Backend("cleanup state vanished".to_owned())
                            })?;
                            state.terminated.insert(
                                shard_id,
                                TerminatedShard {
                                    worker_id: cleaning.worker_id,
                                    worker_epoch: cleaning.worker_epoch,
                                },
                            );
                            Ok(KillShardOutcome::Terminated(result))
                        } else {
                            Ok(KillShardOutcome::CleanupIncomplete(result))
                        }
                    });
                    return cleanup.await.map_err(|error| {
                        SandboxError::Backend(format!("cleanup task failed: {error}"))
                    })?;
                }
            }
        }
    }

    pub async fn inspect_resources(
        &self,
        shard_id: &ShardId,
        worker_epoch: u64,
    ) -> Result<InspectResources, SandboxError> {
        let handle = {
            let state = self.state.lock().await;
            let active = state
                .active
                .get(shard_id)
                .ok_or(SandboxError::ShardNotFound)?;
            if active.ownership.worker_epoch != worker_epoch {
                return Err(SandboxError::WorkerEpochMismatch {
                    expected: active.ownership.worker_epoch,
                    actual: worker_epoch,
                });
            }
            active.handle.clone()
        };
        self.backend.inspect(&handle).await
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum RenewLeaseError {
    #[error("sandbox shard does not exist")]
    ShardNotFound,
    #[error("worker epoch mismatch: expected {expected}, received {actual}")]
    WorkerEpochMismatch { expected: u64, actual: u64 },
    #[error("the supervisor lease has already expired")]
    LeaseExpired,
    #[error("the renewed supervisor lease exceeds its configured TTL")]
    InvalidNewExpiry,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SandboxError {
    #[error("supervisor and directory lease TTLs must be nonzero")]
    ZeroLeaseTtl,
    #[error("sandbox cleanup stage timeout must be nonzero")]
    ZeroCleanupTimeout,
    #[error("supervisor lease TTL cannot exceed directory lease TTL")]
    InvalidLeaseOrdering,
    #[error("production sandbox capability is missing: {name}")]
    MissingCapability { name: &'static str },
    #[error("launch spec and owner lease do not identify the same worker epoch")]
    OwnershipMismatch,
    #[error("owner lease is expired or exceeds the configured supervisor TTL")]
    InvalidOwnerLease,
    #[error("sandbox shard does not exist")]
    ShardNotFound,
    #[error("worker epoch mismatch: expected {expected}, received {actual}")]
    WorkerEpochMismatch { expected: u64, actual: u64 },
    #[error("sandbox has incomplete cleanup: {result:?}")]
    IncompleteCleanup { result: CleanupResult },
    #[error("sandbox backend failed: {0}")]
    Backend(String),
}
