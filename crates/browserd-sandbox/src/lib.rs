//! Shard sandbox supervisor contract, ownership leases, and cleanup ordering.

mod linux;

pub use linux::{
    CHROMIUM_CDP_READ_FD, CHROMIUM_CDP_WRITE_FD, CgroupLimits, ChildIdentity, ChromiumRuntime,
    EgressRouteBackend, LinuxProcessBackend, LinuxSandboxBackend, LinuxSandboxConfig,
    ProcessSignal, ReadOnlyMount, SandboxFilesystem, SpawnRequest, StdLinuxProcessBackend,
    StdSandboxFilesystem,
};

use std::collections::HashMap;
use std::time::Duration;

use async_trait::async_trait;
use browserd_core::{ShardId, WorkerId};
use thiserror::Error;
use tokio::sync::Mutex;
use tokio::time::Instant;

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
        })
    }

    pub const fn supervisor_lease_ttl(self) -> Duration {
        self.supervisor_lease_ttl
    }

    pub const fn directory_lease_ttl(self) -> Duration {
        self.directory_lease_ttl
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CleanupReason {
    WorkerLeaseExpired,
    SecurityViolation,
    Administrative,
    BrowserFailure,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CleanupResult {
    pub route_revoked: bool,
    pub cgroup_killed: bool,
    pub namespaces_cleaned: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InspectResources {
    pub memory_current_bytes: u64,
    pub memory_peak_bytes: u64,
    pub process_count: u32,
    pub egress_route_active: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CreateShardOutcome {
    Created,
    AlreadyExists,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KillShardOutcome {
    Terminated(CleanupResult),
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

#[derive(Debug, Default)]
struct SupervisorState {
    active: HashMap<ShardId, ActiveShard>,
    provisioning: HashMap<ShardId, ProvisioningShard>,
    terminated: HashMap<ShardId, u64>,
}

#[derive(Debug)]
pub struct SandboxSupervisor<B> {
    config: SupervisorConfig,
    backend: B,
    state: Mutex<SupervisorState>,
}

impl<B> SandboxSupervisor<B>
where
    B: SandboxBackend,
{
    pub fn new(config: SupervisorConfig, backend: B) -> Self {
        Self {
            config,
            backend,
            state: Mutex::new(SupervisorState::default()),
        }
    }

    pub async fn create_shard(
        &self,
        spec: LaunchSpec,
        ownership: WorkerOwnership,
    ) -> Result<CreateShardOutcome, SandboxError> {
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
            if state.active.contains_key(&spec.shard_id)
                || state.provisioning.contains_key(&spec.shard_id)
                || state.terminated.contains_key(&spec.shard_id)
            {
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
                    state
                        .terminated
                        .insert(spec.shard_id.clone(), ownership.worker_epoch);
                    drop(state);
                    let cleanup = self.cleanup(&handle, reason).await;
                    if cleanup.route_revoked && cleanup.cgroup_killed && cleanup.namespaces_cleaned
                    {
                        Ok(CreateShardOutcome::Cancelled)
                    } else {
                        Err(SandboxError::IncompleteCleanup { result: cleanup })
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
            let expired_ids = state
                .active
                .iter()
                .filter_map(|(shard_id, active)| {
                    (active.ownership.expires_at <= now).then_some(shard_id.clone())
                })
                .collect::<Vec<_>>();
            let expired_provisioning = state
                .provisioning
                .iter()
                .filter_map(|(shard_id, provisioning)| {
                    (provisioning.ownership.expires_at <= now
                        && provisioning.cancellation.is_none())
                    .then_some((shard_id.clone(), provisioning.ownership.worker_epoch))
                })
                .collect::<Vec<_>>();
            for (shard_id, worker_epoch) in expired_provisioning {
                if let Some(provisioning) = state.provisioning.get_mut(&shard_id) {
                    provisioning.cancellation = Some(CleanupReason::WorkerLeaseExpired);
                }
                state.terminated.insert(shard_id, worker_epoch);
            }
            expired_ids
                .into_iter()
                .filter_map(|shard_id| {
                    state.active.remove(&shard_id).map(|active| {
                        state
                            .terminated
                            .insert(shard_id.clone(), active.ownership.worker_epoch);
                        (shard_id, active.handle)
                    })
                })
                .collect::<Vec<_>>()
        };

        let mut results = Vec::with_capacity(expired.len());
        for (shard_id, handle) in expired {
            let result = self
                .cleanup(&handle, CleanupReason::WorkerLeaseExpired)
                .await;
            results.push((shard_id, result));
        }
        results
    }

    pub async fn kill_shard(
        &self,
        shard_id: &ShardId,
        worker_epoch: u64,
        reason: CleanupReason,
    ) -> Result<KillShardOutcome, SandboxError> {
        let handle = {
            let mut state = self.state.lock().await;
            if let Some(terminated_epoch) = state.terminated.get(shard_id) {
                if *terminated_epoch != worker_epoch {
                    return Err(SandboxError::WorkerEpochMismatch {
                        expected: *terminated_epoch,
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
                state.terminated.insert(shard_id.clone(), worker_epoch);
                return Ok(KillShardOutcome::CancellationRequested);
            }
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
            state
                .terminated
                .insert(shard_id.clone(), active.ownership.worker_epoch);
            active.handle
        };

        Ok(KillShardOutcome::Terminated(
            self.cleanup(&handle, reason).await,
        ))
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

    async fn cleanup(&self, handle: &SandboxHandle, reason: CleanupReason) -> CleanupResult {
        let route_revoked = self.backend.revoke_egress(handle, reason).await.is_ok();
        let cgroup_killed = self.backend.kill_cgroup(handle, reason).await.is_ok();
        let namespaces_cleaned = self.backend.cleanup_namespaces(handle).await.is_ok();
        CleanupResult {
            route_revoked,
            cgroup_killed,
            namespaces_cleaned,
        }
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
    #[error("supervisor lease TTL cannot exceed directory lease TTL")]
    InvalidLeaseOrdering,
    #[error("production sandbox capability is missing: {name}")]
    MissingCapability { name: &'static str },
    #[error("launch spec and owner lease do not identify the same worker epoch")]
    OwnershipMismatch,
    #[error("sandbox shard does not exist")]
    ShardNotFound,
    #[error("worker epoch mismatch: expected {expected}, received {actual}")]
    WorkerEpochMismatch { expected: u64, actual: u64 },
    #[error("sandbox has incomplete cleanup: {result:?}")]
    IncompleteCleanup { result: CleanupResult },
    #[error("sandbox backend failed: {0}")]
    Backend(String),
}
