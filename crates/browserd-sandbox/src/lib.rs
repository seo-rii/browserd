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
    CHROMIUM_CDP_READ_FD, CHROMIUM_CDP_WRITE_FD, CgroupLimits, ChildIdentity, ChromiumCdpPipes,
    ChromiumRuntime, EgressRouteBackend, LaunchGateRuntime, LinuxProcessBackend,
    LinuxSandboxBackend, LinuxSandboxConfig, NetworkNamespaceIdentity, PinnedNetworkNamespace,
    PreparedLinuxChild, ProcessSignal, ReadOnlyMount, SandboxFilesystem, ShardEgressFence,
    ShardEgressReservation, ShardIngressLease, ShardIngressReceipt, SpawnRequest,
    StdLinuxProcessBackend, StdSandboxFilesystem,
};
pub use rpc::{
    RpcFailureCode, SandboxRpcClient, SandboxRpcConfig, SandboxRpcError, SandboxRpcServer,
};

use std::collections::HashMap;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use browserd_core::{LeaseId, ShardId, WorkerId};
use futures::{FutureExt, future::join_all};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::{Mutex, oneshot, watch};
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

    /// Transfers the exact runtime's parent-side CDP capabilities at most once.
    /// Returning `Err` must not newly consume the capabilities during that call. The supervisor
    /// may cancel this future after its bounded claim interval; any uncertain effect must remain
    /// owned by `handle` so the ordinary revoke/kill/namespace cleanup path can close it
    /// fail-closed.
    async fn claim_cdp_pipes(
        &self,
        _handle: &SandboxHandle,
    ) -> Result<ChromiumCdpPipes, SandboxError> {
        Err(SandboxError::Backend(
            "CDP pipe claim is unsupported by this sandbox backend".into(),
        ))
    }

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
    cdp_claim: CdpClaimState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum CdpClaimState {
    Available,
    InProgress(LeaseId),
    Committed(LeaseId),
    Claimed,
}

enum CdpClaimReceipt {
    Commit {
        final_receipt: oneshot::Receiver<oneshot::Sender<()>>,
        accepted: oneshot::Sender<()>,
    },
    Reject(CleanupReason),
    AlreadyInactive,
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

pub(crate) struct PendingCdpClaim<B> {
    supervisor: SandboxSupervisor<B>,
    shard_id: ShardId,
    worker_id: WorkerId,
    worker_epoch: u64,
    transfer_id: LeaseId,
    pipes: Option<ChromiumCdpPipes>,
    receipt_sender: Option<oneshot::Sender<CdpClaimReceipt>>,
}

impl<B> PendingCdpClaim<B>
where
    B: SandboxBackend,
{
    pub(crate) const fn transfer_id(&self) -> &LeaseId {
        &self.transfer_id
    }

    pub(crate) fn pipes(&self) -> &ChromiumCdpPipes {
        self.pipes
            .as_ref()
            .unwrap_or_else(|| unreachable!("a pending claim always owns its pipes"))
    }

    pub(crate) async fn commit(mut self) -> Result<CommittedCdpClaim<B>, SandboxError> {
        let validation = {
            let mut state = self.supervisor.state.lock().await;
            match state.active.get_mut(&self.shard_id) {
                None => Err((
                    SandboxError::ShardNotFound,
                    CdpClaimReceipt::AlreadyInactive,
                )),
                Some(active) if active.ownership.worker_id != self.worker_id => Err((
                    SandboxError::OwnershipMismatch,
                    CdpClaimReceipt::AlreadyInactive,
                )),
                Some(active) if active.ownership.worker_epoch != self.worker_epoch => Err((
                    SandboxError::WorkerEpochMismatch {
                        expected: active.ownership.worker_epoch,
                        actual: self.worker_epoch,
                    },
                    CdpClaimReceipt::AlreadyInactive,
                )),
                Some(active)
                    if active.cdp_claim != CdpClaimState::InProgress(self.transfer_id.clone()) =>
                {
                    Err((
                        SandboxError::Backend(
                            "CDP claim reservation changed before caller receipt".to_owned(),
                        ),
                        CdpClaimReceipt::Reject(CleanupReason::BrowserFailure),
                    ))
                }
                Some(active) if active.ownership.expires_at <= Instant::now() => {
                    active.cdp_claim = CdpClaimState::Committed(self.transfer_id.clone());
                    Err((
                        SandboxError::InvalidOwnerLease,
                        CdpClaimReceipt::Reject(CleanupReason::WorkerLeaseExpired),
                    ))
                }
                Some(active) => {
                    active.cdp_claim = CdpClaimState::Committed(self.transfer_id.clone());
                    Ok(())
                }
            }
        };
        let receipt_sender = self.receipt_sender.take().ok_or_else(|| {
            SandboxError::Backend("CDP claim receipt channel is missing".to_owned())
        })?;
        if let Err((error, receipt)) = validation {
            let _ = receipt_sender.send(receipt);
            return Err(error);
        }

        let (final_receipt_sender, final_receipt_receiver) = oneshot::channel();
        let (accepted_sender, accepted_receiver) = oneshot::channel();
        if receipt_sender
            .send(CdpClaimReceipt::Commit {
                final_receipt: final_receipt_receiver,
                accepted: accepted_sender,
            })
            .is_err()
        {
            self.supervisor
                .cleanup_cdp_claim_until_terminal(
                    &self.shard_id,
                    self.worker_epoch,
                    CleanupReason::BrowserFailure,
                )
                .await;
            return Err(SandboxError::Backend(
                "CDP claim task failed before commit".to_owned(),
            ));
        }
        if accepted_receiver.await.is_err() {
            self.supervisor
                .cleanup_cdp_claim_until_terminal(
                    &self.shard_id,
                    self.worker_epoch,
                    CleanupReason::BrowserFailure,
                )
                .await;
            return Err(SandboxError::Backend(
                "CDP claim task failed while committing".to_owned(),
            ));
        }
        let pipes = self.pipes.take().ok_or_else(|| {
            SandboxError::Backend("CDP claim capabilities are missing".to_owned())
        })?;
        Ok(CommittedCdpClaim {
            supervisor: self.supervisor.clone(),
            shard_id: self.shard_id.clone(),
            worker_epoch: self.worker_epoch,
            pipes: Some(pipes),
            final_receipt_sender: Some(final_receipt_sender),
        })
    }
}

pub(crate) struct CommittedCdpClaim<B> {
    supervisor: SandboxSupervisor<B>,
    shard_id: ShardId,
    worker_epoch: u64,
    pipes: Option<ChromiumCdpPipes>,
    final_receipt_sender: Option<oneshot::Sender<oneshot::Sender<()>>>,
}

impl<B> CommittedCdpClaim<B>
where
    B: SandboxBackend,
{
    pub(crate) async fn finish(mut self) -> Result<ChromiumCdpPipes, SandboxError> {
        let pipes = self.pipes.take().ok_or_else(|| {
            SandboxError::Backend("committed CDP capabilities are missing".to_owned())
        })?;
        let final_receipt_sender = self.final_receipt_sender.take().ok_or_else(|| {
            SandboxError::Backend("committed CDP receipt channel is missing".to_owned())
        })?;
        let (completed_sender, completed_receiver) = oneshot::channel();
        if final_receipt_sender.send(completed_sender).is_err() {
            drop(pipes);
            self.supervisor
                .cleanup_cdp_claim_until_terminal(
                    &self.shard_id,
                    self.worker_epoch,
                    CleanupReason::BrowserFailure,
                )
                .await;
            return Err(SandboxError::Backend(
                "CDP claim task failed before final receipt".to_owned(),
            ));
        }
        if completed_receiver.await.is_err() {
            drop(pipes);
            self.supervisor
                .cleanup_cdp_claim_until_terminal(
                    &self.shard_id,
                    self.worker_epoch,
                    CleanupReason::BrowserFailure,
                )
                .await;
            return Err(SandboxError::Backend(
                "CDP claim task failed while finalizing receipt".to_owned(),
            ));
        }
        Ok(pipes)
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
                    state.active.insert(
                        spec.shard_id,
                        ActiveShard {
                            ownership,
                            handle,
                            cdp_claim: CdpClaimState::Available,
                        },
                    );
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
                            result.route_revoked = matches!(
                                timeout(
                                    supervisor.config.cleanup_stage_timeout,
                                    AssertUnwindSafe(
                                        supervisor.backend.revoke_egress(&handle, reason),
                                    )
                                    .catch_unwind(),
                                )
                                .await,
                                Ok(Ok(Ok(())))
                            );
                        }
                        if !result.cgroup_killed {
                            result.cgroup_killed = matches!(
                                timeout(
                                    supervisor.config.cleanup_stage_timeout,
                                    AssertUnwindSafe(
                                        supervisor.backend.kill_cgroup(&handle, reason),
                                    )
                                    .catch_unwind(),
                                )
                                .await,
                                Ok(Ok(Ok(())))
                            );
                        }
                        if !result.namespaces_cleaned {
                            result.namespaces_cleaned = matches!(
                                timeout(
                                    supervisor.config.cleanup_stage_timeout,
                                    AssertUnwindSafe(
                                        supervisor.backend.cleanup_namespaces(&handle),
                                    )
                                    .catch_unwind(),
                                )
                                .await,
                                Ok(Ok(Ok(())))
                            );
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

    pub(crate) async fn prepare_cdp_pipes(
        &self,
        shard_id: &ShardId,
        worker_id: &WorkerId,
        worker_epoch: u64,
    ) -> Result<PendingCdpClaim<B>, SandboxError> {
        let transfer_id = LeaseId::new();
        let handle = {
            let mut state = self.state.lock().await;
            let active = state
                .active
                .get_mut(shard_id)
                .ok_or(SandboxError::ShardNotFound)?;
            if active.ownership.worker_id != *worker_id {
                return Err(SandboxError::OwnershipMismatch);
            }
            if active.ownership.worker_epoch != worker_epoch {
                return Err(SandboxError::WorkerEpochMismatch {
                    expected: active.ownership.worker_epoch,
                    actual: worker_epoch,
                });
            }
            if active.ownership.expires_at <= Instant::now() {
                return Err(SandboxError::InvalidOwnerLease);
            }
            match &active.cdp_claim {
                CdpClaimState::Available => {
                    active.cdp_claim = CdpClaimState::InProgress(transfer_id.clone());
                }
                CdpClaimState::InProgress(_) => return Err(SandboxError::CdpClaimInProgress),
                CdpClaimState::Committed(_) => {
                    return Err(SandboxError::CdpPipesAlreadyClaimed);
                }
                CdpClaimState::Claimed => return Err(SandboxError::CdpPipesAlreadyClaimed),
            }
            active.handle.clone()
        };

        let supervisor = self.clone();
        let claim_shard_id = shard_id.clone();
        let claim_worker_id = worker_id.clone();
        let claim_transfer_id = transfer_id.clone();
        let (response_sender, response_receiver) = oneshot::channel();
        let (receipt_sender, receipt_receiver) = oneshot::channel();
        tokio::spawn(async move {
            if response_sender.is_closed() {
                let mut state = supervisor.state.lock().await;
                if let Some(active) = state.active.get_mut(&claim_shard_id)
                    && active.ownership.worker_id == claim_worker_id
                    && active.ownership.worker_epoch == worker_epoch
                    && active.cdp_claim == CdpClaimState::InProgress(claim_transfer_id.clone())
                {
                    active.cdp_claim = CdpClaimState::Available;
                }
                return;
            }

            let (backend_result, uncertain_backend_effect) = match timeout(
                supervisor.config.cleanup_stage_timeout,
                AssertUnwindSafe(supervisor.backend.claim_cdp_pipes(&handle)).catch_unwind(),
            )
            .await
            {
                Ok(Ok(result)) => (result, false),
                Ok(Err(_)) => (
                    Err(SandboxError::Backend(
                        "CDP capability backend panicked during claim".to_owned(),
                    )),
                    true,
                ),
                Err(_) => (
                    Err(SandboxError::Backend(
                        "CDP capability backend claim timed out".to_owned(),
                    )),
                    true,
                ),
            };
            let mut cleanup_reason = None;
            let response = {
                let mut state = supervisor.state.lock().await;
                match state.active.get_mut(&claim_shard_id) {
                    None => Err(SandboxError::ShardNotFound),
                    Some(active) if active.ownership.worker_id != claim_worker_id => {
                        Err(SandboxError::OwnershipMismatch)
                    }
                    Some(active) if active.ownership.worker_epoch != worker_epoch => {
                        Err(SandboxError::WorkerEpochMismatch {
                            expected: active.ownership.worker_epoch,
                            actual: worker_epoch,
                        })
                    }
                    Some(active)
                        if active.cdp_claim
                            != CdpClaimState::InProgress(claim_transfer_id.clone()) =>
                    {
                        cleanup_reason = Some(CleanupReason::BrowserFailure);
                        Err(SandboxError::Backend(
                            "CDP claim reservation changed during backend handoff".to_owned(),
                        ))
                    }
                    Some(active) if active.ownership.expires_at <= Instant::now() => {
                        active.cdp_claim = CdpClaimState::Claimed;
                        cleanup_reason = Some(CleanupReason::WorkerLeaseExpired);
                        Err(SandboxError::InvalidOwnerLease)
                    }
                    Some(active) if uncertain_backend_effect => {
                        active.cdp_claim = CdpClaimState::Claimed;
                        cleanup_reason = Some(CleanupReason::BrowserFailure);
                        backend_result
                    }
                    Some(active) => match backend_result {
                        Ok(pipes) => Ok(pipes),
                        Err(error) => {
                            active.cdp_claim = CdpClaimState::Available;
                            Err(error)
                        }
                    },
                }
            };

            if let Some(reason) = cleanup_reason {
                supervisor
                    .cleanup_cdp_claim_until_terminal(&claim_shard_id, worker_epoch, reason)
                    .await;
            }
            let response_contains_capability = response.is_ok();
            match response_sender.send(response) {
                Ok(()) if response_contains_capability => match receipt_receiver.await {
                    Ok(CdpClaimReceipt::Commit {
                        final_receipt,
                        accepted,
                    }) => {
                        if accepted.send(()).is_err() {
                            supervisor
                                .cleanup_cdp_claim_until_terminal(
                                    &claim_shard_id,
                                    worker_epoch,
                                    CleanupReason::BrowserFailure,
                                )
                                .await;
                            return;
                        }
                        let Ok(completed) = final_receipt.await else {
                            supervisor
                                .cleanup_cdp_claim_until_terminal(
                                    &claim_shard_id,
                                    worker_epoch,
                                    CleanupReason::BrowserFailure,
                                )
                                .await;
                            return;
                        };
                        let finalized = {
                            let mut state = supervisor.state.lock().await;
                            match state.active.get_mut(&claim_shard_id) {
                                Some(active)
                                    if active.ownership.worker_id == claim_worker_id
                                        && active.ownership.worker_epoch == worker_epoch
                                        && active.cdp_claim
                                            == CdpClaimState::Committed(
                                                claim_transfer_id.clone(),
                                            ) =>
                                {
                                    active.cdp_claim = CdpClaimState::Claimed;
                                    true
                                }
                                _ => false,
                            }
                        };
                        if !finalized || completed.send(()).is_err() {
                            supervisor
                                .cleanup_cdp_claim_until_terminal(
                                    &claim_shard_id,
                                    worker_epoch,
                                    CleanupReason::BrowserFailure,
                                )
                                .await;
                        }
                    }
                    Ok(CdpClaimReceipt::AlreadyInactive) => {}
                    Ok(CdpClaimReceipt::Reject(reason)) => {
                        supervisor
                            .cleanup_cdp_claim_until_terminal(&claim_shard_id, worker_epoch, reason)
                            .await;
                    }
                    Err(_) => {
                        let cleanup_reason = {
                            let mut state = supervisor.state.lock().await;
                            state.active.get_mut(&claim_shard_id).and_then(|active| {
                                if active.ownership.worker_id != claim_worker_id
                                    || active.ownership.worker_epoch != worker_epoch
                                    || !matches!(
                                        &active.cdp_claim,
                                        CdpClaimState::InProgress(transfer_id)
                                            | CdpClaimState::Committed(transfer_id)
                                            if transfer_id == &claim_transfer_id
                                    )
                                {
                                    return None;
                                }
                                if matches!(
                                    &active.cdp_claim,
                                    CdpClaimState::InProgress(transfer_id)
                                        if transfer_id == &claim_transfer_id
                                ) {
                                    active.cdp_claim =
                                        CdpClaimState::Committed(claim_transfer_id.clone());
                                }
                                Some(if active.ownership.expires_at <= Instant::now() {
                                    CleanupReason::WorkerLeaseExpired
                                } else {
                                    CleanupReason::BrowserFailure
                                })
                            })
                        };
                        if let Some(reason) = cleanup_reason {
                            supervisor
                                .cleanup_cdp_claim_until_terminal(
                                    &claim_shard_id,
                                    worker_epoch,
                                    reason,
                                )
                                .await;
                        }
                    }
                },
                Err(Ok(pipes)) => {
                    drop(pipes);
                    supervisor
                        .cleanup_cdp_claim_until_terminal(
                            &claim_shard_id,
                            worker_epoch,
                            CleanupReason::BrowserFailure,
                        )
                        .await;
                }
                Ok(()) | Err(Err(_)) => {}
            }
        });

        let response = response_receiver.await.map_err(|error| {
            SandboxError::Backend(format!("CDP claim task failed before responding: {error}"))
        })?;
        match response {
            Ok(pipes) => Ok(PendingCdpClaim {
                supervisor: self.clone(),
                shard_id: shard_id.clone(),
                worker_id: worker_id.clone(),
                worker_epoch,
                transfer_id,
                pipes: Some(pipes),
                receipt_sender: Some(receipt_sender),
            }),
            Err(error) => Err(error),
        }
    }

    async fn cleanup_cdp_claim_until_terminal(
        &self,
        shard_id: &ShardId,
        worker_epoch: u64,
        reason: CleanupReason,
    ) {
        let cleanup_window = self
            .config
            .cleanup_stage_timeout
            .saturating_mul(4)
            .max(Duration::from_millis(100));
        let cleanup_deadline = Instant::now() + cleanup_window;
        loop {
            match self.kill_shard(shard_id, worker_epoch, reason).await {
                Ok(KillShardOutcome::Terminated(_) | KillShardOutcome::AlreadyTerminated)
                | Err(SandboxError::ShardNotFound | SandboxError::WorkerEpochMismatch { .. }) => {
                    return;
                }
                Ok(
                    KillShardOutcome::CleanupIncomplete(_)
                    | KillShardOutcome::CancellationRequested,
                ) if Instant::now() < cleanup_deadline => {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
                Err(_) if Instant::now() < cleanup_deadline => {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
                Ok(_) | Err(_) => return,
            }
        }
    }

    pub(crate) fn start_cdp_claim_cleanup_guard(
        &self,
        shard_id: &ShardId,
        worker_epoch: u64,
    ) -> oneshot::Sender<()> {
        let cleanup_supervisor = self.clone();
        let cleanup_shard_id = shard_id.clone();
        let (claim_completed, claim_completion) = oneshot::channel();
        tokio::spawn(async move {
            if claim_completion.await.is_err() {
                cleanup_supervisor
                    .cleanup_cdp_claim_until_terminal(
                        &cleanup_shard_id,
                        worker_epoch,
                        CleanupReason::BrowserFailure,
                    )
                    .await;
            }
        });
        claim_completed
    }

    pub async fn claim_cdp_pipes(
        &self,
        shard_id: &ShardId,
        worker_id: &WorkerId,
        worker_epoch: u64,
    ) -> Result<ChromiumCdpPipes, SandboxError> {
        let pending = self
            .prepare_cdp_pipes(shard_id, worker_id, worker_epoch)
            .await?;
        let claim_completed = self.start_cdp_claim_cleanup_guard(shard_id, worker_epoch);
        let pipes = pending.commit().await?.finish().await?;
        let _ = claim_completed.send(());
        Ok(pipes)
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
    #[error("a CDP capability claim is already in progress")]
    CdpClaimInProgress,
    #[error("the CDP capabilities have already been claimed")]
    CdpPipesAlreadyClaimed,
    #[error("sandbox has incomplete cleanup: {result:?}")]
    IncompleteCleanup { result: CleanupResult },
    #[error("sandbox backend failed: {0}")]
    Backend(String),
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::sync::Mutex as StdMutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    struct ClaimReceiptTestBackend {
        pipes: StdMutex<Option<ChromiumCdpPipes>>,
        kill_calls: AtomicUsize,
        kill_reasons: StdMutex<Vec<CleanupReason>>,
        kill_called: tokio::sync::Notify,
    }

    #[async_trait]
    impl SandboxBackend for ClaimReceiptTestBackend {
        fn capabilities(&self) -> SandboxCapabilities {
            SandboxCapabilities::production_required()
        }

        async fn provision(&self, spec: &LaunchSpec) -> Result<SandboxHandle, SandboxError> {
            Ok(SandboxHandle::new(spec.shard_id().clone(), "receipt-test"))
        }

        async fn claim_cdp_pipes(
            &self,
            _handle: &SandboxHandle,
        ) -> Result<ChromiumCdpPipes, SandboxError> {
            self.pipes
                .lock()
                .expect("test pipe lock is available")
                .take()
                .ok_or(SandboxError::CdpPipesAlreadyClaimed)
        }

        async fn revoke_egress(
            &self,
            _handle: &SandboxHandle,
            _reason: CleanupReason,
        ) -> Result<(), SandboxError> {
            Ok(())
        }

        async fn kill_cgroup(
            &self,
            _handle: &SandboxHandle,
            reason: CleanupReason,
        ) -> Result<(), SandboxError> {
            self.kill_calls.fetch_add(1, Ordering::AcqRel);
            self.kill_reasons
                .lock()
                .expect("test kill-reason lock is available")
                .push(reason);
            self.kill_called.notify_one();
            Ok(())
        }

        async fn cleanup_namespaces(&self, _handle: &SandboxHandle) -> Result<(), SandboxError> {
            Ok(())
        }

        async fn inspect(&self, _handle: &SandboxHandle) -> Result<InspectResources, SandboxError> {
            Ok(InspectResources {
                memory_current_bytes: 0,
                memory_peak_bytes: 0,
                process_count: 1,
                egress_route_active: true,
            })
        }
    }

    async fn claim_receipt_test_supervisor(
        cleanup_stage_timeout: Duration,
    ) -> (
        SandboxSupervisor<ClaimReceiptTestBackend>,
        ShardId,
        WorkerId,
    ) {
        let (_command_reader, command_writer) =
            nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).expect("command pipe is created");
        let (event_reader, _event_writer) =
            nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).expect("event pipe is created");
        let pipes = ChromiumCdpPipes::from_owned_fds(command_writer, event_reader)
            .expect("test CDP capabilities are valid");
        let backend = ClaimReceiptTestBackend {
            pipes: StdMutex::new(Some(pipes)),
            kill_calls: AtomicUsize::new(0),
            kill_reasons: StdMutex::new(Vec::new()),
            kill_called: tokio::sync::Notify::new(),
        };
        let config = SupervisorConfig::new(Duration::from_secs(1), Duration::from_secs(2))
            .expect("test lease ordering is valid")
            .with_cleanup_stage_timeout(cleanup_stage_timeout)
            .expect("test cleanup timeout is valid");
        let supervisor = SandboxSupervisor::new(config, backend);
        let shard_id = ShardId::new();
        let worker_id = WorkerId::new("receipt-test-worker").expect("test worker ID is valid");
        supervisor
            .create_shard(
                LaunchSpec::production(shard_id.clone(), worker_id.clone(), 1),
                WorkerOwnership::new(
                    worker_id.clone(),
                    1,
                    Instant::now() + Duration::from_millis(900),
                ),
            )
            .await
            .expect("test shard is created");
        (supervisor, shard_id, worker_id)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn finishing_a_claim_synchronously_commits_the_supervisor_transaction() {
        let (supervisor, shard_id, worker_id) =
            claim_receipt_test_supervisor(Duration::from_millis(100)).await;

        let _pipes = tokio::time::timeout(Duration::from_millis(200), async {
            let pending = supervisor
                .prepare_cdp_pipes(&shard_id, &worker_id, 1)
                .await
                .expect("claim is prepared");
            let committed = pending.commit().await.expect("claim is committed");
            committed.finish().await.expect("claim is finished")
        })
        .await
        .expect("the receipt transaction must complete within its test bound");

        let state = supervisor.state.lock().await;
        let active = state.active.get(&shard_id).expect("shard remains active");
        assert_eq!(active.cdp_claim, CdpClaimState::Claimed);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn live_claim_guards_do_not_expire_while_the_owner_retains_them() {
        let cleanup_stage_timeout = Duration::from_millis(10);
        let (supervisor, shard_id, worker_id) =
            claim_receipt_test_supervisor(cleanup_stage_timeout).await;

        tokio::time::timeout(Duration::from_millis(500), async {
            let pending = supervisor
                .prepare_cdp_pipes(&shard_id, &worker_id, 1)
                .await
                .expect("claim is prepared");
            tokio::time::sleep(cleanup_stage_timeout.saturating_mul(3)).await;
            assert!(supervisor.state.lock().await.active.contains_key(&shard_id));
            assert_eq!(supervisor.backend.kill_calls.load(Ordering::Acquire), 0);

            let committed = pending.commit().await.expect("claim is committed");
            tokio::time::sleep(cleanup_stage_timeout.saturating_mul(3)).await;
            assert!(supervisor.state.lock().await.active.contains_key(&shard_id));
            assert_eq!(supervisor.backend.kill_calls.load(Ordering::Acquire), 0);

            let _pipes = committed.finish().await.expect("claim is finished");
        })
        .await
        .expect("live claim guards must finish within their test bound");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn dropping_an_unobserved_completed_claim_fails_closed() {
        let (supervisor, shard_id, worker_id) =
            claim_receipt_test_supervisor(Duration::from_millis(100)).await;
        let mut claim = Box::pin(supervisor.claim_cdp_pipes(&shard_id, &worker_id, 1));

        tokio::time::timeout(Duration::from_millis(200), async {
            loop {
                let claimed = {
                    let state = supervisor.state.lock().await;
                    state
                        .active
                        .get(&shard_id)
                        .is_some_and(|active| active.cdp_claim == CdpClaimState::Claimed)
                };
                if claimed {
                    break;
                }
                assert!(futures::poll!(claim.as_mut()).is_pending());
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the claim must reach its unobserved completed state");
        drop(claim);

        tokio::time::timeout(
            Duration::from_millis(100),
            supervisor.backend.kill_called.notified(),
        )
        .await
        .expect("dropping an unobserved claim result must kill the shard");
        assert_eq!(
            supervisor
                .backend
                .kill_reasons
                .lock()
                .expect("test kill-reason lock is available")
                .as_slice(),
            [CleanupReason::BrowserFailure]
        );
    }
}
