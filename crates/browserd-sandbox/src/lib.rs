//! Shard sandbox supervisor contract, ownership leases, and cleanup ordering.

mod journal;
mod linux;
mod netns_listener;
mod rpc;

#[cfg(test)]
mod netns_listener_tests;

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
pub use netns_listener::{
    DedicatedEgressListener, DedicatedEgressListenerError, DedicatedEgressListenerReceipt,
    create_dedicated_egress_listener,
};
pub use rpc::{
    RpcFailureCode, SandboxRpcClient, SandboxRpcConfig, SandboxRpcError, SandboxRpcPeerBinding,
    SandboxRpcServer,
};

use std::collections::HashMap;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use browserd_core::{EgressFence, LaunchGeneration, LeaseId, ShardId, TenantId, WorkerId};
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

pub const MAX_DEDICATED_EGRESS_LEASE_TTL: Duration = Duration::from_secs(5 * 60);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EgressPolicyBinding {
    profile: String,
    snapshot_digest: [u8; 32],
}

impl EgressPolicyBinding {
    pub fn new(
        profile: impl Into<String>,
        snapshot_digest: [u8; 32],
    ) -> Result<Self, SandboxError> {
        let binding = Self {
            profile: profile.into(),
            snapshot_digest,
        };
        binding.validate()?;
        Ok(binding)
    }

    fn validate(&self) -> Result<(), SandboxError> {
        if self.profile.is_empty()
            || self.profile.len() > 128
            || self.snapshot_digest == [0; 32]
            || !self.profile.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'-' | b'_' | b'.')
            })
        {
            return Err(SandboxError::InvalidEgressPolicyBinding);
        }
        Ok(())
    }

    pub fn profile(&self) -> &str {
        &self.profile
    }

    pub const fn snapshot_digest(&self) -> &[u8; 32] {
        &self.snapshot_digest
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DedicatedEgressSpec {
    egress_fence: EgressFence,
    policy_binding: EgressPolicyBinding,
    initial_lease_ttl_ms: u64,
}

impl DedicatedEgressSpec {
    pub fn new(
        egress_fence: EgressFence,
        policy_binding: EgressPolicyBinding,
        initial_lease_ttl: Duration,
    ) -> Result<Self, SandboxError> {
        let initial_lease_ttl_ms = u64::try_from(initial_lease_ttl.as_millis())
            .map_err(|_| SandboxError::InvalidEgressLease)?;
        let spec = Self {
            egress_fence,
            policy_binding,
            initial_lease_ttl_ms,
        };
        spec.validate()?;
        Ok(spec)
    }

    fn validate(&self) -> Result<(), SandboxError> {
        self.policy_binding.validate()?;
        if self.initial_lease_ttl_ms == 0
            || self.initial_lease_ttl_ms
                > u64::try_from(MAX_DEDICATED_EGRESS_LEASE_TTL.as_millis())
                    .map_err(|_| SandboxError::InvalidEgressLease)?
        {
            return Err(SandboxError::InvalidEgressLease);
        }
        Ok(())
    }

    pub const fn egress_fence(&self) -> &EgressFence {
        &self.egress_fence
    }

    pub const fn policy_binding(&self) -> &EgressPolicyBinding {
        &self.policy_binding
    }

    pub const fn initial_lease_ttl(&self) -> Duration {
        Duration::from_millis(self.initial_lease_ttl_ms)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchSpec {
    tenant_id: TenantId,
    shard_id: ShardId,
    worker_id: WorkerId,
    worker_epoch: u64,
    dedicated_egress: DedicatedEgressSpec,
}

impl LaunchSpec {
    pub fn production(tenant_id: TenantId, dedicated_egress: DedicatedEgressSpec) -> Self {
        let shard_fence = dedicated_egress.egress_fence().shard();
        Self {
            tenant_id,
            shard_id: shard_fence.shard_id().clone(),
            worker_id: shard_fence.owner().worker_id().clone(),
            worker_epoch: shard_fence.owner().worker_epoch().get(),
            dedicated_egress,
        }
    }

    pub(crate) fn from_wire(
        tenant_id: TenantId,
        shard_id: ShardId,
        worker_id: WorkerId,
        worker_epoch: u64,
        dedicated_egress: DedicatedEgressSpec,
    ) -> Result<Self, SandboxError> {
        let spec = Self {
            tenant_id,
            shard_id,
            worker_id,
            worker_epoch,
            dedicated_egress,
        };
        spec.validate()?;
        Ok(spec)
    }

    fn validate(&self) -> Result<(), SandboxError> {
        self.dedicated_egress.validate()?;
        let shard_fence = self.dedicated_egress.egress_fence().shard();
        if &self.shard_id != shard_fence.shard_id()
            || &self.worker_id != shard_fence.owner().worker_id()
            || self.worker_epoch != shard_fence.owner().worker_epoch().get()
        {
            return Err(SandboxError::LaunchFenceMismatch);
        }
        Ok(())
    }

    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    pub const fn shard_id(&self) -> &ShardId {
        &self.shard_id
    }

    pub const fn worker_id(&self) -> &WorkerId {
        &self.worker_id
    }

    pub const fn worker_epoch(&self) -> u64 {
        self.worker_epoch
    }

    pub const fn launch_generation(&self) -> LaunchGeneration {
        self.dedicated_egress
            .egress_fence()
            .shard()
            .launch_generation()
    }

    pub const fn dedicated_egress(&self) -> &DedicatedEgressSpec {
        &self.dedicated_egress
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

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ShutdownReport {
    cleaned_shards: usize,
    pending_shards: usize,
}

impl ShutdownReport {
    #[must_use]
    pub const fn is_complete(self) -> bool {
        self.pending_shards == 0
    }

    #[must_use]
    pub const fn cleaned_shards(self) -> usize {
        self.cleaned_shards
    }

    #[must_use]
    pub const fn pending_shards(self) -> usize {
        self.pending_shards
    }
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

    /// Creates all containment and egress state while keeping the Chromium launch gate closed.
    /// Backends that do not expose a gate may use the legacy `provision` behavior.
    async fn provision_gated(&self, spec: &LaunchSpec) -> Result<SandboxHandle, SandboxError> {
        self.provision(spec).await
    }

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

    /// Durably records that the worker receipted the exact CDP capabilities.
    async fn commit_cdp_claim(&self, _handle: &SandboxHandle) -> Result<(), SandboxError> {
        Ok(())
    }

    /// Releases the one-shot launch gate. This must be idempotent after an uncertain response.
    async fn activate(&self, _handle: &SandboxHandle) -> Result<(), SandboxError> {
        Ok(())
    }

    /// Extends the exact runtime's dedicated egress route before its local owner lease moves.
    async fn renew_egress(
        &self,
        _handle: &SandboxHandle,
        _lease_ttl: Duration,
    ) -> Result<(), SandboxError> {
        Err(SandboxError::Backend(
            "egress route renewal is unsupported by this sandbox backend".into(),
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
    launch_spec: LaunchSpec,
    ownership: WorkerOwnership,
    handle: SandboxHandle,
    renewal_operation: Arc<Mutex<()>>,
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
    launch_spec: LaunchSpec,
    ownership: WorkerOwnership,
    cancellation: Option<CleanupReason>,
    completion: watch::Sender<Option<Result<CreateShardOutcome, SandboxError>>>,
}

#[derive(Debug)]
struct FailedProvision {
    launch_spec: LaunchSpec,
    worker_id: WorkerId,
    worker_epoch: u64,
    error: SandboxError,
}

#[derive(Debug)]
struct CleaningShard {
    launch_spec: LaunchSpec,
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
    launch_spec: LaunchSpec,
    worker_id: WorkerId,
    worker_epoch: u64,
}

#[derive(Debug, Default)]
struct SupervisorState {
    admission_closed: bool,
    active: HashMap<ShardId, ActiveShard>,
    provisioning: HashMap<ShardId, ProvisioningShard>,
    failed: HashMap<ShardId, FailedProvision>,
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
    launch_generation: LaunchGeneration,
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
                    if active.launch_spec.launch_generation() != self.launch_generation =>
                {
                    Err((
                        SandboxError::LaunchGenerationMismatch,
                        CdpClaimReceipt::AlreadyInactive,
                    ))
                }
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
                    self.launch_generation,
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
                    self.launch_generation,
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
            launch_generation: self.launch_generation,
            pipes: Some(pipes),
            final_receipt_sender: Some(final_receipt_sender),
        })
    }
}

pub(crate) struct CommittedCdpClaim<B> {
    supervisor: SandboxSupervisor<B>,
    shard_id: ShardId,
    worker_epoch: u64,
    launch_generation: LaunchGeneration,
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
                    self.launch_generation,
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
                    self.launch_generation,
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
        spec.validate()?;
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

        let (mut completion, owns_provision) = {
            let mut state = self.state.lock().await;
            if state.admission_closed {
                return Err(SandboxError::AdmissionClosed);
            }
            if let Some(provisioning) = state.provisioning.get(&spec.shard_id) {
                if provisioning.ownership.worker_id != spec.worker_id {
                    return Err(SandboxError::OwnershipMismatch);
                }
                if provisioning.ownership.worker_epoch != spec.worker_epoch {
                    return Err(SandboxError::WorkerEpochMismatch {
                        expected: provisioning.ownership.worker_epoch,
                        actual: spec.worker_epoch,
                    });
                }
                if provisioning.launch_spec.dedicated_egress.egress_fence
                    != spec.dedicated_egress.egress_fence
                {
                    return Err(SandboxError::LaunchFenceMismatch);
                }
                if provisioning.launch_spec != spec {
                    return Err(SandboxError::LaunchBindingMismatch);
                }
                (provisioning.completion.subscribe(), false)
            } else {
                let existing_owner = state
                    .active
                    .get(&spec.shard_id)
                    .map(|active| {
                        (
                            active.ownership.worker_id.clone(),
                            active.ownership.worker_epoch,
                            active.launch_spec.clone(),
                        )
                    })
                    .or_else(|| {
                        state.cleaning.get(&spec.shard_id).map(|cleaning| {
                            (
                                cleaning.worker_id.clone(),
                                cleaning.worker_epoch,
                                cleaning.launch_spec.clone(),
                            )
                        })
                    });
                if let Some((existing_worker_id, existing_worker_epoch, existing_spec)) =
                    existing_owner
                {
                    if existing_worker_id != spec.worker_id {
                        return Err(SandboxError::OwnershipMismatch);
                    }
                    if existing_worker_epoch != spec.worker_epoch {
                        return Err(SandboxError::WorkerEpochMismatch {
                            expected: existing_worker_epoch,
                            actual: spec.worker_epoch,
                        });
                    }
                    if existing_spec.dedicated_egress.egress_fence
                        != spec.dedicated_egress.egress_fence
                    {
                        return Err(SandboxError::LaunchFenceMismatch);
                    }
                    if existing_spec != spec {
                        return Err(SandboxError::LaunchBindingMismatch);
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
                    if terminated.launch_spec.dedicated_egress.egress_fence
                        != spec.dedicated_egress.egress_fence
                    {
                        return Err(SandboxError::LaunchFenceMismatch);
                    }
                    if terminated.launch_spec != spec {
                        return Err(SandboxError::LaunchBindingMismatch);
                    }
                    return Ok(CreateShardOutcome::AlreadyExists);
                }
                if let Some(failed) = state.failed.get(&spec.shard_id) {
                    if failed.worker_id != spec.worker_id {
                        return Err(SandboxError::OwnershipMismatch);
                    }
                    if failed.worker_epoch != spec.worker_epoch {
                        return Err(SandboxError::WorkerEpochMismatch {
                            expected: failed.worker_epoch,
                            actual: spec.worker_epoch,
                        });
                    }
                    let failed_generation = failed
                        .launch_spec
                        .dedicated_egress
                        .egress_fence
                        .shard()
                        .launch_generation();
                    let requested_generation = spec
                        .dedicated_egress
                        .egress_fence
                        .shard()
                        .launch_generation();
                    if requested_generation <= failed_generation {
                        if failed.launch_spec.dedicated_egress.egress_fence
                            != spec.dedicated_egress.egress_fence
                        {
                            return Err(SandboxError::LaunchFenceMismatch);
                        }
                        if failed.launch_spec != spec {
                            return Err(SandboxError::LaunchBindingMismatch);
                        }
                        return Err(failed.error.clone());
                    }
                    if failed.launch_spec.tenant_id != spec.tenant_id {
                        return Err(SandboxError::LaunchBindingMismatch);
                    }
                    state.failed.remove(&spec.shard_id);
                }
                let (completion, receiver) = watch::channel(None);
                state.provisioning.insert(
                    spec.shard_id.clone(),
                    ProvisioningShard {
                        launch_spec: spec.clone(),
                        ownership: ownership.clone(),
                        cancellation: None,
                        completion,
                    },
                );
                (receiver, true)
            }
        };

        if owns_provision {
            let supervisor = self.clone();
            let owned_spec = spec.clone();
            tokio::spawn(async move {
                supervisor.run_provision_owner(owned_spec).await;
            });
        }

        loop {
            if let Some(result) = completion.borrow().clone() {
                return if owns_provision {
                    result
                } else {
                    match result {
                        Ok(CreateShardOutcome::Created) => Ok(CreateShardOutcome::AlreadyExists),
                        result => result,
                    }
                };
            }
            completion.changed().await.map_err(|_| {
                SandboxError::Backend(
                    "provisioning completion disappeared before publication".to_owned(),
                )
            })?;
        }
    }

    async fn run_provision_owner(&self, spec: LaunchSpec) {
        let provisioned = AssertUnwindSafe(self.backend.provision_gated(&spec))
            .catch_unwind()
            .await
            .unwrap_or_else(|_| {
                Err(SandboxError::Backend(
                    "sandbox backend panicked while provisioning".to_owned(),
                ))
            });
        let mut state = self.state.lock().await;
        let Some(provisioning) = state.provisioning.remove(&spec.shard_id) else {
            return;
        };
        let ownership = provisioning.ownership.clone();
        let completion = provisioning.completion.clone();
        match provisioned {
            Ok(handle) => {
                if let Some(reason) = provisioning.cancellation {
                    let (notifications, _) = watch::channel(0);
                    state.cleaning.insert(
                        spec.shard_id.clone(),
                        CleaningShard {
                            launch_spec: provisioning.launch_spec,
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
                    let result = match self
                        .continue_cleanup(
                            &spec.shard_id,
                            ownership.worker_epoch,
                            spec.launch_generation(),
                        )
                        .await
                    {
                        Ok(
                            KillShardOutcome::Terminated(_) | KillShardOutcome::AlreadyTerminated,
                        ) => Ok(CreateShardOutcome::Cancelled),
                        Ok(KillShardOutcome::CleanupIncomplete(result)) => {
                            Err(SandboxError::IncompleteCleanup { result })
                        }
                        Ok(KillShardOutcome::CancellationRequested) => Err(SandboxError::Backend(
                            "cleanup did not acquire the provisioned shard".to_owned(),
                        )),
                        Err(error) => Err(error),
                    };
                    let _ = completion.send(Some(result.clone()));
                    let _ = result;
                } else {
                    state.active.insert(
                        spec.shard_id.clone(),
                        ActiveShard {
                            launch_spec: spec,
                            ownership,
                            handle,
                            renewal_operation: Arc::new(Mutex::new(())),
                            cdp_claim: CdpClaimState::Available,
                        },
                    );
                    let result = Ok(CreateShardOutcome::Created);
                    let _ = completion.send(Some(result.clone()));
                    let _ = result;
                }
            }
            Err(error) => {
                state.failed.insert(
                    spec.shard_id.clone(),
                    FailedProvision {
                        launch_spec: provisioning.launch_spec,
                        worker_id: ownership.worker_id,
                        worker_epoch: ownership.worker_epoch,
                        error: error.clone(),
                    },
                );
                let result = Err(error);
                let _ = completion.send(Some(result.clone()));
                let _ = result;
            }
        }
    }

    pub async fn renew_owner_lease(
        &self,
        shard_id: &ShardId,
        worker_epoch: u64,
        launch_generation: LaunchGeneration,
        now: Instant,
        new_expires_at: Instant,
    ) -> Result<(), RenewLeaseError> {
        let renewal_operation = {
            let mut state = self.state.lock().await;
            if let Some(active) = state.active.get(shard_id) {
                if active.launch_spec.launch_generation() != launch_generation {
                    return Err(RenewLeaseError::LaunchGenerationMismatch);
                }
                if active.ownership.worker_epoch != worker_epoch {
                    return Err(RenewLeaseError::WorkerEpochMismatch {
                        expected: active.ownership.worker_epoch,
                        actual: worker_epoch,
                    });
                }
                if active.ownership.expires_at <= now {
                    return Err(RenewLeaseError::LeaseExpired);
                }
                if new_expires_at <= now
                    || new_expires_at < active.ownership.expires_at
                    || new_expires_at > now + self.config.supervisor_lease_ttl
                {
                    return Err(RenewLeaseError::InvalidNewExpiry);
                }
                Arc::clone(&active.renewal_operation)
            } else if let Some(provisioning) = state.provisioning.get_mut(shard_id) {
                if provisioning.launch_spec.launch_generation() != launch_generation {
                    return Err(RenewLeaseError::LaunchGenerationMismatch);
                }
                if provisioning.cancellation.is_some() {
                    return Err(RenewLeaseError::ShardNotFound);
                }
                if provisioning.ownership.worker_epoch != worker_epoch {
                    return Err(RenewLeaseError::WorkerEpochMismatch {
                        expected: provisioning.ownership.worker_epoch,
                        actual: worker_epoch,
                    });
                }
                if provisioning.ownership.expires_at <= now {
                    return Err(RenewLeaseError::LeaseExpired);
                }
                if new_expires_at <= now
                    || new_expires_at < provisioning.ownership.expires_at
                    || new_expires_at > now + self.config.supervisor_lease_ttl
                {
                    return Err(RenewLeaseError::InvalidNewExpiry);
                }
                provisioning.ownership.expires_at = new_expires_at;
                return Ok(());
            } else {
                return Err(RenewLeaseError::ShardNotFound);
            }
        };

        let _renewal_guard = renewal_operation.lock().await;
        let (handle, observed_expires_at) = {
            let state = self.state.lock().await;
            let active = state
                .active
                .get(shard_id)
                .ok_or(RenewLeaseError::ShardNotFound)?;
            if active.launch_spec.launch_generation() != launch_generation {
                return Err(RenewLeaseError::LaunchGenerationMismatch);
            }
            if active.ownership.worker_epoch != worker_epoch {
                return Err(RenewLeaseError::WorkerEpochMismatch {
                    expected: active.ownership.worker_epoch,
                    actual: worker_epoch,
                });
            }
            if active.ownership.expires_at <= now {
                return Err(RenewLeaseError::LeaseExpired);
            }
            if new_expires_at <= now
                || new_expires_at < active.ownership.expires_at
                || new_expires_at > now + self.config.supervisor_lease_ttl
            {
                return Err(RenewLeaseError::InvalidNewExpiry);
            }
            (active.handle.clone(), active.ownership.expires_at)
        };

        self.backend
            .renew_egress(&handle, new_expires_at.duration_since(now))
            .await
            .map_err(|_| RenewLeaseError::EgressRenewalFailed)?;

        let mut state = self.state.lock().await;
        let active = state
            .active
            .get_mut(shard_id)
            .ok_or(RenewLeaseError::ShardNotFound)?;
        if active.launch_spec.launch_generation() != launch_generation {
            return Err(RenewLeaseError::LaunchGenerationMismatch);
        }
        if active.ownership.worker_epoch != worker_epoch {
            return Err(RenewLeaseError::WorkerEpochMismatch {
                expected: active.ownership.worker_epoch,
                actual: worker_epoch,
            });
        }
        if active.handle != handle || active.ownership.expires_at != observed_expires_at {
            return Err(RenewLeaseError::ShardNotFound);
        }
        active.ownership.expires_at = new_expires_at;
        Ok(())
    }

    pub async fn expire_leases(&self, now: Instant) -> Vec<(ShardId, CleanupResult)> {
        let expired = {
            let mut state = self.state.lock().await;
            let mut expired = state
                .active
                .iter()
                .filter_map(|(shard_id, active)| {
                    (active.ownership.expires_at <= now).then_some((
                        shard_id.clone(),
                        active.ownership.worker_epoch,
                        active.launch_spec.launch_generation(),
                    ))
                })
                .collect::<Vec<_>>();
            expired.extend(state.cleaning.iter().filter_map(|(shard_id, cleaning)| {
                (!cleaning.in_progress).then_some((
                    shard_id.clone(),
                    cleaning.worker_epoch,
                    cleaning.launch_spec.launch_generation(),
                ))
            }));
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

        join_all(expired.into_iter().map(
            |(shard_id, worker_epoch, launch_generation)| async move {
                let outcome = self
                    .kill_shard(
                        &shard_id,
                        worker_epoch,
                        launch_generation,
                        CleanupReason::WorkerLeaseExpired,
                    )
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
            },
        ))
        .await
        .into_iter()
        .flatten()
        .collect()
    }

    /// Permanently closes admission and makes a bounded best effort to revoke and destroy every
    /// shard owned by this supervisor incarnation. An incomplete report requires process exit so
    /// the launch-gate EOF and startup reconciler remain the final fail-closed boundary.
    pub async fn shutdown_fail_closed(&self) -> ShutdownReport {
        let (initial_targets, provisioning_waiters) = {
            let mut state = self.state.lock().await;
            state.admission_closed = true;
            let initial_targets =
                state.active.len() + state.cleaning.len() + state.provisioning.len();
            let mut waiters = Vec::with_capacity(state.provisioning.len());
            for provisioning in state.provisioning.values_mut() {
                provisioning
                    .cancellation
                    .get_or_insert(CleanupReason::Administrative);
                waiters.push(provisioning.completion.subscribe());
            }
            (initial_targets, waiters)
        };

        let provision_deadline = self
            .config
            .cleanup_stage_timeout
            .saturating_mul(4)
            .max(Duration::from_millis(100));
        for mut completion in provisioning_waiters {
            let _ = timeout(provision_deadline, async {
                loop {
                    if completion.borrow().is_some() {
                        break;
                    }
                    if completion.changed().await.is_err() {
                        break;
                    }
                }
            })
            .await;
        }

        let mut owned = {
            let state = self.state.lock().await;
            state
                .active
                .iter()
                .map(|(shard_id, active)| {
                    (
                        shard_id.clone(),
                        active.ownership.worker_epoch,
                        active.launch_spec.launch_generation(),
                    )
                })
                .chain(state.cleaning.iter().map(|(shard_id, cleaning)| {
                    (
                        shard_id.clone(),
                        cleaning.worker_epoch,
                        cleaning.launch_spec.launch_generation(),
                    )
                }))
                .collect::<Vec<_>>()
        };
        owned.sort_unstable_by(|left, right| left.0.cmp(&right.0));
        owned.dedup();
        for (shard_id, worker_epoch, launch_generation) in owned {
            let _ = self
                .kill_shard(
                    &shard_id,
                    worker_epoch,
                    launch_generation,
                    CleanupReason::Administrative,
                )
                .await;
        }

        let pending_shards = {
            let state = self.state.lock().await;
            state.active.len() + state.cleaning.len() + state.provisioning.len()
        };
        ShutdownReport {
            cleaned_shards: initial_targets.saturating_sub(pending_shards),
            pending_shards,
        }
    }

    pub async fn kill_shard(
        &self,
        shard_id: &ShardId,
        worker_epoch: u64,
        launch_generation: LaunchGeneration,
        reason: CleanupReason,
    ) -> Result<KillShardOutcome, SandboxError> {
        {
            let mut state = self.state.lock().await;
            if let Some(terminated) = state.terminated.get(shard_id) {
                if terminated.launch_spec.launch_generation() != launch_generation {
                    return Err(SandboxError::LaunchGenerationMismatch);
                }
                if terminated.worker_epoch != worker_epoch {
                    return Err(SandboxError::WorkerEpochMismatch {
                        expected: terminated.worker_epoch,
                        actual: worker_epoch,
                    });
                }
                return Ok(KillShardOutcome::AlreadyTerminated);
            }
            if let Some(provisioning) = state.provisioning.get_mut(shard_id) {
                if provisioning.launch_spec.launch_generation() != launch_generation {
                    return Err(SandboxError::LaunchGenerationMismatch);
                }
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
                if active.launch_spec.launch_generation() != launch_generation {
                    return Err(SandboxError::LaunchGenerationMismatch);
                }
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
                        launch_spec: active.launch_spec,
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

        self.continue_cleanup(shard_id, worker_epoch, launch_generation)
            .await
    }

    async fn continue_cleanup(
        &self,
        shard_id: &ShardId,
        worker_epoch: u64,
        launch_generation: LaunchGeneration,
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
                    if terminated.launch_spec.launch_generation() != launch_generation {
                        return Err(SandboxError::LaunchGenerationMismatch);
                    }
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
                    if cleaning.launch_spec.launch_generation() != launch_generation {
                        return Err(SandboxError::LaunchGenerationMismatch);
                    }
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
                        let revoke = async {
                            if result.route_revoked {
                                return true;
                            }
                            matches!(
                                timeout(
                                    supervisor.config.cleanup_stage_timeout,
                                    AssertUnwindSafe(
                                        supervisor.backend.revoke_egress(&handle, reason),
                                    )
                                    .catch_unwind(),
                                )
                                .await,
                                Ok(Ok(Ok(())))
                            )
                        };
                        let kill = async {
                            if result.cgroup_killed {
                                return true;
                            }
                            matches!(
                                timeout(
                                    supervisor.config.cleanup_stage_timeout,
                                    AssertUnwindSafe(
                                        supervisor.backend.kill_cgroup(&handle, reason),
                                    )
                                    .catch_unwind(),
                                )
                                .await,
                                Ok(Ok(Ok(())))
                            )
                        };
                        (result.route_revoked, result.cgroup_killed) = tokio::join!(revoke, kill);
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
                                    launch_spec: cleaning.launch_spec,
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
        launch_generation: LaunchGeneration,
    ) -> Result<InspectResources, SandboxError> {
        let handle = {
            let state = self.state.lock().await;
            let active = state
                .active
                .get(shard_id)
                .ok_or(SandboxError::ShardNotFound)?;
            if active.launch_spec.launch_generation() != launch_generation {
                return Err(SandboxError::LaunchGenerationMismatch);
            }
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
        launch_generation: LaunchGeneration,
    ) -> Result<PendingCdpClaim<B>, SandboxError> {
        let transfer_id = LeaseId::new();
        let handle = {
            let mut state = self.state.lock().await;
            let active = state
                .active
                .get_mut(shard_id)
                .ok_or(SandboxError::ShardNotFound)?;
            if active.launch_spec.launch_generation() != launch_generation {
                return Err(SandboxError::LaunchGenerationMismatch);
            }
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
                    && active.launch_spec.launch_generation() == launch_generation
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
                    Some(active) if active.launch_spec.launch_generation() != launch_generation => {
                        Err(SandboxError::LaunchGenerationMismatch)
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
                    .cleanup_cdp_claim_until_terminal(
                        &claim_shard_id,
                        worker_epoch,
                        launch_generation,
                        reason,
                    )
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
                                    launch_generation,
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
                                    launch_generation,
                                    CleanupReason::BrowserFailure,
                                )
                                .await;
                            return;
                        };
                        let activation_handle = {
                            let state = supervisor.state.lock().await;
                            state.active.get(&claim_shard_id).and_then(|active| {
                                (active.ownership.worker_id == claim_worker_id
                                    && active.ownership.worker_epoch == worker_epoch
                                    && active.launch_spec.launch_generation() == launch_generation
                                    && active.cdp_claim
                                        == CdpClaimState::Committed(claim_transfer_id.clone()))
                                .then(|| active.handle.clone())
                            })
                        };
                        let activated = if let Some(handle) = activation_handle {
                            matches!(
                                timeout(
                                    supervisor.config.cleanup_stage_timeout.saturating_mul(2),
                                    AssertUnwindSafe(async {
                                        supervisor.backend.commit_cdp_claim(&handle).await?;
                                        supervisor.backend.activate(&handle).await
                                    })
                                    .catch_unwind(),
                                )
                                .await,
                                Ok(Ok(Ok(())))
                            )
                        } else {
                            false
                        };
                        let finalized = if activated {
                            let mut state = supervisor.state.lock().await;
                            match state.active.get_mut(&claim_shard_id) {
                                Some(active)
                                    if active.ownership.worker_id == claim_worker_id
                                        && active.ownership.worker_epoch == worker_epoch
                                        && active.launch_spec.launch_generation()
                                            == launch_generation
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
                        } else {
                            false
                        };
                        if !finalized || completed.send(()).is_err() {
                            supervisor
                                .cleanup_cdp_claim_until_terminal(
                                    &claim_shard_id,
                                    worker_epoch,
                                    launch_generation,
                                    CleanupReason::BrowserFailure,
                                )
                                .await;
                        }
                    }
                    Ok(CdpClaimReceipt::AlreadyInactive) => {}
                    Ok(CdpClaimReceipt::Reject(reason)) => {
                        supervisor
                            .cleanup_cdp_claim_until_terminal(
                                &claim_shard_id,
                                worker_epoch,
                                launch_generation,
                                reason,
                            )
                            .await;
                    }
                    Err(_) => {
                        let cleanup_reason = {
                            let mut state = supervisor.state.lock().await;
                            state.active.get_mut(&claim_shard_id).and_then(|active| {
                                if active.ownership.worker_id != claim_worker_id
                                    || active.ownership.worker_epoch != worker_epoch
                                    || active.launch_spec.launch_generation() != launch_generation
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
                                    launch_generation,
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
                            launch_generation,
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
                launch_generation,
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
        launch_generation: LaunchGeneration,
        reason: CleanupReason,
    ) {
        let cleanup_window = self
            .config
            .cleanup_stage_timeout
            .saturating_mul(4)
            .max(Duration::from_millis(100));
        let cleanup_deadline = Instant::now() + cleanup_window;
        loop {
            match self
                .kill_shard(shard_id, worker_epoch, launch_generation, reason)
                .await
            {
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
        launch_generation: LaunchGeneration,
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
                        launch_generation,
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
        launch_generation: LaunchGeneration,
    ) -> Result<ChromiumCdpPipes, SandboxError> {
        let pending = self
            .prepare_cdp_pipes(shard_id, worker_id, worker_epoch, launch_generation)
            .await?;
        let claim_completed =
            self.start_cdp_claim_cleanup_guard(shard_id, worker_epoch, launch_generation);
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
    #[error("launch generation mismatch")]
    LaunchGenerationMismatch,
    #[error("the supervisor lease has already expired")]
    LeaseExpired,
    #[error("the renewed supervisor lease exceeds its configured TTL")]
    InvalidNewExpiry,
    #[error("the dedicated egress lease could not be renewed")]
    EgressRenewalFailed,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SandboxError {
    #[error("launch generation mismatch")]
    LaunchGenerationMismatch,
    #[error("supervisor and directory lease TTLs must be nonzero")]
    ZeroLeaseTtl,
    #[error("sandbox cleanup stage timeout must be nonzero")]
    ZeroCleanupTimeout,
    #[error("supervisor lease TTL cannot exceed directory lease TTL")]
    InvalidLeaseOrdering,
    #[error("dedicated egress policy binding is invalid")]
    InvalidEgressPolicyBinding,
    #[error("dedicated egress lease TTL must be nonzero and at most five minutes")]
    InvalidEgressLease,
    #[error("launch identity does not match the dedicated egress fence")]
    LaunchFenceMismatch,
    #[error("launch immutable binding conflicts with the existing shard")]
    LaunchBindingMismatch,
    #[error("production sandbox capability is missing: {name}")]
    MissingCapability { name: &'static str },
    #[error("launch spec and owner lease do not identify the same worker epoch")]
    OwnershipMismatch,
    #[error("owner lease is expired or exceeds the configured supervisor TTL")]
    InvalidOwnerLease,
    #[error("sandbox supervisor admission is permanently closed")]
    AdmissionClosed,
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
        let worker_epoch = browserd_core::WorkerEpoch::new(1).expect("worker epoch is positive");
        let egress_fence = EgressFence::new(
            browserd_core::ShardFence::new(
                browserd_core::OwnerFence::new(worker_id.clone(), worker_epoch),
                shard_id.clone(),
                browserd_core::LaunchGeneration::new(1).expect("launch generation is positive"),
            ),
            browserd_core::RouteGeneration::new(1).expect("route generation is positive"),
            browserd_core::SessionId::new(),
            browserd_core::SessionIncarnation::new(1).expect("session incarnation is positive"),
        );
        let policy_binding = EgressPolicyBinding::new("test-public-web", [1; 32])
            .expect("test policy binding is valid");
        let dedicated_egress =
            DedicatedEgressSpec::new(egress_fence, policy_binding, Duration::from_millis(500))
                .expect("test egress spec is valid");
        supervisor
            .create_shard(
                LaunchSpec::production(TenantId::new(), dedicated_egress),
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
                .prepare_cdp_pipes(
                    &shard_id,
                    &worker_id,
                    1,
                    LaunchGeneration::new(1).expect("generation"),
                )
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
                .prepare_cdp_pipes(
                    &shard_id,
                    &worker_id,
                    1,
                    LaunchGeneration::new(1).expect("generation"),
                )
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
        let mut claim = Box::pin(supervisor.claim_cdp_pipes(
            &shard_id,
            &worker_id,
            1,
            LaunchGeneration::new(1).expect("generation"),
        ));

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
