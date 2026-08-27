use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use browserd_core::{LaunchGeneration, SessionId, ShardFence, ShardId, TenantId, WorkerId};
use browserd_sandbox::{
    ChromiumCdpPipes, CleanupReason, CreateShardOutcome, KillShardOutcome, LaunchSpec,
    SandboxRpcClient, SandboxRpcError,
};
use browserd_session::OwnershipFence;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use crate::{BrowserShardRuntime, ShardRuntimeError};

#[derive(Clone, Debug)]
pub struct ShardLaunchDescriptor {
    launch_spec: LaunchSpec,
    shard_fence: ShardFence,
    resource_profile: String,
    isolation_profile: String,
}

impl ShardLaunchDescriptor {
    pub fn new(
        launch_spec: LaunchSpec,
        shard_fence: ShardFence,
        resource_profile: impl Into<String>,
        isolation_profile: impl Into<String>,
    ) -> Result<Self, ShardRuntimeError> {
        let resource_profile = resource_profile.into();
        let isolation_profile = isolation_profile.into();
        let launch_fence = launch_spec.dedicated_egress().egress_fence().shard();
        if launch_fence != &shard_fence
            || launch_spec.shard_id() != shard_fence.shard_id()
            || launch_spec.worker_id() != shard_fence.owner().worker_id()
            || launch_spec.worker_epoch() != shard_fence.owner().worker_epoch().get()
            || !valid_profile(&resource_profile)
            || !valid_profile(&isolation_profile)
        {
            return Err(ShardRuntimeError::Rejected);
        }
        Ok(Self {
            launch_spec,
            shard_fence,
            resource_profile,
            isolation_profile,
        })
    }

    #[must_use]
    pub const fn launch_spec(&self) -> &LaunchSpec {
        &self.launch_spec
    }

    #[must_use]
    pub const fn shard_fence(&self) -> &ShardFence {
        &self.shard_fence
    }

    #[must_use]
    pub fn resource_profile(&self) -> &str {
        &self.resource_profile
    }

    #[must_use]
    pub fn isolation_profile(&self) -> &str {
        &self.isolation_profile
    }
}

fn valid_profile(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

#[async_trait]
pub trait SandboxShardRpc: Send + Sync + 'static {
    async fn create_shard(
        &self,
        spec: LaunchSpec,
        lease_ttl: Duration,
    ) -> Result<CreateShardOutcome, ShardRuntimeError>;

    async fn claim_cdp_pipes(
        &self,
        shard_id: &ShardId,
        worker_id: &WorkerId,
        worker_epoch: u64,
        launch_generation: LaunchGeneration,
    ) -> Result<ChromiumCdpPipes, ShardRuntimeError>;

    async fn kill_shard(
        &self,
        shard_id: &ShardId,
        worker_epoch: u64,
        launch_generation: LaunchGeneration,
        reason: CleanupReason,
    ) -> Result<KillShardOutcome, ShardRuntimeError>;
}

#[async_trait]
impl SandboxShardRpc for SandboxRpcClient {
    async fn create_shard(
        &self,
        spec: LaunchSpec,
        lease_ttl: Duration,
    ) -> Result<CreateShardOutcome, ShardRuntimeError> {
        SandboxRpcClient::create_shard(self, spec, lease_ttl)
            .await
            .map_err(map_rpc_error)
    }

    async fn claim_cdp_pipes(
        &self,
        shard_id: &ShardId,
        worker_id: &WorkerId,
        worker_epoch: u64,
        launch_generation: LaunchGeneration,
    ) -> Result<ChromiumCdpPipes, ShardRuntimeError> {
        SandboxRpcClient::claim_cdp_pipes(
            self,
            shard_id,
            worker_id,
            worker_epoch,
            launch_generation,
        )
        .await
        .map_err(map_rpc_error)
    }

    async fn kill_shard(
        &self,
        shard_id: &ShardId,
        worker_epoch: u64,
        launch_generation: LaunchGeneration,
        reason: CleanupReason,
    ) -> Result<KillShardOutcome, ShardRuntimeError> {
        SandboxRpcClient::kill_shard(self, shard_id, worker_epoch, launch_generation, reason)
            .await
            .map_err(map_rpc_error)
    }
}

#[async_trait]
pub trait CdpPipeAcceptor: Send + Sync + 'static {
    /// Takes exclusive ownership of both capability FDs. Returning success means the exact
    /// Chromium transport has accepted them; they must never be reused.
    async fn accept_cdp_pipes(&self, pipes: ChromiumCdpPipes) -> Result<(), ShardRuntimeError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProvisionState {
    New,
    Ready,
    Tainted,
    Terminated,
}

pub struct ProductionSandboxShardRuntime<B, C, R> {
    descriptor: ShardLaunchDescriptor,
    lease_ttl: Duration,
    rpc: Arc<B>,
    cdp: Arc<C>,
    inner: Arc<R>,
    state: Mutex<ProvisionState>,
}

impl<B, C, R> ProductionSandboxShardRuntime<B, C, R> {
    #[must_use]
    pub fn new(
        descriptor: ShardLaunchDescriptor,
        lease_ttl: Duration,
        rpc: Arc<B>,
        cdp: Arc<C>,
        inner: Arc<R>,
    ) -> Self {
        Self {
            descriptor,
            lease_ttl,
            rpc,
            cdp,
            inner,
            state: Mutex::new(ProvisionState::New),
        }
    }

    fn validate_fence(&self, fence: &ShardFence) -> Result<(), ShardRuntimeError> {
        if fence == self.descriptor.shard_fence() {
            Ok(())
        } else {
            Err(ShardRuntimeError::Rejected)
        }
    }

    async fn cleanup_shard(&self, reason: CleanupReason) -> Result<(), ShardRuntimeError>
    where
        B: SandboxShardRpc,
    {
        match self
            .rpc
            .kill_shard(
                self.descriptor.launch_spec().shard_id(),
                self.descriptor.launch_spec().worker_epoch(),
                self.descriptor.launch_spec().launch_generation(),
                reason,
            )
            .await?
        {
            KillShardOutcome::Terminated(_) | KillShardOutcome::AlreadyTerminated => Ok(()),
            KillShardOutcome::CleanupIncomplete(_) | KillShardOutcome::CancellationRequested => {
                Err(ShardRuntimeError::OutcomeUncertain)
            }
        }
    }
}

#[async_trait]
impl<B, C, R> BrowserShardRuntime for ProductionSandboxShardRuntime<B, C, R>
where
    B: SandboxShardRpc,
    C: CdpPipeAcceptor,
    R: BrowserShardRuntime,
{
    async fn readiness_check(
        &self,
        fence: &ShardFence,
        cancellation: CancellationToken,
    ) -> Result<(), ShardRuntimeError> {
        self.validate_fence(fence)?;
        let mut state = self.state.lock().await;
        match *state {
            ProvisionState::Ready => return Ok(()),
            ProvisionState::New => {}
            ProvisionState::Tainted | ProvisionState::Terminated => {
                return Err(ShardRuntimeError::Rejected);
            }
        }
        if cancellation.is_cancelled() || self.lease_ttl.is_zero() {
            return Err(ShardRuntimeError::Cancelled);
        }
        match self
            .rpc
            .create_shard(self.descriptor.launch_spec().clone(), self.lease_ttl)
            .await?
        {
            CreateShardOutcome::Created | CreateShardOutcome::AlreadyExists => {}
            CreateShardOutcome::Cancelled => return Err(ShardRuntimeError::Cancelled),
        }
        let setup = async {
            if cancellation.is_cancelled() {
                return Err(ShardRuntimeError::Cancelled);
            }
            let pipes = self
                .rpc
                .claim_cdp_pipes(
                    self.descriptor.launch_spec().shard_id(),
                    self.descriptor.launch_spec().worker_id(),
                    self.descriptor.launch_spec().worker_epoch(),
                    self.descriptor.launch_spec().launch_generation(),
                )
                .await?;
            self.cdp.accept_cdp_pipes(pipes).await?;
            self.inner.readiness_check(fence, cancellation).await
        }
        .await;
        if let Err(error) = setup {
            *state = ProvisionState::Tainted;
            return match self.cleanup_shard(CleanupReason::BrowserFailure).await {
                Ok(()) => Err(error),
                Err(_) => Err(ShardRuntimeError::OutcomeUncertain),
            };
        }
        *state = ProvisionState::Ready;
        Ok(())
    }

    async fn create_context(
        &self,
        session_id: &SessionId,
        fence: &OwnershipFence,
        cancellation: CancellationToken,
    ) -> Result<(), ShardRuntimeError> {
        if *self.state.lock().await != ProvisionState::Ready {
            return Err(ShardRuntimeError::Rejected);
        }
        self.inner
            .create_context(session_id, fence, cancellation)
            .await
    }

    async fn create_context_owned(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        fence: &OwnershipFence,
        cancellation: CancellationToken,
    ) -> Result<(), ShardRuntimeError> {
        if *self.state.lock().await != ProvisionState::Ready {
            return Err(ShardRuntimeError::Rejected);
        }
        self.inner
            .create_context_owned(tenant_id, session_id, fence, cancellation)
            .await
    }

    async fn dispose_context(
        &self,
        session_id: &SessionId,
        fence: &OwnershipFence,
        cancellation: CancellationToken,
    ) -> Result<(), ShardRuntimeError> {
        if *self.state.lock().await != ProvisionState::Ready {
            return Err(ShardRuntimeError::Rejected);
        }
        self.inner
            .dispose_context(session_id, fence, cancellation)
            .await
    }

    async fn terminate(&self, fence: &ShardFence) -> Result<(), ShardRuntimeError> {
        self.validate_fence(fence)?;
        let mut state = self.state.lock().await;
        if *state == ProvisionState::Terminated {
            return Ok(());
        }
        let inner = self.inner.terminate(fence).await;
        let cleanup = self.cleanup_shard(CleanupReason::WorkerLeaseExpired).await;
        *state = ProvisionState::Terminated;
        match (inner, cleanup) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(ShardRuntimeError::OutcomeUncertain), _) | (_, Err(_)) => {
                Err(ShardRuntimeError::OutcomeUncertain)
            }
            (Err(error), Ok(())) => Err(error),
        }
    }
}

fn map_rpc_error(error: SandboxRpcError) -> ShardRuntimeError {
    match error {
        SandboxRpcError::InvalidConfig | SandboxRpcError::InvalidLease => {
            ShardRuntimeError::Rejected
        }
        SandboxRpcError::Remote { .. } => ShardRuntimeError::Rejected,
        _ => ShardRuntimeError::OutcomeUncertain,
    }
}
