use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use browserd_core::{LaunchGeneration, SessionId, ShardFence, ShardId, TenantId, WorkerId};
use browserd_sandbox::{
    ChromiumCdpPipes, CleanupReason, CreateShardOutcome, KillShardOutcome, LaunchSpec,
    SandboxRpcClient, SandboxRpcError,
};
use browserd_session::OwnershipFence;
use tokio::sync::{Mutex, RwLock, oneshot, watch};
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

    async fn cancel_or_kill_shard(
        &self,
        spec: &LaunchSpec,
        reason: CleanupReason,
    ) -> Result<KillShardOutcome, ShardRuntimeError>;

    async fn claim_cdp_pipes(
        &self,
        shard_id: &ShardId,
        worker_id: &WorkerId,
        worker_epoch: u64,
        launch_generation: LaunchGeneration,
    ) -> Result<ChromiumCdpPipes, ShardRuntimeError>;

    async fn renew_owner_lease(
        &self,
        shard_id: &ShardId,
        worker_epoch: u64,
        launch_generation: LaunchGeneration,
        lease_ttl: Duration,
    ) -> Result<(), ShardRuntimeError>;

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

    async fn cancel_or_kill_shard(
        &self,
        spec: &LaunchSpec,
        reason: CleanupReason,
    ) -> Result<KillShardOutcome, ShardRuntimeError> {
        SandboxRpcClient::cancel_or_kill_shard(self, spec, reason)
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

    async fn renew_owner_lease(
        &self,
        shard_id: &ShardId,
        worker_epoch: u64,
        launch_generation: LaunchGeneration,
        lease_ttl: Duration,
    ) -> Result<(), ShardRuntimeError> {
        SandboxRpcClient::renew_owner_lease(
            self,
            shard_id,
            worker_epoch,
            launch_generation,
            lease_ttl,
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

    /// Cancels and joins every execution owner created after accepting the CDP capabilities.
    async fn shutdown_cdp(&self) -> Result<(), ShardRuntimeError>;
}

async fn cleanup_runtime<B, C, R>(
    rpc: &B,
    cdp: &C,
    inner: &R,
    spec: &LaunchSpec,
    fence: &ShardFence,
    reason: CleanupReason,
) -> Result<(), ShardRuntimeError>
where
    B: SandboxShardRpc,
    C: CdpPipeAcceptor,
    R: BrowserShardRuntime,
{
    let (local, sandbox) = tokio::join!(
        cleanup_local(cdp, inner, fence),
        exact_cleanup(rpc, spec, reason),
    );
    sandbox?;
    local
}

async fn cleanup_local<C, R>(
    cdp: &C,
    inner: &R,
    fence: &ShardFence,
) -> Result<(), ShardRuntimeError>
where
    C: CdpPipeAcceptor,
    R: BrowserShardRuntime,
{
    let inner = inner.terminate(fence).await;
    let cdp = cdp.shutdown_cdp().await;
    match (inner, cdp) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(ShardRuntimeError::OutcomeUncertain), _)
        | (_, Err(ShardRuntimeError::OutcomeUncertain)) => Err(ShardRuntimeError::OutcomeUncertain),
        (Err(error), _) | (_, Err(error)) => Err(error),
    }
}

async fn exact_cleanup<B>(
    rpc: &B,
    spec: &LaunchSpec,
    reason: CleanupReason,
) -> Result<(), ShardRuntimeError>
where
    B: SandboxShardRpc,
{
    match rpc.cancel_or_kill_shard(spec, reason).await {
        Ok(KillShardOutcome::Terminated(_) | KillShardOutcome::AlreadyTerminated) => Ok(()),
        Ok(KillShardOutcome::CleanupIncomplete(_) | KillShardOutcome::CancellationRequested)
        | Err(_) => Err(ShardRuntimeError::OutcomeUncertain),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProvisionState {
    New,
    Provisioning,
    Ready,
    Tainted,
    Terminating,
    Terminated,
}

#[derive(Clone)]
struct ProvisionAttempt {
    cancellation: CancellationToken,
    completion: CancellationToken,
}

struct RuntimeState {
    phase: ProvisionState,
    provision: Option<ProvisionAttempt>,
    termination: Option<watch::Receiver<Option<Result<(), ShardRuntimeError>>>>,
}

struct CancelOnDrop(CancellationToken);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

pub struct ProductionSandboxShardRuntime<B, C, R> {
    descriptor: ShardLaunchDescriptor,
    lease_ttl: Duration,
    rpc: Arc<B>,
    cdp: Arc<C>,
    inner: Arc<R>,
    state: Arc<Mutex<RuntimeState>>,
    operations: Arc<RwLock<()>>,
    operation_cancellation: CancellationToken,
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
            state: Arc::new(Mutex::new(RuntimeState {
                phase: ProvisionState::New,
                provision: None,
                termination: None,
            })),
            operations: Arc::new(RwLock::new(())),
            operation_cancellation: CancellationToken::new(),
        }
    }

    fn validate_fence(&self, fence: &ShardFence) -> Result<(), ShardRuntimeError> {
        if fence == self.descriptor.shard_fence() {
            Ok(())
        } else {
            Err(ShardRuntimeError::Rejected)
        }
    }

    async fn admit_operation(
        &self,
    ) -> Result<tokio::sync::RwLockReadGuard<'_, ()>, ShardRuntimeError> {
        let operation = self.operations.read().await;
        if self.state.lock().await.phase != ProvisionState::Ready {
            return Err(ShardRuntimeError::Rejected);
        }
        Ok(operation)
    }

    pub async fn renew_owner_lease(&self, fence: &ShardFence) -> Result<(), ShardRuntimeError>
    where
        B: SandboxShardRpc,
    {
        self.validate_fence(fence)?;
        let _operation = self.admit_operation().await?;
        let lifecycle = self.operation_cancellation.child_token();
        let _cancel_on_drop = CancelOnDrop(lifecycle.clone());
        tokio::select! {
            biased;
            () = lifecycle.cancelled() => Err(ShardRuntimeError::Cancelled),
            result = self.rpc.renew_owner_lease(
                self.descriptor.launch_spec().shard_id(),
                self.descriptor.launch_spec().worker_epoch(),
                self.descriptor.launch_spec().launch_generation(),
                self.lease_ttl,
            ) => result,
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
        if cancellation.is_cancelled() || self.lease_ttl.is_zero() {
            return Err(ShardRuntimeError::Cancelled);
        }
        let attempt = ProvisionAttempt {
            cancellation: CancellationToken::new(),
            completion: CancellationToken::new(),
        };
        {
            let mut state = self.state.lock().await;
            match state.phase {
                ProvisionState::Ready => return Ok(()),
                ProvisionState::New => {
                    state.phase = ProvisionState::Provisioning;
                    state.provision = Some(attempt.clone());
                }
                ProvisionState::Provisioning
                | ProvisionState::Tainted
                | ProvisionState::Terminating
                | ProvisionState::Terminated => {
                    return Err(ShardRuntimeError::Rejected);
                }
            }
        }
        let (disarm_cleanup, cleanup_disarmed) = oneshot::channel::<()>();
        let cleanup_rpc = Arc::clone(&self.rpc);
        let cleanup_cdp = Arc::clone(&self.cdp);
        let cleanup_inner = Arc::clone(&self.inner);
        let cleanup_spec = self.descriptor.launch_spec().clone();
        let cleanup_fence = fence.clone();
        let cleanup_state = Arc::clone(&self.state);
        let cleanup_completion = attempt.completion.clone();
        let cleanup_task = tokio::spawn(async move {
            let cleanup = match cleanup_disarmed.await {
                Ok(()) => Ok(()),
                Err(_) => {
                    let cleanup_is_owned_by_termination = {
                        let state = cleanup_state.lock().await;
                        matches!(
                            state.phase,
                            ProvisionState::Terminating | ProvisionState::Terminated
                        )
                    };
                    if cleanup_is_owned_by_termination {
                        Ok(())
                    } else {
                        cleanup_runtime(
                            cleanup_rpc.as_ref(),
                            cleanup_cdp.as_ref(),
                            cleanup_inner.as_ref(),
                            &cleanup_spec,
                            &cleanup_fence,
                            CleanupReason::BrowserFailure,
                        )
                        .await
                    }
                }
            };
            let mut state = cleanup_state.lock().await;
            if state.phase == ProvisionState::Provisioning {
                state.phase = ProvisionState::Tainted;
            }
            state.provision = None;
            drop(state);
            cleanup_completion.cancel();
            cleanup
        });
        let operation_cancel = attempt.cancellation.clone();
        let provision = tokio::select! {
            biased;
            () = cancellation.cancelled() => {
                attempt.cancellation.cancel();
                Err(ShardRuntimeError::Cancelled)
            },
            () = attempt.cancellation.cancelled() => Err(ShardRuntimeError::Cancelled),
            result = async {
                match self
                    .rpc
                    .create_shard(self.descriptor.launch_spec().clone(), self.lease_ttl)
                    .await?
                {
                    CreateShardOutcome::Created | CreateShardOutcome::AlreadyExists => {}
                    CreateShardOutcome::Cancelled => {
                        return Err(ShardRuntimeError::Cancelled);
                    }
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
                self.inner.readiness_check(fence, operation_cancel).await
            } => result,
        };
        match provision {
            Ok(()) => {
                let mut state = self.state.lock().await;
                if state.phase != ProvisionState::Provisioning {
                    drop(state);
                    drop(disarm_cleanup);
                    let result = match cleanup_task.await {
                        Ok(Ok(())) => Err(ShardRuntimeError::Cancelled),
                        Ok(Err(_)) | Err(_) => Err(ShardRuntimeError::OutcomeUncertain),
                    };
                    if !attempt.completion.is_cancelled() {
                        let mut state = self.state.lock().await;
                        state.provision = None;
                        attempt.completion.cancel();
                    }
                    return result;
                }
                if disarm_cleanup.send(()).is_err() {
                    state.phase = ProvisionState::Tainted;
                    state.provision = None;
                    attempt.completion.cancel();
                    cleanup_task.abort();
                    return Err(ShardRuntimeError::OutcomeUncertain);
                }
                state.phase = ProvisionState::Ready;
                state.provision = None;
                attempt.completion.cancel();
                cleanup_task.abort();
                Ok(())
            }
            Err(error) => {
                let mut state = self.state.lock().await;
                if state.phase == ProvisionState::Provisioning {
                    state.phase = ProvisionState::Tainted;
                }
                drop(state);
                drop(disarm_cleanup);
                let result = match cleanup_task.await {
                    Ok(Ok(())) => Err(error),
                    Ok(Err(_)) | Err(_) => Err(ShardRuntimeError::OutcomeUncertain),
                };
                if !attempt.completion.is_cancelled() {
                    let mut state = self.state.lock().await;
                    state.provision = None;
                    attempt.completion.cancel();
                }
                result
            }
        }
    }

    async fn create_context(
        &self,
        session_id: &SessionId,
        fence: &OwnershipFence,
        cancellation: CancellationToken,
    ) -> Result<(), ShardRuntimeError> {
        let _operation = self.admit_operation().await?;
        let lifecycle = self.operation_cancellation.child_token();
        let _cancel_on_drop = CancelOnDrop(lifecycle.clone());
        let operation_cancel = lifecycle.clone();
        tokio::select! {
            biased;
            () = cancellation.cancelled() => Err(ShardRuntimeError::Cancelled),
            () = lifecycle.cancelled() => Err(ShardRuntimeError::Cancelled),
            result = self.inner.create_context(
                session_id,
                fence,
                operation_cancel,
            ) => result,
        }
    }

    async fn create_context_owned(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        fence: &OwnershipFence,
        cancellation: CancellationToken,
    ) -> Result<(), ShardRuntimeError> {
        let _operation = self.admit_operation().await?;
        let lifecycle = self.operation_cancellation.child_token();
        let _cancel_on_drop = CancelOnDrop(lifecycle.clone());
        let operation_cancel = lifecycle.clone();
        tokio::select! {
            biased;
            () = cancellation.cancelled() => Err(ShardRuntimeError::Cancelled),
            () = lifecycle.cancelled() => Err(ShardRuntimeError::Cancelled),
            result = self.inner.create_context_owned(
                tenant_id,
                session_id,
                fence,
                operation_cancel,
            ) => result,
        }
    }

    async fn dispose_context(
        &self,
        session_id: &SessionId,
        fence: &OwnershipFence,
        cancellation: CancellationToken,
    ) -> Result<(), ShardRuntimeError> {
        let _operation = self.admit_operation().await?;
        let lifecycle = self.operation_cancellation.child_token();
        let _cancel_on_drop = CancelOnDrop(lifecycle.clone());
        let operation_cancel = lifecycle.clone();
        tokio::select! {
            biased;
            () = cancellation.cancelled() => Err(ShardRuntimeError::Cancelled),
            () = lifecycle.cancelled() => Err(ShardRuntimeError::Cancelled),
            result = self.inner.dispose_context(
                session_id,
                fence,
                operation_cancel,
            ) => result,
        }
    }

    async fn terminate(&self, fence: &ShardFence) -> Result<(), ShardRuntimeError> {
        self.validate_fence(fence)?;
        let (mut completion, start) = {
            let mut state = self.state.lock().await;
            match state.phase {
                ProvisionState::Terminated => return Ok(()),
                ProvisionState::Terminating => {
                    let completion = state
                        .termination
                        .as_ref()
                        .cloned()
                        .ok_or(ShardRuntimeError::OutcomeUncertain)?;
                    (completion, None)
                }
                ProvisionState::New
                | ProvisionState::Provisioning
                | ProvisionState::Ready
                | ProvisionState::Tainted => {
                    let provision = state.provision.take();
                    let (sender, receiver) = watch::channel(None);
                    state.phase = ProvisionState::Terminating;
                    state.termination = Some(receiver.clone());
                    (receiver, Some((sender, provision)))
                }
            }
        };
        if let Some((sender, provision)) = start {
            self.operation_cancellation.cancel();
            let rpc = Arc::clone(&self.rpc);
            let cdp = Arc::clone(&self.cdp);
            let inner = Arc::clone(&self.inner);
            let operations = Arc::clone(&self.operations);
            let state = Arc::clone(&self.state);
            let spec = self.descriptor.launch_spec().clone();
            let fence = fence.clone();
            tokio::spawn(async move {
                if let Some(provision) = provision.as_ref() {
                    provision.cancellation.cancel();
                }
                let quiesce = async {
                    if let Some(provision) = provision.as_ref() {
                        provision.completion.cancelled().await;
                    }
                    operations.write_owned().await
                };
                let (preemptive, operation_guard) = tokio::join!(
                    exact_cleanup(rpc.as_ref(), &spec, CleanupReason::WorkerLeaseExpired,),
                    quiesce,
                );
                let local = cleanup_local(cdp.as_ref(), inner.as_ref(), &fence).await;
                let result = match (preemptive, local) {
                    (Ok(()), Ok(())) => Ok(()),
                    (Err(_), _) | (_, Err(ShardRuntimeError::OutcomeUncertain)) => {
                        Err(ShardRuntimeError::OutcomeUncertain)
                    }
                    (Ok(()), Err(error)) => Err(error),
                };
                drop(operation_guard);
                {
                    let mut state = state.lock().await;
                    state.provision = None;
                    state.termination = None;
                    state.phase = if result.is_ok() {
                        ProvisionState::Terminated
                    } else {
                        ProvisionState::Tainted
                    };
                }
                sender.send_replace(Some(result));
            });
        }
        loop {
            if let Some(result) = *completion.borrow() {
                return result;
            }
            if completion.changed().await.is_err() {
                let mut state = self.state.lock().await;
                if state.phase == ProvisionState::Terminating {
                    state.phase = ProvisionState::Tainted;
                    state.termination = None;
                }
                return Err(ShardRuntimeError::OutcomeUncertain);
            }
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
