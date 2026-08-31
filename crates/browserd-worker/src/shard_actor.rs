use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex, MutexGuard};

use async_trait::async_trait;
use browserd_core::{
    SessionId, ShardAdmission, ShardEvent, ShardFence, ShardHealth, ShardLifecycle, ShardState,
    TenantId,
};
use browserd_session::OwnershipFence;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::{SandboxTerminationProof, WorkerSessionOptionsV1};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShardRuntimeError {
    Unavailable,
    Rejected,
    OutcomeUncertain,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShardActorError {
    InvalidConfiguration,
    StaleShardFence,
    StaleSessionFence,
    InvalidLifecycle,
    AdmissionClosed,
    CapacityExceeded,
    SessionNotFound,
    MailboxFull,
    OwnershipLost,
    ActorStopped,
    Runtime(ShardRuntimeError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachSessionOutcome {
    Attached,
    AlreadyAttached,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DetachSessionOutcome {
    Detached,
    AlreadyDetached,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrowserShardSnapshot {
    pub fence: ShardFence,
    pub lifecycle: ShardLifecycle,
    pub health: ShardHealth,
    pub admission: ShardAdmission,
    pub live_sessions: usize,
    pub total_contexts_created: u64,
}

#[derive(Clone, Debug)]
pub struct BrowserShardActorConfig {
    fence: ShardFence,
    mailbox_capacity: usize,
    max_live_sessions: usize,
    max_contexts_created_lifetime: u64,
}

impl BrowserShardActorConfig {
    pub fn new(
        fence: ShardFence,
        mailbox_capacity: usize,
        max_live_sessions: usize,
        max_contexts_created_lifetime: u64,
    ) -> Result<Self, ShardActorError> {
        let live_limit_exceeds_lifetime = match u64::try_from(max_live_sessions) {
            Ok(maximum) => maximum > max_contexts_created_lifetime,
            Err(_) => true,
        };
        if mailbox_capacity == 0
            || max_live_sessions == 0
            || max_contexts_created_lifetime == 0
            || live_limit_exceeds_lifetime
        {
            return Err(ShardActorError::InvalidConfiguration);
        }
        Ok(Self {
            fence,
            mailbox_capacity,
            max_live_sessions,
            max_contexts_created_lifetime,
        })
    }

    #[must_use]
    pub const fn fence(&self) -> &ShardFence {
        &self.fence
    }
}

#[async_trait]
pub trait BrowserShardRuntime: Send + Sync + 'static {
    async fn readiness_check(
        &self,
        fence: &ShardFence,
        cancellation: CancellationToken,
    ) -> Result<(), ShardRuntimeError>;

    async fn create_context(
        &self,
        session_id: &SessionId,
        fence: &OwnershipFence,
        cancellation: CancellationToken,
    ) -> Result<(), ShardRuntimeError>;

    async fn create_context_owned(
        &self,
        _tenant_id: &TenantId,
        session_id: &SessionId,
        fence: &OwnershipFence,
        cancellation: CancellationToken,
    ) -> Result<(), ShardRuntimeError> {
        self.create_context(session_id, fence, cancellation).await
    }

    async fn create_context_owned_with_options(
        &self,
        _tenant_id: &TenantId,
        _session_id: &SessionId,
        _fence: &OwnershipFence,
        _options: &WorkerSessionOptionsV1,
        _cancellation: CancellationToken,
    ) -> Result<(), ShardRuntimeError> {
        Err(ShardRuntimeError::Rejected)
    }

    async fn dispose_context(
        &self,
        session_id: &SessionId,
        fence: &OwnershipFence,
        cancellation: CancellationToken,
    ) -> Result<(), ShardRuntimeError>;

    async fn terminate(&self, fence: &ShardFence) -> Result<(), ShardRuntimeError>;

    /// Releases only local runtime ownership after exact sandbox termination has been proven.
    async fn force_terminate(
        &self,
        fence: &ShardFence,
        proof: &SandboxTerminationProof,
    ) -> Result<(), ShardRuntimeError> {
        if !proof.matches_fence(fence) {
            return Err(ShardRuntimeError::Rejected);
        }
        self.terminate(fence).await
    }
}

type ActorResult<T> = Result<T, ShardActorError>;

enum Command {
    Activate {
        fence: ShardFence,
        reply: oneshot::Sender<ActorResult<()>>,
    },
    AttachSession {
        shard_fence: ShardFence,
        tenant_id: Option<TenantId>,
        session_id: SessionId,
        session_fence: OwnershipFence,
        options: Option<Box<WorkerSessionOptionsV1>>,
        reply: oneshot::Sender<ActorResult<AttachSessionOutcome>>,
    },
    DetachSession {
        shard_fence: ShardFence,
        session_id: SessionId,
        session_fence: OwnershipFence,
        reply: oneshot::Sender<ActorResult<DetachSessionOutcome>>,
    },
    BeginDraining {
        fence: ShardFence,
        reply: oneshot::Sender<ActorResult<()>>,
    },
    StopIfEmpty {
        fence: ShardFence,
        reply: oneshot::Sender<ActorResult<()>>,
    },
    Snapshot {
        fence: ShardFence,
        reply: oneshot::Sender<ActorResult<BrowserShardSnapshot>>,
    },
}

impl Command {
    fn reject(self, error: ShardActorError) {
        match self {
            Self::Activate { reply, .. }
            | Self::BeginDraining { reply, .. }
            | Self::StopIfEmpty { reply, .. } => {
                let _ = reply.send(Err(error));
            }
            Self::AttachSession { reply, .. } => {
                let _ = reply.send(Err(error));
            }
            Self::DetachSession { reply, .. } => {
                let _ = reply.send(Err(error));
            }
            Self::Snapshot { reply, .. } => {
                let _ = reply.send(Err(error));
            }
        }
    }
}

#[derive(Clone)]
pub struct BrowserShardActor {
    sender: mpsc::Sender<Command>,
    fence: ShardFence,
    ownership_lost: CancellationToken,
    ownership_gate: Arc<Mutex<OwnershipGate>>,
    termination: watch::Receiver<Option<Result<(), ShardRuntimeError>>>,
    handle_lifetime: Arc<ActorHandleLifetime>,
}

#[derive(Default)]
struct OwnershipGate {
    lost: bool,
}

struct ActorHandleLifetime {
    shutdown: CancellationToken,
}

impl Drop for ActorHandleLifetime {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

impl BrowserShardActor {
    #[must_use]
    pub fn spawn<R: BrowserShardRuntime>(
        config: BrowserShardActorConfig,
        runtime: Arc<R>,
    ) -> (Self, JoinHandle<Result<(), ShardRuntimeError>>) {
        let (sender, receiver) = mpsc::channel(config.mailbox_capacity);
        let ownership_lost = CancellationToken::new();
        let ownership_gate = Arc::new(Mutex::new(OwnershipGate::default()));
        let shutdown = CancellationToken::new();
        let (termination_sender, termination) = watch::channel(None);
        let actor = Self {
            sender,
            fence: config.fence.clone(),
            ownership_lost: ownership_lost.clone(),
            ownership_gate: ownership_gate.clone(),
            termination,
            handle_lifetime: Arc::new(ActorHandleLifetime {
                shutdown: shutdown.clone(),
            }),
        };
        let task = tokio::spawn(
            ShardActorTask::new(
                config,
                runtime,
                receiver,
                ownership_lost,
                ownership_gate,
                shutdown,
                termination_sender,
            )
            .run(),
        );
        (actor, task)
    }

    pub async fn activate(&self, fence: &ShardFence) -> ActorResult<()> {
        let (reply, response) = oneshot::channel();
        self.send(Command::Activate {
            fence: fence.clone(),
            reply,
        })
        .await?;
        self.receive(response).await
    }

    pub async fn attach_session(
        &self,
        shard_fence: &ShardFence,
        session_id: SessionId,
        session_fence: OwnershipFence,
    ) -> ActorResult<AttachSessionOutcome> {
        let (reply, response) = oneshot::channel();
        self.send(Command::AttachSession {
            shard_fence: shard_fence.clone(),
            tenant_id: None,
            session_id,
            session_fence,
            options: None,
            reply,
        })
        .await?;
        self.receive(response).await
    }

    pub async fn attach_session_owned(
        &self,
        shard_fence: &ShardFence,
        tenant_id: TenantId,
        session_id: SessionId,
        session_fence: OwnershipFence,
    ) -> ActorResult<AttachSessionOutcome> {
        let (reply, response) = oneshot::channel();
        self.send(Command::AttachSession {
            shard_fence: shard_fence.clone(),
            tenant_id: Some(tenant_id),
            session_id,
            session_fence,
            options: None,
            reply,
        })
        .await?;
        self.receive(response).await
    }

    pub async fn attach_session_owned_with_options(
        &self,
        shard_fence: &ShardFence,
        tenant_id: TenantId,
        session_id: SessionId,
        session_fence: OwnershipFence,
        options: WorkerSessionOptionsV1,
    ) -> ActorResult<AttachSessionOutcome> {
        let (reply, response) = oneshot::channel();
        self.send(Command::AttachSession {
            shard_fence: shard_fence.clone(),
            tenant_id: Some(tenant_id),
            session_id,
            session_fence,
            options: Some(Box::new(options)),
            reply,
        })
        .await?;
        self.receive(response).await
    }

    pub async fn detach_session(
        &self,
        shard_fence: &ShardFence,
        session_id: SessionId,
        session_fence: OwnershipFence,
    ) -> ActorResult<DetachSessionOutcome> {
        let (reply, response) = oneshot::channel();
        self.send(Command::DetachSession {
            shard_fence: shard_fence.clone(),
            session_id,
            session_fence,
            reply,
        })
        .await?;
        self.receive(response).await
    }

    pub async fn begin_draining(&self, fence: &ShardFence) -> ActorResult<()> {
        let (reply, response) = oneshot::channel();
        self.send(Command::BeginDraining {
            fence: fence.clone(),
            reply,
        })
        .await?;
        self.receive(response).await
    }

    pub async fn stop_if_empty(&self, fence: &ShardFence) -> ActorResult<()> {
        let (reply, response) = oneshot::channel();
        self.send(Command::StopIfEmpty {
            fence: fence.clone(),
            reply,
        })
        .await?;
        self.receive(response).await
    }

    pub async fn snapshot(&self, fence: &ShardFence) -> ActorResult<BrowserShardSnapshot> {
        let (reply, response) = oneshot::channel();
        self.send(Command::Snapshot {
            fence: fence.clone(),
            reply,
        })
        .await?;
        self.receive(response).await
    }

    pub async fn try_snapshot(&self, fence: &ShardFence) -> ActorResult<BrowserShardSnapshot> {
        if self.ownership_lost.is_cancelled() {
            return Err(ShardActorError::OwnershipLost);
        }
        let (reply, response) = oneshot::channel();
        self.sender
            .try_send(Command::Snapshot {
                fence: fence.clone(),
                reply,
            })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => ShardActorError::MailboxFull,
                mpsc::error::TrySendError::Closed(_) => ShardActorError::ActorStopped,
            })?;
        self.receive(response).await
    }

    #[must_use]
    pub fn remaining_mailbox_capacity(&self) -> usize {
        self.sender.capacity()
    }

    pub async fn lose_ownership(&self, fence: &ShardFence) -> ActorResult<()> {
        if fence != &self.fence {
            return Err(ShardActorError::StaleShardFence);
        }
        let first_loss = {
            let mut ownership = lock_ownership_gate(&self.ownership_gate);
            let first_loss = !ownership.lost;
            ownership.lost = true;
            first_loss
        };
        let mut termination = self.termination.clone();
        let previous_result = *termination.borrow();
        self.ownership_lost.cancel();
        if first_loss && previous_result.is_some() && previous_result != Some(Ok(())) {
            termination
                .changed()
                .await
                .map_err(|_| ShardActorError::ActorStopped)?;
        }
        loop {
            if let Some(result) = *termination.borrow() {
                return result.map_err(ShardActorError::Runtime);
            }
            if termination.changed().await.is_err() {
                return Err(ShardActorError::ActorStopped);
            }
        }
    }

    /// Stops the actor even when cloned handles remain alive and waits for the runtime's terminal
    /// result. The task handle returned by [`Self::spawn`] can then be joined by its owner.
    pub async fn shutdown(&self, fence: &ShardFence) -> ActorResult<()> {
        if fence != &self.fence {
            return Err(ShardActorError::StaleShardFence);
        }
        self.handle_lifetime.shutdown.cancel();
        let mut termination = self.termination.clone();
        loop {
            if let Some(result) = *termination.borrow() {
                return result.map_err(ShardActorError::Runtime);
            }
            if termination.changed().await.is_err() {
                return Err(ShardActorError::ActorStopped);
            }
        }
    }

    async fn send(&self, command: Command) -> ActorResult<()> {
        if self.ownership_lost.is_cancelled() {
            return Err(ShardActorError::OwnershipLost);
        }
        self.sender.send(command).await.map_err(|_| {
            if self.ownership_lost.is_cancelled() {
                ShardActorError::OwnershipLost
            } else {
                ShardActorError::ActorStopped
            }
        })
    }

    async fn receive<T>(&self, response: oneshot::Receiver<ActorResult<T>>) -> ActorResult<T> {
        response.await.map_err(|_| {
            if self.ownership_lost.is_cancelled() {
                ShardActorError::OwnershipLost
            } else {
                ShardActorError::ActorStopped
            }
        })?
    }
}

fn lock_ownership_gate(gate: &Mutex<OwnershipGate>) -> MutexGuard<'_, OwnershipGate> {
    match gate.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

struct ShardActorTask<R> {
    config: BrowserShardActorConfig,
    runtime: Arc<R>,
    receiver: mpsc::Receiver<Command>,
    ownership_cancel: CancellationToken,
    ownership_gate: Arc<Mutex<OwnershipGate>>,
    shutdown_cancel: CancellationToken,
    termination_sender: watch::Sender<Option<Result<(), ShardRuntimeError>>>,
    state: ShardState,
    live_sessions: HashMap<
        SessionId,
        (
            Option<TenantId>,
            OwnershipFence,
            Option<WorkerSessionOptionsV1>,
        ),
    >,
    detached_sessions: HashMap<SessionId, OwnershipFence>,
    total_contexts_created: u64,
    ownership_lost: bool,
    shutdown_requested: bool,
    termination_result: Option<Result<(), ShardRuntimeError>>,
}

impl<R: BrowserShardRuntime> ShardActorTask<R> {
    fn new(
        config: BrowserShardActorConfig,
        runtime: Arc<R>,
        receiver: mpsc::Receiver<Command>,
        ownership_cancel: CancellationToken,
        ownership_gate: Arc<Mutex<OwnershipGate>>,
        shutdown_cancel: CancellationToken,
        termination_sender: watch::Sender<Option<Result<(), ShardRuntimeError>>>,
    ) -> Self {
        Self {
            config,
            runtime,
            receiver,
            ownership_cancel,
            ownership_gate,
            shutdown_cancel,
            termination_sender,
            state: ShardState::starting(),
            live_sessions: HashMap::new(),
            detached_sessions: HashMap::new(),
            total_contexts_created: 0,
            ownership_lost: false,
            shutdown_requested: false,
            termination_result: None,
        }
    }

    async fn run(mut self) -> Result<(), ShardRuntimeError> {
        loop {
            tokio::select! {
                biased;
                () = self.ownership_cancel.cancelled(), if !self.ownership_lost => {
                    return self.terminate_for_ownership_loss().await;
                }
                () = self.shutdown_cancel.cancelled(), if !self.shutdown_requested => {
                    return self.terminate_after_channel_close().await;
                }
                command = self.receiver.recv() => {
                    let Some(command) = command else {
                        return self.terminate_after_channel_close().await;
                    };
                    if self.ownership_lost {
                        command.reject(ShardActorError::OwnershipLost);
                    } else {
                        self.process(command).await;
                        if self.ownership_lost || self.shutdown_requested {
                            return self
                                .termination_result
                                .unwrap_or(Err(ShardRuntimeError::OutcomeUncertain));
                        }
                    }
                }
            }
        }
    }

    async fn process(&mut self, command: Command) {
        match command {
            Command::Activate { fence, reply } => {
                let result = self.activate(&fence).await;
                let _ = reply.send(result);
            }
            Command::AttachSession {
                shard_fence,
                tenant_id,
                session_id,
                session_fence,
                options,
                reply,
            } => {
                let result = self
                    .attach_session(
                        &shard_fence,
                        tenant_id,
                        session_id,
                        session_fence,
                        options.map(|options| *options),
                    )
                    .await;
                let _ = reply.send(result);
            }
            Command::DetachSession {
                shard_fence,
                session_id,
                session_fence,
                reply,
            } => {
                let result = self
                    .detach_session(&shard_fence, session_id, session_fence)
                    .await;
                let _ = reply.send(result);
            }
            Command::BeginDraining { fence, reply } => {
                let result = self.begin_draining(&fence);
                let _ = reply.send(result);
            }
            Command::StopIfEmpty { fence, reply } => {
                let result = self.stop_if_empty(&fence).await;
                let _ = reply.send(result);
            }
            Command::Snapshot { fence, reply } => {
                let result = self.snapshot(&fence);
                let _ = reply.send(result);
            }
        }
    }

    async fn activate(&mut self, fence: &ShardFence) -> ActorResult<()> {
        self.validate_shard_fence(fence)?;
        match self.state.lifecycle() {
            ShardLifecycle::Starting => {}
            ShardLifecycle::Active => return Ok(()),
            _ => return Err(ShardActorError::InvalidLifecycle),
        }
        let runtime = self.runtime.clone();
        let operation_cancel = self.ownership_cancel.child_token();
        self.await_runtime(runtime.readiness_check(fence, operation_cancel))
            .await?;
        self.commit_if_owned(|actor| actor.transition(ShardEvent::ReadinessSucceeded))
            .await
    }

    async fn attach_session(
        &mut self,
        shard_fence: &ShardFence,
        tenant_id: Option<TenantId>,
        session_id: SessionId,
        session_fence: OwnershipFence,
        options: Option<WorkerSessionOptionsV1>,
    ) -> ActorResult<AttachSessionOutcome> {
        self.validate_shard_fence(shard_fence)?;
        self.validate_session_fence(&session_fence)?;
        if let Some((existing_tenant, existing_fence, existing_options)) =
            self.live_sessions.get(&session_id)
        {
            return if existing_tenant == &tenant_id
                && existing_fence == &session_fence
                && existing_options == &options
            {
                Ok(AttachSessionOutcome::AlreadyAttached)
            } else {
                Err(ShardActorError::StaleSessionFence)
            };
        }
        if self.detached_sessions.contains_key(&session_id) {
            return Err(ShardActorError::StaleSessionFence);
        }
        if self.state.lifecycle() != ShardLifecycle::Active
            || self.state.admission() != ShardAdmission::Open
        {
            return Err(ShardActorError::AdmissionClosed);
        }
        if self.live_sessions.len() >= self.config.max_live_sessions
            || self.total_contexts_created >= self.config.max_contexts_created_lifetime
        {
            return Err(ShardActorError::CapacityExceeded);
        }

        let runtime = self.runtime.clone();
        let operation_cancel = self.ownership_cancel.child_token();
        let result = match (tenant_id.as_ref(), options.as_ref()) {
            (Some(tenant_id), Some(options)) => {
                self.await_runtime(runtime.create_context_owned_with_options(
                    tenant_id,
                    &session_id,
                    &session_fence,
                    options,
                    operation_cancel,
                ))
                .await
            }
            (Some(tenant_id), None) => {
                self.await_runtime(runtime.create_context_owned(
                    tenant_id,
                    &session_id,
                    &session_fence,
                    operation_cancel,
                ))
                .await
            }
            (None, None) => {
                self.await_runtime(runtime.create_context(
                    &session_id,
                    &session_fence,
                    operation_cancel,
                ))
                .await
            }
            (None, Some(_)) => Err(ShardActorError::StaleSessionFence),
        };
        if let Err(error) = result {
            if error == ShardActorError::Runtime(ShardRuntimeError::OutcomeUncertain) {
                let _ = self.transition(ShardEvent::TaintDetected);
            }
            return Err(error);
        }
        self.commit_if_owned(move |actor| {
            actor
                .live_sessions
                .insert(session_id, (tenant_id, session_fence, options));
            actor.total_contexts_created += 1;
            if actor.total_contexts_created == actor.config.max_contexts_created_lifetime {
                actor.transition(ShardEvent::BeginDraining)?;
            }
            Ok(AttachSessionOutcome::Attached)
        })
        .await
    }

    async fn detach_session(
        &mut self,
        shard_fence: &ShardFence,
        session_id: SessionId,
        session_fence: OwnershipFence,
    ) -> ActorResult<DetachSessionOutcome> {
        self.validate_shard_fence(shard_fence)?;
        self.validate_session_fence(&session_fence)?;
        if let Some(detached) = self.detached_sessions.get(&session_id) {
            return if detached == &session_fence {
                Ok(DetachSessionOutcome::AlreadyDetached)
            } else {
                Err(ShardActorError::StaleSessionFence)
            };
        }
        let Some((_, current, _)) = self.live_sessions.get(&session_id) else {
            return Err(ShardActorError::SessionNotFound);
        };
        if current != &session_fence {
            return Err(ShardActorError::StaleSessionFence);
        }

        let runtime = self.runtime.clone();
        let operation_cancel = self.ownership_cancel.child_token();
        let result = self
            .await_runtime(runtime.dispose_context(&session_id, &session_fence, operation_cancel))
            .await;
        if let Err(error) = result {
            if error != ShardActorError::OwnershipLost {
                let _ = self.transition(ShardEvent::TaintDetected);
            }
            return Err(error);
        }
        self.commit_if_owned(move |actor| {
            actor.live_sessions.remove(&session_id);
            actor.detached_sessions.insert(session_id, session_fence);
            Ok(DetachSessionOutcome::Detached)
        })
        .await
    }

    fn begin_draining(&mut self, fence: &ShardFence) -> ActorResult<()> {
        self.validate_shard_fence(fence)?;
        match self.state.lifecycle() {
            ShardLifecycle::Active => self.transition(ShardEvent::BeginDraining),
            ShardLifecycle::Draining => Ok(()),
            _ => Err(ShardActorError::InvalidLifecycle),
        }
    }

    async fn stop_if_empty(&mut self, fence: &ShardFence) -> ActorResult<()> {
        self.validate_shard_fence(fence)?;
        match self.state.lifecycle() {
            ShardLifecycle::Dead => return Ok(()),
            ShardLifecycle::Draining if self.live_sessions.is_empty() => {
                self.transition(ShardEvent::StopWhenEmpty { live_sessions: 0 })?;
            }
            ShardLifecycle::Stopping => {}
            _ => return Err(ShardActorError::InvalidLifecycle),
        }
        self.terminate_runtime()
            .await
            .map_err(ShardActorError::Runtime)?;
        self.transition(ShardEvent::Stopped)?;
        Ok(())
    }

    fn snapshot(&self, fence: &ShardFence) -> ActorResult<BrowserShardSnapshot> {
        self.validate_shard_fence(fence)?;
        Ok(BrowserShardSnapshot {
            fence: self.config.fence.clone(),
            lifecycle: self.state.lifecycle(),
            health: self.state.health(),
            admission: self.state.admission(),
            live_sessions: self.live_sessions.len(),
            total_contexts_created: self.total_contexts_created,
        })
    }

    async fn await_runtime<T, F>(&mut self, future: F) -> ActorResult<T>
    where
        F: Future<Output = Result<T, ShardRuntimeError>>,
    {
        tokio::select! {
            biased;
            () = self.ownership_cancel.cancelled() => {
                let _ = self.terminate_for_ownership_loss().await;
                Err(ShardActorError::OwnershipLost)
            }
            () = self.shutdown_cancel.cancelled() => {
                let _ = self.terminate_after_channel_close().await;
                Err(ShardActorError::ActorStopped)
            }
            result = future => {
                let ownership_was_lost = lock_ownership_gate(&self.ownership_gate).lost;
                if ownership_was_lost {
                    let _ = self.terminate_for_ownership_loss().await;
                    Err(ShardActorError::OwnershipLost)
                } else if self.shutdown_cancel.is_cancelled() {
                    let _ = self.terminate_after_channel_close().await;
                    Err(ShardActorError::ActorStopped)
                } else {
                    result.map_err(ShardActorError::Runtime)
                }
            },
        }
    }

    async fn commit_if_owned<T>(
        &mut self,
        commit: impl FnOnce(&mut Self) -> ActorResult<T>,
    ) -> ActorResult<T> {
        let ownership_gate = self.ownership_gate.clone();
        {
            let ownership = lock_ownership_gate(&ownership_gate);
            if !ownership.lost {
                return commit(self);
            }
        }
        let _ = self.terminate_for_ownership_loss().await;
        Err(ShardActorError::OwnershipLost)
    }

    async fn terminate_for_ownership_loss(&mut self) -> Result<(), ShardRuntimeError> {
        self.ownership_lost = true;
        if self.state.lifecycle() != ShardLifecycle::Dead {
            self.terminate_runtime().await?;
            let _ = self.transition(ShardEvent::ImmediateTermination);
            self.live_sessions.clear();
        }
        Ok(())
    }

    async fn terminate_after_channel_close(&mut self) -> Result<(), ShardRuntimeError> {
        self.shutdown_requested = true;
        if self.state.lifecycle() != ShardLifecycle::Dead {
            self.terminate_runtime().await?;
            let _ = self.transition(ShardEvent::ImmediateTermination);
            self.live_sessions.clear();
        }
        Ok(())
    }

    async fn terminate_runtime(&mut self) -> Result<(), ShardRuntimeError> {
        if self.termination_result == Some(Ok(())) {
            return Ok(());
        }
        let result = self.runtime.terminate(&self.config.fence).await;
        self.termination_result = Some(result);
        self.termination_sender.send_replace(Some(result));
        result
    }

    fn validate_shard_fence(&self, received: &ShardFence) -> ActorResult<()> {
        if received == &self.config.fence {
            Ok(())
        } else {
            Err(ShardActorError::StaleShardFence)
        }
    }

    fn validate_session_fence(&self, received: &OwnershipFence) -> ActorResult<()> {
        let expected_owner = self.config.fence.owner();
        if received.worker_id() == expected_owner.worker_id()
            && received.worker_epoch() == expected_owner.worker_epoch().get()
            && received.placement_version() != 0
            && received.session_incarnation() != 0
        {
            Ok(())
        } else {
            Err(ShardActorError::StaleSessionFence)
        }
    }

    fn transition(&mut self, event: ShardEvent) -> ActorResult<()> {
        self.state = self
            .state
            .clone()
            .transition(event)
            .map_err(|_| ShardActorError::InvalidLifecycle)?;
        Ok(())
    }
}
