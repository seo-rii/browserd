use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use browserd_core::{SessionId, ShardFence, TenantId};
use browserd_session::OwnershipFence;
use browserd_targets::{
    BootstrapBackend, BootstrapStageFailure, PausedTarget, TargetBootstrapBarrier,
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::{BrowserShardRuntime, ShardRuntimeError};

const MAX_BOOTSTRAP_TARGETS: usize = 4_096;
const MAX_TARGET_EVENT_CAPACITY: usize = 4_096;

#[derive(Clone, Debug)]
pub struct TargetBootstrapSnapshot {
    initial_targets: Vec<PausedTarget>,
    catch_up_targets: Vec<PausedTarget>,
}

impl TargetBootstrapSnapshot {
    pub fn new(
        initial_targets: Vec<PausedTarget>,
        catch_up_targets: Vec<PausedTarget>,
    ) -> Result<Self, ShardRuntimeError> {
        if initial_targets.len().saturating_add(catch_up_targets.len()) > MAX_BOOTSTRAP_TARGETS {
            return Err(ShardRuntimeError::Rejected);
        }
        Ok(Self {
            initial_targets,
            catch_up_targets,
        })
    }
}

pub trait TargetManagerBackend: BootstrapBackend + Send + 'static {
    /// Atomically enables recursive wait-for-debugger auto-attach and returns both the initial
    /// target snapshot and every attach observed through the snapshot watermark.
    fn enable_auto_attach_and_snapshot(
        &mut self,
    ) -> Result<TargetBootstrapSnapshot, ShardRuntimeError>;
}

pub trait TargetManagerDrain: Send + Sync + 'static {
    fn begin_drain(&self);
}

#[derive(Clone, Debug)]
pub enum TargetManagerEvent {
    Attached(PausedTarget),
    Detached { target_id: String },
    Overflow,
    TransportLost,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TargetManagerIngressError {
    Overflow,
    Closed,
}

pub struct TargetManagerIngress<D> {
    sender: mpsc::Sender<TargetManagerEvent>,
    drain: Arc<D>,
    state: Arc<ManagerState>,
}

impl<D: TargetManagerDrain> TargetManagerIngress<D> {
    pub fn try_send(&self, event: TargetManagerEvent) -> Result<(), TargetManagerIngressError> {
        match self.sender.try_send(event) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => {
                taint_and_drain(&self.state, &*self.drain);
                Err(TargetManagerIngressError::Overflow)
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                taint_and_drain(&self.state, &*self.drain);
                Err(TargetManagerIngressError::Closed)
            }
        }
    }

    pub(crate) fn fail_closed(&self, event: TargetManagerEvent) {
        taint_and_drain(&self.state, &*self.drain);
        let _ignored = self.sender.try_send(event);
    }
}

struct ManagerState {
    bootstrap_started: AtomicBool,
    ready: AtomicBool,
    tainted: AtomicBool,
    ready_targets: Mutex<BTreeSet<String>>,
    target_changed: Condvar,
}

#[derive(Clone)]
pub(crate) struct TargetReadiness {
    state: Arc<ManagerState>,
}

impl TargetReadiness {
    pub(crate) fn wait_until_ready(
        &self,
        target_id: &str,
        timeout: Duration,
    ) -> Result<(), ShardRuntimeError> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(ShardRuntimeError::Rejected)?;
        let mut ready_targets = self
            .state
            .ready_targets
            .lock()
            .map_err(|_| ShardRuntimeError::Unavailable)?;
        loop {
            if self.state.tainted.load(Ordering::Acquire) {
                return Err(ShardRuntimeError::OutcomeUncertain);
            }
            if ready_targets.contains(target_id) {
                return Ok(());
            }
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or(ShardRuntimeError::OutcomeUncertain)?;
            let (guard, result) = self
                .state
                .target_changed
                .wait_timeout(ready_targets, remaining)
                .map_err(|_| ShardRuntimeError::Unavailable)?;
            ready_targets = guard;
            if result.timed_out() && !ready_targets.contains(target_id) {
                return Err(ShardRuntimeError::OutcomeUncertain);
            }
        }
    }
}

pub struct ProductionTargetManager<B, D> {
    fence: ShardFence,
    backend: Arc<Mutex<B>>,
    receiver: Mutex<Option<mpsc::Receiver<TargetManagerEvent>>>,
    drain: Arc<D>,
    state: Arc<ManagerState>,
}

/// Browser shard runtime decorator that withholds readiness and all context admission until the
/// target snapshot/catch-up bootstrap barrier has completed.
pub struct TargetManagedShardRuntime<R, B, D> {
    inner: Arc<R>,
    targets: Arc<ProductionTargetManager<B, D>>,
}

impl<R, B, D> TargetManagedShardRuntime<R, B, D> {
    #[must_use]
    pub fn new(inner: Arc<R>, targets: Arc<ProductionTargetManager<B, D>>) -> Self {
        Self { inner, targets }
    }
}

#[async_trait::async_trait]
impl<R, B, D> BrowserShardRuntime for TargetManagedShardRuntime<R, B, D>
where
    R: BrowserShardRuntime,
    B: TargetManagerBackend,
    D: TargetManagerDrain,
{
    async fn readiness_check(
        &self,
        fence: &ShardFence,
        cancellation: CancellationToken,
    ) -> Result<(), ShardRuntimeError> {
        if fence != self.targets.fence() {
            return Err(ShardRuntimeError::Rejected);
        }
        self.inner
            .readiness_check(fence, cancellation.clone())
            .await?;
        if let Err(error) = self.targets.bootstrap().await {
            let _ = self.inner.terminate(fence).await;
            return Err(error);
        }
        Ok(())
    }

    async fn create_context(
        &self,
        session_id: &SessionId,
        fence: &OwnershipFence,
        cancellation: CancellationToken,
    ) -> Result<(), ShardRuntimeError> {
        if !self.targets.is_ready() {
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
        if !self.targets.is_ready() {
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
        self.inner
            .dispose_context(session_id, fence, cancellation)
            .await
    }

    async fn terminate(&self, fence: &ShardFence) -> Result<(), ShardRuntimeError> {
        self.inner.terminate(fence).await
    }
}

impl<B, D> ProductionTargetManager<B, D>
where
    B: TargetManagerBackend,
    D: TargetManagerDrain,
{
    pub fn new_bounded(
        fence: ShardFence,
        backend: B,
        event_capacity: usize,
        drain: Arc<D>,
    ) -> Result<(Self, TargetManagerIngress<D>), ShardRuntimeError> {
        if event_capacity == 0 || event_capacity > MAX_TARGET_EVENT_CAPACITY {
            return Err(ShardRuntimeError::Rejected);
        }
        let (sender, receiver) = mpsc::channel(event_capacity);
        let manager = Self::new(fence, backend, receiver, drain.clone())?;
        let ingress = TargetManagerIngress {
            sender,
            drain,
            state: manager.state.clone(),
        };
        Ok((manager, ingress))
    }

    pub fn new(
        fence: ShardFence,
        backend: B,
        receiver: mpsc::Receiver<TargetManagerEvent>,
        drain: Arc<D>,
    ) -> Result<Self, ShardRuntimeError> {
        if receiver.max_capacity() == 0 || receiver.max_capacity() > MAX_TARGET_EVENT_CAPACITY {
            return Err(ShardRuntimeError::Rejected);
        }
        Ok(Self {
            fence,
            backend: Arc::new(Mutex::new(backend)),
            receiver: Mutex::new(Some(receiver)),
            drain,
            state: Arc::new(ManagerState {
                bootstrap_started: AtomicBool::new(false),
                ready: AtomicBool::new(false),
                tainted: AtomicBool::new(false),
                ready_targets: Mutex::new(BTreeSet::new()),
                target_changed: Condvar::new(),
            }),
        })
    }

    pub async fn bootstrap(&self) -> Result<(), ShardRuntimeError> {
        if self
            .state
            .bootstrap_started
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
            || self.state.tainted.load(Ordering::Acquire)
        {
            return Err(ShardRuntimeError::Rejected);
        }
        let backend = self.backend.clone();
        let snapshot = tokio::task::spawn_blocking(move || {
            backend
                .lock()
                .map_err(|_| ShardRuntimeError::Unavailable)?
                .enable_auto_attach_and_snapshot()
        })
        .await
        .map_err(|_| ShardRuntimeError::Unavailable)??;
        for target in snapshot
            .initial_targets
            .iter()
            .chain(snapshot.catch_up_targets.iter())
        {
            if self.bootstrap_target(target.clone()).await.is_err() {
                self.taint_and_drain();
                return Err(ShardRuntimeError::OutcomeUncertain);
            }
        }
        if self.state.tainted.load(Ordering::Acquire) {
            return Err(ShardRuntimeError::OutcomeUncertain);
        }
        let receiver = self
            .receiver
            .lock()
            .map_err(|_| ShardRuntimeError::Unavailable)?
            .take()
            .ok_or(ShardRuntimeError::Rejected)?;
        self.spawn_event_pump(receiver);
        self.state.ready.store(true, Ordering::Release);
        Ok(())
    }

    async fn bootstrap_target(&self, target: PausedTarget) -> Result<(), BootstrapStageFailure> {
        let target_id = target.target_id().to_owned();
        let backend = self.backend.clone();
        tokio::task::spawn_blocking(move || {
            let mut backend = backend
                .lock()
                .map_err(|_| BootstrapStageFailure::StateOverflow)?;
            TargetBootstrapBarrier::new()
                .bootstrap(&target, &mut *backend)
                .map(|_| ())
                .map_err(|error| match error {
                    browserd_targets::BootstrapError::StageFailed { cause, .. } => cause,
                })
        })
        .await
        .map_err(|_| BootstrapStageFailure::StateOverflow)??;
        let mut ready_targets = self
            .state
            .ready_targets
            .lock()
            .map_err(|_| BootstrapStageFailure::StateOverflow)?;
        if !ready_targets.insert(target_id) {
            return Err(BootstrapStageFailure::StateOverflow);
        }
        self.state.target_changed.notify_all();
        Ok(())
    }

    fn spawn_event_pump(&self, mut receiver: mpsc::Receiver<TargetManagerEvent>) {
        let backend = self.backend.clone();
        let state = self.state.clone();
        let drain = self.drain.clone();
        tokio::spawn(async move {
            while let Some(event) = receiver.recv().await {
                match event {
                    TargetManagerEvent::Attached(target) => {
                        let target_id = target.target_id().to_owned();
                        let target_backend = backend.clone();
                        let result = tokio::task::spawn_blocking(move || {
                            target_backend
                                .lock()
                                .map_err(|_| ())
                                .and_then(|mut backend| {
                                    TargetBootstrapBarrier::new()
                                        .bootstrap(&target, &mut *backend)
                                        .map_err(|_| ())
                                })
                        })
                        .await
                        .map_err(|_| ())
                        .and_then(|result| result);
                        if result.is_ok() {
                            let inserted = state
                                .ready_targets
                                .lock()
                                .map(|mut ready_targets| ready_targets.insert(target_id))
                                .unwrap_or(false);
                            if inserted {
                                state.target_changed.notify_all();
                                continue;
                            }
                        }
                    }
                    TargetManagerEvent::Detached { target_id } => {
                        let removed = state
                            .ready_targets
                            .lock()
                            .map(|mut ready_targets| ready_targets.remove(&target_id))
                            .unwrap_or(false);
                        if removed {
                            state.target_changed.notify_all();
                            continue;
                        }
                    }
                    TargetManagerEvent::Overflow | TargetManagerEvent::TransportLost => {}
                }
                state.ready.store(false, Ordering::Release);
                state.tainted.store(true, Ordering::Release);
                state.target_changed.notify_all();
                drain.begin_drain();
                return;
            }
            state.ready.store(false, Ordering::Release);
            state.tainted.store(true, Ordering::Release);
            state.target_changed.notify_all();
            drain.begin_drain();
        });
    }

    fn taint_and_drain(&self) {
        taint_and_drain(&self.state, &*self.drain);
    }

    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.state.ready.load(Ordering::Acquire) && !self.is_tainted()
    }

    #[must_use]
    pub fn is_tainted(&self) -> bool {
        self.state.tainted.load(Ordering::Acquire)
    }

    #[must_use]
    pub fn ready_target_count(&self) -> usize {
        match self.state.ready_targets.lock() {
            Ok(ready_targets) => ready_targets.len(),
            Err(_) => {
                self.taint_and_drain();
                0
            }
        }
    }

    #[must_use]
    pub fn has_ready_target(&self, target_id: &str) -> bool {
        match self.state.ready_targets.lock() {
            Ok(ready_targets) => ready_targets.contains(target_id),
            Err(_) => {
                self.taint_and_drain();
                false
            }
        }
    }

    pub(crate) fn readiness(&self) -> TargetReadiness {
        TargetReadiness {
            state: self.state.clone(),
        }
    }

    #[must_use]
    pub const fn fence(&self) -> &ShardFence {
        &self.fence
    }
}

fn taint_and_drain<D: TargetManagerDrain>(state: &ManagerState, drain: &D) {
    state.ready.store(false, Ordering::Release);
    state.tainted.store(true, Ordering::Release);
    state.target_changed.notify_all();
    drain.begin_drain();
}
