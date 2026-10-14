use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use browserd_core::{SessionId, ShardFence, TenantId};
use browserd_session::OwnershipFence;
use browserd_targets::{
    BootstrapBackend, BootstrapDisposition, BootstrapStageFailure, PausedTarget,
    TargetBootstrapBarrier,
};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
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
    drain_started: AtomicBool,
    ready_targets: Mutex<BTreeSet<String>>,
    closing_targets: Mutex<BTreeSet<String>>,
    target_changed: Condvar,
}

enum EventPumpLifecycle {
    NotStarted,
    Running(JoinHandle<()>),
    Joined(Result<(), ShardRuntimeError>),
}

struct EventPumpControl {
    cancellation: CancellationToken,
    lifecycle: tokio::sync::Mutex<EventPumpLifecycle>,
}

#[derive(Clone)]
pub(crate) struct TargetReadiness {
    state: Arc<ManagerState>,
}

impl TargetReadiness {
    pub(crate) fn wait_until_targets_absent(
        &self,
        targets: &[String],
        timeout: Duration,
    ) -> Result<(), ShardRuntimeError> {
        if targets.len() > MAX_BOOTSTRAP_TARGETS {
            return Err(ShardRuntimeError::Rejected);
        }
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(ShardRuntimeError::Rejected)?;
        let mut ready = self
            .state
            .ready_targets
            .lock()
            .map_err(|_| ShardRuntimeError::Unavailable)?;
        loop {
            if self.state.tainted.load(Ordering::Acquire) {
                return Err(ShardRuntimeError::OutcomeUncertain);
            }
            if targets.iter().all(|target| !ready.contains(target)) {
                return Ok(());
            }
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or(ShardRuntimeError::OutcomeUncertain)?;
            let (guard, result) = self
                .state
                .target_changed
                .wait_timeout(ready, remaining)
                .map_err(|_| ShardRuntimeError::Unavailable)?;
            ready = guard;
            if result.timed_out() && targets.iter().any(|target| ready.contains(target)) {
                return Err(ShardRuntimeError::OutcomeUncertain);
            }
        }
    }
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

    pub(crate) fn wait_until_empty(&self, timeout: Duration) -> Result<(), ShardRuntimeError> {
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
            if ready_targets.is_empty() {
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
            if result.timed_out() && !ready_targets.is_empty() {
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
    pump: EventPumpControl,
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

    async fn create_context_owned_with_options(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        fence: &OwnershipFence,
        options: &crate::WorkerSessionOptionsV1,
        cancellation: CancellationToken,
    ) -> Result<(), ShardRuntimeError> {
        if !self.targets.is_ready() {
            return Err(ShardRuntimeError::Rejected);
        }
        self.inner
            .create_context_owned_with_options(tenant_id, session_id, fence, options, cancellation)
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
        let target_result = self.targets.shutdown().await;
        let runtime_result = self.inner.terminate(fence).await;
        target_result.and(runtime_result)
    }

    async fn force_terminate(
        &self,
        fence: &ShardFence,
        proof: &crate::SandboxTerminationProof,
    ) -> Result<(), ShardRuntimeError> {
        if !proof.matches_fence(fence) {
            return Err(ShardRuntimeError::Rejected);
        }
        let target_result = self.targets.shutdown().await;
        let runtime_result = self.inner.force_terminate(fence, proof).await;
        target_result.and(runtime_result)
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
                drain_started: AtomicBool::new(false),
                ready_targets: Mutex::new(BTreeSet::new()),
                closing_targets: Mutex::new(BTreeSet::new()),
                target_changed: Condvar::new(),
            }),
            pump: EventPumpControl {
                cancellation: CancellationToken::new(),
                lifecycle: tokio::sync::Mutex::new(EventPumpLifecycle::NotStarted),
            },
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
        let mut pump = self.pump.lifecycle.lock().await;
        if self.pump.cancellation.is_cancelled() || !matches!(*pump, EventPumpLifecycle::NotStarted)
        {
            drop(receiver);
            return Err(ShardRuntimeError::Cancelled);
        }
        *pump = EventPumpLifecycle::Running(self.spawn_event_pump(receiver));
        self.state.ready.store(true, Ordering::Release);
        drop(pump);
        Ok(())
    }

    async fn bootstrap_target(&self, target: PausedTarget) -> Result<(), BootstrapStageFailure> {
        let target_id = target.target_id().to_owned();
        let backend = self.backend.clone();
        let disposition = tokio::task::spawn_blocking(move || {
            let mut backend = backend
                .lock()
                .map_err(|_| BootstrapStageFailure::StateOverflow)?;
            TargetBootstrapBarrier::new()
                .bootstrap_with_disposition(&target, &mut *backend)
                .map_err(|error| match error {
                    browserd_targets::BootstrapError::StageFailed { cause, .. } => cause,
                })
        })
        .await
        .map_err(|_| BootstrapStageFailure::StateOverflow)??;
        if disposition != BootstrapDisposition::Completed {
            let mut closing = self
                .state
                .closing_targets
                .lock()
                .map_err(|_| BootstrapStageFailure::StateOverflow)?;
            if closing.len() >= MAX_BOOTSTRAP_TARGETS || !closing.insert(target_id) {
                return Err(BootstrapStageFailure::StateOverflow);
            }
            self.state.target_changed.notify_all();
            return Ok(());
        }
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

    fn spawn_event_pump(&self, mut receiver: mpsc::Receiver<TargetManagerEvent>) -> JoinHandle<()> {
        let backend = self.backend.clone();
        let state = self.state.clone();
        let drain = self.drain.clone();
        let cancellation = self.pump.cancellation.clone();
        tokio::spawn(async move {
            'events: loop {
                let event = tokio::select! {
                    biased;
                    () = cancellation.cancelled() => break,
                    event = receiver.recv() => {
                        let Some(event) = event else {
                            taint_and_drain(&state, &*drain);
                            return;
                        };
                        event
                    }
                };
                match event {
                    TargetManagerEvent::Attached(target) => {
                        let target_id = target.target_id().to_owned();
                        let target_backend = backend.clone();
                        let mut callback = tokio::task::spawn_blocking(move || {
                            target_backend
                                .lock()
                                .map_err(|_| ())
                                .and_then(|mut backend| {
                                    TargetBootstrapBarrier::new()
                                        .bootstrap_with_disposition(&target, &mut *backend)
                                        .map_err(|_| ())
                                })
                        });
                        let result = tokio::select! {
                            biased;
                            () = cancellation.cancelled() => {
                                let _ = callback.await;
                                break 'events;
                            }
                            result = &mut callback => {
                                result.map_err(|_| ()).and_then(|result| result)
                            }
                        };
                        if matches!(
                            result,
                            Ok(BootstrapDisposition::OwnedClosing
                                | BootstrapDisposition::OwnedRetired)
                        ) {
                            let inserted = state
                                .closing_targets
                                .lock()
                                .map(|mut closing| {
                                    closing.len() < MAX_BOOTSTRAP_TARGETS
                                        && closing.insert(target_id)
                                })
                                .unwrap_or(false);
                            if inserted {
                                state.target_changed.notify_all();
                                continue;
                            }
                        } else if result == Ok(BootstrapDisposition::Completed) {
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
                        let closing_removed = state
                            .closing_targets
                            .lock()
                            .map(|mut closing| closing.remove(&target_id))
                            .unwrap_or(false);
                        if removed || closing_removed {
                            state.target_changed.notify_all();
                            continue;
                        }
                    }
                    TargetManagerEvent::Overflow | TargetManagerEvent::TransportLost => {}
                }
                taint_and_drain(&state, &*drain);
                return;
            }
            state.ready.store(false, Ordering::Release);
            state.target_changed.notify_all();
        })
    }

    pub async fn shutdown(&self) -> Result<(), ShardRuntimeError> {
        let mut pump = self.pump.lifecycle.lock().await;
        if let EventPumpLifecycle::Joined(result) = &*pump {
            return *result;
        }
        self.pump.cancellation.cancel();
        self.taint_and_drain();
        let receiver_result = self
            .receiver
            .lock()
            .map(|mut receiver| {
                receiver.take();
            })
            .map_err(|_| ShardRuntimeError::Unavailable);
        let join_result = match std::mem::replace(
            &mut *pump,
            EventPumpLifecycle::Joined(Err(ShardRuntimeError::Unavailable)),
        ) {
            EventPumpLifecycle::NotStarted => Ok(()),
            EventPumpLifecycle::Running(handle) => handle
                .await
                .map_err(|_| ShardRuntimeError::OutcomeUncertain),
            EventPumpLifecycle::Joined(result) => result,
        };
        let result = receiver_result.and(join_result);
        *pump = EventPumpLifecycle::Joined(result);
        result
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
    if !state.drain_started.swap(true, Ordering::AcqRel) {
        drain.begin_drain();
    }
}

#[cfg(test)]
mod context_retirement_tests {
    #![allow(clippy::expect_used)]
    use super::*;
    use browserd_core::{LaunchGeneration, OwnerFence, ShardId, WorkerEpoch, WorkerId};
    use browserd_targets::{BootstrapStage, ShardTaintReason, TargetKind};
    use std::sync::atomic::AtomicUsize;

    struct Drain(AtomicUsize);
    impl TargetManagerDrain for Drain {
        fn begin_drain(&self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    struct Backend {
        stages: Arc<Mutex<Vec<(String, BootstrapStage)>>>,
        gate: Arc<(Mutex<bool>, Condvar)>,
    }
    impl BootstrapBackend for Backend {
        fn run_stage(
            &mut self,
            target: &PausedTarget,
            stage: BootstrapStage,
        ) -> Result<(), BootstrapStageFailure> {
            self.stages
                .lock()
                .expect("stages")
                .push((target.target_id().to_owned(), stage));
            Ok(())
        }
        fn run_stage_with_disposition(
            &mut self,
            target: &PausedTarget,
            stage: BootstrapStage,
        ) -> Result<BootstrapDisposition, BootstrapStageFailure> {
            self.run_stage(target, stage)?;
            if target.target_id() == "unowned" {
                return Err(BootstrapStageFailure::UnknownOwnership);
            }
            if target.target_id() == "closing-worker" && stage == BootstrapStage::ApplyEmulation {
                let (lock, changed) = &*self.gate;
                let open = lock.lock().expect("gate");
                let (open, result) = changed
                    .wait_timeout_while(open, Duration::from_secs(2), |open| !*open)
                    .expect("gate wait");
                if result.timed_out() || !*open {
                    return Err(BootstrapStageFailure::StateOverflow);
                }
                return Ok(BootstrapDisposition::OwnedClosing);
            }
            Ok(BootstrapDisposition::Completed)
        }
        fn close_paused_target(&mut self, _target: &PausedTarget) {}
        fn taint_shard(&mut self, _reason: ShardTaintReason) {}
    }
    impl TargetManagerBackend for Backend {
        fn enable_auto_attach_and_snapshot(
            &mut self,
        ) -> Result<TargetBootstrapSnapshot, ShardRuntimeError> {
            TargetBootstrapSnapshot::new(
                vec![PausedTarget::new("sibling", TargetKind::Page)],
                vec![],
            )
        }
    }

    #[tokio::test]
    async fn closing_paused_worker_never_becomes_ready_and_sibling_remains_live() {
        let drain = Arc::new(Drain(AtomicUsize::new(0)));
        let stages = Arc::new(Mutex::new(Vec::new()));
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let fence = ShardFence::new(
            OwnerFence::new(
                WorkerId::new("retirement-test").expect("worker"),
                WorkerEpoch::new(1).expect("epoch"),
            ),
            ShardId::new(),
            LaunchGeneration::new(1).expect("launch"),
        );
        let (manager, ingress) = ProductionTargetManager::new_bounded(
            fence,
            Backend {
                stages: stages.clone(),
                gate: gate.clone(),
            },
            8,
            drain.clone(),
        )
        .expect("manager");
        manager.bootstrap().await.expect("sibling bootstrap");
        ingress
            .try_send(TargetManagerEvent::Attached(PausedTarget::new(
                "closing-worker",
                TargetKind::SharedWorker,
            )))
            .expect("paused attach");
        tokio::time::timeout(Duration::from_secs(2), async {
            while !stages
                .lock()
                .expect("stages")
                .iter()
                .any(|(target, stage)| {
                    target == "closing-worker" && *stage == BootstrapStage::ApplyEmulation
                })
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("worker paused at deterministic stage");
        ingress
            .try_send(TargetManagerEvent::Detached {
                target_id: "closing-worker".to_owned(),
            })
            .expect("exact retirement");
        let (open, changed) = &*gate;
        *open.lock().expect("gate") = true;
        changed.notify_all();
        tokio::time::timeout(Duration::from_secs(2), async {
            while manager
                .state
                .closing_targets
                .lock()
                .expect("closing")
                .contains("closing-worker")
                || stages
                    .lock()
                    .expect("stages")
                    .iter()
                    .filter(|(target, _)| target == "closing-worker")
                    .count()
                    < 8
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("retirement processed");
        assert!(manager.has_ready_target("sibling"));
        assert!(!manager.has_ready_target("closing-worker"));
        assert!(
            !stages
                .lock()
                .expect("stages")
                .contains(&("closing-worker".to_owned(), BootstrapStage::Resume))
        );
        assert!(!manager.is_tainted());
        assert_eq!(drain.0.load(Ordering::SeqCst), 0);
        manager
            .readiness()
            .wait_until_targets_absent(&["closing-worker".to_owned()], Duration::from_millis(20))
            .expect("sibling excluded from close barrier");
        ingress
            .try_send(TargetManagerEvent::Attached(PausedTarget::new(
                "unowned",
                TargetKind::Iframe,
            )))
            .expect("unowned attach");
        tokio::time::timeout(Duration::from_secs(2), async {
            while !manager.is_tainted() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("unowned still fails closed");
        assert_eq!(drain.0.load(Ordering::SeqCst), 1);
        assert!(
            stages
                .lock()
                .expect("stages")
                .contains(&("unowned".to_owned(), BootstrapStage::AttributeOwnership)),
            "closing retirement must not taint before the separate unowned target"
        );
        assert_eq!(
            manager.readiness().wait_until_targets_absent(
                &["closing-worker".to_owned()],
                Duration::from_millis(20)
            ),
            Err(ShardRuntimeError::OutcomeUncertain)
        );
        manager.shutdown().await.expect("shutdown");
    }
}
