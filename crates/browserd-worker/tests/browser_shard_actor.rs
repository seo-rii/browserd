use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use browserd_core::{
    LaunchGeneration, OwnerFence, SessionId, ShardAdmission, ShardFence, ShardHealth, ShardId,
    ShardLifecycle, WorkerEpoch, WorkerId,
};
use browserd_session::OwnershipFence;
use browserd_worker::{
    AttachSessionOutcome, BrowserShardActor, BrowserShardActorConfig, BrowserShardRuntime,
    DetachSessionOutcome, ShardActorError, ShardRuntimeError,
};
use tokio::sync::{Notify, Semaphore};
use tokio_util::sync::CancellationToken;

struct InFlight<'a>(&'a AtomicUsize);

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

struct FakeRuntime {
    create_calls: AtomicUsize,
    dispose_calls: AtomicUsize,
    terminate_calls: AtomicUsize,
    in_flight: AtomicUsize,
    max_in_flight: AtomicUsize,
    block_readiness: AtomicBool,
    readiness_started: Semaphore,
    readiness_release: Semaphore,
    block_create: AtomicBool,
    create_started: Semaphore,
    create_release: Semaphore,
    created: Mutex<Vec<SessionId>>,
    disposed: Mutex<Vec<SessionId>>,
    create_results: Mutex<VecDeque<Result<(), ShardRuntimeError>>>,
    dispose_results: Mutex<VecDeque<Result<(), ShardRuntimeError>>>,
    terminate_results: Mutex<VecDeque<Result<(), ShardRuntimeError>>>,
    terminated: Notify,
}

impl Default for FakeRuntime {
    fn default() -> Self {
        Self {
            create_calls: AtomicUsize::new(0),
            dispose_calls: AtomicUsize::new(0),
            terminate_calls: AtomicUsize::new(0),
            in_flight: AtomicUsize::new(0),
            max_in_flight: AtomicUsize::new(0),
            block_readiness: AtomicBool::new(false),
            readiness_started: Semaphore::new(0),
            readiness_release: Semaphore::new(0),
            block_create: AtomicBool::new(false),
            create_started: Semaphore::new(0),
            create_release: Semaphore::new(0),
            created: Mutex::new(Vec::new()),
            disposed: Mutex::new(Vec::new()),
            create_results: Mutex::new(VecDeque::new()),
            dispose_results: Mutex::new(VecDeque::new()),
            terminate_results: Mutex::new(VecDeque::new()),
            terminated: Notify::new(),
        }
    }
}

impl FakeRuntime {
    async fn enter(&self) -> InFlight<'_> {
        let current = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        self.max_in_flight.fetch_max(current, Ordering::SeqCst);
        tokio::task::yield_now().await;
        InFlight(&self.in_flight)
    }
}

#[async_trait]
impl BrowserShardRuntime for FakeRuntime {
    async fn readiness_check(
        &self,
        _fence: &ShardFence,
        cancellation: CancellationToken,
    ) -> Result<(), ShardRuntimeError> {
        let _in_flight = self.enter().await;
        if self.block_readiness.load(Ordering::SeqCst) {
            self.readiness_started.add_permits(1);
            tokio::select! {
                permit = self.readiness_release.acquire() => {
                    permit.map_err(|_| ShardRuntimeError::Unavailable)?.forget();
                }
                () = cancellation.cancelled() => return Err(ShardRuntimeError::Cancelled),
            }
        }
        Ok(())
    }

    async fn create_context(
        &self,
        session_id: &SessionId,
        _fence: &OwnershipFence,
        cancellation: CancellationToken,
    ) -> Result<(), ShardRuntimeError> {
        let _in_flight = self.enter().await;
        self.create_calls.fetch_add(1, Ordering::SeqCst);
        self.create_started.add_permits(1);
        if self.block_create.load(Ordering::SeqCst) {
            tokio::select! {
                permit = self.create_release.acquire() => {
                    permit.map_err(|_| ShardRuntimeError::Unavailable)?.forget();
                }
                () = cancellation.cancelled() => return Err(ShardRuntimeError::Cancelled),
            }
        }
        if let Ok(mut results) = self.create_results.lock()
            && let Some(result) = results.pop_front()
        {
            result?;
        }
        let Ok(mut created) = self.created.lock() else {
            return Err(ShardRuntimeError::Unavailable);
        };
        created.push(session_id.clone());
        Ok(())
    }

    async fn dispose_context(
        &self,
        session_id: &SessionId,
        _fence: &OwnershipFence,
        _cancellation: CancellationToken,
    ) -> Result<(), ShardRuntimeError> {
        let _in_flight = self.enter().await;
        self.dispose_calls.fetch_add(1, Ordering::SeqCst);
        if let Ok(mut results) = self.dispose_results.lock()
            && let Some(result) = results.pop_front()
        {
            result?;
        }
        let Ok(mut disposed) = self.disposed.lock() else {
            return Err(ShardRuntimeError::Unavailable);
        };
        disposed.push(session_id.clone());
        Ok(())
    }

    async fn terminate(&self, _fence: &ShardFence) -> Result<(), ShardRuntimeError> {
        let _in_flight = self.enter().await;
        self.terminate_calls.fetch_add(1, Ordering::SeqCst);
        self.terminated.notify_waiters();
        if let Ok(mut results) = self.terminate_results.lock()
            && let Some(result) = results.pop_front()
        {
            return result;
        }
        Ok(())
    }
}

fn shard_fence(worker_epoch: u64, launch_generation: u64) -> Option<ShardFence> {
    let worker_id = WorkerId::new("worker-a").ok()?;
    let worker_epoch = WorkerEpoch::new(worker_epoch)?;
    let launch_generation = LaunchGeneration::new(launch_generation)?;
    Some(ShardFence::new(
        OwnerFence::new(worker_id, worker_epoch),
        ShardId::new(),
        launch_generation,
    ))
}

fn replacement_fence(original: &ShardFence, worker_epoch: u64) -> Option<ShardFence> {
    Some(ShardFence::new(
        OwnerFence::new(
            original.owner().worker_id().clone(),
            WorkerEpoch::new(worker_epoch)?,
        ),
        original.shard_id().clone(),
        original.launch_generation(),
    ))
}

fn session_fence(shard: &ShardFence, placement_version: u64) -> OwnershipFence {
    OwnershipFence::new(
        shard.owner().worker_id().clone(),
        shard.owner().worker_epoch().get(),
        placement_version,
        1,
    )
}

fn config(fence: ShardFence, mailbox_capacity: usize) -> Option<BrowserShardActorConfig> {
    BrowserShardActorConfig::new(fence, mailbox_capacity, 16, 64).ok()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shard_actor_serializes_context_effects_and_rejects_every_stale_fence() {
    let Some(fence) = shard_fence(7, 1) else {
        return;
    };
    let Some(config) = config(fence.clone(), 32) else {
        return;
    };
    let runtime = Arc::new(FakeRuntime::default());
    let (actor, task) = BrowserShardActor::spawn(config, runtime.clone());
    assert_eq!(actor.activate(&fence).await, Ok(()));

    let mut attaches = Vec::new();
    for placement_version in 1..=8 {
        let actor = actor.clone();
        let fence = fence.clone();
        attaches.push(tokio::spawn(async move {
            let session_id = SessionId::new();
            let session_fence = session_fence(&fence, placement_version);
            actor
                .attach_session(&fence, session_id, session_fence)
                .await
        }));
    }
    for attach in attaches {
        let joined = attach.await;
        assert!(joined.is_ok());
        let Some(result) = joined.ok() else {
            return;
        };
        assert_eq!(
            result,
            Ok(AttachSessionOutcome::Attached),
            "each independently admitted context must attach exactly once"
        );
    }

    assert_eq!(runtime.create_calls.load(Ordering::SeqCst), 8);
    assert_eq!(runtime.max_in_flight.load(Ordering::SeqCst), 1);
    let snapshot = actor.snapshot(&fence).await;
    assert!(snapshot.is_ok());
    let Some(snapshot) = snapshot.ok() else {
        return;
    };
    assert_eq!(snapshot.lifecycle, ShardLifecycle::Active);
    assert_eq!(snapshot.health, ShardHealth::Healthy);
    assert_eq!(snapshot.admission, ShardAdmission::Open);
    assert_eq!(snapshot.live_sessions, 8);
    assert_eq!(snapshot.total_contexts_created, 8);

    let Some(stale_shard) = replacement_fence(&fence, 8) else {
        return;
    };
    assert_eq!(
        actor.snapshot(&stale_shard).await,
        Err(ShardActorError::StaleShardFence)
    );
    let stale_session = OwnershipFence::new(fence.owner().worker_id().clone(), 8, 1, 1);
    assert_eq!(
        actor
            .attach_session(&fence, SessionId::new(), stale_session)
            .await,
        Err(ShardActorError::StaleSessionFence)
    );
    assert_eq!(runtime.create_calls.load(Ordering::SeqCst), 8);

    drop(actor);
    assert!(task.await.is_ok());
    assert_eq!(runtime.terminate_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancelling_a_caller_does_not_cancel_an_admitted_attach_or_duplicate_it() {
    let Some(fence) = shard_fence(11, 1) else {
        return;
    };
    let Some(config) = config(fence.clone(), 8) else {
        return;
    };
    let runtime = Arc::new(FakeRuntime::default());
    runtime.block_create.store(true, Ordering::SeqCst);
    let (actor, task) = BrowserShardActor::spawn(config, runtime.clone());
    assert_eq!(actor.activate(&fence).await, Ok(()));

    let session_id = SessionId::new();
    let ownership = session_fence(&fence, 3);
    let attach = {
        let actor = actor.clone();
        let fence = fence.clone();
        let session_id = session_id.clone();
        let ownership = ownership.clone();
        tokio::spawn(async move { actor.attach_session(&fence, session_id, ownership).await })
    };
    let started = runtime.create_started.acquire().await;
    assert!(started.is_ok());
    let Some(started) = started.ok() else {
        return;
    };
    started.forget();
    attach.abort();
    runtime.create_release.add_permits(1);

    let snapshot = actor.snapshot(&fence).await;
    assert!(snapshot.is_ok());
    let Some(snapshot) = snapshot.ok() else {
        return;
    };
    assert_eq!(snapshot.live_sessions, 1);
    assert_eq!(runtime.create_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        actor.attach_session(&fence, session_id, ownership).await,
        Ok(AttachSessionOutcome::AlreadyAttached)
    );
    assert_eq!(runtime.create_calls.load(Ordering::SeqCst), 1);

    drop(actor);
    assert!(task.await.is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ownership_loss_preempts_a_blocked_effect_even_when_the_mailbox_is_full() {
    let Some(fence) = shard_fence(17, 4) else {
        return;
    };
    let Some(config) = config(fence.clone(), 1) else {
        return;
    };
    let runtime = Arc::new(FakeRuntime::default());
    runtime.block_create.store(true, Ordering::SeqCst);
    let (actor, task) = BrowserShardActor::spawn(config, runtime.clone());
    assert_eq!(actor.activate(&fence).await, Ok(()));

    let attach = {
        let actor = actor.clone();
        let fence = fence.clone();
        tokio::spawn(async move {
            actor
                .attach_session(&fence, SessionId::new(), session_fence(&fence, 1))
                .await
        })
    };
    let started = runtime.create_started.acquire().await;
    assert!(started.is_ok());
    let Some(started) = started.ok() else {
        return;
    };
    started.forget();

    let queued = {
        let actor = actor.clone();
        let fence = fence.clone();
        tokio::spawn(async move { actor.snapshot(&fence).await })
    };
    while actor.remaining_mailbox_capacity() != 0 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        actor.try_snapshot(&fence).await,
        Err(ShardActorError::MailboxFull)
    );

    assert_eq!(actor.lose_ownership(&fence).await, Ok(()));
    let attached = attach.await;
    assert!(attached.is_ok());
    let Some(attached) = attached.ok() else {
        return;
    };
    assert_eq!(attached, Err(ShardActorError::OwnershipLost));
    let queued = queued.await;
    assert!(queued.is_ok());
    let Some(queued) = queued.ok() else {
        return;
    };
    assert_eq!(queued, Err(ShardActorError::OwnershipLost));
    assert_eq!(runtime.terminate_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        actor
            .attach_session(&fence, SessionId::new(), session_fence(&fence, 2),)
            .await,
        Err(ShardActorError::OwnershipLost)
    );

    let task_finished = tokio::time::timeout(Duration::from_secs(1), task).await;
    assert!(task_finished.is_ok());
    assert!(task_finished.ok().is_some_and(|result| result.is_ok()));
    drop(actor);
}

#[tokio::test]
async fn drain_closes_admission_and_exact_detach_retries_are_idempotent() {
    let Some(fence) = shard_fence(23, 2) else {
        return;
    };
    let Some(config) = config(fence.clone(), 8) else {
        return;
    };
    let runtime = Arc::new(FakeRuntime::default());
    let (actor, task) = BrowserShardActor::spawn(config, runtime.clone());
    assert_eq!(actor.activate(&fence).await, Ok(()));
    let session_id = SessionId::new();
    let ownership = session_fence(&fence, 9);
    assert_eq!(
        actor
            .attach_session(&fence, session_id.clone(), ownership.clone())
            .await,
        Ok(AttachSessionOutcome::Attached)
    );
    assert_eq!(actor.begin_draining(&fence).await, Ok(()));
    assert_eq!(
        actor
            .attach_session(&fence, SessionId::new(), session_fence(&fence, 10),)
            .await,
        Err(ShardActorError::AdmissionClosed)
    );
    assert_eq!(
        actor
            .detach_session(&fence, session_id.clone(), ownership.clone())
            .await,
        Ok(DetachSessionOutcome::Detached)
    );
    assert_eq!(
        actor.detach_session(&fence, session_id, ownership).await,
        Ok(DetachSessionOutcome::AlreadyDetached)
    );
    assert_eq!(runtime.dispose_calls.load(Ordering::SeqCst), 1);
    assert_eq!(actor.stop_if_empty(&fence).await, Ok(()));

    let snapshot = actor.snapshot(&fence).await;
    assert!(snapshot.is_ok());
    let Some(snapshot) = snapshot.ok() else {
        return;
    };
    assert_eq!(snapshot.lifecycle, ShardLifecycle::Dead);
    assert_eq!(snapshot.live_sessions, 0);
    assert_eq!(runtime.terminate_calls.load(Ordering::SeqCst), 1);

    drop(actor);
    assert!(task.await.is_ok());
}

#[tokio::test]
async fn explicit_shutdown_joins_a_dead_actor_while_cloned_handles_remain() {
    let Some(fence) = shard_fence(24, 3) else {
        return;
    };
    let Some(config) = config(fence.clone(), 8) else {
        return;
    };
    let runtime = Arc::new(FakeRuntime::default());
    let (actor, task) = BrowserShardActor::spawn(config, runtime.clone());
    assert_eq!(actor.activate(&fence).await, Ok(()));
    assert_eq!(actor.begin_draining(&fence).await, Ok(()));
    assert_eq!(actor.stop_if_empty(&fence).await, Ok(()));

    let retained_handle = actor.clone();
    assert_eq!(actor.shutdown(&fence).await, Ok(()));
    let finished = tokio::time::timeout(Duration::from_secs(1), task).await;
    assert!(matches!(finished, Ok(Ok(Ok(())))));
    assert_eq!(runtime.terminate_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        retained_handle.snapshot(&fence).await,
        Err(ShardActorError::ActorStopped)
    );
    assert_eq!(retained_handle.shutdown(&fence).await, Ok(()));
    assert_eq!(runtime.terminate_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn terminate_failure_stays_stopping_and_can_be_retried() {
    let Some(fence) = shard_fence(29, 3) else {
        return;
    };
    let Some(config) = config(fence.clone(), 8) else {
        return;
    };
    let runtime = Arc::new(FakeRuntime::default());
    {
        let Ok(mut results) = runtime.terminate_results.lock() else {
            return;
        };
        results.push_back(Err(ShardRuntimeError::Unavailable));
        results.push_back(Ok(()));
    }

    let (actor, task) = BrowserShardActor::spawn(config, runtime.clone());
    assert_eq!(actor.activate(&fence).await, Ok(()));
    assert_eq!(actor.begin_draining(&fence).await, Ok(()));
    assert_eq!(
        actor.stop_if_empty(&fence).await,
        Err(ShardActorError::Runtime(ShardRuntimeError::Unavailable))
    );
    let stopping = actor.snapshot(&fence).await;
    assert!(stopping.is_ok());
    assert_eq!(
        stopping.ok().map(|snapshot| snapshot.lifecycle),
        Some(ShardLifecycle::Stopping)
    );

    assert_eq!(actor.stop_if_empty(&fence).await, Ok(()));
    let dead = actor.snapshot(&fence).await;
    assert!(dead.is_ok());
    assert_eq!(
        dead.ok().map(|snapshot| snapshot.lifecycle),
        Some(ShardLifecycle::Dead)
    );
    assert_eq!(runtime.terminate_calls.load(Ordering::SeqCst), 2);

    drop(actor);
    assert!(task.await.is_ok());
}

#[tokio::test]
async fn uncertain_context_creation_taints_and_drains_the_shard() {
    let Some(fence) = shard_fence(31, 1) else {
        return;
    };
    let Some(config) = config(fence.clone(), 8) else {
        return;
    };
    let runtime = Arc::new(FakeRuntime::default());
    {
        let Ok(mut results) = runtime.create_results.lock() else {
            return;
        };
        results.push_back(Err(ShardRuntimeError::OutcomeUncertain));
    }

    let (actor, task) = BrowserShardActor::spawn(config, runtime);
    assert_eq!(actor.activate(&fence).await, Ok(()));
    assert_eq!(
        actor
            .attach_session(&fence, SessionId::new(), session_fence(&fence, 1))
            .await,
        Err(ShardActorError::Runtime(
            ShardRuntimeError::OutcomeUncertain
        ))
    );
    let snapshot = actor.snapshot(&fence).await;
    assert!(snapshot.is_ok());
    let Some(snapshot) = snapshot.ok() else {
        return;
    };
    assert_eq!(snapshot.lifecycle, ShardLifecycle::Draining);
    assert_eq!(snapshot.health, ShardHealth::Tainted);
    assert_eq!(snapshot.admission, ShardAdmission::Closed);
    assert_eq!(snapshot.live_sessions, 0);

    drop(actor);
    assert!(task.await.is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_the_last_handle_preempts_a_blocked_runtime_effect() {
    let Some(fence) = shard_fence(37, 2) else {
        return;
    };
    let Some(config) = config(fence.clone(), 8) else {
        return;
    };
    let runtime = Arc::new(FakeRuntime::default());
    runtime.block_create.store(true, Ordering::SeqCst);
    let (actor, mut task) = BrowserShardActor::spawn(config, runtime.clone());
    assert_eq!(actor.activate(&fence).await, Ok(()));

    let attach = {
        let actor = actor.clone();
        let fence = fence.clone();
        tokio::spawn(async move {
            actor
                .attach_session(&fence, SessionId::new(), session_fence(&fence, 1))
                .await
        })
    };
    let started = runtime.create_started.acquire().await;
    assert!(started.is_ok());
    let Some(started) = started.ok() else {
        return;
    };
    started.forget();
    drop(actor);
    attach.abort();

    let finished = tokio::time::timeout(Duration::from_secs(1), &mut task).await;
    let finished_without_release = finished.is_ok();
    if !finished_without_release {
        runtime.create_release.add_permits(1);
        assert!(task.await.is_ok());
    }
    assert!(finished_without_release);
    assert_eq!(runtime.terminate_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn dispose_failure_taints_an_already_draining_shard() {
    let Some(fence) = shard_fence(41, 1) else {
        return;
    };
    let Some(config) = config(fence.clone(), 8) else {
        return;
    };
    let runtime = Arc::new(FakeRuntime::default());
    let (actor, task) = BrowserShardActor::spawn(config, runtime.clone());
    assert_eq!(actor.activate(&fence).await, Ok(()));
    let session_id = SessionId::new();
    let ownership = session_fence(&fence, 1);
    assert_eq!(
        actor
            .attach_session(&fence, session_id.clone(), ownership.clone())
            .await,
        Ok(AttachSessionOutcome::Attached)
    );
    assert_eq!(actor.begin_draining(&fence).await, Ok(()));
    {
        let Ok(mut results) = runtime.dispose_results.lock() else {
            return;
        };
        results.push_back(Err(ShardRuntimeError::Unavailable));
    }

    assert_eq!(
        actor.detach_session(&fence, session_id, ownership).await,
        Err(ShardActorError::Runtime(ShardRuntimeError::Unavailable))
    );
    let snapshot = actor.snapshot(&fence).await;
    assert!(snapshot.is_ok());
    let Some(snapshot) = snapshot.ok() else {
        return;
    };
    assert_eq!(snapshot.lifecycle, ShardLifecycle::Draining);
    assert_eq!(snapshot.health, ShardHealth::Tainted);
    assert_eq!(snapshot.admission, ShardAdmission::Closed);
    assert_eq!(snapshot.live_sessions, 1);

    drop(actor);
    assert!(task.await.is_ok());
}
