#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use browserd_core::{
    EgressFence, LaunchGeneration, OwnerFence, RouteGeneration, SessionId, SessionIncarnation,
    ShardFence, ShardId, TenantId, WorkerEpoch, WorkerId,
};
use browserd_sandbox::{
    ChromiumBinaryDigest, ChromiumCdpPipes, CleanupReason, CleanupResult, CreateShardOutcome,
    DedicatedEgressSpec, EgressPolicyBinding, KillShardOutcome, LaunchSpec,
};
use browserd_session::OwnershipFence;
use browserd_worker::{
    BrowserShardRuntime, CdpPipeAcceptor, ProductionSandboxShardRuntime, SandboxShardRpc,
    ShardLaunchDescriptor, ShardRuntimeError,
};
use tokio::sync::{Notify, Semaphore};
use tokio_util::sync::CancellationToken;

struct FakeRpc {
    calls: Mutex<Vec<&'static str>>,
    launch_generations: Mutex<Vec<LaunchGeneration>>,
    cancelled_specs: Mutex<Vec<LaunchSpec>>,
    cleanup_outcomes: Mutex<VecDeque<KillShardOutcome>>,
    cleanup_finished: Notify,
    create_error: bool,
}

#[async_trait]
impl SandboxShardRpc for FakeRpc {
    async fn create_shard(
        &self,
        _spec: LaunchSpec,
        _lease_ttl: Duration,
    ) -> Result<CreateShardOutcome, ShardRuntimeError> {
        self.calls.lock().unwrap().push("create");
        if self.create_error {
            return Err(ShardRuntimeError::OutcomeUncertain);
        }
        Ok(CreateShardOutcome::Created)
    }

    async fn cancel_or_kill_shard(
        &self,
        spec: &LaunchSpec,
        _reason: CleanupReason,
    ) -> Result<KillShardOutcome, ShardRuntimeError> {
        self.calls.lock().unwrap().push("cancel");
        self.launch_generations
            .lock()
            .unwrap()
            .push(spec.launch_generation());
        self.cancelled_specs.lock().unwrap().push(spec.clone());
        let outcome = self
            .cleanup_outcomes
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(KillShardOutcome::AlreadyTerminated);
        self.cleanup_finished.notify_one();
        Ok(outcome)
    }

    async fn claim_cdp_pipes(
        &self,
        _shard_id: &ShardId,
        _worker_id: &WorkerId,
        _worker_epoch: u64,
        launch_generation: LaunchGeneration,
    ) -> Result<ChromiumCdpPipes, ShardRuntimeError> {
        self.calls.lock().unwrap().push("claim");
        self.launch_generations
            .lock()
            .unwrap()
            .push(launch_generation);
        let (_command_reader, command_writer) =
            nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).unwrap();
        let (event_reader, _event_writer) =
            nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).unwrap();
        ChromiumCdpPipes::from_owned_fds(command_writer, event_reader)
            .map_err(|_| ShardRuntimeError::Unavailable)
    }

    async fn renew_owner_lease(
        &self,
        _shard_id: &ShardId,
        _worker_epoch: u64,
        launch_generation: LaunchGeneration,
        _lease_ttl: Duration,
    ) -> Result<(), ShardRuntimeError> {
        self.calls.lock().unwrap().push("renew");
        self.launch_generations
            .lock()
            .unwrap()
            .push(launch_generation);
        Ok(())
    }

    async fn kill_shard(
        &self,
        _shard_id: &ShardId,
        _worker_epoch: u64,
        launch_generation: LaunchGeneration,
        _reason: CleanupReason,
    ) -> Result<KillShardOutcome, ShardRuntimeError> {
        self.calls.lock().unwrap().push("kill");
        self.launch_generations
            .lock()
            .unwrap()
            .push(launch_generation);
        Ok(KillShardOutcome::Terminated(CleanupResult {
            route_revoked: true,
            cgroup_killed: true,
            namespaces_cleaned: true,
        }))
    }
}

struct BlockingCreateRpc {
    create_calls: AtomicUsize,
    create_started: Notify,
    release_create: Notify,
    cancel_started: Notify,
    release_cancel: Notify,
    cancel_finished: Notify,
    cancelled_specs: Mutex<Vec<LaunchSpec>>,
    block_cleanup: bool,
}

#[async_trait]
impl SandboxShardRpc for BlockingCreateRpc {
    async fn create_shard(
        &self,
        _spec: LaunchSpec,
        _lease_ttl: Duration,
    ) -> Result<CreateShardOutcome, ShardRuntimeError> {
        self.create_calls.fetch_add(1, Ordering::SeqCst);
        self.create_started.notify_one();
        self.release_create.notified().await;
        Ok(CreateShardOutcome::Created)
    }

    async fn cancel_or_kill_shard(
        &self,
        spec: &LaunchSpec,
        _reason: CleanupReason,
    ) -> Result<KillShardOutcome, ShardRuntimeError> {
        self.cancelled_specs.lock().unwrap().push(spec.clone());
        self.cancel_started.notify_one();
        if self.block_cleanup {
            self.release_cancel.notified().await;
        }
        self.cancel_finished.notify_one();
        Ok(KillShardOutcome::AlreadyTerminated)
    }

    async fn claim_cdp_pipes(
        &self,
        _shard_id: &ShardId,
        _worker_id: &WorkerId,
        _worker_epoch: u64,
        _launch_generation: LaunchGeneration,
    ) -> Result<ChromiumCdpPipes, ShardRuntimeError> {
        let (_command_reader, command_writer) =
            nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).unwrap();
        let (event_reader, _event_writer) =
            nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).unwrap();
        ChromiumCdpPipes::from_owned_fds(command_writer, event_reader)
            .map_err(|_| ShardRuntimeError::Unavailable)
    }

    async fn renew_owner_lease(
        &self,
        _shard_id: &ShardId,
        _worker_epoch: u64,
        _launch_generation: LaunchGeneration,
        _lease_ttl: Duration,
    ) -> Result<(), ShardRuntimeError> {
        Err(ShardRuntimeError::Rejected)
    }

    async fn kill_shard(
        &self,
        _shard_id: &ShardId,
        _worker_epoch: u64,
        _launch_generation: LaunchGeneration,
        _reason: CleanupReason,
    ) -> Result<KillShardOutcome, ShardRuntimeError> {
        Err(ShardRuntimeError::Rejected)
    }
}

fn blocking_rpc() -> Arc<BlockingCreateRpc> {
    Arc::new(BlockingCreateRpc {
        create_calls: AtomicUsize::new(0),
        create_started: Notify::new(),
        release_create: Notify::new(),
        cancel_started: Notify::new(),
        release_cancel: Notify::new(),
        cancel_finished: Notify::new(),
        cancelled_specs: Mutex::new(Vec::new()),
        block_cleanup: true,
    })
}

fn late_create_rpc() -> Arc<BlockingCreateRpc> {
    Arc::new(BlockingCreateRpc {
        create_calls: AtomicUsize::new(0),
        create_started: Notify::new(),
        release_create: Notify::new(),
        cancel_started: Notify::new(),
        release_cancel: Notify::new(),
        cancel_finished: Notify::new(),
        cancelled_specs: Mutex::new(Vec::new()),
        block_cleanup: false,
    })
}

struct Sink {
    accepts: Mutex<usize>,
    shutdowns: AtomicUsize,
}

#[async_trait]
impl CdpPipeAcceptor for Sink {
    async fn accept_cdp_pipes(&self, _pipes: ChromiumCdpPipes) -> Result<(), ShardRuntimeError> {
        *self.accepts.lock().unwrap() += 1;
        Ok(())
    }

    async fn shutdown_cdp(&self) -> Result<(), ShardRuntimeError> {
        self.shutdowns.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

fn sink() -> Arc<Sink> {
    Arc::new(Sink {
        accepts: Mutex::new(0),
        shutdowns: AtomicUsize::new(0),
    })
}

struct Inner(Mutex<Vec<&'static str>>);

#[async_trait]
impl BrowserShardRuntime for Inner {
    async fn readiness_check(
        &self,
        _fence: &ShardFence,
        _cancellation: CancellationToken,
    ) -> Result<(), ShardRuntimeError> {
        self.0.lock().unwrap().push("ready");
        Ok(())
    }

    async fn create_context(
        &self,
        _session_id: &SessionId,
        _fence: &OwnershipFence,
        _cancellation: CancellationToken,
    ) -> Result<(), ShardRuntimeError> {
        Ok(())
    }

    async fn dispose_context(
        &self,
        _session_id: &SessionId,
        _fence: &OwnershipFence,
        _cancellation: CancellationToken,
    ) -> Result<(), ShardRuntimeError> {
        Ok(())
    }

    async fn terminate(&self, _fence: &ShardFence) -> Result<(), ShardRuntimeError> {
        self.0.lock().unwrap().push("terminate");
        Ok(())
    }
}

struct FlakyTerminateInner {
    terminations: AtomicUsize,
}

struct BlockingReadyInner {
    readiness_started: Notify,
    release_readiness: Notify,
    terminations: AtomicUsize,
    termination_finished: Notify,
}

struct BlockingTerminateInner {
    termination_calls: AtomicUsize,
    termination_started: Semaphore,
    release_termination: Semaphore,
    termination_finished: Semaphore,
}

struct BlockingContextInner {
    context_started: Semaphore,
    release_context: Semaphore,
}

#[async_trait]
impl BrowserShardRuntime for BlockingContextInner {
    async fn readiness_check(
        &self,
        _fence: &ShardFence,
        _cancellation: CancellationToken,
    ) -> Result<(), ShardRuntimeError> {
        Ok(())
    }

    async fn create_context(
        &self,
        _session_id: &SessionId,
        _fence: &OwnershipFence,
        _cancellation: CancellationToken,
    ) -> Result<(), ShardRuntimeError> {
        self.context_started.add_permits(1);
        self.release_context
            .acquire()
            .await
            .map_err(|_| ShardRuntimeError::Cancelled)?
            .forget();
        Ok(())
    }

    async fn dispose_context(
        &self,
        _session_id: &SessionId,
        _fence: &OwnershipFence,
        _cancellation: CancellationToken,
    ) -> Result<(), ShardRuntimeError> {
        Ok(())
    }

    async fn terminate(&self, _fence: &ShardFence) -> Result<(), ShardRuntimeError> {
        Ok(())
    }
}

#[async_trait]
impl BrowserShardRuntime for BlockingTerminateInner {
    async fn readiness_check(
        &self,
        _fence: &ShardFence,
        _cancellation: CancellationToken,
    ) -> Result<(), ShardRuntimeError> {
        Ok(())
    }

    async fn create_context(
        &self,
        _session_id: &SessionId,
        _fence: &OwnershipFence,
        _cancellation: CancellationToken,
    ) -> Result<(), ShardRuntimeError> {
        Ok(())
    }

    async fn dispose_context(
        &self,
        _session_id: &SessionId,
        _fence: &OwnershipFence,
        _cancellation: CancellationToken,
    ) -> Result<(), ShardRuntimeError> {
        Ok(())
    }

    async fn terminate(&self, _fence: &ShardFence) -> Result<(), ShardRuntimeError> {
        self.termination_calls.fetch_add(1, Ordering::SeqCst);
        self.termination_started.add_permits(1);
        self.release_termination
            .acquire()
            .await
            .map_err(|_| ShardRuntimeError::Cancelled)?
            .forget();
        self.termination_finished.add_permits(1);
        Ok(())
    }
}

fn blocking_terminate_inner() -> Arc<BlockingTerminateInner> {
    Arc::new(BlockingTerminateInner {
        termination_calls: AtomicUsize::new(0),
        termination_started: Semaphore::new(0),
        release_termination: Semaphore::new(0),
        termination_finished: Semaphore::new(0),
    })
}

#[async_trait]
impl BrowserShardRuntime for BlockingReadyInner {
    async fn readiness_check(
        &self,
        _fence: &ShardFence,
        _cancellation: CancellationToken,
    ) -> Result<(), ShardRuntimeError> {
        self.readiness_started.notify_one();
        self.release_readiness.notified().await;
        Ok(())
    }

    async fn create_context(
        &self,
        _session_id: &SessionId,
        _fence: &OwnershipFence,
        _cancellation: CancellationToken,
    ) -> Result<(), ShardRuntimeError> {
        Ok(())
    }

    async fn dispose_context(
        &self,
        _session_id: &SessionId,
        _fence: &OwnershipFence,
        _cancellation: CancellationToken,
    ) -> Result<(), ShardRuntimeError> {
        Ok(())
    }

    async fn terminate(&self, _fence: &ShardFence) -> Result<(), ShardRuntimeError> {
        self.terminations.fetch_add(1, Ordering::SeqCst);
        self.termination_finished.notify_one();
        Ok(())
    }
}

#[async_trait]
impl BrowserShardRuntime for FlakyTerminateInner {
    async fn readiness_check(
        &self,
        _fence: &ShardFence,
        _cancellation: CancellationToken,
    ) -> Result<(), ShardRuntimeError> {
        Ok(())
    }

    async fn create_context(
        &self,
        _session_id: &SessionId,
        _fence: &OwnershipFence,
        _cancellation: CancellationToken,
    ) -> Result<(), ShardRuntimeError> {
        Ok(())
    }

    async fn dispose_context(
        &self,
        _session_id: &SessionId,
        _fence: &OwnershipFence,
        _cancellation: CancellationToken,
    ) -> Result<(), ShardRuntimeError> {
        Ok(())
    }

    async fn terminate(&self, _fence: &ShardFence) -> Result<(), ShardRuntimeError> {
        if self.terminations.fetch_add(1, Ordering::SeqCst) == 0 {
            Err(ShardRuntimeError::OutcomeUncertain)
        } else {
            Ok(())
        }
    }
}

fn descriptor() -> (ShardLaunchDescriptor, ShardFence) {
    let worker_id = WorkerId::new("worker-production-sandbox").unwrap();
    let shard = ShardFence::new(
        OwnerFence::new(worker_id, WorkerEpoch::new(7).unwrap()),
        ShardId::new(),
        LaunchGeneration::new(3).unwrap(),
    );
    let egress = EgressFence::new(
        shard.clone(),
        RouteGeneration::new(2).unwrap(),
        SessionId::new(),
        SessionIncarnation::new(1).unwrap(),
    );
    let policy = EgressPolicyBinding::new("strict", [9; 32]).unwrap();
    let dedicated = DedicatedEgressSpec::new(egress, policy, Duration::from_secs(30)).unwrap();
    let launch = LaunchSpec::production(
        TenantId::new(),
        dedicated,
        ChromiumBinaryDigest::new([0x3c; 32]),
    );
    (
        ShardLaunchDescriptor::new(launch, shard.clone(), "dedicated", "strict").unwrap(),
        shard,
    )
}

#[tokio::test]
async fn sandbox_runtime_claims_cdp_before_inner_readiness_and_terminates_exact_shard() {
    let (descriptor, fence) = descriptor();
    let rpc = Arc::new(FakeRpc {
        calls: Mutex::new(Vec::new()),
        launch_generations: Mutex::new(Vec::new()),
        cancelled_specs: Mutex::new(Vec::new()),
        cleanup_outcomes: Mutex::new(VecDeque::new()),
        cleanup_finished: Notify::new(),
        create_error: false,
    });
    let sink = sink();
    let inner = Arc::new(Inner(Mutex::new(Vec::new())));
    let runtime = ProductionSandboxShardRuntime::new(
        descriptor,
        Duration::from_secs(20),
        rpc.clone(),
        sink.clone(),
        inner.clone(),
    );

    assert_eq!(
        runtime
            .readiness_check(&fence, CancellationToken::new())
            .await,
        Ok(())
    );
    assert_eq!(*rpc.calls.lock().unwrap(), vec!["create", "claim"]);
    assert_eq!(
        *rpc.launch_generations.lock().unwrap(),
        vec![LaunchGeneration::new(3).unwrap()]
    );
    assert_eq!(*sink.accepts.lock().unwrap(), 1);
    assert_eq!(*inner.0.lock().unwrap(), vec!["ready"]);
    assert_eq!(runtime.terminate(&fence).await, Ok(()));
    assert_eq!(sink.shutdowns.load(Ordering::SeqCst), 1);
    assert_eq!(
        *rpc.calls.lock().unwrap(),
        vec!["create", "claim", "cancel"]
    );
    assert_eq!(
        *rpc.launch_generations.lock().unwrap(),
        vec![
            LaunchGeneration::new(3).unwrap(),
            LaunchGeneration::new(3).unwrap()
        ]
    );
}

#[tokio::test]
async fn ready_sandbox_runtime_renews_the_exact_launch_lease() {
    let (descriptor, fence) = descriptor();
    let rpc = Arc::new(FakeRpc {
        calls: Mutex::new(Vec::new()),
        launch_generations: Mutex::new(Vec::new()),
        cancelled_specs: Mutex::new(Vec::new()),
        cleanup_outcomes: Mutex::new(VecDeque::new()),
        cleanup_finished: Notify::new(),
        create_error: false,
    });
    let runtime = ProductionSandboxShardRuntime::new(
        descriptor,
        Duration::from_secs(20),
        Arc::clone(&rpc),
        sink(),
        Arc::new(Inner(Mutex::new(Vec::new()))),
    );

    assert_eq!(
        runtime
            .readiness_check(&fence, CancellationToken::new())
            .await,
        Ok(())
    );
    assert_eq!(runtime.renew_owner_lease(&fence).await, Ok(()));
    assert_eq!(*rpc.calls.lock().unwrap(), vec!["create", "claim", "renew"]);
    assert_eq!(
        *rpc.launch_generations.lock().unwrap(),
        vec![
            LaunchGeneration::new(3).unwrap(),
            LaunchGeneration::new(3).unwrap()
        ]
    );

    assert_eq!(runtime.terminate(&fence).await, Ok(()));
    assert_eq!(
        runtime.renew_owner_lease(&fence).await,
        Err(ShardRuntimeError::Rejected)
    );
    assert_eq!(
        *rpc.calls.lock().unwrap(),
        vec!["create", "claim", "renew", "cancel"]
    );
}

#[tokio::test]
async fn stale_shard_fence_is_rejected_before_any_sandbox_rpc_effect() {
    let (descriptor, fence) = descriptor();
    let rpc = Arc::new(FakeRpc {
        calls: Mutex::new(Vec::new()),
        launch_generations: Mutex::new(Vec::new()),
        cancelled_specs: Mutex::new(Vec::new()),
        cleanup_outcomes: Mutex::new(VecDeque::new()),
        cleanup_finished: Notify::new(),
        create_error: false,
    });
    let runtime = ProductionSandboxShardRuntime::new(
        descriptor,
        Duration::from_secs(20),
        rpc.clone(),
        sink(),
        Arc::new(Inner(Mutex::new(Vec::new()))),
    );
    let stale = ShardFence::new(
        fence.owner().clone(),
        fence.shard_id().clone(),
        LaunchGeneration::new(4).unwrap(),
    );
    assert_eq!(
        runtime
            .readiness_check(&stale, CancellationToken::new())
            .await,
        Err(ShardRuntimeError::Rejected)
    );
    assert_eq!(
        runtime.renew_owner_lease(&stale).await,
        Err(ShardRuntimeError::Rejected)
    );
    assert!(rpc.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn incomplete_exact_cleanup_keeps_termination_retryable() {
    let (descriptor, fence) = descriptor();
    let launch_spec = descriptor.launch_spec().clone();
    let rpc = Arc::new(FakeRpc {
        calls: Mutex::new(Vec::new()),
        launch_generations: Mutex::new(Vec::new()),
        cancelled_specs: Mutex::new(Vec::new()),
        cleanup_outcomes: Mutex::new(VecDeque::from([
            KillShardOutcome::CleanupIncomplete(CleanupResult {
                route_revoked: true,
                cgroup_killed: false,
                namespaces_cleaned: false,
            }),
            KillShardOutcome::AlreadyTerminated,
        ])),
        cleanup_finished: Notify::new(),
        create_error: false,
    });
    let runtime = ProductionSandboxShardRuntime::new(
        descriptor,
        Duration::from_secs(20),
        Arc::clone(&rpc),
        sink(),
        Arc::new(Inner(Mutex::new(Vec::new()))),
    );

    assert_eq!(
        runtime
            .readiness_check(&fence, CancellationToken::new())
            .await,
        Ok(())
    );
    assert_eq!(
        runtime.terminate(&fence).await,
        Err(ShardRuntimeError::OutcomeUncertain)
    );
    assert_eq!(runtime.terminate(&fence).await, Ok(()));
    assert_eq!(
        *rpc.calls.lock().unwrap(),
        vec!["create", "claim", "cancel", "cancel"]
    );
    assert_eq!(
        rpc.cancelled_specs.lock().unwrap().as_slice(),
        [launch_spec.clone(), launch_spec]
    );
}

#[tokio::test]
async fn uncertain_local_shutdown_keeps_termination_retryable_after_exact_cleanup() {
    let (descriptor, fence) = descriptor();
    let rpc = Arc::new(FakeRpc {
        calls: Mutex::new(Vec::new()),
        launch_generations: Mutex::new(Vec::new()),
        cancelled_specs: Mutex::new(Vec::new()),
        cleanup_outcomes: Mutex::new(VecDeque::new()),
        cleanup_finished: Notify::new(),
        create_error: false,
    });
    let inner = Arc::new(FlakyTerminateInner {
        terminations: AtomicUsize::new(0),
    });
    let runtime = ProductionSandboxShardRuntime::new(
        descriptor,
        Duration::from_secs(20),
        Arc::clone(&rpc),
        sink(),
        Arc::clone(&inner),
    );

    assert_eq!(
        runtime
            .readiness_check(&fence, CancellationToken::new())
            .await,
        Ok(())
    );
    assert_eq!(
        runtime.terminate(&fence).await,
        Err(ShardRuntimeError::OutcomeUncertain)
    );
    assert_eq!(runtime.terminate(&fence).await, Ok(()));
    assert_eq!(inner.terminations.load(Ordering::SeqCst), 2);
    assert_eq!(
        *rpc.calls.lock().unwrap(),
        vec!["create", "claim", "cancel", "cancel"]
    );
}

#[tokio::test]
async fn blocked_local_shutdown_does_not_delay_exact_sandbox_cleanup() {
    let (descriptor, fence) = descriptor();
    let rpc = Arc::new(FakeRpc {
        calls: Mutex::new(Vec::new()),
        launch_generations: Mutex::new(Vec::new()),
        cancelled_specs: Mutex::new(Vec::new()),
        cleanup_outcomes: Mutex::new(VecDeque::new()),
        cleanup_finished: Notify::new(),
        create_error: false,
    });
    let inner = blocking_terminate_inner();
    let runtime = Arc::new(ProductionSandboxShardRuntime::new(
        descriptor,
        Duration::from_secs(20),
        Arc::clone(&rpc),
        sink(),
        Arc::clone(&inner),
    ));
    assert_eq!(
        runtime
            .readiness_check(&fence, CancellationToken::new())
            .await,
        Ok(())
    );

    let owned_runtime = Arc::clone(&runtime);
    let owned_fence = fence.clone();
    let mut termination = tokio::spawn(async move { owned_runtime.terminate(&owned_fence).await });
    tokio::time::timeout(Duration::from_secs(1), inner.termination_started.acquire())
        .await
        .expect("local shutdown must start")
        .unwrap()
        .forget();
    tokio::time::timeout(Duration::from_secs(1), rpc.cleanup_finished.notified())
        .await
        .expect("exact sandbox cleanup must run independently");
    assert!(
        tokio::time::timeout(Duration::from_millis(25), &mut termination)
            .await
            .is_err(),
        "termination must still join the local owner"
    );

    inner.release_termination.add_permits(1);
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), termination)
            .await
            .expect("termination must finish after the local owner")
            .unwrap(),
        Ok(())
    );
}

#[tokio::test]
async fn dropping_terminate_does_not_cancel_the_owned_cleanup() {
    let (descriptor, fence) = descriptor();
    let rpc = Arc::new(FakeRpc {
        calls: Mutex::new(Vec::new()),
        launch_generations: Mutex::new(Vec::new()),
        cancelled_specs: Mutex::new(Vec::new()),
        cleanup_outcomes: Mutex::new(VecDeque::new()),
        cleanup_finished: Notify::new(),
        create_error: false,
    });
    let inner = blocking_terminate_inner();
    let runtime = Arc::new(ProductionSandboxShardRuntime::new(
        descriptor,
        Duration::from_secs(20),
        Arc::clone(&rpc),
        sink(),
        Arc::clone(&inner),
    ));
    assert_eq!(
        runtime
            .readiness_check(&fence, CancellationToken::new())
            .await,
        Ok(())
    );
    let owned_runtime = Arc::clone(&runtime);
    let owned_fence = fence.clone();
    let termination = tokio::spawn(async move { owned_runtime.terminate(&owned_fence).await });
    tokio::time::timeout(Duration::from_secs(1), inner.termination_started.acquire())
        .await
        .expect("local cleanup must start")
        .unwrap()
        .forget();

    termination.abort();
    assert!(termination.await.unwrap_err().is_cancelled());
    inner.release_termination.add_permits(1);
    tokio::time::timeout(Duration::from_secs(1), inner.termination_finished.acquire())
        .await
        .expect("owned cleanup must survive the caller drop")
        .unwrap()
        .forget();
    assert_eq!(runtime.terminate(&fence).await, Ok(()));
    assert_eq!(inner.termination_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn concurrent_terminate_callers_share_one_owned_cleanup() {
    let (descriptor, fence) = descriptor();
    let rpc = Arc::new(FakeRpc {
        calls: Mutex::new(Vec::new()),
        launch_generations: Mutex::new(Vec::new()),
        cancelled_specs: Mutex::new(Vec::new()),
        cleanup_outcomes: Mutex::new(VecDeque::new()),
        cleanup_finished: Notify::new(),
        create_error: false,
    });
    let inner = blocking_terminate_inner();
    let runtime = Arc::new(ProductionSandboxShardRuntime::new(
        descriptor,
        Duration::from_secs(20),
        Arc::clone(&rpc),
        sink(),
        Arc::clone(&inner),
    ));
    assert_eq!(
        runtime
            .readiness_check(&fence, CancellationToken::new())
            .await,
        Ok(())
    );
    let first_runtime = Arc::clone(&runtime);
    let first_fence = fence.clone();
    let first = tokio::spawn(async move { first_runtime.terminate(&first_fence).await });
    tokio::time::timeout(Duration::from_secs(1), inner.termination_started.acquire())
        .await
        .expect("first cleanup must start")
        .unwrap()
        .forget();

    let second_runtime = Arc::clone(&runtime);
    let second_fence = fence.clone();
    let (entered, entered_rx) = tokio::sync::oneshot::channel();
    let second = tokio::spawn(async move {
        let _ = entered.send(());
        second_runtime.terminate(&second_fence).await
    });
    entered_rx.await.unwrap();
    assert!(
        tokio::time::timeout(
            Duration::from_millis(25),
            inner.termination_started.acquire(),
        )
        .await
        .is_err(),
        "a concurrent caller must not start a second cleanup"
    );

    inner.release_termination.add_permits(1);
    assert_eq!(first.await.unwrap(), Ok(()));
    assert_eq!(second.await.unwrap(), Ok(()));
    assert_eq!(inner.termination_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn termination_cancels_and_joins_an_admitted_context_operation() {
    let (descriptor, fence) = descriptor();
    let rpc = Arc::new(FakeRpc {
        calls: Mutex::new(Vec::new()),
        launch_generations: Mutex::new(Vec::new()),
        cancelled_specs: Mutex::new(Vec::new()),
        cleanup_outcomes: Mutex::new(VecDeque::new()),
        cleanup_finished: Notify::new(),
        create_error: false,
    });
    let inner = Arc::new(BlockingContextInner {
        context_started: Semaphore::new(0),
        release_context: Semaphore::new(0),
    });
    let runtime = Arc::new(ProductionSandboxShardRuntime::new(
        descriptor,
        Duration::from_secs(20),
        Arc::clone(&rpc),
        sink(),
        Arc::clone(&inner),
    ));
    assert_eq!(
        runtime
            .readiness_check(&fence, CancellationToken::new())
            .await,
        Ok(())
    );
    let session_id = SessionId::new();
    let ownership = OwnershipFence::new(
        fence.owner().worker_id().clone(),
        fence.owner().worker_epoch().get(),
        1,
        1,
    );
    let operation_runtime = Arc::clone(&runtime);
    let operation = tokio::spawn(async move {
        operation_runtime
            .create_context(&session_id, &ownership, CancellationToken::new())
            .await
    });
    tokio::time::timeout(Duration::from_secs(1), inner.context_started.acquire())
        .await
        .expect("context operation must start")
        .unwrap()
        .forget();

    let termination_runtime = Arc::clone(&runtime);
    let termination_fence = fence.clone();
    let termination =
        tokio::spawn(async move { termination_runtime.terminate(&termination_fence).await });
    tokio::time::timeout(Duration::from_secs(1), rpc.cleanup_finished.notified())
        .await
        .expect("exact cleanup must start before the context is released");
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), operation)
            .await
            .expect("termination must cancel the context operation")
            .unwrap(),
        Err(ShardRuntimeError::Cancelled)
    );
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), termination)
            .await
            .expect("termination must join the cancelled operation")
            .unwrap(),
        Ok(())
    );
}

#[tokio::test]
async fn create_rpc_error_installs_the_exact_tombstone_before_readiness_returns() {
    let (descriptor, fence) = descriptor();
    let launch_spec = descriptor.launch_spec().clone();
    let rpc = Arc::new(FakeRpc {
        calls: Mutex::new(Vec::new()),
        launch_generations: Mutex::new(Vec::new()),
        cancelled_specs: Mutex::new(Vec::new()),
        cleanup_outcomes: Mutex::new(VecDeque::new()),
        cleanup_finished: Notify::new(),
        create_error: true,
    });
    let runtime = ProductionSandboxShardRuntime::new(
        descriptor,
        Duration::from_secs(20),
        Arc::clone(&rpc),
        sink(),
        Arc::new(Inner(Mutex::new(Vec::new()))),
    );

    assert_eq!(
        runtime
            .readiness_check(&fence, CancellationToken::new())
            .await,
        Err(ShardRuntimeError::OutcomeUncertain)
    );
    assert_eq!(*rpc.calls.lock().unwrap(), vec!["create", "cancel"]);
    assert_eq!(
        rpc.cancelled_specs.lock().unwrap().as_slice(),
        [launch_spec]
    );
    assert_eq!(
        runtime
            .readiness_check(&fence, CancellationToken::new())
            .await,
        Err(ShardRuntimeError::Rejected),
        "a failed launch must never begin a second create"
    );
    assert_eq!(*rpc.calls.lock().unwrap(), vec!["create", "cancel"]);
}

#[tokio::test]
async fn dropping_readiness_during_create_triggers_exact_cancel_without_terminate() {
    let (descriptor, fence) = descriptor();
    let launch_spec = descriptor.launch_spec().clone();
    let rpc = blocking_rpc();
    let runtime = Arc::new(ProductionSandboxShardRuntime::new(
        descriptor,
        Duration::from_secs(20),
        Arc::clone(&rpc),
        sink(),
        Arc::new(Inner(Mutex::new(Vec::new()))),
    ));
    let owned_runtime = Arc::clone(&runtime);
    let owned_fence = fence.clone();
    let task = tokio::spawn(async move {
        owned_runtime
            .readiness_check(&owned_fence, CancellationToken::new())
            .await
    });

    tokio::time::timeout(Duration::from_secs(1), rpc.create_started.notified())
        .await
        .expect("create must start");
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());

    tokio::time::timeout(Duration::from_secs(1), rpc.cancel_started.notified())
        .await
        .expect("dropping readiness must start exact cleanup");
    assert_eq!(
        rpc.cancelled_specs.lock().unwrap().as_slice(),
        [launch_spec]
    );
    rpc.release_cancel.notify_one();
    tokio::time::timeout(Duration::from_secs(1), rpc.cancel_finished.notified())
        .await
        .expect("exact cleanup must finish");

    assert_eq!(
        runtime
            .readiness_check(&fence, CancellationToken::new())
            .await,
        Err(ShardRuntimeError::Rejected)
    );
    assert_eq!(rpc.create_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn provisioning_state_does_not_block_duplicate_or_precancelled_readiness() {
    let (descriptor, fence) = descriptor();
    let rpc = blocking_rpc();
    let runtime = Arc::new(ProductionSandboxShardRuntime::new(
        descriptor,
        Duration::from_secs(20),
        Arc::clone(&rpc),
        sink(),
        Arc::new(Inner(Mutex::new(Vec::new()))),
    ));
    let owned_runtime = Arc::clone(&runtime);
    let owned_fence = fence.clone();
    let task = tokio::spawn(async move {
        owned_runtime
            .readiness_check(&owned_fence, CancellationToken::new())
            .await
    });
    tokio::time::timeout(Duration::from_secs(1), rpc.create_started.notified())
        .await
        .expect("first create must start");

    let cancelled = CancellationToken::new();
    cancelled.cancel();
    assert_eq!(
        tokio::time::timeout(
            Duration::from_secs(1),
            runtime.readiness_check(&fence, cancelled),
        )
        .await
        .expect("pre-cancelled readiness must not wait behind provisioning"),
        Err(ShardRuntimeError::Cancelled)
    );
    assert_eq!(
        tokio::time::timeout(
            Duration::from_secs(1),
            runtime.readiness_check(&fence, CancellationToken::new()),
        )
        .await
        .expect("duplicate readiness must observe provisioning immediately"),
        Err(ShardRuntimeError::Rejected)
    );

    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    tokio::time::timeout(Duration::from_secs(1), rpc.cancel_started.notified())
        .await
        .expect("drop must start cleanup");
    rpc.release_cancel.notify_one();
    tokio::time::timeout(Duration::from_secs(1), rpc.cancel_finished.notified())
        .await
        .expect("drop cleanup must finish");
}

#[tokio::test]
async fn terminate_during_create_starts_exact_cleanup_without_releasing_create() {
    let (descriptor, fence) = descriptor();
    let rpc = blocking_rpc();
    let runtime = Arc::new(ProductionSandboxShardRuntime::new(
        descriptor,
        Duration::from_secs(20),
        Arc::clone(&rpc),
        sink(),
        Arc::new(Inner(Mutex::new(Vec::new()))),
    ));
    let readiness_runtime = Arc::clone(&runtime);
    let readiness_fence = fence.clone();
    let readiness = tokio::spawn(async move {
        readiness_runtime
            .readiness_check(&readiness_fence, CancellationToken::new())
            .await
    });
    tokio::time::timeout(Duration::from_secs(1), rpc.create_started.notified())
        .await
        .expect("create must start");

    let termination_runtime = Arc::clone(&runtime);
    let termination_fence = fence.clone();
    let termination =
        tokio::spawn(async move { termination_runtime.terminate(&termination_fence).await });
    tokio::time::timeout(Duration::from_secs(1), rpc.cancel_started.notified())
        .await
        .expect("terminate must not wait for the blocked create");
    rpc.release_cancel.notify_waiters();
    rpc.release_cancel.notify_one();
    tokio::time::timeout(Duration::from_secs(1), rpc.cancel_finished.notified())
        .await
        .expect("termination cleanup must finish");
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), termination)
            .await
            .expect("terminate must finish")
            .unwrap(),
        Ok(())
    );
    assert_eq!(readiness.await.unwrap(), Err(ShardRuntimeError::Cancelled));
    assert_eq!(rpc.create_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn terminate_joins_provisioning_before_a_late_create_can_accept_cdp() {
    let (descriptor, fence) = descriptor();
    let rpc = late_create_rpc();
    let sink = sink();
    let inner = Arc::new(Inner(Mutex::new(Vec::new())));
    let runtime = Arc::new(ProductionSandboxShardRuntime::new(
        descriptor,
        Duration::from_secs(20),
        Arc::clone(&rpc),
        Arc::clone(&sink),
        Arc::clone(&inner),
    ));
    let readiness_runtime = Arc::clone(&runtime);
    let readiness_fence = fence.clone();
    let readiness = tokio::spawn(async move {
        readiness_runtime
            .readiness_check(&readiness_fence, CancellationToken::new())
            .await
    });
    tokio::time::timeout(Duration::from_secs(1), rpc.create_started.notified())
        .await
        .expect("create must start");

    assert_eq!(runtime.terminate(&fence).await, Ok(()));
    rpc.release_create.notify_one();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(1), readiness)
            .await
            .expect("readiness must be joined by termination")
            .unwrap(),
        Err(ShardRuntimeError::Cancelled | ShardRuntimeError::Rejected)
    ));
    assert_eq!(sink.accepts.lock().unwrap().to_owned(), 0);
    assert!(
        !inner.0.lock().unwrap().contains(&"ready"),
        "no local owner may start after termination returns"
    );
}

#[tokio::test]
async fn dropping_readiness_after_cdp_acceptance_joins_every_local_owner() {
    let (descriptor, fence) = descriptor();
    let launch_spec = descriptor.launch_spec().clone();
    let rpc = Arc::new(FakeRpc {
        calls: Mutex::new(Vec::new()),
        launch_generations: Mutex::new(Vec::new()),
        cancelled_specs: Mutex::new(Vec::new()),
        cleanup_outcomes: Mutex::new(VecDeque::new()),
        cleanup_finished: Notify::new(),
        create_error: false,
    });
    let sink = sink();
    let inner = Arc::new(BlockingReadyInner {
        readiness_started: Notify::new(),
        release_readiness: Notify::new(),
        terminations: AtomicUsize::new(0),
        termination_finished: Notify::new(),
    });
    let runtime = Arc::new(ProductionSandboxShardRuntime::new(
        descriptor,
        Duration::from_secs(20),
        Arc::clone(&rpc),
        Arc::clone(&sink),
        Arc::clone(&inner),
    ));
    let owned_runtime = Arc::clone(&runtime);
    let owned_fence = fence.clone();
    let task = tokio::spawn(async move {
        owned_runtime
            .readiness_check(&owned_fence, CancellationToken::new())
            .await
    });

    tokio::time::timeout(Duration::from_secs(1), inner.readiness_started.notified())
        .await
        .expect("inner readiness must start after accepting CDP pipes");
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());

    tokio::time::timeout(
        Duration::from_secs(1),
        inner.termination_finished.notified(),
    )
    .await
    .expect("drop cleanup must terminate and join the inner owner");
    tokio::time::timeout(Duration::from_secs(1), rpc.cleanup_finished.notified())
        .await
        .expect("drop cleanup must terminate the exact sandbox shard");
    assert_eq!(inner.terminations.load(Ordering::SeqCst), 1);
    assert_eq!(sink.shutdowns.load(Ordering::SeqCst), 1);
    assert_eq!(
        rpc.cancelled_specs.lock().unwrap().as_slice(),
        [launch_spec]
    );
}

#[tokio::test]
async fn cancellation_during_create_waits_for_terminal_exact_cleanup() {
    let (descriptor, fence) = descriptor();
    let launch_spec = descriptor.launch_spec().clone();
    let rpc = blocking_rpc();
    let runtime = Arc::new(ProductionSandboxShardRuntime::new(
        descriptor,
        Duration::from_secs(20),
        Arc::clone(&rpc),
        sink(),
        Arc::new(Inner(Mutex::new(Vec::new()))),
    ));
    let cancellation = CancellationToken::new();
    let owned_runtime = Arc::clone(&runtime);
    let owned_fence = fence.clone();
    let owned_cancellation = cancellation.clone();
    let mut task = tokio::spawn(async move {
        owned_runtime
            .readiness_check(&owned_fence, owned_cancellation)
            .await
    });

    tokio::time::timeout(Duration::from_secs(1), rpc.create_started.notified())
        .await
        .expect("create must start");
    cancellation.cancel();
    tokio::time::timeout(Duration::from_secs(1), rpc.cancel_started.notified())
        .await
        .expect("cancellation must start exact cleanup");
    assert_eq!(
        rpc.cancelled_specs.lock().unwrap().as_slice(),
        [launch_spec]
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(25), &mut task)
            .await
            .is_err(),
        "readiness must not return before cleanup is terminal"
    );

    rpc.release_cancel.notify_one();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("readiness must return after cleanup")
            .unwrap(),
        Err(ShardRuntimeError::Cancelled)
    );
    assert_eq!(rpc.create_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn nonterminal_cancellation_cleanup_is_uncertain_and_termination_retries_it() {
    let (descriptor, fence) = descriptor();
    let rpc = Arc::new(FakeRpc {
        calls: Mutex::new(Vec::new()),
        launch_generations: Mutex::new(Vec::new()),
        cancelled_specs: Mutex::new(Vec::new()),
        cleanup_outcomes: Mutex::new(VecDeque::from([
            KillShardOutcome::CleanupIncomplete(CleanupResult {
                route_revoked: true,
                cgroup_killed: false,
                namespaces_cleaned: false,
            }),
            KillShardOutcome::AlreadyTerminated,
        ])),
        cleanup_finished: Notify::new(),
        create_error: false,
    });
    let inner = Arc::new(BlockingReadyInner {
        readiness_started: Notify::new(),
        release_readiness: Notify::new(),
        terminations: AtomicUsize::new(0),
        termination_finished: Notify::new(),
    });
    let runtime = Arc::new(ProductionSandboxShardRuntime::new(
        descriptor,
        Duration::from_secs(20),
        Arc::clone(&rpc),
        sink(),
        Arc::clone(&inner),
    ));
    let cancellation = CancellationToken::new();
    let owned_runtime = Arc::clone(&runtime);
    let owned_fence = fence.clone();
    let owned_cancellation = cancellation.clone();
    let readiness = tokio::spawn(async move {
        owned_runtime
            .readiness_check(&owned_fence, owned_cancellation)
            .await
    });
    tokio::time::timeout(Duration::from_secs(1), inner.readiness_started.notified())
        .await
        .expect("inner readiness must start");

    cancellation.cancel();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), readiness)
            .await
            .expect("cancelled readiness must finish")
            .unwrap(),
        Err(ShardRuntimeError::OutcomeUncertain)
    );
    assert_eq!(runtime.terminate(&fence).await, Ok(()));
    assert_eq!(
        *rpc.calls.lock().unwrap(),
        vec!["create", "claim", "cancel", "cancel"]
    );
    assert_eq!(inner.terminations.load(Ordering::SeqCst), 2);
}
