#![allow(clippy::unwrap_used)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use browserd_core::{
    EgressFence, LaunchGeneration, OwnerFence, RouteGeneration, SessionId, SessionIncarnation,
    ShardFence, ShardId, TenantId, WorkerEpoch, WorkerId,
};
use browserd_sandbox::{
    ChromiumCdpPipes, CleanupReason, CleanupResult, CreateShardOutcome, DedicatedEgressSpec,
    EgressPolicyBinding, KillShardOutcome, LaunchSpec,
};
use browserd_session::OwnershipFence;
use browserd_worker::{
    BrowserShardRuntime, CdpPipeAcceptor, ProductionSandboxShardRuntime, SandboxShardRpc,
    ShardLaunchDescriptor, ShardRuntimeError,
};
use tokio_util::sync::CancellationToken;

struct FakeRpc {
    calls: Mutex<Vec<&'static str>>,
    launch_generations: Mutex<Vec<LaunchGeneration>>,
}

#[async_trait]
impl SandboxShardRpc for FakeRpc {
    async fn create_shard(
        &self,
        _spec: LaunchSpec,
        _lease_ttl: Duration,
    ) -> Result<CreateShardOutcome, ShardRuntimeError> {
        self.calls.lock().unwrap().push("create");
        Ok(CreateShardOutcome::Created)
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

struct Sink(Mutex<usize>);

#[async_trait]
impl CdpPipeAcceptor for Sink {
    async fn accept_cdp_pipes(&self, _pipes: ChromiumCdpPipes) -> Result<(), ShardRuntimeError> {
        *self.0.lock().unwrap() += 1;
        Ok(())
    }
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
    let launch = LaunchSpec::production(TenantId::new(), dedicated);
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
    });
    let sink = Arc::new(Sink(Mutex::new(0)));
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
    assert_eq!(*sink.0.lock().unwrap(), 1);
    assert_eq!(*inner.0.lock().unwrap(), vec!["ready"]);
    assert_eq!(runtime.terminate(&fence).await, Ok(()));
    assert_eq!(*rpc.calls.lock().unwrap(), vec!["create", "claim", "kill"]);
    assert_eq!(
        *rpc.launch_generations.lock().unwrap(),
        vec![
            LaunchGeneration::new(3).unwrap(),
            LaunchGeneration::new(3).unwrap()
        ]
    );
}

#[tokio::test]
async fn stale_shard_fence_is_rejected_before_any_sandbox_rpc_effect() {
    let (descriptor, fence) = descriptor();
    let rpc = Arc::new(FakeRpc {
        calls: Mutex::new(Vec::new()),
        launch_generations: Mutex::new(Vec::new()),
    });
    let runtime = ProductionSandboxShardRuntime::new(
        descriptor,
        Duration::from_secs(20),
        rpc.clone(),
        Arc::new(Sink(Mutex::new(0))),
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
    assert!(rpc.calls.lock().unwrap().is_empty());
}
