#![allow(clippy::expect_used)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use browserd_core::{
    EgressFence, LaunchGeneration, OwnerFence, RouteGeneration, SessionId, SessionIncarnation,
    ShardFence, ShardId, TenantId, WorkerEpoch, WorkerId,
};
use browserd_sandbox::{
    CleanupReason, CreateShardOutcome, DedicatedEgressSpec, EgressPolicyBinding, InspectResources,
    LaunchSpec, RpcFailureCode, SandboxBackend, SandboxCapabilities, SandboxError, SandboxHandle,
    SandboxRpcClient, SandboxRpcConfig, SandboxRpcError, SandboxRpcServer, SandboxSupervisor,
    SupervisorConfig, WorkerOwnership,
};
use serde_json::json;
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio_util::sync::CancellationToken;

fn worker() -> WorkerId {
    WorkerId::new("worker-launch-contract").expect("worker ID is valid")
}

fn launch_spec(shard_id: ShardId, worker_id: WorkerId, worker_epoch: u64) -> LaunchSpec {
    let worker_epoch = WorkerEpoch::new(worker_epoch).expect("worker epoch is positive");
    let egress_fence = EgressFence::new(
        ShardFence::new(
            OwnerFence::new(worker_id, worker_epoch),
            shard_id,
            LaunchGeneration::new(3).expect("launch generation is positive"),
        ),
        RouteGeneration::new(5).expect("route generation is positive"),
        SessionId::new(),
        SessionIncarnation::new(1).expect("session incarnation is positive"),
    );
    let policy_binding =
        EgressPolicyBinding::new("public-web-v1", [0x5a; 32]).expect("policy binding is valid");
    let dedicated_egress =
        DedicatedEgressSpec::new(egress_fence, policy_binding, Duration::from_millis(50))
            .expect("dedicated egress spec is valid");
    LaunchSpec::production(TenantId::new(), dedicated_egress)
}

#[test]
fn production_launch_spec_derives_every_duplicate_identity_from_the_full_fence() {
    let shard_id = ShardId::new();
    let worker_id = worker();
    let spec = launch_spec(shard_id.clone(), worker_id.clone(), 7);

    assert_eq!(spec.shard_id(), &shard_id);
    assert_eq!(spec.worker_id(), &worker_id);
    assert_eq!(spec.worker_epoch(), 7);
    assert_eq!(
        spec.dedicated_egress().egress_fence().shard().shard_id(),
        spec.shard_id()
    );
    assert_eq!(
        spec.dedicated_egress()
            .egress_fence()
            .shard()
            .owner()
            .worker_id(),
        spec.worker_id()
    );
    assert_eq!(
        spec.dedicated_egress()
            .egress_fence()
            .shard()
            .owner()
            .worker_epoch()
            .get(),
        spec.worker_epoch()
    );
    assert_eq!(
        spec.dedicated_egress().policy_binding().profile(),
        "public-web-v1"
    );
    assert_eq!(
        spec.dedicated_egress().initial_lease_ttl(),
        Duration::from_millis(50)
    );
}

#[test]
fn dedicated_egress_ttl_is_nonzero_and_bounded() {
    let valid = launch_spec(ShardId::new(), worker(), 7);
    let fence = valid.dedicated_egress().egress_fence().clone();
    let binding = valid.dedicated_egress().policy_binding().clone();

    assert_eq!(
        DedicatedEgressSpec::new(fence.clone(), binding.clone(), Duration::ZERO),
        Err(SandboxError::InvalidEgressLease)
    );
    assert_eq!(
        DedicatedEgressSpec::new(fence, binding, Duration::from_secs(301)),
        Err(SandboxError::InvalidEgressLease)
    );
}

#[test]
fn policy_binding_rejects_an_uninitialized_snapshot_digest() {
    assert_eq!(
        EgressPolicyBinding::new("public-web-v1", [0; 32]),
        Err(SandboxError::InvalidEgressPolicyBinding)
    );
}

#[derive(Clone, Default)]
struct CountingBackend {
    provisions: Arc<AtomicUsize>,
    specs: Arc<Mutex<Vec<LaunchSpec>>>,
}

#[async_trait]
impl SandboxBackend for CountingBackend {
    fn capabilities(&self) -> SandboxCapabilities {
        SandboxCapabilities::production_required()
    }

    async fn provision(&self, spec: &LaunchSpec) -> Result<SandboxHandle, SandboxError> {
        self.provisions.fetch_add(1, Ordering::AcqRel);
        self.specs
            .lock()
            .expect("spec recording lock is available")
            .push(spec.clone());
        Ok(SandboxHandle::new(
            spec.shard_id().clone(),
            "launch-contract",
        ))
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
        _reason: CleanupReason,
    ) -> Result<(), SandboxError> {
        Ok(())
    }

    async fn cleanup_namespaces(&self, _handle: &SandboxHandle) -> Result<(), SandboxError> {
        Ok(())
    }

    async fn inspect(&self, _handle: &SandboxHandle) -> Result<InspectResources, SandboxError> {
        Ok(InspectResources {
            memory_current_bytes: 0,
            memory_peak_bytes: 0,
            process_count: 0,
            egress_route_active: false,
        })
    }
}

#[tokio::test]
async fn rpc_round_trip_preserves_the_complete_dedicated_egress_launch_contract() {
    let temporary = tempdir().expect("temporary directory is available");
    let socket = temporary.path().join("sandboxd.sock");
    let listener = UnixListener::bind(&socket).expect("Unix socket binds");
    let shutdown = CancellationToken::new();
    let backend = CountingBackend::default();
    let observed_backend = backend.clone();
    let supervisor = Arc::new(SandboxSupervisor::new(
        SupervisorConfig::new(Duration::from_millis(100), Duration::from_secs(1))
            .expect("supervisor config is valid"),
        backend,
    ));
    let rpc_config = SandboxRpcConfig::new(
        8 * 1024,
        2,
        Duration::from_millis(200),
        Duration::from_millis(5),
        Some(nix::unistd::Uid::effective().as_raw()),
    )
    .expect("RPC config is valid");
    let server = SandboxRpcServer::new(supervisor, rpc_config);
    let server_shutdown = shutdown.clone();
    let task = tokio::spawn(async move { server.serve(listener, server_shutdown).await });
    let client = SandboxRpcClient::new(socket, 8 * 1024, Duration::from_millis(200))
        .expect("client config is valid");
    let spec = launch_spec(ShardId::new(), worker(), 7);

    assert_eq!(
        client
            .create_shard(spec.clone(), Duration::from_millis(80))
            .await,
        Ok(CreateShardOutcome::Created)
    );
    let conflicting_binding = EgressPolicyBinding::new("restricted-web-v1", [0xa5; 32])
        .expect("conflicting binding is valid");
    let conflicting_egress = DedicatedEgressSpec::new(
        spec.dedicated_egress().egress_fence().clone(),
        conflicting_binding,
        spec.dedicated_egress().initial_lease_ttl(),
    )
    .expect("conflicting egress spec is structurally valid");
    assert!(matches!(
        client
            .create_shard(
                LaunchSpec::production(spec.tenant_id().clone(), conflicting_egress),
                Duration::from_millis(80),
            )
            .await,
        Err(SandboxRpcError::Remote {
            code: RpcFailureCode::LaunchBindingMismatch,
            ..
        })
    ));
    assert_eq!(
        observed_backend
            .specs
            .lock()
            .expect("spec recording lock is available")
            .as_slice(),
        [spec]
    );

    shutdown.cancel();
    assert!(matches!(task.await, Ok(Ok(()))));
}

#[tokio::test]
async fn an_existing_shard_distinguishes_fence_and_immutable_binding_conflicts() {
    let backend = CountingBackend::default();
    let observed_backend = backend.clone();
    let supervisor = SandboxSupervisor::new(
        SupervisorConfig::new(Duration::from_secs(1), Duration::from_secs(2))
            .expect("supervisor config is valid"),
        backend,
    );
    let shard_id = ShardId::new();
    let worker_id = worker();
    let first = launch_spec(shard_id.clone(), worker_id.clone(), 7);
    let conflicting_fence = launch_spec(shard_id, worker_id.clone(), 7);
    let conflicting_policy =
        EgressPolicyBinding::new("restricted-web-v1", [0xa5; 32]).expect("binding is valid");
    let conflicting_egress = DedicatedEgressSpec::new(
        first.dedicated_egress().egress_fence().clone(),
        conflicting_policy,
        first.dedicated_egress().initial_lease_ttl(),
    )
    .expect("conflicting egress spec remains structurally valid");
    let conflicting_binding = LaunchSpec::production(first.tenant_id().clone(), conflicting_egress);
    let conflicting_ttl_egress = DedicatedEgressSpec::new(
        first.dedicated_egress().egress_fence().clone(),
        first.dedicated_egress().policy_binding().clone(),
        first.dedicated_egress().initial_lease_ttl() + Duration::from_millis(1),
    )
    .expect("conflicting TTL remains structurally valid");
    let conflicting_ttl = LaunchSpec::production(first.tenant_id().clone(), conflicting_ttl_egress);

    assert_eq!(
        supervisor
            .create_shard(
                first,
                WorkerOwnership::new(
                    worker_id.clone(),
                    7,
                    tokio::time::Instant::now() + Duration::from_millis(900),
                ),
            )
            .await,
        Ok(CreateShardOutcome::Created)
    );
    assert_eq!(
        supervisor
            .create_shard(
                conflicting_fence,
                WorkerOwnership::new(
                    worker_id.clone(),
                    7,
                    tokio::time::Instant::now() + Duration::from_millis(900),
                ),
            )
            .await,
        Err(SandboxError::LaunchFenceMismatch)
    );
    assert_eq!(
        supervisor
            .create_shard(
                conflicting_binding,
                WorkerOwnership::new(
                    worker_id.clone(),
                    7,
                    tokio::time::Instant::now() + Duration::from_millis(900),
                ),
            )
            .await,
        Err(SandboxError::LaunchBindingMismatch)
    );
    assert_eq!(
        supervisor
            .create_shard(
                conflicting_ttl,
                WorkerOwnership::new(
                    worker_id,
                    7,
                    tokio::time::Instant::now() + Duration::from_millis(900),
                ),
            )
            .await,
        Err(SandboxError::LaunchBindingMismatch)
    );
    assert_eq!(observed_backend.provisions.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn rpc_rejects_conflicting_identities_and_unvalidated_immutable_bindings() {
    let temporary = tempdir().expect("temporary directory is available");
    let socket = temporary.path().join("sandboxd.sock");
    let listener = UnixListener::bind(&socket).expect("Unix socket binds");
    let shutdown = CancellationToken::new();
    let backend = CountingBackend::default();
    let observed_backend = backend.clone();
    let supervisor = Arc::new(SandboxSupervisor::new(
        SupervisorConfig::new(Duration::from_millis(100), Duration::from_secs(1))
            .expect("supervisor config is valid"),
        backend,
    ));
    let rpc_config = SandboxRpcConfig::new(
        8 * 1024,
        2,
        Duration::from_millis(200),
        Duration::from_millis(5),
        Some(nix::unistd::Uid::effective().as_raw()),
    )
    .expect("RPC config is valid");
    let server = SandboxRpcServer::new(supervisor, rpc_config);
    let server_shutdown = shutdown.clone();
    let task = tokio::spawn(async move { server.serve(listener, server_shutdown).await });

    let spec = launch_spec(ShardId::new(), worker(), 7);
    let mut excessive_ttl =
        serde_json::to_value(spec.dedicated_egress()).expect("egress spec serializes");
    excessive_ttl["initial_lease_ttl_ms"] = json!(300_001);
    let mut uninitialized_digest =
        serde_json::to_value(spec.dedicated_egress()).expect("egress spec serializes");
    uninitialized_digest["policy_binding"]["snapshot_digest"] =
        serde_json::to_value([0_u8; 32]).expect("zero digest serializes");
    let conflicting_requests = [
        (
            json!({
                "operation": "create_shard",
                "shard_id": ShardId::new(),
                "worker_id": spec.worker_id(),
                "worker_epoch": spec.worker_epoch(),
                "tenant_id": spec.tenant_id(),
                "dedicated_egress": spec.dedicated_egress(),
                "lease_ttl_ms": 80
            }),
            RpcFailureCode::LaunchFenceMismatch,
        ),
        (
            json!({
                "operation": "create_shard",
                "shard_id": spec.shard_id(),
                "worker_id": WorkerId::new("conflicting-worker").expect("worker ID is valid"),
                "worker_epoch": spec.worker_epoch(),
                "tenant_id": spec.tenant_id(),
                "dedicated_egress": spec.dedicated_egress(),
                "lease_ttl_ms": 80
            }),
            RpcFailureCode::LaunchFenceMismatch,
        ),
        (
            json!({
                "operation": "create_shard",
                "shard_id": spec.shard_id(),
                "worker_id": spec.worker_id(),
                "worker_epoch": spec.worker_epoch() + 1,
                "tenant_id": spec.tenant_id(),
                "dedicated_egress": spec.dedicated_egress(),
                "lease_ttl_ms": 80
            }),
            RpcFailureCode::LaunchFenceMismatch,
        ),
        (
            json!({
                "operation": "create_shard",
                "shard_id": spec.shard_id(),
                "worker_id": spec.worker_id(),
                "worker_epoch": spec.worker_epoch(),
                "tenant_id": spec.tenant_id(),
                "dedicated_egress": excessive_ttl,
                "lease_ttl_ms": 80
            }),
            RpcFailureCode::InvalidLease,
        ),
        (
            json!({
                "operation": "create_shard",
                "shard_id": spec.shard_id(),
                "worker_id": spec.worker_id(),
                "worker_epoch": spec.worker_epoch(),
                "tenant_id": spec.tenant_id(),
                "dedicated_egress": uninitialized_digest,
                "lease_ttl_ms": 80
            }),
            RpcFailureCode::InvalidEgressPolicyBinding,
        ),
    ];
    for (conflicting_request, expected_code) in conflicting_requests {
        let mut stream = UnixStream::connect(&socket)
            .await
            .expect("raw client connects");
        let request = serde_json::to_vec(&conflicting_request).expect("request serializes");
        let request_length = u32::try_from(request.len())
            .expect("request fits a frame")
            .to_be_bytes();
        stream
            .write_all(&request_length)
            .await
            .expect("request length writes");
        stream
            .write_all(&request)
            .await
            .expect("request body writes");
        let mut response_length = [0_u8; 4];
        stream
            .read_exact(&mut response_length)
            .await
            .expect("response length reads");
        let mut response = vec![0_u8; u32::from_be_bytes(response_length) as usize];
        stream
            .read_exact(&mut response)
            .await
            .expect("response body reads");
        let response: serde_json::Value =
            serde_json::from_slice(&response).expect("response is JSON");

        assert_eq!(response["status"], "failure");
        assert_eq!(response["value"]["code"], json!(expected_code));
    }
    assert_eq!(observed_backend.provisions.load(Ordering::Acquire), 0);

    shutdown.cancel();
    assert!(matches!(task.await, Ok(Ok(()))));
}
