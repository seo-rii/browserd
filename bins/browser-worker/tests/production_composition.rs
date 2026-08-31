#![allow(clippy::expect_used)]

use std::os::unix::fs::MetadataExt;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use browser_worker::{
    LifecycleBounds, ProductionWorkerRuntime, ProvisionedSessionShard, RoutedArtifactStore,
    SessionShardFactory, SessionShardLifecycle, SessionShardRouter,
};
use browserd_core::{OperationId, PageId, SessionId, TenantId, WorkerId};
use browserd_session::{LeasePolicy, OwnershipFence, SessionTimeoutPolicy};
use browserd_worker::{
    ActionJournalConfig, ArtifactStoreReceipt, ArtifactStoreRequest, AuthenticatedPeer,
    DependencyError, InternalEndpoint, UnavailableChromiumDriver, WorkerConfig, WorkerControlPlane,
    WorkerCreateSessionRequest, WorkerIsolationProfile, WorkerRpcClient, WorkerRpcConfig,
};
use tokio_util::sync::CancellationToken;

struct ShardLifecycle {
    terminations: Arc<AtomicUsize>,
}

impl SessionShardLifecycle for ShardLifecycle {
    fn qualify(&self) -> Result<(), DependencyError> {
        Ok(())
    }

    fn heartbeat(&self) -> Result<(), DependencyError> {
        Ok(())
    }

    fn terminate(&self, _fence: &OwnershipFence) -> Result<(), DependencyError> {
        self.terminations.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

struct ShardFactory {
    creations: AtomicUsize,
    terminations: Arc<AtomicUsize>,
}

impl SessionShardFactory for ShardFactory {
    fn qualify_daemon(&self) -> Result<(), DependencyError> {
        Ok(())
    }

    fn heartbeat_daemon(
        &self,
        _worker_id: &WorkerId,
        _worker_epoch: u64,
    ) -> Result<(), DependencyError> {
        Ok(())
    }

    fn create(
        &self,
        _tenant_id: &TenantId,
        _session_id: &SessionId,
        _fence: &OwnershipFence,
    ) -> Result<ProvisionedSessionShard, DependencyError> {
        self.creations.fetch_add(1, Ordering::SeqCst);
        Ok(ProvisionedSessionShard::new(
            PageId::new(),
            Arc::new(UnavailableChromiumDriver),
            Arc::new(ShardLifecycle {
                terminations: Arc::clone(&self.terminations),
            }),
        ))
    }
}

struct RejectArtifacts;

impl RoutedArtifactStore for RejectArtifacts {
    fn store(
        &self,
        _request: &ArtifactStoreRequest,
    ) -> Result<ArtifactStoreReceipt, DependencyError> {
        Err(DependencyError::Rejected)
    }
}

#[tokio::test]
async fn production_runtime_serves_the_real_control_plane_and_drains_owned_shards() {
    let directory = tempfile::tempdir().expect("temporary runtime directory should be available");
    let action_journal = directory.path().join("actions");
    std::fs::create_dir(&action_journal).expect("action journal directory should be created");
    let socket_path = directory.path().join("worker.sock");
    let worker_id = WorkerId::new("worker-production-composition")
        .expect("production worker identity should be valid");
    let peer = AuthenticatedPeer::new("gateway-production-composition")
        .expect("internal peer identity should be valid");
    let worker_epoch = 7;
    let max_sessions = 4;
    let worker_config = WorkerConfig::new(
        worker_id.clone(),
        worker_epoch,
        InternalEndpoint::unix(&socket_path).expect("worker endpoint should be valid"),
        peer.clone(),
        max_sessions,
        16,
        LeasePolicy::new(Duration::from_secs(15), Duration::from_secs(3))
            .expect("lease policy should be valid"),
        SessionTimeoutPolicy::new(Duration::from_secs(30 * 60), Duration::from_secs(10 * 60))
            .expect("session timeout policy should be valid"),
        Duration::from_secs(5 * 60),
        ActionJournalConfig::with_default_limits(action_journal)
            .expect("action journal should be valid"),
    )
    .expect("worker configuration should be valid");
    let terminations = Arc::new(AtomicUsize::new(0));
    let factory = Arc::new(ShardFactory {
        creations: AtomicUsize::new(0),
        terminations: Arc::clone(&terminations),
    });
    let router = Arc::new(
        SessionShardRouter::new(
            worker_id,
            worker_epoch,
            Arc::clone(&factory),
            Arc::new(RejectArtifacts),
            max_sessions,
        )
        .expect("session shard router should be valid"),
    );
    let worker = Arc::new(WorkerControlPlane::new(
        worker_config,
        Arc::clone(&router),
        Arc::clone(&router),
    ));
    let uid = std::fs::metadata("/proc/self")
        .expect("current process metadata should be available")
        .uid();
    let rpc_config = WorkerRpcConfig::new(
        &socket_path,
        128 * 1024,
        16,
        Duration::from_millis(500),
        Some(uid),
    )
    .expect("worker RPC configuration should be valid");
    let bounds = LifecycleBounds::new(
        Duration::from_millis(100),
        Duration::from_millis(100),
        Duration::from_secs(15),
        Duration::from_secs(2),
    )
    .expect("worker lifecycle bounds should be valid");
    let shutdown = CancellationToken::new();
    let runtime = ProductionWorkerRuntime::new(worker, peer, rpc_config, bounds)
        .expect("qualified production composition should start");
    let runtime_shutdown = shutdown.clone();
    let runtime_task = tokio::spawn(async move { runtime.serve(runtime_shutdown).await });
    let client = WorkerRpcClient::new(
        &socket_path,
        128 * 1024,
        Duration::from_millis(500),
        Some(uid),
    )
    .expect("worker RPC client should be valid");

    let probe = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Ok(receipt) = client.probe(worker_epoch).await {
                break receipt;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("production RPC socket should become ready");
    assert!(probe.ready);
    assert_eq!(probe.worker_epoch, worker_epoch);

    let now_unix_millis = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after the Unix epoch")
            .as_millis(),
    )
    .expect("current Unix time should fit in u64");
    let created = client
        .create_session(WorkerCreateSessionRequest {
            operation_id: OperationId::new(),
            tenant_id: TenantId::new(),
            idempotency_key: "production-composition-create".to_owned(),
            canonical_request_hash: [7; 32],
            expected_worker_epoch: worker_epoch,
            placement_version: 1,
            session_incarnation: 1,
            requested_isolation: WorkerIsolationProfile::SharedContext,
            now_unix_millis,
        })
        .await
        .expect("the real worker control plane should create a routed session");
    assert_eq!(created.worker_epoch, worker_epoch);
    assert_eq!(
        created.effective_isolation,
        WorkerIsolationProfile::DedicatedProcess
    );
    assert_eq!(factory.creations.load(Ordering::SeqCst), 1);

    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(3), runtime_task)
        .await
        .expect("production runtime shutdown should be bounded")
        .expect("production runtime task should not panic")
        .expect("production runtime should shut down cleanly");
    assert_eq!(terminations.load(Ordering::SeqCst), 1);
    assert!(
        !socket_path.exists(),
        "the runtime must release its Unix socket for a fenced worker restart"
    );
}
