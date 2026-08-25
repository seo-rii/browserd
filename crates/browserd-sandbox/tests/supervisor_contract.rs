#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use browserd_core::{ShardId, WorkerId};
use browserd_sandbox::{
    CleanupReason, CleanupResult, CreateShardOutcome, InspectResources, KillShardOutcome,
    LaunchSpec, RenewLeaseError, SandboxBackend, SandboxCapabilities, SandboxError, SandboxHandle,
    SandboxSupervisor, SupervisorConfig, WorkerOwnership,
};
use tokio::time::Instant;

#[derive(Clone)]
struct RecordingBackend {
    capabilities: SandboxCapabilities,
    events: Arc<Mutex<Vec<String>>>,
    fail_revoke: bool,
}

impl RecordingBackend {
    fn production_capable() -> Self {
        Self {
            capabilities: SandboxCapabilities::production_required(),
            events: Arc::new(Mutex::new(Vec::new())),
            fail_revoke: false,
        }
    }

    fn events(&self) -> Vec<String> {
        self.events.lock().unwrap().clone()
    }

    fn record(&self, event: &str) {
        self.events.lock().unwrap().push(event.to_owned());
    }
}

#[async_trait]
impl SandboxBackend for RecordingBackend {
    fn capabilities(&self) -> SandboxCapabilities {
        self.capabilities
    }

    async fn provision(&self, spec: &LaunchSpec) -> Result<SandboxHandle, SandboxError> {
        self.record("provision");
        Ok(SandboxHandle::new(
            spec.shard_id().clone(),
            "backend-handle",
        ))
    }

    async fn revoke_egress(
        &self,
        _handle: &SandboxHandle,
        _reason: CleanupReason,
    ) -> Result<(), SandboxError> {
        self.record("revoke_egress");
        if self.fail_revoke {
            Err(SandboxError::Backend("route revoke failed".to_owned()))
        } else {
            Ok(())
        }
    }

    async fn kill_cgroup(
        &self,
        _handle: &SandboxHandle,
        _reason: CleanupReason,
    ) -> Result<(), SandboxError> {
        self.record("kill_cgroup");
        Ok(())
    }

    async fn cleanup_namespaces(&self, _handle: &SandboxHandle) -> Result<(), SandboxError> {
        self.record("cleanup_namespaces");
        Ok(())
    }

    async fn inspect(&self, _handle: &SandboxHandle) -> Result<InspectResources, SandboxError> {
        Ok(InspectResources {
            memory_current_bytes: 123,
            memory_peak_bytes: 456,
            process_count: 7,
            egress_route_active: true,
        })
    }
}

fn worker() -> WorkerId {
    WorkerId::new("worker-apne2-a-001").expect("test worker ID must be valid")
}

fn config() -> SupervisorConfig {
    SupervisorConfig::new(Duration::from_secs(10), Duration::from_secs(30))
        .expect("lease ordering must be valid")
}

fn launch_spec(shard_id: ShardId) -> LaunchSpec {
    LaunchSpec::production(shard_id, worker(), 17)
}

#[test]
fn supervisor_lease_must_not_outlive_directory_lease() {
    assert!(SupervisorConfig::new(Duration::from_secs(10), Duration::from_secs(30)).is_ok());
    assert!(SupervisorConfig::new(Duration::from_secs(30), Duration::from_secs(30)).is_ok());
    assert!(matches!(
        SupervisorConfig::new(Duration::from_secs(31), Duration::from_secs(30)),
        Err(SandboxError::InvalidLeaseOrdering)
    ));
    assert!(matches!(
        SupervisorConfig::new(Duration::ZERO, Duration::from_secs(30)),
        Err(SandboxError::ZeroLeaseTtl)
    ));
}

#[tokio::test]
async fn production_creation_fails_closed_when_any_required_capability_is_missing() {
    for capability in SandboxCapabilities::REQUIRED_NAMES {
        let mut capabilities = SandboxCapabilities::production_required();
        capabilities.disable(capability);
        let backend = RecordingBackend {
            capabilities,
            events: Arc::new(Mutex::new(Vec::new())),
            fail_revoke: false,
        };
        let supervisor = SandboxSupervisor::new(config(), backend.clone());
        let shard_id = ShardId::new();
        let result = supervisor
            .create_shard(
                launch_spec(shard_id),
                WorkerOwnership::new(worker(), 17, Instant::now() + Duration::from_secs(10)),
            )
            .await;

        assert!(matches!(
            result,
            Err(SandboxError::MissingCapability { name }) if name == capability
        ));
        assert!(backend.events().is_empty());
    }
}

#[tokio::test]
async fn stale_worker_epoch_cannot_renew_or_control_a_shard() {
    let backend = RecordingBackend::production_capable();
    let supervisor = SandboxSupervisor::new(config(), backend);
    let shard_id = ShardId::new();
    let now = Instant::now();
    supervisor
        .create_shard(
            launch_spec(shard_id.clone()),
            WorkerOwnership::new(worker(), 17, now + Duration::from_secs(10)),
        )
        .await
        .expect("sandbox creation must succeed");

    assert_eq!(
        supervisor
            .renew_owner_lease(
                &shard_id,
                16,
                now + Duration::from_secs(5),
                now + Duration::from_secs(15)
            )
            .await,
        Err(RenewLeaseError::WorkerEpochMismatch {
            expected: 17,
            actual: 16,
        })
    );
    assert!(
        supervisor
            .renew_owner_lease(
                &shard_id,
                17,
                now + Duration::from_secs(5),
                now + Duration::from_secs(15)
            )
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn lease_expiry_revokes_egress_before_killing_and_cleaning_the_shard() {
    let backend = RecordingBackend::production_capable();
    let supervisor = SandboxSupervisor::new(config(), backend.clone());
    let shard_id = ShardId::new();
    let now = Instant::now();
    assert_eq!(
        supervisor
            .create_shard(
                launch_spec(shard_id.clone()),
                WorkerOwnership::new(worker(), 17, now + Duration::from_secs(10)),
            )
            .await,
        Ok(CreateShardOutcome::Created)
    );

    let before = supervisor.expire_leases(now + Duration::from_secs(9)).await;
    assert!(before.is_empty());
    let expired = supervisor
        .expire_leases(now + Duration::from_secs(10))
        .await;
    assert_eq!(
        expired,
        vec![(
            shard_id,
            CleanupResult {
                route_revoked: true,
                cgroup_killed: true,
                namespaces_cleaned: true,
            }
        )]
    );
    assert_eq!(
        backend.events(),
        [
            "provision",
            "revoke_egress",
            "kill_cgroup",
            "cleanup_namespaces"
        ]
    );
}

#[tokio::test]
async fn cleanup_continues_to_kill_when_route_revocation_reports_failure() {
    let backend = RecordingBackend {
        fail_revoke: true,
        ..RecordingBackend::production_capable()
    };
    let supervisor = SandboxSupervisor::new(config(), backend.clone());
    let shard_id = ShardId::new();
    let now = Instant::now();
    supervisor
        .create_shard(
            launch_spec(shard_id.clone()),
            WorkerOwnership::new(worker(), 17, now + Duration::from_secs(10)),
        )
        .await
        .expect("sandbox creation must succeed");

    assert_eq!(
        supervisor
            .kill_shard(&shard_id, 17, CleanupReason::SecurityViolation)
            .await
            .expect("cleanup must return its partial result"),
        KillShardOutcome::Terminated(CleanupResult {
            route_revoked: false,
            cgroup_killed: true,
            namespaces_cleaned: true,
        })
    );
    assert_eq!(
        backend.events(),
        [
            "provision",
            "revoke_egress",
            "kill_cgroup",
            "cleanup_namespaces"
        ]
    );
}

#[tokio::test]
async fn explicit_kill_is_idempotent_and_resource_inspection_is_fenced() {
    let backend = RecordingBackend::production_capable();
    let supervisor = SandboxSupervisor::new(config(), backend.clone());
    let shard_id = ShardId::new();
    let now = Instant::now();
    supervisor
        .create_shard(
            launch_spec(shard_id.clone()),
            WorkerOwnership::new(worker(), 17, now + Duration::from_secs(10)),
        )
        .await
        .expect("sandbox creation must succeed");

    assert_eq!(
        supervisor.inspect_resources(&shard_id, 17).await,
        Ok(InspectResources {
            memory_current_bytes: 123,
            memory_peak_bytes: 456,
            process_count: 7,
            egress_route_active: true,
        })
    );
    assert!(matches!(
        supervisor.inspect_resources(&shard_id, 18).await,
        Err(SandboxError::WorkerEpochMismatch { .. })
    ));

    let first = supervisor
        .kill_shard(&shard_id, 17, CleanupReason::Administrative)
        .await;
    assert!(matches!(first, Ok(KillShardOutcome::Terminated(_))));
    let second = supervisor
        .kill_shard(&shard_id, 17, CleanupReason::Administrative)
        .await;
    assert_eq!(second, Ok(KillShardOutcome::AlreadyTerminated));
    assert_eq!(
        backend
            .events()
            .iter()
            .filter(|event| event.as_str() == "kill_cgroup")
            .count(),
        1
    );
}
