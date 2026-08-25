#![allow(clippy::expect_used)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use browserd_core::{ShardId, WorkerId};
use browserd_sandbox::{
    CleanupReason, CreateShardOutcome, InspectResources, KillShardOutcome, LaunchSpec,
    RenewLeaseError, SandboxBackend, SandboxCapabilities, SandboxError, SandboxHandle,
    SandboxSupervisor, SupervisorConfig, WorkerOwnership,
};
use tokio::sync::Notify;
use tokio::time::Instant;

#[derive(Clone)]
struct GatedBackend {
    provision_started: Arc<Notify>,
    allow_provision: Arc<Notify>,
    events: Arc<Mutex<Vec<&'static str>>>,
    fail_revoke: bool,
    fail_kill: bool,
    fail_cleanup: bool,
}

#[async_trait]
impl SandboxBackend for GatedBackend {
    fn capabilities(&self) -> SandboxCapabilities {
        SandboxCapabilities::production_required()
    }

    async fn provision(&self, spec: &LaunchSpec) -> Result<SandboxHandle, SandboxError> {
        self.events
            .lock()
            .expect("event lock should work")
            .push("provision");
        self.provision_started.notify_one();
        self.allow_provision.notified().await;
        Ok(SandboxHandle::new(spec.shard_id().clone(), "gated"))
    }

    async fn revoke_egress(
        &self,
        _handle: &SandboxHandle,
        _reason: CleanupReason,
    ) -> Result<(), SandboxError> {
        self.events
            .lock()
            .expect("event lock should work")
            .push("revoke");
        if self.fail_revoke {
            return Err(SandboxError::Backend("injected revoke failure".into()));
        }
        Ok(())
    }

    async fn kill_cgroup(
        &self,
        _handle: &SandboxHandle,
        _reason: CleanupReason,
    ) -> Result<(), SandboxError> {
        self.events
            .lock()
            .expect("event lock should work")
            .push("kill");
        if self.fail_kill {
            return Err(SandboxError::Backend("injected kill failure".into()));
        }
        Ok(())
    }

    async fn cleanup_namespaces(&self, _handle: &SandboxHandle) -> Result<(), SandboxError> {
        self.events
            .lock()
            .expect("event lock should work")
            .push("cleanup");
        if self.fail_cleanup {
            return Err(SandboxError::Backend("injected cleanup failure".into()));
        }
        Ok(())
    }

    async fn inspect(&self, _handle: &SandboxHandle) -> Result<InspectResources, SandboxError> {
        Err(SandboxError::Backend("not used".into()))
    }
}

fn worker() -> WorkerId {
    WorkerId::new("race-worker").expect("worker should be valid")
}

#[tokio::test]
async fn kill_and_renew_during_provision_are_fenced_and_cannot_resurrect_shard() {
    let backend = GatedBackend {
        provision_started: Arc::new(Notify::new()),
        allow_provision: Arc::new(Notify::new()),
        events: Arc::new(Mutex::new(Vec::new())),
        fail_revoke: false,
        fail_kill: false,
        fail_cleanup: false,
    };
    let supervisor = Arc::new(SandboxSupervisor::new(
        SupervisorConfig::new(Duration::from_secs(10), Duration::from_secs(30))
            .expect("config should work"),
        backend.clone(),
    ));
    let shard_id = ShardId::new();
    let now = Instant::now();
    let create = {
        let supervisor = supervisor.clone();
        let shard_id = shard_id.clone();
        tokio::spawn(async move {
            supervisor
                .create_shard(
                    LaunchSpec::production(shard_id, worker(), 7),
                    WorkerOwnership::new(worker(), 7, now + Duration::from_secs(10)),
                )
                .await
        })
    };
    backend.provision_started.notified().await;

    supervisor
        .renew_owner_lease(
            &shard_id,
            7,
            now + Duration::from_secs(1),
            now + Duration::from_secs(9),
        )
        .await
        .expect("provisioning lease should renew");
    assert_eq!(
        supervisor
            .kill_shard(&shard_id, 7, CleanupReason::Administrative)
            .await,
        Ok(KillShardOutcome::CancellationRequested)
    );
    assert_eq!(
        supervisor
            .renew_owner_lease(
                &shard_id,
                7,
                now + Duration::from_secs(2),
                now + Duration::from_secs(9),
            )
            .await,
        Err(RenewLeaseError::ShardNotFound)
    );
    backend.allow_provision.notify_one();
    assert_eq!(
        create
            .await
            .expect("create task should not panic")
            .expect("cancellation cleanup should complete"),
        CreateShardOutcome::Cancelled
    );
    assert_eq!(
        backend
            .events
            .lock()
            .expect("event lock should work")
            .as_slice(),
        ["provision", "revoke", "kill", "cleanup"]
    );
    assert_eq!(
        supervisor
            .kill_shard(&shard_id, 7, CleanupReason::Administrative)
            .await,
        Ok(KillShardOutcome::AlreadyTerminated)
    );
}

#[tokio::test]
async fn cancellation_or_expiry_during_provision_surfaces_incomplete_cleanup() {
    for expire in [false, true] {
        let backend = GatedBackend {
            provision_started: Arc::new(Notify::new()),
            allow_provision: Arc::new(Notify::new()),
            events: Arc::new(Mutex::new(Vec::new())),
            fail_revoke: true,
            fail_kill: false,
            fail_cleanup: false,
        };
        let supervisor = Arc::new(SandboxSupervisor::new(
            SupervisorConfig::new(Duration::from_secs(10), Duration::from_secs(30))
                .expect("config should work"),
            backend.clone(),
        ));
        let shard_id = ShardId::new();
        let now = Instant::now();
        let create = {
            let supervisor = supervisor.clone();
            let shard_id = shard_id.clone();
            tokio::spawn(async move {
                supervisor
                    .create_shard(
                        LaunchSpec::production(shard_id, worker(), 7),
                        WorkerOwnership::new(worker(), 7, now + Duration::from_secs(10)),
                    )
                    .await
            })
        };
        backend.provision_started.notified().await;

        if expire {
            assert!(
                supervisor
                    .expire_leases(now + Duration::from_secs(11))
                    .await
                    .is_empty()
            );
        } else {
            assert_eq!(
                supervisor
                    .kill_shard(&shard_id, 7, CleanupReason::Administrative)
                    .await,
                Ok(KillShardOutcome::CancellationRequested)
            );
        }
        backend.allow_provision.notify_one();
        let error = create
            .await
            .expect("create task should not panic")
            .expect_err("incomplete cancellation cleanup must be surfaced");
        assert!(error.to_string().contains("incomplete cleanup"));
        assert_eq!(
            backend
                .events
                .lock()
                .expect("event lock should work")
                .as_slice(),
            ["provision", "revoke", "kill", "cleanup"]
        );
    }
}

#[tokio::test]
async fn concurrent_renew_and_duplicate_kill_have_one_cleanup_owner() {
    let backend = GatedBackend {
        provision_started: Arc::new(Notify::new()),
        allow_provision: Arc::new(Notify::new()),
        events: Arc::new(Mutex::new(Vec::new())),
        fail_revoke: false,
        fail_kill: false,
        fail_cleanup: false,
    };
    backend.allow_provision.notify_one();
    let supervisor = Arc::new(SandboxSupervisor::new(
        SupervisorConfig::new(Duration::from_secs(10), Duration::from_secs(30))
            .expect("config should work"),
        backend.clone(),
    ));
    let shard_id = ShardId::new();
    let now = Instant::now();
    supervisor
        .create_shard(
            LaunchSpec::production(shard_id.clone(), worker(), 7),
            WorkerOwnership::new(worker(), 7, now + Duration::from_secs(10)),
        )
        .await
        .expect("shard should provision");
    let start = Arc::new(tokio::sync::Barrier::new(4));
    let renew = {
        let supervisor = supervisor.clone();
        let shard_id = shard_id.clone();
        let start = start.clone();
        tokio::spawn(async move {
            start.wait().await;
            supervisor
                .renew_owner_lease(
                    &shard_id,
                    7,
                    now + Duration::from_secs(1),
                    now + Duration::from_secs(9),
                )
                .await
        })
    };
    let mut kills = Vec::new();
    for _ in 0..2 {
        let supervisor = supervisor.clone();
        let shard_id = shard_id.clone();
        let start = start.clone();
        kills.push(tokio::spawn(async move {
            start.wait().await;
            supervisor
                .kill_shard(&shard_id, 7, CleanupReason::Administrative)
                .await
        }));
    }
    start.wait().await;

    let renew = renew.await.expect("renew task should not panic");
    assert!(
        renew.is_ok() || matches!(renew, Err(browserd_sandbox::RenewLeaseError::ShardNotFound))
    );
    let mut outcomes = Vec::new();
    for kill in kills {
        outcomes.push(
            kill.await
                .expect("kill task should not panic")
                .expect("kill should be fenced"),
        );
    }
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, KillShardOutcome::Terminated(_)))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == KillShardOutcome::AlreadyTerminated)
            .count(),
        1
    );
    let events = backend.events.lock().expect("event lock should work");
    assert_eq!(events.iter().filter(|event| **event == "revoke").count(), 1);
    assert_eq!(events.iter().filter(|event| **event == "kill").count(), 1);
    assert_eq!(
        events.iter().filter(|event| **event == "cleanup").count(),
        1
    );
}
