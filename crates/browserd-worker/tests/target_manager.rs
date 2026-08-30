#![allow(clippy::unwrap_used)]

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use browserd_core::{
    LaunchGeneration, OwnerFence, SessionId, ShardFence, ShardId, TenantId, WorkerEpoch, WorkerId,
};
use browserd_session::OwnershipFence;
use browserd_targets::{
    BootstrapBackend, BootstrapStage, BootstrapStageFailure, PausedTarget, ShardTaintReason,
    TargetKind,
};
use browserd_worker::{
    BrowserShardRuntime, ProductionTargetManager, ShardRuntimeError, TargetBootstrapSnapshot,
    TargetManagedShardRuntime, TargetManagerBackend, TargetManagerDrain, TargetManagerEvent,
    TargetManagerIngressError,
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

struct Backend {
    snapshot: Mutex<Option<TargetBootstrapSnapshot>>,
    stages: Mutex<Vec<(String, BootstrapStage)>>,
    fail_resume: bool,
}

#[test]
fn full_manager_owned_ingress_taints_and_drains_without_enqueuing_overflow() {
    let snapshot = TargetBootstrapSnapshot::new(vec![], vec![]).unwrap();
    let backend = Backend {
        snapshot: Mutex::new(Some(snapshot)),
        stages: Mutex::new(Vec::new()),
        fail_resume: false,
    };
    let drain = Arc::new(Drain(AtomicBool::new(false)));
    let (manager, ingress) =
        ProductionTargetManager::new_bounded(fence(), backend, 1, drain.clone()).unwrap();
    assert_eq!(
        ingress.try_send(TargetManagerEvent::Attached(PausedTarget::new(
            "first",
            TargetKind::Page,
        ))),
        Ok(())
    );
    assert_eq!(
        ingress.try_send(TargetManagerEvent::Attached(PausedTarget::new(
            "overflow",
            TargetKind::Page,
        ))),
        Err(TargetManagerIngressError::Overflow)
    );
    assert!(manager.is_tainted());
    assert!(drain.0.load(Ordering::SeqCst));
}

impl BootstrapBackend for Backend {
    fn run_stage(
        &mut self,
        target: &PausedTarget,
        stage: BootstrapStage,
    ) -> Result<(), BootstrapStageFailure> {
        self.stages
            .lock()
            .unwrap()
            .push((target.target_id().to_owned(), stage));
        if self.fail_resume && stage == BootstrapStage::Resume {
            Err(BootstrapStageFailure::StateOverflow)
        } else {
            Ok(())
        }
    }
    fn close_paused_target(&mut self, _target: &PausedTarget) {}
    fn taint_shard(&mut self, _reason: ShardTaintReason) {}
}

impl TargetManagerBackend for Backend {
    fn enable_auto_attach_and_snapshot(
        &mut self,
    ) -> Result<TargetBootstrapSnapshot, browserd_worker::ShardRuntimeError> {
        self.snapshot
            .lock()
            .unwrap()
            .take()
            .ok_or(browserd_worker::ShardRuntimeError::OutcomeUncertain)
    }
}

struct Drain(AtomicBool);
impl TargetManagerDrain for Drain {
    fn begin_drain(&self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

#[derive(Default)]
struct OwnershipForwardingRuntime {
    owned_creates: Mutex<Vec<(TenantId, SessionId, OwnershipFence)>>,
    unfenced_creates: AtomicUsize,
}

#[async_trait::async_trait]
impl BrowserShardRuntime for OwnershipForwardingRuntime {
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
        self.unfenced_creates.fetch_add(1, Ordering::SeqCst);
        Err(ShardRuntimeError::Rejected)
    }

    async fn create_context_owned(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        fence: &OwnershipFence,
        _cancellation: CancellationToken,
    ) -> Result<(), ShardRuntimeError> {
        self.owned_creates
            .lock()
            .map_err(|_| ShardRuntimeError::Unavailable)?
            .push((tenant_id.clone(), session_id.clone(), fence.clone()));
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

fn fence() -> ShardFence {
    ShardFence::new(
        OwnerFence::new(
            WorkerId::new("target-worker").unwrap(),
            WorkerEpoch::new(9).unwrap(),
        ),
        ShardId::new(),
        LaunchGeneration::new(1).unwrap(),
    )
}

#[tokio::test]
async fn target_managed_runtime_preserves_owned_context_tenant_and_full_fence() {
    let snapshot = TargetBootstrapSnapshot::new(vec![], vec![]).unwrap();
    let backend = Backend {
        snapshot: Mutex::new(Some(snapshot)),
        stages: Mutex::new(Vec::new()),
        fail_resume: false,
    };
    let drain = Arc::new(Drain(AtomicBool::new(false)));
    let (manager, _ingress) =
        ProductionTargetManager::new_bounded(fence(), backend, 2, drain).unwrap();
    assert_eq!(manager.bootstrap().await, Ok(()));
    let inner = Arc::new(OwnershipForwardingRuntime::default());
    let runtime = TargetManagedShardRuntime::new(Arc::clone(&inner), Arc::new(manager));
    let tenant_id = TenantId::new();
    let session_id = SessionId::new();
    let ownership = OwnershipFence::new(WorkerId::new("target-worker").unwrap(), 9, 41, 7);

    let result = runtime
        .create_context_owned(
            &tenant_id,
            &session_id,
            &ownership,
            CancellationToken::new(),
        )
        .await;

    assert_eq!(result, Ok(()));
    assert_eq!(inner.unfenced_creates.load(Ordering::SeqCst), 0);
    assert_eq!(
        inner.owned_creates.lock().ok().map(|calls| calls.clone()),
        Some(vec![(tenant_id, session_id, ownership)])
    );
}

#[tokio::test]
async fn snapshot_and_catch_up_targets_are_bootstrapped_before_ready() {
    let snapshot = TargetBootstrapSnapshot::new(
        vec![PausedTarget::new("initial", TargetKind::Page)],
        vec![PausedTarget::new("catch-up", TargetKind::DedicatedWorker)],
    )
    .unwrap();
    let backend = Backend {
        snapshot: Mutex::new(Some(snapshot)),
        stages: Mutex::new(Vec::new()),
        fail_resume: false,
    };
    let (_tx, rx) = mpsc::channel(2);
    let drain = Arc::new(Drain(AtomicBool::new(false)));
    let manager = ProductionTargetManager::new(fence(), backend, rx, drain.clone()).unwrap();
    assert_eq!(manager.bootstrap().await, Ok(()));
    assert!(manager.is_ready());
    assert_eq!(manager.ready_target_count(), 2);
    assert!(!drain.0.load(Ordering::SeqCst));
}

#[tokio::test]
async fn event_overflow_taints_and_drains_a_ready_shard() {
    let snapshot = TargetBootstrapSnapshot::new(vec![], vec![]).unwrap();
    let backend = Backend {
        snapshot: Mutex::new(Some(snapshot)),
        stages: Mutex::new(Vec::new()),
        fail_resume: false,
    };
    let (tx, rx) = mpsc::channel(1);
    let drain = Arc::new(Drain(AtomicBool::new(false)));
    let manager = ProductionTargetManager::new(fence(), backend, rx, drain.clone()).unwrap();
    assert_eq!(manager.bootstrap().await, Ok(()));
    tx.send(TargetManagerEvent::Overflow).await.unwrap();
    tokio::task::yield_now().await;
    assert!(manager.is_tainted());
    assert!(drain.0.load(Ordering::SeqCst));
}

#[tokio::test]
async fn bootstrap_response_loss_never_becomes_ready() {
    let snapshot =
        TargetBootstrapSnapshot::new(vec![PausedTarget::new("lost", TargetKind::Page)], vec![])
            .unwrap();
    let backend = Backend {
        snapshot: Mutex::new(Some(snapshot)),
        stages: Mutex::new(Vec::new()),
        fail_resume: true,
    };
    let (_tx, rx) = mpsc::channel(1);
    let drain = Arc::new(Drain(AtomicBool::new(false)));
    let manager = ProductionTargetManager::new(fence(), backend, rx, drain.clone()).unwrap();
    assert_eq!(
        manager.bootstrap().await,
        Err(browserd_worker::ShardRuntimeError::OutcomeUncertain)
    );
    assert!(!manager.is_ready());
    assert!(manager.is_tainted());
    assert!(drain.0.load(Ordering::SeqCst));
}

#[tokio::test]
async fn exact_detach_removes_the_registered_target_without_draining() {
    let snapshot =
        TargetBootstrapSnapshot::new(vec![PausedTarget::new("live", TargetKind::Page)], vec![])
            .unwrap();
    let backend = Backend {
        snapshot: Mutex::new(Some(snapshot)),
        stages: Mutex::new(Vec::new()),
        fail_resume: false,
    };
    let drain = Arc::new(Drain(AtomicBool::new(false)));
    let (manager, ingress) =
        ProductionTargetManager::new_bounded(fence(), backend, 2, drain.clone()).unwrap();
    assert_eq!(manager.bootstrap().await, Ok(()));
    assert!(manager.has_ready_target("live"));

    ingress
        .try_send(TargetManagerEvent::Detached {
            target_id: "live".to_owned(),
        })
        .unwrap();
    let detached = tokio::time::timeout(std::time::Duration::from_millis(200), async {
        while manager.ready_target_count() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert!(
        detached.is_ok(),
        "the exact target must leave the ready registry"
    );

    assert!(!manager.has_ready_target("live"));
    assert!(manager.is_ready());
    assert!(!manager.is_tainted());
    assert!(!drain.0.load(Ordering::SeqCst));
}

#[tokio::test]
async fn duplicate_or_unknown_detach_is_fail_closed() {
    let snapshot =
        TargetBootstrapSnapshot::new(vec![PausedTarget::new("live", TargetKind::Page)], vec![])
            .unwrap();
    let backend = Backend {
        snapshot: Mutex::new(Some(snapshot)),
        stages: Mutex::new(Vec::new()),
        fail_resume: false,
    };
    let drain = Arc::new(Drain(AtomicBool::new(false)));
    let (manager, ingress) =
        ProductionTargetManager::new_bounded(fence(), backend, 2, drain.clone()).unwrap();
    assert_eq!(manager.bootstrap().await, Ok(()));

    ingress
        .try_send(TargetManagerEvent::Detached {
            target_id: "live".to_owned(),
        })
        .unwrap();
    ingress
        .try_send(TargetManagerEvent::Detached {
            target_id: "live".to_owned(),
        })
        .unwrap();
    let tainted = tokio::time::timeout(std::time::Duration::from_millis(200), async {
        while !manager.is_tainted() {
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert!(
        tainted.is_ok(),
        "a stale duplicate detach must taint the shard"
    );

    assert!(drain.0.load(Ordering::SeqCst));
}

#[tokio::test]
async fn attached_target_identity_cannot_replace_an_existing_registry_entry() {
    let snapshot =
        TargetBootstrapSnapshot::new(vec![PausedTarget::new("same", TargetKind::Page)], vec![])
            .unwrap();
    let backend = Backend {
        snapshot: Mutex::new(Some(snapshot)),
        stages: Mutex::new(Vec::new()),
        fail_resume: false,
    };
    let drain = Arc::new(Drain(AtomicBool::new(false)));
    let (manager, ingress) =
        ProductionTargetManager::new_bounded(fence(), backend, 2, drain.clone()).unwrap();
    assert_eq!(manager.bootstrap().await, Ok(()));

    ingress
        .try_send(TargetManagerEvent::Attached(PausedTarget::new(
            "same",
            TargetKind::Page,
        )))
        .unwrap();
    let tainted = tokio::time::timeout(std::time::Duration::from_millis(200), async {
        while !manager.is_tainted() {
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert!(
        tainted.is_ok(),
        "a duplicate attached identity must taint the shard"
    );

    assert!(drain.0.load(Ordering::SeqCst));
}
