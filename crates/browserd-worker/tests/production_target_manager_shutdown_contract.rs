#![allow(clippy::expect_used)]

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use browserd_core::{LaunchGeneration, OwnerFence, ShardFence, ShardId, WorkerEpoch, WorkerId};
use browserd_targets::{
    BootstrapBackend, BootstrapStage, BootstrapStageFailure, PausedTarget, ShardTaintReason,
    TargetKind,
};
use browserd_worker::{
    ProductionTargetManager, ShardRuntimeError, TargetBootstrapSnapshot, TargetManagerBackend,
    TargetManagerDrain, TargetManagerEvent, TargetManagerIngressError,
};

struct CallbackGate {
    entered: AtomicBool,
    released: Mutex<bool>,
    changed: Condvar,
}

struct Backend {
    snapshot: Option<TargetBootstrapSnapshot>,
    callback_targets: Arc<Mutex<Vec<String>>>,
    callback_gate: Arc<CallbackGate>,
}

impl BootstrapBackend for Backend {
    fn run_stage(
        &mut self,
        target: &PausedTarget,
        _stage: BootstrapStage,
    ) -> Result<(), BootstrapStageFailure> {
        self.callback_targets
            .lock()
            .expect("callback target registry should remain available")
            .push(target.target_id().to_owned());
        if target.target_id() == "in-flight"
            && !self.callback_gate.entered.swap(true, Ordering::SeqCst)
        {
            let released = self
                .callback_gate
                .released
                .lock()
                .expect("callback gate should remain available");
            let _released = self
                .callback_gate
                .changed
                .wait_while(released, |released| !*released)
                .expect("callback gate should remain available while blocked");
        }
        Ok(())
    }

    fn close_paused_target(&mut self, _target: &PausedTarget) {}

    fn taint_shard(&mut self, _reason: ShardTaintReason) {}
}

impl TargetManagerBackend for Backend {
    fn enable_auto_attach_and_snapshot(
        &mut self,
    ) -> Result<TargetBootstrapSnapshot, ShardRuntimeError> {
        self.snapshot
            .take()
            .ok_or(ShardRuntimeError::OutcomeUncertain)
    }
}

struct DrainCounter(AtomicUsize);

impl TargetManagerDrain for DrainCounter {
    fn begin_drain(&self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn explicit_shutdown_cancels_drains_and_joins_the_event_pump_exactly_once() {
    let callback_targets = Arc::new(Mutex::new(Vec::new()));
    let callback_gate = Arc::new(CallbackGate {
        entered: AtomicBool::new(false),
        released: Mutex::new(false),
        changed: Condvar::new(),
    });
    let drain = Arc::new(DrainCounter(AtomicUsize::new(0)));
    let snapshot = TargetBootstrapSnapshot::new(Vec::new(), Vec::new())
        .expect("empty target bootstrap snapshot should be valid");
    let backend = Backend {
        snapshot: Some(snapshot),
        callback_targets: Arc::clone(&callback_targets),
        callback_gate: Arc::clone(&callback_gate),
    };
    let fence = ShardFence::new(
        OwnerFence::new(
            WorkerId::new("target-shutdown-worker")
                .expect("shutdown worker identity should be valid"),
            WorkerEpoch::new(1).expect("shutdown worker epoch should be valid"),
        ),
        ShardId::new(),
        LaunchGeneration::new(1).expect("shutdown launch generation should be valid"),
    );
    let (manager, ingress) =
        ProductionTargetManager::new_bounded(fence, backend, 4, Arc::clone(&drain))
            .expect("bounded target manager should be valid");
    manager
        .bootstrap()
        .await
        .expect("empty bootstrap should start the event pump");

    ingress
        .try_send(TargetManagerEvent::Attached(PausedTarget::new(
            "in-flight",
            TargetKind::Page,
        )))
        .expect("the in-flight event should enter the bounded pump");
    tokio::time::timeout(Duration::from_secs(1), async {
        while !callback_gate.entered.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the first event callback should become in flight");
    ingress
        .try_send(TargetManagerEvent::Attached(PausedTarget::new(
            "must-not-run",
            TargetKind::Page,
        )))
        .expect("the post-cancellation candidate should be queued before shutdown");

    let mut shutdown = Box::pin(manager.shutdown());
    assert!(
        tokio::time::timeout(Duration::from_millis(50), &mut shutdown)
            .await
            .is_err(),
        "shutdown returned without joining its in-flight callback"
    );
    {
        let mut released = callback_gate
            .released
            .lock()
            .expect("callback gate should remain available for release");
        *released = true;
    }
    callback_gate.changed.notify_all();

    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), &mut shutdown)
            .await
            .expect("event-pump shutdown should be bounded after the callback exits"),
        Ok(())
    );
    assert!(!manager.is_ready());
    assert_eq!(drain.0.load(Ordering::SeqCst), 1);

    assert_eq!(
        tokio::time::timeout(Duration::from_millis(100), manager.shutdown())
            .await
            .expect("repeated event-pump shutdown should be bounded"),
        Ok(())
    );
    assert_eq!(drain.0.load(Ordering::SeqCst), 1);
    assert_eq!(
        ingress.try_send(TargetManagerEvent::Attached(PausedTarget::new(
            "after-shutdown",
            TargetKind::Page,
        ))),
        Err(TargetManagerIngressError::Closed)
    );
    tokio::time::sleep(Duration::from_millis(50)).await;
    let callbacks = callback_targets
        .lock()
        .expect("callback target registry should remain available");
    assert!(callbacks.iter().any(|target| target == "in-flight"));
    assert!(!callbacks.iter().any(|target| target == "must-not-run"));
    assert!(!callbacks.iter().any(|target| target == "after-shutdown"));
}
