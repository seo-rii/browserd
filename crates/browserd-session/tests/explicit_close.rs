use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::Duration;

use browserd_session::{
    CleanupBackend, CleanupFailure, CleanupStage, LeasePolicy, OwnershipFence, SessionError,
    SessionId, SessionLifecycle, SessionMachine, SessionTime, TargetId, WorkerId,
};

fn ready_session() -> Option<(SessionMachine, OwnershipFence)> {
    let policy = LeasePolicy::new(Duration::from_secs(10), Duration::from_secs(1)).ok()?;
    let worker = WorkerId::new("worker-close").ok()?;
    let (mut machine, fence) = SessionMachine::create(
        SessionId::new(),
        OwnershipFence::new(worker, 7, 3, 2),
        policy,
        SessionTime::new(0),
    );
    assert_eq!(
        machine.start(&fence, SessionTime::new(0)),
        Ok(SessionLifecycle::Creating)
    );
    assert_eq!(
        machine.mark_running(&fence, SessionTime::new(1)),
        Ok(SessionLifecycle::Ready)
    );
    Some((machine, fence))
}

#[derive(Default)]
struct SuccessfulCleanup;

impl CleanupBackend for SuccessfulCleanup {
    fn run_stage(
        &mut self,
        _stage: CleanupStage,
        _active_targets: &[TargetId],
    ) -> Result<(), CleanupFailure> {
        Ok(())
    }
}

#[test]
fn explicit_close_is_fenced_idempotent_and_only_cleanup_reaches_closed() {
    let Some((mut machine, fence)) = ready_session() else {
        return;
    };
    let stale = OwnershipFence::new(
        fence.worker_id().clone(),
        fence.worker_epoch(),
        fence.placement_version().saturating_add(1),
        fence.session_incarnation(),
    );
    assert!(matches!(
        machine.begin_close(&stale, SessionTime::new(2)),
        Err(SessionError::PlacementVersionMismatch { .. })
    ));
    assert_eq!(machine.lifecycle(), SessionLifecycle::Ready);

    assert_eq!(
        machine.begin_close(&fence, SessionTime::new(2)),
        Ok(SessionLifecycle::Closing)
    );
    assert_eq!(machine.lifecycle(), SessionLifecycle::Closing);
    assert!(!machine.accepting_targets());
    assert_eq!(
        machine.begin_close(&fence, SessionTime::new(3)),
        Ok(SessionLifecycle::Closing)
    );

    let mut cleanup = SuccessfulCleanup;
    assert!(machine.run_cleanup(&fence, &mut cleanup).is_ok());
    assert_eq!(machine.lifecycle(), SessionLifecycle::Closed);
    assert_eq!(
        machine.begin_close(&fence, SessionTime::new(4)),
        Ok(SessionLifecycle::Closed)
    );
}

#[test]
fn close_linearizes_against_action_and_control_mutations() {
    for _iteration in 0..50 {
        let Some((machine, fence)) = ready_session() else {
            return;
        };
        let shared = Arc::new(Mutex::new(machine));
        let barrier = Arc::new(Barrier::new(3));

        let close_shared = shared.clone();
        let close_barrier = barrier.clone();
        let close_fence = fence.clone();
        let close = thread::spawn(move || {
            close_barrier.wait();
            let Ok(mut machine) = close_shared.lock() else {
                return Err(SessionError::StateUnavailable);
            };
            machine.begin_close(&close_fence, SessionTime::new(2))
        });

        let action_shared = shared.clone();
        let action_barrier = barrier.clone();
        let action_fence = fence.clone();
        let action_id = browserd_session::ActionId::new();
        let action = thread::spawn(move || {
            action_barrier.wait();
            let Ok(mut machine) = action_shared.lock() else {
                return Err(SessionError::StateUnavailable);
            };
            machine.begin_action(&action_fence, action_id, SessionTime::new(2))
        });

        barrier.wait();
        let close_result = close.join();
        let action_result = action.join();
        assert!(close_result.is_ok());
        assert!(action_result.is_ok());
        let Some(close_result) = close_result.ok() else {
            return;
        };
        let Some(action_result) = action_result.ok() else {
            return;
        };
        assert_eq!(close_result, Ok(SessionLifecycle::Closing));
        assert!(
            action_result.is_ok()
                || matches!(
                    action_result,
                    Err(SessionError::InvalidTransition {
                        from: SessionLifecycle::Closing,
                        ..
                    })
                )
        );

        let Ok(mut machine) = shared.lock() else {
            return;
        };
        assert_eq!(machine.lifecycle(), SessionLifecycle::Closing);
        assert!(matches!(
            machine.acquire_human_control(&fence, SessionTime::new(3)),
            Err(SessionError::InvalidTransition {
                from: SessionLifecycle::Closing,
                ..
            })
        ));
    }
}

#[test]
fn creating_session_can_close_before_becoming_ready() {
    assert_eq!(SessionTime::new(7).get(), 7);
    let policy = LeasePolicy::new(Duration::from_secs(10), Duration::from_secs(1));
    assert!(policy.is_ok());
    let Some(policy) = policy.ok() else {
        return;
    };
    let worker = WorkerId::new("worker-close");
    assert!(worker.is_ok());
    let Some(worker) = worker.ok() else {
        return;
    };
    let (mut machine, fence) = SessionMachine::create(
        SessionId::new(),
        OwnershipFence::new(worker, 7, 3, 2),
        policy,
        SessionTime::new(0),
    );
    assert_eq!(
        machine.begin_close(&fence, SessionTime::new(1)),
        Ok(SessionLifecycle::Closing)
    );
    assert!(matches!(
        machine.mark_running(&fence, SessionTime::new(2)),
        Err(SessionError::InvalidTransition {
            from: SessionLifecycle::Closing,
            ..
        })
    ));
}
