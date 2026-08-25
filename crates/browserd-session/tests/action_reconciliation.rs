use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::Duration;

use browserd_session::{
    ActionId, LeasePolicy, OwnershipFence, SessionError, SessionExecution, SessionId,
    SessionLifecycle, SessionMachine, SessionTime, WorkerId,
};

fn running_action() -> Option<(SessionMachine, OwnershipFence, ActionId)> {
    let policy = LeasePolicy::new(Duration::from_secs(10), Duration::from_secs(1)).ok()?;
    let worker = WorkerId::new("worker-reconcile").ok()?;
    let (mut machine, fence) = SessionMachine::create(
        SessionId::new(),
        OwnershipFence::new(worker, 9, 4, 2),
        policy,
        SessionTime::new(0),
    );
    assert!(machine.start(&fence, SessionTime::new(0)).is_ok());
    assert_eq!(
        machine.mark_running(&fence, SessionTime::new(1)),
        Ok(SessionLifecycle::Ready)
    );
    let action_id = ActionId::new();
    assert_eq!(
        machine.begin_action(&fence, action_id.clone(), SessionTime::new(2)),
        Ok(())
    );
    Some((machine, fence, action_id))
}

#[test]
fn only_the_current_action_can_become_unknown_and_resolve() {
    let Some((mut machine, fence, action_id)) = running_action() else {
        return;
    };
    let other = ActionId::new();
    assert_eq!(
        machine.mark_action_outcome_unknown(&fence, &other, SessionTime::new(3)),
        Err(SessionError::ActionIdentityMismatch)
    );
    assert_eq!(
        machine.snapshot().execution,
        SessionExecution::Running(action_id.clone())
    );

    let stale = OwnershipFence::new(
        fence.worker_id().clone(),
        fence.worker_epoch().saturating_add(1),
        fence.placement_version(),
        fence.session_incarnation(),
    );
    assert!(matches!(
        machine.mark_action_outcome_unknown(&stale, &action_id, SessionTime::new(3)),
        Err(SessionError::WorkerEpochMismatch { .. })
    ));
    assert_eq!(
        machine.mark_action_outcome_unknown(&fence, &action_id, SessionTime::new(3)),
        Ok(())
    );
    assert_eq!(
        machine.snapshot().execution,
        SessionExecution::ReconciliationRequired(action_id.clone())
    );
    assert_eq!(
        machine.resolve_action(&fence, &other, SessionTime::new(4)),
        Err(SessionError::ActionIdentityMismatch)
    );
    assert_eq!(
        machine.resolve_action(&fence, &action_id, SessionTime::new(4)),
        Ok(())
    );
    assert_eq!(machine.snapshot().execution, SessionExecution::Idle);
    assert_eq!(
        machine.resolve_action(&fence, &action_id, SessionTime::new(5)),
        Err(SessionError::ActionIdentityMismatch)
    );
}

#[test]
fn concurrent_duplicate_resolve_has_exactly_one_winner() {
    for _iteration in 0..50 {
        let Some((mut machine, fence, action_id)) = running_action() else {
            return;
        };
        assert!(
            machine
                .mark_action_outcome_unknown(&fence, &action_id, SessionTime::new(3))
                .is_ok()
        );
        let shared = Arc::new(Mutex::new(machine));
        let barrier = Arc::new(Barrier::new(3));
        let mut handles = Vec::new();
        for _resolver in 0..2 {
            let shared = shared.clone();
            let barrier = barrier.clone();
            let fence = fence.clone();
            let action_id = action_id.clone();
            handles.push(thread::spawn(move || {
                barrier.wait();
                let Ok(mut machine) = shared.lock() else {
                    return Err(SessionError::StateUnavailable);
                };
                machine.resolve_action(&fence, &action_id, SessionTime::new(4))
            }));
        }
        barrier.wait();
        let mut successes = 0;
        let mut identity_failures = 0;
        for handle in handles {
            let result = handle.join();
            assert!(result.is_ok());
            let Some(result) = result.ok() else {
                return;
            };
            if result.is_ok() {
                successes += 1;
            } else if result == Err(SessionError::ActionIdentityMismatch) {
                identity_failures += 1;
            }
        }
        assert_eq!(successes, 1);
        assert_eq!(identity_failures, 1);
        let Ok(machine) = shared.lock() else {
            return;
        };
        assert_eq!(machine.snapshot().execution, SessionExecution::Idle);
    }
}
