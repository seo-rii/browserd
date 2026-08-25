use std::time::Duration;

use browserd_session::{
    ActionId, CleanupBackend, CleanupFailure, CleanupStage, ExpireDecision, LeasePolicy,
    OwnershipFence, SessionControl, SessionError, SessionExecution, SessionId, SessionLifecycle,
    SessionMachine, SessionTime, SessionTimeoutPolicy, TargetId, WorkerId,
};

fn worker(value: &str) -> Option<WorkerId> {
    WorkerId::new(value).ok()
}

fn running() -> Option<(SessionMachine, OwnershipFence)> {
    let policy = LeasePolicy::new(Duration::from_millis(100), Duration::from_millis(20)).ok()?;
    let initial = OwnershipFence::new(worker("worker-a")?, 1, 1, 1);
    let (mut machine, fence) =
        SessionMachine::create(SessionId::new(), initial, policy, SessionTime::new(0));
    assert!(machine.start(&fence, SessionTime::new(0)).is_ok());
    assert!(machine.mark_running(&fence, SessionTime::new(1)).is_ok());
    Some((machine, fence))
}

#[derive(Default)]
struct CleanupRecorder(Vec<CleanupStage>);

impl CleanupBackend for CleanupRecorder {
    fn run_stage(
        &mut self,
        stage: CleanupStage,
        _active_targets: &[TargetId],
    ) -> Result<(), CleanupFailure> {
        self.0.push(stage);
        Ok(())
    }
}

#[test]
fn stale_timer_and_cleanup_callbacks_cannot_mutate_a_transferred_session() {
    let lease = LeasePolicy::new(Duration::from_millis(1_000), Duration::from_millis(20));
    let timeouts =
        SessionTimeoutPolicy::new(Duration::from_millis(100), Duration::from_millis(100));
    assert!(lease.is_ok());
    assert!(timeouts.is_ok());
    let (Some(lease), Some(timeouts), Some(worker_a), Some(worker_b)) = (
        lease.ok(),
        timeouts.ok(),
        worker("worker-a"),
        worker("worker-b"),
    ) else {
        return;
    };
    let initial = OwnershipFence::new(worker_a, 1, 1, 1);
    let (mut machine, stale) = SessionMachine::create_with_timeouts(
        SessionId::new(),
        initial,
        lease,
        timeouts,
        SessionTime::new(0),
    );
    assert!(machine.start(&stale, SessionTime::new(0)).is_ok());
    assert!(machine.mark_running(&stale, SessionTime::new(1)).is_ok());
    let current = machine.transfer_owner(&stale, worker_b, 1, SessionTime::new(10));
    assert!(current.is_ok());
    let Some(current) = current.ok() else {
        return;
    };

    assert_eq!(
        machine.expire_due(&stale, SessionTime::new(100)),
        Err(SessionError::StaleWorkerId),
    );
    assert_eq!(machine.lifecycle(), SessionLifecycle::Ready);
    assert_eq!(
        machine.expire_due(&current, SessionTime::new(100)),
        Ok(ExpireDecision::BeganExpiring),
    );
    let mut backend = CleanupRecorder::default();
    assert_eq!(
        machine.run_cleanup(&stale, &mut backend),
        Err(SessionError::StaleWorkerId),
    );
    assert!(backend.0.is_empty());
    assert!(machine.run_cleanup(&current, &mut backend).is_ok());
}

#[test]
fn core_execution_preserves_exact_action_identity_and_worker_loss_uncertainty() {
    let Some((mut machine, fence)) = running() else {
        return;
    };
    let action = ActionId::new();
    let other = ActionId::new();
    assert!(
        machine
            .begin_action(&fence, action.clone(), SessionTime::new(2))
            .is_ok()
    );
    assert_eq!(
        machine.snapshot().execution,
        SessionExecution::Running(action.clone()),
    );
    assert_eq!(
        machine.finish_action(&fence, &other, SessionTime::new(3)),
        Err(SessionError::ActionIdentityMismatch),
    );
    assert_eq!(
        machine.expire_due(&fence, SessionTime::new(100)),
        Ok(ExpireDecision::OwnershipLost),
    );
    assert_eq!(
        machine.snapshot().execution,
        SessionExecution::ReconciliationRequired(action),
    );
}

#[test]
fn duplicate_human_control_transitions_are_rejected_without_state_change() {
    let Some((mut machine, fence)) = running() else {
        return;
    };
    assert!(
        machine
            .acquire_human_control(&fence, SessionTime::new(2))
            .is_ok()
    );
    assert_eq!(
        machine.acquire_human_control(&fence, SessionTime::new(3)),
        Err(SessionError::HumanControlAlreadyAcquired),
    );
    assert_eq!(machine.snapshot().control, SessionControl::Human);
    assert!(
        machine
            .release_human_control(&fence, SessionTime::new(4))
            .is_ok()
    );
    assert_eq!(
        machine.release_human_control(&fence, SessionTime::new(5)),
        Err(SessionError::HumanControlNotAcquired),
    );
    assert_eq!(machine.snapshot().control, SessionControl::Agent);
}
