use std::time::Duration;

use browserd_session::{
    ActionId, ExpireCause, LeasePolicy, OwnershipFence, PlacementState, SessionControl,
    SessionExecution, SessionId, SessionLifecycle, SessionMachine, SessionTime,
    SessionTimeoutPolicy, WorkerId,
};

fn configured() -> Option<(SessionMachine, OwnershipFence)> {
    let lease = LeasePolicy::new(Duration::from_millis(50), Duration::from_millis(10));
    assert!(lease.is_ok());
    let lease = lease.ok()?;
    let timeouts = SessionTimeoutPolicy::new(Duration::from_millis(200), Duration::from_millis(40));
    assert!(timeouts.is_ok());
    let timeouts = timeouts.ok()?;
    let worker = WorkerId::new("worker-a").ok()?;
    Some(SessionMachine::create_with_timeouts(
        SessionId::new(),
        OwnershipFence::new(worker, 1, 1, 1),
        lease,
        timeouts,
        SessionTime::new(10),
    ))
}

#[test]
fn lifecycle_uses_the_spec_states_instead_of_collapsing_other_axes_into_it() {
    let _states = [
        SessionLifecycle::Creating,
        SessionLifecycle::Ready,
        SessionLifecycle::Closing,
        SessionLifecycle::Closed,
        SessionLifecycle::Failed,
    ];
}

#[test]
fn lifecycle_placement_execution_and_control_are_independent_axes() {
    let Some((mut machine, fence)) = configured() else {
        return;
    };
    let created = machine.snapshot();
    assert_eq!(created.lifecycle, SessionLifecycle::Creating);
    assert_eq!(created.placement, PlacementState::Reserved);
    assert_eq!(created.execution, SessionExecution::Idle);
    assert_eq!(created.control, SessionControl::Agent);

    assert!(machine.start(&fence, SessionTime::new(10)).is_ok());
    assert!(machine.mark_running(&fence, SessionTime::new(11)).is_ok());
    let action = ActionId::new();
    assert!(
        machine
            .begin_action(&fence, action.clone(), SessionTime::new(12))
            .is_ok()
    );
    assert!(
        machine
            .acquire_human_control(&fence, SessionTime::new(13))
            .is_err()
    );
    assert!(
        machine
            .finish_action(&fence, &action, SessionTime::new(14))
            .is_ok()
    );
    assert!(
        machine
            .acquire_human_control(&fence, SessionTime::new(15))
            .is_ok()
    );

    let active = machine.snapshot();
    assert_eq!(active.lifecycle, SessionLifecycle::Ready);
    assert_eq!(active.placement, PlacementState::Attached);
    assert_eq!(active.execution, SessionExecution::Idle);
    assert_eq!(active.control, SessionControl::Human);
}

#[test]
fn activity_extends_only_idle_deadline_and_never_the_absolute_ttl() {
    let Some((mut machine, fence)) = configured() else {
        return;
    };
    assert!(machine.start(&fence, SessionTime::new(10)).is_ok());
    assert!(machine.mark_running(&fence, SessionTime::new(11)).is_ok());
    let initial = machine.snapshot();
    assert_eq!(initial.session_expires_at, Some(SessionTime::new(210)));
    assert_eq!(initial.idle_expires_at, Some(SessionTime::new(50)));

    assert!(
        machine
            .record_activity(&fence, SessionTime::new(45))
            .is_ok()
    );
    let active = machine.snapshot();
    assert_eq!(active.session_expires_at, Some(SessionTime::new(210)));
    assert_eq!(active.idle_expires_at, Some(SessionTime::new(85)));
}

#[test]
fn idle_and_absolute_ttl_expiry_are_distinguished() {
    let Some((mut idle, idle_fence)) = configured() else {
        return;
    };
    assert!(idle.start(&idle_fence, SessionTime::new(10)).is_ok());
    assert!(idle.mark_running(&idle_fence, SessionTime::new(11)).is_ok());
    assert!(idle.expire_due(&idle_fence, SessionTime::new(50)).is_ok());
    assert_eq!(idle.expire_cause(), Some(ExpireCause::IdleTimeout));

    let lease = LeasePolicy::new(Duration::from_millis(500), Duration::from_millis(10));
    assert!(lease.is_ok());
    let Some(lease) = lease.ok() else {
        return;
    };
    let timeouts =
        SessionTimeoutPolicy::new(Duration::from_millis(100), Duration::from_millis(500));
    assert!(timeouts.is_ok());
    let Some(timeouts) = timeouts.ok() else {
        return;
    };
    let Some(worker) = WorkerId::new("worker-a").ok() else {
        return;
    };
    let (mut absolute, absolute_fence) = SessionMachine::create_with_timeouts(
        SessionId::new(),
        OwnershipFence::new(worker, 1, 1, 1),
        lease,
        timeouts,
        SessionTime::new(0),
    );
    assert!(absolute.start(&absolute_fence, SessionTime::new(0)).is_ok());
    assert!(
        absolute
            .mark_running(&absolute_fence, SessionTime::new(1))
            .is_ok()
    );
    assert!(
        absolute
            .expire_due(&absolute_fence, SessionTime::new(100))
            .is_ok()
    );
    assert_eq!(absolute.expire_cause(), Some(ExpireCause::SessionTtl));
}

#[test]
fn timeout_expiry_marks_a_dispatched_action_for_reconciliation() {
    let lease = LeasePolicy::new(Duration::from_millis(500), Duration::from_millis(10));
    let timeouts =
        SessionTimeoutPolicy::new(Duration::from_millis(100), Duration::from_millis(500));
    assert!(lease.is_ok());
    assert!(timeouts.is_ok());
    let (Some(lease), Some(timeouts)) = (lease.ok(), timeouts.ok()) else {
        return;
    };
    let Some(worker) = WorkerId::new("worker-timeout").ok() else {
        return;
    };
    let (mut machine, fence) = SessionMachine::create_with_timeouts(
        SessionId::new(),
        OwnershipFence::new(worker, 1, 1, 1),
        lease,
        timeouts,
        SessionTime::new(0),
    );
    assert!(machine.start(&fence, SessionTime::new(0)).is_ok());
    assert!(machine.mark_running(&fence, SessionTime::new(1)).is_ok());
    let action_id = ActionId::new();
    assert!(
        machine
            .begin_action(&fence, action_id.clone(), SessionTime::new(2))
            .is_ok()
    );

    assert_eq!(
        machine.expire_due(&fence, SessionTime::new(100)),
        Ok(browserd_session::ExpireDecision::BeganExpiring)
    );
    assert_eq!(
        machine.snapshot().execution,
        SessionExecution::ReconciliationRequired(action_id)
    );
}

#[test]
fn stale_owner_cannot_mutate_any_independent_axis() {
    let Some((mut machine, fence)) = configured() else {
        return;
    };
    assert!(machine.start(&fence, SessionTime::new(10)).is_ok());
    assert!(machine.mark_running(&fence, SessionTime::new(11)).is_ok());
    let Some(worker_b) = WorkerId::new("worker-b").ok() else {
        return;
    };
    let next = machine.transfer_owner(&fence, worker_b, 1, SessionTime::new(12));
    assert!(next.is_ok());

    assert!(
        machine
            .begin_action(&fence, ActionId::new(), SessionTime::new(13))
            .is_err()
    );
    assert!(
        machine
            .acquire_human_control(&fence, SessionTime::new(13))
            .is_err()
    );
    assert!(
        machine
            .record_activity(&fence, SessionTime::new(13))
            .is_err()
    );
    let snapshot = machine.snapshot();
    assert_eq!(snapshot.execution, SessionExecution::Idle);
    assert_eq!(snapshot.control, SessionControl::Agent);
}

#[test]
fn work_cannot_resurrect_an_expired_ownership_or_idle_deadline() {
    let Some((mut idle, idle_fence)) = configured() else {
        return;
    };
    assert!(idle.start(&idle_fence, SessionTime::new(10)).is_ok());
    assert!(idle.mark_running(&idle_fence, SessionTime::new(11)).is_ok());
    assert_eq!(
        idle.begin_action(&idle_fence, ActionId::new(), SessionTime::new(50)),
        Err(browserd_session::SessionError::SessionDeadlineElapsed {
            cause: ExpireCause::IdleTimeout,
            expired_at: SessionTime::new(50),
        }),
    );
    assert_eq!(idle.snapshot().execution, SessionExecution::Idle);

    let lease = LeasePolicy::new(Duration::from_millis(50), Duration::from_millis(10));
    assert!(lease.is_ok());
    let Some(lease) = lease.ok() else {
        return;
    };
    let Some(worker) = WorkerId::new("worker-a").ok() else {
        return;
    };
    let (mut owner, owner_fence) = SessionMachine::create(
        SessionId::new(),
        OwnershipFence::new(worker, 1, 1, 1),
        lease,
        SessionTime::new(0),
    );
    assert!(owner.start(&owner_fence, SessionTime::new(0)).is_ok());
    assert!(
        owner
            .mark_running(&owner_fence, SessionTime::new(1))
            .is_ok()
    );
    assert_eq!(
        owner.begin_action(&owner_fence, ActionId::new(), SessionTime::new(50)),
        Err(browserd_session::SessionError::SessionDeadlineElapsed {
            cause: ExpireCause::OwnershipLease,
            expired_at: SessionTime::new(50),
        }),
    );
}
