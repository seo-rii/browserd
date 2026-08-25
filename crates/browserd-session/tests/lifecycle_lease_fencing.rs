use std::time::Duration;

use browserd_session::{
    ExpireDecision, LeasePolicy, LeaseRenewal, OwnershipFence, PlacementState, SessionError,
    SessionId, SessionLifecycle, SessionMachine, SessionOperation, SessionTime,
    SessionTimeoutPolicy, WorkerId,
};

fn machine(ttl_ms: u64, grace_ms: u64) -> Option<(SessionMachine, OwnershipFence)> {
    let policy = LeasePolicy::new(
        Duration::from_millis(ttl_ms),
        Duration::from_millis(grace_ms),
    );
    assert!(policy.is_ok());
    let policy = policy.ok()?;
    let worker = WorkerId::new("worker-a").ok()?;
    Some(SessionMachine::create(
        SessionId::new(),
        OwnershipFence::new(worker, 1, 1, 1),
        policy,
        SessionTime::new(0),
    ))
}

fn running_machine(ttl_ms: u64, grace_ms: u64) -> Option<(SessionMachine, OwnershipFence)> {
    let (mut machine, fence) = machine(ttl_ms, grace_ms)?;
    assert_eq!(
        machine.start(&fence, SessionTime::new(0)),
        Ok(SessionLifecycle::Creating),
    );
    assert_eq!(
        machine.mark_running(&fence, SessionTime::new(1)),
        Ok(SessionLifecycle::Ready),
    );
    Some((machine, fence))
}

#[test]
fn lifecycle_is_created_starting_running_expiring_then_cleanup_terminated() {
    let lease = LeasePolicy::new(Duration::from_millis(1_000), Duration::from_millis(20));
    let timeouts =
        SessionTimeoutPolicy::new(Duration::from_millis(100), Duration::from_millis(100));
    assert!(lease.is_ok());
    assert!(timeouts.is_ok());
    let (Some(lease), Some(timeouts)) = (lease.ok(), timeouts.ok()) else {
        return;
    };
    let Some(worker) = WorkerId::new("worker-a").ok() else {
        return;
    };
    let (mut machine, fence) = SessionMachine::create_with_timeouts(
        SessionId::new(),
        OwnershipFence::new(worker, 1, 1, 1),
        lease,
        timeouts,
        SessionTime::new(0),
    );
    assert_eq!(machine.lifecycle(), SessionLifecycle::Creating);
    assert_eq!(
        machine.start(&fence, SessionTime::new(0)),
        Ok(SessionLifecycle::Creating),
    );
    assert_eq!(machine.lease_expires_at(), Some(SessionTime::new(1_000)));
    assert_eq!(
        machine.mark_running(&fence, SessionTime::new(1)),
        Ok(SessionLifecycle::Ready),
    );
    assert_eq!(
        machine.expire_due(&fence, SessionTime::new(99)),
        Ok(ExpireDecision::NotDue {
            expires_at: SessionTime::new(100),
        }),
    );
    assert_eq!(
        machine.expire_due(&fence, SessionTime::new(100)),
        Ok(ExpireDecision::BeganExpiring),
    );
    assert_eq!(machine.lifecycle(), SessionLifecycle::Closing);
}

#[test]
fn invalid_lifecycle_transitions_are_explicit() {
    let Some((mut machine, fence)) = machine(100, 20) else {
        return;
    };
    assert_eq!(
        machine.mark_running(&fence, SessionTime::new(0)),
        Err(SessionError::InvalidTransition {
            from: SessionLifecycle::Creating,
            operation: SessionOperation::MarkRunning,
        }),
    );
}

#[test]
fn renewal_uses_now_plus_ttl_and_accepts_the_exact_grace_boundary() {
    let Some((mut early, early_fence)) = running_machine(100, 20) else {
        return;
    };
    assert_eq!(
        early.renew_lease(&early_fence, SessionTime::new(80)),
        Ok(LeaseRenewal {
            previous_expires_at: SessionTime::new(100),
            expires_at: SessionTime::new(180),
        }),
    );

    let Some((mut at_boundary, boundary_fence)) = running_machine(100, 20) else {
        return;
    };
    assert_eq!(
        at_boundary.renew_lease(&boundary_fence, SessionTime::new(120)),
        Ok(LeaseRenewal {
            previous_expires_at: SessionTime::new(100),
            expires_at: SessionTime::new(220),
        }),
    );
}

#[test]
fn renewal_after_grace_and_backwards_time_fail_closed_without_mutation() {
    let Some((mut machine, fence)) = running_machine(100, 20) else {
        return;
    };
    assert_eq!(
        machine.renew_lease(&fence, SessionTime::new(121)),
        Err(SessionError::RenewGraceElapsed {
            expired_at: SessionTime::new(100),
            grace_until: SessionTime::new(120),
        }),
    );
    assert_eq!(machine.lease_expires_at(), Some(SessionTime::new(100)));

    let Some((mut monotonic, monotonic_fence)) = running_machine(100, 20) else {
        return;
    };
    assert!(
        monotonic
            .renew_lease(&monotonic_fence, SessionTime::new(50))
            .is_ok()
    );
    assert_eq!(
        monotonic.renew_lease(&monotonic_fence, SessionTime::new(49)),
        Err(SessionError::ClockMovedBackwards),
    );
    assert_eq!(monotonic.lease_expires_at(), Some(SessionTime::new(150)));
}

#[test]
fn ownership_transfer_monotonically_fences_the_previous_owner_and_epoch() {
    let Some((mut machine, first_fence)) = running_machine(100, 20) else {
        return;
    };
    let Some(worker_b) = WorkerId::new("worker-b").ok() else {
        return;
    };
    let second = machine.transfer_owner(&first_fence, worker_b.clone(), 4, SessionTime::new(10));
    assert!(second.is_ok());
    let Some(second) = second.ok() else {
        return;
    };
    assert_eq!(second.worker_epoch(), 4);
    assert_eq!(second.placement_version(), 2);
    assert_eq!(second.session_incarnation(), 1);
    assert_eq!(
        machine.renew_lease(&first_fence, SessionTime::new(11)),
        Err(SessionError::StaleWorkerId),
    );

    let stale_epoch = OwnershipFence::new(worker_b.clone(), 3, 2, 1);
    assert_eq!(
        machine.renew_lease(&stale_epoch, SessionTime::new(11)),
        Err(SessionError::WorkerEpochMismatch {
            expected: 4,
            received: 3,
        }),
    );
    let Some(worker_c) = WorkerId::new("worker-c").ok() else {
        return;
    };
    let wrong_owner = OwnershipFence::new(worker_c.clone(), 4, 2, 1);
    assert_eq!(
        machine.renew_lease(&wrong_owner, SessionTime::new(11)),
        Err(SessionError::StaleWorkerId),
    );

    let third = machine.transfer_owner(&second, worker_c, 9, SessionTime::new(12));
    assert!(third.is_ok());
    let Some(third) = third.ok() else {
        return;
    };
    assert_eq!(third.worker_epoch(), 9);
    assert_eq!(third.placement_version(), 3);
    assert_eq!(third.session_incarnation(), 1);
}

#[test]
fn timer_overflow_fails_before_creation_or_transfer_state_mutates() {
    let policy = LeasePolicy::new(Duration::from_millis(2), Duration::ZERO);
    assert!(policy.is_ok());
    let Some(policy) = policy.ok() else {
        return;
    };
    let Some(worker) = WorkerId::new("worker-a").ok() else {
        return;
    };
    let (mut overflowed_create, create_fence) = SessionMachine::create(
        SessionId::new(),
        OwnershipFence::new(worker, 1, 1, 1),
        policy,
        SessionTime::new(u64::MAX),
    );
    assert_eq!(
        overflowed_create.start(&create_fence, SessionTime::new(u64::MAX)),
        Err(SessionError::TimeOverflow),
    );

    let policy = LeasePolicy::new(Duration::from_millis(u64::MAX), Duration::ZERO);
    assert!(policy.is_ok());
    let Some(policy) = policy.ok() else {
        return;
    };
    let Some(worker_a) = WorkerId::new("worker-a").ok() else {
        return;
    };
    let (mut running, fence) = SessionMachine::create(
        SessionId::new(),
        OwnershipFence::new(worker_a, 1, 1, 1),
        policy,
        SessionTime::new(0),
    );
    assert!(running.start(&fence, SessionTime::new(0)).is_ok());
    assert!(running.mark_running(&fence, SessionTime::new(1)).is_ok());
    let Some(worker_b) = WorkerId::new("worker-b").ok() else {
        return;
    };
    assert_eq!(
        running.transfer_owner(&fence, worker_b, 1, SessionTime::new(u64::MAX - 1),),
        Err(SessionError::TimeOverflow),
    );
    assert!(running.record_activity(&fence, SessionTime::new(2)).is_ok());
}

#[test]
fn ownership_lease_loss_is_failed_and_lost_not_a_graceful_session_close() {
    let Some((mut machine, fence)) = running_machine(100, 20) else {
        return;
    };
    assert!(
        machine
            .register_target(&fence, browserd_session::TargetId::new("target-a"))
            .is_ok()
    );
    assert_eq!(
        machine.expire_due(&fence, SessionTime::new(100)),
        Ok(ExpireDecision::OwnershipLost),
    );
    let snapshot = machine.snapshot();
    assert_eq!(snapshot.lifecycle, SessionLifecycle::Failed);
    assert_eq!(snapshot.placement, PlacementState::Lost);
    assert!(!snapshot.accepting_targets);
}
