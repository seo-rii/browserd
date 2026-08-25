use std::time::Duration;

use browserd_core::{
    LeaseId, PlacementFence, PlacementState, SessionId, SessionLifecycle, WorkerId,
};
use browserd_session::{
    ActionId, ClientBinding, LeasePolicy, OwnershipFence, ReconnectError, SessionError,
    SessionMachine, SessionTime,
};

fn worker(value: &str) -> Option<WorkerId> {
    WorkerId::new(value).ok()
}

#[test]
fn session_api_reuses_core_identifiers_states_and_opaque_lease_ids() {
    let Some(worker) = worker("worker-a") else {
        return;
    };
    let policy = LeasePolicy::new(Duration::from_millis(100), Duration::from_millis(20));
    assert!(policy.is_ok());
    let Some(policy) = policy.ok() else {
        return;
    };
    let session_id: SessionId = SessionId::new();
    let (machine, fence) = SessionMachine::create(
        session_id,
        OwnershipFence::new(worker, 7, 11, 1),
        policy,
        SessionTime::new(0),
    );

    let _: SessionLifecycle = machine.lifecycle();
    let _: PlacementState = machine.snapshot().placement;
    let _: PlacementFence = fence.as_placement_fence();
    let _: LeaseId = browserd_session::ReconnectToken::new();
    assert_eq!(fence.as_placement_fence(), PlacementFence::new(7, 11, 1),);
}

#[test]
fn every_placement_fence_dimension_is_checked_before_mutation() {
    let (Some(worker_a), Some(worker_b)) = (worker("worker-a"), worker("worker-b")) else {
        return;
    };
    let policy = LeasePolicy::new(Duration::from_millis(100), Duration::from_millis(20));
    assert!(policy.is_ok());
    let Some(policy) = policy.ok() else {
        return;
    };
    let (mut machine, fence) = SessionMachine::create(
        SessionId::new(),
        OwnershipFence::new(worker_a.clone(), 7, 11, 1),
        policy,
        SessionTime::new(0),
    );
    assert!(machine.start(&fence, SessionTime::new(0)).is_ok());
    assert!(machine.mark_running(&fence, SessionTime::new(1)).is_ok());

    let stale_worker = OwnershipFence::new(worker_b.clone(), 7, 11, 1);
    let stale_epoch = OwnershipFence::new(worker_a.clone(), 6, 11, 1);
    let stale_placement = OwnershipFence::new(worker_a.clone(), 7, 10, 1);
    let stale_incarnation = OwnershipFence::new(worker_a, 7, 11, 2);
    for stale in [
        stale_worker,
        stale_epoch,
        stale_placement,
        stale_incarnation,
    ] {
        assert!(
            machine
                .begin_action(&stale, ActionId::new(), SessionTime::new(2))
                .is_err()
        );
    }
    assert_eq!(
        machine.snapshot().execution,
        browserd_session::SessionExecution::Idle
    );

    let next = machine.transfer_owner(&fence, worker_b, 3, SessionTime::new(2));
    assert!(next.is_ok());
    let Some(next) = next.ok() else {
        return;
    };
    assert_eq!(next.worker_epoch(), 3);
    assert_eq!(next.placement_version(), 12);
    assert_eq!(next.session_incarnation(), 1);
    assert_eq!(
        machine.renew_lease(&fence, SessionTime::new(3)),
        Err(SessionError::StaleWorkerId),
    );
}

#[test]
fn placement_version_overflow_rejects_transfer_without_changing_ownership() {
    let (Some(worker_a), Some(worker_b)) = (worker("worker-a"), worker("worker-b")) else {
        return;
    };
    let policy = LeasePolicy::new(Duration::from_millis(100), Duration::from_millis(20));
    assert!(policy.is_ok());
    let Some(policy) = policy.ok() else {
        return;
    };
    let (mut machine, fence) = SessionMachine::create(
        SessionId::new(),
        OwnershipFence::new(worker_a, 7, u64::MAX, 1),
        policy,
        SessionTime::new(0),
    );
    assert!(machine.start(&fence, SessionTime::new(0)).is_ok());
    assert!(machine.mark_running(&fence, SessionTime::new(1)).is_ok());
    assert_eq!(
        machine.transfer_owner(&fence, worker_b, 3, SessionTime::new(2)),
        Err(SessionError::PlacementVersionOverflow),
    );
    assert_eq!(machine.snapshot().owner_fence, fence);
}

#[test]
fn reconnect_issuance_rejects_each_stale_fence_dimension() {
    let (Some(worker_a), Some(worker_b)) = (worker("worker-a"), worker("worker-b")) else {
        return;
    };
    let policy = LeasePolicy::new(Duration::from_millis(100), Duration::from_millis(20));
    assert!(policy.is_ok());
    let Some(policy) = policy.ok() else {
        return;
    };
    let (mut machine, fence) = SessionMachine::create(
        SessionId::new(),
        OwnershipFence::new(worker_a.clone(), 7, 11, 1),
        policy,
        SessionTime::new(0),
    );
    assert!(machine.start(&fence, SessionTime::new(0)).is_ok());
    assert!(machine.mark_running(&fence, SessionTime::new(1)).is_ok());
    let binding = ClientBinding::new("principal-a", "channel-a");

    let cases = [
        (
            OwnershipFence::new(worker_b, 7, 11, 1),
            ReconnectError::StaleWorkerId,
        ),
        (
            OwnershipFence::new(worker_a.clone(), 6, 11, 1),
            ReconnectError::WorkerEpochMismatch,
        ),
        (
            OwnershipFence::new(worker_a.clone(), 7, 10, 1),
            ReconnectError::PlacementVersionMismatch,
        ),
        (
            OwnershipFence::new(worker_a, 7, 11, 2),
            ReconnectError::SessionIncarnationMismatch,
        ),
    ];
    for (stale, expected) in cases {
        assert_eq!(
            machine.issue_reconnect_token(
                &stale,
                binding.clone(),
                SessionTime::new(2),
                Duration::from_millis(20),
            ),
            Err(expected),
        );
    }
}
