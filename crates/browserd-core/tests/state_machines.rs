use browserd_core::{
    ActionEvent, ActionId, ActionState, CreateOperationEvent, CreateOperationState, PlacementEvent,
    PlacementState, SessionCommand, SessionExecution, SessionExecutionEvent, SessionLifecycle,
    SessionLifecycleEvent, ShardAdmission, ShardEvent, ShardHealth, ShardLifecycle, ShardState,
};

#[test]
fn create_operation_follows_reservation_success_path() {
    assert_eq!(
        CreateOperationState::Accepted
            .transition(CreateOperationEvent::Enqueue)
            .ok(),
        Some(CreateOperationState::Queued)
    );
    assert_eq!(
        CreateOperationState::Queued
            .transition(CreateOperationEvent::BeginReservation)
            .ok(),
        Some(CreateOperationState::Reserving)
    );
    assert_eq!(
        CreateOperationState::Reserving
            .transition(CreateOperationEvent::ReservationCommitted)
            .ok(),
        Some(CreateOperationState::Creating)
    );
    assert_eq!(
        CreateOperationState::Creating
            .transition(CreateOperationEvent::SessionReady)
            .ok(),
        Some(CreateOperationState::Succeeded)
    );
}

#[test]
fn reservation_capacity_race_returns_operation_to_queue() {
    assert_eq!(
        CreateOperationState::Reserving
            .transition(CreateOperationEvent::CapacityRace)
            .ok(),
        Some(CreateOperationState::Queued)
    );
}

#[test]
fn create_operation_deadline_cancel_and_fatal_paths_are_terminal() {
    let timed_out = CreateOperationState::Queued
        .transition(CreateOperationEvent::DeadlineElapsed)
        .ok();
    let cancelled = CreateOperationState::Creating
        .transition(CreateOperationEvent::CancelBeforeCommit)
        .ok();
    let failed = CreateOperationState::Creating
        .transition(CreateOperationEvent::Fatal)
        .ok();

    assert_eq!(timed_out, Some(CreateOperationState::TimedOut));
    assert_eq!(cancelled, Some(CreateOperationState::Cancelled));
    assert_eq!(failed, Some(CreateOperationState::Failed));

    for terminal in [
        CreateOperationState::Succeeded,
        CreateOperationState::TimedOut,
        CreateOperationState::Cancelled,
        CreateOperationState::Failed,
    ] {
        assert!(terminal.transition(CreateOperationEvent::Enqueue).is_err());
    }
}

#[test]
fn create_operation_rejects_out_of_order_transitions() {
    assert!(
        CreateOperationState::Accepted
            .transition(CreateOperationEvent::SessionReady)
            .is_err()
    );
    assert!(
        CreateOperationState::Queued
            .transition(CreateOperationEvent::ReservationCommitted)
            .is_err()
    );
    assert!(
        CreateOperationState::Creating
            .transition(CreateOperationEvent::CapacityRace)
            .is_err()
    );
}

#[test]
fn shard_lifecycle_closes_admission_while_draining_and_waits_for_empty() {
    let active = ShardState::starting()
        .transition(ShardEvent::ReadinessSucceeded)
        .ok();
    assert!(active.is_some());
    let Some(active) = active else {
        return;
    };
    assert_eq!(active.lifecycle(), ShardLifecycle::Active);
    assert_eq!(active.health(), ShardHealth::Healthy);
    assert_eq!(active.admission(), ShardAdmission::Open);

    let draining = active.transition(ShardEvent::BeginDraining).ok();
    assert!(draining.is_some());
    let Some(draining) = draining else {
        return;
    };
    assert_eq!(draining.lifecycle(), ShardLifecycle::Draining);
    assert_eq!(draining.admission(), ShardAdmission::Closed);
    assert!(
        draining
            .clone()
            .transition(ShardEvent::StopWhenEmpty { live_sessions: 1 })
            .is_err()
    );

    let stopping = draining
        .transition(ShardEvent::StopWhenEmpty { live_sessions: 0 })
        .ok();
    assert!(stopping.is_some());
    let Some(stopping) = stopping else {
        return;
    };
    assert_eq!(stopping.lifecycle(), ShardLifecycle::Stopping);
    assert_eq!(
        stopping
            .transition(ShardEvent::Stopped)
            .ok()
            .map(|s| s.lifecycle()),
        Some(ShardLifecycle::Dead)
    );
}

#[test]
fn shard_taint_drains_and_hard_failure_terminates_immediately() {
    let active = ShardState::active();
    let tainted = active.clone().transition(ShardEvent::TaintDetected).ok();
    assert!(tainted.is_some());
    let Some(tainted) = tainted else {
        return;
    };
    assert_eq!(tainted.lifecycle(), ShardLifecycle::Draining);
    assert_eq!(tainted.health(), ShardHealth::Tainted);
    assert_eq!(tainted.admission(), ShardAdmission::Closed);
    let tainted_again = tainted.transition(ShardEvent::TaintDetected).ok();
    assert!(tainted_again.is_some());
    assert_eq!(
        tainted_again.as_ref().map(ShardState::lifecycle),
        Some(ShardLifecycle::Draining)
    );
    assert_eq!(
        tainted_again.as_ref().map(ShardState::health),
        Some(ShardHealth::Tainted)
    );

    let terminated = active.transition(ShardEvent::ImmediateTermination).ok();
    assert!(terminated.is_some());
    let Some(terminated) = terminated else {
        return;
    };
    assert_eq!(terminated.lifecycle(), ShardLifecycle::Dead);
    assert_eq!(terminated.admission(), ShardAdmission::Closed);
    assert!(
        terminated
            .transition(ShardEvent::ReadinessSucceeded)
            .is_err()
    );
}

#[test]
fn session_lifecycle_and_placement_follow_independent_axes() {
    assert_eq!(
        SessionLifecycle::Creating
            .transition(SessionLifecycleEvent::CreationSucceeded)
            .ok(),
        Some(SessionLifecycle::Ready)
    );
    assert_eq!(
        SessionLifecycle::Ready
            .transition(SessionLifecycleEvent::CloseRequested)
            .ok(),
        Some(SessionLifecycle::Closing)
    );
    assert_eq!(
        SessionLifecycle::Closing
            .transition(SessionLifecycleEvent::CleanupFinished)
            .ok(),
        Some(SessionLifecycle::Closed)
    );
    assert_eq!(
        SessionLifecycle::Ready
            .transition(SessionLifecycleEvent::Fatal)
            .ok(),
        Some(SessionLifecycle::Failed)
    );
    assert!(
        SessionLifecycle::Closed
            .transition(SessionLifecycleEvent::CreationSucceeded)
            .is_err()
    );
    assert!(
        SessionLifecycle::Failed
            .transition(SessionLifecycleEvent::CreationSucceeded)
            .is_err()
    );

    assert_eq!(
        PlacementState::Reserved
            .transition(PlacementEvent::Attach)
            .ok(),
        Some(PlacementState::Attached)
    );
    assert_eq!(
        PlacementState::Attached
            .transition(PlacementEvent::OwnershipLost)
            .ok(),
        Some(PlacementState::Lost)
    );
    assert!(
        PlacementState::Lost
            .transition(PlacementEvent::Attach)
            .is_err()
    );
}

#[test]
fn session_execution_tracks_action_identity_and_approval() {
    let action_id = ActionId::new();
    let other_action = ActionId::new();

    let running = SessionExecution::Idle
        .transition(SessionExecutionEvent::ActionAccepted(action_id.clone()))
        .ok();
    assert_eq!(running, Some(SessionExecution::Running(action_id.clone())));

    let pending = SessionExecution::Running(action_id.clone())
        .transition(SessionExecutionEvent::ApprovalRequired(action_id.clone()))
        .ok();
    assert_eq!(
        pending,
        Some(SessionExecution::PendingApproval(action_id.clone()))
    );
    assert!(
        SessionExecution::Running(action_id.clone())
            .transition(SessionExecutionEvent::KnownCompletion(other_action))
            .is_err()
    );
    assert_eq!(
        SessionExecution::PendingApproval(action_id.clone())
            .transition(SessionExecutionEvent::ApprovalGranted(action_id.clone()))
            .ok(),
        Some(SessionExecution::Running(action_id))
    );

    let completed_action = ActionId::new();
    assert_eq!(
        SessionExecution::Running(completed_action.clone())
            .transition(SessionExecutionEvent::KnownCompletion(completed_action))
            .ok(),
        Some(SessionExecution::Idle)
    );
}

#[test]
fn reconciliation_allows_reads_but_only_resolve_or_close_can_unblock_mutation() {
    let unknown_action = ActionId::new();
    let next_action = ActionId::new();
    let reconciling = SessionExecution::Running(unknown_action.clone())
        .transition(SessionExecutionEvent::OutcomeUnknown(
            unknown_action.clone(),
        ))
        .ok();
    assert_eq!(
        reconciling,
        Some(SessionExecution::ReconciliationRequired(
            unknown_action.clone()
        ))
    );
    let Some(reconciling) = reconciling else {
        return;
    };

    assert!(reconciling.allows(SessionCommand::Read));
    assert!(reconciling.allows(SessionCommand::Snapshot));
    assert!(reconciling.allows(SessionCommand::Resolve));
    assert!(reconciling.allows(SessionCommand::Close));
    assert!(!reconciling.allows(SessionCommand::MutatingAction));
    assert!(
        reconciling
            .clone()
            .transition(SessionExecutionEvent::ActionAccepted(next_action))
            .is_err()
    );
    assert!(
        reconciling
            .clone()
            .transition(SessionExecutionEvent::KnownCompletion(
                unknown_action.clone()
            ))
            .is_err()
    );

    assert_eq!(
        reconciling
            .clone()
            .transition(SessionExecutionEvent::Resolve(unknown_action.clone()))
            .ok(),
        Some(SessionExecution::Idle)
    );
    assert!(
        reconciling
            .transition(SessionExecutionEvent::Resolve(ActionId::new()))
            .is_err()
    );
}

#[test]
fn action_dispatch_intent_is_the_boundary_for_safe_cancellation() {
    for state in [
        ActionState::Accepted,
        ActionState::Queued,
        ActionState::PendingApproval,
        ActionState::ReadyToDispatch,
    ] {
        assert_eq!(
            state.transition(ActionEvent::CancelBeforeDispatch).ok(),
            Some(ActionState::CancelledBeforeDispatch)
        );
    }

    assert_eq!(
        ActionState::ReadyToDispatch
            .transition(ActionEvent::RecordDispatchIntent)
            .ok(),
        Some(ActionState::MayHaveExecuted)
    );
    assert!(
        ActionState::MayHaveExecuted
            .transition(ActionEvent::CancelBeforeDispatch)
            .is_err()
    );
}

#[test]
fn action_state_supports_approval_and_all_terminal_outcomes() {
    assert_eq!(
        ActionState::Accepted.transition(ActionEvent::Enqueue).ok(),
        Some(ActionState::Queued)
    );
    assert_eq!(
        ActionState::Queued
            .transition(ActionEvent::ApprovalRequired)
            .ok(),
        Some(ActionState::PendingApproval)
    );
    assert_eq!(
        ActionState::PendingApproval
            .transition(ActionEvent::ApprovalGranted)
            .ok(),
        Some(ActionState::ReadyToDispatch)
    );
    assert_eq!(
        ActionState::PendingApproval
            .transition(ActionEvent::ApprovalDenied)
            .ok(),
        Some(ActionState::FailedKnown)
    );
    assert_eq!(
        ActionState::PendingApproval
            .transition(ActionEvent::ApprovalTimedOut)
            .ok(),
        Some(ActionState::FailedKnown)
    );
    assert_eq!(
        ActionState::Queued
            .transition(ActionEvent::ReadyForDispatch)
            .ok(),
        Some(ActionState::ReadyToDispatch)
    );

    for (event, terminal) in [
        (ActionEvent::Succeeded, ActionState::Succeeded),
        (ActionEvent::FailedKnown, ActionState::FailedKnown),
        (
            ActionEvent::CancellationConfirmed,
            ActionState::CancelledConfirmed,
        ),
        (ActionEvent::OutcomeUncertain, ActionState::OutcomeUnknown),
    ] {
        assert_eq!(
            ActionState::MayHaveExecuted.transition(event).ok(),
            Some(terminal)
        );
    }
}

#[test]
fn action_terminal_states_never_reenter_the_dispatch_pipeline() {
    for terminal in [
        ActionState::Succeeded,
        ActionState::FailedKnown,
        ActionState::CancelledBeforeDispatch,
        ActionState::CancelledConfirmed,
        ActionState::OutcomeUnknown,
    ] {
        assert!(terminal.transition(ActionEvent::Enqueue).is_err());
        assert!(
            terminal
                .transition(ActionEvent::RecordDispatchIntent)
                .is_err()
        );
    }
}
