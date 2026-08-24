use std::time::Duration;

use browserd_core::{
    InvalidWorkerId, LeaseConfig, LeaseConfigError, Placement, PlacementFence, PlacementFenceError,
    PlacementState, ShardId, WorkerId,
};

fn attached_placement() -> Result<Placement, InvalidWorkerId> {
    WorkerId::new("worker-apne2-a-001")
        .map(|worker_id| Placement::new(worker_id, 17, ShardId::new(), 9, PlacementState::Attached))
}

#[test]
fn exact_placement_fence_is_accepted() -> Result<(), InvalidWorkerId> {
    let placement = attached_placement()?;
    let fence = PlacementFence::new(17, 9, 1);

    assert_eq!(placement.validate_fence(1, &fence), Ok(()));
    Ok(())
}

#[test]
fn every_fencing_dimension_is_mandatory() -> Result<(), InvalidWorkerId> {
    let placement = attached_placement()?;

    assert!(matches!(
        placement.validate_fence(1, &PlacementFence::new(16, 9, 1)),
        Err(PlacementFenceError::WorkerEpochMismatch { .. })
    ));
    assert!(matches!(
        placement.validate_fence(1, &PlacementFence::new(17, 8, 1)),
        Err(PlacementFenceError::PlacementVersionMismatch { .. })
    ));
    assert!(matches!(
        placement.validate_fence(1, &PlacementFence::new(17, 9, 2)),
        Err(PlacementFenceError::SessionIncarnationMismatch { .. })
    ));
    Ok(())
}

#[test]
fn reserved_or_lost_placement_cannot_execute_session_rpc() -> Result<(), InvalidWorkerId> {
    let attached = attached_placement()?;
    let fence = PlacementFence::new(17, 9, 1);
    let reserved = attached.clone().with_state(PlacementState::Reserved);
    let lost = attached.with_state(PlacementState::Lost);

    assert!(matches!(
        reserved.validate_fence(1, &fence),
        Err(PlacementFenceError::PlacementNotAttached {
            state: PlacementState::Reserved
        })
    ));
    assert!(matches!(
        lost.validate_fence(1, &fence),
        Err(PlacementFenceError::PlacementNotAttached {
            state: PlacementState::Lost
        })
    ));
    Ok(())
}

#[test]
fn stale_worker_epoch_never_becomes_valid_after_placement_version_changes()
-> Result<(), InvalidWorkerId> {
    let original = attached_placement()?;
    let old_fence = PlacementFence::new(17, 9, 1);
    let replacement_worker = WorkerId::new("worker-apne2-a-002")?;
    let moved = Placement::new(
        replacement_worker,
        18,
        ShardId::new(),
        10,
        PlacementState::Attached,
    );

    assert_eq!(original.validate_fence(1, &old_fence), Ok(()));
    assert!(moved.validate_fence(1, &old_fence).is_err());
    Ok(())
}

#[test]
fn supervisor_lease_may_be_shorter_than_or_equal_to_directory_lease() {
    let shorter = LeaseConfig::new(Duration::from_secs(10), Duration::from_secs(30));
    let equal = LeaseConfig::new(Duration::from_secs(30), Duration::from_secs(30));

    assert!(shorter.is_ok());
    assert!(equal.is_ok());
}

#[test]
fn supervisor_lease_must_never_outlive_directory_ownership() {
    let invalid = LeaseConfig::new(Duration::from_secs(31), Duration::from_secs(30));

    assert_eq!(invalid, Err(LeaseConfigError::SupervisorExceedsDirectory));
}

#[test]
fn lease_time_to_live_must_be_nonzero() {
    assert_eq!(
        LeaseConfig::new(Duration::ZERO, Duration::from_secs(30)),
        Err(LeaseConfigError::ZeroSupervisorTtl)
    );
    assert_eq!(
        LeaseConfig::new(Duration::from_secs(10), Duration::ZERO),
        Err(LeaseConfigError::ZeroDirectoryTtl)
    );
}
