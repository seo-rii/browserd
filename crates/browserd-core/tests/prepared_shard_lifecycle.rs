#![allow(clippy::expect_used)]

use browserd_core::{
    EgressFence, LaunchGeneration, OwnerFence, PreparedShardLifecycle, PreparedShardState,
    PreparedShardTransition, PreparedShardTransitionError, RouteGeneration, SessionId,
    SessionIncarnation, ShardFence, ShardId, TransitionOutcome, WorkerEpoch, WorkerId,
};

fn shard_fence(worker: &str, worker_epoch: u64, shard_id: ShardId, launch: u64) -> ShardFence {
    ShardFence::new(
        OwnerFence::new(
            WorkerId::new(worker).expect("worker identity must be valid"),
            WorkerEpoch::new(worker_epoch).expect("worker epoch must be positive"),
        ),
        shard_id,
        LaunchGeneration::new(launch).expect("launch generation must be positive"),
    )
}

fn advance_to_containment(
    lifecycle: &mut PreparedShardLifecycle,
    fence: &ShardFence,
    session_id: SessionId,
) -> EgressFence {
    for transition in [
        PreparedShardTransition::FilesystemCgroupReady,
        PreparedShardTransition::ChildGated,
        PreparedShardTransition::ProcessIdentityProven,
        PreparedShardTransition::CgroupAttached,
        PreparedShardTransition::NetnsIdentityProven,
    ] {
        assert!(matches!(
            lifecycle.apply(fence, transition),
            Ok(TransitionOutcome::Applied | TransitionOutcome::AlreadyApplied)
        ));
    }
    let egress_fence = EgressFence::new(
        fence.clone(),
        RouteGeneration::new(1).expect("route generation must be positive"),
        session_id,
        SessionIncarnation::new(1).expect("session incarnation must be positive"),
    );
    assert_eq!(
        lifecycle.apply(
            fence,
            PreparedShardTransition::IngressRegistered(egress_fence.clone()),
        ),
        Ok(TransitionOutcome::Applied)
    );
    assert_eq!(
        lifecycle.apply(fence, PreparedShardTransition::CdpClaimed),
        Ok(TransitionOutcome::Applied)
    );
    assert_eq!(
        lifecycle.apply(fence, PreparedShardTransition::ContainmentProven),
        Ok(TransitionOutcome::Applied)
    );
    egress_fence
}

#[test]
fn stale_launch_generation_cannot_release_a_newer_shard() {
    let shard_id = ShardId::new();
    let current = shard_fence("worker-a", 9, shard_id.clone(), 2);
    let stale = shard_fence("worker-a", 9, shard_id, 1);
    let mut lifecycle = PreparedShardLifecycle::new(current.clone());
    advance_to_containment(&mut lifecycle, &current, SessionId::new());
    assert_eq!(
        lifecycle.apply(&current, PreparedShardTransition::ReleaseIntentRecorded),
        Ok(TransitionOutcome::Applied)
    );

    assert!(matches!(
        lifecycle.apply(
            &stale,
            PreparedShardTransition::ReleaseTokenSent {
                release_sequence: 41,
            },
        ),
        Err(PreparedShardTransitionError::FenceMismatch { .. })
    ));
    assert_eq!(lifecycle.state(), PreparedShardState::ReleaseIntent);
    assert_eq!(lifecycle.release_sequence(), None);

    assert_eq!(
        lifecycle.apply(
            &current,
            PreparedShardTransition::ReleaseTokenSent {
                release_sequence: 41,
            },
        ),
        Ok(TransitionOutcome::Applied)
    );
    assert_eq!(lifecycle.state(), PreparedShardState::Released);
    assert_eq!(lifecycle.release_sequence(), Some(41));
}

#[test]
fn every_shard_fence_dimension_is_required_and_rejections_are_read_only() {
    let shard_id = ShardId::new();
    let current = shard_fence("worker-a", 9, shard_id.clone(), 2);
    let stale_fences = [
        shard_fence("worker-b", 9, shard_id.clone(), 2),
        shard_fence("worker-a", 8, shard_id.clone(), 2),
        shard_fence("worker-a", 9, ShardId::new(), 2),
        shard_fence("worker-a", 9, shard_id, 1),
    ];
    let mut lifecycle = PreparedShardLifecycle::new(current.clone());

    for stale in stale_fences {
        assert!(matches!(
            lifecycle.apply(&stale, PreparedShardTransition::FilesystemCgroupReady),
            Err(PreparedShardTransitionError::FenceMismatch { .. })
        ));
        assert_eq!(lifecycle.state(), PreparedShardState::Reserved);
    }

    assert_eq!(lifecycle.fence(), &current);
}

#[test]
fn duplicate_transitions_are_idempotent_but_conflicting_evidence_is_rejected() {
    let fence = shard_fence("worker-a", 9, ShardId::new(), 1);
    let mut lifecycle = PreparedShardLifecycle::new(fence.clone());

    assert_eq!(
        lifecycle.apply(&fence, PreparedShardTransition::FilesystemCgroupReady),
        Ok(TransitionOutcome::Applied)
    );
    assert_eq!(
        lifecycle.apply(&fence, PreparedShardTransition::FilesystemCgroupReady),
        Ok(TransitionOutcome::AlreadyApplied)
    );

    advance_to_containment(&mut lifecycle, &fence, SessionId::new());
    assert_eq!(
        lifecycle.apply(&fence, PreparedShardTransition::ReleaseIntentRecorded),
        Ok(TransitionOutcome::Applied)
    );
    assert_eq!(
        lifecycle.apply(
            &fence,
            PreparedShardTransition::ReleaseTokenSent {
                release_sequence: 7,
            },
        ),
        Ok(TransitionOutcome::Applied)
    );
    assert_eq!(
        lifecycle.apply(
            &fence,
            PreparedShardTransition::ReleaseTokenSent {
                release_sequence: 7,
            },
        ),
        Ok(TransitionOutcome::AlreadyApplied)
    );
    assert_eq!(
        lifecycle.apply(
            &fence,
            PreparedShardTransition::ReleaseTokenSent {
                release_sequence: 8,
            },
        ),
        Err(PreparedShardTransitionError::ConflictingReleaseSequence {
            recorded: 7,
            received: 8,
        })
    );
}

#[test]
fn egress_registration_is_bound_to_the_exact_shard_and_is_immutable() {
    let fence = shard_fence("worker-a", 9, ShardId::new(), 1);
    let foreign = shard_fence("worker-a", 9, ShardId::new(), 1);
    let mut lifecycle = PreparedShardLifecycle::new(fence.clone());
    for transition in [
        PreparedShardTransition::FilesystemCgroupReady,
        PreparedShardTransition::ChildGated,
        PreparedShardTransition::ProcessIdentityProven,
        PreparedShardTransition::CgroupAttached,
        PreparedShardTransition::NetnsIdentityProven,
    ] {
        lifecycle
            .apply(&fence, transition)
            .expect("preparation transition must succeed");
    }
    let wrong = EgressFence::new(
        foreign,
        RouteGeneration::new(1).expect("route generation must be positive"),
        SessionId::new(),
        SessionIncarnation::new(1).expect("session incarnation must be positive"),
    );

    assert!(matches!(
        lifecycle.apply(&fence, PreparedShardTransition::IngressRegistered(wrong),),
        Err(PreparedShardTransitionError::EgressFenceMismatch)
    ));
    assert_eq!(lifecycle.state(), PreparedShardState::NetnsIdentityProven);

    let registered = EgressFence::new(
        fence.clone(),
        RouteGeneration::new(2).expect("route generation must be positive"),
        SessionId::new(),
        SessionIncarnation::new(1).expect("session incarnation must be positive"),
    );
    assert_eq!(
        lifecycle.apply(
            &fence,
            PreparedShardTransition::IngressRegistered(registered.clone()),
        ),
        Ok(TransitionOutcome::Applied)
    );
    assert_eq!(lifecycle.egress_fence(), Some(&registered));

    let replacement = EgressFence::new(
        fence.clone(),
        RouteGeneration::new(3).expect("route generation must be positive"),
        SessionId::new(),
        SessionIncarnation::new(1).expect("session incarnation must be positive"),
    );
    assert_eq!(
        lifecycle.apply(
            &fence,
            PreparedShardTransition::IngressRegistered(replacement),
        ),
        Err(PreparedShardTransitionError::ConflictingEgressFence)
    );
    assert_eq!(lifecycle.egress_fence(), Some(&registered));
}

#[test]
fn revoke_linearizes_against_release_and_cleanup_is_irreversible() {
    let fence = shard_fence("worker-a", 9, ShardId::new(), 1);
    let mut lifecycle = PreparedShardLifecycle::new(fence.clone());
    advance_to_containment(&mut lifecycle, &fence, SessionId::new());
    assert_eq!(
        lifecycle.apply(&fence, PreparedShardTransition::ReleaseIntentRecorded),
        Ok(TransitionOutcome::Applied)
    );

    assert_eq!(
        lifecycle.apply(&fence, PreparedShardTransition::RevokeStarted),
        Ok(TransitionOutcome::Applied)
    );
    assert_eq!(lifecycle.state(), PreparedShardState::Revoking);
    assert!(matches!(
        lifecycle.apply(
            &fence,
            PreparedShardTransition::ReleaseTokenSent {
                release_sequence: 1,
            },
        ),
        Err(PreparedShardTransitionError::ReleaseForbidden { .. })
    ));

    for (transition, expected_state) in [
        (
            PreparedShardTransition::GateAbortStarted,
            PreparedShardState::AbortingGate,
        ),
        (
            PreparedShardTransition::CgroupKillStarted,
            PreparedShardState::Killing,
        ),
        (
            PreparedShardTransition::CleanupStarted,
            PreparedShardState::Cleaning,
        ),
        (
            PreparedShardTransition::CleanupCompleted,
            PreparedShardState::ReleasedTombstone,
        ),
    ] {
        assert_eq!(
            lifecycle.apply(&fence, transition),
            Ok(TransitionOutcome::Applied)
        );
        assert_eq!(lifecycle.state(), expected_state);
    }

    assert!(matches!(
        lifecycle.apply(&fence, PreparedShardTransition::FilesystemCgroupReady),
        Err(PreparedShardTransitionError::InvalidTransition { .. })
    ));
    assert_eq!(lifecycle.state(), PreparedShardState::ReleasedTombstone);
}

#[test]
fn fence_generations_are_positive_and_serialize_as_numbers() {
    assert!(WorkerEpoch::new(0).is_none());
    assert!(LaunchGeneration::new(0).is_none());
    assert!(RouteGeneration::new(0).is_none());
    assert!(SessionIncarnation::new(0).is_none());

    let encoded = serde_json::to_string(
        &LaunchGeneration::new(17).expect("launch generation must be positive"),
    )
    .expect("generation must serialize");
    assert_eq!(encoded, "17");
}
