#![allow(clippy::expect_used)]

mod common;

use std::sync::Arc;

use browserd_artifacts::{
    ArtifactQuota, QuotaError, QuotaLimits, ReservationAbortOutcome, ReservationCommitOutcome,
};
use tokio::sync::Barrier;

use common::{artifact_fixture, artifact_key};

#[tokio::test]
async fn reservation_tracks_actual_bytes_and_converts_only_actual_bytes_to_committed() {
    let fixture = artifact_fixture();
    let quota = ArtifactQuota::new(
        fixture.namespace,
        QuotaLimits {
            max_committed_bytes: 100,
            max_in_flight_bytes: 100,
        },
    );
    let reservation = quota
        .reserve(fixture.key, 60)
        .await
        .expect("reservation within limits should succeed");

    assert_eq!(quota.snapshot().await.reserved_bytes, 60);
    assert_eq!(quota.snapshot().await.actual_bytes_in_flight, 0);

    reservation
        .add_actual_bytes(40)
        .await
        .expect("actual bytes within reservation should succeed");
    let during = quota.snapshot().await;
    assert_eq!(during.reserved_bytes, 60);
    assert_eq!(during.actual_bytes_in_flight, 40);
    assert_eq!(during.committed_bytes, 0);

    assert_eq!(
        reservation
            .commit()
            .await
            .expect("first commit should succeed"),
        ReservationCommitOutcome::Committed
    );
    assert_eq!(
        reservation
            .commit()
            .await
            .expect("duplicate commit should be idempotent"),
        ReservationCommitOutcome::AlreadyCommitted
    );

    let after = quota.snapshot().await;
    assert_eq!(after.reserved_bytes, 0);
    assert_eq!(after.actual_bytes_in_flight, 0);
    assert_eq!(after.committed_bytes, 40);
    assert_eq!(after.active_reservations, 0);
}

#[tokio::test]
async fn actual_bytes_cannot_grow_past_the_reserved_hard_limit() {
    let fixture = artifact_fixture();
    let quota = ArtifactQuota::new(
        fixture.namespace,
        QuotaLimits {
            max_committed_bytes: 100,
            max_in_flight_bytes: 100,
        },
    );
    let reservation = quota
        .reserve(fixture.key, 10)
        .await
        .expect("reservation within limits should succeed");

    reservation
        .add_actual_bytes(8)
        .await
        .expect("actual bytes within reservation should succeed");
    assert!(matches!(
        reservation.add_actual_bytes(3).await,
        Err(QuotaError::HardLimitExceeded { .. })
    ));
    assert_eq!(quota.snapshot().await.actual_bytes_in_flight, 8);

    assert_eq!(
        reservation
            .abort()
            .await
            .expect("first abort should succeed"),
        ReservationAbortOutcome::Aborted
    );
    assert_eq!(
        reservation
            .abort()
            .await
            .expect("duplicate abort should be idempotent"),
        ReservationAbortOutcome::AlreadyAborted
    );
    assert_eq!(quota.snapshot().await.reserved_bytes, 0);
    assert_eq!(quota.snapshot().await.actual_bytes_in_flight, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_reservations_never_oversubscribe_the_hard_limit() {
    const ATTEMPTS: usize = 16;

    let fixture = artifact_fixture();
    let namespace = fixture.namespace;
    let quota = Arc::new(ArtifactQuota::new(
        namespace.clone(),
        QuotaLimits {
            max_committed_bytes: 100,
            max_in_flight_bytes: 100,
        },
    ));
    let start = Arc::new(Barrier::new(ATTEMPTS + 1));
    let mut tasks = Vec::with_capacity(ATTEMPTS);

    for _ in 0..ATTEMPTS {
        let quota = quota.clone();
        let start = start.clone();
        let key = artifact_key(&namespace);
        tasks.push(tokio::spawn(async move {
            start.wait().await;
            quota.reserve(key, 30).await
        }));
    }

    start.wait().await;

    let mut reservations = Vec::new();
    let mut denials = 0;
    for task in tasks {
        match task.await.expect("reservation task should not panic") {
            Ok(reservation) => reservations.push(reservation),
            Err(error) => {
                assert!(
                    matches!(error, QuotaError::HardLimitExceeded { .. }),
                    "unexpected reservation error: {error:?}"
                );
                denials += 1;
            }
        }
    }

    assert_eq!(reservations.len(), 3);
    assert_eq!(denials, ATTEMPTS - 3);
    assert_eq!(quota.snapshot().await.reserved_bytes, 90);

    for reservation in reservations {
        reservation
            .abort()
            .await
            .expect("successful reservation should abort cleanly");
    }
    assert_eq!(quota.snapshot().await.reserved_bytes, 0);
}

#[tokio::test]
async fn committed_capacity_is_reserved_before_a_writer_can_start() {
    let fixture = artifact_fixture();
    let namespace = fixture.namespace;
    let quota = ArtifactQuota::new(
        namespace.clone(),
        QuotaLimits {
            max_committed_bytes: 100,
            max_in_flight_bytes: 100,
        },
    );

    let first = quota
        .reserve(fixture.key, 60)
        .await
        .expect("first reservation should succeed");
    first
        .add_actual_bytes(40)
        .await
        .expect("first actual byte count should fit");
    first.commit().await.expect("first commit should succeed");

    let second = quota
        .reserve(artifact_key(&namespace), 60)
        .await
        .expect("remaining committed capacity should be reservable");
    second
        .add_actual_bytes(60)
        .await
        .expect("second actual byte count should fit");
    second
        .commit()
        .await
        .expect("second commit should fill capacity");
    assert_eq!(quota.snapshot().await.committed_bytes, 100);

    assert!(matches!(
        quota.reserve(artifact_key(&namespace), 1).await,
        Err(QuotaError::HardLimitExceeded { .. })
    ));
}
