#![allow(clippy::expect_used, clippy::panic)]

use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

use browserd_core::{SessionId, ShardId, TenantId, WorkerId};
use browserd_fleet::{
    AttachOutcome, DirectoryError, DirectoryTime, SessionAttachment, SessionDirectory,
};

fn attachment() -> SessionAttachment {
    SessionAttachment::new(
        TenantId::new(),
        SessionId::new(),
        WorkerId::new("worker-a").expect("worker ID should be valid"),
        7,
        ShardId::new(),
        3,
    )
    .expect("attachment should be valid")
}

#[test]
fn concurrent_identical_attach_has_one_linearization_point_and_one_receipt() {
    let directory = Arc::new(
        SessionDirectory::new(Duration::from_secs(30)).expect("lease policy should be valid"),
    );
    let attachment = attachment();
    let start = Arc::new(Barrier::new(17));
    let mut handles = Vec::new();

    for _ in 0..16 {
        let directory = Arc::clone(&directory);
        let attachment = attachment.clone();
        let start = Arc::clone(&start);
        handles.push(thread::spawn(move || {
            start.wait();
            directory.attach(attachment, DirectoryTime::from_millis(10))
        }));
    }
    start.wait();

    let mut created = 0;
    let mut snapshots = Vec::new();
    for handle in handles {
        let outcome = handle.join().expect("attach thread should not panic");
        match outcome.expect("identical attachment should be idempotent") {
            AttachOutcome::Created(snapshot) => {
                created += 1;
                snapshots.push(snapshot);
            }
            AttachOutcome::Existing(snapshot) => snapshots.push(snapshot),
        }
    }

    assert_eq!(created, 1);
    assert_eq!(snapshots.len(), 16);
    assert!(snapshots.windows(2).all(|pair| pair[0] == pair[1]));
    assert_eq!(snapshots[0].placement_version(), 1);
    assert_eq!(
        snapshots[0].lease_expires_at(),
        DirectoryTime::from_millis(30_010)
    );
}

#[test]
fn conflicting_attach_and_stale_fences_fail_closed() {
    let directory =
        SessionDirectory::new(Duration::from_secs(30)).expect("lease policy should be valid");
    let attachment = attachment();
    let created = directory
        .attach(attachment.clone(), DirectoryTime::from_millis(10))
        .expect("first attachment should succeed")
        .into_snapshot();

    let mut conflicting = attachment.clone();
    conflicting = SessionAttachment::new(
        conflicting.tenant_id().clone(),
        conflicting.session_id().clone(),
        WorkerId::new("worker-b").expect("worker ID should be valid"),
        8,
        conflicting.shard_id().clone(),
        conflicting.session_incarnation(),
    )
    .expect("conflicting attachment should still be structurally valid");
    assert_eq!(
        directory.attach(conflicting, DirectoryTime::from_millis(11)),
        Err(DirectoryError::PlacementConflict)
    );

    let mut stale_fence = created.fence();
    stale_fence.worker_epoch = stale_fence.worker_epoch.saturating_sub(1);
    assert_eq!(
        directory.renew(
            created.tenant_id(),
            created.session_id(),
            &stale_fence,
            DirectoryTime::from_millis(20),
        ),
        Err(DirectoryError::FenceMismatch)
    );
}

#[test]
fn lease_renewal_and_expiry_sweep_are_linearizable_under_race() {
    for _ in 0..128 {
        let directory = Arc::new(
            SessionDirectory::new(Duration::from_millis(100))
                .expect("lease policy should be valid"),
        );
        let attachment = attachment();
        let created = directory
            .attach(attachment, DirectoryTime::from_millis(0))
            .expect("attachment should succeed")
            .into_snapshot();
        let fence = created.fence();
        let start = Arc::new(Barrier::new(3));

        let renew_directory = Arc::clone(&directory);
        let renew_tenant = created.tenant_id().clone();
        let renew_session = created.session_id().clone();
        let renew_start = Arc::clone(&start);
        let renew = thread::spawn(move || {
            renew_start.wait();
            renew_directory.renew(
                &renew_tenant,
                &renew_session,
                &fence,
                DirectoryTime::from_millis(99),
            )
        });

        let sweep_directory = Arc::clone(&directory);
        let sweep_start = Arc::clone(&start);
        let sweep = thread::spawn(move || {
            sweep_start.wait();
            sweep_directory.expire_leases(DirectoryTime::from_millis(100), 1)
        });

        start.wait();
        let renewed = renew.join().expect("renew thread should not panic");
        let expired = sweep
            .join()
            .expect("sweep thread should not panic")
            .expect("sweep should complete");

        match renewed {
            Ok(snapshot) => {
                assert!(expired.is_empty());
                assert_eq!(
                    directory.lookup(
                        snapshot.tenant_id(),
                        snapshot.session_id(),
                        DirectoryTime::from_millis(100),
                    ),
                    Ok(snapshot)
                );
            }
            Err(DirectoryError::PlacementNotAttached) => {
                assert_eq!(expired.len(), 1);
                assert_eq!(
                    directory.lookup(
                        created.tenant_id(),
                        created.session_id(),
                        DirectoryTime::from_millis(100),
                    ),
                    Err(DirectoryError::PlacementNotAttached)
                );
            }
            outcome => panic!("non-linearizable renew/sweep outcome: {outcome:?}"),
        }
    }
}

#[test]
fn expired_routes_never_route_before_or_after_bounded_sweep() {
    let directory =
        SessionDirectory::new(Duration::from_millis(50)).expect("lease policy should be valid");
    let first = directory
        .attach(attachment(), DirectoryTime::from_millis(10))
        .expect("first attachment should succeed")
        .into_snapshot();
    let second = directory
        .attach(attachment(), DirectoryTime::from_millis(10))
        .expect("second attachment should succeed")
        .into_snapshot();

    assert_eq!(
        directory.lookup(
            first.tenant_id(),
            first.session_id(),
            DirectoryTime::from_millis(60),
        ),
        Err(DirectoryError::LeaseExpired)
    );
    let expired = directory
        .expire_leases(DirectoryTime::from_millis(60), 1)
        .expect("bounded sweep should succeed");
    assert_eq!(expired.len(), 1);

    let first_result = directory.lookup(
        first.tenant_id(),
        first.session_id(),
        DirectoryTime::from_millis(60),
    );
    let second_result = directory.lookup(
        second.tenant_id(),
        second.session_id(),
        DirectoryTime::from_millis(60),
    );
    assert!(matches!(
        (first_result, second_result),
        (
            Err(DirectoryError::PlacementNotAttached),
            Err(DirectoryError::LeaseExpired)
        ) | (
            Err(DirectoryError::LeaseExpired),
            Err(DirectoryError::PlacementNotAttached)
        )
    ));

    assert_eq!(
        directory.expire_leases(DirectoryTime::from_millis(60), 0),
        Err(DirectoryError::InvalidLimit)
    );
}

#[test]
fn exact_worker_epoch_revocation_is_bounded_and_dominates_concurrent_renewal() {
    for _ in 0..128 {
        let directory = Arc::new(
            SessionDirectory::new(Duration::from_secs(30)).expect("lease policy should be valid"),
        );
        let attachment = attachment();
        let worker_id = attachment.worker_id().clone();
        let created = directory
            .attach(attachment, DirectoryTime::from_millis(10))
            .expect("attachment should succeed")
            .into_snapshot();
        let fence = created.fence();
        let start = Arc::new(Barrier::new(3));

        assert!(
            directory
                .revoke_worker(&worker_id, 6, 1)
                .expect("stale epoch lookup should be safe")
                .is_empty()
        );

        let renew_directory = Arc::clone(&directory);
        let renew_tenant = created.tenant_id().clone();
        let renew_session = created.session_id().clone();
        let renew_start = Arc::clone(&start);
        let renew = thread::spawn(move || {
            renew_start.wait();
            renew_directory.renew(
                &renew_tenant,
                &renew_session,
                &fence,
                DirectoryTime::from_millis(20),
            )
        });

        let revoke_directory = Arc::clone(&directory);
        let revoke_worker = worker_id.clone();
        let revoke_start = Arc::clone(&start);
        let revoke = thread::spawn(move || {
            revoke_start.wait();
            revoke_directory.revoke_worker(&revoke_worker, 7, 1)
        });

        start.wait();
        let renewed = renew.join().expect("renew thread should not panic");
        let revoked = revoke
            .join()
            .expect("revoke thread should not panic")
            .expect("worker revocation should succeed");
        assert_eq!(revoked.len(), 1);
        assert!(matches!(
            renewed,
            Ok(_) | Err(DirectoryError::PlacementNotAttached)
        ));
        assert_eq!(
            directory.lookup(
                created.tenant_id(),
                created.session_id(),
                DirectoryTime::from_millis(21),
            ),
            Err(DirectoryError::PlacementNotAttached)
        );
    }

    let directory =
        SessionDirectory::new(Duration::from_secs(30)).expect("lease policy should be valid");
    assert_eq!(
        directory.revoke_worker(
            &WorkerId::new("worker-a").expect("worker ID should be valid"),
            7,
            0,
        ),
        Err(DirectoryError::InvalidLimit)
    );
    assert_eq!(
        directory.revoke_worker(
            &WorkerId::new("worker-a").expect("worker ID should be valid"),
            0,
            1,
        ),
        Err(DirectoryError::InvalidWorkerEpoch)
    );
}
