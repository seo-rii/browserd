#![allow(clippy::expect_used, clippy::panic)]

use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

use browserd_core::WorkerId;
use browserd_fleet::{
    CompatibilityKey, DirectoryTime, RegisterWorkerOutcome, ResourceVector, WorkerAdvertisement,
    WorkerDirectory, WorkerDirectoryError, WorkerHeartbeat,
};

fn advertisement(epoch: u64) -> WorkerAdvertisement {
    WorkerAdvertisement::new(
        WorkerId::new("worker-a").expect("worker ID should be valid"),
        epoch,
        "ap-northeast-2",
        "browserd-1",
        vec![CompatibilityKey::new("chromium-1:policy-4")],
        ResourceVector::new(8_000, 8_000, 800, 80_000, 80, 800),
        ResourceVector::new(7_000, 7_000, 700, 70_000, 70, 700),
        0,
        true,
    )
    .expect("advertisement should be valid")
}

#[test]
fn racing_process_epochs_never_move_worker_ownership_backwards() {
    for _ in 0..128 {
        let directory = Arc::new(
            WorkerDirectory::new(Duration::from_secs(30)).expect("lease policy should be valid"),
        );
        let start = Arc::new(Barrier::new(3));
        let mut handles = Vec::new();
        for epoch in [7, 8] {
            let directory = Arc::clone(&directory);
            let start = Arc::clone(&start);
            handles.push(thread::spawn(move || {
                start.wait();
                directory.register(advertisement(epoch), DirectoryTime::from_millis(10))
            }));
        }
        start.wait();
        let outcomes = handles
            .into_iter()
            .map(|handle| handle.join().expect("registration thread should not panic"))
            .collect::<Vec<_>>();
        assert!(outcomes.iter().any(Result::is_ok));

        let current = directory
            .lookup_ready(
                &WorkerId::new("worker-a").expect("worker ID should be valid"),
                DirectoryTime::from_millis(11),
            )
            .expect("highest epoch should be routable");
        assert_eq!(current.worker_epoch(), 8);
        assert!(matches!(
            directory.register(advertisement(7), DirectoryTime::from_millis(12)),
            Err(WorkerDirectoryError::StaleWorkerEpoch {
                current: 8,
                proposed: 7
            })
        ));
    }
}

#[test]
fn identical_registration_is_idempotent_but_never_renews_a_lease() {
    let directory =
        WorkerDirectory::new(Duration::from_millis(100)).expect("lease policy should be valid");
    let first = directory
        .register(advertisement(7), DirectoryTime::from_millis(10))
        .expect("first registration should succeed");
    let repeated = directory
        .register(advertisement(7), DirectoryTime::from_millis(50))
        .expect("identical registration should be idempotent");
    assert!(matches!(&first, RegisterWorkerOutcome::Registered(_)));
    assert!(matches!(&repeated, RegisterWorkerOutcome::Existing(_)));
    assert_eq!(first.into_snapshot(), repeated.into_snapshot());
    assert_eq!(
        directory.lookup_ready(
            &WorkerId::new("worker-a").expect("worker ID should be valid"),
            DirectoryTime::from_millis(110),
        ),
        Err(WorkerDirectoryError::LeaseExpired)
    );
}

#[test]
fn heartbeat_and_expiry_sweep_are_linearizable_and_stale_epoch_cannot_revive() {
    for _ in 0..128 {
        let directory = Arc::new(
            WorkerDirectory::new(Duration::from_millis(100)).expect("lease policy should be valid"),
        );
        directory
            .register(advertisement(7), DirectoryTime::from_millis(0))
            .expect("registration should succeed");
        let start = Arc::new(Barrier::new(3));

        let heartbeat_directory = Arc::clone(&directory);
        let heartbeat_start = Arc::clone(&start);
        let heartbeat = thread::spawn(move || {
            heartbeat_start.wait();
            heartbeat_directory.heartbeat(
                &WorkerId::new("worker-a").expect("worker ID should be valid"),
                7,
                WorkerHeartbeat::new(
                    ResourceVector::new(6_000, 6_000, 600, 60_000, 60, 600),
                    3,
                    2,
                    true,
                )
                .expect("heartbeat should be valid"),
                DirectoryTime::from_millis(99),
            )
        });

        let sweep_directory = Arc::clone(&directory);
        let sweep_start = Arc::clone(&start);
        let sweep = thread::spawn(move || {
            sweep_start.wait();
            sweep_directory.expire_workers(DirectoryTime::from_millis(100), 1)
        });

        start.wait();
        let heartbeat = heartbeat.join().expect("heartbeat thread should not panic");
        let expired = sweep
            .join()
            .expect("sweep thread should not panic")
            .expect("sweep should succeed");
        match heartbeat {
            Ok(snapshot) => {
                assert!(expired.is_empty());
                assert_eq!(snapshot.worker_epoch(), 7);
                assert_eq!(snapshot.queue_depth(), 3);
            }
            Err(WorkerDirectoryError::NotOwned) => assert_eq!(expired.len(), 1),
            outcome => panic!("non-linearizable heartbeat/sweep outcome: {outcome:?}"),
        }

        directory
            .register(advertisement(8), DirectoryTime::from_millis(101))
            .expect("new process epoch should replace the tombstone");
        assert_eq!(
            directory.heartbeat(
                &WorkerId::new("worker-a").expect("worker ID should be valid"),
                7,
                WorkerHeartbeat::new(ResourceVector::ZERO, 0, 0, true)
                    .expect("heartbeat should be valid"),
                DirectoryTime::from_millis(102),
            ),
            Err(WorkerDirectoryError::EpochMismatch {
                current: 8,
                received: 7,
            })
        );
    }
}

#[test]
fn expired_epoch_is_a_tombstone_and_unready_or_overcapacity_workers_do_not_route() {
    let directory =
        WorkerDirectory::new(Duration::from_millis(50)).expect("lease policy should be valid");
    directory
        .register(advertisement(7), DirectoryTime::from_millis(10))
        .expect("registration should succeed");
    assert_eq!(
        directory.register(advertisement(7), DirectoryTime::from_millis(60)),
        Err(WorkerDirectoryError::LeaseExpired)
    );

    directory
        .register(advertisement(8), DirectoryTime::from_millis(61))
        .expect("higher epoch should replace expired ownership");
    directory
        .heartbeat(
            &WorkerId::new("worker-a").expect("worker ID should be valid"),
            8,
            WorkerHeartbeat::new(
                ResourceVector::new(7_000, 7_000, 700, 70_000, 70, 700),
                0,
                0,
                false,
            )
            .expect("heartbeat should be valid"),
            DirectoryTime::from_millis(62),
        )
        .expect("heartbeat should update readiness");
    assert_eq!(
        directory.lookup_ready(
            &WorkerId::new("worker-a").expect("worker ID should be valid"),
            DirectoryTime::from_millis(63),
        ),
        Err(WorkerDirectoryError::NotReady)
    );

    assert!(
        WorkerAdvertisement::new(
            WorkerId::new("worker-b").expect("worker ID should be valid"),
            1,
            "",
            "browserd-1",
            Vec::new(),
            ResourceVector::ZERO,
            ResourceVector::new(1, 0, 0, 0, 0, 0),
            0,
            true,
        )
        .is_err()
    );
}
