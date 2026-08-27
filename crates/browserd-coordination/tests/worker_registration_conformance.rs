#![allow(clippy::expect_used)]

use std::sync::Arc;
use std::time::Duration;

use browserd_coordination::{
    EphemeralCoordinationError, ManualCoordinationClock, MemoryEphemeralCoordinationStore,
    WorkerCapacity, WorkerHeartbeat, WorkerLeaseMutation, WorkerLeaseStore, WorkerReadiness,
    WorkerRegistration, WorkerRegistrationQuery, WorkerRegistrationSnapshot,
};
use browserd_core::WorkerId;
use tokio::sync::Barrier;

fn capacity(memory_bytes: u64) -> WorkerCapacity {
    WorkerCapacity::new(memory_bytes, 2_000, 64, 10_000, 8, 32)
}

fn registration(worker_epoch: u64) -> WorkerRegistration {
    WorkerRegistration::new(
        WorkerId::new("worker-registration-conformance").expect("worker id should validate"),
        worker_epoch,
        "ap-northeast-2",
        "browserd-2026.08",
        vec!["chromium-140".to_owned(), "websocket-v1".to_owned()],
        capacity(16_000),
        "worker-rpc://10.0.0.7:7443",
    )
    .expect("registration should validate")
}

fn heartbeat(free_memory: u64, readiness: WorkerReadiness) -> WorkerHeartbeat {
    WorkerHeartbeat::new(capacity(free_memory), 2, 3, readiness).expect("heartbeat should validate")
}

#[tokio::test]
async fn epoch_takeover_is_atomic_and_fences_old_snapshot_cas() {
    let clock = ManualCoordinationClock::new();
    let store = MemoryEphemeralCoordinationStore::new(clock);
    let old = store
        .register_worker(
            registration(7),
            heartbeat(8_000, WorkerReadiness::Ready),
            Duration::from_secs(30),
        )
        .await
        .expect("registration should work")
        .into_snapshot()
        .expect("registration should return its snapshot");

    assert_eq!(
        store
            .register_worker(
                registration(6),
                heartbeat(8_000, WorkerReadiness::Ready),
                Duration::from_secs(30),
            )
            .await
            .expect("stale epoch should be a fenced outcome"),
        WorkerLeaseMutation::FenceMismatch
    );
    let current = store
        .register_worker(
            registration(8),
            heartbeat(7_000, WorkerReadiness::Ready),
            Duration::from_secs(30),
        )
        .await
        .expect("higher epoch should take ownership")
        .into_snapshot()
        .expect("takeover should return its snapshot");
    assert_eq!(current.worker_epoch(), 8);
    assert_eq!(
        store
            .heartbeat_worker(
                &old,
                heartbeat(6_000, WorkerReadiness::Draining),
                Duration::from_secs(30),
            )
            .await
            .expect("stale heartbeat should be a fenced outcome"),
        WorkerLeaseMutation::FenceMismatch
    );
}

#[tokio::test]
async fn same_epoch_retry_is_idempotent_only_for_exact_immutable_identity() {
    let clock = ManualCoordinationClock::new();
    let store = MemoryEphemeralCoordinationStore::new(clock);
    let immutable = registration(11);
    store
        .register_worker(
            immutable.clone(),
            heartbeat(8_000, WorkerReadiness::Ready),
            Duration::from_secs(30),
        )
        .await
        .expect("registration should work");
    assert_eq!(
        store
            .register_worker(
                immutable,
                heartbeat(7_000, WorkerReadiness::Draining),
                Duration::from_secs(30),
            )
            .await
            .expect("exact retry should be idempotent"),
        WorkerLeaseMutation::AlreadyApplied
    );

    let drifted = WorkerRegistration::new(
        WorkerId::new("worker-registration-conformance").expect("worker id should validate"),
        11,
        "ap-northeast-2",
        "browserd-2026.08",
        vec!["chromium-140".to_owned()],
        capacity(16_000),
        "worker-rpc://10.0.0.8:7443",
    )
    .expect("drift fixture should validate");
    assert_eq!(
        store
            .register_worker(
                drifted,
                heartbeat(8_000, WorkerReadiness::Ready),
                Duration::from_secs(30),
            )
            .await
            .expect("same epoch drift should be fenced"),
        WorkerLeaseMutation::FenceMismatch
    );
}

#[tokio::test]
async fn concurrent_heartbeat_cas_has_one_winner_and_enforces_capacity() {
    let clock = ManualCoordinationClock::new();
    let store = Arc::new(MemoryEphemeralCoordinationStore::new(clock));
    let snapshot = store
        .register_worker(
            registration(5),
            heartbeat(8_000, WorkerReadiness::Ready),
            Duration::from_secs(30),
        )
        .await
        .expect("registration should work")
        .into_snapshot()
        .expect("registration should return its snapshot");
    let barrier = Arc::new(Barrier::new(3));
    let mut tasks = Vec::new();
    for free in [6_000, 7_000] {
        let store = Arc::clone(&store);
        let barrier = Arc::clone(&barrier);
        let snapshot = snapshot.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store
                .heartbeat_worker(
                    &snapshot,
                    heartbeat(free, WorkerReadiness::Ready),
                    Duration::from_secs(30),
                )
                .await
        }));
    }
    barrier.wait().await;
    let mut applied = 0;
    let mut stale = 0;
    let mut unexpected = 0;
    for task in tasks {
        match task
            .await
            .expect("task should join")
            .expect("CAS should run")
        {
            WorkerLeaseMutation::Applied(_) => applied += 1,
            WorkerLeaseMutation::CasMismatch => stale += 1,
            _ => unexpected += 1,
        }
    }
    assert_eq!((applied, stale), (1, 1));
    assert_eq!(unexpected, 0);
    assert_eq!(
        store
            .heartbeat_worker(
                &snapshot,
                heartbeat(16_001, WorkerReadiness::Ready),
                Duration::from_secs(30),
            )
            .await,
        Err(EphemeralCoordinationError::InvalidInput),
        "free resources cannot exceed the registered capacity",
    );
}

#[tokio::test]
async fn ready_query_is_bounded_and_excludes_expired_or_draining_workers() {
    let clock = ManualCoordinationClock::new();
    let store = MemoryEphemeralCoordinationStore::new(clock.clone());
    store
        .register_worker(
            registration(3),
            heartbeat(8_000, WorkerReadiness::Ready),
            Duration::from_millis(5),
        )
        .await
        .expect("registration should work");
    let query = WorkerRegistrationQuery::new("ap-northeast-2", "chromium-140", 8)
        .expect("query should validate");
    assert_eq!(
        store
            .query_ready_workers(&query)
            .await
            .expect("query should work")
            .len(),
        1
    );
    clock.advance(Duration::from_millis(5));
    assert!(
        store
            .query_ready_workers(&query)
            .await
            .expect("expired lookup should work")
            .is_empty()
    );
    assert!(WorkerRegistrationQuery::new("ap-northeast-2", "chromium-140", 0).is_err());
}

#[tokio::test]
async fn expired_lease_keeps_the_worker_epoch_high_water_mark() {
    let clock = ManualCoordinationClock::new();
    let store = MemoryEphemeralCoordinationStore::new(clock.clone());
    store
        .register_worker(
            registration(7),
            heartbeat(8_000, WorkerReadiness::Ready),
            Duration::from_millis(5),
        )
        .await
        .expect("registration should work");
    clock.advance(Duration::from_millis(5));

    assert_eq!(
        store
            .register_worker(
                registration(6),
                heartbeat(8_000, WorkerReadiness::Ready),
                Duration::from_secs(30),
            )
            .await
            .expect("stale epoch should be a fenced outcome"),
        WorkerLeaseMutation::FenceMismatch
    );
    assert!(
        store
            .register_worker(
                registration(8),
                heartbeat(8_000, WorkerReadiness::Ready),
                Duration::from_secs(30),
            )
            .await
            .expect("higher epoch should take over")
            .into_snapshot()
            .is_ok()
    );
}

#[test]
fn typed_worker_wire_and_input_bounds_fail_closed() {
    assert!(
        WorkerRegistration::new(
            WorkerId::new("worker-registration-conformance").expect("worker id should validate"),
            0,
            "ap-northeast-2",
            "release",
            vec!["compat".to_owned()],
            capacity(1),
            "worker-rpc://endpoint",
        )
        .is_err()
    );
    assert!(
        WorkerRegistration::new(
            WorkerId::new("worker-registration-conformance").expect("worker id should validate"),
            1,
            "ap-northeast-2",
            "release",
            vec!["compat".to_owned(); 129],
            capacity(1),
            "worker-rpc://endpoint",
        )
        .is_err()
    );
    assert!(
        WorkerRegistration::new(
            WorkerId::new("worker-registration-conformance").expect("worker id should validate"),
            1,
            "ap-northeast-2",
            "release",
            vec!["compat".to_owned()],
            capacity(1),
            "worker-rpc://bad\nendpoint",
        )
        .is_err()
    );
    assert!(WorkerRegistrationQuery::new("ap-northeast-2", "chromium-140", 10_000).is_err());
    assert!(
        WorkerRegistration::new(
            WorkerId::new("worker-registration-conformance").expect("worker id should validate"),
            1,
            "bad\nregion",
            "release",
            vec!["compat".to_owned()],
            capacity(1),
            "worker-rpc://endpoint",
        )
        .is_err()
    );

    let mut wire = serde_json::to_value(registration(1)).expect("registration should serialize");
    wire["worker_epoch"] = serde_json::json!(0);
    assert!(serde_json::from_value::<WorkerRegistration>(wire).is_err());
    let mut wire = serde_json::to_value(registration(1)).expect("registration should serialize");
    wire["unexpected"] = serde_json::json!(true);
    assert!(serde_json::from_value::<WorkerRegistration>(wire).is_err());
    let mut snapshot = serde_json::to_value(
        WorkerRegistrationSnapshot::from_persisted(
            registration(1),
            heartbeat(1, WorkerReadiness::Ready),
            1,
            10,
        )
        .expect("snapshot should validate"),
    )
    .expect("snapshot should serialize");
    snapshot["revision"] = serde_json::json!(0);
    assert!(serde_json::from_value::<WorkerRegistrationSnapshot>(snapshot).is_err());
}

#[tokio::test]
async fn ttl_and_unavailability_fail_closed() {
    let clock = ManualCoordinationClock::new();
    let store = MemoryEphemeralCoordinationStore::new(clock);
    for invalid in [Duration::ZERO, Duration::from_millis(300_001)] {
        assert_eq!(
            store
                .register_worker(
                    registration(1),
                    heartbeat(1, WorkerReadiness::Ready),
                    invalid,
                )
                .await,
            Err(EphemeralCoordinationError::InvalidInput)
        );
    }
    store.set_available(false);
    assert_eq!(
        store
            .register_worker(
                registration(1),
                heartbeat(1, WorkerReadiness::Ready),
                Duration::from_secs(1),
            )
            .await,
        Err(EphemeralCoordinationError::Unavailable)
    );
}
