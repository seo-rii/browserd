#![allow(clippy::expect_used)]

use std::sync::Arc;
use std::time::Duration;

use browserd_coordination::{
    EphemeralCoordinationError, ManualCoordinationClock, MemoryEphemeralCoordinationStore,
    WorkerCapacity, WorkerHeartbeat, WorkerLeaseStore, WorkerReadiness, WorkerRegistration,
    WorkerRegistrationQuery, WorkerRegistrationSnapshot, WorkerReservationMutation,
    WorkerReservationOutcome, WorkerReservationRequest, WorkerReservationStore,
};
use browserd_core::{OperationId, TenantId, WorkerId};
use tokio::sync::Barrier;

fn resources(memory_bytes: u64) -> WorkerCapacity {
    WorkerCapacity::new(memory_bytes, 0, 0, 0, 0, 0)
}

fn registration(epoch: u64) -> WorkerRegistration {
    WorkerRegistration::new(
        WorkerId::new("reservation-worker").expect("worker id should validate"),
        epoch,
        "ap-northeast-2",
        "browserd-2026.08",
        vec!["chromium-140".to_owned()],
        resources(100),
        "worker-rpc://10.0.0.9:7443",
    )
    .expect("registration should validate")
}

fn heartbeat(memory_bytes: u64, readiness: WorkerReadiness) -> WorkerHeartbeat {
    WorkerHeartbeat::new(resources(memory_bytes), 0, 0, readiness)
        .expect("heartbeat should validate")
}

async fn register(
    store: &MemoryEphemeralCoordinationStore,
    epoch: u64,
    readiness: WorkerReadiness,
) -> WorkerRegistrationSnapshot {
    store
        .register_worker(
            registration(epoch),
            heartbeat(100, readiness),
            Duration::from_secs(30),
        )
        .await
        .expect("worker registration should work")
        .into_snapshot()
        .expect("registration should return a snapshot")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_gateways_acquire_one_exact_operation_reservation() {
    let clock = ManualCoordinationClock::new();
    let store = Arc::new(MemoryEphemeralCoordinationStore::new(clock));
    let worker = register(&store, 7, WorkerReadiness::Ready).await;
    let request = WorkerReservationRequest::new(OperationId::new(), TenantId::new(), resources(60))
        .expect("request should validate");
    let barrier = Arc::new(Barrier::new(65));
    let mut tasks = Vec::new();
    for _ in 0..64 {
        let store = Arc::clone(&store);
        let barrier = Arc::clone(&barrier);
        let worker = worker.clone();
        let request = request.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store
                .reserve_worker(&worker, request, Duration::from_secs(5))
                .await
        }));
    }
    barrier.wait().await;
    let mut acquired = 0;
    let mut existing = 0;
    let mut unexpected = 0;
    for task in tasks {
        match task
            .await
            .expect("task should join")
            .expect("reserve should run")
        {
            WorkerReservationOutcome::Acquired(_) => acquired += 1,
            WorkerReservationOutcome::Existing(_) => existing += 1,
            _ => unexpected += 1,
        }
    }
    assert_eq!((acquired, existing, unexpected), (1, 63, 0));
}

#[tokio::test]
async fn operation_id_is_exactly_idempotent_and_conflicting_reuse_fails_closed() {
    let store = MemoryEphemeralCoordinationStore::new(ManualCoordinationClock::new());
    let worker = register(&store, 3, WorkerReadiness::Ready).await;
    let operation_id = OperationId::new();
    let tenant = TenantId::new();
    let request = WorkerReservationRequest::new(operation_id.clone(), tenant, resources(40))
        .expect("request should validate");
    let acquired = store
        .reserve_worker(&worker, request.clone(), Duration::from_secs(5))
        .await
        .expect("reserve should work")
        .into_grant()
        .expect("reservation should return a grant");
    assert!(matches!(
        store
            .reserve_worker(&worker, request, Duration::from_secs(5))
            .await
            .expect("retry should work"),
        WorkerReservationOutcome::Existing(_)
    ));
    let conflict = WorkerReservationRequest::new(operation_id, TenantId::new(), resources(41))
        .expect("conflict fixture should validate");
    assert_eq!(
        store
            .reserve_worker(&worker, conflict, Duration::from_secs(5))
            .await
            .expect("conflict should be an outcome"),
        WorkerReservationOutcome::Conflict
    );
    assert_eq!(acquired.reservation().resources(), resources(40));
}

#[tokio::test]
async fn worker_epoch_revision_and_readiness_are_checked_before_capacity_effects() {
    let store = MemoryEphemeralCoordinationStore::new(ManualCoordinationClock::new());
    let old = register(&store, 4, WorkerReadiness::Ready).await;
    let current = register(&store, 5, WorkerReadiness::Ready).await;
    let request = WorkerReservationRequest::new(OperationId::new(), TenantId::new(), resources(20))
        .expect("request should validate");
    assert_eq!(
        store
            .reserve_worker(&old, request.clone(), Duration::from_secs(5))
            .await
            .expect("stale reserve should be an outcome"),
        WorkerReservationOutcome::FenceMismatch
    );
    let draining = store
        .heartbeat_worker(
            &current,
            heartbeat(100, WorkerReadiness::Draining),
            Duration::from_secs(30),
        )
        .await
        .expect("heartbeat should work")
        .into_snapshot()
        .expect("heartbeat should return a snapshot");
    assert_eq!(
        store
            .reserve_worker(&draining, request, Duration::from_secs(5))
            .await
            .expect("draining reserve should be an outcome"),
        WorkerReservationOutcome::WorkerUnavailable
    );
}

#[tokio::test]
async fn capacity_is_atomically_returned_by_exact_release_or_ttl_expiry() {
    let clock = ManualCoordinationClock::new();
    let store = MemoryEphemeralCoordinationStore::new(clock.clone());
    let worker = register(&store, 9, WorkerReadiness::Ready).await;
    let first = WorkerReservationRequest::new(OperationId::new(), TenantId::new(), resources(70))
        .expect("request should validate");
    let grant = store
        .reserve_worker(&worker, first, Duration::from_millis(5))
        .await
        .expect("reserve should work")
        .into_grant()
        .expect("reserve should return a grant");
    let second = WorkerReservationRequest::new(OperationId::new(), TenantId::new(), resources(70))
        .expect("request should validate");
    assert_eq!(
        store
            .reserve_worker(grant.worker(), second.clone(), Duration::from_secs(5))
            .await
            .expect("capacity check should work"),
        WorkerReservationOutcome::CapacityExhausted
    );
    let released_worker = store
        .release_worker_reservation(grant.reservation())
        .await
        .expect("release should work")
        .into_worker()
        .expect("release should return the updated worker");
    let expiring = store
        .reserve_worker(&released_worker, second, Duration::from_millis(5))
        .await
        .expect("reserve after release should work")
        .into_grant()
        .expect("reserve should return a grant");
    clock.advance(Duration::from_millis(5));
    let after_expiry =
        WorkerReservationRequest::new(OperationId::new(), TenantId::new(), resources(70))
            .expect("request should validate");
    assert!(
        store
            .reserve_worker(expiring.worker(), after_expiry, Duration::from_secs(5))
            .await
            .expect("expired capacity should be reclaimed")
            .into_grant()
            .is_ok()
    );
    assert_eq!(
        store
            .release_worker_reservation(expiring.reservation())
            .await
            .expect("expired release should be an outcome"),
        WorkerReservationMutation::Expired
    );
}

#[tokio::test]
async fn an_exact_older_reservation_can_release_after_a_later_reservation() {
    let store = MemoryEphemeralCoordinationStore::new(ManualCoordinationClock::new());
    let worker = register(&store, 12, WorkerReadiness::Ready).await;
    let first = store
        .reserve_worker(
            &worker,
            WorkerReservationRequest::new(OperationId::new(), TenantId::new(), resources(30))
                .expect("request should validate"),
            Duration::from_secs(5),
        )
        .await
        .expect("first reserve should work")
        .into_grant()
        .expect("first reserve should return a grant");
    let second = store
        .reserve_worker(
            first.worker(),
            WorkerReservationRequest::new(OperationId::new(), TenantId::new(), resources(30))
                .expect("request should validate"),
            Duration::from_secs(5),
        )
        .await
        .expect("second reserve should work")
        .into_grant()
        .expect("second reserve should return a grant");

    let after_release = store
        .release_worker_reservation(first.reservation())
        .await
        .expect("older exact reservation should release")
        .into_worker()
        .expect("release should return the latest worker snapshot");
    assert!(
        store
            .reserve_worker(
                &after_release,
                WorkerReservationRequest::new(OperationId::new(), TenantId::new(), resources(60),)
                    .expect("request should validate"),
                Duration::from_secs(5),
            )
            .await
            .expect("exactly restored capacity should be usable")
            .into_grant()
            .is_ok()
    );
    assert_ne!(
        second.reservation().operation_id(),
        first.reservation().operation_id()
    );
}

#[tokio::test]
async fn release_first_after_expiry_reclaims_capacity_exactly_once() {
    let clock = ManualCoordinationClock::new();
    let store = MemoryEphemeralCoordinationStore::new(clock.clone());
    let worker = register(&store, 13, WorkerReadiness::Ready).await;
    let expired = store
        .reserve_worker(
            &worker,
            WorkerReservationRequest::new(OperationId::new(), TenantId::new(), resources(100))
                .expect("request should validate"),
            Duration::from_millis(5),
        )
        .await
        .expect("reserve should work")
        .into_grant()
        .expect("reserve should return a grant");
    clock.advance(Duration::from_millis(5));
    assert_eq!(
        store
            .release_worker_reservation(expired.reservation())
            .await
            .expect("expired release should be an outcome"),
        WorkerReservationMutation::Expired
    );
    let current = store
        .query_ready_workers(
            &WorkerRegistrationQuery::new("ap-northeast-2", "chromium-140", 1)
                .expect("query should validate"),
        )
        .await
        .expect("current worker should be readable")
        .pop()
        .expect("worker should remain ready");
    assert!(
        store
            .reserve_worker(
                &current,
                WorkerReservationRequest::new(OperationId::new(), TenantId::new(), resources(100),)
                    .expect("request should validate"),
                Duration::from_secs(5),
            )
            .await
            .expect("expired capacity should have been reclaimed")
            .into_grant()
            .is_ok()
    );
}

#[tokio::test]
async fn reservation_wire_ttl_and_resource_bounds_fail_closed() {
    assert!(
        WorkerReservationRequest::new(
            OperationId::new(),
            TenantId::new(),
            WorkerCapacity::new(0, 0, 0, 0, 0, 0),
        )
        .is_err()
    );
    let request = WorkerReservationRequest::new(OperationId::new(), TenantId::new(), resources(1))
        .expect("request should validate");
    let mut wire = serde_json::to_value(request).expect("request should serialize");
    wire["unexpected"] = serde_json::json!(true);
    assert!(serde_json::from_value::<WorkerReservationRequest>(wire).is_err());
    let store = MemoryEphemeralCoordinationStore::new(ManualCoordinationClock::new());
    let worker = register(&store, 1, WorkerReadiness::Ready).await;
    for ttl in [Duration::ZERO, Duration::from_millis(300_001)] {
        assert_eq!(
            store
                .reserve_worker(
                    &worker,
                    WorkerReservationRequest::new(
                        OperationId::new(),
                        TenantId::new(),
                        resources(1),
                    )
                    .expect("request should validate"),
                    ttl,
                )
                .await,
            Err(EphemeralCoordinationError::InvalidInput)
        );
    }
}

#[tokio::test]
async fn expired_old_epoch_reservation_never_credits_a_new_worker_epoch() {
    let clock = ManualCoordinationClock::new();
    let store = MemoryEphemeralCoordinationStore::new(clock.clone());
    let old = register(&store, 20, WorkerReadiness::Ready).await;
    store
        .reserve_worker(
            &old,
            WorkerReservationRequest::new(OperationId::new(), TenantId::new(), resources(100))
                .expect("request should validate"),
            Duration::from_millis(5),
        )
        .await
        .expect("old epoch reserve should work");
    clock.advance(Duration::from_millis(5));
    let current = register(&store, 21, WorkerReadiness::Ready).await;
    assert!(
        store
            .reserve_worker(
                &current,
                WorkerReservationRequest::new(OperationId::new(), TenantId::new(), resources(100),)
                    .expect("request should validate"),
                Duration::from_secs(5),
            )
            .await
            .expect("new epoch reserve should work")
            .into_grant()
            .is_ok()
    );
}

#[tokio::test]
async fn release_terminal_reason_is_stable_across_retries() {
    let clock = ManualCoordinationClock::new();
    let store = MemoryEphemeralCoordinationStore::new(clock.clone());
    let worker = register(&store, 22, WorkerReadiness::Ready).await;
    let released = store
        .reserve_worker(
            &worker,
            WorkerReservationRequest::new(OperationId::new(), TenantId::new(), resources(1))
                .expect("request should validate"),
            Duration::from_secs(5),
        )
        .await
        .expect("reserve should work")
        .into_grant()
        .expect("reserve should acquire");
    assert!(matches!(
        store
            .release_worker_reservation(released.reservation())
            .await
            .expect("release should work"),
        WorkerReservationMutation::Released(_)
    ));
    assert_eq!(
        store
            .release_worker_reservation(released.reservation())
            .await
            .expect("release retry should work"),
        WorkerReservationMutation::AlreadyReleased
    );

    let current = store
        .query_ready_workers(
            &WorkerRegistrationQuery::new("ap-northeast-2", "chromium-140", 1)
                .expect("query should validate"),
        )
        .await
        .expect("worker should remain queryable")
        .pop()
        .expect("worker should remain ready");
    let expired = store
        .reserve_worker(
            &current,
            WorkerReservationRequest::new(OperationId::new(), TenantId::new(), resources(1))
                .expect("request should validate"),
            Duration::from_millis(5),
        )
        .await
        .expect("reserve should work")
        .into_grant()
        .expect("reserve should acquire");
    clock.advance(Duration::from_millis(5));
    for _ in 0..2 {
        assert_eq!(
            store
                .release_worker_reservation(expired.reservation())
                .await
                .expect("expired retry should work"),
            WorkerReservationMutation::Expired
        );
    }
}

#[tokio::test]
async fn memory_expiry_reclaim_work_is_bounded_to_sixty_four_records() {
    let clock = ManualCoordinationClock::new();
    let store = MemoryEphemeralCoordinationStore::new(clock.clone());
    let mut worker = register(&store, 23, WorkerReadiness::Ready).await;
    for _ in 0..65 {
        worker = store
            .reserve_worker(
                &worker,
                WorkerReservationRequest::new(OperationId::new(), TenantId::new(), resources(1))
                    .expect("request should validate"),
                Duration::from_millis(5),
            )
            .await
            .expect("reserve should work")
            .into_grant()
            .expect("reserve should acquire")
            .worker()
            .clone();
    }
    clock.advance(Duration::from_millis(5));
    let first = store
        .reserve_worker(
            &worker,
            WorkerReservationRequest::new(OperationId::new(), TenantId::new(), resources(100))
                .expect("request should validate"),
            Duration::from_secs(5),
        )
        .await
        .expect("bounded reclaim should return an outcome");
    assert!(!matches!(first, WorkerReservationOutcome::Acquired(_)));
}

#[tokio::test]
async fn heartbeat_preserves_active_debits_and_removes_them_after_terminalization() {
    let clock = ManualCoordinationClock::new();
    let store = MemoryEphemeralCoordinationStore::new(clock.clone());
    let worker = register(&store, 24, WorkerReadiness::Ready).await;
    let active = store
        .reserve_worker(
            &worker,
            WorkerReservationRequest::new(OperationId::new(), TenantId::new(), resources(30))
                .expect("request should validate"),
            Duration::from_secs(5),
        )
        .await
        .expect("reserve should work")
        .into_grant()
        .expect("reserve should acquire");
    let heartbeated = store
        .heartbeat_worker(
            active.worker(),
            WorkerHeartbeat::new(resources(100), 7, 2, WorkerReadiness::Draining)
                .expect("advertised heartbeat should validate"),
            Duration::from_secs(20),
        )
        .await
        .expect("heartbeat should work")
        .into_snapshot()
        .expect("heartbeat should apply");
    assert_eq!(heartbeated.heartbeat().free(), resources(70));
    assert_eq!(heartbeated.heartbeat().queue_depth(), 7);
    assert_eq!(
        heartbeated.heartbeat().readiness(),
        WorkerReadiness::Draining
    );

    let released = store
        .release_worker_reservation(active.reservation())
        .await
        .expect("release should work")
        .into_worker()
        .expect("release should return current worker");
    let after_release = store
        .heartbeat_worker(
            &released,
            WorkerHeartbeat::new(resources(100), 8, 2, WorkerReadiness::Ready)
                .expect("advertised heartbeat should validate"),
            Duration::from_secs(20),
        )
        .await
        .expect("heartbeat should work")
        .into_snapshot()
        .expect("heartbeat should apply");
    assert_eq!(after_release.heartbeat().free(), resources(100));

    let expiring = store
        .reserve_worker(
            &after_release,
            WorkerReservationRequest::new(OperationId::new(), TenantId::new(), resources(25))
                .expect("request should validate"),
            Duration::from_millis(5),
        )
        .await
        .expect("reserve should work")
        .into_grant()
        .expect("reserve should acquire");
    clock.advance(Duration::from_millis(5));
    assert_eq!(
        store
            .release_worker_reservation(expiring.reservation())
            .await
            .expect("expired release should work"),
        WorkerReservationMutation::Expired
    );
    let current = store
        .query_ready_workers(
            &WorkerRegistrationQuery::new("ap-northeast-2", "chromium-140", 1)
                .expect("query should validate"),
        )
        .await
        .expect("query should work")
        .pop()
        .expect("worker should remain ready");
    assert_eq!(current.heartbeat().free(), resources(100));
}

#[tokio::test]
async fn reservation_ttl_cannot_outlive_the_current_worker_lease() {
    let clock = ManualCoordinationClock::new();
    let store = MemoryEphemeralCoordinationStore::new(clock.clone());
    let worker = register(&store, 25, WorkerReadiness::Ready).await;
    clock.advance(Duration::from_secs(29));
    assert_eq!(
        store
            .reserve_worker(
                &worker,
                WorkerReservationRequest::new(OperationId::new(), TenantId::new(), resources(1),)
                    .expect("request should validate"),
                Duration::from_secs(2),
            )
            .await,
        Err(EphemeralCoordinationError::InvalidInput)
    );
}

#[test]
fn reservation_accounting_is_aggregate_and_advertised_free_is_documented() {
    let memory = include_str!("../src/memory_ephemeral.rs");
    let redis = include_str!("../src/redis.rs");
    let api = include_str!("../src/ephemeral.rs");
    assert!(memory.contains("worker_reserved"));
    for field in [
        "reserved_memory_bytes",
        "reserved_cpu_millis",
        "reserved_pids",
        "reserved_disk_bytes",
        "reserved_contexts",
        "reserved_targets",
    ] {
        assert!(redis.contains(field));
    }
    assert!(api.contains("advertised free resources before coordination reservations"));
}

#[tokio::test]
async fn heartbeat_reclaims_expired_reservations_without_release_or_new_reserve() {
    let clock = ManualCoordinationClock::new();
    let store = MemoryEphemeralCoordinationStore::new(clock.clone());
    let worker = register(&store, 26, WorkerReadiness::Ready).await;
    let request =
        WorkerReservationRequest::new(OperationId::new(), TenantId::new(), resources(100))
            .expect("request should validate");
    let grant = store
        .reserve_worker(&worker, request.clone(), Duration::from_millis(5))
        .await
        .expect("reserve should work")
        .into_grant()
        .expect("reserve should acquire");
    clock.advance(Duration::from_millis(5));
    let swept = store
        .heartbeat_worker(
            grant.worker(),
            WorkerHeartbeat::new(resources(100), 0, 0, WorkerReadiness::Ready)
                .expect("advertised heartbeat should validate"),
            Duration::from_secs(20),
        )
        .await
        .expect("heartbeat sweep should work")
        .into_snapshot()
        .expect("heartbeat should apply");
    assert_eq!(swept.heartbeat().free(), resources(100));
    assert_eq!(
        store
            .reserve_worker(&swept, request, Duration::from_secs(5))
            .await
            .expect("expired exact retry should be stable"),
        WorkerReservationOutcome::Expired
    );
    assert!(
        store
            .reserve_worker(
                &swept,
                WorkerReservationRequest::new(OperationId::new(), TenantId::new(), resources(100),)
                    .expect("request should validate"),
                Duration::from_secs(5),
            )
            .await
            .expect("reclaimed capacity should be usable")
            .into_grant()
            .is_ok()
    );
}

#[tokio::test]
async fn heartbeat_expiry_sweep_is_bounded_to_sixty_four_records() {
    let clock = ManualCoordinationClock::new();
    let store = MemoryEphemeralCoordinationStore::new(clock.clone());
    let mut worker = register(&store, 27, WorkerReadiness::Ready).await;
    for _ in 0..65 {
        worker = store
            .reserve_worker(
                &worker,
                WorkerReservationRequest::new(OperationId::new(), TenantId::new(), resources(1))
                    .expect("request should validate"),
                Duration::from_millis(5),
            )
            .await
            .expect("reserve should work")
            .into_grant()
            .expect("reserve should acquire")
            .worker()
            .clone();
    }
    clock.advance(Duration::from_millis(5));
    let first = store
        .heartbeat_worker(
            &worker,
            WorkerHeartbeat::new(resources(100), 0, 0, WorkerReadiness::Ready)
                .expect("advertised heartbeat should validate"),
            Duration::from_secs(20),
        )
        .await
        .expect("first bounded sweep should work")
        .into_snapshot()
        .expect("heartbeat should apply");
    assert_eq!(first.heartbeat().free(), resources(99));
    let second = store
        .heartbeat_worker(
            &first,
            WorkerHeartbeat::new(resources(100), 0, 0, WorkerReadiness::Ready)
                .expect("advertised heartbeat should validate"),
            Duration::from_secs(20),
        )
        .await
        .expect("second bounded sweep should work")
        .into_snapshot()
        .expect("heartbeat should apply");
    assert_eq!(second.heartbeat().free(), resources(100));
}

#[test]
fn memory_uses_a_per_worker_ordered_reservation_expiry_index() {
    let memory = include_str!("../src/memory_ephemeral.rs");
    assert!(memory.contains("worker_reservation_expiry_index"));
    assert!(!memory.contains("worker_reservations.values()"));
}
