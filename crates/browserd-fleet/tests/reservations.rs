use std::sync::{Arc, Barrier};
use std::thread;

use browserd_core::{OperationId, TenantId};
use browserd_fleet::{ReservationError, ReservationOutcome, ReservationPool, ResourceVector};

#[test]
fn every_resource_dimension_is_reserved_atomically() {
    let pool = ReservationPool::new(ResourceVector::new(2_000, 2_000, 20, 4_000, 2, 100));
    let first = pool.reserve(
        OperationId::new(),
        TenantId::new(),
        ResourceVector::new(1_500, 500, 10, 1_000, 1, 20),
    );
    assert!(matches!(first, Ok(ReservationOutcome::Acquired(_))));

    let rejected = pool.reserve(
        OperationId::new(),
        TenantId::new(),
        ResourceVector::new(600, 100, 1, 1, 1, 1),
    );
    assert_eq!(rejected, Err(ReservationError::InsufficientCapacity));
    assert_eq!(
        pool.snapshot().reserved,
        ResourceVector::new(1_500, 500, 10, 1_000, 1, 20)
    );
}

#[test]
fn reservation_drop_releases_and_commit_moves_capacity_to_active() {
    let pool = ReservationPool::new(ResourceVector::new(100, 100, 10, 100, 2, 10));
    let operation = OperationId::new();
    let tenant = TenantId::new();
    let request = ResourceVector::new(40, 20, 2, 10, 1, 2);

    let lease = match pool.reserve(operation, tenant, request) {
        Ok(ReservationOutcome::Acquired(lease)) => lease,
        _ => return,
    };
    drop(lease);
    assert_eq!(pool.snapshot().reserved, ResourceVector::ZERO);

    let lease = match pool.reserve(OperationId::new(), TenantId::new(), request) {
        Ok(ReservationOutcome::Acquired(lease)) => lease,
        _ => return,
    };
    let allocation = lease.commit();
    assert_eq!(pool.snapshot().reserved, ResourceVector::ZERO);
    assert_eq!(pool.snapshot().active, request);
    drop(allocation);
    assert_eq!(pool.snapshot().active, ResourceVector::ZERO);
}

#[test]
fn duplicate_operation_never_reserves_twice_under_race() {
    let pool = Arc::new(ReservationPool::new(ResourceVector::new(
        10_000, 10_000, 100, 10_000, 100, 1_000,
    )));
    let operation = OperationId::new();
    let tenant = TenantId::new();
    let barrier = Arc::new(Barrier::new(17));
    let mut threads = Vec::new();

    for _ in 0..16 {
        let pool = pool.clone();
        let operation = operation.clone();
        let tenant = tenant.clone();
        let barrier = barrier.clone();
        threads.push(thread::spawn(move || {
            barrier.wait();
            let outcome = pool.reserve(
                operation,
                tenant,
                ResourceVector::new(100, 100, 1, 100, 1, 1),
            );
            barrier.wait();
            outcome
        }));
    }
    barrier.wait();
    barrier.wait();

    let mut acquired = 0;
    let mut duplicate = 0;
    let mut held = Vec::new();
    for handle in threads {
        let outcome = match handle.join() {
            Ok(outcome) => outcome,
            Err(_) => return,
        };
        match outcome {
            Ok(ReservationOutcome::Acquired(lease)) => {
                acquired += 1;
                held.push(lease);
            }
            Ok(ReservationOutcome::Existing) => duplicate += 1,
            Err(_) => return,
        }
    }
    assert_eq!(acquired, 1);
    assert_eq!(duplicate, 15);
    assert_eq!(pool.snapshot().reservation_count, 1);
    drop(held);
}

#[test]
fn zero_or_overflowing_vectors_fail_closed_without_partial_accounting() {
    let pool = ReservationPool::new(ResourceVector::new(u64::MAX, 1, 1, 1, 1, 1));
    assert_eq!(
        pool.reserve(OperationId::new(), TenantId::new(), ResourceVector::ZERO),
        Err(ReservationError::InvalidRequest)
    );
    assert_eq!(pool.snapshot().reserved, ResourceVector::ZERO);
}
