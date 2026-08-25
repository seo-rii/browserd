use std::sync::{Arc, Barrier, Mutex};
use std::thread;

use browserd_core::{OperationId, TenantId};
use browserd_fleet::{FairQueue, QueueClaim, QueueError, QueueTime, QueuedOperation};

fn operation(tenant_id: TenantId, cost: u32, deadline: u64) -> QueuedOperation {
    QueuedOperation::new(
        OperationId::new(),
        tenant_id,
        cost,
        QueueTime::new(deadline),
    )
}

#[test]
fn queue_limits_deadlines_duplicates_and_cancel_are_exact() {
    let mut queue = FairQueue::new(10, 2, 3);
    let tenant = TenantId::new();
    let first = operation(tenant.clone(), 1, 100);
    let first_id = first.operation_id().clone();
    assert_eq!(queue.enqueue(first.clone(), QueueTime::new(0)), Ok(()));
    assert_eq!(
        queue.enqueue(first, QueueTime::new(0)),
        Err(QueueError::Duplicate)
    );
    assert_eq!(
        queue.enqueue(operation(tenant.clone(), 1, 100), QueueTime::new(0)),
        Ok(())
    );
    assert_eq!(
        queue.enqueue(operation(tenant.clone(), 1, 100), QueueTime::new(0)),
        Err(QueueError::TenantLimit)
    );
    assert!(queue.cancel(&first_id));
    assert!(!queue.cancel(&first_id));
    assert_eq!(
        queue.enqueue(operation(tenant, 1, 5), QueueTime::new(5)),
        Err(QueueError::DeadlineExpired)
    );
}

#[test]
fn weighted_deficit_round_robin_is_fair_and_cost_aware() {
    let mut queue = FairQueue::new(1, 100, 200);
    let standard = TenantId::new();
    let premium = TenantId::new();
    assert_eq!(queue.set_weight(standard.clone(), 1), Ok(()));
    assert_eq!(queue.set_weight(premium.clone(), 3), Ok(()));

    for _ in 0..40 {
        assert!(
            queue
                .enqueue(operation(standard.clone(), 1, 10_000), QueueTime::new(0))
                .is_ok()
        );
        assert!(
            queue
                .enqueue(operation(premium.clone(), 1, 10_000), QueueTime::new(0))
                .is_ok()
        );
    }

    let mut standard_count = 0;
    let mut premium_count = 0;
    for _ in 0..40 {
        let Some(next) = queue.dequeue(QueueTime::new(1)) else {
            return;
        };
        if next.tenant_id() == &standard {
            standard_count += 1;
        } else if next.tenant_id() == &premium {
            premium_count += 1;
        }
    }
    assert!(standard_count > 0, "the lower-weight tenant was starved");
    assert!(premium_count >= standard_count * 2);
    assert!(premium_count <= standard_count * 4);
}

#[test]
fn expired_heads_do_not_block_other_tenants() {
    let mut queue = FairQueue::new(10, 10, 10);
    let expired = TenantId::new();
    let live = TenantId::new();
    assert!(
        queue
            .enqueue(operation(expired, 1, 5), QueueTime::new(0))
            .is_ok()
    );
    let live_operation = operation(live, 1, 100);
    let live_id = live_operation.operation_id().clone();
    assert!(queue.enqueue(live_operation, QueueTime::new(0)).is_ok());

    let dequeued = queue.dequeue(QueueTime::new(10));
    assert_eq!(
        dequeued.as_ref().map(QueueClaim::operation_id),
        Some(&live_id)
    );
    assert_eq!(queue.expired_count(), 1);
}

#[test]
fn dequeued_operation_remains_exclusively_owned_until_completed() -> Result<(), &'static str> {
    let mut queue = FairQueue::new(10, 10, 10);
    let original = operation(TenantId::new(), 1, 100);
    let operation_id = original.operation_id().clone();
    assert_eq!(queue.enqueue(original.clone(), QueueTime::new(0)), Ok(()));

    let claimed = queue
        .dequeue(QueueTime::new(1))
        .ok_or("operation should be claimable")?;
    assert_eq!(claimed.operation_id(), &operation_id);
    assert_eq!(
        queue.enqueue(original.clone(), QueueTime::new(1)),
        Err(QueueError::Duplicate)
    );
    assert!(!queue.cancel(&operation_id));
    assert!(queue.complete(&claimed));
    assert!(!queue.complete(&claimed));
    assert_eq!(queue.enqueue(original, QueueTime::new(1)), Ok(()));
    Ok(())
}

#[test]
fn competing_consumer_cannot_reenqueue_and_dequeue_an_owned_operation() {
    let mut queue = FairQueue::new(10, 10, 10);
    let original = operation(TenantId::new(), 1, 100);
    let operation_id = original.operation_id().clone();
    assert_eq!(queue.enqueue(original.clone(), QueueTime::new(0)), Ok(()));

    let queue = Arc::new(Mutex::new(queue));
    let claimed = Arc::new(Barrier::new(2));
    let owner_queue = Arc::clone(&queue);
    let owner_claimed = Arc::clone(&claimed);
    let owner = thread::spawn(move || {
        let claimed_operation = owner_queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .dequeue(QueueTime::new(1));
        owner_claimed.wait();
        claimed_operation
    });

    claimed.wait();
    let mut contender_queue = queue
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let competing_enqueue = contender_queue.enqueue(original, QueueTime::new(1));
    let competing_dequeue = contender_queue.dequeue(QueueTime::new(1));
    drop(contender_queue);

    let owned = owner.join().unwrap_or_default();
    assert_eq!(
        owned.as_ref().map(QueueClaim::operation_id),
        Some(&operation_id)
    );
    assert_eq!(competing_enqueue, Err(QueueError::Duplicate));
    assert!(competing_dequeue.is_none());
}

#[test]
fn explicit_requeue_preserves_tenant_fifo_and_round_robin_order() -> Result<(), &'static str> {
    let mut queue = FairQueue::new(1, 10, 10);
    let tenant_a = TenantId::new();
    let tenant_b = TenantId::new();
    let a1 = operation(tenant_a.clone(), 1, 100);
    let a1_id = a1.operation_id().clone();
    let a2 = operation(tenant_a, 1, 100);
    let a2_id = a2.operation_id().clone();
    let b1 = operation(tenant_b, 1, 100);
    let b1_id = b1.operation_id().clone();
    assert_eq!(queue.enqueue(a1, QueueTime::new(0)), Ok(()));
    assert_eq!(queue.enqueue(a2, QueueTime::new(0)), Ok(()));
    assert_eq!(queue.enqueue(b1, QueueTime::new(0)), Ok(()));

    let a1_claim = queue
        .dequeue(QueueTime::new(1))
        .ok_or("first tenant operation should be claimable")?;
    assert_eq!(a1_claim.operation_id(), &a1_id);
    assert_eq!(queue.requeue(&a1_claim, QueueTime::new(1)), Ok(()));
    assert_eq!(
        queue.requeue(&a1_claim, QueueTime::new(1)),
        Err(QueueError::NotInFlight)
    );

    let next_ids = (0..3)
        .filter_map(|_| queue.dequeue(QueueTime::new(1)))
        .map(|claim| claim.operation_id().clone())
        .collect::<Vec<_>>();
    assert_eq!(next_ids, vec![b1_id, a1_id, a2_id]);
    Ok(())
}

#[test]
fn requeue_refunds_the_unfulfilled_drr_debit() -> Result<(), &'static str> {
    let mut queue = FairQueue::new(1, 10, 10);
    let tenant_a = TenantId::new();
    let tenant_b = TenantId::new();
    let a1 = operation(tenant_a.clone(), 2, 100);
    let a1_id = a1.operation_id().clone();
    let a2 = operation(tenant_a, 2, 100);
    let b1 = operation(tenant_b.clone(), 1, 100);
    let b1_id = b1.operation_id().clone();
    let b2 = operation(tenant_b.clone(), 1, 100);
    let b2_id = b2.operation_id().clone();
    let b3 = operation(tenant_b, 1, 100);
    assert_eq!(queue.enqueue(a1, QueueTime::new(0)), Ok(()));
    assert_eq!(queue.enqueue(a2, QueueTime::new(0)), Ok(()));
    assert_eq!(queue.enqueue(b1, QueueTime::new(0)), Ok(()));
    assert_eq!(queue.enqueue(b2, QueueTime::new(0)), Ok(()));
    assert_eq!(queue.enqueue(b3, QueueTime::new(0)), Ok(()));

    let first = queue
        .dequeue(QueueTime::new(1))
        .ok_or("first operation should be claimable")?;
    assert_eq!(first.operation_id(), &b1_id);
    let failed_placement = queue
        .dequeue(QueueTime::new(1))
        .ok_or("heavy operation should be claimable")?;
    assert_eq!(failed_placement.operation_id(), &a1_id);
    assert_eq!(queue.requeue(&failed_placement, QueueTime::new(1)), Ok(()));
    let next = queue
        .dequeue(QueueTime::new(1))
        .ok_or("next light operation should be claimable")?;
    assert_eq!(next.operation_id(), &b2_id);

    let after_refund = queue
        .dequeue(QueueTime::new(1))
        .ok_or("requeued heavy operation should retain its debit")?;
    assert_eq!(after_refund.operation_id(), &a1_id);
    Ok(())
}

#[test]
fn failed_requeue_keeps_in_flight_ownership_until_resolution() -> Result<(), &'static str> {
    let mut queue = FairQueue::new(10, 1, 1);
    let first = operation(TenantId::new(), 1, 100);
    let second = operation(TenantId::new(), 1, 100);
    assert_eq!(queue.enqueue(first, QueueTime::new(0)), Ok(()));
    let first_claim = queue
        .dequeue(QueueTime::new(1))
        .ok_or("first operation should be claimable")?;
    assert_eq!(queue.enqueue(second, QueueTime::new(1)), Ok(()));

    assert_eq!(
        queue.requeue(&first_claim, QueueTime::new(1)),
        Err(QueueError::GlobalLimit)
    );
    assert!(queue.complete(&first_claim));
    assert!(!queue.complete(&first_claim));
    Ok(())
}

#[test]
fn stale_claim_cannot_complete_a_later_dequeue_generation() -> Result<(), &'static str> {
    let mut queue = FairQueue::new(10, 10, 10);
    let original = operation(TenantId::new(), 1, 100);
    assert_eq!(queue.enqueue(original.clone(), QueueTime::new(0)), Ok(()));

    let stale_claim = queue
        .dequeue(QueueTime::new(1))
        .ok_or("operation should be claimable")?;
    assert_eq!(queue.requeue(&stale_claim, QueueTime::new(1)), Ok(()));
    let current_claim = queue
        .dequeue(QueueTime::new(1))
        .ok_or("requeued operation should be claimable again")?;

    assert!(!queue.complete(&stale_claim));
    assert_eq!(
        queue.requeue(&stale_claim, QueueTime::new(1)),
        Err(QueueError::NotInFlight)
    );
    assert_eq!(
        queue.enqueue(original.clone(), QueueTime::new(1)),
        Err(QueueError::Duplicate)
    );
    assert!(queue.complete(&current_claim));
    assert_eq!(queue.enqueue(original, QueueTime::new(1)), Ok(()));
    Ok(())
}
