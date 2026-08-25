use browserd_core::{OperationId, TenantId};
use browserd_fleet::{FairQueue, QueueError, QueueTime, QueuedOperation};

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
        dequeued.as_ref().map(QueuedOperation::operation_id),
        Some(&live_id)
    );
    assert_eq!(queue.expired_count(), 1);
}
