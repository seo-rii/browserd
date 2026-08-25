#![allow(clippy::expect_used)]

use std::sync::{Arc, Barrier};
use std::thread;

use browserd_core::TenantId;
use browserd_observability::{
    UsageAggregator, UsageDimension, UsageEvent, UsageEventId, UsageRecordError, UsageRecordOutcome,
};

fn usage_event(id: &str, tenant_id: TenantId, quantity: u64) -> UsageEvent {
    UsageEvent::new(
        UsageEventId::new(id).expect("usage ID should be valid"),
        tenant_id,
        UsageDimension::BrowserWeightedSeconds,
        quantity,
        "dedicated_process",
        "interactive",
    )
}

#[test]
fn duplicate_usage_event_is_aggregated_exactly_once() {
    let tenant_id = TenantId::new();
    let aggregator = UsageAggregator::new();
    let event = usage_event("usage-1", tenant_id.clone(), 17);

    assert_eq!(
        aggregator
            .record(event.clone())
            .expect("first record should work"),
        UsageRecordOutcome::Recorded
    );
    assert_eq!(
        aggregator
            .record(event)
            .expect("retry should be idempotent"),
        UsageRecordOutcome::Existing
    );
    assert_eq!(
        aggregator
            .total(
                &tenant_id,
                UsageDimension::BrowserWeightedSeconds,
                "dedicated_process",
                "interactive",
            )
            .expect("total should work"),
        17
    );
}

#[test]
fn reused_usage_id_with_different_body_conflicts() {
    let tenant_id = TenantId::new();
    let aggregator = UsageAggregator::new();
    aggregator
        .record(usage_event("usage-conflict", tenant_id.clone(), 1))
        .expect("first event should record");
    assert_eq!(
        aggregator.record(usage_event("usage-conflict", tenant_id, 2)),
        Err(UsageRecordError::EventIdConflict)
    );
}

#[test]
fn concurrent_duplicate_usage_delivery_has_one_aggregation() {
    const DELIVERIES: usize = 48;

    let tenant_id = TenantId::new();
    let aggregator = Arc::new(UsageAggregator::new());
    let event = usage_event("usage-race", tenant_id.clone(), 23);
    let start = Arc::new(Barrier::new(DELIVERIES + 1));
    let mut tasks = Vec::with_capacity(DELIVERIES);
    for _ in 0..DELIVERIES {
        let aggregator = aggregator.clone();
        let event = event.clone();
        let start = start.clone();
        tasks.push(thread::spawn(move || {
            start.wait();
            aggregator.record(event)
        }));
    }
    start.wait();

    let outcomes: Vec<_> = tasks
        .into_iter()
        .map(|task| {
            task.join()
                .expect("usage thread should not panic")
                .expect("duplicate delivery should be accepted")
        })
        .collect();
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == UsageRecordOutcome::Recorded)
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == UsageRecordOutcome::Existing)
            .count(),
        DELIVERIES - 1
    );
    assert_eq!(
        aggregator
            .total(
                &tenant_id,
                UsageDimension::BrowserWeightedSeconds,
                "dedicated_process",
                "interactive",
            )
            .expect("total should work"),
        23
    );
}

#[test]
fn aggregation_overflow_does_not_consume_event_id() {
    let tenant_id = TenantId::new();
    let aggregator = UsageAggregator::new();
    aggregator
        .record(usage_event("max", tenant_id.clone(), u64::MAX))
        .expect("max should fit an empty total");
    assert_eq!(
        aggregator.record(usage_event("overflow", tenant_id.clone(), 1)),
        Err(UsageRecordError::TotalOverflow)
    );
    assert_eq!(
        aggregator.record(usage_event("overflow", TenantId::new(), 1)),
        Ok(UsageRecordOutcome::Recorded)
    );
}

#[test]
fn action_usage_is_partitioned_by_effective_action_type() {
    let tenant_id = TenantId::new();
    let aggregator = UsageAggregator::new();
    for (id, action_type, quantity) in [("clicks", "click", 3), ("navs", "navigate", 5)] {
        aggregator
            .record(UsageEvent::new(
                UsageEventId::new(id).expect("usage ID should be valid"),
                tenant_id.clone(),
                UsageDimension::ActionCountByType(action_type.into()),
                quantity,
                "dedicated_process",
                "interactive",
            ))
            .expect("action usage should record");
    }
    assert_eq!(
        aggregator
            .total(
                &tenant_id,
                UsageDimension::ActionCountByType("click".into()),
                "dedicated_process",
                "interactive",
            )
            .expect("click total should work"),
        3
    );
    assert_eq!(
        aggregator
            .total(
                &tenant_id,
                UsageDimension::ActionCountByType("navigate".into()),
                "dedicated_process",
                "interactive",
            )
            .expect("navigate total should work"),
        5
    );
}
