#![allow(clippy::expect_used, clippy::panic)]

use std::collections::HashSet;
use std::error::Error;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

use browserd_core::{ActionId, CreateOperationState, OperationId, TenantId};
use browserd_operations::{
    ActionCancelDecision, ActionTracker, CancelDecision, CanonicalRequestHash,
    CreateSessionOperation, GatewayActionState, IDEMPOTENCY_RETENTION, IdempotencyClaim,
    IdempotencyError, IdempotencyKey, IdempotencyRegistry, KnownActionFailure,
    OperationTransitionError, RegistryConfigError, TenantFairQueue, UncertaintyReason,
};
use serde_json::json;

fn hash_for(sequence: u64) -> CanonicalRequestHash {
    CanonicalRequestHash::from_json(&json!({
        "isolation": "shared_context",
        "metadata": {"sequence": sequence}
    }))
}

fn operation_for(tenant_id: TenantId, sequence: u64) -> Arc<CreateSessionOperation> {
    Arc::new(CreateSessionOperation::new(
        OperationId::new(),
        tenant_id,
        hash_for(sequence),
    ))
}

#[test]
fn canonical_hash_ignores_object_key_order_but_not_semantic_changes() {
    let first = CanonicalRequestHash::from_json(&json!({
        "viewport": {"width": 1280, "height": 720},
        "locale": "ko-KR"
    }));
    let reordered = CanonicalRequestHash::from_json(&json!({
        "locale": "ko-KR",
        "viewport": {"height": 720, "width": 1280}
    }));
    let changed = CanonicalRequestHash::from_json(&json!({
        "locale": "ko-KR",
        "viewport": {"height": 721, "width": 1280}
    }));

    assert_eq!(first, reordered);
    assert_ne!(first, changed);
}

#[test]
fn idempotency_scope_is_tenant_and_key() -> Result<(), Box<dyn Error>> {
    let registry = IdempotencyRegistry::default();
    let tenant_a = TenantId::new();
    let tenant_b = TenantId::new();
    let key = IdempotencyKey::new("create-run-42")?;
    let hash = hash_for(42);
    let now = Instant::now();

    let first = registry.claim(tenant_a.clone(), key.clone(), hash, now)?;
    let retry = registry.claim(tenant_a, key.clone(), hash, now + Duration::from_secs(1))?;
    let other_tenant = registry.claim(tenant_b, key, hash, now)?;

    assert!(matches!(first, IdempotencyClaim::Created(_)));
    assert!(matches!(retry, IdempotencyClaim::Existing(_)));
    assert_eq!(first.operation_id(), retry.operation_id());
    assert_ne!(first.operation_id(), other_tenant.operation_id());
    Ok(())
}

#[test]
fn same_key_with_different_canonical_body_conflicts() -> Result<(), Box<dyn Error>> {
    let registry = IdempotencyRegistry::default();
    let tenant = TenantId::new();
    let key = IdempotencyKey::new("create-run-conflict")?;
    let now = Instant::now();
    let original = registry.claim(tenant.clone(), key.clone(), hash_for(1), now)?;

    let conflict = registry.claim(tenant, key, hash_for(2), now);
    assert!(matches!(
        conflict,
        Err(IdempotencyError::Conflict {
            existing_operation_id
        }) if &existing_operation_id == original.operation_id()
    ));
    Ok(())
}

#[test]
fn mappings_are_retained_for_at_least_24_hours() -> Result<(), Box<dyn Error>> {
    assert_eq!(IDEMPOTENCY_RETENTION, Duration::from_secs(24 * 60 * 60));
    assert!(matches!(
        IdempotencyRegistry::new(IDEMPOTENCY_RETENTION - Duration::from_secs(1)),
        Err(RegistryConfigError::RetentionBelowMinimum)
    ));

    let registry = IdempotencyRegistry::new(IDEMPOTENCY_RETENTION)?;
    let tenant = TenantId::new();
    let key = IdempotencyKey::new("create-run-retention")?;
    let hash = hash_for(7);
    let now = Instant::now();
    let first = registry.claim(tenant.clone(), key.clone(), hash, now)?;
    let before_expiry = registry.claim(
        tenant.clone(),
        key.clone(),
        hash,
        now + IDEMPOTENCY_RETENTION - Duration::from_nanos(1),
    )?;
    let at_expiry = registry.claim(tenant, key, hash, now + IDEMPOTENCY_RETENTION)?;

    assert_eq!(first.operation_id(), before_expiry.operation_id());
    assert_ne!(first.operation_id(), at_expiry.operation_id());
    assert!(matches!(at_expiry, IdempotencyClaim::Created(_)));
    Ok(())
}

#[test]
fn prune_removes_elapsed_entries_without_changing_claim_semantics() -> Result<(), Box<dyn Error>> {
    let registry = IdempotencyRegistry::new(IDEMPOTENCY_RETENTION)?;
    let tenant = TenantId::new();
    let key_one = IdempotencyKey::new("prune-one")?;
    let key_two = IdempotencyKey::new("prune-two")?;
    let now = Instant::now();
    let first = registry.claim(tenant.clone(), key_one.clone(), hash_for(1), now)?;
    registry.claim(tenant.clone(), key_two.clone(), hash_for(2), now)?;

    // Nothing has elapsed yet, so a prune removes nothing and a retry still resolves to the
    // original operation.
    assert!(registry.prune(now + Duration::from_secs(1))?.is_empty());
    let retry = registry.claim(
        tenant.clone(),
        key_one.clone(),
        hash_for(1),
        now + Duration::from_secs(2),
    )?;
    assert_eq!(retry.operation_id(), first.operation_id());

    // Past retention both entries are reclaimed, and prune reports their operation ids so a caller
    // can drop the per-operation state it keyed on them.
    let pruned = registry.prune(now + IDEMPOTENCY_RETENTION)?;
    assert_eq!(pruned.len(), 2);
    assert!(pruned.contains(first.operation_id()));

    // Pruning is behavior-neutral: a re-claim after it mints a fresh operation, exactly as an
    // unpruned but elapsed entry would.
    let after = registry.claim(tenant, key_one, hash_for(1), now + IDEMPOTENCY_RETENTION)?;
    assert!(matches!(after, IdempotencyClaim::Created(_)));
    assert_ne!(after.operation_id(), first.operation_id());
    Ok(())
}

#[test]
fn concurrent_retries_linearize_to_one_operation() -> Result<(), Box<dyn Error>> {
    const CALLERS: usize = 32;
    let registry = Arc::new(IdempotencyRegistry::default());
    let barrier = Arc::new(Barrier::new(CALLERS));
    let tenant = TenantId::new();
    let key = IdempotencyKey::new("create-run-concurrent")?;
    let hash = hash_for(99);
    let now = Instant::now();
    let mut handles = Vec::new();

    for _ in 0..CALLERS {
        let registry = Arc::clone(&registry);
        let barrier = Arc::clone(&barrier);
        let tenant = tenant.clone();
        let key = key.clone();
        handles.push(thread::spawn(move || {
            barrier.wait();
            registry.claim(tenant, key, hash, now)
        }));
    }

    let mut created = 0;
    let mut operation_ids = HashSet::new();
    for handle in handles {
        let joined = handle.join();
        assert!(joined.is_ok());
        if let Ok(Ok(claim)) = joined {
            if matches!(claim, IdempotencyClaim::Created(_)) {
                created += 1;
            }
            operation_ids.insert(claim.operation_id().clone());
        }
    }

    assert_eq!(created, 1);
    assert_eq!(operation_ids.len(), 1);
    Ok(())
}

#[test]
fn concurrent_conflicting_claims_choose_exactly_one_canonical_body() -> Result<(), Box<dyn Error>> {
    const CALLERS: usize = 32;
    let registry = Arc::new(IdempotencyRegistry::default());
    let barrier = Arc::new(Barrier::new(CALLERS));
    let tenant = TenantId::new();
    let key = IdempotencyKey::new("create-run-concurrent-conflict")?;
    let now = Instant::now();
    let mut handles = Vec::new();

    for sequence in 0..CALLERS {
        let registry = Arc::clone(&registry);
        let barrier = Arc::clone(&barrier);
        let tenant = tenant.clone();
        let key = key.clone();
        handles.push(thread::spawn(move || {
            barrier.wait();
            registry.claim(tenant, key, hash_for(sequence as u64 % 2), now)
        }));
    }

    let claims = handles
        .into_iter()
        .map(|handle| {
            handle
                .join()
                .map_err(|_| std::io::Error::other("claim thread panicked"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let created = claims
        .iter()
        .filter(|claim| matches!(claim, Ok(IdempotencyClaim::Created(_))))
        .count();
    let successful_ids = claims
        .iter()
        .filter_map(|claim| claim.as_ref().ok().map(IdempotencyClaim::operation_id))
        .collect::<HashSet<_>>();

    assert_eq!(created, 1);
    assert_eq!(successful_ids.len(), 1);
    assert_eq!(
        claims.iter().filter(|claim| claim.is_err()).count(),
        CALLERS / 2
    );
    Ok(())
}

#[test]
fn backward_clock_and_huge_retention_do_not_expire_or_overflow() -> Result<(), Box<dyn Error>> {
    let registry = IdempotencyRegistry::new(Duration::MAX)?;
    let tenant = TenantId::new();
    let key = IdempotencyKey::new("create-run-clock")?;
    let hash = hash_for(8);
    let now = Instant::now();
    let first = registry.claim(tenant.clone(), key.clone(), hash, now)?;
    let backwards = now.checked_sub(Duration::from_secs(1)).unwrap_or(now);
    let retry = registry.claim(tenant, key, hash, backwards)?;

    assert_eq!(first.operation_id(), retry.operation_id());
    assert!(matches!(retry, IdempotencyClaim::Existing(_)));
    Ok(())
}

#[test]
fn create_operation_transitions_are_terminal_and_monotonic() {
    let operation = operation_for(TenantId::new(), 1);

    assert_eq!(operation.enqueue(), Ok(CreateOperationState::Queued));
    assert_eq!(
        operation.begin_reservation(),
        Ok(CreateOperationState::Reserving)
    );
    assert_eq!(
        operation.commit_creation(),
        Ok(CreateOperationState::Creating)
    );
    assert_eq!(operation.succeed(), Ok(CreateOperationState::Succeeded));
    assert_eq!(operation.state(), Ok(CreateOperationState::Succeeded));
    assert!(matches!(
        operation.fail(),
        Err(OperationTransitionError::Terminal(
            CreateOperationState::Succeeded
        ))
    ));
    assert!(matches!(
        operation.request_cancel(),
        Ok(CancelDecision::Terminal(CreateOperationState::Succeeded))
    ));
    assert_eq!(operation.state(), Ok(CreateOperationState::Succeeded));
}

#[test]
fn capacity_race_requeues_without_creating_a_live_session() {
    let operation = operation_for(TenantId::new(), 2);

    assert_eq!(operation.enqueue(), Ok(CreateOperationState::Queued));
    assert_eq!(
        operation.begin_reservation(),
        Ok(CreateOperationState::Reserving)
    );
    assert_eq!(operation.capacity_race(), Ok(CreateOperationState::Queued));
    assert!(!operation.creation_committed().unwrap_or(true));
}

#[test]
fn cancellation_is_immediate_before_commit_and_cooperative_after_commit() {
    let before_commit = operation_for(TenantId::new(), 3);
    assert_eq!(before_commit.enqueue(), Ok(CreateOperationState::Queued));
    assert_eq!(
        before_commit.request_cancel(),
        Ok(CancelDecision::Cancelled)
    );
    assert_eq!(before_commit.state(), Ok(CreateOperationState::Cancelled));

    let after_commit = operation_for(TenantId::new(), 4);
    assert_eq!(after_commit.enqueue(), Ok(CreateOperationState::Queued));
    assert_eq!(
        after_commit.begin_reservation(),
        Ok(CreateOperationState::Reserving)
    );
    assert_eq!(
        after_commit.commit_creation(),
        Ok(CreateOperationState::Creating)
    );
    assert_eq!(
        after_commit.request_cancel(),
        Ok(CancelDecision::CancelPending)
    );
    assert_eq!(after_commit.cancellation_requested(), Ok(true));
    assert_eq!(after_commit.state(), Ok(CreateOperationState::Creating));
    assert_eq!(
        after_commit.confirm_cancelled(),
        Ok(CreateOperationState::Cancelled)
    );
    assert_eq!(
        after_commit.request_cancel(),
        Ok(CancelDecision::Terminal(CreateOperationState::Cancelled))
    );
}

#[test]
fn commit_and_cancel_race_is_linearized_at_the_irreversible_boundary() {
    for sequence in 0..64 {
        let operation = operation_for(TenantId::new(), sequence);
        assert_eq!(operation.enqueue(), Ok(CreateOperationState::Queued));
        assert_eq!(
            operation.begin_reservation(),
            Ok(CreateOperationState::Reserving)
        );
        let barrier = Arc::new(Barrier::new(2));

        let commit_operation = Arc::clone(&operation);
        let commit_barrier = Arc::clone(&barrier);
        let commit = thread::spawn(move || {
            commit_barrier.wait();
            commit_operation.commit_creation()
        });
        let cancel_operation = Arc::clone(&operation);
        let cancel = thread::spawn(move || {
            barrier.wait();
            cancel_operation.request_cancel()
        });

        let commit = commit.join().expect("commit thread must not panic");
        let cancel = cancel.join().expect("cancel thread must not panic");
        match (commit, cancel) {
            (Ok(CreateOperationState::Creating), Ok(CancelDecision::CancelPending)) => {
                assert_eq!(operation.state(), Ok(CreateOperationState::Creating));
                assert_eq!(operation.cancellation_requested(), Ok(true));
            }
            (
                Err(OperationTransitionError::Terminal(CreateOperationState::Cancelled)),
                Ok(CancelDecision::Cancelled),
            ) => assert_eq!(operation.state(), Ok(CreateOperationState::Cancelled)),
            outcome => panic!("non-linearizable commit/cancel outcome: {outcome:?}"),
        }
    }
}

#[test]
fn tenant_queue_preserves_fifo_and_round_robin_fairness() -> Result<(), Box<dyn Error>> {
    let queue = TenantFairQueue::default();
    let tenant_a = TenantId::new();
    let tenant_b = TenantId::new();
    let a1 = operation_for(tenant_a.clone(), 1);
    let a2 = operation_for(tenant_a, 2);
    let b1 = operation_for(tenant_b, 3);

    queue.enqueue(Arc::clone(&a1))?;
    queue.enqueue(Arc::clone(&a2))?;
    queue.enqueue(Arc::clone(&b1))?;

    assert_eq!(queue.pop_next()?.as_ref().map(|op| op.id()), Some(a1.id()));
    assert_eq!(queue.pop_next()?.as_ref().map(|op| op.id()), Some(b1.id()));
    assert_eq!(queue.pop_next()?.as_ref().map(|op| op.id()), Some(a2.id()));
    assert!(queue.pop_next()?.is_none());
    Ok(())
}

#[test]
fn tenant_queue_skips_operations_cancelled_while_waiting() -> Result<(), Box<dyn Error>> {
    let queue = TenantFairQueue::default();
    let tenant = TenantId::new();
    let cancelled = operation_for(tenant.clone(), 1);
    let live = operation_for(tenant, 2);
    queue.enqueue(Arc::clone(&cancelled))?;
    queue.enqueue(Arc::clone(&live))?;
    assert_eq!(cancelled.request_cancel()?, CancelDecision::Cancelled);

    assert_eq!(
        queue.pop_next()?.as_ref().map(|op| op.id()),
        Some(live.id())
    );
    assert!(queue.pop_next()?.is_none());
    Ok(())
}

#[test]
fn capacity_race_operation_can_be_reinserted_into_the_fair_queue() -> Result<(), Box<dyn Error>> {
    let queue = TenantFairQueue::default();
    let operation = operation_for(TenantId::new(), 31);

    queue.enqueue(Arc::clone(&operation))?;
    let reserved = queue.pop_next()?.ok_or("operation must be queued")?;
    assert_eq!(
        reserved.begin_reservation()?,
        CreateOperationState::Reserving
    );
    assert_eq!(reserved.capacity_race()?, CreateOperationState::Queued);
    queue.enqueue(Arc::clone(&reserved))?;

    assert_eq!(
        queue.pop_next()?.as_ref().map(|queued| queued.id()),
        Some(operation.id())
    );
    Ok(())
}

#[test]
fn worker_loss_before_dispatch_is_known_not_dispatched() {
    for state in [
        GatewayActionState::Accepted,
        GatewayActionState::Queued,
        GatewayActionState::PendingApproval,
        GatewayActionState::ReadyToDispatch,
    ] {
        let tracker = ActionTracker::from_state(ActionId::new(), state);
        assert_eq!(
            tracker.on_worker_loss(),
            Ok(GatewayActionState::FailedKnown(
                KnownActionFailure::NotDispatched
            ))
        );
    }
}

#[test]
fn worker_loss_after_dispatch_intent_preserves_uncertainty_terminally() {
    for state in [
        GatewayActionState::DispatchIntentRecorded,
        GatewayActionState::MayHaveExecuted,
    ] {
        let tracker = ActionTracker::from_state(ActionId::new(), state);
        assert_eq!(
            tracker.on_worker_loss(),
            Ok(GatewayActionState::OutcomeUnknown(
                UncertaintyReason::WorkerLost
            ))
        );
        assert!(matches!(
            tracker.succeed(),
            Err(OperationTransitionError::ActionTerminal(
                GatewayActionState::OutcomeUnknown(UncertaintyReason::WorkerLost)
            ))
        ));
        assert_eq!(
            tracker.on_worker_loss(),
            Ok(GatewayActionState::OutcomeUnknown(
                UncertaintyReason::WorkerLost
            ))
        );
    }
}

#[test]
fn proven_delivery_failure_after_dispatch_intent_is_known_not_dispatched() {
    let tracker =
        ActionTracker::from_state(ActionId::new(), GatewayActionState::DispatchIntentRecorded);

    assert_eq!(
        tracker.record_proven_delivery_failure(),
        Ok(GatewayActionState::FailedKnown(
            KnownActionFailure::NotDispatched
        ))
    );
    assert_eq!(
        tracker.on_worker_loss(),
        Ok(GatewayActionState::FailedKnown(
            KnownActionFailure::NotDispatched
        ))
    );
}

#[test]
fn worker_loss_never_overwrites_a_known_terminal_result() {
    for state in [
        GatewayActionState::Succeeded,
        GatewayActionState::FailedKnown(KnownActionFailure::WorkerRejected),
        GatewayActionState::CancelledBeforeDispatch,
        GatewayActionState::CancelledConfirmed,
    ] {
        let tracker = ActionTracker::from_state(ActionId::new(), state.clone());
        assert_eq!(tracker.on_worker_loss(), Ok(state));
    }
}

#[test]
fn recovered_cancelled_action_preserves_its_cancellation_evidence() {
    for state in [
        GatewayActionState::CancelledBeforeDispatch,
        GatewayActionState::CancelledConfirmed,
    ] {
        let tracker = ActionTracker::from_state(ActionId::new(), state);
        assert_eq!(tracker.cancellation_requested(), Ok(true));
    }
}

#[test]
fn worker_loss_and_known_completion_race_has_one_monotonic_terminal_result() {
    for _ in 0..64 {
        let tracker = Arc::new(ActionTracker::from_state(
            ActionId::new(),
            GatewayActionState::MayHaveExecuted,
        ));
        let barrier = Arc::new(Barrier::new(2));

        let success_tracker = Arc::clone(&tracker);
        let success_barrier = Arc::clone(&barrier);
        let success = thread::spawn(move || {
            success_barrier.wait();
            success_tracker.succeed()
        });
        let loss_tracker = Arc::clone(&tracker);
        let loss = thread::spawn(move || {
            barrier.wait();
            loss_tracker.on_worker_loss()
        });

        let success = success.join().expect("success thread must not panic");
        let loss = loss.join().expect("worker-loss thread must not panic");
        let terminal = tracker
            .state()
            .expect("tracker mutex must remain available");
        assert!(matches!(
            terminal,
            GatewayActionState::Succeeded
                | GatewayActionState::OutcomeUnknown(UncertaintyReason::WorkerLost)
        ));
        assert!(success.is_ok() ^ matches!(loss, Ok(GatewayActionState::OutcomeUnknown(_))));
        assert_eq!(tracker.on_worker_loss(), Ok(terminal));
    }
}

#[test]
fn action_cancel_is_known_safe_only_before_dispatch_intent() {
    for state in [
        GatewayActionState::Accepted,
        GatewayActionState::Queued,
        GatewayActionState::PendingApproval,
        GatewayActionState::ReadyToDispatch,
    ] {
        let tracker = ActionTracker::from_state(ActionId::new(), state);

        assert_eq!(
            tracker.request_cancel(),
            Ok(ActionCancelDecision::CancelledBeforeDispatch)
        );
        assert_eq!(
            tracker.state(),
            Ok(GatewayActionState::CancelledBeforeDispatch)
        );
        assert_eq!(tracker.cancellation_requested(), Ok(true));
    }

    for state in [
        GatewayActionState::DispatchIntentRecorded,
        GatewayActionState::MayHaveExecuted,
    ] {
        let tracker = ActionTracker::from_state(ActionId::new(), state.clone());

        assert_eq!(
            tracker.request_cancel(),
            Ok(ActionCancelDecision::CancelPending)
        );
        assert_eq!(tracker.state(), Ok(state));
        assert_eq!(tracker.cancellation_requested(), Ok(true));
        assert_eq!(
            tracker.confirm_cancelled(),
            Ok(GatewayActionState::CancelledConfirmed)
        );
    }
}

#[test]
fn action_dispatch_and_cancel_race_linearizes_at_dispatch_intent() {
    for _ in 0..64 {
        let tracker = Arc::new(ActionTracker::from_state(
            ActionId::new(),
            GatewayActionState::ReadyToDispatch,
        ));
        let barrier = Arc::new(Barrier::new(2));

        let dispatch_tracker = Arc::clone(&tracker);
        let dispatch_barrier = Arc::clone(&barrier);
        let dispatch = thread::spawn(move || {
            dispatch_barrier.wait();
            dispatch_tracker.record_dispatch_intent()
        });
        let cancel_tracker = Arc::clone(&tracker);
        let cancel = thread::spawn(move || {
            barrier.wait();
            cancel_tracker.request_cancel()
        });

        let dispatch = dispatch.join().expect("dispatch thread must not panic");
        let cancel = cancel.join().expect("cancel thread must not panic");
        match (dispatch, cancel) {
            (
                Ok(GatewayActionState::DispatchIntentRecorded),
                Ok(ActionCancelDecision::CancelPending),
            ) => {
                assert_eq!(
                    tracker.state(),
                    Ok(GatewayActionState::DispatchIntentRecorded)
                );
                assert_eq!(tracker.cancellation_requested(), Ok(true));
            }
            (
                Err(OperationTransitionError::ActionTerminal(
                    GatewayActionState::CancelledBeforeDispatch,
                )),
                Ok(ActionCancelDecision::CancelledBeforeDispatch),
            ) => assert_eq!(
                tracker.state(),
                Ok(GatewayActionState::CancelledBeforeDispatch)
            ),
            outcome => panic!("non-linearizable dispatch/cancel outcome: {outcome:?}"),
        }
    }
}

#[test]
fn ambiguous_transport_loss_uses_gateway_delivery_state() {
    for state in [
        GatewayActionState::Accepted,
        GatewayActionState::Queued,
        GatewayActionState::PendingApproval,
        GatewayActionState::ReadyToDispatch,
    ] {
        let tracker = ActionTracker::from_state(ActionId::new(), state);
        assert_eq!(
            tracker.on_ambiguous_transport_loss(),
            Ok(GatewayActionState::FailedKnown(
                KnownActionFailure::NotDispatched
            ))
        );
    }

    for state in [
        GatewayActionState::DispatchIntentRecorded,
        GatewayActionState::MayHaveExecuted,
    ] {
        let tracker = ActionTracker::from_state(ActionId::new(), state);
        assert_eq!(
            tracker.on_ambiguous_transport_loss(),
            Ok(GatewayActionState::OutcomeUnknown(
                UncertaintyReason::AmbiguousTransportLoss
            ))
        );
        assert_eq!(
            tracker.request_cancel(),
            Ok(ActionCancelDecision::Terminal(
                GatewayActionState::OutcomeUnknown(UncertaintyReason::AmbiguousTransportLoss)
            ))
        );
        assert!(matches!(
            tracker.succeed(),
            Err(OperationTransitionError::ActionTerminal(
                GatewayActionState::OutcomeUnknown(UncertaintyReason::AmbiguousTransportLoss)
            ))
        ));
    }
}

#[test]
fn unconfirmed_cancel_does_not_turn_worker_loss_into_known_cancellation() {
    for state in [
        GatewayActionState::DispatchIntentRecorded,
        GatewayActionState::MayHaveExecuted,
    ] {
        let tracker = ActionTracker::from_state(ActionId::new(), state);
        assert_eq!(
            tracker.request_cancel(),
            Ok(ActionCancelDecision::CancelPending)
        );
        assert_eq!(
            tracker.on_worker_loss(),
            Ok(GatewayActionState::OutcomeUnknown(
                UncertaintyReason::WorkerLost
            ))
        );
    }
}
