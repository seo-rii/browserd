//! Bounded request and blocking-poll leases for action receipt waiting.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use browserd_actions::ActionSnapshot;
use browserd_core::TenantId;

pub(super) struct ActionWaitAdmission {
    waiters: Arc<TenantLane>,
    polls: Arc<TenantLane>,
}

impl Default for ActionWaitAdmission {
    fn default() -> Self {
        Self::new(256, 32, 64, 8)
    }
}

impl ActionWaitAdmission {
    pub(super) fn new(
        wait_global: usize,
        wait_tenant: usize,
        poll_global: usize,
        poll_tenant: usize,
    ) -> Self {
        Self {
            waiters: Arc::new(TenantLane::new(wait_global, wait_tenant)),
            polls: Arc::new(TenantLane::new(poll_global, poll_tenant)),
        }
    }

    /// Share this one counted lease between the handler and its blocking submit/poll jobs. A
    /// disconnected handler cannot free it while a job still owns an `Arc` to the guard.
    pub(super) fn try_waiter(&self, tenant: &TenantId) -> Option<Arc<ActionWaitGuard>> {
        self.waiters
            .try_acquire(tenant)
            .map(|lease| Arc::new(ActionWaitGuard { _lease: lease }))
    }

    /// Move the returned guard into the blocking poll closure, rather than retaining it only
    /// around its JoinHandle. Dropping a timed-out future does not stop an already running job.
    pub(super) fn try_poll(&self, tenant: &TenantId) -> Option<ActionPollGuard> {
        self.polls
            .try_acquire(tenant)
            .map(|lease| ActionPollGuard { _lease: lease })
    }
}

/// The guard itself is non-Clone; cloning an Arc shares one admission, never a second slot.
pub(super) struct ActionWaitGuard {
    _lease: TenantLease,
}

/// A non-Clone lease owned by exactly one blocking poll job.
pub(super) struct ActionPollGuard {
    _lease: TenantLease,
}

#[derive(Default)]
struct TenantCounts {
    global: usize,
    per_tenant: HashMap<TenantId, usize>,
}

struct TenantLane {
    counts: Mutex<TenantCounts>,
    global_limit: usize,
    tenant_limit: usize,
}

impl TenantLane {
    fn new(global_limit: usize, tenant_limit: usize) -> Self {
        Self {
            counts: Mutex::new(TenantCounts::default()),
            global_limit,
            tenant_limit,
        }
    }

    fn try_acquire(self: &Arc<Self>, tenant: &TenantId) -> Option<TenantLease> {
        // Poison closes future admission. Releasing existing guards still recovers the counts,
        // but never clears the poison or reopens a lane with uncertain accounting.
        let mut counts = self.counts.lock().ok()?;
        let tenant_count = counts.per_tenant.get(tenant).copied().unwrap_or(0);
        if counts.global >= self.global_limit || tenant_count >= self.tenant_limit {
            return None;
        }
        let next_global = counts.global.checked_add(1)?;
        let next_tenant = tenant_count.checked_add(1)?;
        counts.per_tenant.insert(tenant.clone(), next_tenant);
        counts.global = next_global;
        Some(TenantLease {
            lane: Arc::clone(self),
            tenant: tenant.clone(),
        })
    }
}

struct TenantLease {
    lane: Arc<TenantLane>,
    tenant: TenantId,
}

impl Drop for TenantLease {
    fn drop(&mut self) {
        let mut counts = self
            .lane
            .counts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        counts.global = counts.global.saturating_sub(1);
        if let Some(count) = counts.per_tenant.get_mut(&self.tenant) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                counts.per_tenant.remove(&self.tenant);
            }
        }
    }
}

/// Only immutable action identity is compared: status, delivery evidence, result, and resolution
/// may advance while the same action is observed. Tenant/session authority remains with the API.
pub(super) fn same_action_receipt(first: &ActionSnapshot, next: &ActionSnapshot) -> bool {
    first.action_id() == next.action_id()
        && first.action_sequence() == next.action_sequence()
        && first.request() == next.request()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::sync::Barrier;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    use browserd_actions::{
        ActionKind, ActionSequence, ActionSnapshotFacts, CanonicalRequestHash, IdempotencyKey,
        OutcomeUnknownReason, TerminalDetail,
    };
    use browserd_core::{ActionId, ActionState};

    fn assert_empty(lane: &TenantLane) {
        let counts = lane
            .counts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(counts.global, 0);
        assert!(counts.per_tenant.is_empty());
    }

    #[test]
    fn defaults_enforce_both_global_and_tenant_caps_for_each_lane() {
        let admission = ActionWaitAdmission::default();
        let tenants: Vec<_> = (0..8).map(|_| TenantId::new()).collect();
        let mut waiters = Vec::new();
        let mut polls = Vec::new();
        for tenant in &tenants {
            for _ in 0..32 {
                waiters.push(admission.try_waiter(tenant).expect("waiter"));
            }
            assert!(admission.try_waiter(tenant).is_none());
            for _ in 0..8 {
                polls.push(admission.try_poll(tenant).expect("poll"));
            }
            assert!(admission.try_poll(tenant).is_none());
        }
        assert!(admission.try_waiter(&TenantId::new()).is_none());
        assert!(admission.try_poll(&TenantId::new()).is_none());
        drop(waiters);
        drop(polls);
        assert_empty(&admission.waiters);
        assert_empty(&admission.polls);
    }

    #[test]
    fn noisy_tenant_cannot_consume_other_tenants_remaining_slots() {
        let admission = ActionWaitAdmission::new(4, 1, 4, 1);
        let noisy = TenantId::new();
        let quiet = TenantId::new();
        let _noisy_wait = admission.try_waiter(&noisy).expect("waiter");
        let _noisy_poll = admission.try_poll(&noisy).expect("poll");
        assert!(admission.try_waiter(&noisy).is_none());
        assert!(admission.try_poll(&noisy).is_none());
        assert!(admission.try_waiter(&quiet).is_some());
        assert!(admission.try_poll(&quiet).is_some());
    }

    #[test]
    fn waiters_and_polls_are_independent_and_zero_limits_disable_admission() {
        let admission = ActionWaitAdmission::new(1, 1, 1, 1);
        let tenant = TenantId::new();
        let waiter = admission.try_waiter(&tenant).expect("waiter");
        let poll = admission.try_poll(&tenant).expect("independent poll");
        assert!(admission.try_waiter(&tenant).is_none());
        assert!(admission.try_poll(&tenant).is_none());
        drop(waiter);
        assert!(admission.try_waiter(&tenant).is_some());
        assert!(admission.try_poll(&tenant).is_none());
        drop(poll);
        assert!(admission.try_poll(&tenant).is_some());
        for admission in [
            ActionWaitAdmission::new(0, 1, 0, 1),
            ActionWaitAdmission::new(1, 0, 1, 0),
        ] {
            assert!(admission.try_waiter(&tenant).is_none());
            assert!(admission.try_poll(&tenant).is_none());
        }
    }

    #[test]
    fn only_the_last_waiter_arc_releases_capacity_and_prunes_the_tenant() {
        let admission = ActionWaitAdmission::new(1, 1, 1, 1);
        let tenant = TenantId::new();
        let handler = admission.try_waiter(&tenant).expect("handler lease");
        let submit_job = Arc::clone(&handler);
        let poll_job = Arc::clone(&handler);
        drop(handler);
        assert!(admission.try_waiter(&tenant).is_none());
        drop(submit_job);
        assert!(admission.try_waiter(&tenant).is_none());
        drop(poll_job);
        assert_empty(&admission.waiters);
        assert!(admission.try_waiter(&tenant).is_some());
    }

    #[test]
    fn releasing_many_transient_tenants_does_not_retain_unbounded_map_entries() {
        let admission = ActionWaitAdmission::new(8, 2, 8, 2);
        for _ in 0..256 {
            let tenant = TenantId::new();
            let waiter = admission.try_waiter(&tenant).expect("waiter");
            let poll = admission.try_poll(&tenant).expect("poll");
            drop(waiter);
            drop(poll);
            assert_empty(&admission.waiters);
            assert_empty(&admission.polls);
        }
    }

    #[test]
    fn concurrent_admission_never_exceeds_atomic_global_and_tenant_caps() {
        for poll in [false, true] {
            let admission = Arc::new(ActionWaitAdmission::new(7, 2, 7, 2));
            let tenants: Vec<_> = (0..4).map(|_| TenantId::new()).collect();
            let start = Arc::new(Barrier::new(33));
            let admitted = Arc::new(Barrier::new(33));
            let release = Arc::new(Barrier::new(33));
            let accepted = Arc::new(AtomicUsize::new(0));
            let mut threads = Vec::new();
            for index in 0..32 {
                let admission = Arc::clone(&admission);
                let tenant = tenants[index % tenants.len()].clone();
                let start = Arc::clone(&start);
                let admitted = Arc::clone(&admitted);
                let release = Arc::clone(&release);
                let accepted = Arc::clone(&accepted);
                threads.push(thread::spawn(move || {
                    start.wait();
                    let held: Option<Box<dyn Send>> = if poll {
                        admission
                            .try_poll(&tenant)
                            .map(|guard| Box::new(guard) as Box<dyn Send>)
                    } else {
                        admission
                            .try_waiter(&tenant)
                            .map(|guard| Box::new(guard) as Box<dyn Send>)
                    };
                    if held.is_some() {
                        accepted.fetch_add(1, Ordering::SeqCst);
                    }
                    admitted.wait();
                    release.wait();
                    drop(held);
                }));
            }
            start.wait();
            admitted.wait();
            {
                let lane = if poll {
                    &admission.polls
                } else {
                    &admission.waiters
                };
                let counts = lane.counts.lock().expect("counts");
                assert_eq!(counts.global, 7);
                assert_eq!(accepted.load(Ordering::SeqCst), 7);
                assert!(counts.per_tenant.values().all(|count| *count <= 2));
            }
            release.wait();
            for thread in threads {
                thread.join().expect("admission thread");
            }
            assert_empty(&admission.waiters);
            assert_empty(&admission.polls);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn disconnected_handler_and_abandoned_join_handle_keep_blocking_job_leases() {
        let admission = Arc::new(ActionWaitAdmission::new(1, 1, 1, 1));
        let tenant = TenantId::new();
        let handler_waiter = admission.try_waiter(&tenant).expect("waiter");
        let job_waiter = Arc::clone(&handler_waiter);
        let job_poll = admission.try_poll(&tenant).expect("poll");
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (released_tx, released_rx) = tokio::sync::oneshot::channel();
        let (finish_tx, finish_rx) = mpsc::channel();
        let job = tokio::task::spawn_blocking(move || {
            started_tx.send(()).expect("job started");
            finish_rx
                .recv_timeout(Duration::from_secs(3))
                .expect("finish job");
            drop(job_poll);
            drop(job_waiter);
            released_tx.send(()).expect("job released");
        });
        started_rx.await.expect("job running");
        drop(job);
        drop(handler_waiter);
        assert!(admission.try_waiter(&tenant).is_none());
        assert!(admission.try_poll(&tenant).is_none());
        finish_tx.send(()).expect("finish");
        released_rx.await.expect("leases released");
        assert_empty(&admission.waiters);
        assert_empty(&admission.polls);
        assert!(admission.try_waiter(&tenant).is_some());
        assert!(admission.try_poll(&tenant).is_some());
    }

    #[test]
    fn poisoned_lane_rejects_new_work_but_existing_drop_recovers_cleanup() {
        let admission = ActionWaitAdmission::new(1, 1, 1, 1);
        let tenant = TenantId::new();
        let waiter = admission.try_waiter(&tenant).expect("waiter");
        let poisoned = Arc::clone(&admission.waiters);
        assert!(
            thread::spawn(move || {
                let _counts = poisoned.counts.lock().expect("counts");
                panic!("test admission poison");
            })
            .join()
            .is_err()
        );
        assert!(admission.try_waiter(&tenant).is_none());
        assert!(admission.try_poll(&tenant).is_some());
        drop(waiter);
        assert_empty(&admission.waiters);
        assert!(admission.try_waiter(&tenant).is_none());
    }

    fn snapshot_facts() -> ActionSnapshotFacts {
        ActionSnapshotFacts {
            action_id: ActionId::new(),
            action_sequence: ActionSequence::new(7),
            idempotency_key: IdempotencyKey::new("test-action-key"),
            canonical_request_hash: CanonicalRequestHash::new([1; 32]),
            kind: ActionKind::Mutating,
            state: ActionState::Accepted,
            dispatch_acknowledged: false,
            approval_decision: None,
            terminal_detail: None,
            resolution: None,
            result_content: None,
        }
    }

    #[test]
    fn receipt_identity_rejects_each_changed_immutable_action_fact() {
        let facts = snapshot_facts();
        let initial = ActionSnapshot::from_facts(facts.clone()).expect("initial receipt");
        for field in 0..5 {
            let mut changed = facts.clone();
            match field {
                0 => changed.action_id = ActionId::new(),
                1 => changed.action_sequence = ActionSequence::new(8),
                2 => changed.idempotency_key = IdempotencyKey::new("different-key"),
                3 => changed.canonical_request_hash = CanonicalRequestHash::new([2; 32]),
                _ => changed.kind = ActionKind::ReadOnly,
            }
            let candidate = ActionSnapshot::from_facts(changed).expect("candidate receipt");
            assert!(!same_action_receipt(&initial, &candidate));
        }
    }

    #[test]
    fn same_receipt_identity_survives_pending_and_terminal_progress() {
        let mut facts = snapshot_facts();
        let initial = ActionSnapshot::from_facts(facts.clone()).expect("initial receipt");
        facts.state = ActionState::MayHaveExecuted;
        facts.dispatch_acknowledged = true;
        let pending = ActionSnapshot::from_facts(facts.clone()).expect("pending receipt");
        assert!(same_action_receipt(&initial, &pending));
        facts.state = ActionState::OutcomeUnknown;
        facts.terminal_detail = Some(TerminalDetail::OutcomeUnknown(
            OutcomeUnknownReason::WorkerLost,
        ));
        let terminal = ActionSnapshot::from_facts(facts.clone()).expect("terminal receipt");
        assert!(same_action_receipt(&initial, &terminal));
        assert!(terminal.state().is_terminal());
        facts.state = ActionState::Succeeded;
        facts.terminal_detail = Some(TerminalDetail::Succeeded(
            browserd_actions::ResultDigest::new([3; 32]),
        ));
        facts.result_content = Some(br#"{"value":3}"#.to_vec());
        let succeeded = ActionSnapshot::from_facts(facts).expect("successful receipt");
        assert!(same_action_receipt(&initial, &succeeded));
        assert!(succeeded.state().is_terminal());
    }
}
