use browserd_core::{ShardId, WorkerId};
use browserd_fleet::{
    CandidateAdmission, CandidateHealth, CandidateLifecycle, CompatibilityKey, EpochError,
    ResourceVector, ShardCandidate, ShardSelector, WorkerEpochRegistry,
};

fn candidate(
    id: ShardId,
    compatibility: &str,
    capacity_ratio_ppm: u32,
    health: CandidateHealth,
) -> ShardCandidate {
    ShardCandidate {
        shard_id: id,
        lifecycle: CandidateLifecycle::Active,
        admission: CandidateAdmission::Open,
        health,
        compatibility: CompatibilityKey::new(compatibility),
        remaining: ResourceVector::new(1_000, 1_000, 10, 1_000, 4, 100),
        capacity_ratio_ppm,
        cpu_ewma_ppm: 0,
        pressure_penalty_ppm: 0,
        age_penalty_ppm: 0,
    }
}

#[test]
fn selector_requires_exact_compatibility_and_all_eligibility_axes() {
    let expected = CompatibilityKey::new("chromium-a:policy-7:features-x");
    let wrong = candidate(
        ShardId::new(),
        "chromium-b:policy-7:features-x",
        1,
        CandidateHealth::Healthy,
    );
    let mut closed = candidate(
        ShardId::new(),
        "chromium-a:policy-7:features-x",
        2,
        CandidateHealth::Healthy,
    );
    closed.admission = CandidateAdmission::Closed;
    let mut draining = candidate(
        ShardId::new(),
        "chromium-a:policy-7:features-x",
        3,
        CandidateHealth::Healthy,
    );
    draining.lifecycle = CandidateLifecycle::Draining;
    let tainted = candidate(
        ShardId::new(),
        "chromium-a:policy-7:features-x",
        4,
        CandidateHealth::Tainted,
    );
    let chosen = candidate(
        ShardId::new(),
        "chromium-a:policy-7:features-x",
        900_000,
        CandidateHealth::Healthy,
    );
    let expected_id = chosen.shard_id.clone();

    let candidates = [wrong, closed, draining, tainted, chosen];
    let selected = ShardSelector::select(
        &candidates,
        &expected,
        ResourceVector::new(100, 100, 1, 100, 1, 1),
        false,
    );
    assert_eq!(
        selected.map(|candidate| &candidate.shard_id),
        Some(&expected_id)
    );
}

#[test]
fn selector_uses_spec_score_and_only_allows_degraded_when_explicit() {
    let compatibility = CompatibilityKey::new("same");
    let healthy = candidate(ShardId::new(), "same", 400_000, CandidateHealth::Healthy);
    let healthy_id = healthy.shard_id.clone();
    let degraded = candidate(ShardId::new(), "same", 100_000, CandidateHealth::Degraded);
    let degraded_id = degraded.shard_id.clone();
    let candidates = [healthy, degraded];
    let request = ResourceVector::new(1, 1, 1, 1, 1, 1);

    assert_eq!(
        ShardSelector::select(&candidates, &compatibility, request, false)
            .map(|candidate| &candidate.shard_id),
        Some(&healthy_id)
    );
    assert_eq!(
        ShardSelector::select(&candidates, &compatibility, request, true)
            .map(|candidate| &candidate.shard_id),
        Some(&degraded_id)
    );
}

#[test]
fn worker_epoch_never_reuses_or_moves_backwards() {
    let registry = WorkerEpochRegistry::new();
    let worker = match WorkerId::new("worker-apne2-a-001") {
        Ok(worker) => worker,
        Err(_) => return,
    };
    assert_eq!(registry.register(worker.clone(), 41), Ok(()));
    assert_eq!(
        registry.register(worker.clone(), 41),
        Err(EpochError::NotMonotonic {
            previous: 41,
            proposed: 41
        })
    );
    assert_eq!(
        registry.register(worker.clone(), 40),
        Err(EpochError::NotMonotonic {
            previous: 41,
            proposed: 40
        })
    );
    registry.mark_lost(&worker, 41);
    assert_eq!(registry.register(worker, 42), Ok(()));
}
