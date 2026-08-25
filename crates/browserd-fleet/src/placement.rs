use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};

use browserd_core::{ShardId, WorkerId};

use crate::ResourceVector;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompatibilityKey(String);

impl CompatibilityKey {
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidateLifecycle {
    Active,
    Draining,
    Stopping,
    Dead,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidateAdmission {
    Open,
    Closed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidateHealth {
    Healthy,
    Degraded,
    Tainted,
    Compromised,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShardCandidate {
    pub shard_id: ShardId,
    pub lifecycle: CandidateLifecycle,
    pub admission: CandidateAdmission,
    pub health: CandidateHealth,
    pub compatibility: CompatibilityKey,
    pub remaining: ResourceVector,
    pub capacity_ratio_ppm: u32,
    pub cpu_ewma_ppm: u32,
    pub pressure_penalty_ppm: u32,
    pub age_penalty_ppm: u32,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ShardSelector;

impl ShardSelector {
    #[must_use]
    pub fn select<'a>(
        candidates: &'a [ShardCandidate],
        compatibility: &CompatibilityKey,
        request: ResourceVector,
        allow_degraded: bool,
    ) -> Option<&'a ShardCandidate> {
        candidates
            .iter()
            .filter(|candidate| {
                candidate.lifecycle == CandidateLifecycle::Active
                    && candidate.admission == CandidateAdmission::Open
                    && (candidate.health == CandidateHealth::Healthy
                        || (allow_degraded && candidate.health == CandidateHealth::Degraded))
                    && &candidate.compatibility == compatibility
                    && request.fits_within(candidate.remaining)
            })
            .min_by(|left, right| {
                let left_score = u64::from(left.capacity_ratio_ppm)
                    .saturating_add(u64::from(left.cpu_ewma_ppm) / 4)
                    .saturating_add(u64::from(left.pressure_penalty_ppm))
                    .saturating_add(u64::from(left.age_penalty_ppm));
                let right_score = u64::from(right.capacity_ratio_ppm)
                    .saturating_add(u64::from(right.cpu_ewma_ppm) / 4)
                    .saturating_add(u64::from(right.pressure_penalty_ppm))
                    .saturating_add(u64::from(right.age_penalty_ppm));
                left_score
                    .cmp(&right_score)
                    .then_with(|| left.shard_id.cmp(&right.shard_id))
            })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EpochError {
    InvalidEpoch,
    NotMonotonic { previous: u64, proposed: u64 },
}

#[derive(Clone, Copy, Debug)]
struct WorkerEpoch {
    value: u64,
    lost: bool,
}

#[derive(Debug, Default)]
pub struct WorkerEpochRegistry {
    epochs: Mutex<HashMap<WorkerId, WorkerEpoch>>,
}

impl WorkerEpochRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&self, worker_id: WorkerId, proposed: u64) -> Result<(), EpochError> {
        if proposed == 0 {
            return Err(EpochError::InvalidEpoch);
        }
        let mut epochs = lock(&self.epochs);
        if let Some(previous) = epochs.get(&worker_id)
            && proposed <= previous.value
        {
            return Err(EpochError::NotMonotonic {
                previous: previous.value,
                proposed,
            });
        }
        epochs.insert(
            worker_id,
            WorkerEpoch {
                value: proposed,
                lost: false,
            },
        );
        Ok(())
    }

    pub fn mark_lost(&self, worker_id: &WorkerId, epoch: u64) {
        let mut epochs = lock(&self.epochs);
        if let Some(current) = epochs.get_mut(worker_id)
            && current.value == epoch
        {
            current.lost = true;
        }
    }

    #[must_use]
    pub fn is_current(&self, worker_id: &WorkerId, epoch: u64) -> bool {
        lock(&self.epochs)
            .get(worker_id)
            .is_some_and(|current| current.value == epoch && !current.lost)
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}
