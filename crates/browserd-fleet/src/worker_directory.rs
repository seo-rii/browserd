use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use browserd_core::WorkerId;

use crate::{CompatibilityKey, DirectoryTime, ResourceVector};

const MAX_WORKER_LEASE: Duration = Duration::from_secs(5 * 60);
const MAX_COMPATIBILITY_KEYS: usize = 128;
const MAX_QUEUE_DEPTH: usize = 65_536;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerAdvertisement {
    worker_id: WorkerId,
    worker_epoch: u64,
    region: String,
    release: String,
    compatibility: Vec<CompatibilityKey>,
    capacity: ResourceVector,
    free: ResourceVector,
    queue_depth: usize,
    ready: bool,
}

impl WorkerAdvertisement {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        worker_id: WorkerId,
        worker_epoch: u64,
        region: impl Into<String>,
        release: impl Into<String>,
        mut compatibility: Vec<CompatibilityKey>,
        capacity: ResourceVector,
        free: ResourceVector,
        queue_depth: usize,
        ready: bool,
    ) -> Result<Self, WorkerDirectoryError> {
        let region = region.into();
        let release = release.into();
        if worker_epoch == 0
            || region.is_empty()
            || region.len() > 255
            || region.trim() != region
            || region.chars().any(char::is_control)
            || release.is_empty()
            || release.len() > 255
            || release.trim() != release
            || release.chars().any(char::is_control)
            || compatibility.is_empty()
            || compatibility.len() > MAX_COMPATIBILITY_KEYS
            || compatibility.iter().any(|key| {
                key.as_str().is_empty()
                    || key.as_str().len() > 1_024
                    || key.as_str().chars().any(char::is_control)
            })
            || capacity == ResourceVector::ZERO
            || !free.fits_within(capacity)
            || queue_depth > MAX_QUEUE_DEPTH
        {
            return Err(WorkerDirectoryError::InvalidAdvertisement);
        }
        compatibility.sort();
        compatibility.dedup();
        Ok(Self {
            worker_id,
            worker_epoch,
            region,
            release,
            compatibility,
            capacity,
            free,
            queue_depth,
            ready,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkerHeartbeat {
    free: ResourceVector,
    queue_depth: usize,
    active_shards: usize,
    ready: bool,
}

impl WorkerHeartbeat {
    pub fn new(
        free: ResourceVector,
        queue_depth: usize,
        active_shards: usize,
        ready: bool,
    ) -> Result<Self, WorkerDirectoryError> {
        if queue_depth > MAX_QUEUE_DEPTH || active_shards > MAX_QUEUE_DEPTH {
            return Err(WorkerDirectoryError::InvalidHeartbeat);
        }
        Ok(Self {
            free,
            queue_depth,
            active_shards,
            ready,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerDirectorySnapshot {
    worker_id: WorkerId,
    worker_epoch: u64,
    region: String,
    release: String,
    compatibility: Vec<CompatibilityKey>,
    capacity: ResourceVector,
    free: ResourceVector,
    queue_depth: usize,
    active_shards: usize,
    ready: bool,
    lease_expires_at: DirectoryTime,
    owned: bool,
}

impl WorkerDirectorySnapshot {
    #[must_use]
    pub const fn worker_id(&self) -> &WorkerId {
        &self.worker_id
    }

    #[must_use]
    pub const fn worker_epoch(&self) -> u64 {
        self.worker_epoch
    }

    #[must_use]
    pub fn region(&self) -> &str {
        &self.region
    }

    #[must_use]
    pub fn release(&self) -> &str {
        &self.release
    }

    #[must_use]
    pub fn compatibility(&self) -> &[CompatibilityKey] {
        &self.compatibility
    }

    #[must_use]
    pub const fn capacity(&self) -> ResourceVector {
        self.capacity
    }

    #[must_use]
    pub const fn free(&self) -> ResourceVector {
        self.free
    }

    #[must_use]
    pub const fn queue_depth(&self) -> usize {
        self.queue_depth
    }

    #[must_use]
    pub const fn active_shards(&self) -> usize {
        self.active_shards
    }

    #[must_use]
    pub const fn ready(&self) -> bool {
        self.ready
    }

    #[must_use]
    pub const fn lease_expires_at(&self) -> DirectoryTime {
        self.lease_expires_at
    }

    #[must_use]
    pub const fn owned(&self) -> bool {
        self.owned
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegisterWorkerOutcome {
    Registered(WorkerDirectorySnapshot),
    Existing(WorkerDirectorySnapshot),
}

impl RegisterWorkerOutcome {
    #[must_use]
    pub fn into_snapshot(self) -> WorkerDirectorySnapshot {
        match self {
            Self::Registered(snapshot) | Self::Existing(snapshot) => snapshot,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkerDirectoryError {
    InvalidLease,
    InvalidAdvertisement,
    InvalidHeartbeat,
    InvalidLimit,
    NotFound,
    NotOwned,
    NotReady,
    LeaseExpired,
    TimeOverflow,
    EpochConflict,
    EpochMismatch { current: u64, received: u64 },
    StaleWorkerEpoch { current: u64, proposed: u64 },
    StateUnavailable,
}

impl fmt::Display for WorkerDirectoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "worker directory error: {self:?}")
    }
}

impl std::error::Error for WorkerDirectoryError {}

#[derive(Debug)]
pub struct WorkerDirectory {
    lease_duration_millis: u64,
    workers: Mutex<BTreeMap<WorkerId, WorkerDirectorySnapshot>>,
}

impl WorkerDirectory {
    pub fn new(lease_duration: Duration) -> Result<Self, WorkerDirectoryError> {
        if lease_duration.is_zero() || lease_duration > MAX_WORKER_LEASE {
            return Err(WorkerDirectoryError::InvalidLease);
        }
        let lease_duration_millis = u64::try_from(lease_duration.as_millis())
            .map_err(|_| WorkerDirectoryError::InvalidLease)?;
        if lease_duration_millis == 0 {
            return Err(WorkerDirectoryError::InvalidLease);
        }
        Ok(Self {
            lease_duration_millis,
            workers: Mutex::new(BTreeMap::new()),
        })
    }

    pub fn register(
        &self,
        advertisement: WorkerAdvertisement,
        now: DirectoryTime,
    ) -> Result<RegisterWorkerOutcome, WorkerDirectoryError> {
        let lease_expires_at = self.checked_expiry(now)?;
        let mut workers = self.lock_workers()?;
        if let Some(existing) = workers.get(&advertisement.worker_id) {
            if advertisement.worker_epoch < existing.worker_epoch {
                return Err(WorkerDirectoryError::StaleWorkerEpoch {
                    current: existing.worker_epoch,
                    proposed: advertisement.worker_epoch,
                });
            }
            if advertisement.worker_epoch == existing.worker_epoch {
                if !existing.owned || existing.lease_expires_at <= now {
                    return Err(WorkerDirectoryError::LeaseExpired);
                }
                if existing.region != advertisement.region
                    || existing.release != advertisement.release
                    || existing.compatibility != advertisement.compatibility
                    || existing.capacity != advertisement.capacity
                {
                    return Err(WorkerDirectoryError::EpochConflict);
                }
                return Ok(RegisterWorkerOutcome::Existing(existing.clone()));
            }
        }
        let worker_id = advertisement.worker_id.clone();
        let snapshot = WorkerDirectorySnapshot {
            worker_id: advertisement.worker_id,
            worker_epoch: advertisement.worker_epoch,
            region: advertisement.region,
            release: advertisement.release,
            compatibility: advertisement.compatibility,
            capacity: advertisement.capacity,
            free: advertisement.free,
            queue_depth: advertisement.queue_depth,
            active_shards: 0,
            ready: advertisement.ready,
            lease_expires_at,
            owned: true,
        };
        workers.insert(worker_id, snapshot.clone());
        Ok(RegisterWorkerOutcome::Registered(snapshot))
    }

    pub fn heartbeat(
        &self,
        worker_id: &WorkerId,
        worker_epoch: u64,
        heartbeat: WorkerHeartbeat,
        now: DirectoryTime,
    ) -> Result<WorkerDirectorySnapshot, WorkerDirectoryError> {
        let lease_expires_at = self.checked_expiry(now)?;
        let mut workers = self.lock_workers()?;
        let worker = workers
            .get_mut(worker_id)
            .ok_or(WorkerDirectoryError::NotFound)?;
        if worker.worker_epoch != worker_epoch {
            return Err(WorkerDirectoryError::EpochMismatch {
                current: worker.worker_epoch,
                received: worker_epoch,
            });
        }
        if !worker.owned {
            return Err(WorkerDirectoryError::NotOwned);
        }
        if worker.lease_expires_at <= now {
            return Err(WorkerDirectoryError::LeaseExpired);
        }
        if !heartbeat.free.fits_within(worker.capacity) {
            return Err(WorkerDirectoryError::InvalidHeartbeat);
        }
        worker.free = heartbeat.free;
        worker.queue_depth = heartbeat.queue_depth;
        worker.active_shards = heartbeat.active_shards;
        worker.ready = heartbeat.ready;
        worker.lease_expires_at = lease_expires_at;
        Ok(worker.clone())
    }

    pub fn lookup_ready(
        &self,
        worker_id: &WorkerId,
        now: DirectoryTime,
    ) -> Result<WorkerDirectorySnapshot, WorkerDirectoryError> {
        let workers = self.lock_workers()?;
        let worker = workers
            .get(worker_id)
            .ok_or(WorkerDirectoryError::NotFound)?;
        if !worker.owned {
            return Err(WorkerDirectoryError::NotOwned);
        }
        if worker.lease_expires_at <= now {
            return Err(WorkerDirectoryError::LeaseExpired);
        }
        if !worker.ready {
            return Err(WorkerDirectoryError::NotReady);
        }
        Ok(worker.clone())
    }

    pub fn expire_workers(
        &self,
        now: DirectoryTime,
        limit: usize,
    ) -> Result<Vec<WorkerDirectorySnapshot>, WorkerDirectoryError> {
        if limit == 0 {
            return Err(WorkerDirectoryError::InvalidLimit);
        }
        let mut workers = self.lock_workers()?;
        let mut expired = Vec::new();
        for worker in workers.values_mut() {
            if expired.len() == limit {
                break;
            }
            if worker.owned && worker.lease_expires_at <= now {
                worker.owned = false;
                worker.ready = false;
                expired.push(worker.clone());
            }
        }
        Ok(expired)
    }

    fn checked_expiry(&self, now: DirectoryTime) -> Result<DirectoryTime, WorkerDirectoryError> {
        now.as_millis()
            .checked_add(self.lease_duration_millis)
            .map(DirectoryTime::from_millis)
            .ok_or(WorkerDirectoryError::TimeOverflow)
    }

    fn lock_workers(
        &self,
    ) -> Result<MutexGuard<'_, BTreeMap<WorkerId, WorkerDirectorySnapshot>>, WorkerDirectoryError>
    {
        self.workers
            .lock()
            .map_err(|_| WorkerDirectoryError::StateUnavailable)
    }
}
