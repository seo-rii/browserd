use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;

use crate::ephemeral::{MAX_EPHEMERAL_TTL_MILLIS, ttl_millis};
use crate::{
    DirectoryEntry, DirectoryKey, DirectoryMutation, DirectorySnapshot, EphemeralCoordinationError,
    EphemeralCoordinationStore, OneTimeCapability, OneTimeConsume, OneTimeIssue, WorkerCapacity,
    WorkerHeartbeat, WorkerLeaseMutation, WorkerLeaseStore, WorkerReadiness, WorkerRegistration,
    WorkerRegistrationQuery, WorkerRegistrationSnapshot, WorkerReservationGrant,
    WorkerReservationMutation, WorkerReservationOutcome, WorkerReservationRequest,
    WorkerReservationSnapshot, WorkerReservationStore,
};

#[derive(Clone, Default)]
pub struct ManualCoordinationClock {
    now_millis: Arc<AtomicU64>,
}
impl ManualCoordinationClock {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    pub fn advance(&self, duration: Duration) {
        self.now_millis.fetch_add(
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX),
            Ordering::AcqRel,
        );
    }
    fn now(&self) -> u64 {
        self.now_millis.load(Ordering::Acquire)
    }
}

struct MemoryState {
    directories: HashMap<DirectoryKey, DirectorySnapshot>,
    workers: HashMap<browserd_core::WorkerId, WorkerRegistrationSnapshot>,
    worker_epoch_high_water: HashMap<browserd_core::WorkerId, u64>,
    worker_reserved: HashMap<browserd_core::WorkerId, WorkerCapacity>,
    worker_reservations: HashMap<browserd_core::OperationId, MemoryReservation>,
    worker_reservation_expiry_index:
        HashMap<browserd_core::WorkerId, BTreeSet<(u64, browserd_core::OperationId)>>,
    capabilities:
        HashMap<(browserd_core::TenantId, browserd_core::SessionId, [u8; 32]), CapabilityRecord>,
}

struct CapabilityRecord {
    expires_at_millis: u64,
    consumed: bool,
}

struct MemoryReservation {
    snapshot: WorkerReservationSnapshot,
    worker: WorkerRegistrationSnapshot,
    terminal_reason: Option<MemoryReservationTerminal>,
    tombstone_expires_at_millis: u64,
}

#[derive(Clone, Copy)]
enum MemoryReservationTerminal {
    Released,
    Expired,
}

struct WorkerReservationReclaimPlan {
    worker_id: browserd_core::WorkerId,
    expired: Vec<(u64, browserd_core::OperationId)>,
    tombstone_expires_at_millis: Option<u64>,
    worker: WorkerRegistrationSnapshot,
    reserved: WorkerCapacity,
    worker_changed: bool,
}

impl WorkerReservationReclaimPlan {
    fn apply(self, state: &mut MemoryState) -> WorkerRegistrationSnapshot {
        if let Some(index) = state
            .worker_reservation_expiry_index
            .get_mut(&self.worker_id)
        {
            for (expires_at, operation_id) in &self.expired {
                let removed = index.remove(&(*expires_at, operation_id.clone()));
                debug_assert!(removed);
            }
        }
        if let Some(tombstone_expires_at_millis) = self.tombstone_expires_at_millis {
            for (_, operation_id) in self.expired {
                if let Some(record) = state.worker_reservations.get_mut(&operation_id) {
                    record.terminal_reason = Some(MemoryReservationTerminal::Expired);
                    record.tombstone_expires_at_millis = tombstone_expires_at_millis;
                }
            }
        }
        if self.worker_changed {
            state
                .worker_reserved
                .insert(self.worker_id.clone(), self.reserved);
            state.workers.insert(self.worker_id, self.worker.clone());
        }
        self.worker
    }
}

pub struct MemoryEphemeralCoordinationStore {
    clock: ManualCoordinationClock,
    available: AtomicBool,
    state: Mutex<MemoryState>,
}
impl MemoryEphemeralCoordinationStore {
    #[must_use]
    pub fn new(clock: ManualCoordinationClock) -> Self {
        Self {
            clock,
            available: AtomicBool::new(true),
            state: Mutex::new(MemoryState {
                directories: HashMap::new(),
                workers: HashMap::new(),
                worker_epoch_high_water: HashMap::new(),
                worker_reserved: HashMap::new(),
                worker_reservations: HashMap::new(),
                worker_reservation_expiry_index: HashMap::new(),
                capabilities: HashMap::new(),
            }),
        }
    }
    pub fn set_available(&self, available: bool) {
        self.available.store(available, Ordering::Release);
    }
    #[must_use]
    pub fn from_snapshot(clock: ManualCoordinationClock, snapshot: DirectorySnapshot) -> Self {
        let store = Self::new(clock);
        if let Ok(mut state) = store.state.lock() {
            state
                .directories
                .insert(snapshot.entry().key().clone(), snapshot);
        }
        store
    }
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, MemoryState>, EphemeralCoordinationError> {
        if !self.available.load(Ordering::Acquire) {
            return Err(EphemeralCoordinationError::Unavailable);
        }
        self.state
            .lock()
            .map_err(|_| EphemeralCoordinationError::Unavailable)
    }
}

fn plan_expired_worker_reservations(
    state: &MemoryState,
    current: WorkerRegistrationSnapshot,
    now: u64,
) -> Result<WorkerReservationReclaimPlan, EphemeralCoordinationError> {
    let worker_id = current.registration().worker_id().clone();
    let current_reserved = state
        .worker_reserved
        .get(&worker_id)
        .copied()
        .ok_or(EphemeralCoordinationError::InvalidResponse)?;
    let expired = state
        .worker_reservation_expiry_index
        .get(&worker_id)
        .map(|index| {
            index
                .iter()
                .take_while(|(expires_at, _)| *expires_at <= now)
                .take(64)
                .cloned()
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let mut reclaimed = WorkerCapacity::new(0, 0, 0, 0, 0, 0);
    for (expires_at, operation_id) in &expired {
        let Some(record) = state.worker_reservations.get(operation_id) else {
            return Err(EphemeralCoordinationError::InvalidResponse);
        };
        if record.terminal_reason.is_some() {
            return Err(EphemeralCoordinationError::InvalidResponse);
        }
        if record.snapshot.worker_id() != &worker_id
            || record.snapshot.expires_at_millis() != *expires_at
        {
            return Err(EphemeralCoordinationError::InvalidResponse);
        }
        if record.snapshot.worker_epoch() == current.worker_epoch() {
            reclaimed = reclaimed
                .checked_add(record.snapshot.resources())
                .ok_or(EphemeralCoordinationError::InvalidResponse)?;
        }
    }
    let tombstone_expires_at_millis = if expired.is_empty() {
        None
    } else {
        Some(
            now.checked_add(MAX_EPHEMERAL_TTL_MILLIS)
                .ok_or(EphemeralCoordinationError::InvalidInput)?,
        )
    };
    let worker_changed = !reclaimed.is_zero();
    let (worker, reserved) = if worker_changed {
        let reserved = current_reserved
            .checked_sub(reclaimed)
            .ok_or(EphemeralCoordinationError::InvalidResponse)?;
        let free = current
            .heartbeat()
            .free()
            .checked_add(reclaimed)
            .filter(|free| free.fits_within(current.registration().capacity()))
            .ok_or(EphemeralCoordinationError::InvalidResponse)?;
        let heartbeat = WorkerHeartbeat::new(
            free,
            current.heartbeat().queue_depth(),
            current.heartbeat().active_shards(),
            current.heartbeat().readiness(),
        )?;
        let worker = WorkerRegistrationSnapshot::from_persisted(
            current.registration().clone(),
            heartbeat,
            current
                .revision()
                .checked_add(1)
                .ok_or(EphemeralCoordinationError::RevisionExhausted)?,
            current.expires_at_millis(),
        )?;
        (worker, reserved)
    } else {
        (current, current_reserved)
    };
    Ok(WorkerReservationReclaimPlan {
        worker_id,
        expired,
        tombstone_expires_at_millis,
        worker,
        reserved,
        worker_changed,
    })
}

#[async_trait]
impl EphemeralCoordinationStore for MemoryEphemeralCoordinationStore {
    async fn register_directory(
        &self,
        entry: DirectoryEntry,
        ttl: Duration,
    ) -> Result<DirectoryMutation, EphemeralCoordinationError> {
        let expires = self
            .clock
            .now()
            .checked_add(ttl_millis(ttl)?)
            .ok_or(EphemeralCoordinationError::InvalidInput)?;
        let mut state = self.lock()?;
        if state
            .directories
            .get(entry.key())
            .is_some_and(|current| current.expires_at_millis() <= self.clock.now())
        {
            state.directories.remove(entry.key());
        }
        if let Some(current) = state.directories.get(entry.key()) {
            let requested = entry.fence();
            let existing = current.entry().fence();
            if current.entry() == &entry {
                return Ok(DirectoryMutation::AlreadyApplied);
            }
            if requested.session_incarnation() < existing.session_incarnation()
                || requested.placement_version() <= existing.placement_version()
                || (requested.worker_id() == existing.worker_id()
                    && requested.worker_epoch() < existing.worker_epoch())
            {
                return Ok(DirectoryMutation::FenceMismatch);
            }
        }
        let revision = match state.directories.get(entry.key()) {
            Some(item) => item
                .revision()
                .checked_add(1)
                .ok_or(EphemeralCoordinationError::RevisionExhausted)?,
            None => 1,
        };
        state.directories.insert(
            entry.key().clone(),
            DirectorySnapshot::new(entry, revision, expires),
        );
        Ok(DirectoryMutation::Applied)
    }
    async fn resolve_directory(
        &self,
        key: &DirectoryKey,
    ) -> Result<Option<DirectorySnapshot>, EphemeralCoordinationError> {
        let mut state = self.lock()?;
        let now = self.clock.now();
        if state
            .directories
            .get(key)
            .is_some_and(|value| value.expires_at_millis() <= now)
        {
            state.directories.remove(key);
        }
        Ok(state.directories.get(key).cloned())
    }
    async fn renew_directory(
        &self,
        snapshot: &DirectorySnapshot,
        ttl: Duration,
    ) -> Result<DirectoryMutation, EphemeralCoordinationError> {
        let now = self.clock.now();
        let expires = now
            .checked_add(ttl_millis(ttl)?)
            .ok_or(EphemeralCoordinationError::InvalidInput)?;
        let mut state = self.lock()?;
        let Some(current) = state.directories.get_mut(snapshot.entry().key()) else {
            return Ok(DirectoryMutation::Expired);
        };
        if current.expires_at_millis() <= now {
            state.directories.remove(snapshot.entry().key());
            return Ok(DirectoryMutation::Expired);
        }
        if current.revision() != snapshot.revision() || current.entry() != snapshot.entry() {
            return Ok(DirectoryMutation::CasMismatch);
        }
        let revision = current
            .revision()
            .checked_add(1)
            .ok_or(EphemeralCoordinationError::RevisionExhausted)?;
        *current = DirectorySnapshot::new(current.entry().clone(), revision, expires);
        Ok(DirectoryMutation::Applied)
    }
    async fn remove_directory(
        &self,
        snapshot: &DirectorySnapshot,
    ) -> Result<DirectoryMutation, EphemeralCoordinationError> {
        let now = self.clock.now();
        let mut state = self.lock()?;
        let Some(current) = state.directories.get(snapshot.entry().key()) else {
            return Ok(DirectoryMutation::Expired);
        };
        if current.expires_at_millis() <= now {
            state.directories.remove(snapshot.entry().key());
            return Ok(DirectoryMutation::Expired);
        }
        if current.revision() != snapshot.revision() || current.entry() != snapshot.entry() {
            return Ok(DirectoryMutation::CasMismatch);
        }
        state.directories.remove(snapshot.entry().key());
        Ok(DirectoryMutation::Applied)
    }
    async fn issue_one_time(
        &self,
        capability: OneTimeCapability,
        ttl: Duration,
    ) -> Result<OneTimeIssue, EphemeralCoordinationError> {
        let expires = self
            .clock
            .now()
            .checked_add(ttl_millis(ttl)?)
            .ok_or(EphemeralCoordinationError::InvalidInput)?;
        let key = (
            capability.tenant_id().clone(),
            capability.session_id().clone(),
            *capability.secret_hash(),
        );
        let mut state = self.lock()?;
        if state
            .capabilities
            .get(&key)
            .is_some_and(|current| current.expires_at_millis <= self.clock.now())
        {
            state.capabilities.remove(&key);
        }
        if let Some(current) = state.capabilities.get(&key) {
            return Ok(if current.consumed {
                OneTimeIssue::AlreadyConsumed
            } else {
                OneTimeIssue::AlreadyIssued
            });
        }
        state.capabilities.insert(
            key,
            CapabilityRecord {
                expires_at_millis: expires,
                consumed: false,
            },
        );
        Ok(OneTimeIssue::Issued)
    }
    async fn consume_one_time(
        &self,
        capability: &OneTimeCapability,
    ) -> Result<OneTimeConsume, EphemeralCoordinationError> {
        let now = self.clock.now();
        let key = (
            capability.tenant_id().clone(),
            capability.session_id().clone(),
            *capability.secret_hash(),
        );
        let mut state = self.lock()?;
        let Some(record) = state.capabilities.get_mut(&key) else {
            return Ok(OneTimeConsume::AlreadyConsumed);
        };
        if record.consumed {
            return Ok(OneTimeConsume::AlreadyConsumed);
        }
        if record.expires_at_millis <= now {
            state.capabilities.remove(&key);
            return Ok(OneTimeConsume::AlreadyConsumed);
        }
        record.consumed = true;
        record.expires_at_millis = now
            .checked_add(MAX_EPHEMERAL_TTL_MILLIS)
            .ok_or(EphemeralCoordinationError::InvalidInput)?;
        Ok(OneTimeConsume::Consumed)
    }
}

#[async_trait]
impl WorkerLeaseStore for MemoryEphemeralCoordinationStore {
    async fn register_worker(
        &self,
        registration: WorkerRegistration,
        heartbeat: WorkerHeartbeat,
        ttl: Duration,
    ) -> Result<WorkerLeaseMutation, EphemeralCoordinationError> {
        let now = self.clock.now();
        let expires = now
            .checked_add(ttl_millis(ttl)?)
            .ok_or(EphemeralCoordinationError::InvalidInput)?;
        if !heartbeat.free().fits_within(registration.capacity()) {
            return Err(EphemeralCoordinationError::InvalidInput);
        }
        let mut state = self.lock()?;
        if state
            .worker_epoch_high_water
            .get(registration.worker_id())
            .is_some_and(|high_water| registration.worker_epoch() < *high_water)
        {
            return Ok(WorkerLeaseMutation::FenceMismatch);
        }
        let current = state.workers.get(registration.worker_id()).cloned();
        if state
            .worker_epoch_high_water
            .get(registration.worker_id())
            .is_some_and(|high_water| *high_water == registration.worker_epoch())
            && current
                .as_ref()
                .is_some_and(|snapshot| snapshot.expires_at_millis() <= now)
        {
            return Ok(WorkerLeaseMutation::FenceMismatch);
        }
        if let Some(current) = current
            .as_ref()
            .filter(|value| value.expires_at_millis() > now)
        {
            if registration.worker_epoch() < current.worker_epoch() {
                return Ok(WorkerLeaseMutation::FenceMismatch);
            }
            if registration.worker_epoch() == current.worker_epoch() {
                return Ok(if &registration == current.registration() {
                    WorkerLeaseMutation::AlreadyApplied
                } else {
                    WorkerLeaseMutation::FenceMismatch
                });
            }
        }
        let revision = current
            .map_or(Some(1), |value| value.revision().checked_add(1))
            .ok_or(EphemeralCoordinationError::InvalidInput)?;
        let worker_id = registration.worker_id().clone();
        state
            .worker_epoch_high_water
            .insert(worker_id.clone(), registration.worker_epoch());
        state
            .worker_reserved
            .insert(worker_id.clone(), WorkerCapacity::new(0, 0, 0, 0, 0, 0));
        let snapshot =
            WorkerRegistrationSnapshot::from_persisted(registration, heartbeat, revision, expires)?;
        state.workers.insert(worker_id, snapshot.clone());
        Ok(WorkerLeaseMutation::Applied(Box::new(snapshot)))
    }

    async fn heartbeat_worker(
        &self,
        expected: &WorkerRegistrationSnapshot,
        heartbeat: WorkerHeartbeat,
        ttl: Duration,
    ) -> Result<WorkerLeaseMutation, EphemeralCoordinationError> {
        let now = self.clock.now();
        let expires = now
            .checked_add(ttl_millis(ttl)?)
            .ok_or(EphemeralCoordinationError::InvalidInput)?;
        if !heartbeat
            .free()
            .fits_within(expected.registration().capacity())
        {
            return Err(EphemeralCoordinationError::InvalidInput);
        }
        let mut state = self.lock()?;
        let Some(current) = state
            .workers
            .get(expected.registration().worker_id())
            .cloned()
        else {
            return Ok(WorkerLeaseMutation::Expired);
        };
        if current.expires_at_millis() <= now {
            state.workers.remove(expected.registration().worker_id());
            return Ok(WorkerLeaseMutation::Expired);
        }
        if current.worker_epoch() != expected.worker_epoch() {
            return Ok(WorkerLeaseMutation::FenceMismatch);
        }
        if &current != expected {
            return Ok(WorkerLeaseMutation::CasMismatch);
        }
        let reclaim = plan_expired_worker_reservations(&state, current, now)?;
        let current = reclaim.worker.clone();
        let reserved = reclaim.reserved;
        let effective_free = heartbeat
            .free()
            .checked_sub(reserved)
            .ok_or(EphemeralCoordinationError::InvalidInput)?;
        let heartbeat = WorkerHeartbeat::new(
            effective_free,
            heartbeat.queue_depth(),
            heartbeat.active_shards(),
            heartbeat.readiness(),
        )?;
        let revision = current
            .revision()
            .checked_add(1)
            .ok_or(EphemeralCoordinationError::RevisionExhausted)?;
        let snapshot = WorkerRegistrationSnapshot::from_persisted(
            current.registration().clone(),
            heartbeat,
            revision,
            expires,
        )?;
        reclaim.apply(&mut state);
        state.workers.insert(
            expected.registration().worker_id().clone(),
            snapshot.clone(),
        );
        Ok(WorkerLeaseMutation::Applied(Box::new(snapshot)))
    }

    async fn query_ready_workers(
        &self,
        query: &WorkerRegistrationQuery,
    ) -> Result<Vec<WorkerRegistrationSnapshot>, EphemeralCoordinationError> {
        let now = self.clock.now();
        let state = self.lock()?;
        let mut matches = state
            .workers
            .values()
            .filter(|snapshot| {
                snapshot.expires_at_millis() > now
                    && snapshot.heartbeat().readiness() == WorkerReadiness::Ready
                    && snapshot.registration().region() == query.region()
                    && snapshot
                        .registration()
                        .compatibility()
                        .iter()
                        .any(|value| value == query.compatibility())
            })
            .cloned()
            .collect::<Vec<_>>();
        matches.sort_by(|left, right| {
            left.registration()
                .worker_id()
                .as_str()
                .cmp(right.registration().worker_id().as_str())
        });
        matches.truncate(query.limit());
        Ok(matches)
    }
}

#[async_trait]
impl WorkerReservationStore for MemoryEphemeralCoordinationStore {
    async fn reserve_worker(
        &self,
        expected_worker: &WorkerRegistrationSnapshot,
        request: WorkerReservationRequest,
        ttl: Duration,
    ) -> Result<WorkerReservationOutcome, EphemeralCoordinationError> {
        let now = self.clock.now();
        let expires = now
            .checked_add(ttl_millis(ttl)?)
            .ok_or(EphemeralCoordinationError::InvalidInput)?;
        let mut state = self.lock()?;
        let existing = state
            .worker_reservations
            .get(request.operation_id())
            .filter(|existing| {
                existing.terminal_reason.is_none() || existing.tombstone_expires_at_millis > now
            });
        if let Some(existing) = existing {
            if existing.snapshot.request() != &request {
                return Ok(WorkerReservationOutcome::Conflict);
            }
            if let Some(reason) = existing.terminal_reason {
                return Ok(match reason {
                    MemoryReservationTerminal::Released => WorkerReservationOutcome::Conflict,
                    MemoryReservationTerminal::Expired => WorkerReservationOutcome::Expired,
                });
            }
            if existing.snapshot.expires_at_millis() <= now {
                return Ok(WorkerReservationOutcome::Expired);
            }
            return Ok(WorkerReservationOutcome::Existing(Box::new(
                WorkerReservationGrant::new(existing.snapshot.clone(), existing.worker.clone()),
            )));
        }
        let worker_id = expected_worker.registration().worker_id().clone();
        let Some(mut current) = state.workers.get(&worker_id).cloned() else {
            return Ok(WorkerReservationOutcome::WorkerUnavailable);
        };
        if current.expires_at_millis() <= now
            || current.heartbeat().readiness() != WorkerReadiness::Ready
        {
            return Ok(WorkerReservationOutcome::WorkerUnavailable);
        }
        if expires > current.expires_at_millis() {
            return Err(EphemeralCoordinationError::InvalidInput);
        }
        if current.worker_epoch() != expected_worker.worker_epoch() {
            return Ok(WorkerReservationOutcome::FenceMismatch);
        }
        if &current != expected_worker {
            return Ok(WorkerReservationOutcome::CasMismatch);
        }

        let reclaim = plan_expired_worker_reservations(&state, current, now)?;
        current = reclaim.worker.clone();
        let Some(free) = current.heartbeat().free().checked_sub(request.resources()) else {
            reclaim.apply(&mut state);
            return Ok(WorkerReservationOutcome::CapacityExhausted);
        };
        let reserved = reclaim
            .reserved
            .checked_add(request.resources())
            .ok_or(EphemeralCoordinationError::InvalidResponse)?;
        let heartbeat = WorkerHeartbeat::new(
            free,
            current.heartbeat().queue_depth(),
            current.heartbeat().active_shards(),
            current.heartbeat().readiness(),
        )?;
        let worker = WorkerRegistrationSnapshot::from_persisted(
            current.registration().clone(),
            heartbeat,
            current
                .revision()
                .checked_add(1)
                .ok_or(EphemeralCoordinationError::RevisionExhausted)?,
            current.expires_at_millis(),
        )?;
        let reservation =
            WorkerReservationSnapshot::from_persisted(request.clone(), worker.clone(), expires)?;
        state.worker_reservations.retain(|_, record| {
            record.terminal_reason.is_none() || record.tombstone_expires_at_millis > now
        });
        reclaim.apply(&mut state);
        state.workers.insert(worker_id, worker.clone());
        state
            .worker_reserved
            .insert(worker.registration().worker_id().clone(), reserved);
        state.worker_reservations.insert(
            request.operation_id().clone(),
            MemoryReservation {
                snapshot: reservation.clone(),
                worker: worker.clone(),
                terminal_reason: None,
                tombstone_expires_at_millis: expires,
            },
        );
        state
            .worker_reservation_expiry_index
            .entry(worker.registration().worker_id().clone())
            .or_default()
            .insert((expires, request.operation_id().clone()));
        Ok(WorkerReservationOutcome::Acquired(Box::new(
            WorkerReservationGrant::new(reservation, worker),
        )))
    }

    async fn release_worker_reservation(
        &self,
        expected: &WorkerReservationSnapshot,
    ) -> Result<WorkerReservationMutation, EphemeralCoordinationError> {
        let now = self.clock.now();
        let mut state = self.lock()?;
        let Some(record) = state
            .worker_reservations
            .get(expected.operation_id())
            .map(|record| {
                (
                    record.snapshot.clone(),
                    record.terminal_reason,
                    record.worker.clone(),
                )
            })
        else {
            return Ok(WorkerReservationMutation::Expired);
        };
        if let Some(reason) = record.1 {
            return Ok(match reason {
                MemoryReservationTerminal::Released => WorkerReservationMutation::AlreadyReleased,
                MemoryReservationTerminal::Expired => WorkerReservationMutation::Expired,
            });
        }
        let expired = record.0.expires_at_millis() <= now;
        if &record.0 != expected {
            return Ok(WorkerReservationMutation::CasMismatch);
        }
        let Some(current) = state.workers.get(expected.worker_id()).cloned() else {
            return Ok(WorkerReservationMutation::Expired);
        };
        if current.worker_epoch() != expected.worker_epoch() {
            return Ok(WorkerReservationMutation::FenceMismatch);
        }
        let free = current
            .heartbeat()
            .free()
            .checked_add(expected.resources())
            .filter(|free| free.fits_within(current.registration().capacity()))
            .ok_or(EphemeralCoordinationError::InvalidResponse)?;
        let reserved = state
            .worker_reserved
            .get(expected.worker_id())
            .copied()
            .ok_or(EphemeralCoordinationError::InvalidResponse)?
            .checked_sub(expected.resources())
            .ok_or(EphemeralCoordinationError::InvalidResponse)?;
        let heartbeat = WorkerHeartbeat::new(
            free,
            current.heartbeat().queue_depth(),
            current.heartbeat().active_shards(),
            current.heartbeat().readiness(),
        )?;
        let worker = WorkerRegistrationSnapshot::from_persisted(
            current.registration().clone(),
            heartbeat,
            current
                .revision()
                .checked_add(1)
                .ok_or(EphemeralCoordinationError::RevisionExhausted)?,
            current.expires_at_millis(),
        )?;
        let tombstone_expires_at_millis = now
            .checked_add(MAX_EPHEMERAL_TTL_MILLIS)
            .ok_or(EphemeralCoordinationError::InvalidInput)?;
        let indexed = state
            .worker_reservation_expiry_index
            .get(expected.worker_id())
            .is_some_and(|index| {
                index.contains(&(
                    expected.expires_at_millis(),
                    expected.operation_id().clone(),
                ))
            });
        if !indexed {
            return Err(EphemeralCoordinationError::InvalidResponse);
        }
        if let Some(index) = state
            .worker_reservation_expiry_index
            .get_mut(expected.worker_id())
        {
            let removed = index.remove(&(
                expected.expires_at_millis(),
                expected.operation_id().clone(),
            ));
            debug_assert!(removed);
        }
        state
            .workers
            .insert(expected.worker_id().clone(), worker.clone());
        state
            .worker_reserved
            .insert(expected.worker_id().clone(), reserved);
        if let Some(stored) = state.worker_reservations.get_mut(expected.operation_id()) {
            stored.terminal_reason = Some(if expired {
                MemoryReservationTerminal::Expired
            } else {
                MemoryReservationTerminal::Released
            });
            stored.tombstone_expires_at_millis = tombstone_expires_at_millis;
        }
        if expired {
            return Ok(WorkerReservationMutation::Expired);
        }
        Ok(WorkerReservationMutation::Released(Box::new(worker)))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::panic, clippy::too_many_arguments)]

    use super::*;
    use browserd_core::{OperationId, TenantId, WorkerId};

    fn capacity(memory_bytes: u64) -> WorkerCapacity {
        WorkerCapacity::new(memory_bytes, 0, 0, 0, 0, 0)
    }

    async fn reserved_fixture(
        ttl: Duration,
    ) -> (
        ManualCoordinationClock,
        MemoryEphemeralCoordinationStore,
        WorkerRegistrationSnapshot,
        WorkerReservationSnapshot,
    ) {
        let clock = ManualCoordinationClock::new();
        let store = MemoryEphemeralCoordinationStore::new(clock.clone());
        let registration = WorkerRegistration::new(
            WorkerId::new("memory-atomicity-worker").expect("worker id"),
            7,
            "ap-northeast-2",
            "browserd-2026.08",
            vec!["chromium-140".to_owned()],
            capacity(100),
            "worker-rpc://10.0.0.9:7443",
        )
        .expect("registration");
        let heartbeat =
            WorkerHeartbeat::new(capacity(100), 0, 0, WorkerReadiness::Ready).expect("heartbeat");
        let worker = store
            .register_worker(registration, heartbeat, Duration::from_secs(30))
            .await
            .expect("register")
            .into_snapshot()
            .expect("registered snapshot");
        let request =
            WorkerReservationRequest::new(OperationId::new(), TenantId::new(), capacity(40))
                .expect("reservation request");
        let grant = match store
            .reserve_worker(&worker, request, ttl)
            .await
            .expect("reserve")
        {
            WorkerReservationOutcome::Acquired(grant) => grant,
            outcome => panic!("unexpected reservation outcome: {outcome:?}"),
        };
        let reservation = grant.reservation().clone();
        let worker = grant.worker().clone();
        (clock, store, worker, reservation)
    }

    fn force_worker_revision_max(
        store: &MemoryEphemeralCoordinationStore,
        worker: &WorkerRegistrationSnapshot,
    ) -> WorkerRegistrationSnapshot {
        let max_revision = WorkerRegistrationSnapshot::from_persisted(
            worker.registration().clone(),
            worker.heartbeat().clone(),
            u64::MAX,
            worker.expires_at_millis(),
        )
        .expect("max revision snapshot");
        store.state.lock().expect("state lock").workers.insert(
            worker.registration().worker_id().clone(),
            max_revision.clone(),
        );
        max_revision
    }

    fn assert_reservation_state_unchanged(
        store: &MemoryEphemeralCoordinationStore,
        worker_before: &WorkerRegistrationSnapshot,
        reservation: &WorkerReservationSnapshot,
        index_before: &BTreeSet<(u64, OperationId)>,
        reserved_before: WorkerCapacity,
        record_worker_before: &WorkerRegistrationSnapshot,
        terminal_before: Option<MemoryReservationTerminal>,
        tombstone_before: u64,
    ) {
        let state = store.state.lock().expect("state lock");
        assert_eq!(
            state.workers.get(reservation.worker_id()),
            Some(worker_before)
        );
        assert_eq!(
            state.worker_reserved.get(reservation.worker_id()),
            Some(&reserved_before)
        );
        assert_eq!(
            state
                .worker_reservation_expiry_index
                .get(reservation.worker_id()),
            Some(index_before)
        );
        let record = state
            .worker_reservations
            .get(reservation.operation_id())
            .expect("reservation record");
        assert_eq!(&record.snapshot, reservation);
        assert_eq!(&record.worker, record_worker_before);
        assert_eq!(record.tombstone_expires_at_millis, tombstone_before);
        assert_eq!(
            record
                .terminal_reason
                .map(|value| std::mem::discriminant(&value)),
            terminal_before.map(|value| std::mem::discriminant(&value))
        );
    }

    #[tokio::test]
    async fn reclaim_revision_exhaustion_leaves_all_reservation_state_unchanged() {
        let (clock, store, worker, reservation) = reserved_fixture(Duration::from_millis(10)).await;
        let worker_before = force_worker_revision_max(&store, &worker);
        let (
            index_before,
            reserved_before,
            record_worker_before,
            terminal_before,
            tombstone_before,
        ) = {
            let state = store.state.lock().expect("state lock");
            let record = state
                .worker_reservations
                .get(reservation.operation_id())
                .expect("reservation record");
            (
                state
                    .worker_reservation_expiry_index
                    .get(reservation.worker_id())
                    .expect("expiry index")
                    .clone(),
                *state
                    .worker_reserved
                    .get(reservation.worker_id())
                    .expect("reserved aggregate"),
                record.worker.clone(),
                record.terminal_reason,
                record.tombstone_expires_at_millis,
            )
        };
        clock.advance(Duration::from_millis(10));

        let result = store
            .heartbeat_worker(
                &worker_before,
                worker_before.heartbeat().clone(),
                Duration::from_secs(30),
            )
            .await;
        assert!(matches!(
            result,
            Err(EphemeralCoordinationError::RevisionExhausted)
        ));
        assert_reservation_state_unchanged(
            &store,
            &worker_before,
            &reservation,
            &index_before,
            reserved_before,
            &record_worker_before,
            terminal_before,
            tombstone_before,
        );
    }

    #[tokio::test]
    async fn release_revision_exhaustion_leaves_all_reservation_state_unchanged() {
        let (_clock, store, worker, reservation) = reserved_fixture(Duration::from_secs(5)).await;
        let worker_before = force_worker_revision_max(&store, &worker);
        let (
            index_before,
            reserved_before,
            record_worker_before,
            terminal_before,
            tombstone_before,
        ) = {
            let state = store.state.lock().expect("state lock");
            let record = state
                .worker_reservations
                .get(reservation.operation_id())
                .expect("reservation record");
            (
                state
                    .worker_reservation_expiry_index
                    .get(reservation.worker_id())
                    .expect("expiry index")
                    .clone(),
                *state
                    .worker_reserved
                    .get(reservation.worker_id())
                    .expect("reserved aggregate"),
                record.worker.clone(),
                record.terminal_reason,
                record.tombstone_expires_at_millis,
            )
        };

        let result = store.release_worker_reservation(&reservation).await;
        assert!(matches!(
            result,
            Err(EphemeralCoordinationError::RevisionExhausted)
        ));
        assert_reservation_state_unchanged(
            &store,
            &worker_before,
            &reservation,
            &index_before,
            reserved_before,
            &record_worker_before,
            terminal_before,
            tombstone_before,
        );
    }

    #[tokio::test]
    async fn invalid_heartbeat_after_expiry_reclaim_leaves_all_reservations_unchanged() {
        let (clock, store, worker, expired) = reserved_fixture(Duration::from_millis(10)).await;
        let active = match store
            .reserve_worker(
                &worker,
                WorkerReservationRequest::new(OperationId::new(), TenantId::new(), capacity(30))
                    .expect("active request"),
                Duration::from_secs(5),
            )
            .await
            .expect("active reserve")
        {
            WorkerReservationOutcome::Acquired(grant) => grant,
            outcome => panic!("unexpected active reservation outcome: {outcome:?}"),
        };
        let worker_before = active.worker().clone();
        let (index_before, reserved_before, expired_before, active_before) = {
            let state = store.state.lock().expect("state lock");
            let capture = |reservation: &WorkerReservationSnapshot| {
                let record = state
                    .worker_reservations
                    .get(reservation.operation_id())
                    .expect("reservation record");
                (
                    record.worker.clone(),
                    record.terminal_reason,
                    record.tombstone_expires_at_millis,
                )
            };
            (
                state
                    .worker_reservation_expiry_index
                    .get(expired.worker_id())
                    .expect("expiry index")
                    .clone(),
                *state
                    .worker_reserved
                    .get(expired.worker_id())
                    .expect("reserved aggregate"),
                capture(&expired),
                capture(active.reservation()),
            )
        };
        clock.advance(Duration::from_millis(10));
        assert_eq!(
            store
                .heartbeat_worker(
                    &worker_before,
                    WorkerHeartbeat::new(capacity(20), 0, 0, WorkerReadiness::Ready)
                        .expect("heartbeat"),
                    Duration::from_secs(20),
                )
                .await,
            Err(EphemeralCoordinationError::InvalidInput)
        );
        assert_reservation_state_unchanged(
            &store,
            &worker_before,
            &expired,
            &index_before,
            reserved_before,
            &expired_before.0,
            expired_before.1,
            expired_before.2,
        );
        assert_reservation_state_unchanged(
            &store,
            &worker_before,
            active.reservation(),
            &index_before,
            reserved_before,
            &active_before.0,
            active_before.1,
            active_before.2,
        );
    }

    #[tokio::test]
    async fn final_heartbeat_revision_overflow_after_reclaim_leaves_state_unchanged() {
        let (clock, store, worker, reservation) = reserved_fixture(Duration::from_millis(10)).await;
        let worker_before = WorkerRegistrationSnapshot::from_persisted(
            worker.registration().clone(),
            worker.heartbeat().clone(),
            u64::MAX - 1,
            worker.expires_at_millis(),
        )
        .expect("near-max revision snapshot");
        store.state.lock().expect("state lock").workers.insert(
            worker.registration().worker_id().clone(),
            worker_before.clone(),
        );
        let (
            index_before,
            reserved_before,
            record_worker_before,
            terminal_before,
            tombstone_before,
        ) = {
            let state = store.state.lock().expect("state lock");
            let record = state
                .worker_reservations
                .get(reservation.operation_id())
                .expect("record");
            (
                state
                    .worker_reservation_expiry_index
                    .get(reservation.worker_id())
                    .expect("index")
                    .clone(),
                *state
                    .worker_reserved
                    .get(reservation.worker_id())
                    .expect("reserved"),
                record.worker.clone(),
                record.terminal_reason,
                record.tombstone_expires_at_millis,
            )
        };
        clock.advance(Duration::from_millis(10));
        assert_eq!(
            store
                .heartbeat_worker(
                    &worker_before,
                    worker_before.heartbeat().clone(),
                    Duration::from_secs(20)
                )
                .await,
            Err(EphemeralCoordinationError::RevisionExhausted)
        );
        assert_reservation_state_unchanged(
            &store,
            &worker_before,
            &reservation,
            &index_before,
            reserved_before,
            &record_worker_before,
            terminal_before,
            tombstone_before,
        );
    }

    #[tokio::test]
    async fn expired_operation_outcome_precedes_worker_fencing_and_conflicting_reuse() {
        let (clock, store, stale_worker, reservation) =
            reserved_fixture(Duration::from_millis(10)).await;
        clock.advance(Duration::from_millis(10));
        let current_worker = store
            .register_worker(
                WorkerRegistration::new(
                    reservation.worker_id().clone(),
                    reservation.worker_epoch() + 1,
                    "ap-northeast-2",
                    "browserd-2026.08",
                    vec!["chromium-140".to_owned()],
                    capacity(100),
                    "worker-rpc://10.0.0.9:7443",
                )
                .expect("higher epoch registration"),
                WorkerHeartbeat::new(capacity(100), 0, 0, WorkerReadiness::Ready)
                    .expect("higher epoch heartbeat"),
                Duration::from_secs(30),
            )
            .await
            .expect("higher epoch register")
            .into_snapshot()
            .expect("higher epoch snapshot");

        let exact = store
            .reserve_worker(
                &stale_worker,
                reservation.request().clone(),
                Duration::from_secs(5),
            )
            .await
            .expect("expired exact retry outcome");
        let conflict = store
            .reserve_worker(
                &current_worker,
                WorkerReservationRequest::new(
                    reservation.operation_id().clone(),
                    TenantId::new(),
                    capacity(41),
                )
                .expect("conflicting request"),
                Duration::from_secs(5),
            )
            .await
            .expect("expired conflicting retry outcome");

        assert_eq!(exact, WorkerReservationOutcome::Expired);
        assert_eq!(conflict, WorkerReservationOutcome::Conflict);
    }

    #[tokio::test]
    async fn failed_reservation_does_not_collect_terminal_operation_tombstones() {
        let (clock, store, _worker, reservation) = reserved_fixture(Duration::from_secs(5)).await;
        let released_worker = store
            .release_worker_reservation(&reservation)
            .await
            .expect("release")
            .into_worker()
            .expect("released worker");
        clock.advance(Duration::from_millis(1));
        let renewed_worker = store
            .heartbeat_worker(
                &released_worker,
                released_worker.heartbeat().clone(),
                Duration::from_millis(MAX_EPHEMERAL_TTL_MILLIS),
            )
            .await
            .expect("renew worker beyond tombstone horizon")
            .into_snapshot()
            .expect("renewed worker");
        clock.advance(Duration::from_millis(MAX_EPHEMERAL_TTL_MILLIS - 1));
        let worker_before = force_worker_revision_max(&store, &renewed_worker);

        let result = store
            .reserve_worker(
                &worker_before,
                WorkerReservationRequest::new(OperationId::new(), TenantId::new(), capacity(1))
                    .expect("new request"),
                Duration::from_millis(1),
            )
            .await;

        assert_eq!(result, Err(EphemeralCoordinationError::RevisionExhausted));
        assert!(
            store
                .state
                .lock()
                .expect("state lock")
                .worker_reservations
                .contains_key(reservation.operation_id()),
            "failed reserve must not collect an unrelated terminal tombstone"
        );
    }
}
