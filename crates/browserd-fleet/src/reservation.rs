use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};

use browserd_core::{OperationId, TenantId};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ResourceVector {
    pub memory_bytes: u64,
    pub cpu_millis: u64,
    pub pids: u64,
    pub disk_bytes: u64,
    pub contexts: u64,
    pub targets: u64,
}

impl ResourceVector {
    pub const ZERO: Self = Self::new(0, 0, 0, 0, 0, 0);

    #[must_use]
    pub const fn new(
        memory_bytes: u64,
        cpu_millis: u64,
        pids: u64,
        disk_bytes: u64,
        contexts: u64,
        targets: u64,
    ) -> Self {
        Self {
            memory_bytes,
            cpu_millis,
            pids,
            disk_bytes,
            contexts,
            targets,
        }
    }

    #[must_use]
    pub const fn fits_within(self, capacity: Self) -> bool {
        self.memory_bytes <= capacity.memory_bytes
            && self.cpu_millis <= capacity.cpu_millis
            && self.pids <= capacity.pids
            && self.disk_bytes <= capacity.disk_bytes
            && self.contexts <= capacity.contexts
            && self.targets <= capacity.targets
    }

    fn checked_add(self, other: Self) -> Option<Self> {
        Some(Self {
            memory_bytes: self.memory_bytes.checked_add(other.memory_bytes)?,
            cpu_millis: self.cpu_millis.checked_add(other.cpu_millis)?,
            pids: self.pids.checked_add(other.pids)?,
            disk_bytes: self.disk_bytes.checked_add(other.disk_bytes)?,
            contexts: self.contexts.checked_add(other.contexts)?,
            targets: self.targets.checked_add(other.targets)?,
        })
    }

    fn checked_sub(self, other: Self) -> Option<Self> {
        Some(Self {
            memory_bytes: self.memory_bytes.checked_sub(other.memory_bytes)?,
            cpu_millis: self.cpu_millis.checked_sub(other.cpu_millis)?,
            pids: self.pids.checked_sub(other.pids)?,
            disk_bytes: self.disk_bytes.checked_sub(other.disk_bytes)?,
            contexts: self.contexts.checked_sub(other.contexts)?,
            targets: self.targets.checked_sub(other.targets)?,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReservationError {
    InvalidRequest,
    ArithmeticOverflow,
    InsufficientCapacity,
    OperationConflict,
}

impl fmt::Display for ReservationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "worker reservation failed: {self:?}")
    }
}

impl std::error::Error for ReservationError {}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReservationSnapshot {
    pub capacity: ResourceVector,
    pub reserved: ResourceVector,
    pub active: ResourceVector,
    pub reservation_count: usize,
    pub allocation_count: usize,
}

#[derive(Debug)]
enum ClaimState {
    Reserved,
    Active,
}

#[derive(Debug)]
struct Claim {
    tenant_id: TenantId,
    resources: ResourceVector,
    state: ClaimState,
}

#[derive(Debug)]
struct PoolState {
    reserved: ResourceVector,
    active: ResourceVector,
    claims: HashMap<OperationId, Claim>,
}

#[derive(Debug)]
struct PoolInner {
    capacity: ResourceVector,
    state: Mutex<PoolState>,
}

#[derive(Clone, Debug)]
pub struct ReservationPool {
    inner: Arc<PoolInner>,
}

impl ReservationPool {
    #[must_use]
    pub fn new(capacity: ResourceVector) -> Self {
        Self {
            inner: Arc::new(PoolInner {
                capacity,
                state: Mutex::new(PoolState {
                    reserved: ResourceVector::ZERO,
                    active: ResourceVector::ZERO,
                    claims: HashMap::new(),
                }),
            }),
        }
    }

    pub fn reserve(
        &self,
        operation_id: OperationId,
        tenant_id: TenantId,
        resources: ResourceVector,
    ) -> Result<ReservationOutcome, ReservationError> {
        if resources == ResourceVector::ZERO {
            return Err(ReservationError::InvalidRequest);
        }
        let mut state = lock(&self.inner.state);
        if let Some(existing) = state.claims.get(&operation_id) {
            return if existing.tenant_id == tenant_id && existing.resources == resources {
                Ok(ReservationOutcome::Existing)
            } else {
                Err(ReservationError::OperationConflict)
            };
        }
        let used = state
            .reserved
            .checked_add(state.active)
            .ok_or(ReservationError::ArithmeticOverflow)?;
        let attempted = used
            .checked_add(resources)
            .ok_or(ReservationError::ArithmeticOverflow)?;
        if !attempted.fits_within(self.inner.capacity) {
            return Err(ReservationError::InsufficientCapacity);
        }
        state.reserved = state
            .reserved
            .checked_add(resources)
            .ok_or(ReservationError::ArithmeticOverflow)?;
        state.claims.insert(
            operation_id.clone(),
            Claim {
                tenant_id,
                resources,
                state: ClaimState::Reserved,
            },
        );
        drop(state);
        Ok(ReservationOutcome::Acquired(ReservationLease {
            inner: self.inner.clone(),
            operation_id,
            resources,
            live: true,
        }))
    }

    #[must_use]
    pub fn snapshot(&self) -> ReservationSnapshot {
        let state = lock(&self.inner.state);
        ReservationSnapshot {
            capacity: self.inner.capacity,
            reserved: state.reserved,
            active: state.active,
            reservation_count: state
                .claims
                .values()
                .filter(|claim| matches!(claim.state, ClaimState::Reserved))
                .count(),
            allocation_count: state
                .claims
                .values()
                .filter(|claim| matches!(claim.state, ClaimState::Active))
                .count(),
        }
    }
}

#[derive(Debug)]
pub enum ReservationOutcome {
    Acquired(ReservationLease),
    Existing,
}

impl PartialEq for ReservationOutcome {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Existing, Self::Existing) => true,
            (Self::Acquired(left), Self::Acquired(right)) => {
                left.operation_id == right.operation_id
            }
            _ => false,
        }
    }
}

impl Eq for ReservationOutcome {}

#[derive(Debug)]
pub struct ReservationLease {
    inner: Arc<PoolInner>,
    operation_id: OperationId,
    resources: ResourceVector,
    live: bool,
}

impl ReservationLease {
    #[must_use]
    pub fn commit(mut self) -> ActiveAllocation {
        let mut state = lock(&self.inner.state);
        let can_commit = state
            .claims
            .get(&self.operation_id)
            .is_some_and(|claim| matches!(claim.state, ClaimState::Reserved));
        if can_commit
            && let (Some(next_reserved), Some(next_active)) = (
                state.reserved.checked_sub(self.resources),
                state.active.checked_add(self.resources),
            )
        {
            state.reserved = next_reserved;
            state.active = next_active;
            if let Some(claim) = state.claims.get_mut(&self.operation_id) {
                claim.state = ClaimState::Active;
            }
            self.live = false;
        }
        drop(state);
        ActiveAllocation {
            inner: self.inner.clone(),
            operation_id: self.operation_id.clone(),
            resources: self.resources,
            live: !self.live,
        }
    }
}

impl Drop for ReservationLease {
    fn drop(&mut self) {
        if !self.live {
            return;
        }
        let mut state = lock(&self.inner.state);
        let is_reserved = state
            .claims
            .get(&self.operation_id)
            .is_some_and(|claim| matches!(claim.state, ClaimState::Reserved));
        if is_reserved && let Some(next) = state.reserved.checked_sub(self.resources) {
            state.reserved = next;
            state.claims.remove(&self.operation_id);
        }
        self.live = false;
    }
}

#[derive(Debug)]
pub struct ActiveAllocation {
    inner: Arc<PoolInner>,
    operation_id: OperationId,
    resources: ResourceVector,
    live: bool,
}

impl Drop for ActiveAllocation {
    fn drop(&mut self) {
        if !self.live {
            return;
        }
        let mut state = lock(&self.inner.state);
        let is_active = state
            .claims
            .get(&self.operation_id)
            .is_some_and(|claim| matches!(claim.state, ClaimState::Active));
        if is_active && let Some(next) = state.active.checked_sub(self.resources) {
            state.active = next;
            state.claims.remove(&self.operation_id);
        }
        self.live = false;
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}
