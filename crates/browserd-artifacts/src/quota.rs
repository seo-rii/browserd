use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};

use crate::{ArtifactKey, ArtifactNamespace};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuotaLimits {
    pub max_committed_bytes: u64,
    pub max_in_flight_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuotaDimension {
    CommittedBytes,
    InFlightBytes,
    ReservationBytes,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QuotaError {
    NamespaceDenied,
    ReservationAlreadyExists,
    ReservationClosed,
    SizeOverflow,
    HardLimitExceeded {
        dimension: QuotaDimension,
        limit: u64,
        attempted: u64,
    },
}

impl fmt::Display for QuotaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NamespaceDenied => formatter.write_str("artifact quota namespace denied"),
            Self::ReservationAlreadyExists => {
                formatter.write_str("an active reservation already exists for this artifact")
            }
            Self::ReservationClosed => formatter.write_str("artifact reservation is closed"),
            Self::SizeOverflow => formatter.write_str("artifact byte accounting overflowed"),
            Self::HardLimitExceeded {
                dimension,
                limit,
                attempted,
            } => write!(
                formatter,
                "artifact {dimension:?} hard limit {limit} exceeded by attempted total {attempted}"
            ),
        }
    }
}

impl std::error::Error for QuotaError {}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct QuotaSnapshot {
    pub committed_bytes: u64,
    pub reserved_bytes: u64,
    pub actual_bytes_in_flight: u64,
    pub active_reservations: usize,
}

#[derive(Clone)]
pub struct ArtifactQuota {
    namespace: ArtifactNamespace,
    inner: Arc<QuotaInner>,
}

struct QuotaInner {
    limits: QuotaLimits,
    state: Mutex<QuotaState>,
}

#[derive(Default)]
struct QuotaState {
    committed_bytes: u64,
    reserved_bytes: u64,
    actual_bytes_in_flight: u64,
    next_reservation_id: u64,
    reservations: HashMap<u64, ActiveReservation>,
}

struct ActiveReservation {
    key: ArtifactKey,
    requested_bytes: u64,
    actual_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReservationState {
    Active,
    Committed,
    Aborted,
}

pub struct ArtifactReservation {
    id: u64,
    key: ArtifactKey,
    requested_bytes: u64,
    quota: Arc<QuotaInner>,
    state: Mutex<ReservationState>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReservationCommitOutcome {
    Committed,
    AlreadyCommitted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReservationAbortOutcome {
    Aborted,
    AlreadyAborted,
}

impl ArtifactQuota {
    #[must_use]
    pub fn new(namespace: ArtifactNamespace, limits: QuotaLimits) -> Self {
        Self {
            namespace,
            inner: Arc::new(QuotaInner {
                limits,
                state: Mutex::new(QuotaState::default()),
            }),
        }
    }

    pub async fn reserve(
        &self,
        key: ArtifactKey,
        requested_bytes: u64,
    ) -> Result<ArtifactReservation, QuotaError> {
        self.namespace
            .authorize(&key)
            .map_err(|_| QuotaError::NamespaceDenied)?;

        let mut state = lock(&self.inner.state);
        if state
            .reservations
            .values()
            .any(|reservation| reservation.key == key)
        {
            return Err(QuotaError::ReservationAlreadyExists);
        }

        let attempted_in_flight = checked_total(state.reserved_bytes, requested_bytes)?;
        if attempted_in_flight > self.inner.limits.max_in_flight_bytes {
            return Err(QuotaError::HardLimitExceeded {
                dimension: QuotaDimension::InFlightBytes,
                limit: self.inner.limits.max_in_flight_bytes,
                attempted: attempted_in_flight,
            });
        }

        let attempted_committed = checked_total(state.committed_bytes, attempted_in_flight)?;
        if attempted_committed > self.inner.limits.max_committed_bytes {
            return Err(QuotaError::HardLimitExceeded {
                dimension: QuotaDimension::CommittedBytes,
                limit: self.inner.limits.max_committed_bytes,
                attempted: attempted_committed,
            });
        }

        let id = state.next_reservation_id;
        state.next_reservation_id = state
            .next_reservation_id
            .checked_add(1)
            .ok_or(QuotaError::SizeOverflow)?;
        state.reserved_bytes = attempted_in_flight;
        state.reservations.insert(
            id,
            ActiveReservation {
                key: key.clone(),
                requested_bytes,
                actual_bytes: 0,
            },
        );
        drop(state);

        Ok(ArtifactReservation {
            id,
            key,
            requested_bytes,
            quota: self.inner.clone(),
            state: Mutex::new(ReservationState::Active),
        })
    }

    pub async fn snapshot(&self) -> QuotaSnapshot {
        let state = lock(&self.inner.state);
        QuotaSnapshot {
            committed_bytes: state.committed_bytes,
            reserved_bytes: state.reserved_bytes,
            actual_bytes_in_flight: state.actual_bytes_in_flight,
            active_reservations: state.reservations.len(),
        }
    }
}

impl ArtifactReservation {
    #[must_use]
    pub const fn key(&self) -> &ArtifactKey {
        &self.key
    }

    #[must_use]
    pub const fn requested_bytes(&self) -> u64 {
        self.requested_bytes
    }

    pub async fn add_actual_bytes(&self, bytes: u64) -> Result<(), QuotaError> {
        let lifecycle = lock(&self.state);
        if *lifecycle != ReservationState::Active {
            return Err(QuotaError::ReservationClosed);
        }

        let mut quota = lock(&self.quota.state);
        let current = quota
            .reservations
            .get(&self.id)
            .ok_or(QuotaError::ReservationClosed)?
            .actual_bytes;
        let attempted_reservation = checked_total(current, bytes)?;
        if attempted_reservation > self.requested_bytes {
            return Err(QuotaError::HardLimitExceeded {
                dimension: QuotaDimension::ReservationBytes,
                limit: self.requested_bytes,
                attempted: attempted_reservation,
            });
        }

        let attempted_in_flight = checked_total(quota.actual_bytes_in_flight, bytes)?;
        if attempted_in_flight > self.quota.limits.max_in_flight_bytes {
            return Err(QuotaError::HardLimitExceeded {
                dimension: QuotaDimension::InFlightBytes,
                limit: self.quota.limits.max_in_flight_bytes,
                attempted: attempted_in_flight,
            });
        }

        let active = quota
            .reservations
            .get_mut(&self.id)
            .ok_or(QuotaError::ReservationClosed)?;
        active.actual_bytes = attempted_reservation;
        quota.actual_bytes_in_flight = attempted_in_flight;
        drop(quota);
        drop(lifecycle);
        Ok(())
    }

    pub async fn commit(&self) -> Result<ReservationCommitOutcome, QuotaError> {
        let mut lifecycle = lock(&self.state);
        match *lifecycle {
            ReservationState::Committed => return Ok(ReservationCommitOutcome::AlreadyCommitted),
            ReservationState::Aborted => return Err(QuotaError::ReservationClosed),
            ReservationState::Active => {}
        }

        let mut quota = lock(&self.quota.state);
        let active = quota
            .reservations
            .get(&self.id)
            .ok_or(QuotaError::ReservationClosed)?;
        let requested_bytes = active.requested_bytes;
        let actual_bytes = active.actual_bytes;
        let next_reserved = quota
            .reserved_bytes
            .checked_sub(requested_bytes)
            .ok_or(QuotaError::SizeOverflow)?;
        let next_actual_in_flight = quota
            .actual_bytes_in_flight
            .checked_sub(actual_bytes)
            .ok_or(QuotaError::SizeOverflow)?;
        let next_committed = checked_total(quota.committed_bytes, actual_bytes)?;

        quota.reservations.remove(&self.id);
        quota.reserved_bytes = next_reserved;
        quota.actual_bytes_in_flight = next_actual_in_flight;
        quota.committed_bytes = next_committed;
        *lifecycle = ReservationState::Committed;
        drop(quota);
        drop(lifecycle);
        Ok(ReservationCommitOutcome::Committed)
    }

    pub async fn abort(&self) -> Result<ReservationAbortOutcome, QuotaError> {
        let mut lifecycle = lock(&self.state);
        match *lifecycle {
            ReservationState::Aborted => return Ok(ReservationAbortOutcome::AlreadyAborted),
            ReservationState::Committed => return Err(QuotaError::ReservationClosed),
            ReservationState::Active => {}
        }

        release_active(&self.quota, self.id);
        *lifecycle = ReservationState::Aborted;
        drop(lifecycle);
        Ok(ReservationAbortOutcome::Aborted)
    }
}

impl Drop for ArtifactReservation {
    fn drop(&mut self) {
        let mut lifecycle = lock(&self.state);
        if *lifecycle == ReservationState::Active {
            release_active(&self.quota, self.id);
            *lifecycle = ReservationState::Aborted;
        }
    }
}

fn release_active(quota: &QuotaInner, id: u64) {
    let mut state = lock(&quota.state);
    if let Some(active) = state.reservations.remove(&id) {
        state.reserved_bytes = state.reserved_bytes.saturating_sub(active.requested_bytes);
        state.actual_bytes_in_flight = state
            .actual_bytes_in_flight
            .saturating_sub(active.actual_bytes);
    }
}

fn checked_total(left: u64, right: u64) -> Result<u64, QuotaError> {
    left.checked_add(right).ok_or(QuotaError::SizeOverflow)
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}
