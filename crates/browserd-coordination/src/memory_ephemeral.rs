use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;

use crate::ephemeral::{MAX_EPHEMERAL_TTL_MILLIS, ttl_millis};
use crate::{
    DirectoryEntry, DirectoryKey, DirectoryMutation, DirectorySnapshot, EphemeralCoordinationError,
    EphemeralCoordinationStore, OneTimeCapability, OneTimeConsume, OneTimeIssue,
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
    capabilities:
        HashMap<(browserd_core::TenantId, browserd_core::SessionId, [u8; 32]), CapabilityRecord>,
}

struct CapabilityRecord {
    expires_at_millis: u64,
    consumed: bool,
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
