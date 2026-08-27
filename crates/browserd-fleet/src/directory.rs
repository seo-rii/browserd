use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use browserd_core::{PlacementState, SessionId, ShardId, TenantId, WorkerId};

const MAX_DIRECTORY_LEASE: Duration = Duration::from_secs(5 * 60);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DirectoryTime(u64);

impl DirectoryTime {
    #[must_use]
    pub const fn from_millis(milliseconds: u64) -> Self {
        Self(milliseconds)
    }

    #[must_use]
    pub const fn as_millis(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionAttachment {
    tenant_id: TenantId,
    session_id: SessionId,
    worker_id: WorkerId,
    worker_epoch: u64,
    shard_id: ShardId,
    session_incarnation: u64,
}

impl SessionAttachment {
    pub fn new(
        tenant_id: TenantId,
        session_id: SessionId,
        worker_id: WorkerId,
        worker_epoch: u64,
        shard_id: ShardId,
        session_incarnation: u64,
    ) -> Result<Self, DirectoryError> {
        if worker_epoch == 0 || session_incarnation == 0 {
            return Err(DirectoryError::InvalidAttachment);
        }
        Ok(Self {
            tenant_id,
            session_id,
            worker_id,
            worker_epoch,
            shard_id,
            session_incarnation,
        })
    }

    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    #[must_use]
    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    #[must_use]
    pub const fn worker_id(&self) -> &WorkerId {
        &self.worker_id
    }

    #[must_use]
    pub const fn worker_epoch(&self) -> u64 {
        self.worker_epoch
    }

    #[must_use]
    pub const fn shard_id(&self) -> &ShardId {
        &self.shard_id
    }

    #[must_use]
    pub const fn session_incarnation(&self) -> u64 {
        self.session_incarnation
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectoryFence {
    pub worker_id: WorkerId,
    pub worker_epoch: u64,
    pub placement_version: u64,
    pub session_incarnation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionRoute {
    tenant_id: TenantId,
    session_id: SessionId,
    worker_id: WorkerId,
    worker_epoch: u64,
    shard_id: ShardId,
    placement_version: u64,
    session_incarnation: u64,
    placement_state: PlacementState,
    lease_expires_at: DirectoryTime,
}

impl SessionRoute {
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    #[must_use]
    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    #[must_use]
    pub const fn worker_id(&self) -> &WorkerId {
        &self.worker_id
    }

    #[must_use]
    pub const fn worker_epoch(&self) -> u64 {
        self.worker_epoch
    }

    #[must_use]
    pub const fn shard_id(&self) -> &ShardId {
        &self.shard_id
    }

    #[must_use]
    pub const fn placement_version(&self) -> u64 {
        self.placement_version
    }

    #[must_use]
    pub const fn session_incarnation(&self) -> u64 {
        self.session_incarnation
    }

    #[must_use]
    pub const fn placement_state(&self) -> PlacementState {
        self.placement_state
    }

    #[must_use]
    pub const fn lease_expires_at(&self) -> DirectoryTime {
        self.lease_expires_at
    }

    #[must_use]
    pub fn fence(&self) -> DirectoryFence {
        DirectoryFence {
            worker_id: self.worker_id.clone(),
            worker_epoch: self.worker_epoch,
            placement_version: self.placement_version,
            session_incarnation: self.session_incarnation,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AttachOutcome {
    Created(SessionRoute),
    Existing(SessionRoute),
}

impl AttachOutcome {
    #[must_use]
    pub fn into_snapshot(self) -> SessionRoute {
        match self {
            Self::Created(snapshot) | Self::Existing(snapshot) => snapshot,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DirectoryError {
    InvalidLease,
    InvalidAttachment,
    InvalidWorkerEpoch,
    InvalidLimit,
    NotFound,
    PlacementConflict,
    PlacementNotAttached,
    FenceMismatch,
    LeaseExpired,
    TimeOverflow,
    StateUnavailable,
}

impl fmt::Display for DirectoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "session directory error: {self:?}")
    }
}

impl std::error::Error for DirectoryError {}

#[derive(Debug)]
pub struct SessionDirectory {
    lease_duration_millis: u64,
    routes: Mutex<BTreeMap<SessionId, SessionRoute>>,
}

impl SessionDirectory {
    pub fn new(lease_duration: Duration) -> Result<Self, DirectoryError> {
        if lease_duration.is_zero() || lease_duration > MAX_DIRECTORY_LEASE {
            return Err(DirectoryError::InvalidLease);
        }
        let lease_duration_millis =
            u64::try_from(lease_duration.as_millis()).map_err(|_| DirectoryError::InvalidLease)?;
        if lease_duration_millis == 0 {
            return Err(DirectoryError::InvalidLease);
        }
        Ok(Self {
            lease_duration_millis,
            routes: Mutex::new(BTreeMap::new()),
        })
    }

    pub fn attach(
        &self,
        attachment: SessionAttachment,
        now: DirectoryTime,
    ) -> Result<AttachOutcome, DirectoryError> {
        let lease_expires_at = self.checked_expiry(now)?;
        let mut routes = self.lock_routes()?;
        if let Some(existing) = routes.get(attachment.session_id()) {
            if existing.tenant_id == attachment.tenant_id
                && existing.worker_id == attachment.worker_id
                && existing.worker_epoch == attachment.worker_epoch
                && existing.shard_id == attachment.shard_id
                && existing.session_incarnation == attachment.session_incarnation
                && existing.placement_state == PlacementState::Attached
            {
                if existing.lease_expires_at <= now {
                    return Err(DirectoryError::LeaseExpired);
                }
                return Ok(AttachOutcome::Existing(existing.clone()));
            }
            return Err(DirectoryError::PlacementConflict);
        }
        let route = SessionRoute {
            tenant_id: attachment.tenant_id,
            session_id: attachment.session_id.clone(),
            worker_id: attachment.worker_id,
            worker_epoch: attachment.worker_epoch,
            shard_id: attachment.shard_id,
            placement_version: 1,
            session_incarnation: attachment.session_incarnation,
            placement_state: PlacementState::Attached,
            lease_expires_at,
        };
        routes.insert(attachment.session_id, route.clone());
        Ok(AttachOutcome::Created(route))
    }

    pub fn lookup(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        now: DirectoryTime,
    ) -> Result<SessionRoute, DirectoryError> {
        let routes = self.lock_routes()?;
        let route = routes.get(session_id).ok_or(DirectoryError::NotFound)?;
        if &route.tenant_id != tenant_id {
            return Err(DirectoryError::NotFound);
        }
        if route.placement_state != PlacementState::Attached {
            return Err(DirectoryError::PlacementNotAttached);
        }
        if route.lease_expires_at <= now {
            return Err(DirectoryError::LeaseExpired);
        }
        Ok(route.clone())
    }

    pub fn renew(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        fence: &DirectoryFence,
        now: DirectoryTime,
    ) -> Result<SessionRoute, DirectoryError> {
        let proposed_expiry = self.checked_expiry(now)?;
        let mut routes = self.lock_routes()?;
        let route = routes.get_mut(session_id).ok_or(DirectoryError::NotFound)?;
        if &route.tenant_id != tenant_id {
            return Err(DirectoryError::NotFound);
        }
        if route.placement_state != PlacementState::Attached {
            return Err(DirectoryError::PlacementNotAttached);
        }
        if route.lease_expires_at <= now {
            return Err(DirectoryError::LeaseExpired);
        }
        if route.worker_id != fence.worker_id
            || route.worker_epoch != fence.worker_epoch
            || route.placement_version != fence.placement_version
            || route.session_incarnation != fence.session_incarnation
        {
            return Err(DirectoryError::FenceMismatch);
        }
        if proposed_expiry > route.lease_expires_at {
            route.lease_expires_at = proposed_expiry;
        }
        Ok(route.clone())
    }

    pub fn expire_leases(
        &self,
        now: DirectoryTime,
        limit: usize,
    ) -> Result<Vec<SessionRoute>, DirectoryError> {
        if limit == 0 {
            return Err(DirectoryError::InvalidLimit);
        }
        let mut routes = self.lock_routes()?;
        let mut expired = Vec::new();
        for route in routes.values_mut() {
            if expired.len() == limit {
                break;
            }
            if route.placement_state == PlacementState::Attached && route.lease_expires_at <= now {
                route.placement_state = PlacementState::Lost;
                expired.push(route.clone());
            }
        }
        Ok(expired)
    }

    pub fn revoke_worker(
        &self,
        worker_id: &WorkerId,
        worker_epoch: u64,
        limit: usize,
    ) -> Result<Vec<SessionRoute>, DirectoryError> {
        if worker_epoch == 0 {
            return Err(DirectoryError::InvalidWorkerEpoch);
        }
        if limit == 0 {
            return Err(DirectoryError::InvalidLimit);
        }
        let mut routes = self.lock_routes()?;
        let mut revoked = Vec::new();
        for route in routes.values_mut() {
            if revoked.len() == limit {
                break;
            }
            if route.placement_state == PlacementState::Attached
                && &route.worker_id == worker_id
                && route.worker_epoch == worker_epoch
            {
                route.placement_state = PlacementState::Lost;
                revoked.push(route.clone());
            }
        }
        Ok(revoked)
    }

    fn checked_expiry(&self, now: DirectoryTime) -> Result<DirectoryTime, DirectoryError> {
        now.0
            .checked_add(self.lease_duration_millis)
            .map(DirectoryTime)
            .ok_or(DirectoryError::TimeOverflow)
    }

    fn lock_routes(
        &self,
    ) -> Result<MutexGuard<'_, BTreeMap<SessionId, SessionRoute>>, DirectoryError> {
        self.routes
            .lock()
            .map_err(|_| DirectoryError::StateUnavailable)
    }
}
