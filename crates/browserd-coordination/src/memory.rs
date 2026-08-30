use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use browserd_core::{CreateOperationState, OperationId, TenantId};
use chrono::{DateTime, Utc};

use crate::gateway_actions::GatewayActionMemoryState;
use crate::{
    ClaimCreateOperation, ClaimOutcome, CoordinationError, CreateOperationSnapshot,
    CreateSessionCoordination, DispatchLease, DispatchLeaseToken, IdempotencyKey,
    MINIMUM_DISPATCH_LEASE_TTL, OperationMutation, StoreConfig, is_terminal, validate_mutation,
};

#[derive(Clone, Default)]
pub struct MemoryCoordinationDatabase {
    rows: Arc<Mutex<HashMap<(TenantId, IdempotencyKey), MemoryRow>>>,
    pub(crate) gateway_actions: Arc<Mutex<GatewayActionMemoryState>>,
}

#[derive(Clone)]
struct MemoryRow {
    request_hash: crate::CanonicalRequestHash,
    snapshot: CreateOperationSnapshot,
}

#[derive(Clone)]
pub struct MemoryCreateSessionStore {
    database: MemoryCoordinationDatabase,
    config: StoreConfig,
}

impl MemoryCreateSessionStore {
    #[must_use]
    pub const fn attach(database: MemoryCoordinationDatabase, config: StoreConfig) -> Self {
        Self { database, config }
    }
}

impl Default for MemoryCreateSessionStore {
    fn default() -> Self {
        Self::attach(
            MemoryCoordinationDatabase::default(),
            StoreConfig::default(),
        )
    }
}

#[async_trait]
impl CreateSessionCoordination for MemoryCreateSessionStore {
    async fn claim_create(
        &self,
        claim: ClaimCreateOperation,
        now: DateTime<Utc>,
    ) -> Result<ClaimOutcome, CoordinationError> {
        let mut rows = self
            .database
            .rows
            .lock()
            .map_err(|_| CoordinationError::LockUnavailable)?;
        let key = (claim.tenant_id.clone(), claim.idempotency_key.clone());
        if let Some(existing) = rows.get(&key) {
            if existing.request_hash != claim.request_hash {
                return Err(CoordinationError::IdempotencyConflict {
                    existing_operation_id: existing.snapshot.operation_id.clone(),
                });
            }
            return Ok(ClaimOutcome::Existing(existing.snapshot.clone()));
        }

        let retention = chrono::Duration::from_std(self.config.retention())
            .map_err(|_| CoordinationError::CorruptData("retention exceeds chrono range"))?;
        let retain_until =
            now.checked_add_signed(retention)
                .ok_or(CoordinationError::CorruptData(
                    "retention timestamp overflow",
                ))?;
        let snapshot = CreateOperationSnapshot {
            tenant_id: claim.tenant_id,
            principal_id: claim.principal_id,
            operation_id: claim.operation_id,
            request_hash: claim.request_hash,
            state: CreateOperationState::Accepted,
            revision: 0,
            result: None,
            error: None,
            dispatch_lease: None,
            dispatch_generation: 0,
            intent: claim.intent,
            created_at: now,
            updated_at: now,
            retain_until,
        };
        rows.insert(
            key,
            MemoryRow {
                request_hash: claim.request_hash,
                snapshot: snapshot.clone(),
            },
        );
        Ok(ClaimOutcome::Created(snapshot))
    }

    async fn get(
        &self,
        tenant_id: &TenantId,
        operation_id: &OperationId,
    ) -> Result<Option<CreateOperationSnapshot>, CoordinationError> {
        let rows = self
            .database
            .rows
            .lock()
            .map_err(|_| CoordinationError::LockUnavailable)?;
        Ok(rows
            .values()
            .find(|row| {
                row.snapshot.tenant_id == *tenant_id && row.snapshot.operation_id == *operation_id
            })
            .map(|row| row.snapshot.clone()))
    }

    async fn compare_and_set(
        &self,
        tenant_id: &TenantId,
        operation_id: &OperationId,
        expected_revision: u64,
        expected_state: CreateOperationState,
        mutation: OperationMutation,
        now: DateTime<Utc>,
    ) -> Result<CreateOperationSnapshot, CoordinationError> {
        let mut rows = self
            .database
            .rows
            .lock()
            .map_err(|_| CoordinationError::LockUnavailable)?;
        let row = rows
            .values_mut()
            .find(|row| {
                row.snapshot.tenant_id == *tenant_id && row.snapshot.operation_id == *operation_id
            })
            .ok_or(CoordinationError::NotFound)?;
        if row.snapshot.revision != expected_revision || row.snapshot.state != expected_state {
            return Err(CoordinationError::StaleWrite(Box::new(
                row.snapshot.clone(),
            )));
        }
        if is_terminal(row.snapshot.state) {
            return Err(CoordinationError::TerminalImmutable(row.snapshot.state));
        }
        validate_mutation(&row.snapshot, &mutation, now)?;
        row.snapshot.state = mutation.next_state;
        row.snapshot.revision = row
            .snapshot
            .revision
            .checked_add(1)
            .ok_or(CoordinationError::CorruptData("revision overflow"))?;
        row.snapshot.result = mutation.result;
        row.snapshot.error = mutation.error;
        row.snapshot.dispatch_lease = mutation.dispatch_lease;
        row.snapshot.updated_at = now;
        Ok(row.snapshot.clone())
    }

    async fn purge_expired(&self, now: DateTime<Utc>) -> Result<u64, CoordinationError> {
        let mut rows = self
            .database
            .rows
            .lock()
            .map_err(|_| CoordinationError::LockUnavailable)?;
        let before = rows.len();
        rows.retain(|_, row| {
            !(is_terminal(row.snapshot.state) && row.snapshot.retain_until <= now)
        });
        u64::try_from(before.saturating_sub(rows.len()))
            .map_err(|_| CoordinationError::CorruptData("purge count overflow"))
    }

    async fn acquire_dispatch_lease(
        &self,
        tenant_id: &TenantId,
        operation_id: &OperationId,
        expected_revision: u64,
        token: DispatchLeaseToken,
        ttl: Duration,
        now: DateTime<Utc>,
    ) -> Result<CreateOperationSnapshot, CoordinationError> {
        if ttl < MINIMUM_DISPATCH_LEASE_TTL {
            return Err(CoordinationError::InvalidDispatchLease);
        }
        let expires_at = now
            .checked_add_signed(
                chrono::Duration::from_std(ttl)
                    .map_err(|_| CoordinationError::InvalidDispatchLease)?,
            )
            .ok_or(CoordinationError::InvalidDispatchLease)?;
        let mut rows = self
            .database
            .rows
            .lock()
            .map_err(|_| CoordinationError::LockUnavailable)?;
        let row = rows
            .values_mut()
            .find(|row| {
                row.snapshot.tenant_id == *tenant_id && row.snapshot.operation_id == *operation_id
            })
            .ok_or(CoordinationError::NotFound)?;
        if row.snapshot.revision != expected_revision {
            return Err(CoordinationError::StaleWrite(Box::new(
                row.snapshot.clone(),
            )));
        }
        match row.snapshot.state {
            CreateOperationState::Reserving => {}
            CreateOperationState::Creating => {
                if row
                    .snapshot
                    .dispatch_lease
                    .as_ref()
                    .is_some_and(|lease| !lease.is_expired_at(now))
                {
                    return Err(CoordinationError::DispatchLeaseActive(Box::new(
                        row.snapshot.clone(),
                    )));
                }
            }
            state => {
                return Err(CoordinationError::InvalidTransition {
                    from: state,
                    to: CreateOperationState::Creating,
                });
            }
        }
        row.snapshot.state = CreateOperationState::Creating;
        row.snapshot.revision = row
            .snapshot
            .revision
            .checked_add(1)
            .ok_or(CoordinationError::CorruptData("revision overflow"))?;
        row.snapshot.dispatch_generation = row.snapshot.dispatch_generation.checked_add(1).ok_or(
            CoordinationError::CorruptData("dispatch generation overflow"),
        )?;
        row.snapshot.dispatch_lease = Some(DispatchLease::new(token, expires_at, now)?);
        row.snapshot.updated_at = now;
        Ok(row.snapshot.clone())
    }

    async fn scan_reconcilable(
        &self,
        limit: usize,
        now: DateTime<Utc>,
    ) -> Result<Vec<CreateOperationSnapshot>, CoordinationError> {
        if !(1..=1_000).contains(&limit) {
            return Err(CoordinationError::InvalidScanLimit);
        }
        let rows = self
            .database
            .rows
            .lock()
            .map_err(|_| CoordinationError::LockUnavailable)?;
        let mut snapshots: Vec<_> = rows
            .values()
            .filter_map(|row| {
                let pending = matches!(
                    row.snapshot.state,
                    CreateOperationState::Accepted
                        | CreateOperationState::Queued
                        | CreateOperationState::Reserving
                ) || (row.snapshot.state == CreateOperationState::Creating
                    && row
                        .snapshot
                        .dispatch_lease
                        .as_ref()
                        .is_none_or(|lease| lease.is_expired_at(now)));
                pending.then(|| row.snapshot.clone())
            })
            .collect();
        snapshots.sort_by_key(|snapshot| (snapshot.created_at, snapshot.operation_id.clone()));
        snapshots.truncate(limit);
        Ok(snapshots)
    }

    async fn renew_dispatch_lease(
        &self,
        tenant_id: &TenantId,
        operation_id: &OperationId,
        expected_revision: u64,
        token: DispatchLeaseToken,
        ttl: Duration,
        now: DateTime<Utc>,
    ) -> Result<CreateOperationSnapshot, CoordinationError> {
        if ttl < MINIMUM_DISPATCH_LEASE_TTL {
            return Err(CoordinationError::InvalidDispatchLease);
        }
        let expires_at = now
            .checked_add_signed(
                chrono::Duration::from_std(ttl)
                    .map_err(|_| CoordinationError::InvalidDispatchLease)?,
            )
            .ok_or(CoordinationError::InvalidDispatchLease)?;
        let mut rows = self
            .database
            .rows
            .lock()
            .map_err(|_| CoordinationError::LockUnavailable)?;
        let row = rows
            .values_mut()
            .find(|row| {
                row.snapshot.tenant_id == *tenant_id && row.snapshot.operation_id == *operation_id
            })
            .ok_or(CoordinationError::NotFound)?;
        if row.snapshot.revision != expected_revision {
            return Err(CoordinationError::StaleWrite(Box::new(
                row.snapshot.clone(),
            )));
        }
        if row.snapshot.state != CreateOperationState::Creating
            || row
                .snapshot
                .dispatch_lease
                .as_ref()
                .map(DispatchLease::token)
                != Some(&token)
        {
            return Err(CoordinationError::DispatchLeaseMismatch);
        }
        row.snapshot.dispatch_lease = Some(DispatchLease::new(token, expires_at, now)?);
        row.snapshot.revision = row
            .snapshot
            .revision
            .checked_add(1)
            .ok_or(CoordinationError::CorruptData("revision overflow"))?;
        row.snapshot.updated_at = now;
        Ok(row.snapshot.clone())
    }
}
