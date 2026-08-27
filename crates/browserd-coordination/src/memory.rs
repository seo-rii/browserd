use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use browserd_core::{CreateOperationState, OperationId, TenantId};
use chrono::{DateTime, Utc};

use crate::{
    ClaimCreateOperation, ClaimOutcome, CoordinationError, CreateOperationSnapshot,
    CreateSessionCoordination, IdempotencyKey, OperationMutation, StoreConfig, is_terminal,
    validate_mutation,
};

#[derive(Clone, Default)]
pub struct MemoryCoordinationDatabase {
    rows: Arc<Mutex<HashMap<(TenantId, IdempotencyKey), MemoryRow>>>,
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
        validate_mutation(row.snapshot.state, &mutation)?;
        row.snapshot.state = mutation.next_state;
        row.snapshot.revision = row
            .snapshot
            .revision
            .checked_add(1)
            .ok_or(CoordinationError::CorruptData("revision overflow"))?;
        row.snapshot.result = mutation.result;
        row.snapshot.error = mutation.error;
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
}
