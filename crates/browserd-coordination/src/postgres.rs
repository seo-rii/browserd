use std::borrow::Cow;

use async_trait::async_trait;
use browserd_core::{CreateOperationState, OperationId, PrincipalId, TenantId};
use chrono::{DateTime, Utc};
use sqlx::SqlSafeStr;
use sqlx::migrate::{Migration, MigrationType, Migrator};
use sqlx::postgres::{PgPool, PgPoolOptions, PgRow};
use sqlx::{Executor, Row};
use uuid::Uuid;

use crate::{
    CanonicalRequestHash, ClaimCreateOperation, ClaimOutcome, CoordinationError,
    CreateOperationError, CreateOperationResult, CreateOperationSnapshot,
    CreateSessionCoordination, OperationMutation, StoreConfig, is_terminal, parse_state,
    state_name, validate_mutation,
};

#[derive(Clone)]
pub struct PostgresCreateSessionStore {
    pool: PgPool,
    config: StoreConfig,
}

impl PostgresCreateSessionStore {
    #[must_use]
    pub const fn new(pool: PgPool, config: StoreConfig) -> Self {
        Self { pool, config }
    }

    pub async fn connect(
        database_url: &str,
        max_connections: u32,
        config: StoreConfig,
    ) -> Result<Self, CoordinationError> {
        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            .connect(database_url)
            .await?;
        Ok(Self::new(pool, config))
    }

    pub async fn migrate(&self) -> Result<(), CoordinationError> {
        let migration = Migration::new(
            1,
            Cow::Borrowed("create session coordination"),
            MigrationType::Simple,
            include_str!("../migrations/0001_create_session_coordination.sql").into_sql_str(),
            false,
        );
        let mut migrator = Migrator::with_migrations(vec![migration]);
        migrator.dangerous_set_table_name("_browserd_coordination_migrations");
        migrator.run(&self.pool).await?;
        Ok(())
    }

    #[must_use]
    pub const fn pool(&self) -> &PgPool {
        &self.pool
    }
}

#[async_trait]
impl CreateSessionCoordination for PostgresCreateSessionStore {
    async fn claim_create(
        &self,
        claim: ClaimCreateOperation,
        now: DateTime<Utc>,
    ) -> Result<ClaimOutcome, CoordinationError> {
        let retention = chrono::Duration::from_std(self.config.retention())
            .map_err(|_| CoordinationError::CorruptData("retention exceeds chrono range"))?;
        let retain_until =
            now.checked_add_signed(retention)
                .ok_or(CoordinationError::CorruptData(
                    "retention timestamp overflow",
                ))?;
        let mut transaction = self.pool.begin().await?;
        let inserted = sqlx::query(
            "INSERT INTO browserd_create_session_operations \
             (tenant_id, idempotency_key, request_hash, operation_id, principal_id, state, \
              revision, result, operation_error, created_at, updated_at, retain_until) \
             VALUES ($1, $2, $3, $4, $5, 'accepted', 0, NULL, NULL, $6, $6, $7) \
             ON CONFLICT (tenant_id, idempotency_key) DO NOTHING",
        )
        .bind(*claim.tenant_id.as_uuid())
        .bind(claim.idempotency_key.as_str())
        .bind(claim.request_hash.as_bytes().to_vec())
        .bind(*claim.operation_id.as_uuid())
        .bind(*claim.principal_id.as_uuid())
        .bind(now)
        .bind(retain_until)
        .execute(&mut *transaction)
        .await?
        .rows_affected()
            == 1;
        let row = sqlx::query(
            "SELECT tenant_id, request_hash, operation_id, principal_id, state, revision, result, \
                    operation_error, created_at, updated_at, retain_until \
             FROM browserd_create_session_operations \
             WHERE tenant_id = $1 AND idempotency_key = $2",
        )
        .bind(*claim.tenant_id.as_uuid())
        .bind(claim.idempotency_key.as_str())
        .fetch_one(&mut *transaction)
        .await?;
        let snapshot = snapshot_from_row(&row)?;
        if snapshot.request_hash != claim.request_hash {
            return Err(CoordinationError::IdempotencyConflict {
                existing_operation_id: snapshot.operation_id,
            });
        }
        transaction.commit().await?;
        Ok(if inserted {
            ClaimOutcome::Created(snapshot)
        } else {
            ClaimOutcome::Existing(snapshot)
        })
    }

    async fn get(
        &self,
        tenant_id: &TenantId,
        operation_id: &OperationId,
    ) -> Result<Option<CreateOperationSnapshot>, CoordinationError> {
        sqlx::query(
            "SELECT tenant_id, request_hash, operation_id, principal_id, state, revision, result, \
                    operation_error, created_at, updated_at, retain_until \
             FROM browserd_create_session_operations \
             WHERE tenant_id = $1 AND operation_id = $2",
        )
        .bind(*tenant_id.as_uuid())
        .bind(*operation_id.as_uuid())
        .fetch_optional(&self.pool)
        .await?
        .as_ref()
        .map(snapshot_from_row)
        .transpose()
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
        let mut transaction = self.pool.begin().await?;
        let row = sqlx::query(
            "SELECT tenant_id, request_hash, operation_id, principal_id, state, revision, result, \
                    operation_error, created_at, updated_at, retain_until \
             FROM browserd_create_session_operations \
             WHERE tenant_id = $1 AND operation_id = $2 FOR UPDATE",
        )
        .bind(*tenant_id.as_uuid())
        .bind(*operation_id.as_uuid())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(CoordinationError::NotFound)?;
        let current = snapshot_from_row(&row)?;
        if current.revision != expected_revision || current.state != expected_state {
            return Err(CoordinationError::StaleWrite(Box::new(current)));
        }
        if is_terminal(current.state) {
            return Err(CoordinationError::TerminalImmutable(current.state));
        }
        validate_mutation(current.state, &mutation)?;
        let expected_revision = i64::try_from(expected_revision)
            .map_err(|_| CoordinationError::CorruptData("revision exceeds PostgreSQL bigint"))?;
        let result = mutation
            .result
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(|_| CoordinationError::CorruptData("result serialization failed"))?;
        let error = mutation
            .error
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(|_| CoordinationError::CorruptData("error serialization failed"))?;
        let updated = sqlx::query(
            "UPDATE browserd_create_session_operations \
             SET state = $1, revision = revision + 1, result = $2, operation_error = $3, \
                 updated_at = $4 \
             WHERE tenant_id = $5 AND operation_id = $6 AND revision = $7 AND state = $8 \
             RETURNING tenant_id, request_hash, operation_id, principal_id, state, revision, result, \
                       operation_error, created_at, updated_at, retain_until",
        )
        .bind(state_name(mutation.next_state))
        .bind(result)
        .bind(error)
        .bind(now)
        .bind(*tenant_id.as_uuid())
        .bind(*operation_id.as_uuid())
        .bind(expected_revision)
        .bind(state_name(expected_state))
        .fetch_one(&mut *transaction)
        .await?;
        let snapshot = snapshot_from_row(&updated)?;
        transaction.commit().await?;
        Ok(snapshot)
    }

    async fn purge_expired(&self, now: DateTime<Utc>) -> Result<u64, CoordinationError> {
        let result = self
            .pool
            .execute(
                sqlx::query(
                    "DELETE FROM browserd_create_session_operations \
                     WHERE state IN ('succeeded', 'timed_out', 'cancelled', 'failed') \
                       AND retain_until <= $1",
                )
                .bind(now),
            )
            .await?;
        Ok(result.rows_affected())
    }
}

fn snapshot_from_row(row: &PgRow) -> Result<CreateOperationSnapshot, CoordinationError> {
    let request_hash: Vec<u8> = row.try_get("request_hash")?;
    let request_hash = <[u8; 32]>::try_from(request_hash)
        .map_err(|_| CoordinationError::CorruptData("request hash is not 32 bytes"))?;
    let revision: i64 = row.try_get("revision")?;
    let revision = u64::try_from(revision)
        .map_err(|_| CoordinationError::CorruptData("revision is negative"))?;
    let tenant_id = TenantId::from_uuid(row.try_get::<Uuid, _>("tenant_id")?)
        .map_err(|_| CoordinationError::CorruptData("tenant ID is not UUIDv7"))?;
    let principal_id = PrincipalId::from_uuid(row.try_get::<Uuid, _>("principal_id")?)
        .map_err(|_| CoordinationError::CorruptData("principal ID is not UUIDv7"))?;
    let operation_id = OperationId::from_uuid(row.try_get::<Uuid, _>("operation_id")?)
        .map_err(|_| CoordinationError::CorruptData("operation ID is not UUIDv7"))?;
    let result = row
        .try_get::<Option<serde_json::Value>, _>("result")?
        .map(serde_json::from_value::<CreateOperationResult>)
        .transpose()
        .map_err(|_| CoordinationError::CorruptData("invalid operation result"))?;
    let error = row
        .try_get::<Option<serde_json::Value>, _>("operation_error")?
        .map(serde_json::from_value::<CreateOperationError>)
        .transpose()
        .map_err(|_| CoordinationError::CorruptData("invalid operation error"))?;
    Ok(CreateOperationSnapshot {
        tenant_id,
        principal_id,
        operation_id,
        request_hash: CanonicalRequestHash::new(request_hash),
        state: parse_state(row.try_get("state")?)?,
        revision,
        result,
        error,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
        retain_until: row.try_get("retain_until")?,
    })
}
