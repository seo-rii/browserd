use std::borrow::Cow;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use browserd_core::{CreateOperationState, OperationId, PrincipalId, TenantId};
use chrono::{DateTime, Utc};
use sqlx::Row;
use sqlx::SqlSafeStr;
use sqlx::migrate::{Migration, MigrationType, Migrator};
use sqlx::postgres::{PgPool, PgPoolOptions, PgRow};
use uuid::Uuid;

use crate::{
    CanonicalRequestHash, ClaimCreateOperation, ClaimOutcome, CoordinationError,
    CreateOperationError, CreateOperationResult, CreateOperationSnapshot,
    CreateSessionCoordination, DispatchLease, DispatchLeaseToken, DownstreamDedupeKey,
    EventStateSummary, MINIMUM_DISPATCH_LEASE_TTL, OperationMutation, OutboxAggregate,
    OutboxAppend, OutboxEventKind, PostgresEventOutbox, RecoverableCreateIntent, StoreConfig,
    is_terminal, parse_state, state_name, validate_mutation,
};

#[derive(Clone)]
pub struct PostgresCreateSessionStore {
    pool: PgPool,
    config: StoreConfig,
    janitor: Arc<tokio::sync::Semaphore>,
}

impl PostgresCreateSessionStore {
    #[must_use]
    pub fn new(pool: PgPool, config: StoreConfig) -> Self {
        Self {
            pool,
            config,
            janitor: Arc::new(tokio::sync::Semaphore::new(1)),
        }
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
        let dispatch_lease_migration = Migration::new(
            2,
            Cow::Borrowed("dispatch leases"),
            MigrationType::Simple,
            include_str!("../migrations/0002_dispatch_leases.sql").into_sql_str(),
            false,
        );
        let intent_migration = Migration::new(
            3,
            Cow::Borrowed("recoverable create intent"),
            MigrationType::Simple,
            include_str!("../migrations/0003_recoverable_create_intent.sql").into_sql_str(),
            false,
        );
        let mut migrator =
            Migrator::with_migrations(vec![migration, dispatch_lease_migration, intent_migration]);
        migrator.dangerous_set_table_name("_browserd_coordination_migrations");
        migrator.run(&self.pool).await?;
        PostgresEventOutbox::new(self.pool.clone(), self.config)
            .migrate()
            .await?;
        Ok(())
    }

    async fn append_operation_event(
        &self,
        transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        snapshot: &CreateOperationSnapshot,
    ) -> Result<(), CoordinationError> {
        let append = OutboxAppend::state_changed(
            snapshot.tenant_id().clone(),
            OutboxAggregate::Operation {
                operation_id: snapshot.operation_id().clone(),
            },
            snapshot.revision(),
            OutboxEventKind::OperationStateChanged,
            EventStateSummary::Operation {
                state: snapshot.state().into(),
            },
        )?;
        PostgresEventOutbox::new(self.pool.clone(), self.config)
            .append_transactional(transaction, append, snapshot.updated_at())
            .await?;
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
        _now: DateTime<Utc>,
    ) -> Result<ClaimOutcome, CoordinationError> {
        let retention_ms = i64::try_from(self.config.retention().as_millis())
            .map_err(|_| CoordinationError::CorruptData("retention exceeds PostgreSQL range"))?;
        let mut transaction = self.pool.begin().await?;
        let inserted = sqlx::query(
            "INSERT INTO browserd_create_session_operations \
             (tenant_id, idempotency_key, request_hash, operation_id, principal_id, state, \
              revision, result, operation_error, created_at, updated_at, retain_until, \
              canonical_request, downstream_dedupe_key, accepted_at, admission_deadline, policy_context) \
             VALUES ($1, $2, $3, $4, $5, 'accepted', 0, NULL, NULL, clock_timestamp(), \
                     clock_timestamp(), clock_timestamp() + ($6 * interval '1 millisecond'), \
                     $7, $8, $9, $10, $11) \
             ON CONFLICT (tenant_id, idempotency_key) DO NOTHING",
        )
        .bind(*claim.tenant_id.as_uuid())
        .bind(claim.idempotency_key.as_str())
        .bind(claim.request_hash.as_bytes().to_vec())
        .bind(*claim.operation_id.as_uuid())
        .bind(*claim.principal_id.as_uuid())
        .bind(retention_ms)
        .bind(claim.intent.canonical_request())
        .bind(claim.intent.downstream_dedupe_key().as_bytes().to_vec())
        .bind(claim.intent.accepted_at())
        .bind(claim.intent.admission_deadline())
        .bind(claim.intent.policy_context())
        .execute(&mut *transaction)
        .await?
        .rows_affected()
            == 1;
        let row = sqlx::query(
            "SELECT tenant_id, request_hash, operation_id, principal_id, state, revision, result, \
                    operation_error, dispatch_lease_token, dispatch_lease_expires_at, \
                    dispatch_generation, canonical_request, downstream_dedupe_key, accepted_at, \
                    admission_deadline, policy_context, created_at, updated_at, retain_until \
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
        if inserted {
            self.append_operation_event(&mut transaction, &snapshot)
                .await?;
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
                    operation_error, dispatch_lease_token, dispatch_lease_expires_at, \
                    dispatch_generation, canonical_request, downstream_dedupe_key, accepted_at, \
                    admission_deadline, policy_context, created_at, updated_at, retain_until \
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
                    operation_error, dispatch_lease_token, dispatch_lease_expires_at, \
                    dispatch_generation, canonical_request, downstream_dedupe_key, accepted_at, \
                    admission_deadline, policy_context, created_at, updated_at, retain_until \
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
        validate_mutation(&current, &mutation, now)?;
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
        let dispatch_lease_token = mutation
            .dispatch_lease
            .as_ref()
            .map(|lease| *lease.token().as_uuid());
        let dispatch_lease_expires_at = mutation
            .dispatch_lease
            .as_ref()
            .map(DispatchLease::expires_at);
        let updated = sqlx::query(
            "UPDATE browserd_create_session_operations \
             SET state = $1, revision = revision + 1, result = $2, operation_error = $3, \
                 dispatch_lease_token = $4, dispatch_lease_expires_at = $5, updated_at = clock_timestamp() \
             WHERE tenant_id = $6 AND operation_id = $7 AND revision = $8 AND state = $9 \
             RETURNING tenant_id, request_hash, operation_id, principal_id, state, revision, result, \
                       operation_error, dispatch_lease_token, dispatch_lease_expires_at, \
                       dispatch_generation, canonical_request, downstream_dedupe_key, accepted_at, \
                       admission_deadline, policy_context, created_at, updated_at, retain_until",
        )
        .bind(state_name(mutation.next_state))
        .bind(result)
        .bind(error)
        .bind(dispatch_lease_token)
        .bind(dispatch_lease_expires_at)
        .bind(*tenant_id.as_uuid())
        .bind(*operation_id.as_uuid())
        .bind(expected_revision)
        .bind(state_name(expected_state))
        .fetch_one(&mut *transaction)
        .await?;
        let snapshot = snapshot_from_row(&updated)?;
        if snapshot.state() != current.state() {
            self.append_operation_event(&mut transaction, &snapshot)
                .await?;
        }
        transaction.commit().await?;
        Ok(snapshot)
    }

    async fn acquire_dispatch_lease(
        &self,
        tenant_id: &TenantId,
        operation_id: &OperationId,
        expected_revision: u64,
        token: DispatchLeaseToken,
        ttl: Duration,
        _now: DateTime<Utc>,
    ) -> Result<CreateOperationSnapshot, CoordinationError> {
        if ttl < MINIMUM_DISPATCH_LEASE_TTL {
            return Err(CoordinationError::InvalidDispatchLease);
        }
        let ttl_ms =
            i64::try_from(ttl.as_millis()).map_err(|_| CoordinationError::InvalidDispatchLease)?;
        let expected_revision = i64::try_from(expected_revision)
            .map_err(|_| CoordinationError::CorruptData("revision exceeds PostgreSQL bigint"))?;
        let mut transaction = self.pool.begin().await?;
        let row = sqlx::query(
            "SELECT tenant_id, request_hash, operation_id, principal_id, state, revision, result, \
                    operation_error, dispatch_lease_token, dispatch_lease_expires_at, \
                    dispatch_generation, canonical_request, downstream_dedupe_key, accepted_at, \
                    admission_deadline, policy_context, created_at, updated_at, retain_until, \
                    clock_timestamp() AS server_now \
             FROM browserd_create_session_operations \
             WHERE tenant_id = $1 AND operation_id = $2 FOR UPDATE",
        )
        .bind(*tenant_id.as_uuid())
        .bind(*operation_id.as_uuid())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(CoordinationError::NotFound)?;
        let current = snapshot_from_row(&row)?;
        if current.revision != u64::try_from(expected_revision).unwrap_or_default() {
            return Err(CoordinationError::StaleWrite(Box::new(current)));
        }
        let server_now: DateTime<Utc> = row.try_get("server_now")?;
        match current.state {
            CreateOperationState::Reserving => {}
            CreateOperationState::Creating
                if current
                    .dispatch_lease
                    .as_ref()
                    .is_some_and(|lease| !lease.is_expired_at(server_now)) =>
            {
                return Err(CoordinationError::DispatchLeaseActive(Box::new(current)));
            }
            CreateOperationState::Creating => {}
            state => {
                return Err(CoordinationError::InvalidTransition {
                    from: state,
                    to: CreateOperationState::Creating,
                });
            }
        }
        let updated = sqlx::query(
            "UPDATE browserd_create_session_operations SET state = 'creating', revision = revision + 1, \
                    dispatch_generation = dispatch_generation + 1, dispatch_lease_token = $1, \
                    dispatch_lease_expires_at = clock_timestamp() + ($2 * interval '1 millisecond'), \
                    updated_at = clock_timestamp() WHERE tenant_id = $3 AND operation_id = $4 AND revision = $5 \
             RETURNING tenant_id, request_hash, operation_id, principal_id, state, revision, result, \
                    operation_error, dispatch_lease_token, dispatch_lease_expires_at, dispatch_generation, \
                    canonical_request, downstream_dedupe_key, accepted_at, admission_deadline, policy_context, \
                    created_at, updated_at, retain_until",
        ).bind(*token.as_uuid()).bind(ttl_ms).bind(*tenant_id.as_uuid()).bind(*operation_id.as_uuid())
         .bind(expected_revision).fetch_one(&mut *transaction).await?;
        let snapshot = snapshot_from_row(&updated)?;
        if snapshot.state() != current.state() {
            self.append_operation_event(&mut transaction, &snapshot)
                .await?;
        }
        transaction.commit().await?;
        Ok(snapshot)
    }

    async fn scan_reconcilable(
        &self,
        limit: usize,
        _now: DateTime<Utc>,
    ) -> Result<Vec<CreateOperationSnapshot>, CoordinationError> {
        if !(1..=1_000).contains(&limit) {
            return Err(CoordinationError::InvalidScanLimit);
        }
        let limit = i64::try_from(limit).map_err(|_| CoordinationError::InvalidScanLimit)?;
        sqlx::query(
            "SELECT tenant_id, request_hash, operation_id, principal_id, state, revision, result, \
                    operation_error, dispatch_lease_token, dispatch_lease_expires_at, dispatch_generation, \
                    canonical_request, downstream_dedupe_key, accepted_at, admission_deadline, policy_context, \
                    created_at, updated_at, retain_until FROM browserd_create_session_operations \
             WHERE state IN ('accepted', 'queued', 'reserving') \
                OR (state = 'creating' AND dispatch_lease_expires_at <= clock_timestamp()) \
             ORDER BY created_at, operation_id LIMIT $1",
        ).bind(limit).fetch_all(&self.pool).await?.iter().map(snapshot_from_row).collect()
    }

    async fn renew_dispatch_lease(
        &self,
        tenant_id: &TenantId,
        operation_id: &OperationId,
        expected_revision: u64,
        token: DispatchLeaseToken,
        ttl: Duration,
        _now: DateTime<Utc>,
    ) -> Result<CreateOperationSnapshot, CoordinationError> {
        if ttl < MINIMUM_DISPATCH_LEASE_TTL {
            return Err(CoordinationError::InvalidDispatchLease);
        }
        let revision = i64::try_from(expected_revision)
            .map_err(|_| CoordinationError::CorruptData("revision exceeds PostgreSQL bigint"))?;
        let ttl_ms =
            i64::try_from(ttl.as_millis()).map_err(|_| CoordinationError::InvalidDispatchLease)?;
        let updated = sqlx::query(
            "UPDATE browserd_create_session_operations SET revision = revision + 1, \
                    dispatch_lease_expires_at = clock_timestamp() + ($1 * interval '1 millisecond'), updated_at = clock_timestamp() \
             WHERE tenant_id = $2 AND operation_id = $3 AND revision = $4 AND state = 'creating' AND dispatch_lease_token = $5 \
             RETURNING tenant_id, request_hash, operation_id, principal_id, state, revision, result, operation_error, \
                    dispatch_lease_token, dispatch_lease_expires_at, dispatch_generation, canonical_request, \
                    downstream_dedupe_key, accepted_at, admission_deadline, policy_context, created_at, updated_at, retain_until",
        ).bind(ttl_ms).bind(*tenant_id.as_uuid()).bind(*operation_id.as_uuid()).bind(revision).bind(*token.as_uuid()).fetch_optional(&self.pool).await?;
        if let Some(row) = updated {
            return snapshot_from_row(&row);
        }
        let current = self
            .get(tenant_id, operation_id)
            .await?
            .ok_or(CoordinationError::NotFound)?;
        if current.revision != expected_revision {
            Err(CoordinationError::StaleWrite(Box::new(current)))
        } else {
            Err(CoordinationError::DispatchLeaseMismatch)
        }
    }

    async fn purge_expired(&self, _now: DateTime<Utc>) -> Result<u64, CoordinationError> {
        // The actor owns an in-flight query even after its caller times out. Store clones share
        // this permit so a later maintenance tick cannot overlap that still-owned query.
        let Ok(_permit) = self.janitor.try_acquire() else {
            return Ok(0);
        };
        // Terminal state and its outbox event commit atomically above; pruning the source after
        // its idempotency horizon must not depend on the retained lifetime of the outbox payload.
        // The existing partial retain_until index bounds candidates before any row locks. A
        // locked candidate is skipped, not replaced by an unbounded scan for additional rows.
        let result = sqlx::query(
            "WITH candidates AS MATERIALIZED ( \
                SELECT tenant_id, idempotency_key FROM browserd_create_session_operations \
                WHERE state IN ('succeeded', 'timed_out', 'cancelled', 'failed') \
                  AND retain_until <= statement_timestamp() \
                ORDER BY retain_until LIMIT 32 \
             ), locked AS MATERIALIZED ( \
                SELECT operation.tenant_id, operation.idempotency_key \
                FROM browserd_create_session_operations operation \
                INNER JOIN candidates candidate USING (tenant_id, idempotency_key) \
                WHERE operation.state IN ('succeeded', 'timed_out', 'cancelled', 'failed') \
                  AND operation.retain_until <= statement_timestamp() \
                FOR UPDATE OF operation SKIP LOCKED \
             ) DELETE FROM browserd_create_session_operations operation USING locked \
               WHERE operation.tenant_id=locked.tenant_id \
                 AND operation.idempotency_key=locked.idempotency_key \
                 AND operation.state IN ('succeeded', 'timed_out', 'cancelled', 'failed') \
                 AND operation.retain_until <= statement_timestamp()",
        )
        .execute(&self.pool)
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
    let dispatch_lease_token = row.try_get::<Option<Uuid>, _>("dispatch_lease_token")?;
    let dispatch_lease_expires_at =
        row.try_get::<Option<DateTime<Utc>>, _>("dispatch_lease_expires_at")?;
    let dispatch_lease = match (dispatch_lease_token, dispatch_lease_expires_at) {
        (Some(token), Some(expires_at)) => Some(DispatchLease {
            token: DispatchLeaseToken::from_uuid(token)?,
            expires_at,
        }),
        (None, None) => None,
        _ => {
            return Err(CoordinationError::CorruptData(
                "dispatch lease columns are not paired",
            ));
        }
    };
    let dispatch_generation = u64::try_from(row.try_get::<i64, _>("dispatch_generation")?)
        .map_err(|_| CoordinationError::CorruptData("dispatch generation is negative"))?;
    let downstream_dedupe_key =
        <[u8; 32]>::try_from(row.try_get::<Vec<u8>, _>("downstream_dedupe_key")?)
            .map_err(|_| CoordinationError::CorruptData("downstream dedupe key is not 32 bytes"))?;
    let intent = RecoverableCreateIntent {
        canonical_request: row.try_get("canonical_request")?,
        downstream_dedupe_key: DownstreamDedupeKey::from_bytes(downstream_dedupe_key),
        accepted_at: row.try_get("accepted_at")?,
        admission_deadline: row.try_get("admission_deadline")?,
        policy_context: row.try_get("policy_context")?,
    };
    Ok(CreateOperationSnapshot {
        tenant_id,
        principal_id,
        operation_id,
        request_hash: CanonicalRequestHash::new(request_hash),
        state: parse_state(row.try_get("state")?)?,
        revision,
        result,
        error,
        dispatch_lease,
        dispatch_generation,
        intent,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
        retain_until: row.try_get("retain_until")?,
    })
}
