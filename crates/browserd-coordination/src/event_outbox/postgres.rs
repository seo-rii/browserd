//! Postgres-backed [`EventOutbox`] (BRD-017 / BRD-003).
//!
//! The review's direction for BRD-003 is to hold the durable authority — including the event
//! outbox — in Postgres, with Redis limited to lease/cache. This backend provides exactly that: the
//! same ordered, idempotent, at-least-once semantics as the other backends, persisted in Postgres
//! so the notification stream inherits Postgres's commit and failover durability.
//!
//! Each tenant's stream is a set of rows in `browserd_event_outbox` keyed by `(tenant_id,
//! tenant_seq)`, with a companion `browserd_event_outbox_cursor` row carrying the sequence counter
//! and the delivered/pruned watermarks. Every mutating operation runs in one transaction under a
//! per-tenant advisory lock, so sequence assignment and the idempotency check are serialized
//! without relying on constraint-violation retries.

use std::borrow::Cow;
use std::time::Duration;

use async_trait::async_trait;
use browserd_core::{ActionId, SessionId, TenantId};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use sqlx::SqlSafeStr;
use sqlx::migrate::{Migration, MigrationType, Migrator};
use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::{Row, Transaction};
use uuid::{Uuid, Version};

use super::{
    EventCursor, EventOutbox, EventOutboxError, MAX_EVENT_PAGE_LIMIT, OutboxAggregate,
    OutboxAppend, OutboxEvent, OutboxEventKind, OutboxPage,
};
use crate::StoreConfig;

/// Advisory-lock namespace for the outbox, keeping its per-tenant locks disjoint from any other
/// feature's advisory locks on the same database.
const ADVISORY_NAMESPACE: i32 = 0x0B0C;

const KIND_ACTION_TERMINAL: &str = "action_terminal";
const KIND_SESSION_LOST: &str = "session_lost";

/// Postgres-backed durable event outbox.
#[derive(Clone)]
pub struct PostgresEventOutbox {
    pool: PgPool,
    retention: Duration,
}

impl PostgresEventOutbox {
    /// Wrap an existing pool.
    #[must_use]
    pub fn new(pool: PgPool, config: StoreConfig) -> Self {
        Self {
            pool,
            retention: config.retention(),
        }
    }

    /// Connect a pool to `database_url`.
    pub async fn connect(
        database_url: &str,
        max_connections: u32,
        config: StoreConfig,
    ) -> Result<Self, EventOutboxError> {
        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            .connect(database_url)
            .await
            .map_err(|_| EventOutboxError::PostgresUnavailable)?;
        Ok(Self::new(pool, config))
    }

    /// Apply the outbox schema. Uses a dedicated migrations table so it composes with the create
    /// session store's own migrations on the same database.
    pub async fn migrate(&self) -> Result<(), EventOutboxError> {
        let migration = Migration::new(
            1,
            Cow::Borrowed("event outbox"),
            MigrationType::Simple,
            include_str!("../../migrations/outbox/0001_event_outbox.sql").into_sql_str(),
            false,
        );
        let mut migrator = Migrator::with_migrations(vec![migration]);
        migrator.dangerous_set_table_name("_browserd_event_outbox_migrations");
        migrator
            .run(&self.pool)
            .await
            .map_err(|_| EventOutboxError::PostgresUnavailable)?;
        Ok(())
    }

    #[must_use]
    pub const fn pool(&self) -> &PgPool {
        &self.pool
    }

    fn dedup_key(aggregate: &OutboxAggregate, revision: u64, kind: OutboxEventKind) -> String {
        let aggregate = match aggregate {
            OutboxAggregate::Action {
                session_id,
                action_id,
            } => format!("A:{session_id}:{action_id}"),
            OutboxAggregate::Session { session_id } => format!("S:{session_id}"),
        };
        let kind = match kind {
            OutboxEventKind::ActionTerminal => "t",
            OutboxEventKind::SessionLost => "l",
        };
        format!("{aggregate}:{revision}:{kind}")
    }

    fn kind_name(kind: OutboxEventKind) -> &'static str {
        match kind {
            OutboxEventKind::ActionTerminal => KIND_ACTION_TERMINAL,
            OutboxEventKind::SessionLost => KIND_SESSION_LOST,
        }
    }

    fn seq_to_i64(seq: u64) -> Result<i64, EventOutboxError> {
        i64::try_from(seq).map_err(|_| EventOutboxError::SequenceOverflow)
    }

    fn seq_from_i64(seq: i64) -> Result<u64, EventOutboxError> {
        u64::try_from(seq).map_err(|_| EventOutboxError::InvalidPostgresState)
    }

    fn revision_from_i64(revision: i64) -> Result<u64, EventOutboxError> {
        u64::try_from(revision).map_err(|_| EventOutboxError::InvalidPostgresState)
    }

    fn cutoff(&self, now: DateTime<Utc>) -> Result<DateTime<Utc>, EventOutboxError> {
        let retention = ChronoDuration::from_std(self.retention)
            .map_err(|_| EventOutboxError::RetentionTimestampOverflow)?;
        now.checked_sub_signed(retention)
            .ok_or(EventOutboxError::RetentionTimestampOverflow)
    }

    async fn lock_tenant(
        transaction: &mut Transaction<'_, sqlx::Postgres>,
        tenant_id: &TenantId,
    ) -> Result<(), EventOutboxError> {
        sqlx::query("SELECT pg_advisory_xact_lock($1, hashtext($2))")
            .bind(ADVISORY_NAMESPACE)
            .bind(tenant_id.to_string())
            .execute(&mut **transaction)
            .await
            .map_err(|_| EventOutboxError::PostgresUnavailable)?;
        Ok(())
    }

    /// Drop events older than retention and advance `pruned_through`, matching the memory backend so
    /// a resume from at-or-before the pruned high-water is reported as a gap. Assumes the caller
    /// holds the per-tenant advisory lock.
    async fn prune(
        transaction: &mut Transaction<'_, sqlx::Postgres>,
        tenant_id: &TenantId,
        now: DateTime<Utc>,
        cutoff: DateTime<Utc>,
    ) -> Result<(), EventOutboxError> {
        let _ = now;
        let pruned = sqlx::query(
            "DELETE FROM browserd_event_outbox
             WHERE tenant_id = $1 AND created_at <= $2
             RETURNING tenant_seq",
        )
        .bind(tenant_id.as_uuid())
        .bind(cutoff)
        .fetch_all(&mut **transaction)
        .await
        .map_err(|_| EventOutboxError::PostgresUnavailable)?;
        let max_pruned = pruned
            .iter()
            .map(|row| row.get::<i64, _>("tenant_seq"))
            .max();
        if let Some(max_pruned) = max_pruned {
            sqlx::query(
                "UPDATE browserd_event_outbox_cursor
                 SET pruned_through = GREATEST(pruned_through, $2)
                 WHERE tenant_id = $1",
            )
            .bind(tenant_id.as_uuid())
            .bind(max_pruned)
            .execute(&mut **transaction)
            .await
            .map_err(|_| EventOutboxError::PostgresUnavailable)?;
        }
        Ok(())
    }

    fn row_to_event(
        row: &sqlx::postgres::PgRow,
        tenant_id: &TenantId,
    ) -> Result<OutboxEvent, EventOutboxError> {
        let tenant_seq = Self::seq_from_i64(row.get::<i64, _>("tenant_seq"))?;
        let event_id: Uuid = row.get("event_id");
        if event_id.get_version() != Some(Version::SortRand) {
            return Err(EventOutboxError::InvalidPostgresState);
        }
        let kind_name: String = row.get("kind");
        let revision = Self::revision_from_i64(row.get::<i64, _>("aggregate_revision"))?;
        let session_uuid: Uuid = row.get("session_id");
        let session_id = SessionId::from_uuid(session_uuid)
            .map_err(|_| EventOutboxError::InvalidPostgresState)?;
        let action_uuid: Option<Uuid> = row.get("action_id");
        let created_at: DateTime<Utc> = row.get("created_at");
        let (kind, aggregate) = match kind_name.as_str() {
            KIND_ACTION_TERMINAL => {
                let action_uuid = action_uuid.ok_or(EventOutboxError::InvalidPostgresState)?;
                let action_id = ActionId::from_uuid(action_uuid)
                    .map_err(|_| EventOutboxError::InvalidPostgresState)?;
                (
                    OutboxEventKind::ActionTerminal,
                    OutboxAggregate::Action {
                        session_id,
                        action_id,
                    },
                )
            }
            KIND_SESSION_LOST => (
                OutboxEventKind::SessionLost,
                OutboxAggregate::Session { session_id },
            ),
            _ => return Err(EventOutboxError::InvalidPostgresState),
        };
        Ok(OutboxEvent {
            event_id,
            tenant_id: tenant_id.clone(),
            tenant_seq,
            aggregate,
            aggregate_revision: revision,
            kind,
            created_at,
        })
    }

    async fn fetch_page(
        transaction: &mut Transaction<'_, sqlx::Postgres>,
        tenant_id: &TenantId,
        after_seq: u64,
        limit: usize,
        cursor_expired: bool,
    ) -> Result<OutboxPage, EventOutboxError> {
        let rows = sqlx::query(
            "SELECT tenant_seq, event_id, kind, session_id, action_id, aggregate_revision, created_at
             FROM browserd_event_outbox
             WHERE tenant_id = $1 AND tenant_seq > $2
             ORDER BY tenant_seq ASC
             LIMIT $3",
        )
        .bind(tenant_id.as_uuid())
        .bind(Self::seq_to_i64(after_seq)?)
        .bind(i64::try_from(limit).map_err(|_| EventOutboxError::InvalidPageLimit)?)
        .fetch_all(&mut **transaction)
        .await
        .map_err(|_| EventOutboxError::PostgresUnavailable)?;
        let mut events = Vec::with_capacity(rows.len());
        for row in &rows {
            events.push(Self::row_to_event(row, tenant_id)?);
        }
        let next_cursor = events.last().map_or(after_seq, |event| event.tenant_seq);
        Ok(OutboxPage {
            events,
            next_cursor: EventCursor::from_position(next_cursor),
            cursor_expired,
        })
    }

    async fn pruned_through(
        transaction: &mut Transaction<'_, sqlx::Postgres>,
        tenant_id: &TenantId,
    ) -> Result<u64, EventOutboxError> {
        let row = sqlx::query(
            "SELECT pruned_through FROM browserd_event_outbox_cursor WHERE tenant_id = $1",
        )
        .bind(tenant_id.as_uuid())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|_| EventOutboxError::PostgresUnavailable)?;
        match row {
            None => Ok(0),
            Some(row) => Self::seq_from_i64(row.get::<i64, _>("pruned_through")),
        }
    }
}

#[async_trait]
impl EventOutbox for PostgresEventOutbox {
    async fn append(
        &self,
        append: OutboxAppend,
        now: DateTime<Utc>,
    ) -> Result<OutboxEvent, EventOutboxError> {
        let cutoff = self.cutoff(now)?;
        let dedup_key = Self::dedup_key(&append.aggregate, append.aggregate_revision, append.kind);
        let (session_id, action_id) = match &append.aggregate {
            OutboxAggregate::Action {
                session_id,
                action_id,
            } => (session_id.clone(), Some(action_id.clone())),
            OutboxAggregate::Session { session_id } => (session_id.clone(), None),
        };
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| EventOutboxError::PostgresUnavailable)?;
        Self::lock_tenant(&mut transaction, &append.tenant_id).await?;
        Self::prune(&mut transaction, &append.tenant_id, now, cutoff).await?;

        // Idempotency: a re-driven terminal commit returns the recorded event unchanged.
        if let Some(row) = sqlx::query(
            "SELECT tenant_seq, event_id, kind, session_id, action_id, aggregate_revision, created_at
             FROM browserd_event_outbox
             WHERE tenant_id = $1 AND dedup_key = $2",
        )
        .bind(append.tenant_id.as_uuid())
        .bind(&dedup_key)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| EventOutboxError::PostgresUnavailable)?
        {
            let event = Self::row_to_event(&row, &append.tenant_id)?;
            transaction
                .commit()
                .await
                .map_err(|_| EventOutboxError::PostgresUnavailable)?;
            return Ok(event);
        }

        // Assign the next per-tenant sequence, creating the cursor row on first use.
        let next_seq: i64 = sqlx::query(
            "INSERT INTO browserd_event_outbox_cursor (tenant_id, next_seq)
             VALUES ($1, 1)
             ON CONFLICT (tenant_id)
             DO UPDATE SET next_seq = browserd_event_outbox_cursor.next_seq + 1
             RETURNING next_seq",
        )
        .bind(append.tenant_id.as_uuid())
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| EventOutboxError::PostgresUnavailable)?
        .get("next_seq");

        let event_id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO browserd_event_outbox
             (tenant_id, tenant_seq, event_id, kind, session_id, action_id, aggregate_revision, dedup_key, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(append.tenant_id.as_uuid())
        .bind(next_seq)
        .bind(event_id)
        .bind(Self::kind_name(append.kind))
        .bind(session_id.as_uuid())
        .bind(action_id.as_ref().map(ActionId::as_uuid))
        .bind(Self::seq_to_i64(append.aggregate_revision)?)
        .bind(&dedup_key)
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(|_| EventOutboxError::PostgresUnavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| EventOutboxError::PostgresUnavailable)?;

        Ok(OutboxEvent {
            event_id,
            tenant_id: append.tenant_id,
            tenant_seq: Self::seq_from_i64(next_seq)?,
            aggregate: append.aggregate,
            aggregate_revision: append.aggregate_revision,
            kind: append.kind,
            created_at: now,
        })
    }

    async fn read_from(
        &self,
        tenant_id: &TenantId,
        after: EventCursor,
        limit: usize,
        now: DateTime<Utc>,
    ) -> Result<OutboxPage, EventOutboxError> {
        if !(1..=MAX_EVENT_PAGE_LIMIT).contains(&limit) {
            return Err(EventOutboxError::InvalidPageLimit);
        }
        let cutoff = self.cutoff(now)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| EventOutboxError::PostgresUnavailable)?;
        Self::lock_tenant(&mut transaction, tenant_id).await?;
        Self::prune(&mut transaction, tenant_id, now, cutoff).await?;
        let pruned_through = Self::pruned_through(&mut transaction, tenant_id).await?;
        let after_seq = after.position();
        let cursor_expired = pruned_through > after_seq;
        let page = Self::fetch_page(
            &mut transaction,
            tenant_id,
            after_seq,
            limit,
            cursor_expired,
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|_| EventOutboxError::PostgresUnavailable)?;
        Ok(page)
    }

    async fn read_after_event_id(
        &self,
        tenant_id: &TenantId,
        after: Option<Uuid>,
        limit: usize,
        now: DateTime<Utc>,
    ) -> Result<OutboxPage, EventOutboxError> {
        if !(1..=MAX_EVENT_PAGE_LIMIT).contains(&limit) {
            return Err(EventOutboxError::InvalidPageLimit);
        }
        let cutoff = self.cutoff(now)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| EventOutboxError::PostgresUnavailable)?;
        Self::lock_tenant(&mut transaction, tenant_id).await?;
        Self::prune(&mut transaction, tenant_id, now, cutoff).await?;

        let (after_seq, cursor_expired) = match after {
            None => (
                0,
                Self::pruned_through(&mut transaction, tenant_id).await? > 0,
            ),
            Some(event_id) => {
                let row = sqlx::query(
                    "SELECT tenant_seq FROM browserd_event_outbox
                     WHERE tenant_id = $1 AND event_id = $2",
                )
                .bind(tenant_id.as_uuid())
                .bind(event_id)
                .fetch_optional(&mut *transaction)
                .await
                .map_err(|_| EventOutboxError::PostgresUnavailable)?;
                match row {
                    Some(row) => (Self::seq_from_i64(row.get::<i64, _>("tenant_seq"))?, false),
                    None => (0, true),
                }
            }
        };
        let page = Self::fetch_page(
            &mut transaction,
            tenant_id,
            after_seq,
            limit,
            cursor_expired,
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|_| EventOutboxError::PostgresUnavailable)?;
        Ok(page)
    }

    async fn mark_delivered(
        &self,
        tenant_id: &TenantId,
        cursor: EventCursor,
    ) -> Result<(), EventOutboxError> {
        let cursor = cursor.position();
        if cursor == 0 {
            return Ok(());
        }
        let updated = sqlx::query(
            "UPDATE browserd_event_outbox_cursor
             SET delivered_through = GREATEST(delivered_through, $2)
             WHERE tenant_id = $1 AND next_seq >= $2",
        )
        .bind(tenant_id.as_uuid())
        .bind(Self::seq_to_i64(cursor)?)
        .execute(&self.pool)
        .await
        .map_err(|_| EventOutboxError::PostgresUnavailable)?;
        if updated.rows_affected() == 0 {
            return Err(EventOutboxError::DeliveryCursorAhead);
        }
        Ok(())
    }

    async fn delivered_cursor(
        &self,
        tenant_id: &TenantId,
    ) -> Result<EventCursor, EventOutboxError> {
        let row = sqlx::query(
            "SELECT delivered_through FROM browserd_event_outbox_cursor WHERE tenant_id = $1",
        )
        .bind(tenant_id.as_uuid())
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| EventOutboxError::PostgresUnavailable)?;
        match row {
            None => Ok(EventCursor::start()),
            Some(row) => Ok(EventCursor::from_position(Self::seq_from_i64(
                row.get::<i64, _>("delivered_through"),
            )?)),
        }
    }
}
