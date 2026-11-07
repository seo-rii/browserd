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
use browserd_core::{
    ActionId, ApprovalId, ArtifactId, NotificationAck, NotificationCommit, OperationId, SessionId,
    TenantId,
};
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
use crate::{GatewayEventProjection, StoreConfig};

mod notification_import;

struct EventInsertIdentity {
    event_id: Uuid,
    created_at: DateTime<Utc>,
    retention_started_at: Option<DateTime<Utc>>,
    require_new: bool,
}

/// Advisory-lock namespace for the outbox, keeping its per-tenant locks disjoint from any other
/// feature's advisory locks on the same database.
const ADVISORY_NAMESPACE: i32 = 0x0B0C;

/// Postgres-backed durable event outbox.
#[derive(Clone)]
pub struct PostgresEventOutbox {
    pool: PgPool,
    retention: Duration,
    notification_import_config: super::NotificationImportConfig,
}

impl PostgresEventOutbox {
    /// Wrap an existing pool.
    #[must_use]
    pub fn new(pool: PgPool, config: StoreConfig) -> Self {
        Self {
            pool,
            retention: config.retention(),
            notification_import_config: super::NotificationImportConfig::default(),
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
        let projection_migration = Migration::new(
            2,
            Cow::Borrowed("event projection watermark"),
            MigrationType::Simple,
            include_str!("../../migrations/outbox/0002_projection_watermark.sql").into_sql_str(),
            false,
        );
        let control_migration = Migration::new(
            3,
            Cow::Borrowed("viewer control projection"),
            MigrationType::Simple,
            include_str!("../../migrations/outbox/0003_viewer_control_projection.sql")
                .into_sql_str(),
            false,
        );
        let notification_migration = Migration::new(
            4,
            Cow::Borrowed("typed event notifications"),
            MigrationType::Simple,
            include_str!("../../migrations/outbox/0004_event_notifications.sql").into_sql_str(),
            false,
        );
        let mut migrator = Migrator::with_migrations(vec![
            migration,
            projection_migration,
            control_migration,
            notification_migration,
        ]);
        migrator.dangerous_set_table_name("_browserd_event_outbox_migrations");
        migrator
            .run(&self.pool)
            .await
            .map_err(|_| EventOutboxError::PostgresUnavailable)?;
        self.migrate_notification_import().await?;
        Ok(())
    }

    #[must_use]
    pub const fn pool(&self) -> &PgPool {
        &self.pool
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
             WHERE tenant_id = $1 AND COALESCE(retention_started_at, created_at) <= $2
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
        let session_id = row
            .get::<Option<Uuid>, _>("session_id")
            .map(SessionId::from_uuid)
            .transpose()
            .map_err(|_| EventOutboxError::InvalidPostgresState)?;
        let action_id = row
            .get::<Option<Uuid>, _>("action_id")
            .map(ActionId::from_uuid)
            .transpose()
            .map_err(|_| EventOutboxError::InvalidPostgresState)?;
        let operation_id = row
            .get::<Option<Uuid>, _>("operation_id")
            .map(OperationId::from_uuid)
            .transpose()
            .map_err(|_| EventOutboxError::InvalidPostgresState)?;
        let approval_id = row
            .get::<Option<Uuid>, _>("approval_id")
            .map(ApprovalId::from_uuid)
            .transpose()
            .map_err(|_| EventOutboxError::InvalidPostgresState)?;
        let artifact_id = row
            .get::<Option<Uuid>, _>("artifact_id")
            .map(ArtifactId::from_uuid)
            .transpose()
            .map_err(|_| EventOutboxError::InvalidPostgresState)?;
        let kind = OutboxEventKind::from_storage_name(&kind_name)
            .ok_or(EventOutboxError::InvalidPostgresState)?;
        let aggregate = match (
            session_id,
            action_id,
            operation_id,
            approval_id,
            artifact_id,
        ) {
            (None, None, Some(operation_id), None, None) => {
                OutboxAggregate::Operation { operation_id }
            }
            (Some(session_id), Some(action_id), None, Some(approval_id), None) => {
                OutboxAggregate::Approval {
                    session_id,
                    action_id,
                    approval_id,
                }
            }
            (Some(session_id), None, None, None, Some(artifact_id)) => OutboxAggregate::Artifact {
                session_id,
                artifact_id,
            },
            (Some(session_id), Some(action_id), None, None, None) => OutboxAggregate::Action {
                session_id,
                action_id,
            },
            (Some(session_id), None, None, None, None) => OutboxAggregate::Session { session_id },
            _ => return Err(EventOutboxError::InvalidPostgresState),
        };
        let summary = row
            .get::<Option<serde_json::Value>, _>("state_summary")
            .map(serde_json::from_value)
            .transpose()
            .map_err(|_| EventOutboxError::InvalidPostgresState)?;
        let event = OutboxEvent {
            event_id,
            tenant_id: tenant_id.clone(),
            tenant_seq,
            aggregate,
            aggregate_revision: revision,
            kind,
            created_at: row.get("created_at"),
            summary,
        };
        event
            .validate()
            .map_err(|_| EventOutboxError::InvalidPostgresState)?;
        Ok(event)
    }

    async fn fetch_page(
        transaction: &mut Transaction<'_, sqlx::Postgres>,
        tenant_id: &TenantId,
        after_seq: u64,
        limit: usize,
        cursor_expired: bool,
    ) -> Result<OutboxPage, EventOutboxError> {
        let rows = sqlx::query(
            "SELECT tenant_seq, event_id, kind, session_id, action_id, operation_id, approval_id, artifact_id, state_summary, aggregate_revision, created_at
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
    pub(crate) async fn append_transactional(
        &self,
        transaction: &mut Transaction<'_, sqlx::Postgres>,
        append: OutboxAppend,
        now: DateTime<Utc>,
    ) -> Result<OutboxEvent, EventOutboxError> {
        Self::lock_tenant(transaction, append.tenant_id()).await?;
        self.append_in_transaction(transaction, append, now).await
    }

    pub(crate) async fn lock_webhook_source(
        &self,
        transaction: &mut Transaction<'_, sqlx::Postgres>,
        tenant: &TenantId,
    ) -> Result<(), EventOutboxError> {
        Self::lock_tenant(transaction, tenant).await
    }

    pub(crate) async fn source_in_transaction(
        &self,
        transaction: &mut Transaction<'_, sqlx::Postgres>,
        tenant: &TenantId,
        after: Option<EventCursor>,
        now: DateTime<Utc>,
    ) -> Result<super::WebhookOutboxSource, EventOutboxError> {
        Self::lock_tenant(transaction, tenant).await?;
        Self::prune(transaction, tenant, now, self.cutoff(now)?).await?;
        let cursor = sqlx::query("SELECT next_seq, pruned_through FROM browserd_event_outbox_cursor WHERE tenant_id = $1")
            .bind(tenant.as_uuid()).fetch_optional(&mut **transaction).await.map_err(|_| EventOutboxError::PostgresUnavailable)?;
        let (tail, pruned) = match cursor {
            Some(row) => (
                Self::seq_from_i64(row.get("next_seq"))?,
                Self::seq_from_i64(row.get("pruned_through"))?,
            ),
            None => (0, 0),
        };
        let next_event = match after {
            Some(after) => Self::fetch_page(transaction, tenant, after.position(), 1, false)
                .await?
                .events
                .into_iter()
                .next(),
            None => None,
        };
        Ok(super::WebhookOutboxSource {
            tail: EventCursor::from_position(tail),
            pruned_through: EventCursor::from_position(pruned),
            next_event,
        })
    }

    /// Caller holds the per-tenant transaction lock. Reused by ordinary appends and source
    /// projection commits so event insertion and the projection highwater share one transaction.
    async fn append_in_transaction(
        &self,
        transaction: &mut Transaction<'_, sqlx::Postgres>,
        append: OutboxAppend,
        now: DateTime<Utc>,
    ) -> Result<OutboxEvent, EventOutboxError> {
        self.append_identified_in_transaction(
            transaction,
            append,
            now,
            EventInsertIdentity {
                event_id: Uuid::now_v7(),
                created_at: now,
                retention_started_at: None,
                require_new: false,
            },
        )
        .await
    }

    async fn append_identified_in_transaction(
        &self,
        transaction: &mut Transaction<'_, sqlx::Postgres>,
        append: OutboxAppend,
        now: DateTime<Utc>,
        identity: EventInsertIdentity,
    ) -> Result<OutboxEvent, EventOutboxError> {
        append.validate()?;
        let cutoff = self.cutoff(now)?;
        let dedup_key =
            super::model::dedup_key(&append.aggregate, append.aggregate_revision, append.kind);
        let session_id = append.session_id();
        let (action_id, operation_id, approval_id, artifact_id) = match &append.aggregate {
            OutboxAggregate::Action { action_id, .. } => (Some(action_id), None, None, None),
            OutboxAggregate::Session { .. } => (None, None, None, None),
            OutboxAggregate::Operation { operation_id } => (None, Some(operation_id), None, None),
            OutboxAggregate::Approval {
                action_id,
                approval_id,
                ..
            } => (Some(action_id), None, Some(approval_id), None),
            OutboxAggregate::Artifact { artifact_id, .. } => (None, None, None, Some(artifact_id)),
        };
        let summary = append
            .summary
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(|_| EventOutboxError::InvalidEvent)?;
        Self::prune(transaction, &append.tenant_id, now, cutoff).await?;

        // Idempotency: a re-driven terminal commit returns the recorded event unchanged.
        if let Some(row) = sqlx::query(
            "SELECT tenant_seq, event_id, kind, session_id, action_id, operation_id, approval_id, artifact_id, state_summary, aggregate_revision, created_at
             FROM browserd_event_outbox
             WHERE tenant_id = $1 AND dedup_key = $2",
        )
        .bind(append.tenant_id.as_uuid())
        .bind(&dedup_key)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|_| EventOutboxError::PostgresUnavailable)?
        {
            let event = Self::row_to_event(&row, &append.tenant_id)?;
            if identity.require_new || !event.matches_append(&append) { return Err(EventOutboxError::ConflictingEvent); }
            return Ok(event);
        }

        if identity.require_new {
            let id_exists: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM browserd_event_outbox WHERE tenant_id=$1 AND event_id=$2)",
            )
            .bind(append.tenant_id.as_uuid())
            .bind(identity.event_id)
            .fetch_one(&mut **transaction)
            .await
            .map_err(|_| EventOutboxError::PostgresUnavailable)?;
            if id_exists {
                return Err(EventOutboxError::ConflictingEvent);
            }
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
        .fetch_one(&mut **transaction)
        .await
        .map_err(|_| EventOutboxError::PostgresUnavailable)?
        .get("next_seq");

        let event_id = identity.event_id;
        let persisted_created_at: DateTime<Utc> = sqlx::query(
            "INSERT INTO browserd_event_outbox
             (tenant_id, tenant_seq, event_id, kind, session_id, action_id, aggregate_revision, dedup_key, created_at, operation_id, approval_id, artifact_id, state_summary, retention_started_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
             RETURNING created_at",
        )
        .bind(append.tenant_id.as_uuid())
        .bind(next_seq)
        .bind(event_id)
        .bind(append.kind.storage_name())
        .bind(session_id.map(SessionId::as_uuid))
        .bind(action_id.map(ActionId::as_uuid))
        .bind(Self::seq_to_i64(append.aggregate_revision)?)
        .bind(&dedup_key)
        .bind(identity.created_at)
        .bind(operation_id.map(OperationId::as_uuid))
        .bind(approval_id.map(ApprovalId::as_uuid))
        .bind(artifact_id.map(ArtifactId::as_uuid))
        .bind(summary)
        .bind(identity.retention_started_at)
        .fetch_one(&mut **transaction)
        .await
        .map_err(|_| EventOutboxError::PostgresUnavailable)?
        .get("created_at");

        Ok(OutboxEvent {
            event_id,
            tenant_id: append.tenant_id,
            tenant_seq: Self::seq_from_i64(next_seq)?,
            aggregate: append.aggregate,
            aggregate_revision: append.aggregate_revision,
            kind: append.kind,
            created_at: persisted_created_at,
            summary: append.summary,
        })
    }
}

#[async_trait]
impl EventOutbox for PostgresEventOutbox {
    async fn append_notification_commit(
        &self,
        commit: NotificationCommit,
        trusted_now: DateTime<Utc>,
    ) -> Result<NotificationAck, EventOutboxError> {
        self.import_notification(commit, trusted_now).await
    }

    async fn append(
        &self,
        append: OutboxAppend,
        now: DateTime<Utc>,
    ) -> Result<OutboxEvent, EventOutboxError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| EventOutboxError::PostgresUnavailable)?;
        Self::lock_tenant(&mut transaction, append.tenant_id()).await?;
        let event = self
            .append_in_transaction(&mut transaction, append, now)
            .await?;
        transaction
            .commit()
            .await
            .map_err(|_| EventOutboxError::PostgresUnavailable)?;
        Ok(event)
    }

    async fn append_projection(
        &self,
        projection: GatewayEventProjection,
        now: DateTime<Utc>,
    ) -> Result<(), EventOutboxError> {
        super::validated_projection(&projection)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|_| EventOutboxError::PostgresUnavailable)?;
        Self::lock_tenant(&mut transaction, projection.tenant_id()).await?;
        let row = sqlx::query(
            "SELECT projected_through FROM browserd_event_projection_watermark
             WHERE tenant_id = $1 AND session_id = $2 AND source = $3",
        )
        .bind(projection.tenant_id().as_uuid())
        .bind(projection.session_id().as_uuid())
        .bind(projection.source().as_str())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| EventOutboxError::PostgresUnavailable)?;
        let highwater = match row {
            Some(row) => Self::seq_from_i64(row.get::<i64, _>("projected_through"))?,
            None => 0,
        };
        if projection.sequence() <= highwater {
            transaction
                .commit()
                .await
                .map_err(|_| EventOutboxError::PostgresUnavailable)?;
            return Ok(());
        }
        if projection.sequence() != highwater + 1 {
            return Err(EventOutboxError::ProjectionGap);
        }
        self.append_in_transaction(&mut transaction, projection.append().clone(), now)
            .await?;
        sqlx::query(
            "INSERT INTO browserd_event_projection_watermark (tenant_id, session_id, projected_through, source)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (tenant_id, session_id, source) DO UPDATE
             SET projected_through = EXCLUDED.projected_through",
        )
        .bind(projection.tenant_id().as_uuid())
        .bind(projection.session_id().as_uuid())
        .bind(Self::seq_to_i64(projection.sequence())?)
        .bind(projection.source().as_str())
        .execute(&mut *transaction)
        .await
        .map_err(|_| EventOutboxError::PostgresUnavailable)?;
        transaction
            .commit()
            .await
            .map_err(|_| EventOutboxError::PostgresUnavailable)?;
        Ok(())
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
