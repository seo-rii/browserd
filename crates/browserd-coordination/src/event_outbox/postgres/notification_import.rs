use std::borrow::Cow;

use browserd_core::{NotificationAck, NotificationCommit};
use chrono::{DateTime, Utc};
use sqlx::{
    Row, SqlSafeStr,
    migrate::{Migration, MigrationType, Migrator},
};

use super::{EventInsertIdentity, EventOutboxError, PostgresEventOutbox};
use crate::event_outbox::notification_import::{
    NOTIFICATION_IMPORT_RECEIPTS_PER_SOURCE, NotificationImportConfig, PreparedNotificationBatch,
    mapped_events, source_family_name,
};

impl PostgresEventOutbox {
    #[must_use]
    pub fn with_notification_import_config(mut self, config: NotificationImportConfig) -> Self {
        self.notification_import_config = config;
        self
    }

    pub(super) async fn migrate_notification_import(&self) -> Result<(), EventOutboxError> {
        let migration = Migration::new(
            1,
            Cow::Borrowed("worker notification imports"),
            MigrationType::Simple,
            include_str!("../../../migrations/notifications/0001_worker_notification_import.sql")
                .into_sql_str(),
            false,
        );
        let mut migrator = Migrator::with_migrations(vec![migration]);
        migrator.dangerous_set_table_name("_browserd_notification_import_migrations");
        migrator
            .run(&self.pool)
            .await
            .map_err(|_| EventOutboxError::PostgresUnavailable)
    }

    pub(super) async fn import_notification(
        &self,
        commit: NotificationCommit,
        trusted_now: DateTime<Utc>,
    ) -> Result<NotificationAck, EventOutboxError> {
        let PreparedNotificationBatch { created_at, events } = mapped_events(&commit)?;
        // Postgres timestamps have microsecond precision. Round the retention start upward so
        // precision loss cannot shorten the promised full retention period after a delayed import.
        let nanos = trusted_now.timestamp_subsec_nanos() % 1_000;
        let retention_started_at = if nanos == 0 {
            trusted_now
        } else {
            trusted_now
                .checked_add_signed(chrono::Duration::nanoseconds(i64::from(1_000 - nanos)))
                .ok_or(EventOutboxError::RetentionTimestampOverflow)?
        };
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|_| EventOutboxError::PostgresUnavailable)?;
        let scope = commit.scope();
        let tenant = scope.tenant_id();
        let worker = scope.original_worker_id().as_str();
        let family = source_family_name(scope.family());
        Self::lock_tenant(&mut tx, tenant).await?;
        // All imports use tenant -> namespace lock order. The namespace lock serializes lifetime
        // admissions across tenants; no payload body is loaded or cloned under this lock.
        let namespace = sqlx::query("SELECT config_sha256, source_count FROM browserd_notification_import_namespace WHERE singleton=TRUE FOR UPDATE")
            .fetch_one(&mut *tx).await.map_err(|_| EventOutboxError::PostgresUnavailable)?;
        let config = self.notification_import_config;
        let config_digest: Option<Vec<u8>> = namespace
            .try_get("config_sha256")
            .map_err(|_| EventOutboxError::InvalidPostgresState)?;
        let source_count = Self::seq_from_i64(
            namespace
                .try_get("source_count")
                .map_err(|_| EventOutboxError::InvalidPostgresState)?,
        )?;
        if config_digest
            .as_ref()
            .is_some_and(|digest| *digest != config.digest())
        {
            return Err(EventOutboxError::InvalidNotificationImportConfig);
        }
        if source_count > config.max_sources() as u64
            || (config_digest.is_none() && source_count != 0)
        {
            return Err(EventOutboxError::InvalidPostgresState);
        }
        let watermark: Option<i64> = sqlx::query_scalar("SELECT imported_through FROM browserd_notification_source_watermark WHERE tenant_id=$1 AND original_worker_id=$2 AND source_id=$3 AND family=$4 FOR UPDATE")
            .bind(tenant.as_uuid()).bind(worker).bind(scope.source_id()).bind(family)
            .fetch_optional(&mut *tx).await.map_err(|_| EventOutboxError::PostgresUnavailable)?;
        let highwater = watermark.map(Self::seq_from_i64).transpose()?.unwrap_or(0);
        if watermark.is_some() && (highwater == 0 || config_digest.is_none() || source_count == 0) {
            return Err(EventOutboxError::InvalidPostgresState);
        }
        if commit.source_sequence() <= highwater {
            let digest: Option<Vec<u8>> = sqlx::query_scalar("SELECT commit_sha256 FROM browserd_notification_import_receipt WHERE tenant_id=$1 AND original_worker_id=$2 AND source_id=$3 AND family=$4 AND source_sequence=$5")
                .bind(tenant.as_uuid()).bind(worker).bind(scope.source_id()).bind(family)
                .bind(Self::seq_to_i64(commit.source_sequence())?)
                .fetch_optional(&mut *tx).await.map_err(|_| EventOutboxError::PostgresUnavailable)?;
            let digest = digest.ok_or(EventOutboxError::NotificationReceiptExpired)?;
            if digest != commit.digest() {
                return Err(EventOutboxError::NotificationDigestMismatch);
            }
            tx.commit()
                .await
                .map_err(|_| EventOutboxError::PostgresUnavailable)?;
            return Ok(commit.ack());
        }
        if commit.source_sequence() != highwater + 1 {
            return Err(EventOutboxError::ProjectionGap);
        }
        if watermark.is_none() {
            let tenant_count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM browserd_notification_source_watermark WHERE tenant_id=$1",
            )
            .bind(tenant.as_uuid())
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| EventOutboxError::PostgresUnavailable)?;
            if source_count >= config.max_sources() as u64
                || Self::seq_from_i64(tenant_count)? >= config.max_sources_per_tenant() as u64
            {
                return Err(EventOutboxError::NotificationSourceCapacity);
            }
        }
        let tenant_tail: Option<i64> = sqlx::query_scalar(
            "SELECT next_seq FROM browserd_event_outbox_cursor WHERE tenant_id=$1",
        )
        .bind(tenant.as_uuid())
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| EventOutboxError::PostgresUnavailable)?;
        let tenant_tail = tenant_tail
            .map(Self::seq_from_i64)
            .transpose()?
            .unwrap_or(0);
        if tenant_tail
            .checked_add(events.len() as u64)
            .is_none_or(|tail| tail > i64::MAX as u64)
        {
            return Err(EventOutboxError::SequenceOverflow);
        }
        for (event_id, append) in events {
            self.append_identified_in_transaction(
                &mut tx,
                append,
                trusted_now,
                EventInsertIdentity {
                    event_id,
                    created_at,
                    retention_started_at: Some(retention_started_at),
                    require_new: true,
                },
            )
            .await?;
        }
        sqlx::query("INSERT INTO browserd_notification_source_watermark (tenant_id,original_worker_id,source_id,family,imported_through) VALUES($1,$2,$3,$4,$5) ON CONFLICT(tenant_id,original_worker_id,source_id,family) DO UPDATE SET imported_through=EXCLUDED.imported_through")
            .bind(tenant.as_uuid()).bind(worker).bind(scope.source_id()).bind(family)
            .bind(Self::seq_to_i64(commit.source_sequence())?)
            .execute(&mut *tx).await.map_err(|_| EventOutboxError::PostgresUnavailable)?;
        sqlx::query("INSERT INTO browserd_notification_import_receipt(tenant_id,original_worker_id,source_id,family,source_sequence,commit_sha256) VALUES($1,$2,$3,$4,$5,$6)")
            .bind(tenant.as_uuid()).bind(worker).bind(scope.source_id()).bind(family)
            .bind(Self::seq_to_i64(commit.source_sequence())?).bind(commit.digest().as_slice())
            .execute(&mut *tx).await.map_err(|_| EventOutboxError::PostgresUnavailable)?;
        let receipt_floor = commit
            .source_sequence()
            .saturating_sub(NOTIFICATION_IMPORT_RECEIPTS_PER_SOURCE as u64);
        sqlx::query("DELETE FROM browserd_notification_import_receipt WHERE tenant_id=$1 AND original_worker_id=$2 AND source_id=$3 AND family=$4 AND source_sequence <= $5")
            .bind(tenant.as_uuid()).bind(worker).bind(scope.source_id()).bind(family)
            .bind(Self::seq_to_i64(receipt_floor)?)
            .execute(&mut *tx).await.map_err(|_| EventOutboxError::PostgresUnavailable)?;
        sqlx::query("UPDATE browserd_notification_import_namespace SET config_sha256=$1,source_count=source_count+$2 WHERE singleton=TRUE")
            .bind(config.digest().as_slice()).bind(if watermark.is_none() {1_i64} else {0_i64})
            .execute(&mut *tx).await.map_err(|_| EventOutboxError::PostgresUnavailable)?;
        tx.commit()
            .await
            .map_err(|_| EventOutboxError::PostgresUnavailable)?;
        Ok(commit.ack())
    }
}
