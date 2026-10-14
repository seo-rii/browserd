use super::{
    engine::{self, Mutation, TenantState},
    *,
};
use crate::{PostgresEventOutbox, StoreConfig, event_outbox::WebhookOutboxSource};
use sqlx::{
    Postgres, Row, SqlSafeStr, Transaction,
    migrate::{Migration, MigrationType, Migrator},
};
use std::borrow::Cow;

const MAX_STATE_BYTES: usize = 32 * 1024 * 1024;
#[derive(Clone)]
pub struct PostgresWebhookStore {
    outbox: PostgresEventOutbox,
    config: WebhookStoreConfig,
}
impl PostgresWebhookStore {
    pub fn new(outbox: PostgresEventOutbox, config: WebhookStoreConfig) -> Result<Self, Error> {
        config.validate()?;
        Ok(Self { outbox, config })
    }
    pub async fn connect(
        database_url: &str,
        max_connections: u32,
        config: WebhookStoreConfig,
    ) -> Result<Self, Error> {
        Self::new(
            PostgresEventOutbox::connect(database_url, max_connections, StoreConfig::default())
                .await
                .map_err(|_| Error::Unavailable)?,
            config,
        )
    }
    pub async fn migrate(&self) -> Result<(), Error> {
        self.outbox
            .migrate()
            .await
            .map_err(|_| Error::Unavailable)?;
        let migration = Migration::new(
            5,
            Cow::Borrowed("webhook registry and delivery"),
            MigrationType::Simple,
            include_str!("../../migrations/outbox/0005_webhook_delivery.sql").into_sql_str(),
            false,
        );
        let mut migrator = Migrator::with_migrations(vec![migration]);
        migrator.dangerous_set_table_name("_browserd_webhook_migrations");
        migrator
            .run(self.outbox.pool())
            .await
            .map_err(|_| Error::Unavailable)?;
        Ok(())
    }
    async fn namespace(&self, tx: &mut Transaction<'_, Postgres>) -> Result<i64, Error> {
        let row=sqlx::query("SELECT config_sha256,endpoint_count FROM browserd_webhook_namespace WHERE singleton=TRUE FOR UPDATE").fetch_one(&mut **tx).await.map_err(|_|Error::Unavailable)?;
        let existing: Option<Vec<u8>> = row
            .try_get("config_sha256")
            .map_err(|_| Error::Unavailable)?;
        if let Some(existing) = existing {
            if existing != self.config.digest() {
                return Err(Error::InvalidConfiguration);
            }
        } else {
            sqlx::query(
                "UPDATE browserd_webhook_namespace SET config_sha256=$1 WHERE singleton=TRUE",
            )
            .bind(self.config.digest().as_slice())
            .execute(&mut **tx)
            .await
            .map_err(|_| Error::Unavailable)?;
        }
        row.try_get("endpoint_count")
            .map_err(|_| Error::Unavailable)
    }
    async fn load(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        tenant: &TenantId,
    ) -> Result<Option<TenantState>, Error> {
        let row = sqlx::query(
            "SELECT state_json FROM browserd_webhook_authority WHERE tenant_id=$1 FOR UPDATE",
        )
        .bind(tenant.as_uuid())
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| Error::Unavailable)?;
        let Some(row) = row else { return Ok(None) };
        let raw: String = row.try_get("state_json").map_err(|_| Error::Unavailable)?;
        if raw.len() > MAX_STATE_BYTES {
            return Err(Error::Unavailable);
        }
        let state: TenantState = serde_json::from_str(&raw).map_err(|_| Error::Unavailable)?;
        state.validate(tenant, &self.config)?;
        let rows=sqlx::query("SELECT attempt_id,octet_length(payload) AS body_len,payload_sha256 FROM browserd_webhook_ack_payload WHERE tenant_id=$1 ORDER BY attempt_id LIMIT $2").bind(tenant.as_uuid()).bind(i64::try_from(self.config.max_acknowledged_per_tenant+1).map_err(|_|Error::Unavailable)?).fetch_all(&mut **tx).await.map_err(|_|Error::Unavailable)?;
        if rows.len() != state.archives().count() {
            return Err(Error::Unavailable);
        }
        for row in rows {
            let id: Uuid = row.try_get("attempt_id").map_err(|_| Error::Unavailable)?;
            let len: i32 = row.try_get("body_len").map_err(|_| Error::Unavailable)?;
            let sha: Vec<u8> = row
                .try_get("payload_sha256")
                .map_err(|_| Error::Unavailable)?;
            let record = state
                .archives()
                .find(|a| a.attempt_id == id)
                .ok_or(Error::Unavailable)?;
            if usize::try_from(len).ok() != Some(record.body_len) || sha != record.body_sha256 {
                return Err(Error::Unavailable);
            }
        }
        Ok(Some(state))
    }
    async fn persist(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        tenant: &TenantId,
        state: &TenantState,
    ) -> Result<(), Error> {
        state.validate(tenant, &self.config)?;
        let raw = serde_json::to_string(state).map_err(|_| Error::Unavailable)?;
        if raw.len() > MAX_STATE_BYTES {
            return Err(Error::Capacity);
        }
        sqlx::query("INSERT INTO browserd_webhook_authority(tenant_id,state_json) VALUES($1,$2) ON CONFLICT(tenant_id) DO UPDATE SET state_json=EXCLUDED.state_json").bind(tenant.as_uuid()).bind(raw).execute(&mut **tx).await.map_err(|_|Error::Unavailable)?;
        let ids: Vec<Uuid> = state.archives().map(|a| a.attempt_id).collect();
        sqlx::query("DELETE FROM browserd_webhook_ack_payload WHERE tenant_id=$1 AND NOT(attempt_id=ANY($2))").bind(tenant.as_uuid()).bind(&ids).execute(&mut **tx).await.map_err(|_|Error::Unavailable)?;
        for archive in state.archives() {
            if let Some(body) = &archive.payload {
                sqlx::query("INSERT INTO browserd_webhook_ack_payload(tenant_id,attempt_id,payload,payload_sha256,acknowledged_at,expires_at) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(tenant_id,attempt_id) DO NOTHING").bind(tenant.as_uuid()).bind(archive.attempt_id).bind(body.as_bytes()).bind(body.sha256.as_slice()).bind(archive.result.finished_at).bind(engine::after(archive.result.finished_at,WEBHOOK_ACK_RETENTION)?).execute(&mut **tx).await.map_err(|_|Error::Unavailable)?;
            }
        }
        Ok(())
    }
    async fn apply<T>(
        &self,
        tenant: &TenantId,
        allow_create: bool,
        f: impl FnOnce(&mut TenantState, &WebhookOutboxSource, DateTime<Utc>) -> Result<T, Error> + Send,
    ) -> Result<T, Error> {
        let mut tx = self
            .outbox
            .pool()
            .begin()
            .await
            .map_err(|_| Error::Unavailable)?;
        self.outbox
            .lock_webhook_source(&mut tx, tenant)
            .await
            .map_err(|_| Error::Unavailable)?;
        let count = self.namespace(&mut tx).await?;
        let stored = self.load(&mut tx, tenant).await?;
        if stored.is_none() && !allow_create {
            return Err(Error::NotFound);
        }
        if stored.is_none()
            && usize::try_from(count).map_err(|_| Error::Unavailable)? >= self.config.max_endpoints
        {
            return Err(Error::Capacity);
        }
        let was_present = stored.is_some();
        let mut current = stored.unwrap_or_default();
        let db_now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| Error::Unavailable)?;
        let now = current.advance_floor(db_now)?;
        let after = current
            .endpoint
            .as_ref()
            .map(WebhookEndpointSnapshot::cursor);
        let source = self
            .outbox
            .source_in_transaction(&mut tx, tenant, after, now)
            .await
            .map_err(|_| Error::Unavailable)?;
        let mut changed = current.clone();
        let result = f(&mut changed, &source, now);
        let state = if result.is_ok() { &changed } else { &current };
        if result.is_ok() || was_present {
            self.persist(&mut tx, tenant, state).await?;
        }
        if result.is_ok() && !was_present {
            sqlx::query("UPDATE browserd_webhook_namespace SET endpoint_count=endpoint_count+1 WHERE singleton=TRUE").execute(&mut *tx).await.map_err(|_|Error::Unavailable)?;
        }
        tx.commit().await.map_err(|_| Error::Unavailable)?;
        result
    }
    async fn keys(
        &self,
        cursor: &WebhookDeliveryCursor,
        limit: usize,
    ) -> Result<Vec<TenantId>, Error> {
        cursor.validate()?;
        if !(1..=MAX_WEBHOOK_EXAMINED).contains(&limit) {
            return Err(Error::InvalidConfiguration);
        }
        let after = cursor.after.as_ref().map(TenantId::as_uuid);
        let rows=sqlx::query("SELECT tenant_id FROM browserd_webhook_authority WHERE ($1::UUID IS NULL OR tenant_id>$1) ORDER BY tenant_id LIMIT $2").bind(after).bind(i64::try_from(limit).map_err(|_|Error::Unavailable)?).fetch_all(self.outbox.pool()).await.map_err(|_|Error::Unavailable)?;
        rows.into_iter()
            .map(|r| {
                let id: Uuid = r.try_get("tenant_id").map_err(|_| Error::Unavailable)?;
                TenantId::from_uuid(id).map_err(|_| Error::Unavailable)
            })
            .collect()
    }
    async fn mutate(
        &self,
        expected: &WebhookEndpointRef,
        binding: WebhookMutationBinding,
        mutation: Mutation,
    ) -> Result<WebhookEndpointSnapshot, Error> {
        if expected.tenant_id() != binding.tenant_id() {
            return Err(Error::InvalidMutation);
        }
        self.apply(binding.tenant_id(), false, |state, source, now| {
            state.mutation(&binding, mutation, None, source, now, &self.config)
        })
        .await
    }
}
#[async_trait]
impl WebhookStore for PostgresWebhookStore {
    async fn put_endpoint(
        &self,
        request: WebhookPutRequest,
    ) -> Result<WebhookEndpointSnapshot, Error> {
        request.validate()?;
        self.apply(request.binding.tenant_id(), true, |state, source, now| {
            state.mutation(
                &request.binding,
                Mutation::Put {
                    expected_revision: request.expected_revision,
                    endpoint_url: request.spec.endpoint_url.clone(),
                },
                Some(&request.spec),
                source,
                now,
                &self.config,
            )
        })
        .await
    }
    async fn get_endpoint(
        &self,
        tenant: &TenantId,
    ) -> Result<Option<WebhookEndpointSnapshot>, Error> {
        match self
            .apply(tenant, false, |state, source, _| {
                Ok(state.observed_endpoint(source))
            })
            .await
        {
            Err(Error::NotFound) => Ok(None),
            result => result,
        }
    }
    async fn delete_endpoint(
        &self,
        expected: &WebhookEndpointRef,
        binding: WebhookMutationBinding,
    ) -> Result<WebhookEndpointSnapshot, Error> {
        self.mutate(
            expected,
            binding,
            Mutation::Delete {
                expected: expected.clone(),
            },
        )
        .await
    }
    async fn suspend_endpoint(
        &self,
        expected: &WebhookEndpointRef,
        binding: WebhookMutationBinding,
    ) -> Result<WebhookEndpointSnapshot, Error> {
        self.mutate(
            expected,
            binding,
            Mutation::Suspend {
                expected: expected.clone(),
            },
        )
        .await
    }
    async fn resume_endpoint(
        &self,
        expected: &WebhookEndpointRef,
        binding: WebhookMutationBinding,
        mode: WebhookResumeMode,
    ) -> Result<WebhookEndpointSnapshot, Error> {
        self.mutate(
            expected,
            binding,
            Mutation::Resume {
                expected: expected.clone(),
                mode,
            },
        )
        .await
    }
    async fn claim_due_attempts(
        &self,
        cursor: WebhookDeliveryCursor,
        limit: usize,
        max_attempts: usize,
        lease_ttl: Duration,
    ) -> Result<WebhookAttemptPage, Error> {
        engine::scan_bounds(&cursor, limit, max_attempts)?;
        engine::lease_ttl(lease_ttl)?;
        let keys = self.keys(&cursor, limit).await?;
        let mut attempts = Vec::new();
        let mut examined = 0;
        for tenant in &keys {
            if attempts.len() == max_attempts {
                break;
            }
            examined += 1;
            let lease = match self
                .apply(tenant, false, |state, source, now| {
                    state.claim(source, now, lease_ttl, &self.config)
                })
                .await
            {
                Ok(lease) => lease,
                Err(Error::Capacity | Error::AuditCapacity) => continue,
                Err(error) => return Err(error),
            };
            if let Some(lease) = lease {
                attempts.push(lease)
            }
        }
        let complete = examined == keys.len() && keys.len() < limit;
        let next_cursor = if complete {
            WebhookDeliveryCursor::default()
        } else {
            WebhookDeliveryCursor {
                schema_version: 1,
                after: keys.get(examined.saturating_sub(1)).cloned(),
            }
        };
        Ok(WebhookAttemptPage {
            attempts,
            next_cursor,
            complete,
            examined,
        })
    }
    async fn finish_attempt(
        &self,
        lease: &WebhookAttemptLease,
        outcome: WebhookAttemptOutcome,
    ) -> Result<WebhookAttemptResult, Error> {
        self.apply(lease.endpoint_ref.tenant_id(), false, |state, _, now| {
            state.finish(lease, outcome, now, &self.config)
        })
        .await
    }
    async fn maintain(
        &self,
        cursor: WebhookDeliveryCursor,
        limit: usize,
    ) -> Result<WebhookMaintenancePage, Error> {
        let keys = self.keys(&cursor, limit).await?;
        let mut reclaimed = 0;
        for tenant in &keys {
            reclaimed += self
                .apply(tenant, false, |state, _, now| state.prune(now))
                .await?;
        }
        let complete = keys.len() < limit;
        let next_cursor = if complete {
            WebhookDeliveryCursor::default()
        } else {
            WebhookDeliveryCursor {
                schema_version: 1,
                after: keys.last().cloned(),
            }
        };
        Ok(WebhookMaintenancePage {
            next_cursor,
            complete,
            examined: keys.len(),
            reclaimed,
        })
    }
}
