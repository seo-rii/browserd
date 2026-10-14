use super::{
    engine::{self, Mutation, TenantState},
    *,
};
use crate::{MemoryEventOutbox, event_outbox::WebhookOutboxSource};
use std::{
    collections::BTreeMap,
    ops::Bound::{Excluded, Unbounded},
    sync::{Arc, Mutex},
};

#[derive(Default)]
pub(crate) struct WebhookMemoryState {
    config_digest: Option<[u8; 32]>,
    tenants: BTreeMap<TenantId, TenantState>,
}
impl std::ops::Deref for WebhookMemoryState {
    type Target = BTreeMap<TenantId, TenantState>;
    fn deref(&self) -> &Self::Target {
        &self.tenants
    }
}
impl std::ops::DerefMut for WebhookMemoryState {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.tenants
    }
}

#[derive(Clone)]
pub struct MemoryWebhookStore {
    outbox: MemoryEventOutbox,
    state: Arc<Mutex<WebhookMemoryState>>,
    config: WebhookStoreConfig,
    clock: Option<Arc<dyn WebhookClock>>,
}
impl MemoryWebhookStore {
    pub fn new(outbox: MemoryEventOutbox, config: WebhookStoreConfig) -> Result<Self, Error> {
        config.validate()?;
        let state = outbox.webhook_state();
        {
            let mut guard = state.lock().map_err(|_| Error::Unavailable)?;
            match guard.config_digest {
                Some(digest) if digest != config.digest() => {
                    return Err(Error::InvalidConfiguration);
                }
                Some(_) => {}
                None => guard.config_digest = Some(config.digest()),
            }
        }
        Ok(Self {
            outbox,
            state,
            config,
            clock: None,
        })
    }
    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn WebhookClock>) -> Self {
        self.clock = Some(clock);
        self
    }
    fn now(&self) -> DateTime<Utc> {
        self.clock.as_ref().map_or_else(Utc::now, |c| c.now())
    }
    fn apply<T>(
        &self,
        tenant: &TenantId,
        allow_create: bool,
        f: impl FnOnce(&mut TenantState, &WebhookOutboxSource, DateTime<Utc>) -> Result<T, Error>,
    ) -> Result<T, Error> {
        // An absent read linearizes here without inventing an empty source stream.
        if !allow_create
            && !self
                .state
                .lock()
                .map_err(|_| Error::Unavailable)?
                .contains_key(tenant)
        {
            return Err(Error::NotFound);
        }
        self.outbox
            .with_webhook_authority(tenant, |reader| {
                let mut guard = self.state.lock().map_err(|_| Error::Unavailable)?;
                if !guard.contains_key(tenant) && !allow_create {
                    return Err(Error::NotFound);
                }
                if !guard.contains_key(tenant) && guard.len() >= self.config.max_endpoints {
                    return Err(Error::Capacity);
                }
                let mut current = guard.get(tenant).cloned().unwrap_or_default();
                let now = current.advance_floor(self.now())?;
                current.validate(tenant, &self.config)?;
                if guard.contains_key(tenant) {
                    guard.insert(tenant.clone(), current.clone());
                }
                let after = current
                    .endpoint
                    .as_ref()
                    .map(WebhookEndpointSnapshot::cursor);
                let source = reader.read(after, now).map_err(|_| Error::Unavailable)?;
                let mut changed = current;
                let result = f(&mut changed, &source, now)?;
                changed.validate(tenant, &self.config)?;
                guard.insert(tenant.clone(), changed);
                Ok(result)
            })
            .map_err(|_| Error::Unavailable)?
    }
    fn keys(&self, cursor: &WebhookDeliveryCursor, limit: usize) -> Result<Vec<TenantId>, Error> {
        cursor.validate()?;
        if !(1..=MAX_WEBHOOK_EXAMINED).contains(&limit) {
            return Err(Error::InvalidConfiguration);
        }
        let state = self.state.lock().map_err(|_| Error::Unavailable)?;
        let after = cursor.after.as_ref().map_or(Unbounded, Excluded);
        Ok(state
            .range((after, Unbounded))
            .take(limit)
            .map(|(k, _)| k.clone())
            .collect())
    }
    fn mutate(
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
    }
}
#[async_trait]
impl WebhookStore for MemoryWebhookStore {
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
    }
    async fn get_endpoint(
        &self,
        tenant: &TenantId,
    ) -> Result<Option<WebhookEndpointSnapshot>, Error> {
        match self.apply(tenant, false, |state, source, _| {
            Ok(state.observed_endpoint(source))
        }) {
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
        let keys = self.keys(&cursor, limit)?;
        let mut attempts = Vec::new();
        let mut examined = 0;
        for tenant in &keys {
            if attempts.len() == max_attempts {
                break;
            }
            examined += 1;
            let lease = match self.apply(tenant, false, |state, source, now| {
                state.claim(source, now, lease_ttl, &self.config)
            }) {
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
    }
    async fn maintain(
        &self,
        cursor: WebhookDeliveryCursor,
        limit: usize,
    ) -> Result<WebhookMaintenancePage, Error> {
        let keys = self.keys(&cursor, limit)?;
        let mut reclaimed = 0;
        for tenant in &keys {
            reclaimed += self.apply(tenant, false, |state, _, now| state.prune(now))?;
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
