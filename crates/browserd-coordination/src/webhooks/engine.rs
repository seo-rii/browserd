use super::*;
use crate::event_outbox::WebhookOutboxSource;
use chrono::Duration as Delta;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TenantState {
    pub schema_version: u8,
    pub floor: DateTime<Utc>,
    pub endpoint: Option<WebhookEndpointSnapshot>,
    pub(super) pending: Option<Pending>,
    mutations: Vec<MutationReceipt>,
    audits: Vec<Audit>,
    acknowledged: Vec<Acknowledged>,
}
impl Default for TenantState {
    fn default() -> Self {
        Self {
            schema_version: 1,
            floor: DateTime::<Utc>::UNIX_EPOCH,
            endpoint: None,
            pending: None,
            mutations: Vec::new(),
            audits: Vec::new(),
            acknowledged: Vec::new(),
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Pending {
    event_id: Uuid,
    event_sequence: u64,
    delivery_id: Uuid,
    payload: WebhookEventBody,
    generation: u64,
    next_attempt_at: DateTime<Utc>,
    lease: Option<WebhookAttemptLease>,
    last_finished: Option<(WebhookAttemptLease, WebhookAttemptResult)>,
    audit_reserved: usize,
}
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) enum Mutation {
    Put {
        expected_revision: Option<u64>,
        endpoint_url: String,
    },
    Delete {
        expected: WebhookEndpointRef,
    },
    Suspend {
        expected: WebhookEndpointRef,
    },
    Resume {
        expected: WebhookEndpointRef,
        mode: WebhookResumeMode,
    },
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MutationReceipt {
    binding: WebhookMutationBinding,
    mutation: Mutation,
    response: WebhookEndpointSnapshot,
    created_at: DateTime<Utc>,
}
#[derive(Clone, Copy, Serialize, Deserialize)]
enum AuditKind {
    Registered,
    Changed,
    Deleted,
    Suspended,
    Resumed,
    GapAcknowledged,
    AttemptFinished,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Audit {
    kind: AuditKind,
    endpoint: WebhookEndpointRef,
    principal: Option<PrincipalId>,
    attempt_id: Option<Uuid>,
    created_at: DateTime<Utc>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Acknowledged {
    pub attempt_id: Uuid,
    pub lease_sha256: [u8; 32],
    pub body_sha256: [u8; 32],
    pub body_len: usize,
    pub result: WebhookAttemptResult,
    #[serde(skip)]
    pub payload: Option<WebhookEventBody>,
}
fn lease_digest(lease: &WebhookAttemptLease) -> Result<[u8; 32], Error> {
    let encoded = serde_json::to_vec(lease).map_err(|_| Error::InvalidPayload)?;
    Ok(Sha256::digest(encoded).into())
}

pub(super) fn checked_time(now: DateTime<Utc>) -> Result<(), Error> {
    if now.timestamp_millis() < 0 {
        Err(Error::Unavailable)
    } else {
        Ok(())
    }
}
pub(super) fn after(now: DateTime<Utc>, duration: Duration) -> Result<DateTime<Utc>, Error> {
    now.checked_add_signed(Delta::from_std(duration).map_err(|_| Error::InvalidConfiguration)?)
        .ok_or(Error::Unavailable)
}
pub(super) fn lease_ttl(ttl: Duration) -> Result<(), Error> {
    if ttl < Duration::from_secs(1) || ttl > Duration::from_secs(30) {
        Err(Error::InvalidConfiguration)
    } else {
        Ok(())
    }
}
pub(super) fn scan_bounds(
    cursor: &WebhookDeliveryCursor,
    limit: usize,
    max_attempts: usize,
) -> Result<(), Error> {
    cursor.validate()?;
    if !(1..=MAX_WEBHOOK_EXAMINED).contains(&limit)
        || !(1..=MAX_WEBHOOK_IN_FLIGHT).contains(&max_attempts)
    {
        Err(Error::InvalidConfiguration)
    } else {
        Ok(())
    }
}
impl TenantState {
    pub fn advance_floor(&mut self, now: DateTime<Utc>) -> Result<DateTime<Utc>, Error> {
        checked_time(now)?;
        self.floor = self.floor.max(now);
        Ok(self.floor)
    }
    pub fn validate(&self, tenant: &TenantId, config: &WebhookStoreConfig) -> Result<(), Error> {
        if self.schema_version != 1
            || self.floor.timestamp_millis() < 0
            || self.mutations.len() > config.max_mutations_per_tenant
            || self.audits.len() + self.reserved() > config.max_audit_rows_per_tenant
            || self.acknowledged.len() > config.max_acknowledged_per_tenant
            || self.payload_bytes() > config.max_payload_bytes_per_tenant
        {
            return Err(Error::Unavailable);
        }
        if let Some(endpoint) = &self.endpoint {
            endpoint.validate()?;
            if endpoint.endpoint_ref.tenant_id() != tenant {
                return Err(Error::Unavailable);
            }
        }
        if let Some(pending) = &self.pending {
            pending.payload.validate()?;
            let endpoint = self.endpoint.as_ref().ok_or(Error::Unavailable)?;
            if pending.event_sequence <= endpoint.cursor_position
                || pending.generation == 0 && pending.lease.is_some()
                || pending.audit_reserved > 2
            {
                return Err(Error::Unavailable);
            }
            if let Some(lease) = &pending.lease {
                lease.validate()?;
                if lease.endpoint_ref != endpoint.endpoint_ref
                    || lease.payload != pending.payload
                    || lease.event_id != pending.event_id
                    || lease.event_sequence != pending.event_sequence
                    || lease.delivery_id != pending.delivery_id
                    || lease.generation != pending.generation
                    || pending.audit_reserved != 2
                {
                    return Err(Error::Unavailable);
                }
            }
        }
        for record in &self.mutations {
            record.binding.validate()?;
            record.response.validate()?;
            if record.binding.tenant_id != *tenant
                || record.response.endpoint_ref.tenant_id != *tenant
            {
                return Err(Error::Unavailable);
            }
        }
        for record in &self.acknowledged {
            record.result.outcome.validate()?;
            record.result.endpoint.validate()?;
            if record.result.endpoint.endpoint_ref.tenant_id != *tenant
                || record.result.attempt_id != record.attempt_id
                || record.body_len == 0
                || record.body_len > MAX_WEBHOOK_BODY_BYTES
                || !nonzero(&record.lease_sha256)
                || !nonzero(&record.body_sha256)
            {
                return Err(Error::Unavailable);
            }
            if let Some(body) = &record.payload {
                body.validate()?;
                if body.bytes.len() != record.body_len || body.sha256 != record.body_sha256 {
                    return Err(Error::Unavailable);
                }
            }
        }
        Ok(())
    }
    fn reserved(&self) -> usize {
        self.pending.as_ref().map_or(0, |p| p.audit_reserved)
    }
    fn payload_bytes(&self) -> usize {
        self.pending
            .as_ref()
            .map_or(0, |p| p.payload.bytes.len() * 3)
            + self.acknowledged.iter().map(|a| a.body_len).sum::<usize>()
    }
    pub(super) fn archives(&self) -> impl Iterator<Item = &Acknowledged> {
        self.acknowledged.iter()
    }
    pub fn prune(&mut self, now: DateTime<Utc>) -> Result<usize, Error> {
        let retention = Delta::from_std(WEBHOOK_ACK_RETENTION).map_err(|_| Error::Unavailable)?;
        let Some(cutoff) = now.checked_sub_signed(retention) else {
            return Ok(0);
        };
        let before = self.mutations.len() + self.audits.len() + self.acknowledged.len();
        self.mutations.retain(|m| m.created_at > cutoff);
        self.audits.retain(|a| a.created_at > cutoff);
        self.acknowledged.retain(|a| a.result.finished_at > cutoff);
        Ok(before - self.mutations.len() - self.audits.len() - self.acknowledged.len())
    }
    fn room(&self, config: &WebhookStoreConfig, new_audits: usize) -> Result<(), Error> {
        if self
            .audits
            .len()
            .checked_add(self.reserved())
            .and_then(|v| v.checked_add(new_audits))
            .is_none_or(|v| v > config.max_audit_rows_per_tenant)
        {
            Err(Error::AuditCapacity)
        } else {
            Ok(())
        }
    }
    fn audit(
        &mut self,
        kind: AuditKind,
        principal: Option<PrincipalId>,
        attempt_id: Option<Uuid>,
        now: DateTime<Utc>,
    ) -> Result<(), Error> {
        let endpoint = self
            .endpoint
            .as_ref()
            .ok_or(Error::NotFound)?
            .endpoint_ref
            .clone();
        self.audits.push(Audit {
            kind,
            endpoint,
            principal,
            attempt_id,
            created_at: now,
        });
        Ok(())
    }
    pub fn observed_endpoint(
        &self,
        source: &WebhookOutboxSource,
    ) -> Option<WebhookEndpointSnapshot> {
        self.endpoint.clone().map(|mut e| {
            if e.suspension_reason == Some(WebhookSuspensionReason::EventGap) {
                e.gap_observation = Some(WebhookGapObservation {
                    pruned_through: source.pruned_through.position(),
                    tail: source.tail.position(),
                });
            }
            e
        })
    }
    fn duplicate(
        &self,
        binding: &WebhookMutationBinding,
        mutation: &Mutation,
    ) -> Result<Option<WebhookEndpointSnapshot>, Error> {
        if let Some(receipt) = self
            .mutations
            .iter()
            .find(|r| r.binding.idempotency_key == binding.idempotency_key)
        {
            if receipt.binding == *binding && receipt.mutation == *mutation {
                Ok(Some(receipt.response.clone()))
            } else {
                Err(Error::IdempotencyConflict)
            }
        } else {
            Ok(None)
        }
    }
    pub(super) fn mutation(
        &mut self,
        binding: &WebhookMutationBinding,
        mutation: Mutation,
        spec: Option<&WebhookEndpointSpec>,
        source: &WebhookOutboxSource,
        now: DateTime<Utc>,
        config: &WebhookStoreConfig,
    ) -> Result<WebhookEndpointSnapshot, Error> {
        self.prune(now)?;
        binding.validate()?;
        if let Some(reply) = self.duplicate(binding, &mutation)? {
            return Ok(reply);
        }
        if self.mutations.len() >= config.max_mutations_per_tenant {
            return Err(Error::Capacity);
        }
        self.room(config, 1)?;
        let kind = match &mutation {
            Mutation::Put {
                expected_revision, ..
            } => {
                let spec = spec.ok_or(Error::InvalidMutation)?;
                spec.validate()?;
                match self.endpoint.as_mut() {
                    Some(endpoint) => {
                        if *expected_revision != Some(endpoint.endpoint_ref.revision) {
                            return Err(Error::Conflict);
                        }
                        endpoint.endpoint_ref.revision = endpoint
                            .endpoint_ref
                            .revision
                            .checked_add(1)
                            .ok_or(Error::Capacity)?;
                        endpoint.spec = spec.clone();
                        endpoint.status = WebhookEndpointStatus::Active;
                        endpoint.updated_at = now;
                        endpoint.failure_count = 0;
                        endpoint.suspension_reason = None;
                        endpoint.gap_observation = None;
                        AuditKind::Changed
                    }
                    None => {
                        if expected_revision.is_some() {
                            return Err(Error::Conflict);
                        }
                        self.endpoint = Some(WebhookEndpointSnapshot {
                            endpoint_ref: WebhookEndpointRef::new(
                                binding.tenant_id.clone(),
                                Uuid::now_v7(),
                                1,
                            )?,
                            spec: spec.clone(),
                            status: WebhookEndpointStatus::Active,
                            cursor_position: source.tail.position(),
                            failure_count: 0,
                            created_at: now,
                            updated_at: now,
                            suspension_reason: None,
                            gap_observation: None,
                        });
                        AuditKind::Registered
                    }
                }
            }
            Mutation::Delete { expected }
            | Mutation::Suspend { expected }
            | Mutation::Resume { expected, .. } => {
                expected.validate()?;
                if expected.tenant_id != binding.tenant_id {
                    return Err(Error::InvalidMutation);
                }
                let endpoint = self.endpoint.as_mut().ok_or(Error::NotFound)?;
                if endpoint.endpoint_ref != *expected {
                    return Err(Error::Conflict);
                }
                endpoint.endpoint_ref.revision = endpoint
                    .endpoint_ref
                    .revision
                    .checked_add(1)
                    .ok_or(Error::Capacity)?;
                endpoint.updated_at = now;
                match &mutation {
                    Mutation::Delete { .. } => {
                        endpoint.status = WebhookEndpointStatus::Deleted;
                        endpoint.suspension_reason = None;
                        endpoint.gap_observation = None;
                        AuditKind::Deleted
                    }
                    Mutation::Suspend { .. } => {
                        endpoint.status = WebhookEndpointStatus::Suspended;
                        endpoint.suspension_reason = Some(WebhookSuspensionReason::Operator);
                        endpoint.gap_observation = None;
                        AuditKind::Suspended
                    }
                    Mutation::Resume { mode, .. } => {
                        if endpoint.status != WebhookEndpointStatus::Suspended {
                            return Err(Error::Conflict);
                        }
                        let is_gap = endpoint.cursor_position < source.pruned_through.position()
                            && self.pending.is_none();
                        let kind = match mode {
                            WebhookResumeMode::Continue => {
                                if is_gap {
                                    return Err(Error::Gap);
                                }
                                AuditKind::Resumed
                            }
                            WebhookResumeMode::AcceptGapToTail {
                                expected_pruned_through,
                                expected_tail,
                            } => {
                                if !is_gap
                                    || self.pending.is_some()
                                    || *expected_pruned_through != source.pruned_through.position()
                                    || *expected_tail != source.tail.position()
                                {
                                    return Err(Error::Conflict);
                                }
                                endpoint.cursor_position = *expected_tail;
                                AuditKind::GapAcknowledged
                            }
                        };
                        endpoint.status = WebhookEndpointStatus::Active;
                        endpoint.suspension_reason = None;
                        endpoint.gap_observation = None;
                        endpoint.failure_count = 0;
                        kind
                    }
                    Mutation::Put { .. } => return Err(Error::InvalidMutation),
                }
            }
        };
        // Configuration changes invalidate all old leases; the pending delivery stays charged.
        if let Some(p) = &mut self.pending {
            p.lease = None;
            p.last_finished = None;
            p.audit_reserved = 0;
            p.next_attempt_at = now;
        }
        self.audit(kind, Some(binding.principal_id.clone()), None, now)?;
        let response = self.endpoint.clone().ok_or(Error::Unavailable)?;
        self.mutations.push(MutationReceipt {
            binding: binding.clone(),
            mutation,
            response: response.clone(),
            created_at: now,
        });
        Ok(response)
    }
    pub fn claim(
        &mut self,
        source: &WebhookOutboxSource,
        now: DateTime<Utc>,
        ttl: Duration,
        config: &WebhookStoreConfig,
    ) -> Result<Option<WebhookAttemptLease>, Error> {
        self.prune(now)?;
        lease_ttl(ttl)?;
        let Some(endpoint) = self.endpoint.as_ref() else {
            return Ok(None);
        };
        if endpoint.status != WebhookEndpointStatus::Active {
            return Ok(None);
        }
        if self.pending.is_none() {
            if endpoint.cursor_position < source.pruned_through.position() {
                self.room(config, 1)?;
                let e = self.endpoint.as_mut().ok_or(Error::Unavailable)?;
                e.endpoint_ref.revision = e
                    .endpoint_ref
                    .revision
                    .checked_add(1)
                    .ok_or(Error::Capacity)?;
                e.status = WebhookEndpointStatus::Suspended;
                e.suspension_reason = Some(WebhookSuspensionReason::EventGap);
                e.gap_observation = Some(WebhookGapObservation {
                    pruned_through: source.pruned_through.position(),
                    tail: source.tail.position(),
                });
                e.updated_at = now;
                self.audit(AuditKind::Suspended, None, None, now)?;
                return Ok(None);
            }
            let Some(event) = &source.next_event else {
                return Ok(None);
            };
            if event.tenant_id() != endpoint.endpoint_ref.tenant_id() {
                return Err(Error::Unavailable);
            }
            if event.cursor().position() <= endpoint.cursor_position {
                return Err(Error::Unavailable);
            }
            let body = encode_webhook_event(event)?;
            if self.acknowledged.len() >= config.max_acknowledged_per_tenant
                || self
                    .payload_bytes()
                    .checked_add(body.bytes.len() * 3)
                    .is_none_or(|v| v > config.max_payload_bytes_per_tenant)
            {
                return Err(Error::Capacity);
            }
            self.pending = Some(Pending {
                event_id: event.event_id(),
                event_sequence: event.cursor().position(),
                delivery_id: Uuid::now_v7(),
                payload: body,
                generation: 0,
                next_attempt_at: now,
                lease: None,
                last_finished: None,
                audit_reserved: 0,
            });
        }
        let p = self.pending.as_ref().ok_or(Error::Unavailable)?;
        if p.next_attempt_at > now || p.lease.as_ref().is_some_and(|l| l.expires_at > now) {
            return Ok(None);
        }
        if p.audit_reserved == 0 {
            self.room(config, 2)?
        }
        let p = self.pending.as_mut().ok_or(Error::Unavailable)?;
        p.generation = p.generation.checked_add(1).ok_or(Error::Capacity)?;
        let endpoint = self.endpoint.as_ref().ok_or(Error::Unavailable)?;
        let lease = WebhookAttemptLease {
            endpoint_ref: endpoint.endpoint_ref.clone(),
            spec: endpoint.spec.clone(),
            event_id: p.event_id,
            event_sequence: p.event_sequence,
            delivery_id: p.delivery_id,
            attempt_id: Uuid::now_v7(),
            lease_token: Uuid::new_v4(),
            generation: p.generation,
            expires_at: after(now, ttl)?,
            send_timestamp_seconds: now.timestamp(),
            payload: p.payload.clone(),
        };
        lease.validate()?;
        p.lease = Some(lease.clone());
        p.last_finished = None;
        p.audit_reserved = 2;
        Ok(Some(lease))
    }
    pub fn finish(
        &mut self,
        lease: &WebhookAttemptLease,
        outcome: WebhookAttemptOutcome,
        now: DateTime<Utc>,
        config: &WebhookStoreConfig,
    ) -> Result<WebhookAttemptResult, Error> {
        self.prune(now)?;
        lease.validate()?;
        outcome.validate()?;
        if let Some(ack) = self
            .acknowledged
            .iter()
            .find(|a| a.attempt_id == lease.attempt_id)
        {
            if ack.lease_sha256 == lease_digest(lease)? && ack.result.outcome == outcome {
                return Ok(ack.result.clone());
            }
            return Err(Error::LeaseMismatch);
        }
        let p = self.pending.as_ref().ok_or(Error::LeaseMismatch)?;
        if let Some((old, result)) = &p.last_finished
            && old == lease
            && result.outcome == outcome
        {
            return Ok(result.clone());
        }
        if p.lease.as_ref() != Some(lease)
            || self
                .endpoint
                .as_ref()
                .is_none_or(|e| e.endpoint_ref != lease.endpoint_ref)
            || p.audit_reserved != 2
        {
            return Err(Error::LeaseMismatch);
        }
        // Expiry permits another delivery, but only the latest exact persisted lease may ACK.
        let p = self.pending.as_mut().ok_or(Error::Unavailable)?;
        p.audit_reserved = 0;
        p.lease = None;
        let endpoint = self.endpoint.as_mut().ok_or(Error::Unavailable)?;
        endpoint.updated_at = now;
        let delivered = matches!(outcome, WebhookAttemptOutcome::Delivered { .. });
        if delivered {
            endpoint.cursor_position = lease.event_sequence;
            endpoint.failure_count = 0;
        } else {
            endpoint.failure_count = endpoint
                .failure_count
                .checked_add(1)
                .ok_or(Error::Capacity)?;
            p.next_attempt_at = after(
                now,
                Duration::from_secs((1u64 << endpoint.failure_count.min(10)).min(900)),
            )?;
        }
        let suspend = !delivered
            && (matches!(outcome, WebhookAttemptOutcome::PermanentFailure { .. })
                || endpoint.failure_count >= config.failures_before_suspend);
        if suspend {
            endpoint.status = WebhookEndpointStatus::Suspended;
            endpoint.suspension_reason = Some(WebhookSuspensionReason::ConsecutiveFailures);
            endpoint.endpoint_ref.revision = endpoint
                .endpoint_ref
                .revision
                .checked_add(1)
                .ok_or(Error::Capacity)?;
        }
        self.audit(
            AuditKind::AttemptFinished,
            None,
            Some(lease.attempt_id),
            now,
        )?;
        if suspend {
            self.audit(AuditKind::Suspended, None, Some(lease.attempt_id), now)?
        }
        let result = WebhookAttemptResult {
            attempt_id: lease.attempt_id,
            outcome,
            endpoint: self.endpoint.clone().ok_or(Error::Unavailable)?,
            finished_at: now,
        };
        if delivered {
            if self.acknowledged.len() >= config.max_acknowledged_per_tenant {
                return Err(Error::Capacity);
            }
            self.acknowledged.push(Acknowledged {
                attempt_id: lease.attempt_id,
                lease_sha256: lease_digest(lease)?,
                body_sha256: lease.payload.sha256,
                body_len: lease.payload.bytes.len(),
                result: result.clone(),
                payload: Some(lease.payload.clone()),
            });
            self.pending = None;
        } else {
            self.pending
                .as_mut()
                .ok_or(Error::Unavailable)?
                .last_finished = Some((lease.clone(), result.clone()));
        }
        Ok(result)
    }
}
