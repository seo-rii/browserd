//! Durable fleet admission lives beside action evidence in the same standalone Redis provider.
//! Rows remain individual bounded values; a namespace revision linearizes bounded read plans.
use std::collections::BTreeMap;

use browserd_core::{LeaseId, WorkerId};
use serde::de::DeserializeOwned;

use super::*;
use crate::{DirectoryKey, DispatchLeaseToken, WorkerCapacity, WorkerReadiness};

mod transaction;
use transaction::{FleetTotals, FleetTransaction, TenantTotals, WorkerRow};

fn worker_candidate(row: &WorkerRow) -> FleetWorkerCandidate<'_> {
    let [memory, cpu, pids, disk, contexts, targets] = row.shadow;
    FleetWorkerCandidate {
        observation: &row.observation,
        expires_at_millis: row.expires,
        shadow: WorkerCapacity::new(memory, cpu, pids, disk, contexts, targets),
    }
}

pub(super) const FLEET_ACTION_SCRIPT: &str = r#"
local function fleet_action_gate(reference, placement, require_live)
  local managed = redis.call('HGET', KEYS[7], 'fleet_digest')
  if not managed then return reference == '' and 0 or 17 end
  if not reference or reference == '' then return 16 end
  if not require_live then return 0 end
  if redis.call('TYPE', KEYS[13])['ok'] ~= 'hash' or redis.call('PTTL', KEYS[13]) ~= -1 then return 17 end
  if redis.call('HGET', KEYS[13], 'reference') ~= reference or redis.call('HGET', KEYS[13], 'placement') ~= placement or redis.call('HGET', KEYS[13], 'status') ~= 'ready' then return 17 end
  if redis.call('TYPE', KEYS[14])['ok'] ~= 'hash' or redis.call('PTTL', KEYS[14]) ~= -1 then return 17 end
  local worker_field = redis.call('HGET', KEYS[13], 'worker_field')
  local worker_identity = redis.call('HGET', KEYS[13], 'worker_identity')
  if not worker_field or not worker_identity or redis.call('HGET', KEYS[14], worker_field) ~= worker_identity then return 17 end
  local expires = tonumber(redis.call('HGET', KEYS[13], 'expires'))
  local now = recovery_now()
  if not now or not expires or expires > 9007199254740991 or expires <= now then return 17 end
  return 0
end
"#;

impl RedisGatewayActionStore {
    pub(super) fn fleet_state_key(&self) -> String {
        format!("{}:fleet:v1:state", self.config.key_prefix)
    }
    fn fleet_index(&self, name: &str) -> String {
        format!("{}:fleet:v1:{name}", self.config.key_prefix)
    }
    pub(super) fn fleet_authority_key(&self, tenant: &TenantId, session: &SessionId) -> String {
        self.fleet_index(&format!("authority:{tenant}:{session}"))
    }
    pub(super) fn fleet_config(
        &self,
    ) -> Result<&GatewayFleetAdmissionConfig, GatewayActionCoordinationError> {
        self.config
            .fleet_admission
            .as_ref()
            .ok_or(GatewayActionCoordinationError::UnsupportedSessionAdmission)
    }
    pub(super) fn action_authority_argument(
        &self,
        authority: Option<&GatewaySessionAuthorityRef>,
    ) -> Result<String, GatewayActionCoordinationError> {
        match authority {
            Some(value) => {
                self.fleet_config()?;
                encode(value)
            }
            None => Ok(String::new()),
        }
    }
    pub(super) async fn require_legacy_admission(
        &self,
    ) -> Result<(), GatewayActionCoordinationError> {
        let marker = self.recovery_format_key();
        let managed: bool = self
            .execute(move |mut connection| async move {
                redis::cmd("HEXISTS")
                    .arg(marker)
                    .arg("fleet_digest")
                    .query_async(&mut connection)
                    .await
            })
            .await?;
        if managed {
            Err(GatewayActionCoordinationError::ManagedActionAdmissionRequired)
        } else {
            Ok(())
        }
    }
    pub(super) async fn initialize_fleet(&self) -> Result<(), GatewayActionCoordinationError> {
        let Some(config) = self.config.fleet_admission.as_ref() else {
            return Ok(());
        };
        let config_raw = encode(config)?;
        let digest = encode(&config.digest())?;
        let totals = encode(&FleetTotals::default())?;
        let marker = self.recovery_format_key();
        let state = self.fleet_state_key();
        let response:String=self.execute(move |mut connection| async move {
            Script::new(r#"
if redis.call('TYPE', KEYS[1])['ok'] ~= 'hash' or redis.call('PTTL', KEYS[1]) ~= -1 or redis.call('HGET', KEYS[1], 'version') ~= '5' or redis.call('HGET', KEYS[1], 'state') ~= 'ready' then return 'invalid' end
local digest=redis.call('HGET', KEYS[1], 'fleet_digest')
local kind=redis.call('TYPE', KEYS[2])['ok']
if digest then
  if digest ~= ARGV[1] then return 'conflict' end
  if kind ~= 'hash' or redis.call('PTTL', KEYS[2]) ~= -1 or redis.call('HGET', KEYS[2], 'config') ~= ARGV[2] or not redis.call('HGET', KEYS[2], 'revision') or not redis.call('HGET', KEYS[2], 'totals') then return 'invalid' end
else
  if kind ~= 'none' then return 'invalid' end
  redis.call('HSET', KEYS[2], 'config', ARGV[2], 'revision', '0', 'totals', ARGV[3])
  redis.call('HSET', KEYS[1], 'fleet_digest', ARGV[1])
end
return 'ok'
"#).key(marker).key(state).arg(digest).arg(config_raw).arg(totals).invoke_async(&mut connection).await
        }).await?;
        match response.as_str() {
            "ok" => Ok(()),
            "conflict" => Err(GatewayActionCoordinationError::AdmissionConflict),
            _ => Err(GatewayActionCoordinationError::InvalidRedisResponse),
        }
    }
}

fn encode<T: Serialize + ?Sized>(value: &T) -> Result<String, GatewayActionCoordinationError> {
    serde_json::to_string(value).map_err(|_| GatewayActionCoordinationError::InvalidRedisResponse)
}
fn decode<T: DeserializeOwned>(raw: &str) -> Result<T, GatewayActionCoordinationError> {
    serde_json::from_str(raw).map_err(|_| GatewayActionCoordinationError::InvalidRedisResponse)
}
fn admission_field(key: &GatewaySessionAdmissionKey) -> String {
    format!("admission:{}|{}", key.tenant_id(), key.operation_id())
}
fn admission_member(key: &GatewaySessionAdmissionKey) -> String {
    format!("{}|{}", key.tenant_id(), key.operation_id())
}
fn tenant_field(tenant: &TenantId) -> String {
    format!("tenant:{tenant}")
}
fn worker_field(worker: &WorkerId) -> String {
    format!("worker:{worker}")
}
fn worker_identity_field(worker: &WorkerId) -> String {
    format!("identity:{worker}")
}
fn authority_field(key: &DirectoryKey) -> String {
    format!("authority:{}|{}", key.tenant_id(), key.session_id())
}
fn increment(value: u64) -> Result<u64, GatewayActionCoordinationError> {
    value
        .checked_add(1)
        .ok_or(GatewayActionCoordinationError::AdmissionCapacity)
}
fn ttl_millis(ttl: Duration) -> Result<u64, GatewayActionCoordinationError> {
    let millis = u64::try_from(ttl.as_millis())
        .map_err(|_| GatewayActionCoordinationError::InvalidSessionAdmission)?;
    if millis == 0 || millis > 300_000 {
        return Err(GatewayActionCoordinationError::InvalidSessionAdmission);
    }
    Ok(millis)
}
fn checked_add(a: [u64; 6], b: [u64; 6]) -> Result<[u64; 6], GatewayActionCoordinationError> {
    let mut next = [0; 6];
    for i in 0..6 {
        next[i] = a[i]
            .checked_add(b[i])
            .ok_or(GatewayActionCoordinationError::AdmissionCapacity)?;
    }
    Ok(next)
}
fn checked_sub(a: [u64; 6], b: [u64; 6]) -> Result<[u64; 6], GatewayActionCoordinationError> {
    let mut next = [0; 6];
    for i in 0..6 {
        next[i] = a[i]
            .checked_sub(b[i])
            .ok_or(GatewayActionCoordinationError::InvalidRedisResponse)?;
    }
    Ok(next)
}
fn fits(used: [u64; 6], limit: [u64; 6]) -> bool {
    used.iter().zip(limit).all(|(a, b)| *a <= b)
}

macro_rules! fleet_retry {
    ($store:expr, $body:block) => {{
        let deadline=tokio::time::Instant::now()+$store.config.command_timeout;
        for _ in 0..MAX_CAS_ATTEMPTS {
            let result=tokio::time::timeout_at(deadline,async $body).await.map_err(|_|GatewayActionCoordinationError::RedisTimedOut)?;
            match result { Err(GatewayActionCoordinationError::AdmissionRevisionMismatch)=>{}, result=>return result }
        }
        Err(GatewayActionCoordinationError::AdmissionRevisionMismatch)
    }};
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlacementRow {
    authority: GatewaySessionPlacementAuthority,
    admission: GatewaySessionAdmissionKey,
}
fn shadow_field(key: &GatewaySessionAdmissionKey) -> String {
    format!("shadow:{}", admission_member(key))
}
fn shadow_index(worker: &GatewayFleetWorkerIdentity) -> String {
    format!(
        "shadow:{}:{}:{}",
        worker.worker_id(),
        worker.worker_epoch(),
        worker.boot_id()
    )
}
fn shadow_member(res: &GatewaySessionReservation) -> Option<String> {
    res.worker_debit_sequence()
        .map(|seq| format!("{seq:020}|{}", admission_member(res.key())))
}
fn confirmed_debit_field(res: &GatewaySessionReservation) -> Option<String> {
    res.worker_debit_sequence().map(|sequence| {
        format!(
            "confirmed:{}:{}:{}:{sequence}",
            res.worker().worker_id(),
            res.worker().worker_epoch(),
            res.worker().boot_id(),
        )
    })
}
fn queue_index(tenant: &TenantId) -> String {
    format!("queue:{tenant}")
}
fn queue_member(row: &GatewaySessionAdmissionSnapshot) -> String {
    format!(
        "{:020}|{}",
        row.queue_sequence(),
        row.request().key().operation_id()
    )
}
fn expiry_member(res: &GatewaySessionReservation) -> String {
    format!(
        "{:020}|{}",
        res.provider_deadline_millis(),
        admission_member(res.key())
    )
}
fn parse_admission_member(
    member: &str,
) -> Result<GatewaySessionAdmissionKey, GatewayActionCoordinationError> {
    let (tenant, op) = member
        .split_once('|')
        .ok_or(GatewayActionCoordinationError::InvalidRedisResponse)?;
    let key = GatewaySessionAdmissionKey::new(
        tenant
            .parse()
            .map_err(|_| GatewayActionCoordinationError::InvalidRedisResponse)?,
        op.parse()
            .map_err(|_| GatewayActionCoordinationError::InvalidRedisResponse)?,
    );
    if admission_member(&key) != member {
        return Err(GatewayActionCoordinationError::InvalidRedisResponse);
    }
    Ok(key)
}
fn required<T>(value: Option<T>) -> Result<T, GatewayActionCoordinationError> {
    value.ok_or(GatewayActionCoordinationError::InvalidRedisResponse)
}
fn subtract(value: u64) -> Result<u64, GatewayActionCoordinationError> {
    value
        .checked_sub(1)
        .ok_or(GatewayActionCoordinationError::InvalidRedisResponse)
}

impl FleetTransaction<'_> {
    async fn admission(
        &mut self,
        key: &GatewaySessionAdmissionKey,
    ) -> Result<Option<GatewaySessionAdmissionSnapshot>, GatewayActionCoordinationError> {
        let field = admission_field(key);
        self.read_rows(std::slice::from_ref(&field), false).await?;
        let value: Option<GatewaySessionAdmissionSnapshot> = self.row(&field)?;
        if value.as_ref().is_some_and(|r| r.request().key() != key) {
            return Err(GatewayActionCoordinationError::InvalidRedisResponse);
        }
        Ok(value)
    }
    async fn placement(
        &mut self,
        key: &DirectoryKey,
    ) -> Result<Option<PlacementRow>, GatewayActionCoordinationError> {
        let field = authority_field(key);
        self.read_rows(std::slice::from_ref(&field), false).await?;
        let value: Option<PlacementRow> = self.row(&field)?;
        if value.as_ref().is_some_and(|r| {
            r.authority.entry().key() != key || r.authority.admission_key() != &r.admission
        }) {
            return Err(GatewayActionCoordinationError::InvalidRedisResponse);
        }
        Ok(value)
    }
    async fn clear_shadow(
        &mut self,
        res: &GatewaySessionReservation,
    ) -> Result<(), GatewayActionCoordinationError> {
        let field = shadow_field(res.key());
        let worker = worker_field(res.worker().worker_id());
        let confirmed = confirmed_debit_field(res);
        let mut fields = vec![field.clone(), worker.clone()];
        if let Some(confirmed) = &confirmed {
            fields.push(confirmed.clone());
        }
        self.read_rows(&fields, false).await?;
        if let Some(confirmed) = confirmed {
            let bound: GatewaySessionReservation = required(self.row(&confirmed)?)?;
            if bound != *res {
                return Err(GatewayActionCoordinationError::InvalidRedisResponse);
            }
            // Positive cleanup or unexposed expiry ends this live binding, even if
            // an observation already retired its shadow charge.
            self.remove(confirmed);
        }
        let Some(shadow) = self.row::<GatewaySessionReservation>(&field)? else {
            return Ok(());
        };
        if !shadow.same_basis(res) {
            return Err(GatewayActionCoordinationError::InvalidRedisResponse);
        }
        let mut row: WorkerRow = required(self.row(&worker)?)?;
        if row.observation.identity() == res.worker() {
            row.shadow = checked_sub(row.shadow, res.resources().components())?;
            self.put(worker, &row)?;
        }
        if let Some(member) = shadow_member(&shadow) {
            self.index(&shadow_index(shadow.worker()), member, false);
        }
        self.remove(field);
        Ok(())
    }
    async fn expire_reserved(&mut self) -> Result<(), GatewayActionCoordinationError> {
        // Deadline index is exact decimal lexicographic, never a floating ZSET score.
        let due = self.range("reserved", None, 64).await?;
        for member in due {
            let (deadline, key) = member
                .split_once('|')
                .ok_or(GatewayActionCoordinationError::InvalidRedisResponse)?;
            let deadline: u64 = deadline
                .parse()
                .map_err(|_| GatewayActionCoordinationError::InvalidRedisResponse)?;
            if deadline > self.now {
                break;
            }
            let key = parse_admission_member(key)?;
            let mut row = required(self.admission(&key).await?)?;
            let res = required(row.reservation().cloned())?;
            if expiry_member(&res) != member
                || row.state() != GatewaySessionAdmissionState::Reserved
            {
                return Err(GatewayActionCoordinationError::InvalidRedisResponse);
            }
            let tenant = tenant_field(key.tenant_id());
            self.read_rows(std::slice::from_ref(&tenant), false).await?;
            let mut totals: FleetTotals = required(self.row("totals")?)?;
            let mut policy: TenantTotals = required(self.row(&tenant)?)?;
            totals.live = subtract(totals.live)?;
            policy.live = subtract(policy.live)?;
            totals.resources = checked_sub(totals.resources, res.resources().components())?;
            policy.resources = checked_sub(policy.resources, res.resources().components())?;
            self.clear_shadow(&res).await?;
            // Preserve exact old reservation identity after releasing its unexposed charge.
            row = row.expire(self.now)?;
            self.put("totals".into(), &totals)?;
            self.put(tenant, &policy)?;
            self.put(admission_field(&key), &row)?;
            self.index("reserved", member, false);
        }
        Ok(())
    }
}

impl RedisGatewayActionStore {
    pub(super) async fn fleet_enqueue(
        &self,
        request: GatewaySessionAdmissionRequest,
    ) -> Result<GatewaySessionAdmissionSnapshot, GatewayActionCoordinationError> {
        request.validate()?;
        let config = self.fleet_config()?;
        config.profile(&request)?;
        fleet_retry!(self, {
            let mut tx = FleetTransaction::begin(self).await?;
            if let Some(existing) = tx.admission(request.key()).await? {
                return if existing.request() == &request {
                    Ok(existing)
                } else {
                    Err(GatewayActionCoordinationError::AdmissionConflict)
                };
            }
            if millis(request.admission_deadline())? <= tx.now {
                return Err(GatewayActionCoordinationError::AdmissionConflict);
            }
            let tenant = tenant_field(request.key().tenant_id());
            tx.read_rows(std::slice::from_ref(&tenant), false).await?;
            let mut totals: FleetTotals = required(tx.row("totals")?)?;
            let mut count: TenantTotals = tx.row(&tenant)?.unwrap_or_default();
            let limits = config.limits();
            let policy = config.tenant_policy(request.key().tenant_id());
            if totals.records >= limits.namespace_records() as u64
                || totals.queued >= limits.namespace_queued() as u64
                || count.records >= policy.retained_operations() as u64
                || count.queued >= policy.queued_operations() as u64
                || (count.queued == 0 && totals.queued_tenants >= limits.queued_tenants() as u64)
            {
                return Err(GatewayActionCoordinationError::AdmissionCapacity);
            }
            if count.queued == 0 {
                totals.queued_tenants = increment(totals.queued_tenants)?;
                tx.index("tenants", request.key().tenant_id().to_string(), true);
            }
            count.queued = increment(count.queued)?;
            count.records = increment(count.records)?;
            totals.queued = increment(totals.queued)?;
            totals.records = increment(totals.records)?;
            totals.sequence = increment(totals.sequence)?;
            let row = GatewaySessionAdmissionSnapshot::queued(request.clone(), totals.sequence)?;
            tx.put("totals".into(), &totals)?;
            tx.put(tenant, &count)?;
            tx.put(admission_field(request.key()), &row)?;
            tx.index("admissions", admission_member(request.key()), true);
            tx.index(
                &queue_index(request.key().tenant_id()),
                queue_member(&row),
                true,
            );
            tx.deadline = Some(millis(request.admission_deadline())?);
            tx.commit().await?;
            Ok(row)
        })
    }
    pub(super) async fn fleet_get(
        &self,
        key: &GatewaySessionAdmissionKey,
    ) -> Result<Option<GatewaySessionAdmissionSnapshot>, GatewayActionCoordinationError> {
        fleet_retry!(self, {
            let mut tx = FleetTransaction::begin(self).await?;
            tx.admission(key).await
        })
    }
    pub(super) async fn fleet_observe(
        &self,
        observation: GatewayFleetWorkerObservation,
        ttl: Duration,
    ) -> Result<(), GatewayActionCoordinationError> {
        observation.validate_config(self.fleet_config()?)?;
        let ttl = ttl_millis(ttl)?;
        fleet_retry!(self, {
            let mut tx = FleetTransaction::begin(self).await?;
            let field = worker_field(observation.identity().worker_id());
            tx.read_rows(std::slice::from_ref(&field), false).await?;
            let prior: Option<WorkerRow> = tx.row(&field)?;
            let mut shadow = [0; 6];
            if let Some(prior) = &prior {
                let old = &prior.observation;
                if observation.identity().worker_epoch() < old.identity().worker_epoch()
                    || (observation.identity().worker_epoch() == old.identity().worker_epoch()
                        && observation.identity() != old.identity())
                {
                    return Err(GatewayActionCoordinationError::InvalidFleetObservation);
                }
                if observation.identity() == old.identity() {
                    if observation.capacity_revision() < old.capacity_revision()
                        || observation.debit_sequence_watermark() < old.debit_sequence_watermark()
                        || (observation.capacity_revision() == old.capacity_revision()
                            && &observation != old)
                        || (old.readiness() == WorkerReadiness::Draining
                            && observation.readiness() != WorkerReadiness::Draining)
                    {
                        return Err(GatewayActionCoordinationError::InvalidFleetObservation);
                    }
                    shadow = prior.shadow;
                }
            }
            // A bounded prefix of positive acknowledged debit sequences is sufficient;
            // leftover shadows only reduce free capacity, and repeated observations drain them.
            let name = shadow_index(observation.identity());
            for member in tx.range(&name, None, 64).await? {
                let (sequence, key) = member
                    .split_once('|')
                    .ok_or(GatewayActionCoordinationError::InvalidRedisResponse)?;
                let sequence: u64 = sequence
                    .parse()
                    .map_err(|_| GatewayActionCoordinationError::InvalidRedisResponse)?;
                if sequence > observation.debit_sequence_watermark() {
                    break;
                }
                let key = parse_admission_member(key)?;
                let field = shadow_field(&key);
                tx.read_rows(std::slice::from_ref(&field), false).await?;
                let debit: GatewaySessionReservation = required(tx.row(&field)?)?;
                if debit.worker() != observation.identity()
                    || shadow_member(&debit).as_deref() != Some(member.as_str())
                {
                    return Err(GatewayActionCoordinationError::InvalidRedisResponse);
                }
                shadow = checked_sub(shadow, debit.resources().components())?;
                tx.remove(field);
                tx.index(&name, member, false);
            }
            let expires = tx
                .now
                .checked_add(ttl)
                .ok_or(GatewayActionCoordinationError::InvalidSessionAdmission)?;
            tx.put(
                worker_identity_field(observation.identity().worker_id()),
                observation.identity(),
            )?;
            tx.put(
                field,
                &WorkerRow {
                    observation: observation.clone(),
                    expires,
                    shadow,
                },
            )?;
            tx.commit().await?;
            Ok(())
        })
    }
    pub(super) async fn fleet_reserve(
        &self,
        ttl: Duration,
    ) -> Result<Option<GatewaySessionAdmissionSnapshot>, GatewayActionCoordinationError> {
        let ttl = ttl_millis(ttl)?;
        let config = self.fleet_config()?;
        fleet_retry!(self, {
            let mut tx = FleetTransaction::begin(self).await?;
            tx.expire_reserved().await?;
            let mut totals: FleetTotals = required(tx.row("totals")?)?;
            let after = totals.tenant_cursor.as_ref().map(ToString::to_string);
            let mut tenants = tx.range("tenants", after.as_deref(), 64).await?;
            if tenants.len() < 64 && after.is_some() {
                let first = tx.range("tenants", None, 64 - tenants.len()).await?;
                for tenant in first {
                    if after.as_ref().is_some_and(|v| &tenant <= v) && !tenants.contains(&tenant) {
                        tenants.push(tenant);
                    }
                }
            }
            if let Some(active) = totals.active_tenant.take() {
                let member = active.to_string();
                tenants.retain(|t| t != &member);
                tenants.insert(0, member);
                tenants.truncate(64);
            }
            let credited: Option<TenantId> =
                required::<FleetTotals>(tx.row("totals")?)?.active_tenant;
            let workers = config.workers();
            let count = workers.len().min(32);
            let start = totals.worker_cursor % workers.len();
            let candidates: Vec<_> = (0..count)
                .map(|i| &workers[(start + i) % workers.len()])
                .collect();
            totals.worker_cursor = (start + count) % workers.len();
            tx.read_rows(
                &candidates
                    .iter()
                    .map(|w| worker_field(w.worker_id()))
                    .collect::<Vec<_>>(),
                false,
            )
            .await?;
            let mut selected = None;
            for tenant_raw in tenants {
                let tenant: TenantId = tenant_raw
                    .parse()
                    .map_err(|_| GatewayActionCoordinationError::InvalidRedisResponse)?;
                totals.tenant_cursor = Some(tenant.clone());
                let field = tenant_field(&tenant);
                tx.read_rows(std::slice::from_ref(&field), false).await?;
                let mut usage: TenantTotals = required(tx.row(&field)?)?;
                let members = tx.range(&queue_index(&tenant), None, 1).await?;
                let member = required(members.first())?;
                let (sequence, op) = member
                    .split_once('|')
                    .ok_or(GatewayActionCoordinationError::InvalidRedisResponse)?;
                let key = GatewaySessionAdmissionKey::new(
                    tenant.clone(),
                    op.parse()
                        .map_err(|_| GatewayActionCoordinationError::InvalidRedisResponse)?,
                );
                let mut row = required(tx.admission(&key).await?)?;
                if row.state() != GatewaySessionAdmissionState::Queued
                    || format!("{:020}", row.queue_sequence()) != sequence
                {
                    return Err(GatewayActionCoordinationError::InvalidRedisResponse);
                }
                let policy = config.tenant_policy(&tenant);
                let profile = config.profile(row.request())?;
                if credited.as_ref() != Some(&tenant) {
                    usage.deficit = usage
                        .deficit
                        .checked_add(u64::from(policy.weight()))
                        .ok_or(GatewayActionCoordinationError::AdmissionCapacity)?
                        .min(64);
                }
                if millis(row.request().admission_deadline())? <= tx.now {
                    row.revision = increment(row.revision)?;
                    row.state = GatewaySessionAdmissionState::Expired;
                    usage.queued = subtract(usage.queued)?;
                    totals.queued = subtract(totals.queued)?;
                    tx.put(admission_field(&key), &row)?;
                    tx.index(&queue_index(&tenant), member.clone(), false);
                    if usage.queued == 0 {
                        usage.deficit = 0;
                        totals.queued_tenants = subtract(totals.queued_tenants)?;
                        tx.index("tenants", tenant_raw, false);
                    }
                    tx.put(field, &usage)?;
                    continue;
                }
                let resources = row.request().resources().components();
                let fleet_next = checked_add(totals.resources, resources)?;
                let tenant_next = checked_add(usage.resources, resources)?;
                if usage.deficit < u64::from(profile.drr_cost())
                    || totals.live >= config.limits().namespace_live() as u64
                    || usage.live >= policy.live_sessions() as u64
                    || !fits(
                        fleet_next,
                        config.limits().fleet_resource_limit().components(),
                    )
                    || !fits(tenant_next, policy.resource_limit().components())
                {
                    tx.put(field, &usage)?;
                    continue;
                }
                let mut best: Option<(usize, String, WorkerRow)> = None;
                for (offset, worker) in candidates.iter().enumerate() {
                    let worker_field = worker_field(worker.worker_id());
                    let Some(worker_row) = tx.row::<WorkerRow>(&worker_field)? else {
                        continue;
                    };
                    let candidate = worker_candidate(&worker_row);
                    if !eligible_worker(config, row.request(), &candidate, tx.now)? {
                        continue;
                    }
                    if let Some((_, _, previous)) = &best
                        && !compare_worker_headroom(&candidate, &worker_candidate(previous))?
                            .is_gt()
                    {
                        continue;
                    }
                    best = Some((offset, worker_field, worker_row));
                }
                if let Some((offset, worker_field, mut worker_row)) = best {
                    // A complete window rotates ties past the winner. Larger inventories retain
                    // the fixed 32-candidate advance so unexamined workers cannot starve.
                    if workers.len() <= 32 {
                        totals.worker_cursor = (start + offset + 1) % workers.len();
                    }
                    let reserved =
                        row.reserve(worker_row.observation.identity().clone(), tx.now, ttl)?;
                    let res = required(reserved.reservation())?;
                    worker_row.shadow = checked_add(worker_row.shadow, resources)?;
                    usage.deficit -= u64::from(profile.drr_cost());
                    usage.live = increment(usage.live)?;
                    usage.queued = subtract(usage.queued)?;
                    usage.resources = tenant_next;
                    totals.live = increment(totals.live)?;
                    totals.queued = subtract(totals.queued)?;
                    totals.resources = fleet_next;
                    if usage.queued == 0 {
                        usage.deficit = 0;
                        totals.queued_tenants = subtract(totals.queued_tenants)?;
                        tx.index("tenants", tenant_raw.clone(), false);
                    }
                    tx.put(worker_field, &worker_row)?;
                    tx.put(shadow_field(&key), res)?;
                    tx.put(admission_field(&key), &reserved)?;
                    tx.index(&queue_index(&tenant), member.clone(), false);
                    tx.index("reserved", expiry_member(res), true);
                    if usage.queued > 0 && usage.deficit > 0 {
                        totals.active_tenant = Some(tenant.clone());
                    }
                    tx.deadline = Some(res.provider_deadline_millis().min(worker_row.expires));
                    selected = Some(reserved);
                }
                tx.put(field, &usage)?;
                if selected.is_some() {
                    break;
                }
            }
            tx.put("totals".into(), &totals)?;
            tx.commit().await?;
            Ok(selected)
        })
    }
    pub(super) async fn fleet_record_reservation(
        &self,
        expected: &GatewaySessionAdmissionSnapshot,
        proof: GatewaySessionWorkerReservationProof,
    ) -> Result<GatewaySessionAdmissionSnapshot, GatewayActionCoordinationError> {
        proof.validate()?;
        fleet_retry!(self, {
            let mut tx = FleetTransaction::begin(self).await?;
            let current = required(tx.admission(expected.request().key()).await?)?;
            let next = current.record_reservation(expected, &proof, tx.now)?;
            if next == current {
                return Ok(current);
            }
            let res = required(next.reservation())?;
            let shadow = shadow_field(res.key());
            let worker = worker_field(res.worker().worker_id());
            let confirmed = required(confirmed_debit_field(res))?;
            tx.read_rows(&[shadow.clone(), worker.clone(), confirmed.clone()], false)
                .await?;
            if tx
                .row::<GatewaySessionReservation>(&confirmed)?
                .is_some_and(|bound| bound != *res)
            {
                return Err(GatewayActionCoordinationError::AdmissionConflict);
            }
            let debit: GatewaySessionReservation = required(tx.row(&shadow)?)?;
            if !debit.same_basis(res) {
                return Err(GatewayActionCoordinationError::InvalidRedisResponse);
            }
            let mut row: WorkerRow = required(tx.row(&worker)?)?;
            if row.observation.identity() != res.worker() {
                return Err(GatewayActionCoordinationError::AdmissionConflict);
            }
            if proof.debit_sequence <= row.observation.debit_sequence_watermark() {
                row.shadow = checked_sub(row.shadow, res.resources().components())?;
                tx.put(worker, &row)?;
                tx.remove(shadow);
            } else {
                tx.put(shadow, res)?;
                tx.index(
                    &shadow_index(res.worker()),
                    required(shadow_member(res))?,
                    true,
                );
            }
            // Preserve the exact debit owner after shadow ACK, bounded by retained
            // live reservations rather than observation or delivery history.
            tx.put(confirmed, res)?;
            tx.deadline = Some(res.provider_deadline_millis());
            tx.put(admission_field(res.key()), &next)?;
            tx.commit().await?;
            Ok(next)
        })
    }
    pub(super) async fn fleet_arm(
        &self,
        expected: &GatewaySessionAdmissionSnapshot,
        dispatch: &DispatchLeaseToken,
        ttl: Duration,
    ) -> Result<GatewaySessionAdmissionSnapshot, GatewayActionCoordinationError> {
        let ttl = ttl_millis(ttl)?;
        fleet_retry!(self, {
            let mut tx = FleetTransaction::begin(self).await?;
            let current = required(tx.admission(expected.request().key()).await?)?;
            let next = current.arm(expected, *dispatch.as_uuid(), tx.now, ttl)?;
            if next == current {
                return Ok(current);
            }
            let res = required(next.reservation())?;
            let field = worker_field(res.worker().worker_id());
            tx.read_rows(std::slice::from_ref(&field), false).await?;
            let worker: WorkerRow = required(tx.row(&field)?)?;
            if worker.observation.identity() != res.worker()
                || worker.observation.readiness() != WorkerReadiness::Ready
                || worker.expires <= tx.now
            {
                return Err(GatewayActionCoordinationError::SessionAuthorityUnavailable);
            }
            tx.deadline = Some(res.provider_deadline_millis().min(worker.expires));
            tx.put(admission_field(res.key()), &next)?;
            tx.index("reserved", expiry_member(res), false);
            tx.commit().await?;
            Ok(next)
        })
    }
    pub(super) async fn fleet_commit(
        &self,
        expected: &GatewaySessionAdmissionSnapshot,
        proof: GatewaySessionWorkerReadyProof,
    ) -> Result<GatewaySessionPlacementAuthority, GatewayActionCoordinationError> {
        proof.validate()?;
        let config = self.fleet_config()?;
        fleet_retry!(self, {
            let mut tx = FleetTransaction::begin(self).await?;
            let current = required(tx.admission(expected.request().key()).await?)?;
            if current
                .ready_proof()
                .is_some_and(|old| old.same_identity(&proof))
            {
                return required(current.placement().cloned());
            }
            let reservation = required(current.reservation())?;
            let worker_field = worker_field(reservation.worker().worker_id());
            tx.read_rows(std::slice::from_ref(&worker_field), false)
                .await?;
            let worker: WorkerRow = required(tx.row(&worker_field)?)?;
            if worker.observation.identity() != reservation.worker() {
                return Err(GatewayActionCoordinationError::SessionAuthorityUnavailable);
            }
            let mut totals: FleetTotals = required(tx.row("totals")?)?;
            totals.authority_revision = increment(totals.authority_revision)?;
            let next =
                current.commit(expected, &proof, totals.authority_revision, tx.now, config)?;
            let authority = required(next.placement().cloned())?;
            if tx.placement(authority.entry().key()).await?.is_some() {
                return Err(GatewayActionCoordinationError::AdmissionConflict);
            }
            // Full placement and empty action-session binding are installed in this same CAS.
            tx.authority(&authority, true)?;
            tx.put(
                authority_field(authority.entry().key()),
                &PlacementRow {
                    authority: authority.clone(),
                    admission: next.request().key().clone(),
                },
            )?;
            tx.put("totals".into(), &totals)?;
            tx.put(admission_field(next.request().key()), &next)?;
            tx.index("projection", admission_member(next.request().key()), true);
            tx.deadline = Some(authority.expires_at_millis());
            tx.commit().await?;
            Ok(authority)
        })
    }
    pub(super) async fn fleet_resolve(
        &self,
        key: &DirectoryKey,
    ) -> Result<Option<GatewaySessionPlacementAuthority>, GatewayActionCoordinationError> {
        fleet_retry!(self, {
            let mut tx = FleetTransaction::begin(self).await?;
            Ok(tx.placement(key).await?.map(|row| row.authority))
        })
    }
    pub(super) async fn fleet_validate_authority(
        &self,
        authority: &GatewaySessionAuthorityRef,
    ) -> Result<(), GatewayActionCoordinationError> {
        authority.validate()?;
        let digest = encode(&self.fleet_config()?.digest())?;
        let reference = encode(authority)?;
        let action_session = self
            .keys(authority.key().tenant_id(), authority.key().session_id())
            .session;
        let state = self.fleet_state_key();
        let placement = Self::serialize_placement(&authority.action_placement()?)?;
        let marker = self.recovery_format_key();
        let key =
            self.fleet_authority_key(authority.key().tenant_id(), authority.key().session_id());
        let code:i64=self.execute(move |mut connection| async move {
            Script::new(r#"
if redis.call('TYPE',KEYS[1])['ok']~='hash' or redis.call('PTTL',KEYS[1])~=-1 or redis.call('HGET',KEYS[1],'version')~='5' or redis.call('HGET',KEYS[1],'state')~='ready' or redis.call('HGET',KEYS[1],'fleet_digest')~=ARGV[1] then return 2 end
if redis.call('TYPE',KEYS[2])['ok']~='hash' or redis.call('PTTL',KEYS[2])~=-1 or redis.call('HGET',KEYS[2],'reference')~=ARGV[2] or redis.call('HGET',KEYS[2],'placement')~=ARGV[3] or redis.call('HGET',KEYS[2],'status')~='ready' then return 1 end
if redis.call('TYPE',KEYS[3])['ok']~='hash' or redis.call('PTTL',KEYS[3])~=-1 then return 2 end
if redis.call('TYPE',KEYS[4])['ok']~='hash' or redis.call('PTTL',KEYS[4])~=-1 or redis.call('HGET',KEYS[4],'placement')~=ARGV[3] then return 2 end
if redis.call('HEXISTS',KEYS[4],'loss_id')==1 then return 1 end
local worker_field=redis.call('HGET',KEYS[2],'worker_field');local worker_identity=redis.call('HGET',KEYS[2],'worker_identity')
if not worker_field or not worker_identity or redis.call('HGET',KEYS[3],worker_field)~=worker_identity then return 1 end
local time=redis.call('TIME');local now=tonumber(time[1])*1000+math.floor(tonumber(time[2])/1000)
local floor=tonumber(redis.call('HGET',KEYS[1],'clock_floor') or '0')
local expires=tonumber(redis.call('HGET',KEYS[2],'expires'))
if not floor or floor<0 or floor>9007199254740991 or not expires or expires>9007199254740991 then return 2 end
now=math.max(now,floor);redis.call('HSET',KEYS[1],'clock_floor',string.format('%.0f',now))
return expires>now and 0 or 1
"#).key(marker).key(key).key(state).key(action_session).arg(digest).arg(reference).arg(placement).invoke_async(&mut connection).await
        }).await?;
        match code {
            0 => Ok(()),
            1 => Err(GatewayActionCoordinationError::SessionAuthorityUnavailable),
            _ => Err(GatewayActionCoordinationError::InvalidRedisResponse),
        }
    }

    pub(super) async fn fleet_begin_renewal(
        &self,
        expected: &GatewaySessionPlacementAuthority,
        nonce: LeaseId,
        ttl: Duration,
    ) -> Result<GatewaySessionRenewalIntent, GatewayActionCoordinationError> {
        let ttl = ttl_millis(ttl)?;
        fleet_retry!(self, {
            let mut tx = FleetTransaction::begin(self).await?;
            let mut stored = required(tx.placement(expected.entry().key()).await?)?;
            let (next, intent) =
                stored
                    .authority
                    .begin_renewal(expected, nonce.clone(), tx.now, ttl)?;
            if next == stored.authority {
                return Ok(intent);
            }
            stored.authority = next;
            let mut admission = required(tx.admission(&stored.admission).await?)?;
            admission.placement = Some(stored.authority.clone());
            tx.deadline = Some(expected.expires_at_millis());
            tx.put(admission_field(&stored.admission), &admission)?;
            tx.put(authority_field(expected.entry().key()), &stored)?;
            tx.commit().await?;
            Ok(intent)
        })
    }
    pub(super) async fn fleet_finish_renewal(
        &self,
        intent: &GatewaySessionRenewalIntent,
        proof: GatewaySessionWorkerRenewalProof,
    ) -> Result<GatewaySessionPlacementAuthority, GatewayActionCoordinationError> {
        intent.validate()?;
        proof.validate()?;
        fleet_retry!(self, {
            let mut tx = FleetTransaction::begin(self).await?;
            let mut stored = required(tx.placement(intent.authority().key()).await?)?;
            let previous_expiry = stored.authority.expires_at_millis();
            let result = stored.authority.finish_renewal(intent, &proof, tx.now)?;
            if result == stored.authority {
                return Ok(result);
            }
            stored.authority = result.clone();
            let mut admission = required(tx.admission(&stored.admission).await?)?;
            admission.placement = Some(result.clone());
            tx.authority(&result, false)?;
            tx.deadline = Some(previous_expiry.min(intent.anchored_expires_at_millis()));
            tx.put(admission_field(&stored.admission), &admission)?;
            tx.put(authority_field(intent.authority().key()), &stored)?;
            tx.commit().await?;
            Ok(result)
        })
    }
    pub(super) async fn fleet_close(
        &self,
        expected: &GatewaySessionPlacementAuthority,
    ) -> Result<GatewaySessionPlacementAuthority, GatewayActionCoordinationError> {
        fleet_retry!(self, {
            let mut tx = FleetTransaction::begin(self).await?;
            let mut stored = required(tx.placement(expected.entry().key()).await?)?;
            let next = stored.authority.close(expected)?;
            if next == stored.authority {
                return Ok(next);
            }
            stored.authority = next;
            let mut admission = required(tx.admission(&stored.admission).await?)?;
            admission.state = GatewaySessionAdmissionState::Closing;
            admission.revision = increment(admission.revision)?;
            admission.placement = Some(stored.authority.clone());
            admission.validate()?;
            tx.authority(&stored.authority, false)?;
            tx.put(admission_field(&stored.admission), &admission)?;
            tx.put(authority_field(expected.entry().key()), &stored)?;
            let authority = stored.authority;
            tx.commit().await?;
            Ok(authority)
        })
    }
    pub(super) async fn fleet_release(
        &self,
        expected: &GatewaySessionAdmissionSnapshot,
        proof: GatewaySessionCleanupProof,
    ) -> Result<GatewaySessionAdmissionSnapshot, GatewayActionCoordinationError> {
        proof.validate()?;
        fleet_retry!(self, {
            let mut tx = FleetTransaction::begin(self).await?;
            let mut row = required(tx.admission(expected.request().key()).await?)?;
            let next = row.release(expected, &proof, tx.now)?;
            if next == row {
                return Ok(row);
            }
            let res = required(row.reservation().cloned())?;
            row = next;
            let field = tenant_field(row.request().key().tenant_id());
            tx.read_rows(std::slice::from_ref(&field), false).await?;
            let mut totals: FleetTotals = required(tx.row("totals")?)?;
            let mut tenant: TenantTotals = required(tx.row(&field)?)?;
            totals.live = subtract(totals.live)?;
            tenant.live = subtract(tenant.live)?;
            totals.resources = checked_sub(totals.resources, res.resources().components())?;
            tenant.resources = checked_sub(tenant.resources, res.resources().components())?;
            tx.clear_shadow(&res).await?;
            tx.index("reserved", expiry_member(&res), false);
            if row.state() == GatewaySessionAdmissionState::Queued {
                // Requeue under the same FIFO identity; only a positive no-effect proof does this.
                let policy = self
                    .fleet_config()?
                    .tenant_policy(row.request().key().tenant_id());
                let limits = self.fleet_config()?.limits();
                if totals.queued >= limits.namespace_queued() as u64
                    || tenant.queued >= policy.queued_operations() as u64
                    || (tenant.queued == 0
                        && totals.queued_tenants >= limits.queued_tenants() as u64)
                {
                    return Err(GatewayActionCoordinationError::AdmissionCapacity);
                }
                if tenant.queued == 0 {
                    totals.queued_tenants = increment(totals.queued_tenants)?;
                    tx.index("tenants", row.request().key().tenant_id().to_string(), true);
                }
                totals.queued = increment(totals.queued)?;
                tenant.queued = increment(tenant.queued)?;
                tx.index(
                    &queue_index(row.request().key().tenant_id()),
                    queue_member(&row),
                    true,
                );
            } else if let Some(authority) = row.placement.as_mut() {
                tx.authority(authority, false)?;
                tx.put(
                    authority_field(authority.entry().key()),
                    &PlacementRow {
                        authority: authority.clone(),
                        admission: row.request.key.clone(),
                    },
                )?;
            }
            row.validate()?;
            tx.put("totals".into(), &totals)?;
            tx.put(field, &tenant)?;
            tx.put(admission_field(row.request().key()), &row)?;
            tx.commit().await?;
            Ok(row)
        })
    }
    pub(super) async fn fleet_scan(
        &self,
        cursor: GatewaySessionAdmissionCursor,
        limit: usize,
    ) -> Result<GatewaySessionAdmissionPage, GatewayActionCoordinationError> {
        cursor.validate()?;
        if !(1..=64).contains(&limit) {
            return Err(GatewayActionCoordinationError::InvalidSessionAdmission);
        }
        fleet_retry!(self, {
            let mut tx = FleetTransaction::begin(self).await?;
            let after = cursor
                .after
                .as_ref()
                .map(|(tenant, op)| format!("{tenant}|{op}"));
            let members = tx.range("admissions", after.as_deref(), limit).await?;
            let complete = members.len() < limit;
            let examined = members.len();
            let keys = members
                .iter()
                .map(|m| parse_admission_member(m))
                .collect::<Result<Vec<_>, _>>()?;
            tx.read_rows(&keys.iter().map(admission_field).collect::<Vec<_>>(), false)
                .await?;
            let mut rows = Vec::with_capacity(keys.len());
            for key in &keys {
                let row: GatewaySessionAdmissionSnapshot =
                    required(tx.row(&admission_field(key))?)?;
                if row.request().key() != key {
                    return Err(GatewayActionCoordinationError::InvalidRedisResponse);
                }
                if matches!(
                    row.state(),
                    GatewaySessionAdmissionState::Queued
                        | GatewaySessionAdmissionState::Reserved
                        | GatewaySessionAdmissionState::CommitArmed
                        | GatewaySessionAdmissionState::Active
                        | GatewaySessionAdmissionState::Closing
                        | GatewaySessionAdmissionState::Expired
                ) || row.pending_create_projection()
                {
                    rows.push(row);
                }
            }
            let next = if complete {
                GatewaySessionAdmissionCursor::default()
            } else {
                GatewaySessionAdmissionCursor::after(required(keys.last())?)
            };
            GatewaySessionAdmissionPage::new(rows, next, complete, examined)
        })
    }
    pub(super) async fn fleet_ack_projection(
        &self,
        expected: &GatewaySessionAdmissionSnapshot,
    ) -> Result<GatewaySessionAdmissionSnapshot, GatewayActionCoordinationError> {
        fleet_retry!(self, {
            let mut tx = FleetTransaction::begin(self).await?;
            let mut row = required(tx.admission(expected.request().key()).await?)?;
            let next = row.ack_projection(expected)?;
            if next == row {
                return Ok(row);
            }
            row = next;
            tx.put(admission_field(row.request().key()), &row)?;
            tx.index("projection", admission_member(row.request().key()), false);
            tx.commit().await?;
            Ok(row)
        })
    }
}
