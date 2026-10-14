//! Memory fleet authority shares the action database's one admission lock.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound::{Excluded, Unbounded};
use std::sync::Arc;
use std::time::Duration;

use browserd_core::{LeaseId, OperationId, SessionId, TenantId, WorkerId};
use chrono::Utc;

use super::{GatewayActionMemoryState, GatewayActionSessionState, MemoryGatewayActionStore};
use crate::session_admission::*;
use crate::{
    DirectoryKey, DispatchLeaseToken, GatewayActionCoordinationError as Error,
    GatewayActionPlacement, WorkerCapacity,
};

#[derive(Clone, Default)]
struct Counters {
    records: usize,
    queued: usize,
    live: usize,
    resources: WorkerCapacity,
}
#[derive(Default)]
struct TenantState {
    counters: Counters,
    queue: BTreeMap<u64, GatewaySessionAdmissionKey>,
    deficit: u64,
}
struct WorkerState {
    observation: GatewayFleetWorkerObservation,
    expires: u64,
    shadow: WorkerCapacity,
    pending: BTreeMap<LeaseId, WorkerCapacity>,
    unack: BTreeMap<u64, (LeaseId, WorkerCapacity)>,
    confirmed: BTreeMap<u64, LeaseId>,
}
#[derive(Default)]
pub(super) struct FleetMemoryState {
    pub(super) config_digest: Option<[u8; 32]>,
    floor: u64,
    records: BTreeMap<GatewaySessionAdmissionKey, GatewaySessionAdmissionSnapshot>,
    operation_owners: BTreeMap<OperationId, TenantId>,
    tenants: BTreeMap<TenantId, TenantState>,
    queue_tenants: BTreeSet<TenantId>,
    workers: BTreeMap<WorkerId, WorkerState>,
    placements: BTreeMap<(TenantId, SessionId), GatewaySessionAdmissionKey>,
    expiry: BTreeSet<(u64, GatewaySessionAdmissionKey)>,
    counters: Counters,
    queue_sequence: u64,
    authority_revision: u64,
    tenant_cursor: Option<TenantId>,
    turn: Option<TenantId>,
    worker_cursor: usize,
}
fn charged(state: GatewaySessionAdmissionState) -> bool {
    matches!(
        state,
        GatewaySessionAdmissionState::Reserved
            | GatewaySessionAdmissionState::CommitArmed
            | GatewaySessionAdmissionState::Active
            | GatewaySessionAdmissionState::Closing
    )
}
fn due(snapshot: &GatewaySessionAdmissionSnapshot) -> Result<Option<u64>, Error> {
    match snapshot.state {
        GatewaySessionAdmissionState::Queued => {
            Ok(Some(millis(snapshot.request.admission_deadline)?))
        }
        GatewaySessionAdmissionState::Reserved => Ok(Some(
            snapshot
                .reservation
                .as_ref()
                .ok_or(Error::CorruptState)?
                .provider_deadline_millis,
        )),
        _ => Ok(None),
    }
}
fn changed_counters(
    before: &Counters,
    old: Option<&GatewaySessionAdmissionSnapshot>,
    new: &GatewaySessionAdmissionSnapshot,
) -> Result<Counters, Error> {
    let mut value = before.clone();
    if old.is_none() {
        value.records = value
            .records
            .checked_add(1)
            .ok_or(Error::RevisionOverflow)?;
    }
    let old_queue = old.is_some_and(|row| row.state == GatewaySessionAdmissionState::Queued);
    let new_queue = new.state == GatewaySessionAdmissionState::Queued;
    if old_queue != new_queue {
        value.queued = if new_queue {
            value.queued.checked_add(1)
        } else {
            value.queued.checked_sub(1)
        }
        .ok_or(Error::CorruptState)?;
    }
    let old_live = old.is_some_and(|row| charged(row.state));
    let new_live = charged(new.state);
    if old_live != new_live {
        value.live = if new_live {
            value.live.checked_add(1)
        } else {
            value.live.checked_sub(1)
        }
        .ok_or(Error::CorruptState)?;
        value.resources = if new_live {
            value.resources.checked_add(new.request.resources)
        } else {
            value.resources.checked_sub(new.request.resources)
        }
        .ok_or(Error::CorruptState)?;
    }
    Ok(value)
}
fn quota(
    config: &GatewayFleetAdmissionConfig,
    tenant: &TenantId,
    namespace: &Counters,
    local: &Counters,
) -> Result<(), Error> {
    let policy = config.tenant_policy(tenant);
    let limits = &config.limits;
    if namespace.records > limits.namespace_records
        || namespace.queued > limits.namespace_queued
        || namespace.live > limits.namespace_live
        || !namespace.resources.fits_within(limits.fleet_resource_limit)
        || local.records > policy.retained_operations
        || local.queued > policy.queued_operations
        || local.live > policy.live_sessions
        || !local.resources.fits_within(policy.resource_limit)
    {
        return Err(Error::AdmissionCapacity);
    }
    Ok(())
}
fn shadow_piece(worker: &WorkerState, res: &GatewaySessionReservation) -> WorkerCapacity {
    if res
        .worker_debit_sequence
        .is_some_and(|seq| seq <= worker.observation.debit_sequence_watermark)
    {
        WorkerCapacity::default()
    } else {
        res.resources
    }
}
struct ShadowChange {
    worker_id: WorkerId,
    aggregate: WorkerCapacity,
    old: Option<GatewaySessionReservation>,
    new: Option<GatewaySessionReservation>,
}
impl FleetMemoryState {
    fn shadow_plan(
        &self,
        old: Option<&GatewaySessionAdmissionSnapshot>,
        new: &GatewaySessionAdmissionSnapshot,
    ) -> Result<Option<ShadowChange>, Error> {
        let old_res = old
            .filter(|row| charged(row.state))
            .and_then(|row| row.reservation.as_ref());
        let new_res = charged(new.state)
            .then_some(new.reservation.as_ref())
            .flatten();
        if old_res == new_res {
            return Ok(None);
        }
        let res = new_res.or(old_res).ok_or(Error::CorruptState)?;
        let Some(worker) = self.workers.get(&res.worker.worker_id) else {
            return Err(Error::CorruptState);
        };
        if worker.observation.identity != res.worker {
            if new_res.is_some() {
                return Err(Error::AdmissionConflict);
            }
            return Ok(None); // Old boot obligations release only their fleet/tenant charge.
        }
        let mut aggregate = worker.shadow;
        if let Some(old) = old_res {
            match old.worker_debit_sequence {
                None => {
                    if worker.pending.get(&old.reservation_id) != Some(&old.resources) {
                        return Err(Error::CorruptState);
                    }
                }
                Some(seq) if seq > worker.observation.debit_sequence_watermark => {
                    if worker.unack.get(&seq) != Some(&(old.reservation_id.clone(), old.resources))
                    {
                        return Err(Error::CorruptState);
                    }
                }
                Some(_) => {}
            }
            aggregate = aggregate
                .checked_sub(shadow_piece(worker, old))
                .ok_or(Error::CorruptState)?;
        }
        if let Some(new) = new_res {
            if let Some(seq) = new.worker_debit_sequence
                && worker
                    .confirmed
                    .get(&seq)
                    .is_some_and(|id| id != &new.reservation_id)
            {
                return Err(Error::AdmissionConflict);
            }
            if new.worker_debit_sequence.is_none()
                && worker.pending.contains_key(&new.reservation_id)
                && old_res.is_none()
            {
                return Err(Error::CorruptState);
            }
            if let Some(seq) = new.worker_debit_sequence
                && seq > worker.observation.debit_sequence_watermark
                && worker
                    .unack
                    .get(&seq)
                    .is_some_and(|(id, _)| id != &new.reservation_id)
            {
                return Err(Error::AdmissionConflict);
            }
            aggregate = aggregate
                .checked_add(shadow_piece(worker, new))
                .ok_or(Error::AdmissionCapacity)?;
        }
        Ok(Some(ShadowChange {
            worker_id: res.worker.worker_id.clone(),
            aggregate,
            old: old_res.cloned(),
            new: new_res.cloned(),
        }))
    }
    fn replace(
        &mut self,
        config: &GatewayFleetAdmissionConfig,
        old: Option<&GatewaySessionAdmissionSnapshot>,
        new: GatewaySessionAdmissionSnapshot,
    ) -> Result<(), Error> {
        new.validate()?;
        let key = &new.request.key;
        if old.is_some_and(|old| old.request.key != *key || self.records.get(key) != Some(old)) {
            return Err(Error::CorruptState);
        }
        let before = self
            .tenants
            .get(&key.tenant_id)
            .map_or(Counters::default(), |tenant| tenant.counters.clone());
        let local = changed_counters(&before, old, &new)?;
        let namespace = changed_counters(&self.counters, old, &new)?;
        quota(config, &key.tenant_id, &namespace, &local)?;
        let adding_queue = new.state == GatewaySessionAdmissionState::Queued
            && !self.queue_tenants.contains(&key.tenant_id);
        if adding_queue && self.queue_tenants.len() >= config.limits.queued_tenants {
            return Err(Error::AdmissionCapacity);
        }
        let old_due = old.map(due).transpose()?.flatten();
        let new_due = due(&new)?;
        let shadow = self.shadow_plan(old, &new)?;
        // Every fallible identity/arithmetic check precedes the committed indexes.
        if let Some(change) = shadow {
            let worker = self
                .workers
                .get_mut(&change.worker_id)
                .ok_or(Error::CorruptState)?;
            if let Some(res) = change.old {
                if let Some(seq) = res.worker_debit_sequence {
                    worker.unack.remove(&seq);
                    worker.confirmed.remove(&seq);
                } else {
                    worker.pending.remove(&res.reservation_id);
                }
            }
            if let Some(res) = change.new {
                if let Some(seq) = res.worker_debit_sequence {
                    worker.confirmed.insert(seq, res.reservation_id.clone());
                    if seq > worker.observation.debit_sequence_watermark {
                        worker
                            .unack
                            .insert(seq, (res.reservation_id, res.resources));
                    }
                } else {
                    worker.pending.insert(res.reservation_id, res.resources);
                }
            }
            worker.shadow = change.aggregate;
        }
        if let Some(at) = old_due {
            self.expiry.remove(&(at, key.clone()));
        }
        if let Some(at) = new_due {
            self.expiry.insert((at, key.clone()));
        }
        let tenant = self.tenants.entry(key.tenant_id.clone()).or_default();
        tenant.counters = local;
        if old.is_some_and(|row| row.state == GatewaySessionAdmissionState::Queued) {
            tenant.queue.remove(&new.queue_sequence);
        }
        if new.state == GatewaySessionAdmissionState::Queued {
            tenant.queue.insert(new.queue_sequence, key.clone());
        }
        if tenant.queue.is_empty() {
            self.queue_tenants.remove(&key.tenant_id);
        } else {
            self.queue_tenants.insert(key.tenant_id.clone());
        }
        self.counters = namespace;
        self.records.insert(key.clone(), new);
        Ok(())
    }
    fn row(
        &self,
        key: &GatewaySessionAdmissionKey,
    ) -> Result<GatewaySessionAdmissionSnapshot, Error> {
        let row = self.records.get(key).ok_or(Error::NotFound)?;
        row.validate()?;
        if row.request.key != *key
            || self.operation_owners.get(&key.operation_id) != Some(&key.tenant_id)
        {
            return Err(Error::CorruptState);
        }
        Ok(row.clone())
    }
    fn expire_one(
        &mut self,
        config: &GatewayFleetAdmissionConfig,
        key: &GatewaySessionAdmissionKey,
        now: u64,
    ) -> Result<(), Error> {
        let old = self.row(key)?;
        if due(&old)?.is_some_and(|at| at <= now) {
            let new = old.expire(now)?;
            self.replace(config, Some(&old), new)?;
        }
        Ok(())
    }
}

impl MemoryGatewayActionStore {
    #[must_use]
    pub fn with_fleet_admission_clock(
        mut self,
        clock: Arc<dyn GatewayFleetAdmissionClock>,
    ) -> Self {
        self.fleet_clock = Some(clock);
        self
    }
    pub fn with_fleet_admission_config(
        mut self,
        config: GatewayFleetAdmissionConfig,
    ) -> Result<Self, Error> {
        config.validate()?;
        let digest = config.digest();
        {
            let mut state = self
                .database
                .gateway_actions
                .lock()
                .map_err(|_| Error::LockUnavailable)?;
            if state.fleet.config_digest.is_some_and(|old| old != digest) {
                return Err(Error::AdmissionConflict);
            }
            state.fleet.config_digest = Some(digest);
        }
        self.fleet_config = Some(Arc::new(config));
        self.fleet_digest = Some(digest);
        Ok(self)
    }
    fn fleet_config(&self) -> Result<&GatewayFleetAdmissionConfig, Error> {
        self.fleet_config
            .as_deref()
            .ok_or(Error::UnsupportedSessionAdmission)
    }
    fn fleet_now(&self, state: &mut GatewayActionMemoryState) -> Result<u64, Error> {
        self.fleet_config()?;
        if state.fleet.config_digest != self.fleet_digest {
            return Err(Error::AdmissionConflict);
        }
        let now = millis(
            self.fleet_clock
                .as_ref()
                .map_or_else(Utc::now, |clock| clock.now()),
        )?;
        state.fleet.floor = state.fleet.floor.max(now);
        Ok(state.fleet.floor)
    }
    pub(super) fn reject_legacy_admission(
        &self,
        state: &GatewayActionMemoryState,
    ) -> Result<(), Error> {
        if self.fleet_config.is_some() || state.fleet.config_digest.is_some() {
            Err(Error::ManagedActionAdmissionRequired)
        } else {
            Ok(())
        }
    }
    pub(super) fn memory_enqueue_session_admission(
        &self,
        request: GatewaySessionAdmissionRequest,
    ) -> Result<GatewaySessionAdmissionSnapshot, Error> {
        request.validate()?;
        let config = self.fleet_config()?;
        config.profile(&request)?;
        let mut state = self
            .database
            .gateway_actions
            .lock()
            .map_err(|_| Error::LockUnavailable)?;
        let now = self.fleet_now(&mut state)?;
        if let Some(old) = state.fleet.records.get(&request.key) {
            if old.request != request {
                return Err(Error::AdmissionConflict);
            }
            return state.fleet.row(&request.key);
        }
        if state
            .fleet
            .operation_owners
            .contains_key(&request.key.operation_id)
            || millis(request.admission_deadline)? <= now
        {
            return Err(Error::AdmissionConflict);
        }
        let sequence = state
            .fleet
            .queue_sequence
            .checked_add(1)
            .ok_or(Error::RevisionOverflow)?;
        let row = GatewaySessionAdmissionSnapshot::queued(request, sequence)?;
        state.fleet.replace(config, None, row.clone())?;
        state.fleet.queue_sequence = sequence;
        state.fleet.operation_owners.insert(
            row.request.key.operation_id.clone(),
            row.request.key.tenant_id.clone(),
        );
        Ok(row)
    }
    pub(super) fn memory_get_session_admission(
        &self,
        key: &GatewaySessionAdmissionKey,
    ) -> Result<Option<GatewaySessionAdmissionSnapshot>, Error> {
        let config = self.fleet_config()?;
        let mut state = self
            .database
            .gateway_actions
            .lock()
            .map_err(|_| Error::LockUnavailable)?;
        let now = self.fleet_now(&mut state)?;
        if !state.fleet.records.contains_key(key) {
            return Ok(None);
        }
        state.fleet.expire_one(config, key, now)?;
        Ok(Some(state.fleet.row(key)?))
    }
    pub(super) fn memory_observe_fleet_worker(
        &self,
        observation: GatewayFleetWorkerObservation,
        ttl: Duration,
    ) -> Result<(), Error> {
        let ttl = ttl_millis(ttl)?;
        let config = self.fleet_config()?;
        observation.validate_config(config)?;
        let mut state = self
            .database
            .gateway_actions
            .lock()
            .map_err(|_| Error::LockUnavailable)?;
        let now = self.fleet_now(&mut state)?;
        let expires = deadline(now, ttl)?;
        if let Some(old) = state.fleet.workers.get(&observation.identity.worker_id) {
            if observation.identity.worker_epoch < old.observation.identity.worker_epoch
                || (observation.identity.worker_epoch == old.observation.identity.worker_epoch
                    && observation.identity.boot_id != old.observation.identity.boot_id)
            {
                return Err(Error::InvalidFleetObservation);
            }
            if observation.identity == old.observation.identity {
                if observation.capacity_revision < old.observation.capacity_revision
                    || observation.debit_sequence_watermark
                        < old.observation.debit_sequence_watermark
                    || (observation.capacity_revision == old.observation.capacity_revision
                        && observation != old.observation)
                    || (old.observation.readiness == crate::WorkerReadiness::Draining
                        && observation.readiness != crate::WorkerReadiness::Draining)
                {
                    return Err(Error::InvalidFleetObservation);
                }
                let ack: Vec<_> = old
                    .unack
                    .range(..=observation.debit_sequence_watermark)
                    .map(|(seq, (_, resources))| (*seq, *resources))
                    .collect();
                let mut shadow = old.shadow;
                for (_, resources) in &ack {
                    shadow = shadow.checked_sub(*resources).ok_or(Error::CorruptState)?;
                }
                let worker = state
                    .fleet
                    .workers
                    .get_mut(&observation.identity.worker_id)
                    .ok_or(Error::CorruptState)?;
                for (seq, _) in ack {
                    worker.unack.remove(&seq);
                }
                worker.shadow = shadow;
                worker.observation = observation;
                worker.expires = expires;
                return Ok(());
            }
        }
        state.fleet.workers.insert(
            observation.identity.worker_id.clone(),
            WorkerState {
                observation,
                expires,
                shadow: WorkerCapacity::default(),
                pending: BTreeMap::new(),
                unack: BTreeMap::new(),
                confirmed: BTreeMap::new(),
            },
        );
        Ok(())
    }
    pub(super) fn memory_reserve_next_session(
        &self,
        reservation_ttl: Duration,
    ) -> Result<Option<GatewaySessionAdmissionSnapshot>, Error> {
        let ttl = ttl_millis(reservation_ttl)?;
        let config = self.fleet_config()?;
        let mut state = self
            .database
            .gateway_actions
            .lock()
            .map_err(|_| Error::LockUnavailable)?;
        let now = self.fleet_now(&mut state)?;
        let due: Vec<_> = state
            .fleet
            .expiry
            .iter()
            .take(MAX_SESSION_ADMISSION_SCAN)
            .take_while(|(at, _)| *at <= now)
            .map(|(_, key)| key.clone())
            .collect();
        for key in &due {
            state.fleet.expire_one(config, key, now)?;
        }
        let budget = MAX_SESSION_ADMISSION_SCAN.saturating_sub(due.len());
        if budget == 0 || state.fleet.queue_tenants.is_empty() {
            return Ok(None);
        }
        let workers: Vec<_> = config
            .workers
            .iter()
            .cycle()
            .skip(state.fleet.worker_cursor)
            .take(config.workers.len().min(MAX_FLEET_WORKER_CANDIDATES))
            .map(|worker| worker.worker_id.clone())
            .collect();
        state.fleet.worker_cursor =
            (state.fleet.worker_cursor + workers.len()) % config.workers.len();
        let mut visited = BTreeSet::new();
        for _ in 0..budget {
            let tenant_id = if let Some(turn) = &state.fleet.turn {
                if state.fleet.queue_tenants.contains(turn) {
                    turn.clone()
                } else {
                    state.fleet.turn = None;
                    continue;
                }
            } else {
                let after = state
                    .fleet
                    .tenant_cursor
                    .as_ref()
                    .map_or(Unbounded, Excluded);
                state
                    .fleet
                    .queue_tenants
                    .range((after, Unbounded))
                    .next()
                    .or_else(|| state.fleet.queue_tenants.first())
                    .cloned()
                    .ok_or(Error::CorruptState)?
            };
            if !visited.insert(tenant_id.clone()) {
                break;
            }
            let starting = state.fleet.turn.as_ref() != Some(&tenant_id);
            let (key, deficit) = {
                let tenant = state
                    .fleet
                    .tenants
                    .get_mut(&tenant_id)
                    .ok_or(Error::CorruptState)?;
                if starting {
                    tenant.deficit = tenant
                        .deficit
                        .checked_add(u64::from(config.tenant_policy(&tenant_id).weight))
                        .ok_or(Error::RevisionOverflow)?
                        .min(64);
                }
                let key = tenant
                    .queue
                    .first_key_value()
                    .ok_or(Error::CorruptState)?
                    .1
                    .clone();
                (key, tenant.deficit)
            };
            let row = state.fleet.row(&key)?;
            let cost = u64::from(config.profile(&row.request)?.drr_cost);
            let candidate = if deficit >= cost {
                let mut best: Option<&WorkerState> = None;
                for id in &workers {
                    let Some(worker) = state.fleet.workers.get(id) else {
                        continue;
                    };
                    let current = FleetWorkerCandidate {
                        observation: &worker.observation,
                        expires_at_millis: worker.expires,
                        shadow: worker.shadow,
                    };
                    if !eligible_worker(config, &row.request, &current, now)? {
                        continue;
                    }
                    let improves = if let Some(selected) = best {
                        compare_worker_headroom(
                            &current,
                            &FleetWorkerCandidate {
                                observation: &selected.observation,
                                expires_at_millis: selected.expires,
                                shadow: selected.shadow,
                            },
                        )? == std::cmp::Ordering::Greater
                    } else {
                        true
                    };
                    if improves {
                        best = Some(worker);
                    }
                }
                best.map(|worker| worker.observation.identity.clone())
            } else {
                None
            };
            if let Some(worker) = candidate {
                let successor = config
                    .workers
                    .binary_search_by(|entry| entry.worker_id.cmp(&worker.worker_id))
                    .map_err(|_| Error::CorruptState)?
                    .checked_add(1)
                    .ok_or(Error::CorruptState)?
                    % config.workers.len();
                let new = row.reserve(worker, now, ttl)?;
                match state.fleet.replace(config, Some(&row), new.clone()) {
                    Ok(()) => {}
                    Err(Error::AdmissionCapacity) => {
                        state.fleet.tenant_cursor = Some(tenant_id);
                        state.fleet.turn = None;
                        continue;
                    }
                    Err(error) => return Err(error),
                }
                // Full windows rotate ties to the selected successor. Partial windows retain
                // their independent +32 discovery rotation so unexamined workers stay reachable.
                if config.workers.len() <= MAX_FLEET_WORKER_CANDIDATES {
                    state.fleet.worker_cursor = successor;
                }
                let tenant = state
                    .fleet
                    .tenants
                    .get_mut(&tenant_id)
                    .ok_or(Error::CorruptState)?;
                tenant.deficit = deficit.checked_sub(cost).ok_or(Error::CorruptState)?;
                if tenant.queue.is_empty() {
                    state.fleet.turn = None;
                    state.fleet.tenant_cursor = Some(tenant_id);
                } else {
                    state.fleet.turn = Some(tenant_id);
                }
                return Ok(Some(new));
            }
            state.fleet.tenant_cursor = Some(tenant_id);
            state.fleet.turn = None;
        }
        Ok(None)
    }
    fn current_worker(
        &self,
        state: &GatewayActionMemoryState,
        reservation: &GatewaySessionReservation,
    ) -> Result<(), Error> {
        let worker = state
            .fleet
            .workers
            .get(&reservation.worker.worker_id)
            .ok_or(Error::SessionAuthorityUnavailable)?;
        if worker.observation.identity != reservation.worker {
            return Err(Error::SessionAuthorityUnavailable);
        }
        Ok(())
    }
    pub(super) fn memory_record_session_reservation(
        &self,
        expected: &GatewaySessionAdmissionSnapshot,
        proof: GatewaySessionWorkerReservationProof,
    ) -> Result<GatewaySessionAdmissionSnapshot, Error> {
        let config = self.fleet_config()?;
        let mut state = self
            .database
            .gateway_actions
            .lock()
            .map_err(|_| Error::LockUnavailable)?;
        let now = self.fleet_now(&mut state)?;
        let old = state.fleet.row(&expected.request.key)?;
        let new = old.record_reservation(expected, &proof, now)?;
        state.fleet.replace(config, Some(&old), new.clone())?;
        Ok(new)
    }
    pub(super) fn memory_arm_session_create(
        &self,
        expected: &GatewaySessionAdmissionSnapshot,
        dispatch_lease: &DispatchLeaseToken,
        placement_ttl: Duration,
    ) -> Result<GatewaySessionAdmissionSnapshot, Error> {
        let ttl = ttl_millis(placement_ttl)?;
        let config = self.fleet_config()?;
        let mut state = self
            .database
            .gateway_actions
            .lock()
            .map_err(|_| Error::LockUnavailable)?;
        let now = self.fleet_now(&mut state)?;
        let old = state.fleet.row(&expected.request.key)?;
        self.current_worker(
            &state,
            old.reservation.as_ref().ok_or(Error::AdmissionConflict)?,
        )?;
        let new = old.arm(expected, *dispatch_lease.as_uuid(), now, ttl)?;
        state.fleet.replace(config, Some(&old), new.clone())?;
        Ok(new)
    }
    pub(super) fn memory_commit_session_placement(
        &self,
        expected: &GatewaySessionAdmissionSnapshot,
        proof: GatewaySessionWorkerReadyProof,
    ) -> Result<GatewaySessionPlacementAuthority, Error> {
        let config = self.fleet_config()?;
        let mut state = self
            .database
            .gateway_actions
            .lock()
            .map_err(|_| Error::LockUnavailable)?;
        let now = self.fleet_now(&mut state)?;
        let old = state.fleet.row(&expected.request.key)?;
        if old.placement.is_none() {
            self.current_worker(
                &state,
                old.reservation.as_ref().ok_or(Error::AdmissionConflict)?,
            )?;
        }
        let revision = state
            .fleet
            .authority_revision
            .checked_add(1)
            .ok_or(Error::RevisionOverflow)?;
        let new = old.commit(expected, &proof, revision, now, config)?;
        let placement = new.placement.clone().ok_or(Error::CorruptState)?;
        let scope = (
            placement.entry.key().tenant_id().clone(),
            placement.entry.key().session_id().clone(),
        );
        if old.placement.is_some() {
            return Ok(placement);
        }
        if state.sessions.contains_key(&scope) || state.fleet.placements.contains_key(&scope) {
            return Err(Error::AdmissionConflict);
        }
        let action_placement = placement.authority.action_placement()?;
        state.fleet.replace(config, Some(&old), new)?;
        state.fleet.authority_revision = revision;
        state
            .fleet
            .placements
            .insert(scope.clone(), expected.request.key.clone());
        state
            .sessions
            .insert(scope, GatewayActionSessionState::new(action_placement));
        Ok(placement)
    }
    fn fleet_placement(
        &self,
        state: &GatewayActionMemoryState,
        key: &DirectoryKey,
    ) -> Result<GatewaySessionPlacementAuthority, Error> {
        let admission = state
            .fleet
            .placements
            .get(&(key.tenant_id().clone(), key.session_id().clone()))
            .ok_or(Error::NotFound)?;
        let row = state.fleet.row(admission)?;
        let place = row.placement.ok_or(Error::CorruptState)?;
        if place.entry.key() != key || place.admission_key != *admission {
            return Err(Error::CorruptState);
        }
        Ok(place)
    }
    pub(super) fn memory_resolve_session_placement(
        &self,
        key: &DirectoryKey,
    ) -> Result<Option<GatewaySessionPlacementAuthority>, Error> {
        let mut state = self
            .database
            .gateway_actions
            .lock()
            .map_err(|_| Error::LockUnavailable)?;
        self.fleet_now(&mut state)?;
        match self.fleet_placement(&state, key) {
            Ok(place) => Ok(Some(place)),
            Err(Error::NotFound) => Ok(None),
            Err(error) => Err(error),
        }
    }
    fn save_placement(
        &self,
        state: &mut GatewayActionMemoryState,
        old: &GatewaySessionPlacementAuthority,
        new: GatewaySessionPlacementAuthority,
    ) -> Result<(), Error> {
        let config = self.fleet_config()?;
        let row = state.fleet.row(&old.admission_key)?;
        if row.placement.as_ref() != Some(old) {
            return Err(Error::CorruptState);
        }
        let mut changed = row.clone();
        changed.revision = changed
            .revision
            .checked_add(1)
            .ok_or(Error::RevisionOverflow)?;
        changed.state = if new.status == GatewaySessionPlacementStatus::Closing {
            GatewaySessionAdmissionState::Closing
        } else {
            row.state
        };
        changed.placement = Some(new);
        state.fleet.replace(config, Some(&row), changed)
    }
    pub(super) fn memory_begin_session_renewal(
        &self,
        expected: &GatewaySessionPlacementAuthority,
        nonce: LeaseId,
        ttl: Duration,
    ) -> Result<GatewaySessionRenewalIntent, Error> {
        let ttl = ttl_millis(ttl)?;
        let mut state = self
            .database
            .gateway_actions
            .lock()
            .map_err(|_| Error::LockUnavailable)?;
        let now = self.fleet_now(&mut state)?;
        let old = self.fleet_placement(&state, &expected.authority.key)?;
        let row = state.fleet.row(&old.admission_key)?;
        self.current_worker(&state, row.reservation.as_ref().ok_or(Error::CorruptState)?)?;
        let (new, intent) = old.begin_renewal(expected, nonce, now, ttl)?;
        if new != old {
            self.save_placement(&mut state, &old, new)?;
        }
        Ok(intent)
    }
    pub(super) fn memory_finish_session_renewal(
        &self,
        intent: &GatewaySessionRenewalIntent,
        proof: GatewaySessionWorkerRenewalProof,
    ) -> Result<GatewaySessionPlacementAuthority, Error> {
        let mut state = self
            .database
            .gateway_actions
            .lock()
            .map_err(|_| Error::LockUnavailable)?;
        let now = self.fleet_now(&mut state)?;
        let old = self.fleet_placement(&state, &intent.authority.key)?;
        let row = state.fleet.row(&old.admission_key)?;
        self.current_worker(&state, row.reservation.as_ref().ok_or(Error::CorruptState)?)?;
        let new = old.finish_renewal(intent, &proof, now)?;
        if new != old {
            self.save_placement(&mut state, &old, new.clone())?;
        }
        Ok(new)
    }
    pub(super) fn memory_begin_session_close(
        &self,
        expected: &GatewaySessionPlacementAuthority,
    ) -> Result<GatewaySessionPlacementAuthority, Error> {
        let mut state = self
            .database
            .gateway_actions
            .lock()
            .map_err(|_| Error::LockUnavailable)?;
        self.fleet_now(&mut state)?;
        let old = self.fleet_placement(&state, &expected.authority.key)?;
        let new = old.close(expected)?;
        if new != old {
            self.save_placement(&mut state, &old, new.clone())?;
        }
        Ok(new)
    }
    pub(super) fn memory_release_session_reservation(
        &self,
        expected: &GatewaySessionAdmissionSnapshot,
        proof: GatewaySessionCleanupProof,
    ) -> Result<GatewaySessionAdmissionSnapshot, Error> {
        let config = self.fleet_config()?;
        let mut state = self
            .database
            .gateway_actions
            .lock()
            .map_err(|_| Error::LockUnavailable)?;
        let now = self.fleet_now(&mut state)?;
        let old = state.fleet.row(&expected.request.key)?;
        let new = old.release(expected, &proof, now)?;
        state.fleet.replace(config, Some(&old), new.clone())?;
        Ok(new)
    }
    pub(super) fn memory_scan_session_admissions(
        &self,
        cursor: GatewaySessionAdmissionCursor,
        limit: usize,
    ) -> Result<GatewaySessionAdmissionPage, Error> {
        if !(1..=MAX_SESSION_ADMISSION_SCAN).contains(&limit) {
            return Err(Error::InvalidSessionAdmission);
        }
        cursor.validate()?;
        let config = self.fleet_config()?;
        let mut state = self
            .database
            .gateway_actions
            .lock()
            .map_err(|_| Error::LockUnavailable)?;
        let now = self.fleet_now(&mut state)?;
        let start = cursor
            .after
            .map(|(tenant, operation)| GatewaySessionAdmissionKey::new(tenant, operation));
        let bound = start.as_ref().map_or(Unbounded, Excluded);
        let keys: Vec<_> = state
            .fleet
            .records
            .range((bound, Unbounded))
            .take(limit)
            .map(|(key, _)| key.clone())
            .collect();
        let mut admissions = Vec::new();
        for key in &keys {
            state.fleet.expire_one(config, key, now)?;
            let row = state.fleet.row(key)?;
            if matches!(
                row.state,
                GatewaySessionAdmissionState::Queued
                    | GatewaySessionAdmissionState::Reserved
                    | GatewaySessionAdmissionState::CommitArmed
                    | GatewaySessionAdmissionState::Active
                    | GatewaySessionAdmissionState::Closing
                    | GatewaySessionAdmissionState::Expired
            ) || row.pending_create_projection
            {
                admissions.push(row);
            }
        }
        let complete = keys.len() < limit;
        let next = if complete {
            GatewaySessionAdmissionCursor::default()
        } else {
            GatewaySessionAdmissionCursor::after(keys.last().ok_or(Error::CorruptState)?)
        };
        GatewaySessionAdmissionPage::new(admissions, next, complete, keys.len())
    }
    pub(super) fn memory_ack_session_create_projection(
        &self,
        expected: &GatewaySessionAdmissionSnapshot,
    ) -> Result<GatewaySessionAdmissionSnapshot, Error> {
        let config = self.fleet_config()?;
        let mut state = self
            .database
            .gateway_actions
            .lock()
            .map_err(|_| Error::LockUnavailable)?;
        self.fleet_now(&mut state)?;
        let old = state.fleet.row(&expected.request.key)?;
        let new = old.ack_projection(expected)?;
        state.fleet.replace(config, Some(&old), new.clone())?;
        Ok(new)
    }
    pub(super) fn memory_validate_session_authority(
        &self,
        authority: &GatewaySessionAuthorityRef,
    ) -> Result<(), Error> {
        let mut state = self
            .database
            .gateway_actions
            .lock()
            .map_err(|_| Error::LockUnavailable)?;
        self.authorize_session_action_locked(
            &mut state,
            authority.key.tenant_id(),
            authority.key.session_id(),
            &authority.action_placement()?,
            authority,
            true,
        )
    }
    pub(super) fn fleet_action_now(
        &self,
        state: &mut GatewayActionMemoryState,
        caller: chrono::DateTime<Utc>,
    ) -> Result<chrono::DateTime<Utc>, Error> {
        let now = self.fleet_now(state)?;
        let trusted = chrono::DateTime::from_timestamp_millis(
            i64::try_from(now).map_err(|_| Error::InvalidSessionAdmission)?,
        )
        .ok_or(Error::InvalidSessionAdmission)?;
        Ok(caller.max(trusted))
    }
    pub(super) fn authorize_session_action_locked(
        &self,
        state: &mut GatewayActionMemoryState,
        tenant: &TenantId,
        session: &SessionId,
        placement: &GatewayActionPlacement,
        authority: &GatewaySessionAuthorityRef,
        require_live: bool,
    ) -> Result<(), Error> {
        let now = self.fleet_now(state)?;
        let key = DirectoryKey::new(tenant.clone(), session.clone());
        let current = self.fleet_placement(state, &key).map_err(|error| {
            if error == Error::NotFound {
                Error::SessionAuthorityUnavailable
            } else {
                error
            }
        })?;
        if current.authority != *authority || authority.action_placement()? != *placement {
            return Err(Error::PlacementMismatch);
        }
        let action_session = state
            .sessions
            .get(&(tenant.clone(), session.clone()))
            .ok_or(Error::CorruptState)?;
        if action_session.placement != *placement {
            return Err(Error::CorruptState);
        }
        if require_live && action_session.loss.is_some() {
            return Err(Error::SessionAuthorityUnavailable);
        }
        if require_live {
            let row = state.fleet.row(&current.admission_key)?;
            self.current_worker(state, row.reservation.as_ref().ok_or(Error::CorruptState)?)?;
        }
        if require_live
            && (current.status != GatewaySessionPlacementStatus::Ready
                || current.expires_at_millis <= now)
        {
            return Err(Error::SessionAuthorityUnavailable);
        }
        Ok(())
    }
}
