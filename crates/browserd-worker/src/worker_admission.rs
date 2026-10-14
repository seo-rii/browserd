//! Worker-local admission; every debit and create transfer shares the control-plane lock.
mod rpc_client;
#[cfg(test)]
mod tests;
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use browserd_core::{LeaseId, TenantId, WorkerId};
pub use browserd_fleet::ResourceVector;
pub use browserd_fleet::ResourceVector as FleetResourceVector;
use browserd_session::{OwnershipFence, SessionLifecycle};
use serde::{Deserialize, Serialize};

use crate::{
    AuthenticatedPeer, ChromiumDriver, CreateSessionCommand, SandboxClient, WorkerControlPlane,
    WorkerCreateSessionReceipt, WorkerCreateSessionRequest, WorkerError, WorkerIsolationProfile,
    WorkerSessionFence, WorkerSessionReceipt,
};

fn ownership_remaining_millis(machine: &browserd_session::SessionMachine, now: u64) -> u64 {
    let snapshot = machine.snapshot();
    [
        snapshot.lease_expires_at,
        snapshot.session_expires_at,
        snapshot.idle_expires_at,
    ]
    .into_iter()
    .map(|deadline| deadline.map_or(0, |value| value.get().saturating_sub(now)))
    .min()
    .unwrap_or(0)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WorkerTenantAssignment {
    worker_id: WorkerId,
    tenant_id: TenantId,
    assignment_digest: [u8; 32],
}
impl WorkerTenantAssignment {
    pub fn new(
        worker_id: WorkerId,
        tenant_id: TenantId,
        assignment_digest: [u8; 32],
    ) -> Result<Self, WorkerError> {
        if assignment_digest == [0; 32] {
            return Err(WorkerError::InvalidConfiguration);
        }
        Ok(Self {
            worker_id,
            tenant_id,
            assignment_digest,
        })
    }
    pub const fn worker_id(&self) -> &WorkerId {
        &self.worker_id
    }
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }
    pub const fn assignment_digest(&self) -> &[u8; 32] {
        &self.assignment_digest
    }
}
impl<'de> Deserialize<'de> for WorkerTenantAssignment {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            worker_id: WorkerId,
            tenant_id: TenantId,
            assignment_digest: [u8; 32],
        }
        let w = Wire::deserialize(d)?;
        Self::new(w.worker_id, w.tenant_id, w.assignment_digest)
            .map_err(|_| serde::de::Error::custom("invalid worker assignment"))
    }
}

#[derive(Clone, Debug)]
pub struct WorkerAdmissionPolicy {
    compatibility_digest: [u8; 32],
    capacity: ResourceVector,
    budgets: Vec<WorkerAdmissionBudget>,
    retained_tokens: usize,
    exclusive: Option<WorkerTenantAssignment>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerAdmissionBudget {
    pub profile_digest: [u8; 32],
    pub isolation: WorkerIsolationProfile,
    pub resources: ResourceVector,
}
impl WorkerAdmissionPolicy {
    pub fn new(
        compatibility_digest: [u8; 32],
        capacity: ResourceVector,
        budgets: Vec<WorkerAdmissionBudget>,
        retained_tokens: usize,
        exclusive: Option<WorkerTenantAssignment>,
    ) -> Result<Self, WorkerError> {
        if compatibility_digest == [0; 32]
            || capacity.contexts == 0
            || budgets.is_empty()
            || budgets.len() > 128
            || !(1..=65_536).contains(&retained_tokens)
        {
            return Err(WorkerError::InvalidConfiguration);
        }
        for (index, budget) in budgets.iter().enumerate() {
            if budget.profile_digest == [0; 32]
                || budget.resources.contexts != 1
                || !budget.resources.fits_within(capacity)
                || budgets[..index]
                    .iter()
                    .any(|b| b.profile_digest == budget.profile_digest)
                || (budget.isolation == WorkerIsolationProfile::DedicatedWorker
                    && exclusive.is_none())
            {
                return Err(WorkerError::InvalidConfiguration);
            }
        }
        if exclusive.is_some()
            && !budgets
                .iter()
                .any(|b| b.isolation == WorkerIsolationProfile::DedicatedWorker)
        {
            return Err(WorkerError::InvalidConfiguration);
        }
        Ok(Self {
            compatibility_digest,
            capacity,
            budgets,
            retained_tokens,
            exclusive,
        })
    }
    pub(crate) fn validate(
        &self,
        worker_id: &WorkerId,
        max_sessions: usize,
    ) -> Result<(), WorkerError> {
        if self.capacity.contexts
            > u64::try_from(max_sessions).map_err(|_| WorkerError::InvalidConfiguration)?
            || self
                .exclusive
                .as_ref()
                .is_some_and(|a| a.worker_id() != worker_id)
        {
            return Err(WorkerError::InvalidConfiguration);
        }
        Ok(())
    }
    pub const fn exclusive_assignment(&self) -> Option<&WorkerTenantAssignment> {
        self.exclusive.as_ref()
    }
    pub const fn compatibility_digest(&self) -> [u8; 32] {
        self.compatibility_digest
    }
    pub const fn capacity(&self) -> ResourceVector {
        self.capacity
    }
    fn budget(&self, digest: [u8; 32]) -> Option<&WorkerAdmissionBudget> {
        self.budgets.iter().find(|b| b.profile_digest == digest)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerReservationRequest {
    pub request: WorkerCreateSessionRequest,
    pub reservation_id: LeaseId,
    pub expected_worker_boot_nonce: LeaseId,
    pub compatibility_digest: [u8; 32],
    pub profile_digest: [u8; 32],
    pub resources: ResourceVector,
    pub ttl_millis: u64,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerReservationToken {
    pub request: WorkerReservationRequest,
    pub worker_id: WorkerId,
    pub worker_reservation_nonce: LeaseId,
    pub debit_sequence: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerReservationPhase {
    Reserved,
    ExposurePossible,
    Active,
    Released,
    Cancelled,
    Expired,
}
impl WorkerReservationPhase {
    fn charged(self) -> bool {
        matches!(self, Self::Reserved | Self::ExposurePossible | Self::Active)
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerCapacityReceipt {
    pub worker_id: WorkerId,
    pub worker_epoch: u64,
    pub worker_boot_nonce: LeaseId,
    pub compatibility_digest: [u8; 32],
    pub capacity_revision: u64,
    pub acknowledged_debit_sequence: u64,
    pub capacity: ResourceVector,
    pub raw_free: ResourceVector,
    pub ready: bool,
    pub draining: bool,
    pub exclusive_assignment: Option<WorkerTenantAssignment>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerReservationReceipt {
    pub token: WorkerReservationToken,
    pub phase: WorkerReservationPhase,
    pub capacity: WorkerCapacityReceipt,
    pub remaining_ttl_millis: u64,
    pub session: Option<WorkerCreateSessionReceipt>,
    pub session_lease_remaining_millis: Option<u64>,
    #[serde(default)]
    pub disposed_session: Option<WorkerSessionFence>,
}

#[derive(Default)]
pub(crate) struct WorkerReservedCreateProgress {
    pub(crate) exposure_possible: bool,
    pub(crate) disposed_session: Option<WorkerSessionFence>,
}
pub(crate) struct WorkerCreateReservation<'a> {
    pub(crate) token: &'a WorkerReservationToken,
    pub(crate) progress: &'a mut WorkerReservedCreateProgress,
}
impl WorkerCreateReservation<'_> {
    pub(crate) fn confirm_disposed(
        &mut self,
        tenant: &TenantId,
        session: &browserd_core::SessionId,
        fence: &OwnershipFence,
    ) {
        self.progress.disposed_session = Some(WorkerSessionFence {
            tenant_id: tenant.clone(),
            session_id: session.clone(),
            worker_epoch: fence.worker_epoch(),
            placement_version: fence.placement_version(),
            session_incarnation: fence.session_incarnation(),
        });
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerReservedSessionRenewReceipt {
    pub token: WorkerReservationToken,
    pub renewal_nonce: LeaseId,
    pub expected_lease_revision: u64,
    pub granted_ttl_millis: u64,
    pub session: WorkerSessionReceipt,
}

struct ReservationRecord {
    token: WorkerReservationToken,
    phase: WorkerReservationPhase,
    deadline: Instant,
    transferred: bool,
    session: Option<WorkerCreateSessionReceipt>,
    disposed_session: Option<WorkerSessionFence>,
    cleanup_acknowledged: bool,
    terminal_at: Option<Instant>,
    lease_revision: u64,
    last_renewal: Option<WorkerReservedSessionRenewReceipt>,
    used_renewals: BTreeMap<LeaseId, u64>,
}
pub(crate) struct WorkerAdmissionState {
    boot_nonce: LeaseId,
    revision: u64,
    debit_sequence: u64,
    records: BTreeMap<LeaseId, ReservationRecord>,
    observed: Option<(ResourceVector, bool, bool, u64)>,
    retained_renewal_nonces: usize,
}
impl WorkerAdmissionState {
    pub(crate) fn new() -> Self {
        Self {
            boot_nonce: LeaseId::new(),
            revision: 1,
            debit_sequence: 0,
            records: BTreeMap::new(),
            observed: None,
            retained_renewal_nonces: 0,
        }
    }
    fn record(&self, token: &WorkerReservationToken) -> Result<&ReservationRecord, WorkerError> {
        self.records
            .get(&token.request.reservation_id)
            .filter(|r| r.token == *token)
            .ok_or(WorkerError::InvalidConfiguration)
    }
    pub(crate) fn validate_creating(
        &self,
        token: &WorkerReservationToken,
        command: &CreateSessionCommand,
    ) -> Result<(), WorkerError> {
        let r = self.record(token)?;
        let request = &token.request.request;
        if r.phase != WorkerReservationPhase::ExposurePossible
            || r.transferred
            || request.tenant_id != command.tenant_id
            || request.idempotency_key != command.idempotency_key
            || request.canonical_request_hash != command.canonical_request_hash
            || request.placement_version != command.placement_version
            || request.session_incarnation != command.session_incarnation
        {
            return Err(WorkerError::InvalidConfiguration);
        }
        Ok(())
    }
    pub(crate) fn begin_transfer(
        &mut self,
        token: &WorkerReservationToken,
    ) -> Result<(), WorkerError> {
        self.record(token)?;
        self.records
            .get_mut(&token.request.reservation_id)
            .ok_or(WorkerError::StateUnavailable)?
            .transferred = true;
        Ok(())
    }
    pub(crate) fn pending_slots_except(&self, token: Option<&WorkerReservationToken>) -> usize {
        self.records
            .values()
            .filter(|r| {
                r.phase.charged()
                    && r.session.is_none()
                    && !r.transferred
                    && token.is_none_or(|t| t != &r.token)
            })
            .count()
    }
}

impl<D: ChromiumDriver, S: SandboxClient> WorkerControlPlane<D, S> {
    pub(crate) fn reserved_create_isolation(
        &self,
        request: &WorkerReservationRequest,
    ) -> Result<WorkerIsolationProfile, WorkerError> {
        let policy = self
            .config
            .admission_policy
            .as_ref()
            .ok_or(WorkerError::InvalidConfiguration)?;
        let budget = policy
            .budget(request.profile_digest)
            .ok_or(WorkerError::InvalidConfiguration)?;
        if request.compatibility_digest != policy.compatibility_digest
            || budget.resources != request.resources
            || !request
                .request
                .requested_isolation
                .satisfied_by(budget.isolation)
        {
            return Err(WorkerError::InvalidConfiguration);
        }
        Ok(budget.isolation)
    }

    pub(crate) fn refresh_admissions(
        &self,
        worker: &mut crate::WorkerState,
        now: Instant,
    ) -> Result<(), WorkerError> {
        for r in worker.admission.records.values_mut() {
            let terminal = if r.phase == WorkerReservationPhase::Reserved && now >= r.deadline {
                Some(WorkerReservationPhase::Expired)
            } else if r.phase == WorkerReservationPhase::Active {
                if let Some(receipt) = &r.session {
                    if let Some(executor) = worker.sessions.get(&receipt.session_id) {
                        let session = executor
                            .state
                            .lock()
                            .map_err(|_| WorkerError::StateUnavailable)?;
                        let fence = OwnershipFence::new(
                            self.config.worker_id.clone(),
                            receipt.worker_epoch,
                            receipt.placement_version,
                            receipt.session_incarnation,
                        );
                        if session.tenant_id != receipt.tenant_id
                            || session.machine.snapshot().owner_fence != fence
                        {
                            return Err(WorkerError::StateUnavailable);
                        }
                        if !session.occupies_capacity {
                            Some(WorkerReservationPhase::Released)
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    return Err(WorkerError::StateUnavailable);
                }
            } else {
                None
            };
            if let Some(phase) = terminal {
                r.phase = phase;
                r.terminal_at = Some(now);
            }
        }
        // Never discard exposure or active records. Terminal replay identity has a 24h floor.
        let reclaim: Vec<_> = worker
            .admission
            .records
            .iter()
            .filter(|(_, r)| {
                r.cleanup_acknowledged
                    && r.terminal_at.is_some_and(|t| {
                        now.saturating_duration_since(t) >= Duration::from_secs(86400)
                    })
            })
            .take(64)
            .map(|(id, _)| id.clone())
            .collect();
        for id in reclaim {
            if let Some(record) = worker.admission.records.remove(&id) {
                worker.admission.retained_renewal_nonces = worker
                    .admission
                    .retained_renewal_nonces
                    .checked_sub(record.used_renewals.len())
                    .ok_or(WorkerError::StateUnavailable)?;
            }
        }
        Ok(())
    }
    fn admission_capacity_locked(
        &self,
        worker: &mut crate::WorkerState,
        ready: bool,
    ) -> Result<WorkerCapacityReceipt, WorkerError> {
        let policy = self
            .config
            .admission_policy
            .as_ref()
            .ok_or(WorkerError::InvalidConfiguration)?;
        self.refresh_admissions(worker, Instant::now())?;
        let used = worker
            .admission
            .records
            .values()
            .filter(|r| r.phase.charged())
            .try_fold(ResourceVector::ZERO, |sum, r| {
                sum.checked_add(r.token.request.resources)
                    .ok_or(WorkerError::StateUnavailable)
            })?;
        let raw_free = policy
            .capacity
            .checked_sub(used)
            .ok_or(WorkerError::StateUnavailable)?;
        let draining = worker.draining || worker.stopped;
        let ready = ready && !draining && !worker.create_cleanup_failed;
        let observation = (raw_free, draining, ready, worker.admission.debit_sequence);
        if worker.admission.observed != Some(observation) {
            worker.admission.revision = worker
                .admission
                .revision
                .checked_add(1)
                .ok_or(WorkerError::StateUnavailable)?;
            worker.admission.observed = Some(observation);
        }
        Ok(WorkerCapacityReceipt {
            worker_id: self.config.worker_id.clone(),
            worker_epoch: self.config.worker_epoch,
            worker_boot_nonce: worker.admission.boot_nonce.clone(),
            compatibility_digest: policy.compatibility_digest,
            capacity_revision: worker.admission.revision,
            acknowledged_debit_sequence: worker.admission.debit_sequence,
            capacity: policy.capacity,
            raw_free,
            ready,
            draining,
            exclusive_assignment: policy.exclusive.clone(),
        })
    }
    pub fn capacity_status(
        &self,
        peer: &AuthenticatedPeer,
        expected_epoch: u64,
    ) -> Result<WorkerCapacityReceipt, WorkerError> {
        self.authorize(peer)?;
        if expected_epoch != 0 && expected_epoch != self.config.worker_epoch {
            return Err(WorkerError::InvalidConfiguration);
        }
        let ready = self.is_ready();
        let mut worker = self.lock_worker()?;
        self.admission_capacity_locked(&mut worker, ready)
    }
    fn reservation_receipt_locked(
        &self,
        worker: &mut crate::WorkerState,
        token: &WorkerReservationToken,
        ready: bool,
    ) -> Result<WorkerReservationReceipt, WorkerError> {
        let capacity = self.admission_capacity_locked(worker, ready)?;
        let r = worker.admission.record(token)?;
        let remaining_ttl_millis = u64::try_from(
            r.deadline
                .saturating_duration_since(Instant::now())
                .as_millis(),
        )
        .map_err(|_| WorkerError::StateUnavailable)?;
        let session_lease_remaining_millis = if let Some(receipt) = &r.session {
            worker
                .sessions
                .get(&receipt.session_id)
                .map(|executor| {
                    let session = executor
                        .state
                        .lock()
                        .map_err(|_| WorkerError::StateUnavailable)?;
                    let now = self
                        .clock
                        .now()?
                        .max(session.machine.last_observed_at())
                        .get();
                    Ok::<_, WorkerError>(ownership_remaining_millis(&session.machine, now))
                })
                .transpose()?
        } else {
            None
        };
        Ok(WorkerReservationReceipt {
            token: token.clone(),
            phase: r.phase,
            capacity,
            remaining_ttl_millis,
            session: r.session.clone(),
            session_lease_remaining_millis,
            disposed_session: r.disposed_session.clone(),
        })
    }
    pub fn reserve_session(
        &self,
        peer: &AuthenticatedPeer,
        request: WorkerReservationRequest,
    ) -> Result<WorkerReservationReceipt, WorkerError> {
        self.authorize(peer)?;
        let policy = self
            .config
            .admission_policy
            .as_ref()
            .ok_or(WorkerError::InvalidConfiguration)?;
        let selected_isolation = self.reserved_create_isolation(&request)?;
        if !request.request.is_valid()
            || request.request.expected_worker_epoch != self.config.worker_epoch
            || request.compatibility_digest != policy.compatibility_digest
            || !(1..=300_000).contains(&request.ttl_millis)
            || policy
                .exclusive
                .as_ref()
                .is_some_and(|a| a.tenant_id() != &request.request.tenant_id)
            || !self.driver.supports_requested_isolation(selected_isolation)
            || self
                .config
                .session_option_support
                .as_ref()
                .is_some_and(|s| s.unsupported_option(&request.request.options).is_some())
        {
            return Err(WorkerError::InvalidConfiguration);
        }
        let ready = self.is_ready();
        let mut worker = self.lock_worker()?;
        if request.expected_worker_boot_nonce != worker.admission.boot_nonce {
            return Err(WorkerError::InvalidConfiguration);
        }
        self.refresh_admissions(&mut worker, Instant::now())?;
        if let Some(existing) = worker.admission.records.get(&request.reservation_id) {
            if existing.token.request != request {
                return Err(WorkerError::IdempotencyConflict);
            }
            let token = existing.token.clone();
            return self.reservation_receipt_locked(&mut worker, &token, ready);
        }
        if !ready || worker.draining || worker.stopped {
            return Err(WorkerError::NotReady);
        }
        if self.runtime_create_isolation(
            &request.request.tenant_id,
            Some(&request.request.options),
            Some(request.request.requested_isolation),
        )? != selected_isolation
        {
            return Err(WorkerError::InvalidConfiguration);
        }
        if worker.admission.records.len() >= policy.retained_tokens {
            return Err(WorkerError::CapacityExceeded);
        }
        if worker.admission.records.values().any(|r| {
            r.token.request.request.tenant_id == request.request.tenant_id
                && r.token.request.request.idempotency_key == request.request.idempotency_key
                && (r.token.request.request.operation_id != request.request.operation_id
                    || r.token.request.request.canonical_request_hash
                        != request.request.canonical_request_hash
                    || !matches!(
                        r.phase,
                        WorkerReservationPhase::Cancelled | WorkerReservationPhase::Expired
                    ))
        }) {
            return Err(WorkerError::IdempotencyConflict);
        }
        let capacity = self.admission_capacity_locked(&mut worker, ready)?;
        if !request.resources.fits_within(capacity.raw_free) {
            return Err(WorkerError::CapacityExceeded);
        }
        let next = worker
            .admission
            .debit_sequence
            .checked_add(1)
            .ok_or(WorkerError::StateUnavailable)?;
        let deadline = Instant::now()
            .checked_add(Duration::from_millis(request.ttl_millis))
            .ok_or(WorkerError::InvalidConfiguration)?;
        let token = WorkerReservationToken {
            request,
            worker_id: self.config.worker_id.clone(),
            worker_reservation_nonce: LeaseId::new(),
            debit_sequence: next,
        };
        worker.admission.debit_sequence = next;
        worker.admission.records.insert(
            token.request.reservation_id.clone(),
            ReservationRecord {
                token: token.clone(),
                phase: WorkerReservationPhase::Reserved,
                deadline,
                transferred: false,
                session: None,
                disposed_session: None,
                cleanup_acknowledged: false,
                terminal_at: None,
                lease_revision: 1,
                last_renewal: None,
                used_renewals: BTreeMap::new(),
            },
        );
        self.reservation_receipt_locked(&mut worker, &token, ready)
    }
    pub fn inspect_session_reservation(
        &self,
        peer: &AuthenticatedPeer,
        token: &WorkerReservationToken,
    ) -> Result<WorkerReservationReceipt, WorkerError> {
        self.authorize(peer)?;
        let ready = self.is_ready();
        let mut worker = self.lock_worker()?;
        worker.admission.record(token)?;
        self.reservation_receipt_locked(&mut worker, token, ready)
    }
    pub fn cancel_session_reservation(
        &self,
        peer: &AuthenticatedPeer,
        token: &WorkerReservationToken,
    ) -> Result<WorkerReservationReceipt, WorkerError> {
        self.authorize(peer)?;
        let ready = self.is_ready();
        let mut worker = self.lock_worker()?;
        self.refresh_admissions(&mut worker, Instant::now())?;
        let phase = worker.admission.record(token)?.phase;
        if phase == WorkerReservationPhase::Reserved {
            let r = worker
                .admission
                .records
                .get_mut(&token.request.reservation_id)
                .ok_or(WorkerError::StateUnavailable)?;
            r.phase = WorkerReservationPhase::Cancelled;
            r.terminal_at = Some(Instant::now());
        } else if !matches!(
            phase,
            WorkerReservationPhase::Cancelled
                | WorkerReservationPhase::Expired
                | WorkerReservationPhase::Released
        ) {
            return Err(WorkerError::InvalidConfiguration);
        }
        self.reservation_receipt_locked(&mut worker, token, ready)
    }
    pub fn commit_reserved_session(
        &self,
        peer: &AuthenticatedPeer,
        token: &WorkerReservationToken,
    ) -> Result<WorkerReservationReceipt, WorkerError> {
        self.authorize(peer)?;
        let ready = self.is_ready();
        let create_now = self.clock.now()?;
        {
            let mut worker = self.lock_worker()?;
            self.refresh_admissions(&mut worker, Instant::now())?;
            let phase = worker.admission.record(token)?.phase;
            if phase != WorkerReservationPhase::Reserved {
                return self.reservation_receipt_locked(&mut worker, token, ready);
            }
            if worker.draining || worker.stopped {
                return Err(WorkerError::Draining);
            }
            worker
                .admission
                .records
                .get_mut(&token.request.reservation_id)
                .ok_or(WorkerError::StateUnavailable)?
                .phase = WorkerReservationPhase::ExposurePossible;
        }
        let request = &token.request.request;
        let mut progress = WorkerReservedCreateProgress::default();
        let result = self.create_session_internal(
            peer,
            CreateSessionCommand {
                tenant_id: request.tenant_id.clone(),
                idempotency_key: request.idempotency_key.clone(),
                canonical_request_hash: request.canonical_request_hash,
                placement_version: request.placement_version,
                session_incarnation: request.session_incarnation,
            },
            Some(&request.options),
            Some(request.requested_isolation),
            create_now,
            Some(WorkerCreateReservation {
                token,
                progress: &mut progress,
            }),
        );
        let ready = self.is_ready();
        let mut worker = self.lock_worker()?;
        let r = worker
            .admission
            .records
            .get_mut(&token.request.reservation_id)
            .ok_or(WorkerError::StateUnavailable)?;
        r.transferred = false;
        if let Ok(outcome) = result {
            r.session = Some(WorkerCreateSessionReceipt {
                operation_id: request.operation_id.clone(),
                tenant_id: request.tenant_id.clone(),
                session_id: outcome.session_id,
                session_incarnation: request.session_incarnation,
                effective_isolation: outcome.effective_isolation,
                primary_page_id: outcome.primary_page_id,
                worker_epoch: request.expected_worker_epoch,
                placement_version: request.placement_version,
                existing: outcome.existing,
                restored_checkpoint: outcome.restored_checkpoint.map(|s| {
                    crate::WorkerCheckpointRestoreReceipt {
                        checkpoint_ref: s.checkpoint_ref,
                        source_session_id: s.source_session_id,
                    }
                }),
            });
            r.phase = WorkerReservationPhase::Active;
        } else if let Some(disposed) = progress.disposed_session {
            r.disposed_session = Some(disposed);
            r.phase = WorkerReservationPhase::Released;
            r.terminal_at = Some(Instant::now());
        } else if !progress.exposure_possible {
            r.phase = WorkerReservationPhase::Cancelled;
            r.terminal_at = Some(Instant::now());
        }
        // An error after arming is uncertainty: keep the exact debit and inspect only.
        self.reservation_receipt_locked(&mut worker, token, ready)
    }
    pub fn ack_session_reservation(
        &self,
        peer: &AuthenticatedPeer,
        token: &WorkerReservationToken,
    ) -> Result<WorkerReservationReceipt, WorkerError> {
        self.authorize(peer)?;
        let ready = self.is_ready();
        let mut worker = self.lock_worker()?;
        self.refresh_admissions(&mut worker, Instant::now())?;
        if !matches!(
            worker.admission.record(token)?.phase,
            WorkerReservationPhase::Cancelled
                | WorkerReservationPhase::Expired
                | WorkerReservationPhase::Released
        ) {
            return Err(WorkerError::InvalidConfiguration);
        }
        let receipt = self.reservation_receipt_locked(&mut worker, token, ready)?;
        worker
            .admission
            .records
            .get_mut(&token.request.reservation_id)
            .ok_or(WorkerError::StateUnavailable)?
            .cleanup_acknowledged = true;
        Ok(receipt)
    }
    pub fn renew_reserved_session(
        &self,
        peer: &AuthenticatedPeer,
        token: &WorkerReservationToken,
        nonce: LeaseId,
        expected_lease_revision: u64,
        requested_ttl_millis: u64,
    ) -> Result<WorkerReservedSessionRenewReceipt, WorkerError> {
        self.authorize(peer)?;
        if !(1..=300_000).contains(&requested_ttl_millis) || expected_lease_revision == 0 {
            return Err(WorkerError::InvalidConfiguration);
        }
        let mut worker = self.lock_worker()?;
        self.refresh_admissions(&mut worker, Instant::now())?;
        let r = worker.admission.record(token)?;
        if r.phase != WorkerReservationPhase::Active {
            return Err(WorkerError::InvalidConfiguration);
        }
        if let Some(existing) = &r.last_renewal
            && existing.renewal_nonce == nonce
        {
            return if existing.expected_lease_revision == expected_lease_revision
                && existing.granted_ttl_millis == requested_ttl_millis
            {
                Ok(existing.clone())
            } else {
                Err(WorkerError::IdempotencyConflict)
            };
        }
        if r.lease_revision != expected_lease_revision {
            return Err(WorkerError::InvalidConfiguration);
        }
        if r.used_renewals.contains_key(&nonce) {
            return Err(WorkerError::IdempotencyConflict);
        }
        if r.used_renewals.len() >= 4096 || worker.admission.retained_renewal_nonces >= 262_144 {
            return Err(WorkerError::CapacityExceeded);
        }
        let next_lease_revision = r
            .lease_revision
            .checked_add(1)
            .ok_or(WorkerError::StateUnavailable)?;
        let receipt = r.session.clone().ok_or(WorkerError::StateUnavailable)?;
        let executor = worker
            .sessions
            .get(&receipt.session_id)
            .ok_or(WorkerError::SessionNotFound)?;
        let mut session = executor
            .state
            .lock()
            .map_err(|_| WorkerError::StateUnavailable)?;
        let fence = OwnershipFence::new(
            self.config.worker_id.clone(),
            receipt.worker_epoch,
            receipt.placement_version,
            receipt.session_incarnation,
        );
        if session.tenant_id != receipt.tenant_id
            || session.machine.lifecycle() != SessionLifecycle::Ready
            || !session.occupies_capacity
        {
            return Err(WorkerError::InvalidConfiguration);
        }
        let now = self.clock.now()?.max(session.machine.last_observed_at());
        let mut next_machine = session.machine.clone();
        next_machine
            .renew_lease(&fence, now)
            .map_err(crate::map_session_error)?;
        let actual = ownership_remaining_millis(&next_machine, self.clock.now()?.max(now).get());
        if actual < requested_ttl_millis {
            return Err(WorkerError::InvalidConfiguration);
        }
        session.machine = next_machine;
        let renewal = WorkerReservedSessionRenewReceipt {
            token: token.clone(),
            renewal_nonce: nonce.clone(),
            expected_lease_revision,
            granted_ttl_millis: requested_ttl_millis,
            session: WorkerSessionReceipt {
                fence: WorkerSessionFence {
                    tenant_id: receipt.tenant_id,
                    session_id: receipt.session_id,
                    worker_epoch: receipt.worker_epoch,
                    placement_version: receipt.placement_version,
                    session_incarnation: receipt.session_incarnation,
                },
                lifecycle: crate::rpc::session_lifecycle(session.machine.lifecycle()),
                primary_page_id: receipt.primary_page_id,
            },
        };
        drop(session);
        let r = worker
            .admission
            .records
            .get_mut(&token.request.reservation_id)
            .ok_or(WorkerError::StateUnavailable)?;
        r.lease_revision = next_lease_revision;
        r.used_renewals.insert(nonce, expected_lease_revision);
        r.last_renewal = Some(renewal.clone());
        worker.admission.retained_renewal_nonces += 1;
        Ok(renewal)
    }
}
