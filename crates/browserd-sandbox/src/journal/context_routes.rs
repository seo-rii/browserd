use super::*;
use crate::{ContextEgressRequest, ContextRoutePolicy, DedicatedEgressProxyBinding};
use browserd_core::LeaseId;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextRoutePhase {
    Intent,
    Active,
    Releasing,
    Released,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContextRouteJournalEntry {
    request: ContextEgressRequest,
    reservation_generation: LeaseId,
    egress_daemon_epoch: u64,
    phase: ContextRoutePhase,
    binding: Option<DedicatedEgressProxyBinding>,
}
impl ContextRouteJournalEntry {
    pub const fn request(&self) -> &ContextEgressRequest {
        &self.request
    }
    pub const fn egress_daemon_epoch(&self) -> u64 {
        self.egress_daemon_epoch
    }
    pub const fn phase(&self) -> ContextRoutePhase {
        self.phase
    }
    pub const fn reservation_generation(&self) -> &LeaseId {
        &self.reservation_generation
    }
    pub const fn binding(&self) -> Option<&DedicatedEgressProxyBinding> {
        self.binding.as_ref()
    }
}

impl PreparedShardJournalRecord {
    pub fn context_routes(&self) -> &[ContextRouteJournalEntry] {
        &self.context_routes
    }
}
impl FilePreparedShardJournal {
    pub fn configure_context_routes(
        &self,
        fence: &ShardFence,
        policy: ContextRoutePolicy,
    ) -> Result<(), PreparedShardJournalError> {
        policy
            .validate()
            .map_err(|_| PreparedShardJournalError::InvalidHistory)?;
        self.edit_context_routes(fence, |record| {
            match &record.context_route_policy {
                Some(old) if old != &policy => {
                    return Err(PreparedShardJournalError::ReservationConflict);
                }
                Some(_) => return Ok(()),
                None => record.context_route_policy = Some(policy),
            }
            Ok(())
        })
    }
    pub fn reserve_context_route(
        &self,
        request: ContextEgressRequest,
        generation: LeaseId,
        egress_daemon_epoch: u64,
        cancelling: bool,
    ) -> Result<ContextRouteJournalEntry, PreparedShardJournalError> {
        request
            .validate()
            .map_err(|_| PreparedShardJournalError::InvalidHistory)?;
        let fence = request.egress().egress_fence().shard().clone();
        self.edit_context_routes(&fence, |record| {
            let policy = record
                .context_route_policy
                .as_ref()
                .ok_or(PreparedShardJournalError::InvalidHistory)?;
            if let Some(old) = record
                .context_routes
                .iter()
                .find(|row| row.request.egress().egress_fence() == request.egress().egress_fence())
            {
                if old.request != request || old.egress_daemon_epoch != egress_daemon_epoch {
                    return Err(PreparedShardJournalError::ReservationConflict);
                }
                return Ok(());
            }
            if record.context_routes.len() >= usize::from(policy.max_lifetime_routes())
                || (!cancelling
                    && record
                        .context_routes
                        .iter()
                        .filter(|row| row.phase != ContextRoutePhase::Released)
                        .count()
                        >= usize::from(policy.max_live_routes()))
            {
                return Err(PreparedShardJournalError::LimitExceeded);
            }
            if record.context_routes.iter().any(|row| {
                row.request.egress().egress_fence().session_id()
                    == request.egress().egress_fence().session_id()
            }) {
                return Err(PreparedShardJournalError::ReservationConflict);
            }
            record.context_routes.push(ContextRouteJournalEntry {
                request: request.clone(),
                reservation_generation: generation,
                egress_daemon_epoch,
                phase: if cancelling {
                    ContextRoutePhase::Releasing
                } else {
                    ContextRoutePhase::Intent
                },
                binding: None,
            });
            Ok(())
        })?;
        self.records()?
            .into_iter()
            .find(|row| row.fence() == &fence)
            .and_then(|row| {
                row.context_routes
                    .into_iter()
                    .find(|row| row.request == request)
            })
            .ok_or(PreparedShardJournalError::RecordNotFound)
    }
    pub fn set_context_route_phase(
        &self,
        request: &ContextEgressRequest,
        phase: ContextRoutePhase,
        binding: Option<DedicatedEgressProxyBinding>,
    ) -> Result<(), PreparedShardJournalError> {
        self.edit_context_routes(request.egress().egress_fence().shard(), |record| {
            let row = record
                .context_routes
                .iter_mut()
                .find(|row| &row.request == request)
                .ok_or(PreparedShardJournalError::RecordNotFound)?;
            if row.phase == phase {
                if phase == ContextRoutePhase::Active && row.binding != binding {
                    return Err(PreparedShardJournalError::ReservationConflict);
                }
                return Ok(());
            }
            if !matches!(
                (row.phase, phase),
                (
                    ContextRoutePhase::Intent,
                    ContextRoutePhase::Active | ContextRoutePhase::Releasing
                ) | (ContextRoutePhase::Active, ContextRoutePhase::Releasing)
                    | (ContextRoutePhase::Releasing, ContextRoutePhase::Released)
            ) {
                return Err(PreparedShardJournalError::InvalidHistory);
            }
            if phase == ContextRoutePhase::Active {
                row.binding = binding;
            }
            row.phase = phase;
            Ok(())
        })
    }
    fn edit_context_routes(
        &self,
        fence: &ShardFence,
        edit: impl FnOnce(&mut PreparedShardJournalRecord) -> Result<(), PreparedShardJournalError>,
    ) -> Result<(), PreparedShardJournalError> {
        let key = record_key(fence)?;
        let mut records = self.lock_records()?;
        let old = records
            .get(&key)
            .ok_or(PreparedShardJournalError::RecordNotFound)?;
        if old.fence() != fence
            || old.recovery_disposition() == PreparedShardRecoveryDisposition::ReleasedTombstone
        {
            return Err(PreparedShardJournalError::FenceMismatch);
        }
        let mut updated = old.clone();
        edit(&mut updated)?;
        if &updated == old {
            return Ok(());
        }
        validate_record(&updated)?;
        self.ensure_capacity(&records, Some(&key), &updated)?;
        self.persist_record(&key, &updated)?;
        records.insert(key, updated);
        Ok(())
    }
}

pub(super) fn validate_context_routes(
    record: &PreparedShardJournalRecord,
) -> Result<(), PreparedShardJournalError> {
    let Some(policy) = &record.context_route_policy else {
        return if record.context_routes.is_empty() {
            Ok(())
        } else {
            Err(PreparedShardJournalError::InvalidHistory)
        };
    };
    policy
        .validate()
        .map_err(|_| PreparedShardJournalError::InvalidHistory)?;
    if record.context_routes.len() > usize::from(policy.max_lifetime_routes()) {
        return Err(PreparedShardJournalError::LimitExceeded);
    }
    if let Some(primary) = record.context_routes.first()
        && (Some(primary.request.egress().egress_fence()) != record.locators.egress_fence()
            || primary.request.placement() != policy.initial_placement())
    {
        return Err(PreparedShardJournalError::InvalidHistory);
    }
    let mut sessions = BTreeSet::new();
    for row in &record.context_routes {
        if let Some(primary) = record.context_routes.first()
            && (row.request.egress().policy_binding() != primary.request.egress().policy_binding()
                || (policy.tenant_dedicated()
                    && row.request.tenant_id() != primary.request.tenant_id()))
        {
            return Err(PreparedShardJournalError::InvalidHistory);
        }
        row.request
            .validate()
            .map_err(|_| PreparedShardJournalError::InvalidHistory)?;
        if row.request.egress().egress_fence().shard() != record.fence()
            || row.egress_daemon_epoch == 0
            || Some(row.egress_daemon_epoch) != record.locators.egress_daemon_epoch()
            || row.reservation_generation.as_bytes() == &[0; 16]
            || !sessions.insert(row.request.egress().egress_fence().session_id())
        {
            return Err(PreparedShardJournalError::InvalidHistory);
        }
        if row.phase == ContextRoutePhase::Active && row.binding.is_none() {
            return Err(PreparedShardJournalError::InvalidHistory);
        }
        if let Some(binding) = &row.binding
            && (binding.tenant_id() != row.request.tenant_id()
                || binding.egress_fence() != row.request.egress().egress_fence()
                || binding.policy_binding() != row.request.egress().policy_binding()
                || binding.reservation_generation() != &row.reservation_generation)
        {
            return Err(PreparedShardJournalError::InvalidHistory);
        }
    }
    Ok(())
}
