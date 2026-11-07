//! Single-writer target reservations, separate from bootstrap and close effects.
//!
//! `TargetAdmission` records creation permits but does not own live inventory.
//! A reservation here therefore survives bootstrap failure, a close request, and
//! an uncertain close response. Only confirmed exact retirement or confirmed
//! disposal of the owning browser context releases it.

use std::collections::BTreeMap;
use std::time::Duration;

use browserd_core::SessionLimits;
use browserd_targets::{
    TargetAdmission, TargetAdmissionError, TargetInventory, TargetKind, TargetLimits, TargetPolicy,
    TargetTime,
};

use super::{ContextOwnership, valid_identifier};

// Match the actor's existing global bookkeeping bounds. SessionLimits supplies
// the tighter, independent quotas within each registered browser context.
const MAX_REGISTERED_CONTEXTS: usize = 1_024;
const MAX_LIVE_RESERVATIONS: usize = 4_096;
const MAX_RETIRED_RESERVATIONS: usize = 4_096;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct OwnerAdmissionTarget {
    pub(super) context_id: String,
    pub(super) target_id: String,
    pub(super) flattened_session_id: String,
    pub(super) kind: TargetKind,
    pub(super) target_incarnation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct OwnerAdmissionReceipt {
    pub(super) creation_sequence: u64,
    pub(super) target_incarnation: u64,
    pub(super) newly_admitted: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum OwnerAdmissionError {
    InvalidIdentity,
    UnknownContext,
    OwnershipMismatch,
    BindingMismatch,
    ContextClosing,
    TargetClosing,
    StateOverflow,
    Admission(TargetAdmissionError),
}

#[derive(Debug)]
struct ContextAdmission {
    owner: ContextOwnership,
    admission: TargetAdmission,
    closing: bool,
}

#[derive(Clone, Debug)]
struct Reservation {
    target: OwnerAdmissionTarget,
    owner: ContextOwnership,
    creation_sequence: u64,
    closing: bool,
}

impl Reservation {
    fn matches(&self, target: &OwnerAdmissionTarget, owner: &ContextOwnership) -> bool {
        self.target == *target && self.owner == *owner
    }

    fn receipt(&self, newly_admitted: bool) -> OwnerAdmissionReceipt {
        OwnerAdmissionReceipt {
            creation_sequence: self.creation_sequence,
            target_incarnation: self.target.target_incarnation,
            newly_admitted,
        }
    }
}

#[derive(Debug)]
pub(super) struct OwnerTargetAdmissions {
    limits: TargetLimits,
    contexts: BTreeMap<String, ContextAdmission>,
    live: BTreeMap<String, Reservation>,
    // Preserve every retired flattened session so a delayed event can never
    // become authority for a replacement, even if its target ID is reused.
    retired: BTreeMap<String, Reservation>,
    last_observed: Option<TargetTime>,
}

impl Default for OwnerTargetAdmissions {
    fn default() -> Self {
        let limits = SessionLimits::default();
        Self::with_limits(TargetLimits {
            max_pages: limits.max_pages_per_session,
            max_frames: limits.max_frames_per_session,
            max_workers: limits.max_workers_per_session,
            max_service_workers: limits.max_service_workers_per_session,
            max_total_targets: limits.max_targets_per_session,
            max_creations_per_window: limits.max_target_creations_per_10s,
            creation_window: Duration::from_secs(10),
        })
    }
}

impl OwnerTargetAdmissions {
    fn with_limits(limits: TargetLimits) -> Self {
        Self {
            limits,
            contexts: BTreeMap::new(),
            live: BTreeMap::new(),
            retired: BTreeMap::new(),
            last_observed: None,
        }
    }

    pub(super) fn register_context(
        &mut self,
        context_id: &str,
        owner: &ContextOwnership,
    ) -> Result<(), OwnerAdmissionError> {
        if !valid_identifier(context_id)
            || owner.fence.worker_epoch() == 0
            || owner.fence.placement_version() == 0
            || owner.fence.session_incarnation() == 0
        {
            return Err(OwnerAdmissionError::InvalidIdentity);
        }
        if let Some(context) = self.contexts.get(context_id) {
            return if context.owner != *owner {
                Err(OwnerAdmissionError::OwnershipMismatch)
            } else if context.closing {
                Err(OwnerAdmissionError::ContextClosing)
            } else {
                // Registration retries cannot reset the creation window.
                Ok(())
            };
        }
        if self.contexts.len() >= MAX_REGISTERED_CONTEXTS {
            return Err(OwnerAdmissionError::StateOverflow);
        }
        self.contexts.insert(
            context_id.to_owned(),
            ContextAdmission {
                owner: owner.clone(),
                admission: TargetAdmission::new(
                    TargetPolicy::shared_context_default(),
                    self.limits,
                ),
                closing: false,
            },
        );
        Ok(())
    }

    /// Reserve every owned target, including pages and iframes, before bootstrap.
    /// `now` must come from the actor's trusted monotonic clock, never a request.
    /// Quotas and creation rate are checked together, exactly once per binding.
    pub(super) fn admit(
        &mut self,
        target: &OwnerAdmissionTarget,
        owner: &ContextOwnership,
        now: TargetTime,
    ) -> Result<OwnerAdmissionReceipt, OwnerAdmissionError> {
        self.admit_with_ceiling(target, owner, now, self.limits.max_total_targets)
    }

    /// An extra ceiling intersects immutable policy without reconstructing controllers,
    /// releasing uncertain closing reservations, or resetting creation windows/sequences.
    pub(super) fn admit_with_ceiling(
        &mut self,
        target: &OwnerAdmissionTarget,
        owner: &ContextOwnership,
        now: TargetTime,
        runtime_ceiling: u32,
    ) -> Result<OwnerAdmissionReceipt, OwnerAdmissionError> {
        if self.last_observed.is_some_and(|last| now < last) {
            return Err(OwnerAdmissionError::Admission(
                TargetAdmissionError::ClockMovedBackwards,
            ));
        }
        self.last_observed = Some(now);
        Self::validate_identity(target)?;
        let context = self.context(&target.context_id, owner)?;
        if context.closing {
            return Err(OwnerAdmissionError::ContextClosing);
        }
        if let Some(existing) = self.live.get(&target.target_id) {
            if !existing.matches(target, owner) {
                return Err(OwnerAdmissionError::BindingMismatch);
            }
            return if existing.closing {
                Err(OwnerAdmissionError::TargetClosing)
            } else {
                Ok(existing.receipt(false))
            };
        }
        if self
            .live
            .values()
            .any(|existing| existing.target.flattened_session_id == target.flattened_session_id)
            || self.retired.contains_key(&target.flattened_session_id)
        {
            return Err(OwnerAdmissionError::BindingMismatch);
        }
        for previous in self
            .retired
            .values()
            .filter(|previous| previous.target.target_id == target.target_id)
        {
            if previous.target.context_id != target.context_id || previous.owner != *owner {
                return Err(OwnerAdmissionError::OwnershipMismatch);
            }
            if target.target_incarnation <= previous.target.target_incarnation {
                return Err(OwnerAdmissionError::BindingMismatch);
            }
        }
        if self.live.len() >= MAX_LIVE_RESERVATIONS {
            return Err(OwnerAdmissionError::StateOverflow);
        }
        let inventory = self.inventory(&target.context_id);
        if inventory.total_targets >= runtime_ceiling.min(self.limits.max_total_targets) {
            return Err(OwnerAdmissionError::Admission(
                TargetAdmissionError::TotalTargetLimit,
            ));
        }
        let permit = self
            .contexts
            .get_mut(&target.context_id)
            .ok_or(OwnerAdmissionError::UnknownContext)?
            .admission
            .check_and_record(target.kind.clone(), inventory, now)
            .map_err(OwnerAdmissionError::Admission)?;
        // No fallible bookkeeping follows the recorded permit. A failed
        // bootstrap/close must leave this reservation in the live inventory.
        let reservation = Reservation {
            target: target.clone(),
            owner: owner.clone(),
            creation_sequence: permit.sequence(),
            closing: false,
        };
        let receipt = reservation.receipt(true);
        self.live.insert(target.target_id.clone(), reservation);
        Ok(receipt)
    }

    /// Both bootstrap validation stages only verify the same reservation; they
    /// must not record a second creation or reconstruct inventory from pages.
    pub(super) fn validate_reserved(
        &self,
        target: &OwnerAdmissionTarget,
        owner: &ContextOwnership,
    ) -> Result<OwnerAdmissionReceipt, OwnerAdmissionError> {
        Self::validate_identity(target)?;
        if self.context(&target.context_id, owner)?.closing {
            return Err(OwnerAdmissionError::ContextClosing);
        }
        let reservation = self.exact_reservation(target, owner)?;
        if reservation.closing {
            return Err(OwnerAdmissionError::TargetClosing);
        }
        Ok(reservation.receipt(false))
    }

    pub(super) fn mark_closing(
        &mut self,
        target: &OwnerAdmissionTarget,
        owner: &ContextOwnership,
    ) -> Result<(), OwnerAdmissionError> {
        Self::validate_identity(target)?;
        self.context(&target.context_id, owner)?;
        self.exact_reservation(target, owner)?;
        if let Some(reservation) = self.live.get_mut(&target.target_id) {
            reservation.closing = true;
        }
        Ok(())
    }

    /// The caller must have exact detach/destruction proof, or final authoritative
    /// target/context absence snapshots matched to a previously fixed exact
    /// owner/context/target/session/incarnation binding. A close command response
    /// alone, including an error, does not satisfy this API.
    pub(super) fn confirmed_retirement(
        &mut self,
        target: &OwnerAdmissionTarget,
        owner: &ContextOwnership,
    ) -> Result<bool, OwnerAdmissionError> {
        Self::validate_identity(target)?;
        self.context(&target.context_id, owner)?;
        if !self.live.contains_key(&target.target_id) {
            return if self
                .retired
                .get(&target.flattened_session_id)
                .is_some_and(|retired| retired.matches(target, owner))
            {
                Ok(false)
            } else {
                Err(OwnerAdmissionError::BindingMismatch)
            };
        }
        self.exact_reservation(target, owner)?;
        if self.retired.len() >= MAX_RETIRED_RESERVATIONS {
            // Keep the live charge if retirement cannot be recorded safely.
            return Err(OwnerAdmissionError::StateOverflow);
        }
        let retired = self
            .live
            .remove(&target.target_id)
            .ok_or(OwnerAdmissionError::BindingMismatch)?;
        self.retired
            .insert(target.flattened_session_id.clone(), retired);
        Ok(true)
    }

    pub(super) fn mark_context_closing(
        &mut self,
        context_id: &str,
        owner: &ContextOwnership,
    ) -> Result<(), OwnerAdmissionError> {
        self.context(context_id, owner)?;
        if let Some(context) = self.contexts.get_mut(context_id) {
            context.closing = true;
        }
        Ok(())
    }

    /// Only the caller's known CDP rejection with the original context/routes
    /// proven unchanged may reopen admission. Uncertain disposal keeps it shut.
    pub(super) fn restore_context_active(
        &mut self,
        context_id: &str,
        owner: &ContextOwnership,
    ) -> Result<(), OwnerAdmissionError> {
        self.context(context_id, owner)?;
        if let Some(context) = self.contexts.get_mut(context_id) {
            context.closing = false;
        }
        Ok(())
    }

    /// The owner must confirm the context and every target are absent, using
    /// the existing disposal proof, before releasing any of their charges.
    pub(super) fn confirmed_context_disposal(
        &mut self,
        context_id: &str,
        owner: &ContextOwnership,
    ) -> Result<usize, OwnerAdmissionError> {
        self.context(context_id, owner)?;
        let before = self.live.len();
        self.live
            .retain(|_, reservation| reservation.target.context_id != context_id);
        self.retired
            .retain(|_, reservation| reservation.target.context_id != context_id);
        self.contexts.remove(context_id);
        Ok(before - self.live.len())
    }

    fn context(
        &self,
        context_id: &str,
        owner: &ContextOwnership,
    ) -> Result<&ContextAdmission, OwnerAdmissionError> {
        let context = self
            .contexts
            .get(context_id)
            .ok_or(OwnerAdmissionError::UnknownContext)?;
        if context.owner != *owner {
            return Err(OwnerAdmissionError::OwnershipMismatch);
        }
        Ok(context)
    }

    fn exact_reservation(
        &self,
        target: &OwnerAdmissionTarget,
        owner: &ContextOwnership,
    ) -> Result<&Reservation, OwnerAdmissionError> {
        self.live
            .get(&target.target_id)
            .filter(|reservation| reservation.matches(target, owner))
            .ok_or(OwnerAdmissionError::BindingMismatch)
    }

    fn validate_identity(target: &OwnerAdmissionTarget) -> Result<(), OwnerAdmissionError> {
        if !valid_identifier(&target.context_id)
            || !valid_identifier(&target.target_id)
            || !valid_identifier(&target.flattened_session_id)
            || target.target_incarnation == 0
        {
            return Err(OwnerAdmissionError::InvalidIdentity);
        }
        Ok(())
    }

    fn inventory(&self, context_id: &str) -> TargetInventory {
        // Global reservations are bounded far below u32::MAX. Counting the
        // immutable records avoids decrement/rollback races across target kinds.
        let mut inventory = TargetInventory::default();
        for reservation in self
            .live
            .values()
            .filter(|reservation| reservation.target.context_id == context_id)
        {
            inventory.total_targets += 1;
            match reservation.target.kind {
                TargetKind::Page => inventory.pages += 1,
                TargetKind::Iframe => inventory.frames += 1,
                TargetKind::DedicatedWorker | TargetKind::SharedWorker => inventory.workers += 1,
                TargetKind::ServiceWorker => inventory.service_workers += 1,
                _ => {}
            }
        }
        inventory
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use browserd_core::{SessionId, TenantId, WorkerId};
    use browserd_session::OwnershipFence;

    use super::*;

    fn ownership() -> ContextOwnership {
        ContextOwnership {
            tenant_id: TenantId::new(),
            session_id: SessionId::new(),
            fence: OwnershipFence::new(WorkerId::new("admission-worker").unwrap(), 1, 2, 3),
        }
    }

    fn target(context: &str, id: &str, kind: TargetKind, incarnation: u64) -> OwnerAdmissionTarget {
        OwnerAdmissionTarget {
            context_id: context.to_owned(),
            target_id: id.to_owned(),
            flattened_session_id: format!("flat-{id}-{incarnation}"),
            kind,
            target_incarnation: incarnation,
        }
    }

    fn limits() -> TargetLimits {
        TargetLimits {
            max_pages: 2,
            max_frames: 3,
            max_workers: 2,
            max_service_workers: 1,
            max_total_targets: 6,
            max_creations_per_window: 3,
            creation_window: Duration::from_secs(10),
        }
    }

    fn ledger(owner: &ContextOwnership) -> OwnerTargetAdmissions {
        let mut ledger = OwnerTargetAdmissions::with_limits(limits());
        ledger.register_context("context", owner).unwrap();
        ledger
    }

    #[test]
    fn runtime_ceiling_counts_uncertain_closing_and_preserves_creation_history() {
        let owner = ownership();
        let mut ledger = ledger(&owner);
        let first = target("context", "first", TargetKind::Page, 1);
        let second = target("context", "second", TargetKind::Iframe, 2);
        let third = target("context", "third", TargetKind::DedicatedWorker, 3);
        assert_eq!(
            ledger
                .admit_with_ceiling(&first, &owner, TargetTime::new(1), 128)
                .unwrap()
                .creation_sequence,
            1
        );
        assert_eq!(
            ledger
                .admit_with_ceiling(&second, &owner, TargetTime::new(2), 128)
                .unwrap()
                .creation_sequence,
            2
        );
        ledger.mark_closing(&first, &owner).unwrap();
        assert_eq!(
            ledger.admit_with_ceiling(&third, &owner, TargetTime::new(3), 1),
            Err(OwnerAdmissionError::Admission(
                TargetAdmissionError::TotalTargetLimit
            ))
        );
        ledger.confirmed_retirement(&first, &owner).unwrap();
        assert_eq!(
            ledger.admit_with_ceiling(&third, &owner, TargetTime::new(4), 1),
            Err(OwnerAdmissionError::Admission(
                TargetAdmissionError::TotalTargetLimit
            ))
        );
        let admitted = ledger
            .admit_with_ceiling(&third, &owner, TargetTime::new(5), 128)
            .unwrap();
        assert_eq!(
            admitted.creation_sequence, 3,
            "ceiling changes never reset sequence"
        );
        let fourth = target("context", "fourth", TargetKind::Iframe, 4);
        assert_eq!(
            ledger.admit_with_ceiling(&fourth, &owner, TargetTime::new(6), 128),
            Err(OwnerAdmissionError::Admission(
                TargetAdmissionError::CreationRateLimit
            ))
        );
        assert!(
            !ledger
                .admit_with_ceiling(&third, &owner, TargetTime::new(7), 1)
                .unwrap()
                .newly_admitted
        );
        assert_eq!(
            ledger
                .admit_with_ceiling(&fourth, &owner, TargetTime::new(10_001), 128)
                .unwrap()
                .creation_sequence,
            4
        );
    }

    #[test]
    fn defaults_match_session_limits_and_record_all_target_classes() {
        let owner = ownership();
        let mut ledger = OwnerTargetAdmissions::default();
        ledger.register_context("context", &owner).unwrap();
        assert_eq!(ledger.limits.max_pages, 8);
        assert_eq!(ledger.limits.max_frames, 64);
        assert_eq!(ledger.limits.max_workers, 16);
        assert_eq!(ledger.limits.max_service_workers, 8);
        assert_eq!(ledger.limits.max_total_targets, 96);
        assert_eq!(ledger.limits.max_creations_per_window, 64);
        assert_eq!(ledger.limits.creation_window, Duration::from_secs(10));
        for (index, kind) in [
            TargetKind::Page,
            TargetKind::Iframe,
            TargetKind::DedicatedWorker,
            TargetKind::SharedWorker,
            TargetKind::ServiceWorker,
        ]
        .into_iter()
        .enumerate()
        {
            ledger
                .admit(
                    &target("context", &format!("t{index}"), kind, index as u64 + 1),
                    &owner,
                    TargetTime::new(0),
                )
                .unwrap();
        }
        assert_eq!(
            ledger.inventory("context"),
            TargetInventory {
                pages: 1,
                frames: 1,
                workers: 2,
                service_workers: 1,
                total_targets: 5,
            }
        );
    }

    #[test]
    fn duplicate_attach_and_bootstrap_validation_record_creation_once() {
        let owner = ownership();
        let mut configured = limits();
        configured.max_creations_per_window = 1;
        let mut ledger = OwnerTargetAdmissions::with_limits(configured);
        ledger.register_context("context", &owner).unwrap();
        let first = target("context", "worker", TargetKind::SharedWorker, 1);
        let receipt = ledger.admit(&first, &owner, TargetTime::new(0)).unwrap();
        assert!(receipt.newly_admitted);
        for now in 1..5 {
            let duplicate = ledger.admit(&first, &owner, TargetTime::new(now)).unwrap();
            assert!(!duplicate.newly_admitted);
            assert_eq!(duplicate.creation_sequence, receipt.creation_sequence);
            assert_eq!(duplicate.target_incarnation, receipt.target_incarnation);
            assert_eq!(ledger.validate_reserved(&first, &owner).unwrap(), duplicate);
        }
        ledger.register_context("context", &owner).unwrap();
        assert_eq!(ledger.inventory("context").workers, 1);
        assert_eq!(
            ledger.admit(
                &target("context", "other", TargetKind::DedicatedWorker, 2),
                &owner,
                TargetTime::new(5),
            ),
            Err(OwnerAdmissionError::Admission(
                TargetAdmissionError::CreationRateLimit
            ))
        );
    }

    #[test]
    fn replacement_requires_exact_retirement_and_never_revives_old_binding() {
        let owner = ownership();
        let mut ledger = ledger(&owner);
        let old = target("context", "worker", TargetKind::DedicatedWorker, 1);
        ledger.admit(&old, &owner, TargetTime::new(0)).unwrap();
        let new = target("context", "worker", TargetKind::DedicatedWorker, 2);
        assert_eq!(
            ledger.admit(&new, &owner, TargetTime::new(1)),
            Err(OwnerAdmissionError::BindingMismatch)
        );
        assert_eq!(ledger.inventory("context").workers, 1);
        assert!(ledger.confirmed_retirement(&old, &owner).unwrap());
        assert!(!ledger.confirmed_retirement(&old, &owner).unwrap());
        assert_eq!(
            ledger.admit(&old, &owner, TargetTime::new(2)),
            Err(OwnerAdmissionError::BindingMismatch)
        );
        let receipt = ledger.admit(&new, &owner, TargetTime::new(3)).unwrap();
        assert_eq!(receipt.creation_sequence, 2);
        assert_eq!(
            ledger.confirmed_retirement(&old, &owner),
            Err(OwnerAdmissionError::BindingMismatch)
        );
        assert!(ledger.validate_reserved(&new, &owner).is_ok());
        let mut reused_flat = target("context", "other", TargetKind::SharedWorker, 3);
        reused_flat
            .flattened_session_id
            .clone_from(&old.flattened_session_id);
        assert_eq!(
            ledger.admit(&reused_flat, &owner, TargetTime::new(4)),
            Err(OwnerAdmissionError::BindingMismatch)
        );
    }

    #[test]
    fn every_owner_fence_component_and_context_are_exact() {
        let original = ownership();
        let mut ledger = ledger(&original);
        let worker = target("context", "worker", TargetKind::SharedWorker, 1);
        ledger
            .admit(&worker, &original, TargetTime::new(0))
            .unwrap();
        let mut wrong_tenant = original.clone();
        wrong_tenant.tenant_id = TenantId::new();
        let mut wrong_session = original.clone();
        wrong_session.session_id = SessionId::new();
        let mut candidates = vec![wrong_tenant, wrong_session];
        for (worker_id, epoch, placement, incarnation) in [
            ("other-worker", 1, 2, 3),
            ("admission-worker", 2, 2, 3),
            ("admission-worker", 1, 3, 3),
            ("admission-worker", 1, 2, 4),
        ] {
            let mut changed = original.clone();
            changed.fence = OwnershipFence::new(
                WorkerId::new(worker_id).unwrap(),
                epoch,
                placement,
                incarnation,
            );
            candidates.push(changed);
        }
        for candidate in candidates {
            assert_eq!(
                ledger.register_context("context", &candidate),
                Err(OwnerAdmissionError::OwnershipMismatch)
            );
            assert_eq!(
                ledger.admit(&worker, &candidate, TargetTime::new(1)),
                Err(OwnerAdmissionError::OwnershipMismatch)
            );
            assert_eq!(
                ledger.confirmed_retirement(&worker, &candidate),
                Err(OwnerAdmissionError::OwnershipMismatch)
            );
            assert_eq!(
                ledger.confirmed_context_disposal("context", &candidate),
                Err(OwnerAdmissionError::OwnershipMismatch)
            );
        }
        let foreign = target("unregistered", "worker", TargetKind::SharedWorker, 1);
        assert_eq!(
            ledger.admit(&foreign, &original, TargetTime::new(2)),
            Err(OwnerAdmissionError::UnknownContext)
        );
        assert_eq!(ledger.inventory("context").workers, 1);
    }

    #[test]
    fn live_flattened_session_and_target_kind_cannot_be_rebound() {
        let owner = ownership();
        let mut ledger = ledger(&owner);
        let first = target("context", "first", TargetKind::DedicatedWorker, 1);
        ledger.admit(&first, &owner, TargetTime::new(0)).unwrap();
        let mut shared = first.clone();
        shared.kind = TargetKind::SharedWorker;
        assert_eq!(
            ledger.admit(&shared, &owner, TargetTime::new(0)),
            Err(OwnerAdmissionError::BindingMismatch)
        );
        let mut second = target("context", "second", TargetKind::SharedWorker, 2);
        second
            .flattened_session_id
            .clone_from(&first.flattened_session_id);
        assert_eq!(
            ledger.admit(&second, &owner, TargetTime::new(0)),
            Err(OwnerAdmissionError::BindingMismatch)
        );
        assert_eq!(ledger.inventory("context").total_targets, 1);
    }

    #[test]
    fn dedicated_and_shared_workers_share_quota_service_workers_have_their_own() {
        let owner = ownership();
        let mut ledger = OwnerTargetAdmissions::default();
        ledger.register_context("context", &owner).unwrap();
        for i in 0..16 {
            let kind = if i & 1 == 0 {
                TargetKind::DedicatedWorker
            } else {
                TargetKind::SharedWorker
            };
            ledger
                .admit(
                    &target("context", &format!("w{i}"), kind, i + 1),
                    &owner,
                    TargetTime::new(0),
                )
                .unwrap();
        }
        assert_eq!(
            ledger.admit(
                &target("context", "overflow-worker", TargetKind::SharedWorker, 17),
                &owner,
                TargetTime::new(0),
            ),
            Err(OwnerAdmissionError::Admission(
                TargetAdmissionError::WorkerLimit
            ))
        );
        for i in 0..8 {
            ledger
                .admit(
                    &target(
                        "context",
                        &format!("s{i}"),
                        TargetKind::ServiceWorker,
                        i + 20,
                    ),
                    &owner,
                    TargetTime::new(0),
                )
                .unwrap();
        }
        assert_eq!(
            ledger.admit(
                &target("context", "overflow-service", TargetKind::ServiceWorker, 30),
                &owner,
                TargetTime::new(0),
            ),
            Err(OwnerAdmissionError::Admission(
                TargetAdmissionError::ServiceWorkerLimit
            ))
        );
        assert_eq!(ledger.inventory("context").total_targets, 24);
    }

    #[test]
    fn existing_pages_and_iframes_participate_in_class_and_total_limits() {
        let owner = ownership();
        let mut ledger = OwnerTargetAdmissions::default();
        ledger.register_context("context", &owner).unwrap();
        let mut incarnation = 1;
        for (kind, count) in [
            (TargetKind::Page, 8),
            (TargetKind::Iframe, 64),
            (TargetKind::SharedWorker, 16),
            (TargetKind::ServiceWorker, 8),
        ] {
            for i in 0..count {
                ledger
                    .admit(
                        &target(
                            "context",
                            &format!("t{incarnation}"),
                            kind.clone(),
                            incarnation,
                        ),
                        &owner,
                        TargetTime::new((incarnation / 32) * 10_000),
                    )
                    .unwrap();
                incarnation += 1;
                if i + 1 == count && matches!(kind, TargetKind::Page | TargetKind::Iframe) {
                    let expected = if kind == TargetKind::Page {
                        TargetAdmissionError::PageLimit
                    } else {
                        TargetAdmissionError::FrameLimit
                    };
                    assert_eq!(
                        ledger.admit(
                            &target("context", "class-overflow", kind.clone(), incarnation),
                            &owner,
                            TargetTime::new((incarnation / 32) * 10_000),
                        ),
                        Err(OwnerAdmissionError::Admission(expected))
                    );
                }
            }
        }
        assert_eq!(ledger.inventory("context").total_targets, 96);
        assert_eq!(
            ledger.admit(
                &target(
                    "context",
                    "total-overflow",
                    TargetKind::DedicatedWorker,
                    100
                ),
                &owner,
                TargetTime::new(40_000),
            ),
            Err(OwnerAdmissionError::Admission(
                TargetAdmissionError::TotalTargetLimit
            ))
        );
    }

    #[test]
    fn creation_rate_survives_retirement_and_resets_only_at_the_window_boundary() {
        let owner = ownership();
        let mut ledger = OwnerTargetAdmissions::default();
        ledger.register_context("context", &owner).unwrap();
        for i in 0..64 {
            let worker = target(
                "context",
                &format!("w{i}"),
                TargetKind::DedicatedWorker,
                i + 1,
            );
            ledger.admit(&worker, &owner, TargetTime::new(0)).unwrap();
            ledger.confirmed_retirement(&worker, &owner).unwrap();
        }
        assert_eq!(ledger.inventory("context").total_targets, 0);
        let next = target("context", "next", TargetKind::SharedWorker, 100);
        assert_eq!(
            ledger.admit(&next, &owner, TargetTime::new(9_999)),
            Err(OwnerAdmissionError::Admission(
                TargetAdmissionError::CreationRateLimit
            ))
        );
        let receipt = ledger
            .admit(&next, &owner, TargetTime::new(10_000))
            .unwrap();
        assert_eq!(receipt.creation_sequence, 65);
    }

    #[test]
    fn trusted_clock_backwards_rejects_duplicates_and_other_contexts_without_releasing() {
        let owner = ownership();
        let mut ledger = ledger(&owner);
        let worker = target("context", "worker", TargetKind::SharedWorker, 1);
        ledger.admit(&worker, &owner, TargetTime::new(50)).unwrap();
        assert_eq!(
            ledger.admit(&worker, &owner, TargetTime::new(49)),
            Err(OwnerAdmissionError::Admission(
                TargetAdmissionError::ClockMovedBackwards
            ))
        );
        let other_owner = ownership();
        ledger
            .register_context("other-context", &other_owner)
            .unwrap();
        let other = target("other-context", "other", TargetKind::ServiceWorker, 2);
        assert_eq!(
            ledger.admit(&other, &other_owner, TargetTime::new(49)),
            Err(OwnerAdmissionError::Admission(
                TargetAdmissionError::ClockMovedBackwards
            ))
        );
        assert_eq!(ledger.inventory("context").workers, 1);
        assert_eq!(ledger.inventory("other-context").total_targets, 0);
        assert!(
            !ledger
                .admit(&worker, &owner, TargetTime::new(50))
                .unwrap()
                .newly_admitted
        );
    }

    #[test]
    fn shared_and_service_workers_outlive_originating_page_and_only_exact_context_disposal_releases()
     {
        let owner = ownership();
        let mut ledger = ledger(&owner);
        let page = target("context", "page", TargetKind::Page, 1);
        let shared = target("context", "shared", TargetKind::SharedWorker, 2);
        let service = target("context", "service", TargetKind::ServiceWorker, 3);
        for binding in [&page, &shared, &service] {
            ledger.admit(binding, &owner, TargetTime::new(0)).unwrap();
        }
        ledger.confirmed_retirement(&page, &owner).unwrap();
        assert!(ledger.validate_reserved(&shared, &owner).is_ok());
        assert!(ledger.validate_reserved(&service, &owner).is_ok());
        assert_eq!(ledger.inventory("context").total_targets, 2);
        let other_owner = ownership();
        ledger
            .register_context("other-context", &other_owner)
            .unwrap();
        let other = target("other-context", "other", TargetKind::Page, 4);
        ledger
            .admit(&other, &other_owner, TargetTime::new(0))
            .unwrap();
        ledger.mark_context_closing("context", &owner).unwrap();
        assert_eq!(ledger.inventory("context").total_targets, 2);
        assert_eq!(
            ledger
                .confirmed_context_disposal("context", &owner)
                .unwrap(),
            2
        );
        assert!(ledger.validate_reserved(&other, &other_owner).is_ok());
        assert_eq!(
            ledger.validate_reserved(&shared, &owner),
            Err(OwnerAdmissionError::UnknownContext)
        );
    }

    #[test]
    fn uncertain_close_holds_capacity_and_stale_confirmation_cannot_release() {
        let owner = ownership();
        let mut configured = limits();
        configured.max_workers = 1;
        let mut ledger = OwnerTargetAdmissions::with_limits(configured);
        ledger.register_context("context", &owner).unwrap();
        let worker = target("context", "worker", TargetKind::DedicatedWorker, 1);
        ledger.admit(&worker, &owner, TargetTime::new(0)).unwrap();
        ledger.mark_closing(&worker, &owner).unwrap();
        assert_eq!(
            ledger.validate_reserved(&worker, &owner),
            Err(OwnerAdmissionError::TargetClosing)
        );
        assert_eq!(
            ledger.admit(
                &target("context", "other", TargetKind::SharedWorker, 2),
                &owner,
                TargetTime::new(1),
            ),
            Err(OwnerAdmissionError::Admission(
                TargetAdmissionError::WorkerLimit
            ))
        );
        let mut stale = worker.clone();
        stale.target_incarnation += 1;
        assert_eq!(
            ledger.confirmed_retirement(&stale, &owner),
            Err(OwnerAdmissionError::BindingMismatch)
        );
        assert_eq!(ledger.inventory("context").workers, 1);
        ledger.confirmed_retirement(&worker, &owner).unwrap();
        assert!(
            ledger
                .admit(
                    &target("context", "other", TargetKind::SharedWorker, 2),
                    &owner,
                    TargetTime::new(2),
                )
                .is_ok()
        );
    }

    #[test]
    fn context_closing_blocks_admission_but_known_no_effect_rejection_preserves_original_reservations()
     {
        let owner = ownership();
        let mut ledger = ledger(&owner);
        let worker = target("context", "worker", TargetKind::SharedWorker, 1);
        let first = ledger.admit(&worker, &owner, TargetTime::new(0)).unwrap();
        ledger.mark_context_closing("context", &owner).unwrap();
        assert_eq!(
            ledger.admit(&worker, &owner, TargetTime::new(1)),
            Err(OwnerAdmissionError::ContextClosing)
        );
        assert_eq!(ledger.inventory("context").workers, 1);
        let foreign = ownership();
        assert_eq!(
            ledger.restore_context_active("context", &foreign),
            Err(OwnerAdmissionError::OwnershipMismatch)
        );
        ledger.restore_context_active("context", &owner).unwrap();
        let restored = ledger.validate_reserved(&worker, &owner).unwrap();
        assert_eq!(restored.creation_sequence, first.creation_sequence);
        assert!(!restored.newly_admitted);
    }

    #[test]
    fn rejected_policy_or_identity_never_consumes_a_creation_permit() {
        let owner = ownership();
        let mut configured = limits();
        configured.max_creations_per_window = 1;
        let mut ledger = OwnerTargetAdmissions::with_limits(configured);
        ledger.register_context("context", &owner).unwrap();
        assert_eq!(
            ledger.admit(
                &target("context", "extension", TargetKind::Extension, 1),
                &owner,
                TargetTime::new(0),
            ),
            Err(OwnerAdmissionError::Admission(
                TargetAdmissionError::ExtensionForbiddenInSharedContext
            ))
        );
        assert_eq!(
            ledger.admit(
                &target("context", "bad", TargetKind::SharedWorker, 0),
                &owner,
                TargetTime::new(0),
            ),
            Err(OwnerAdmissionError::InvalidIdentity)
        );
        let first = target("context", "first", TargetKind::SharedWorker, 2);
        assert_eq!(
            ledger
                .admit(&first, &owner, TargetTime::new(0))
                .unwrap()
                .creation_sequence,
            1
        );
        assert_eq!(ledger.inventory("context").total_targets, 1);
    }

    #[test]
    fn rejected_worker_quota_does_not_consume_the_last_page_creation_permit() {
        let owner = ownership();
        let mut configured = limits();
        configured.max_workers = 1;
        configured.max_creations_per_window = 2;
        let mut ledger = OwnerTargetAdmissions::with_limits(configured);
        ledger.register_context("context", &owner).unwrap();
        ledger
            .admit(
                &target("context", "worker", TargetKind::SharedWorker, 1),
                &owner,
                TargetTime::new(0),
            )
            .unwrap();
        assert_eq!(
            ledger.admit(
                &target("context", "overflow", TargetKind::DedicatedWorker, 2),
                &owner,
                TargetTime::new(0),
            ),
            Err(OwnerAdmissionError::Admission(
                TargetAdmissionError::WorkerLimit
            ))
        );
        let page = ledger
            .admit(
                &target("context", "page", TargetKind::Page, 3),
                &owner,
                TargetTime::new(0),
            )
            .unwrap();
        assert_eq!(page.creation_sequence, 2);
        assert_eq!(ledger.inventory("context").total_targets, 2);
    }

    #[test]
    fn late_old_context_disposal_cannot_release_replacement_owner() {
        let old_owner = ownership();
        let mut ledger = ledger(&old_owner);
        let old_target = target("context", "old", TargetKind::ServiceWorker, 1);
        ledger
            .admit(&old_target, &old_owner, TargetTime::new(0))
            .unwrap();
        assert_eq!(
            ledger
                .confirmed_context_disposal("context", &old_owner)
                .unwrap(),
            1
        );
        let new_owner = ownership();
        ledger.register_context("context", &new_owner).unwrap();
        let new_target = target("context", "new", TargetKind::SharedWorker, 2);
        ledger
            .admit(&new_target, &new_owner, TargetTime::new(1))
            .unwrap();
        assert_eq!(
            ledger.confirmed_context_disposal("context", &old_owner),
            Err(OwnerAdmissionError::OwnershipMismatch)
        );
        assert!(ledger.validate_reserved(&new_target, &new_owner).is_ok());
        assert_eq!(ledger.inventory("context").workers, 1);
    }
}
