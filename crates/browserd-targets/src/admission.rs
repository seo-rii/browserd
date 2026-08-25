use std::time::Duration;

use crate::{TargetKind, TargetTime};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TargetLimits {
    pub max_pages: u32,
    pub max_frames: u32,
    pub max_workers: u32,
    pub max_service_workers: u32,
    pub max_total_targets: u32,
    pub max_creations_per_window: u32,
    pub creation_window: Duration,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TargetInventory {
    pub pages: u32,
    pub frames: u32,
    pub workers: u32,
    pub service_workers: u32,
    pub total_targets: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TargetPolicy {
    allow_prerender: bool,
    allow_approved_extensions: bool,
}

impl TargetPolicy {
    #[must_use]
    pub const fn shared_context_default() -> Self {
        Self {
            allow_prerender: false,
            allow_approved_extensions: false,
        }
    }

    #[must_use]
    pub const fn tenant_dedicated_with_approved_extensions() -> Self {
        Self {
            allow_prerender: false,
            allow_approved_extensions: true,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TargetAdmissionError {
    PrerenderDisabled,
    ExtensionForbiddenInSharedContext,
    DevtoolsForbidden,
    UnknownTargetType,
    PageLimit,
    FrameLimit,
    WorkerLimit,
    ServiceWorkerLimit,
    TotalTargetLimit,
    CreationRateLimit,
    InvalidLimits,
    ClockMovedBackwards,
    CounterOverflow,
}

impl TargetAdmissionError {
    #[must_use]
    pub fn requires_shard_taint(&self) -> bool {
        *self == Self::UnknownTargetType
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetAdmissionPermit {
    sequence: u64,
    kind: TargetKind,
}

impl TargetAdmissionPermit {
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub const fn kind(&self) -> &TargetKind {
        &self.kind
    }
}

/// A session-local, single-writer admission controller.
#[derive(Debug)]
pub struct TargetAdmission {
    policy: TargetPolicy,
    limits: TargetLimits,
    window_millis: Option<u64>,
    window_start: TargetTime,
    last_observed: TargetTime,
    creations_in_window: u32,
    next_sequence: u64,
}

impl TargetAdmission {
    #[must_use]
    pub fn new(policy: TargetPolicy, limits: TargetLimits) -> Self {
        let window_millis = {
            let millis = limits.creation_window.as_millis();
            if millis == 0 || millis > u128::from(u64::MAX) {
                None
            } else {
                u64::try_from(millis).ok()
            }
        };
        Self {
            policy,
            limits,
            window_millis,
            window_start: TargetTime::new(0),
            last_observed: TargetTime::new(0),
            creations_in_window: 0,
            next_sequence: 1,
        }
    }

    pub fn check_and_record(
        &mut self,
        kind: TargetKind,
        inventory: TargetInventory,
        now: TargetTime,
    ) -> Result<TargetAdmissionPermit, TargetAdmissionError> {
        match kind {
            TargetKind::Prerender if !self.policy.allow_prerender => {
                return Err(TargetAdmissionError::PrerenderDisabled);
            }
            TargetKind::Extension if !self.policy.allow_approved_extensions => {
                return Err(TargetAdmissionError::ExtensionForbiddenInSharedContext);
            }
            TargetKind::Devtools => return Err(TargetAdmissionError::DevtoolsForbidden),
            TargetKind::Unknown(_) => return Err(TargetAdmissionError::UnknownTargetType),
            _ => {}
        }
        if inventory.total_targets >= self.limits.max_total_targets {
            return Err(TargetAdmissionError::TotalTargetLimit);
        }
        match kind {
            TargetKind::Page if inventory.pages >= self.limits.max_pages => {
                return Err(TargetAdmissionError::PageLimit);
            }
            TargetKind::Iframe if inventory.frames >= self.limits.max_frames => {
                return Err(TargetAdmissionError::FrameLimit);
            }
            TargetKind::DedicatedWorker | TargetKind::SharedWorker
                if inventory.workers >= self.limits.max_workers =>
            {
                return Err(TargetAdmissionError::WorkerLimit);
            }
            TargetKind::ServiceWorker
                if inventory.service_workers >= self.limits.max_service_workers =>
            {
                return Err(TargetAdmissionError::ServiceWorkerLimit);
            }
            _ => {}
        }
        let Some(window_millis) = self.window_millis else {
            return Err(TargetAdmissionError::InvalidLimits);
        };
        if now < self.last_observed {
            return Err(TargetAdmissionError::ClockMovedBackwards);
        }
        self.last_observed = now;
        if now
            .milliseconds()
            .saturating_sub(self.window_start.milliseconds())
            >= window_millis
        {
            self.window_start = now;
            self.creations_in_window = 0;
        }
        if self.creations_in_window >= self.limits.max_creations_per_window {
            return Err(TargetAdmissionError::CreationRateLimit);
        }

        let next_count = self
            .creations_in_window
            .checked_add(1)
            .ok_or(TargetAdmissionError::CounterOverflow)?;
        let sequence = self.next_sequence;
        let next_sequence = sequence
            .checked_add(1)
            .ok_or(TargetAdmissionError::CounterOverflow)?;
        self.creations_in_window = next_count;
        self.next_sequence = next_sequence;
        Ok(TargetAdmissionPermit { sequence, kind })
    }
}
