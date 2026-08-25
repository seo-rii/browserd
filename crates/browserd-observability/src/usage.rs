use std::collections::HashMap;
use std::fmt;
use std::sync::{Mutex, MutexGuard};

use browserd_core::TenantId;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct UsageEventId(String);

impl UsageEventId {
    pub fn new(value: impl Into<String>) -> Result<Self, UsageRecordError> {
        let value = value.into();
        if value.is_empty() || value.len() > 255 || value.chars().any(char::is_control) {
            return Err(UsageRecordError::InvalidEventId);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum UsageDimension {
    SessionWallSeconds,
    BrowserWeightedSeconds,
    ActionCountByType(String),
    ActionResourceClassSeconds(String),
    EgressBytes,
    IngressBytes,
    ArtifactStorageByteSeconds,
    ArtifactBytesGenerated,
    ViewerSeconds,
    ViewerEgressBytes,
    PdfPages,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UsageEvent {
    id: UsageEventId,
    tenant_id: TenantId,
    dimension: UsageDimension,
    quantity: u64,
    effective_isolation: String,
    effective_workload_class: String,
}

impl UsageEvent {
    #[must_use]
    pub fn new(
        id: UsageEventId,
        tenant_id: TenantId,
        dimension: UsageDimension,
        quantity: u64,
        effective_isolation: impl Into<String>,
        effective_workload_class: impl Into<String>,
    ) -> Self {
        Self {
            id,
            tenant_id,
            dimension,
            quantity,
            effective_isolation: effective_isolation.into(),
            effective_workload_class: effective_workload_class.into(),
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct UsageKey {
    tenant_id: TenantId,
    dimension: UsageDimension,
    effective_isolation: String,
    effective_workload_class: String,
}

#[derive(Default)]
struct UsageState {
    events: HashMap<UsageEventId, UsageEvent>,
    totals: HashMap<UsageKey, u64>,
}

pub struct UsageAggregator {
    state: Mutex<UsageState>,
}

impl UsageAggregator {
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Mutex::new(UsageState::default()),
        }
    }

    pub fn record(&self, event: UsageEvent) -> Result<UsageRecordOutcome, UsageRecordError> {
        let mut state = self.lock_state()?;
        if let Some(existing) = state.events.get(&event.id) {
            return if existing == &event {
                Ok(UsageRecordOutcome::Existing)
            } else {
                Err(UsageRecordError::EventIdConflict)
            };
        }
        let key = UsageKey {
            tenant_id: event.tenant_id.clone(),
            dimension: event.dimension.clone(),
            effective_isolation: event.effective_isolation.clone(),
            effective_workload_class: event.effective_workload_class.clone(),
        };
        let total = state
            .totals
            .get(&key)
            .copied()
            .unwrap_or(0)
            .checked_add(event.quantity)
            .ok_or(UsageRecordError::TotalOverflow)?;
        state.totals.insert(key, total);
        state.events.insert(event.id.clone(), event);
        Ok(UsageRecordOutcome::Recorded)
    }

    pub fn total(
        &self,
        tenant_id: &TenantId,
        dimension: UsageDimension,
        effective_isolation: &str,
        effective_workload_class: &str,
    ) -> Result<u64, UsageRecordError> {
        let state = self.lock_state()?;
        Ok(state
            .totals
            .get(&UsageKey {
                tenant_id: tenant_id.clone(),
                dimension,
                effective_isolation: effective_isolation.to_owned(),
                effective_workload_class: effective_workload_class.to_owned(),
            })
            .copied()
            .unwrap_or(0))
    }

    fn lock_state(&self) -> Result<MutexGuard<'_, UsageState>, UsageRecordError> {
        self.state
            .lock()
            .map_err(|_| UsageRecordError::StateUnavailable)
    }
}

impl Default for UsageAggregator {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UsageRecordOutcome {
    Recorded,
    Existing,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UsageRecordError {
    InvalidEventId,
    EventIdConflict,
    TotalOverflow,
    StateUnavailable,
}

impl fmt::Display for UsageRecordError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "usage aggregation error: {self:?}")
    }
}

impl std::error::Error for UsageRecordError {}
