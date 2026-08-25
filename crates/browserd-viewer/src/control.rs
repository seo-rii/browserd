use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use browserd_core::{PageId, SessionId, TenantId};

use crate::{
    AcquireOutcome, ConnectionId, ControlError, ControlInput, ControlLease, ControlPolicy,
    ControlSnapshot, InputCleanup, InputDecision, InputDiscardReason, InputEffect, InputKind,
    InputStateSnapshot, ViewerConnection,
};

#[derive(Default)]
struct ActiveInputState {
    mouse_buttons: BTreeSet<u8>,
    keys: BTreeSet<String>,
    drag_active: bool,
    composition_preedit: Option<String>,
}

struct ActiveControl {
    lease: ControlLease,
    input: ActiveInputState,
}

#[derive(Default)]
struct ManagerState {
    epoch: u64,
    connections: HashMap<ConnectionId, ViewerConnection>,
    input_times: HashMap<ConnectionId, VecDeque<u64>>,
    retired_connections: HashSet<ConnectionId>,
    active: Option<ActiveControl>,
    transform_epochs: HashMap<PageId, u64>,
    cleanup_events: Vec<InputCleanup>,
}

pub struct ControlManager {
    tenant_id: TenantId,
    session_id: SessionId,
    session_incarnation: u64,
    policy: ControlPolicy,
    state: Mutex<ManagerState>,
}

impl ControlManager {
    pub fn new(
        tenant_id: TenantId,
        session_id: SessionId,
        session_incarnation: u64,
        lease_ttl: Duration,
    ) -> Result<Self, ControlError> {
        let policy = ControlPolicy::new(4, lease_ttl, 240, Duration::from_secs(10))
            .map_err(|_| ControlError::InvalidLeaseTtl)?;
        Ok(Self::with_policy(
            tenant_id,
            session_id,
            session_incarnation,
            policy,
        ))
    }

    #[must_use]
    pub fn with_policy(
        tenant_id: TenantId,
        session_id: SessionId,
        session_incarnation: u64,
        policy: ControlPolicy,
    ) -> Self {
        Self {
            tenant_id,
            session_id,
            session_incarnation,
            policy,
            state: Mutex::new(ManagerState::default()),
        }
    }

    pub fn attach(&self, connection: ViewerConnection) -> Result<(), ControlError> {
        if connection.tenant_id() != &self.tenant_id
            || connection.session_id() != &self.session_id
            || connection.session_incarnation() != self.session_incarnation
        {
            return Err(ControlError::ConnectionBindingMismatch);
        }
        let mut state = self.lock_state()?;
        if state.connections.contains_key(connection.id())
            || state.retired_connections.contains(connection.id())
        {
            return Err(ControlError::ConnectionAlreadyAttached);
        }
        if state.connections.len() >= self.policy.max_observers {
            return Err(ControlError::ObserverLimitExceeded);
        }
        state
            .input_times
            .insert(connection.id().clone(), VecDeque::new());
        state
            .connections
            .insert(connection.id().clone(), connection);
        Ok(())
    }

    pub fn acquire(
        &self,
        connection_id: &ConnectionId,
        page_id: PageId,
        now_millis: u64,
    ) -> Result<AcquireOutcome, ControlError> {
        let mut state = self.lock_state()?;
        let connection = state
            .connections
            .get(connection_id)
            .cloned()
            .ok_or(ControlError::ConnectionNotFound)?;
        if !connection.scopes().can_control() {
            return Err(ControlError::ControlScopeRequired);
        }

        if let Some(active) = state.active.as_ref() {
            if now_millis >= active.lease.expires_at_millis {
                Self::return_to_agent(&mut state)?;
            } else if active.lease.connection_id == *connection_id
                && active.lease.page_id == page_id
            {
                return Ok(AcquireOutcome {
                    lease: active.lease.clone(),
                    replaced_controller: None,
                });
            } else {
                return Err(ControlError::AlreadyControlled);
            }
        }

        self.grant_control(&mut state, connection_id.clone(), page_id, now_millis, None)
    }

    pub fn force_acquire(
        &self,
        connection_id: &ConnectionId,
        page_id: PageId,
        now_millis: u64,
    ) -> Result<AcquireOutcome, ControlError> {
        let mut state = self.lock_state()?;
        let connection = state
            .connections
            .get(connection_id)
            .cloned()
            .ok_or(ControlError::ConnectionNotFound)?;
        if !connection.scopes().can_control() {
            return Err(ControlError::ControlScopeRequired);
        }
        if !connection.scopes().can_admin() {
            return Err(ControlError::AdminScopeRequired);
        }

        if let Some(active) = state.active.as_ref()
            && active.lease.connection_id == *connection_id
            && active.lease.page_id == page_id
            && now_millis < active.lease.expires_at_millis
        {
            return Ok(AcquireOutcome {
                lease: active.lease.clone(),
                replaced_controller: None,
            });
        }

        now_millis
            .checked_add(self.policy.lease_ttl_millis)
            .ok_or(ControlError::TimeOverflow)?;
        let epoch_steps = if state.active.is_some() { 2 } else { 1 };
        state
            .epoch
            .checked_add(epoch_steps)
            .ok_or(ControlError::EpochExhausted)?;

        let replaced = state
            .active
            .as_ref()
            .map(|active| active.lease.connection_id.clone());
        if state.active.is_some() {
            Self::return_to_agent(&mut state)?;
        }
        self.grant_control(
            &mut state,
            connection_id.clone(),
            page_id,
            now_millis,
            replaced,
        )
    }

    pub fn heartbeat(
        &self,
        connection_id: &ConnectionId,
        lease_epoch: u64,
        now_millis: u64,
    ) -> Result<ControlLease, ControlError> {
        let mut state = self.lock_state()?;
        let active = state.active.as_ref().ok_or(ControlError::NoActiveControl)?;
        if active.lease.connection_id != *connection_id {
            return Err(ControlError::NotController);
        }
        if active.lease.epoch != lease_epoch {
            return Err(ControlError::StaleLeaseEpoch);
        }
        if now_millis >= active.lease.expires_at_millis {
            Self::return_to_agent(&mut state)?;
            return Err(ControlError::LeaseExpired);
        }
        let expires_at_millis = now_millis
            .checked_add(self.policy.lease_ttl_millis)
            .ok_or(ControlError::TimeOverflow)?;
        let active = state
            .active
            .as_mut()
            .ok_or(ControlError::StateUnavailable)?;
        active.lease.expires_at_millis = expires_at_millis;
        Ok(active.lease.clone())
    }

    pub fn release(
        &self,
        connection_id: &ConnectionId,
        lease_epoch: u64,
    ) -> Result<InputCleanup, ControlError> {
        let mut state = self.lock_state()?;
        let active = state.active.as_ref().ok_or(ControlError::NoActiveControl)?;
        if active.lease.connection_id != *connection_id {
            return Err(ControlError::NotController);
        }
        if active.lease.epoch != lease_epoch {
            return Err(ControlError::StaleLeaseEpoch);
        }
        Self::return_to_agent(&mut state)?.ok_or(ControlError::StateUnavailable)
    }

    pub fn expire(&self, now_millis: u64) -> Result<Option<InputCleanup>, ControlError> {
        let mut state = self.lock_state()?;
        if state
            .active
            .as_ref()
            .is_some_and(|active| now_millis >= active.lease.expires_at_millis)
        {
            return Self::return_to_agent(&mut state);
        }
        Ok(None)
    }

    pub fn disconnect(
        &self,
        connection_id: &ConnectionId,
    ) -> Result<Option<InputCleanup>, ControlError> {
        let mut state = self.lock_state()?;
        if !state.connections.contains_key(connection_id) {
            return Err(ControlError::ConnectionNotFound);
        }
        let cleanup = if state
            .active
            .as_ref()
            .is_some_and(|active| active.lease.connection_id == *connection_id)
        {
            Self::return_to_agent(&mut state)?
        } else {
            None
        };
        state.connections.remove(connection_id);
        state.input_times.remove(connection_id);
        state.retired_connections.insert(connection_id.clone());
        Ok(cleanup)
    }

    pub fn advance_transform(&self, page_id: PageId) -> Result<u64, ControlError> {
        let mut state = self.lock_state()?;
        let next = state
            .transform_epochs
            .get(&page_id)
            .copied()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(ControlError::EpochExhausted)?;
        state.transform_epochs.insert(page_id, next);
        Ok(next)
    }

    pub fn process_input(
        &self,
        connection_id: &ConnectionId,
        input: ControlInput,
        now_millis: u64,
    ) -> Result<InputDecision, ControlError> {
        let mut state = self.lock_state()?;
        if !state.connections.contains_key(connection_id) {
            return Err(ControlError::ConnectionNotFound);
        }
        let input_times = state
            .input_times
            .get_mut(connection_id)
            .ok_or(ControlError::StateUnavailable)?;
        let window_start = now_millis.saturating_sub(self.policy.input_rate_window_millis);
        while input_times
            .front()
            .is_some_and(|timestamp| *timestamp <= window_start)
        {
            input_times.pop_front();
        }
        if input_times.len() >= self.policy.input_rate_limit {
            return Ok(InputDecision::Discarded(InputDiscardReason::RateLimited));
        }
        input_times.push_back(now_millis);
        let Some(active) = state.active.as_ref() else {
            return Ok(InputDecision::Discarded(
                InputDiscardReason::NoActiveControl,
            ));
        };
        if active.lease.connection_id != *connection_id {
            return Ok(InputDecision::Discarded(InputDiscardReason::NotController));
        }
        if active.lease.epoch != input.lease_epoch {
            return Ok(InputDecision::Discarded(
                InputDiscardReason::StaleLeaseEpoch,
            ));
        }
        if now_millis >= active.lease.expires_at_millis {
            Self::return_to_agent(&mut state)?;
            return Ok(InputDecision::Discarded(InputDiscardReason::LeaseExpired));
        }
        if input.input_sequence <= active.lease.last_input_sequence {
            return Ok(InputDecision::Discarded(InputDiscardReason::ReplaySequence));
        }
        if active.lease.page_id != input.page_id {
            return Ok(InputDecision::Discarded(InputDiscardReason::PageMismatch));
        }
        if state.transform_epochs.get(&input.page_id).copied() != Some(input.transform_epoch) {
            return Ok(InputDecision::Discarded(InputDiscardReason::StaleTransform));
        }

        let active = state
            .active
            .as_mut()
            .ok_or(ControlError::StateUnavailable)?;
        active.lease.last_input_sequence = input.input_sequence;
        let effect = match input.kind {
            InputKind::MouseDown(button) => {
                active.input.mouse_buttons.insert(button);
                InputEffect::None
            }
            InputKind::MouseUp(button) => {
                active.input.mouse_buttons.remove(&button);
                if active.input.mouse_buttons.is_empty() {
                    active.input.drag_active = false;
                }
                InputEffect::None
            }
            InputKind::MouseMove => {
                if !active.input.mouse_buttons.is_empty() {
                    active.input.drag_active = true;
                }
                InputEffect::None
            }
            InputKind::Wheel => InputEffect::None,
            InputKind::KeyDown(key) => {
                active.input.keys.insert(key);
                InputEffect::None
            }
            InputKind::KeyUp(key) => {
                active.input.keys.remove(&key);
                InputEffect::None
            }
            InputKind::InsertText(text) => InputEffect::TextInserted(text),
            InputKind::CompositionStart => {
                if active.input.composition_preedit.is_some() {
                    return Ok(InputDecision::Discarded(
                        InputDiscardReason::CompositionAlreadyActive,
                    ));
                }
                active.input.composition_preedit = Some(String::new());
                InputEffect::None
            }
            InputKind::CompositionUpdate(preedit) => {
                let Some(current) = active.input.composition_preedit.as_mut() else {
                    return Ok(InputDecision::Discarded(
                        InputDiscardReason::CompositionNotActive,
                    ));
                };
                *current = preedit;
                InputEffect::None
            }
            InputKind::CompositionCommit(committed) => {
                if active.input.composition_preedit.take().is_none() {
                    return Ok(InputDecision::Discarded(
                        InputDiscardReason::CompositionNotActive,
                    ));
                }
                InputEffect::CompositionCommitted(committed)
            }
            InputKind::CompositionCancel => {
                if active.input.composition_preedit.take().is_none() {
                    return Ok(InputDecision::Discarded(
                        InputDiscardReason::CompositionNotActive,
                    ));
                }
                InputEffect::None
            }
        };
        Ok(InputDecision::Accepted(effect))
    }

    pub fn snapshot(&self) -> Result<ControlSnapshot, ControlError> {
        let state = self.lock_state()?;
        Ok(ControlSnapshot {
            epoch: state.epoch,
            lease: state.active.as_ref().map(|active| active.lease.clone()),
        })
    }

    pub fn input_snapshot(&self) -> Result<InputStateSnapshot, ControlError> {
        let state = self.lock_state()?;
        let Some(active) = state.active.as_ref() else {
            return Ok(InputStateSnapshot::default());
        };
        Ok(InputStateSnapshot {
            pressed_mouse_buttons: active.input.mouse_buttons.iter().copied().collect(),
            pressed_keys: active.input.keys.iter().cloned().collect(),
            drag_active: active.input.drag_active,
            composition_preedit: active.input.composition_preedit.clone(),
        })
    }

    pub fn drain_cleanup_events(&self) -> Result<Vec<InputCleanup>, ControlError> {
        let mut state = self.lock_state()?;
        Ok(std::mem::take(&mut state.cleanup_events))
    }

    fn lock_state(&self) -> Result<MutexGuard<'_, ManagerState>, ControlError> {
        self.state
            .lock()
            .map_err(|_| ControlError::StateUnavailable)
    }

    fn grant_control(
        &self,
        state: &mut ManagerState,
        connection_id: ConnectionId,
        page_id: PageId,
        now_millis: u64,
        replaced_controller: Option<ConnectionId>,
    ) -> Result<AcquireOutcome, ControlError> {
        let next_epoch = state
            .epoch
            .checked_add(1)
            .ok_or(ControlError::EpochExhausted)?;
        let expires_at_millis = now_millis
            .checked_add(self.policy.lease_ttl_millis)
            .ok_or(ControlError::TimeOverflow)?;
        let lease = ControlLease {
            connection_id,
            epoch: next_epoch,
            page_id,
            expires_at_millis,
            last_input_sequence: 0,
        };
        state.epoch = next_epoch;
        state.active = Some(ActiveControl {
            lease: lease.clone(),
            input: ActiveInputState::default(),
        });
        Ok(AcquireOutcome {
            lease,
            replaced_controller,
        })
    }

    fn return_to_agent(state: &mut ManagerState) -> Result<Option<InputCleanup>, ControlError> {
        if state.active.is_none() {
            return Ok(None);
        }
        let next_epoch = state
            .epoch
            .checked_add(1)
            .ok_or(ControlError::EpochExhausted)?;
        let active = state.active.take().ok_or(ControlError::StateUnavailable)?;
        state.epoch = next_epoch;
        let cleanup = InputCleanup {
            connection_id: active.lease.connection_id,
            lease_epoch: active.lease.epoch,
            released_mouse_buttons: active.input.mouse_buttons.into_iter().collect(),
            released_keys: active.input.keys.into_iter().collect(),
            drag_cancelled: active.input.drag_active,
            cancelled_composition: active.input.composition_preedit,
        };
        state.cleanup_events.push(cleanup.clone());
        Ok(Some(cleanup))
    }
}
