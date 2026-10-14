use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use uuid::Uuid;

use super::state::{Command, Outcome, State, transition};
use super::{
    SafetyAuditAck, SafetyAuditIntent, SafetyAuthority, SafetyAuthorityConfig,
    SafetyAuthorityError, SafetyAuthoritySnapshot, SafetyInitializeRequest, SafetyMutationReceipt,
    SafetyMutationRequest,
};

pub trait SafetyAuthorityClock: Send + Sync {
    fn now_unix_ms(&self) -> Result<u64, SafetyAuthorityError>;
}
#[derive(Default)]
pub struct SystemSafetyAuthorityClock;
impl SafetyAuthorityClock for SystemSafetyAuthorityClock {
    fn now_unix_ms(&self) -> Result<u64, SafetyAuthorityError> {
        u64::try_from(chrono::Utc::now().timestamp_millis())
            .map_err(|_| SafetyAuthorityError::Unavailable)
    }
}

#[derive(Clone)]
pub struct MemorySafetyAuthority {
    state: Arc<Mutex<Option<State>>>,
    config: SafetyAuthorityConfig,
    clock: Arc<dyn SafetyAuthorityClock>,
}
impl MemorySafetyAuthority {
    #[must_use]
    pub fn new(config: SafetyAuthorityConfig) -> Self {
        Self {
            state: Arc::new(Mutex::new(None)),
            config,
            clock: Arc::new(SystemSafetyAuthorityClock),
        }
    }
    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn SafetyAuthorityClock>) -> Self {
        self.clock = clock;
        self
    }
    fn apply(&self, command: Command) -> Result<Outcome, SafetyAuthorityError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| SafetyAuthorityError::Unavailable)?;
        let next = transition(
            state.as_ref(),
            &command,
            self.clock.now_unix_ms()?,
            self.config,
        )?;
        *state = Some(next.state);
        Ok(next.outcome)
    }
}
impl Default for MemorySafetyAuthority {
    fn default() -> Self {
        Self::new(SafetyAuthorityConfig::default())
    }
}
#[async_trait]
impl SafetyAuthority for MemorySafetyAuthority {
    async fn initialize(
        &self,
        request: SafetyInitializeRequest,
    ) -> Result<SafetyMutationReceipt, SafetyAuthorityError> {
        match self.apply(Command::Initialize(request, Uuid::now_v7(), Uuid::now_v7()))? {
            Outcome::Receipt(receipt) => Ok(receipt),
            _ => Err(SafetyAuthorityError::CorruptState),
        }
    }
    async fn read(&self) -> Result<SafetyAuthoritySnapshot, SafetyAuthorityError> {
        let state = self
            .state
            .lock()
            .map_err(|_| SafetyAuthorityError::Unavailable)?;
        let state = state
            .as_ref()
            .ok_or(SafetyAuthorityError::MissingAuthority)?;
        state.validate(self.config)?;
        Ok(state.authority.clone())
    }
    async fn mutate(
        &self,
        request: SafetyMutationRequest,
    ) -> Result<SafetyMutationReceipt, SafetyAuthorityError> {
        match self.apply(Command::Mutate(request, Uuid::now_v7()))? {
            Outcome::Receipt(receipt) => Ok(receipt),
            _ => Err(SafetyAuthorityError::CorruptState),
        }
    }
    async fn pending_audits(
        &self,
        limit: usize,
    ) -> Result<Vec<SafetyAuditIntent>, SafetyAuthorityError> {
        let state = self
            .state
            .lock()
            .map_err(|_| SafetyAuthorityError::Unavailable)?;
        let state = state
            .as_ref()
            .ok_or(SafetyAuthorityError::MissingAuthority)?;
        state.validate(self.config)?;
        state.pending_audits(limit)
    }
    async fn ack_audit(&self, ack: SafetyAuditAck) -> Result<(), SafetyAuthorityError> {
        match self.apply(Command::Ack(ack))? {
            Outcome::Ack => Ok(()),
            _ => Err(SafetyAuthorityError::CorruptState),
        }
    }
    async fn prune_receipts(&self) -> Result<usize, SafetyAuthorityError> {
        match self.apply(Command::Prune)? {
            Outcome::Pruned(count) => Ok(count),
            _ => Err(SafetyAuthorityError::CorruptState),
        }
    }
}
