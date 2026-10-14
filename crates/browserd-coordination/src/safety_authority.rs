//! Global audited runtime safety authority. Ordinary reads never bootstrap missing state.
mod actor;
mod memory;
mod model;
mod observer;
mod redis;
mod state;

use async_trait::async_trait;

pub use actor::SafetyAuthorityBlockingClient;
pub use memory::{MemorySafetyAuthority, SafetyAuthorityClock, SystemSafetyAuthorityClock};
pub use model::{
    SafetyActorIdentity, SafetyAuditAck, SafetyAuditIntent, SafetyAuthorityConfig,
    SafetyAuthorityError, SafetyAuthoritySnapshot, SafetyInitializeRequest, SafetyMutationReceipt,
    SafetyMutationRequest,
};
pub use observer::{SafetyObserver, SafetyObserverWatermark};
pub use redis::{RedisSafetyAuthority, RedisSafetyAuthorityConfig};

#[async_trait]
pub trait SafetyAuthority: Send + Sync {
    async fn initialize(
        &self,
        request: SafetyInitializeRequest,
    ) -> Result<SafetyMutationReceipt, SafetyAuthorityError>;
    async fn read(&self) -> Result<SafetyAuthoritySnapshot, SafetyAuthorityError>;
    async fn mutate(
        &self,
        request: SafetyMutationRequest,
    ) -> Result<SafetyMutationReceipt, SafetyAuthorityError>;
    async fn pending_audits(
        &self,
        limit: usize,
    ) -> Result<Vec<SafetyAuditIntent>, SafetyAuthorityError>;
    async fn ack_audit(&self, ack: SafetyAuditAck) -> Result<(), SafetyAuthorityError>;
    async fn prune_receipts(&self) -> Result<usize, SafetyAuthorityError>;
}
