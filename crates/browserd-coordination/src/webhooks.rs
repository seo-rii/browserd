//! Durable webhook registration and endpoint-specific, at-least-once delivery.

use std::{fmt, time::Duration};

use async_trait::async_trait;
use browserd_core::{PrincipalId, TenantId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::{Uuid, Version};

use crate::{EventCursor, OutboxEvent, encode_outbox_event};

mod actor;
mod engine;
pub(crate) mod memory;
mod postgres;

pub use actor::WebhookBlockingClient;
pub use memory::MemoryWebhookStore;
pub use postgres::PostgresWebhookStore;

pub const MAX_WEBHOOK_BODY_BYTES: usize = 512 * 1024;
pub const MAX_WEBHOOK_EXAMINED: usize = 16;
pub const MAX_WEBHOOK_IN_FLIGHT: usize = 4;
pub const WEBHOOK_ACK_RETENTION: Duration = Duration::from_secs(86_400);

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum WebhookStoreError {
    #[error("invalid webhook configuration")]
    InvalidConfiguration,
    #[error("invalid webhook endpoint")]
    InvalidEndpoint,
    #[error("invalid webhook mutation")]
    InvalidMutation,
    #[error("webhook revision conflict")]
    Conflict,
    #[error("webhook idempotency conflict")]
    IdempotencyConflict,
    #[error("webhook endpoint not found")]
    NotFound,
    #[error("webhook capacity exhausted")]
    Capacity,
    #[error("webhook audit capacity exhausted")]
    AuditCapacity,
    #[error("webhook attempt lease mismatch")]
    LeaseMismatch,
    #[error("webhook event gap requires explicit acknowledgement")]
    Gap,
    #[error("invalid webhook payload")]
    InvalidPayload,
    #[error("webhook storage unavailable")]
    Unavailable,
    #[error("webhook actor busy before admission")]
    Busy,
    #[error("webhook query timed out")]
    QueryTimeout,
    #[error("webhook mutation outcome is pending")]
    MutationTimeout,
}
type Error = WebhookStoreError;

macro_rules! validated {
    ($name:ident {$($field:ident:$ty:ty),* $(,)?}) => {
        #[derive(Clone, Eq, PartialEq, Serialize)]
        pub struct $name {$(pub(crate) $field:$ty),*}
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D:serde::Deserializer<'de>>(d:D)->Result<Self,D::Error>{
                #[derive(Deserialize)] #[serde(deny_unknown_fields)]
                struct Wire {$($field:$ty),*}
                let w=Wire::deserialize(d)?;
                let v=Self{$($field:w.$field),*};
                v.validate().map_err(serde::de::Error::custom)?;
                Ok(v)
            }
        }
    };
}
fn nonzero(hash: &[u8; 32]) -> bool {
    hash.iter().any(|v| *v != 0)
}
fn printable(value: &str, limit: usize) -> bool {
    !value.is_empty() && value.len() <= limit && value.bytes().all(|v| v.is_ascii_graphic())
}

validated!(WebhookSigningKeyRef {
    master_version_id: String,
    key_id: Uuid
});
impl WebhookSigningKeyRef {
    pub fn new(master_version_id: impl Into<String>, key_id: Uuid) -> Result<Self, Error> {
        let v = Self {
            master_version_id: master_version_id.into(),
            key_id,
        };
        v.validate()?;
        Ok(v)
    }
    pub fn validate(&self) -> Result<(), Error> {
        if printable(&self.master_version_id, 64)
            && self.key_id.get_version() == Some(Version::Random)
        {
            Ok(())
        } else {
            Err(Error::InvalidConfiguration)
        }
    }
    #[must_use]
    pub fn master_version_id(&self) -> &str {
        &self.master_version_id
    }
    #[must_use]
    pub const fn key_id(&self) -> Uuid {
        self.key_id
    }
}
impl fmt::Debug for WebhookSigningKeyRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebhookSigningKeyRef")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

validated!(WebhookEndpointSpec {
    endpoint_url: String,
    signing_key_ref: WebhookSigningKeyRef
});
impl WebhookEndpointSpec {
    pub fn new(
        endpoint_url: impl Into<String>,
        signing_key_ref: WebhookSigningKeyRef,
    ) -> Result<Self, Error> {
        let raw = endpoint_url.into();
        let parsed = url::Url::parse(&raw).map_err(|_| Error::InvalidEndpoint)?;
        let v = Self {
            endpoint_url: parsed.to_string(),
            signing_key_ref,
        };
        v.validate()?;
        Ok(v)
    }
    pub fn validate(&self) -> Result<(), Error> {
        self.signing_key_ref.validate()?;
        if self.endpoint_url.len() > 2048 || self.endpoint_url.chars().any(char::is_control) {
            return Err(Error::InvalidEndpoint);
        }
        let u = url::Url::parse(&self.endpoint_url).map_err(|_| Error::InvalidEndpoint)?;
        if u.scheme() != "https"
            || u.host_str().is_none()
            || !u.username().is_empty()
            || u.password().is_some()
            || u.fragment().is_some()
            || u.as_str() != self.endpoint_url
        {
            return Err(Error::InvalidEndpoint);
        }
        Ok(())
    }
    #[must_use]
    pub fn endpoint_url(&self) -> &str {
        &self.endpoint_url
    }
    #[must_use]
    pub const fn signing_key_ref(&self) -> &WebhookSigningKeyRef {
        &self.signing_key_ref
    }
}
impl fmt::Debug for WebhookEndpointSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebhookEndpointSpec")
            .field("endpoint_url", &"[redacted]")
            .field("signing_key_ref", &self.signing_key_ref)
            .finish()
    }
}

validated!(WebhookEndpointRef {
    tenant_id: TenantId,
    endpoint_id: Uuid,
    revision: u64
});
impl WebhookEndpointRef {
    pub fn new(tenant_id: TenantId, endpoint_id: Uuid, revision: u64) -> Result<Self, Error> {
        let v = Self {
            tenant_id,
            endpoint_id,
            revision,
        };
        v.validate()?;
        Ok(v)
    }
    pub fn validate(&self) -> Result<(), Error> {
        if self.endpoint_id.get_version() == Some(Version::SortRand) && self.revision > 0 {
            Ok(())
        } else {
            Err(Error::InvalidMutation)
        }
    }
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }
    #[must_use]
    pub const fn endpoint_id(&self) -> Uuid {
        self.endpoint_id
    }
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }
}
impl fmt::Debug for WebhookEndpointRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebhookEndpointRef")
            .field("tenant_id", &self.tenant_id)
            .field("endpoint_id", &self.endpoint_id)
            .field("revision", &self.revision)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebhookEndpointStatus {
    Active,
    Suspended,
    Deleted,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebhookSuspensionReason {
    Operator,
    ConsecutiveFailures,
    EventGap,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookGapObservation {
    pub(crate) pruned_through: u64,
    pub(crate) tail: u64,
}
impl WebhookGapObservation {
    #[must_use]
    pub const fn pruned_through(&self) -> u64 {
        self.pruned_through
    }
    #[must_use]
    pub const fn tail(&self) -> u64 {
        self.tail
    }
}
validated!(WebhookEndpointSnapshot {endpoint_ref:WebhookEndpointRef,spec:WebhookEndpointSpec,status:WebhookEndpointStatus,cursor_position:u64,failure_count:u32,created_at:DateTime<Utc>,updated_at:DateTime<Utc>,suspension_reason:Option<WebhookSuspensionReason>,gap_observation:Option<WebhookGapObservation>});
impl WebhookEndpointSnapshot {
    pub fn validate(&self) -> Result<(), Error> {
        self.endpoint_ref.validate()?;
        self.spec.validate()?;
        if self.updated_at < self.created_at
            || (self.status == WebhookEndpointStatus::Suspended) != self.suspension_reason.is_some()
        {
            return Err(Error::InvalidMutation);
        }
        Ok(())
    }
    #[must_use]
    pub const fn endpoint_ref(&self) -> &WebhookEndpointRef {
        &self.endpoint_ref
    }
    #[must_use]
    pub const fn spec(&self) -> &WebhookEndpointSpec {
        &self.spec
    }
    #[must_use]
    pub const fn status(&self) -> WebhookEndpointStatus {
        self.status
    }
    #[must_use]
    pub const fn cursor(&self) -> EventCursor {
        EventCursor::from_position(self.cursor_position)
    }
    #[must_use]
    pub const fn failure_count(&self) -> u32 {
        self.failure_count
    }
    #[must_use]
    pub const fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
    #[must_use]
    pub const fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }
    #[must_use]
    pub const fn suspension_reason(&self) -> Option<WebhookSuspensionReason> {
        self.suspension_reason
    }
    #[must_use]
    pub const fn gap_observation(&self) -> Option<WebhookGapObservation> {
        self.gap_observation
    }
}
impl fmt::Debug for WebhookEndpointSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebhookEndpointSnapshot")
            .field("endpoint_ref", &self.endpoint_ref)
            .field("status", &self.status)
            .field("cursor_position", &self.cursor_position)
            .finish_non_exhaustive()
    }
}

validated!(WebhookMutationBinding {
    tenant_id: TenantId,
    principal_id: PrincipalId,
    idempotency_key: String,
    canonical_request_hash: [u8; 32]
});
impl WebhookMutationBinding {
    pub fn new(
        tenant_id: TenantId,
        principal_id: PrincipalId,
        idempotency_key: impl Into<String>,
        canonical_request_hash: [u8; 32],
    ) -> Result<Self, Error> {
        let v = Self {
            tenant_id,
            principal_id,
            idempotency_key: idempotency_key.into(),
            canonical_request_hash,
        };
        v.validate()?;
        Ok(v)
    }
    pub fn validate(&self) -> Result<(), Error> {
        if printable(&self.idempotency_key, 128) && nonzero(&self.canonical_request_hash) {
            Ok(())
        } else {
            Err(Error::InvalidMutation)
        }
    }
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }
    #[must_use]
    pub const fn principal_id(&self) -> &PrincipalId {
        &self.principal_id
    }
    #[must_use]
    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }
}
impl fmt::Debug for WebhookMutationBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebhookMutationBinding")
            .field("tenant_id", &self.tenant_id)
            .field("principal_id", &self.principal_id)
            .finish_non_exhaustive()
    }
}
validated!(WebhookPutRequest {binding:WebhookMutationBinding,expected_revision:Option<u64>,spec:WebhookEndpointSpec});
impl WebhookPutRequest {
    pub fn new(
        binding: WebhookMutationBinding,
        expected_revision: Option<u64>,
        spec: WebhookEndpointSpec,
    ) -> Result<Self, Error> {
        let v = Self {
            binding,
            expected_revision,
            spec,
        };
        v.validate()?;
        Ok(v)
    }
    pub fn validate(&self) -> Result<(), Error> {
        self.binding.validate()?;
        self.spec.validate()?;
        if self.expected_revision == Some(0) {
            return Err(Error::InvalidMutation);
        }
        Ok(())
    }
    #[must_use]
    pub const fn binding(&self) -> &WebhookMutationBinding {
        &self.binding
    }
    #[must_use]
    pub const fn spec(&self) -> &WebhookEndpointSpec {
        &self.spec
    }
}
impl fmt::Debug for WebhookPutRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebhookPutRequest")
            .field("binding", &self.binding)
            .field("expected_revision", &self.expected_revision)
            .field("spec", &self.spec)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum WebhookResumeMode {
    Continue,
    AcceptGapToTail {
        expected_pruned_through: u64,
        expected_tail: u64,
    },
}

validated!(WebhookEventBody {bytes:Vec<u8>,sha256:[u8;32]});
impl WebhookEventBody {
    pub fn validate(&self) -> Result<(), Error> {
        if self.bytes.is_empty()
            || self.bytes.len() > MAX_WEBHOOK_BODY_BYTES
            || <[u8; 32]>::from(Sha256::digest(&self.bytes)) != self.sha256
        {
            return Err(Error::InvalidPayload);
        }
        Ok(())
    }
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    #[must_use]
    pub const fn sha256(&self) -> [u8; 32] {
        self.sha256
    }
}
impl fmt::Debug for WebhookEventBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebhookEventBody")
            .field("size_bytes", &self.bytes.len())
            .field("sha256", &self.sha256)
            .finish()
    }
}
pub fn encode_webhook_event(event: &OutboxEvent) -> Result<WebhookEventBody, Error> {
    let bytes = encode_outbox_event(event).map_err(|_| Error::InvalidPayload)?;
    let body = WebhookEventBody {
        sha256: Sha256::digest(&bytes).into(),
        bytes,
    };
    body.validate()?;
    Ok(body)
}

validated!(WebhookAttemptLease {endpoint_ref:WebhookEndpointRef,spec:WebhookEndpointSpec,event_id:Uuid,event_sequence:u64,delivery_id:Uuid,attempt_id:Uuid,lease_token:Uuid,generation:u64,expires_at:DateTime<Utc>,send_timestamp_seconds:i64,payload:WebhookEventBody});
impl WebhookAttemptLease {
    pub fn validate(&self) -> Result<(), Error> {
        self.endpoint_ref.validate()?;
        self.spec.validate()?;
        self.payload.validate()?;
        if [self.event_id, self.delivery_id, self.attempt_id]
            .iter()
            .any(|id| id.get_version() != Some(Version::SortRand))
            || self.lease_token.get_version() != Some(Version::Random)
            || self.event_sequence == 0
            || self.generation == 0
            || self.send_timestamp_seconds < 0
            || self.expires_at.timestamp() <= self.send_timestamp_seconds
        {
            return Err(Error::LeaseMismatch);
        }
        Ok(())
    }
    #[must_use]
    pub const fn endpoint_ref(&self) -> &WebhookEndpointRef {
        &self.endpoint_ref
    }
    #[must_use]
    pub const fn spec(&self) -> &WebhookEndpointSpec {
        &self.spec
    }
    #[must_use]
    pub const fn signing_key_ref(&self) -> &WebhookSigningKeyRef {
        self.spec.signing_key_ref()
    }
    #[must_use]
    pub const fn event_id(&self) -> Uuid {
        self.event_id
    }
    #[must_use]
    pub const fn event_cursor(&self) -> EventCursor {
        EventCursor::from_position(self.event_sequence)
    }
    #[must_use]
    pub const fn delivery_id(&self) -> Uuid {
        self.delivery_id
    }
    #[must_use]
    pub const fn attempt_id(&self) -> Uuid {
        self.attempt_id
    }
    #[must_use]
    pub const fn lease_token(&self) -> Uuid {
        self.lease_token
    }
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    #[must_use]
    pub const fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }
    #[must_use]
    pub const fn send_timestamp_seconds(&self) -> i64 {
        self.send_timestamp_seconds
    }
    #[must_use]
    pub const fn payload(&self) -> &WebhookEventBody {
        &self.payload
    }
}
impl fmt::Debug for WebhookAttemptLease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebhookAttemptLease")
            .field("endpoint_ref", &self.endpoint_ref)
            .field("event_id", &self.event_id)
            .field("attempt_id", &self.attempt_id)
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum WebhookAttemptOutcome {
    Delivered { status_code: u16 },
    TransientFailure { status_code: Option<u16> },
    PermanentFailure { status_code: Option<u16> },
    TransportUnknown,
}
impl WebhookAttemptOutcome {
    pub fn validate(&self) -> Result<(), Error> {
        let status = match self {
            Self::Delivered { status_code } if (200..300).contains(status_code) => return Ok(()),
            Self::Delivered { .. } => return Err(Error::InvalidMutation),
            Self::TransientFailure { status_code } | Self::PermanentFailure { status_code } => {
                *status_code
            }
            Self::TransportUnknown => None,
        };
        if status.is_some_and(|v| !(100..600).contains(&v)) {
            Err(Error::InvalidMutation)
        } else {
            Ok(())
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookAttemptResult {
    pub(crate) attempt_id: Uuid,
    pub(crate) outcome: WebhookAttemptOutcome,
    pub(crate) endpoint: WebhookEndpointSnapshot,
    pub(crate) finished_at: DateTime<Utc>,
}
impl WebhookAttemptResult {
    #[must_use]
    pub const fn attempt_id(&self) -> Uuid {
        self.attempt_id
    }
    #[must_use]
    pub const fn outcome(&self) -> &WebhookAttemptOutcome {
        &self.outcome
    }
    #[must_use]
    pub const fn endpoint(&self) -> &WebhookEndpointSnapshot {
        &self.endpoint
    }
    #[must_use]
    pub const fn finished_at(&self) -> DateTime<Utc> {
        self.finished_at
    }
}
validated!(WebhookDeliveryCursor {schema_version:u8,after:Option<TenantId>});
impl Default for WebhookDeliveryCursor {
    fn default() -> Self {
        Self {
            schema_version: 1,
            after: None,
        }
    }
}
impl WebhookDeliveryCursor {
    pub fn validate(&self) -> Result<(), Error> {
        if self.schema_version == 1 {
            Ok(())
        } else {
            Err(Error::InvalidMutation)
        }
    }
}
impl fmt::Debug for WebhookDeliveryCursor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebhookDeliveryCursor")
            .field("after", &self.after)
            .finish()
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WebhookAttemptPage {
    pub(crate) attempts: Vec<WebhookAttemptLease>,
    pub(crate) next_cursor: WebhookDeliveryCursor,
    pub(crate) complete: bool,
    pub(crate) examined: usize,
}
impl WebhookAttemptPage {
    #[must_use]
    pub fn attempts(&self) -> &[WebhookAttemptLease] {
        &self.attempts
    }
    #[must_use]
    pub const fn next_cursor(&self) -> &WebhookDeliveryCursor {
        &self.next_cursor
    }
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.complete
    }
    #[must_use]
    pub const fn examined(&self) -> usize {
        self.examined
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WebhookMaintenancePage {
    pub(crate) next_cursor: WebhookDeliveryCursor,
    pub(crate) complete: bool,
    pub(crate) examined: usize,
    pub(crate) reclaimed: usize,
}
impl WebhookMaintenancePage {
    #[must_use]
    pub const fn next_cursor(&self) -> &WebhookDeliveryCursor {
        &self.next_cursor
    }
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.complete
    }
    #[must_use]
    pub const fn examined(&self) -> usize {
        self.examined
    }
    #[must_use]
    pub const fn reclaimed(&self) -> usize {
        self.reclaimed
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WebhookStoreConfig {
    pub(crate) max_endpoints: usize,
    pub(crate) max_mutations_per_tenant: usize,
    pub(crate) max_audit_rows_per_tenant: usize,
    pub(crate) max_acknowledged_per_tenant: usize,
    pub(crate) max_payload_bytes_per_tenant: usize,
    pub(crate) failures_before_suspend: u32,
}
impl Default for WebhookStoreConfig {
    fn default() -> Self {
        Self {
            max_endpoints: 1024,
            max_mutations_per_tenant: 128,
            max_audit_rows_per_tenant: 4096,
            max_acknowledged_per_tenant: 256,
            max_payload_bytes_per_tenant: 16 * 1024 * 1024,
            failures_before_suspend: 8,
        }
    }
}
impl WebhookStoreConfig {
    pub(crate) fn digest(&self) -> [u8; 32] {
        let text = format!(
            "browserd:webhooks:v1:{}:{}:{}:{}:{}:{}",
            self.max_endpoints,
            self.max_mutations_per_tenant,
            self.max_audit_rows_per_tenant,
            self.max_acknowledged_per_tenant,
            self.max_payload_bytes_per_tenant,
            self.failures_before_suspend
        );
        Sha256::digest(text.as_bytes()).into()
    }
    pub fn new(
        max_endpoints: usize,
        max_mutations_per_tenant: usize,
        max_audit_rows_per_tenant: usize,
        max_acknowledged_per_tenant: usize,
        max_payload_bytes_per_tenant: usize,
        failures_before_suspend: u32,
    ) -> Result<Self, Error> {
        let v = Self {
            max_endpoints,
            max_mutations_per_tenant,
            max_audit_rows_per_tenant,
            max_acknowledged_per_tenant,
            max_payload_bytes_per_tenant,
            failures_before_suspend,
        };
        v.validate()?;
        Ok(v)
    }
    pub(crate) fn validate(&self) -> Result<(), Error> {
        if !(1..=65536).contains(&self.max_endpoints)
            || !(1..=1024).contains(&self.max_mutations_per_tenant)
            || !(3..=16384).contains(&self.max_audit_rows_per_tenant)
            || !(1..=1024).contains(&self.max_acknowledged_per_tenant)
            || !(MAX_WEBHOOK_BODY_BYTES..=64 * 1024 * 1024)
                .contains(&self.max_payload_bytes_per_tenant)
            || !(1..=64).contains(&self.failures_before_suspend)
        {
            Err(Error::InvalidConfiguration)
        } else {
            Ok(())
        }
    }
}
pub trait WebhookClock: Send + Sync {
    fn now(&self) -> DateTime<Utc>;
}
#[async_trait]
pub trait WebhookStore: Send + Sync {
    async fn put_endpoint(
        &self,
        request: WebhookPutRequest,
    ) -> Result<WebhookEndpointSnapshot, Error>;
    async fn get_endpoint(
        &self,
        tenant: &TenantId,
    ) -> Result<Option<WebhookEndpointSnapshot>, Error>;
    async fn delete_endpoint(
        &self,
        expected: &WebhookEndpointRef,
        binding: WebhookMutationBinding,
    ) -> Result<WebhookEndpointSnapshot, Error>;
    async fn suspend_endpoint(
        &self,
        expected: &WebhookEndpointRef,
        binding: WebhookMutationBinding,
    ) -> Result<WebhookEndpointSnapshot, Error>;
    async fn resume_endpoint(
        &self,
        expected: &WebhookEndpointRef,
        binding: WebhookMutationBinding,
        mode: WebhookResumeMode,
    ) -> Result<WebhookEndpointSnapshot, Error>;
    async fn claim_due_attempts(
        &self,
        cursor: WebhookDeliveryCursor,
        limit: usize,
        max_attempts: usize,
        lease_ttl: Duration,
    ) -> Result<WebhookAttemptPage, Error>;
    async fn finish_attempt(
        &self,
        lease: &WebhookAttemptLease,
        outcome: WebhookAttemptOutcome,
    ) -> Result<WebhookAttemptResult, Error>;
    async fn maintain(
        &self,
        cursor: WebhookDeliveryCursor,
        limit: usize,
    ) -> Result<WebhookMaintenancePage, Error>;
}
