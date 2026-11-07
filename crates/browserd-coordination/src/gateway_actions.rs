use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use browserd_actions::{
    ActionDeliveryEvidence, ActionEvidence, ActionEvidenceError, ActionEvidenceMutation,
    ActionKind, ActionResultBudget, ActionSequence, ActionTerminalEvidence, ActionTerminalSource,
    BrowserResult, CanonicalRequestHash, DispatchId, IdempotencyKey, ResolutionAnnotation,
    TerminalCustodyReceipt, TerminalCustodyRequirement, TerminalDetail, TransportLoss,
};
use browserd_core::{ActionId, ActionState, LeaseId, SessionId, TenantId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::{Uuid, Version};

use crate::{
    DirectoryFence, MemoryCoordinationDatabase, OutboxAppend, OutboxEventKind, StoreConfig,
};

mod fleet_memory;
mod redis;

use crate::session_admission::*;
use crate::{DirectoryKey, DispatchLeaseToken};

pub use redis::{
    RedisGatewayActionConfig, RedisGatewayActionMigrationProgress, RedisGatewayActionStore,
};

const MAX_MATERIALIZATION_LIMIT: usize = 1_000;
const MAX_EVENT_SCAN_LIMIT: usize = 256;
const MAX_EVENT_SEQUENCE: u64 = i64::MAX as u64;
pub const MAX_RECOVERY_SCAN_LIMIT: usize = 256;
pub const MAX_PENDING_ACTIONS_PER_SESSION: usize = 256;
pub const MAX_PENDING_ACTIONS_PER_NAMESPACE: usize = 65_536;
const MAX_SUBMISSION_ADMISSION_SECONDS: i64 = 5 * 60;

/// A fast, trusted store clock. Implementations must not block or call back into this store.
pub trait GatewayActionRetentionClock: Send + Sync {
    fn now(&self) -> DateTime<Utc>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GatewayActionRetentionLimits {
    namespace_records: usize,
    session_records: usize,
}
impl GatewayActionRetentionLimits {
    const DEFAULT: Self = Self {
        namespace_records: 65_536,
        session_records: 4096,
    };
    pub fn new(
        namespace_records: usize,
        session_records: usize,
    ) -> Result<Self, GatewayActionCoordinationError> {
        if namespace_records == 0
            || namespace_records > 1_048_576
            || session_records == 0
            || session_records > 65_536
            || session_records > namespace_records
        {
            return Err(GatewayActionCoordinationError::InvalidRetentionLimits);
        }
        Ok(Self {
            namespace_records,
            session_records,
        })
    }
    #[must_use]
    pub const fn namespace_records(self) -> usize {
        self.namespace_records
    }
    #[must_use]
    pub const fn session_records(self) -> usize {
        self.session_records
    }
}
impl Default for GatewayActionRetentionLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct GatewayActionRetentionCursor {
    schema_version: u8,
    after: Option<(u64, TenantId, SessionId, ActionId)>,
}
impl<'de> Deserialize<'de> for GatewayActionRetentionCursor {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            schema_version: u8,
            after: Option<(u64, TenantId, SessionId, ActionId)>,
        }
        let wire = Wire::deserialize(deserializer)?;
        let cursor = Self {
            schema_version: wire.schema_version,
            after: wire.after,
        };
        cursor.validate().map_err(serde::de::Error::custom)?;
        Ok(cursor)
    }
}
impl Default for GatewayActionRetentionCursor {
    fn default() -> Self {
        Self {
            schema_version: 1,
            after: None,
        }
    }
}
impl GatewayActionRetentionCursor {
    pub(super) fn after(
        deadline: u64,
        tenant: TenantId,
        session: SessionId,
        action: ActionId,
    ) -> Self {
        Self {
            schema_version: 1,
            after: Some((deadline, tenant, session, action)),
        }
    }
    fn validate(&self) -> Result<(), GatewayActionCoordinationError> {
        if self.schema_version != 1 {
            return Err(GatewayActionCoordinationError::CorruptState);
        }
        Ok(())
    }
}
#[derive(Clone, Debug)]
pub struct GatewayActionRetentionPage {
    next_cursor: GatewayActionRetentionCursor,
    complete: bool,
    examined: usize,
    reclaimed: usize,
    deferred: usize,
}
impl GatewayActionRetentionPage {
    pub fn new(
        next_cursor: GatewayActionRetentionCursor,
        complete: bool,
        examined: usize,
        reclaimed: usize,
        deferred: usize,
    ) -> Result<Self, GatewayActionCoordinationError> {
        next_cursor.validate()?;
        if examined > 256 || reclaimed.checked_add(deferred) != Some(examined) {
            return Err(GatewayActionCoordinationError::CorruptState);
        }
        Ok(Self {
            next_cursor,
            complete,
            examined,
            reclaimed,
            deferred,
        })
    }
    #[must_use]
    pub const fn next_cursor(&self) -> &GatewayActionRetentionCursor {
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
    #[must_use]
    pub const fn deferred(&self) -> usize {
        self.deferred
    }
}

/// A durable obligation to transfer exactly one terminal WAL revision to the coordinator.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayPendingCustody {
    receipt: TerminalCustodyReceipt,
    action_revision: u64,
    #[serde(default)]
    release: bool,
}
impl GatewayPendingCustody {
    #[must_use]
    pub const fn receipt(&self) -> &TerminalCustodyReceipt {
        &self.receipt
    }
    #[must_use]
    pub const fn action_revision(&self) -> u64 {
        self.action_revision
    }
    #[must_use]
    pub const fn is_release(&self) -> bool {
        self.release
    }
}
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GatewayCustodyCursor {
    after: Option<(TenantId, SessionId, ActionId)>,
}
#[derive(Clone, Debug)]
pub struct GatewayCustodyPage {
    entries: Vec<GatewayPendingCustody>,
    next_cursor: GatewayCustodyCursor,
    complete: bool,
}
impl GatewayCustodyPage {
    #[must_use]
    pub fn entries(&self) -> &[GatewayPendingCustody] {
        &self.entries
    }
    #[must_use]
    pub const fn next_cursor(&self) -> &GatewayCustodyCursor {
        &self.next_cursor
    }
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.complete
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct GatewayCustodyState {
    entry: GatewayPendingCustody,
    acknowledged: bool,
    #[serde(default)]
    released: bool,
}

/// Immutable authority to cross the submission boundary. Recovery never transfers this
/// authority: an expired unattempted submission is failed, and an armed action is only queried.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayActionSubmissionLease {
    token: Uuid,
    generation: u64,
    expires_at: DateTime<Utc>,
    admission_deadline: DateTime<Utc>,
}

impl GatewayActionSubmissionLease {
    pub fn new(
        token: Uuid,
        generation: u64,
        expires_at: DateTime<Utc>,
        admission_deadline: DateTime<Utc>,
    ) -> Result<Self, GatewayActionCoordinationError> {
        let lease = Self {
            token,
            generation,
            expires_at,
            admission_deadline,
        };
        lease.validate()?;
        Ok(lease)
    }

    fn validate(&self) -> Result<(), GatewayActionCoordinationError> {
        if self.token.get_version() != Some(Version::SortRand)
            || self.generation == 0
            || self.expires_at.timestamp_millis() <= 0
            || self.expires_at > self.admission_deadline
        {
            return Err(GatewayActionCoordinationError::InvalidSubmissionLease);
        }
        Ok(())
    }

    fn validate_claim(&self, now: DateTime<Utc>) -> Result<(), GatewayActionCoordinationError> {
        self.validate()?;
        if now >= self.expires_at {
            return Err(GatewayActionCoordinationError::SubmissionLeaseExpired);
        }
        if self.admission_deadline.signed_duration_since(now)
            > chrono::Duration::seconds(MAX_SUBMISSION_ADMISSION_SECONDS)
        {
            return Err(GatewayActionCoordinationError::InvalidSubmissionLease);
        }
        Ok(())
    }

    #[must_use]
    pub const fn token(&self) -> &Uuid {
        &self.token
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
    pub const fn admission_deadline(&self) -> DateTime<Utc> {
        self.admission_deadline
    }
}

/// Opaque lexicographic discovery position. Restarting a completed scan is safe; terminal
/// deletions do not shift this position, and inserts behind it are visited on the next pass.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GatewayActionRecoveryCursor {
    after: Option<(TenantId, SessionId, ActionId)>,
}

#[derive(Clone, Debug)]
pub struct GatewayActionRecoveryPage {
    actions: Vec<GatewayActionSnapshot>,
    next_cursor: GatewayActionRecoveryCursor,
    complete: bool,
}

impl GatewayActionRecoveryPage {
    #[must_use]
    pub fn actions(&self) -> &[GatewayActionSnapshot] {
        &self.actions
    }
    #[must_use]
    pub const fn next_cursor(&self) -> &GatewayActionRecoveryCursor {
        &self.next_cursor
    }
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.complete
    }
}

/// A bounded pass over the retained catalog, including rows that need no custody lookup.
#[derive(Clone, Debug)]
pub struct GatewayTerminalCustodyCatchupPage {
    actions: Vec<GatewayActionSnapshot>,
    next_cursor: GatewayActionRecoveryCursor,
    complete: bool,
    examined: usize,
}
impl GatewayTerminalCustodyCatchupPage {
    pub fn new(
        actions: Vec<GatewayActionSnapshot>,
        next_cursor: GatewayActionRecoveryCursor,
        complete: bool,
        examined: usize,
    ) -> Result<Self, GatewayActionCoordinationError> {
        if examined > MAX_RECOVERY_SCAN_LIMIT
            || actions.len() > examined
            || actions
                .iter()
                .any(|action| !action.requires_terminal_custody_catchup())
        {
            return Err(GatewayActionCoordinationError::CorruptState);
        }
        Ok(Self {
            actions,
            next_cursor,
            complete,
            examined,
        })
    }
    #[must_use]
    pub fn actions(&self) -> &[GatewayActionSnapshot] {
        &self.actions
    }
    #[must_use]
    pub const fn next_cursor(&self) -> &GatewayActionRecoveryCursor {
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

/// Independent permanent source sequences projected into the same ordered tenant stream.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventProjectionSource {
    #[default]
    Terminal,
    ViewerControl,
}

impl EventProjectionSource {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Terminal => "terminal",
            Self::ViewerControl => "viewer_control",
        }
    }
}

/// An immutable, source-ordered projection. The session sequence survives payload retention.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GatewayEventProjection {
    #[serde(default)]
    source: EventProjectionSource,
    tenant_id: TenantId,
    session_id: SessionId,
    sequence: u64,
    append: OutboxAppend,
}

impl GatewayEventProjection {
    pub fn new(
        tenant_id: TenantId,
        session_id: SessionId,
        sequence: u64,
        append: OutboxAppend,
    ) -> Result<Self, GatewayActionCoordinationError> {
        Self::new_with_source(
            EventProjectionSource::Terminal,
            tenant_id,
            session_id,
            sequence,
            append,
        )
    }

    pub fn new_with_source(
        source: EventProjectionSource,
        tenant_id: TenantId,
        session_id: SessionId,
        sequence: u64,
        append: OutboxAppend,
    ) -> Result<Self, GatewayActionCoordinationError> {
        if sequence == 0
            || sequence > MAX_EVENT_SEQUENCE
            || append.tenant_id() != &tenant_id
            || append.session_id() != Some(&session_id)
            || (source == EventProjectionSource::ViewerControl)
                != (append.kind() == OutboxEventKind::ControlChanged)
            || (source == EventProjectionSource::ViewerControl
                && append.aggregate_revision() != sequence)
        {
            return Err(GatewayActionCoordinationError::CorruptState);
        }
        Ok(Self {
            source,
            tenant_id,
            session_id,
            sequence,
            append,
        })
    }

    #[must_use]
    pub const fn source(&self) -> EventProjectionSource {
        self.source
    }

    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }
    #[must_use]
    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
    }
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
    #[must_use]
    pub const fn append(&self) -> &OutboxAppend {
        &self.append
    }
}

/// Restarting at the default cursor is safe. Redis SCAN may repeat scopes; exact ACK is idempotent.
#[derive(Clone, Debug, Default)]
pub struct GatewayEventScanCursor {
    redis_cursor: u64,
    redis_pending: VecDeque<(TenantId, SessionId)>,
    memory_after: Option<(TenantId, SessionId)>,
}

#[derive(Clone, Debug)]
pub struct GatewayEventSession {
    tenant_id: TenantId,
    session_id: SessionId,
    loss_claim: Option<SessionLossClaim>,
}

impl GatewayEventSession {
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }
    #[must_use]
    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
    }
    #[must_use]
    pub const fn loss_claim(&self) -> Option<&SessionLossClaim> {
        self.loss_claim.as_ref()
    }
}

#[derive(Clone, Debug)]
pub struct GatewayEventScanPage {
    sessions: Vec<GatewayEventSession>,
    next_cursor: GatewayEventScanCursor,
    complete: bool,
}

impl GatewayEventScanPage {
    #[must_use]
    pub fn sessions(&self) -> &[GatewayEventSession] {
        &self.sessions
    }
    #[must_use]
    pub const fn next_cursor(&self) -> &GatewayEventScanCursor {
        &self.next_cursor
    }
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.complete
    }
}

/// Upper bound on the durable result body persisted with a succeeded action, matching the
/// worker's action result cap. Bodies larger than this are not produced by the current result
/// set; capture artifacts are stored by reference rather than inlined here.
pub const MAX_DURABLE_RESULT_CONTENT_BYTES: usize = 64 * 1024;

/// Validates that a durable result body is paired only with a succeeded action and stays within
/// the trusted accepted action's result profile. Bodies are validated against the digest upstream (on the
/// worker receipt), so this is a fail-closed boundary guard, not the primary integrity check.
fn validate_durable_result_body(
    result: BrowserResult,
    result_body: &Option<Vec<u8>>,
    result_budget: ActionResultBudget,
) -> Result<(), GatewayActionCoordinationError> {
    match result_body {
        None => Ok(()),
        Some(body) => {
            if !matches!(result, BrowserResult::Succeeded(_))
                || body.is_empty()
                || body.len() > result_budget.max_bytes()
            {
                Err(GatewayActionCoordinationError::CorruptState)
            } else {
                Ok(())
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GatewayActionPlacement {
    directory_fence: DirectoryFence,
    directory_revision: u64,
}

impl GatewayActionPlacement {
    pub fn new(
        directory_fence: DirectoryFence,
        directory_revision: u64,
    ) -> Result<Self, GatewayActionCoordinationError> {
        if directory_revision == 0 {
            return Err(GatewayActionCoordinationError::InvalidPlacement);
        }
        Ok(Self {
            directory_fence,
            directory_revision,
        })
    }

    #[must_use]
    pub const fn directory_fence(&self) -> &DirectoryFence {
        &self.directory_fence
    }

    #[must_use]
    pub const fn directory_revision(&self) -> u64 {
        self.directory_revision
    }
}

fn validated_idempotency_key(
    value: impl Into<String>,
) -> Result<IdempotencyKey, GatewayActionCoordinationError> {
    let value = value.into();
    if value.is_empty()
        || value.len() > 255
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(GatewayActionCoordinationError::InvalidIdempotencyKey);
    }
    Ok(IdempotencyKey::new(value))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimGatewayAction {
    tenant_id: TenantId,
    session_id: SessionId,
    proposed_action_id: ActionId,
    idempotency_key: IdempotencyKey,
    request_hash: CanonicalRequestHash,
    kind: ActionKind,
    result_budget: ActionResultBudget,
    placement: GatewayActionPlacement,
    submission_lease: Option<GatewayActionSubmissionLease>,
}

impl ClaimGatewayAction {
    pub fn new(
        tenant_id: TenantId,
        session_id: SessionId,
        proposed_action_id: ActionId,
        idempotency_key: impl Into<String>,
        request_hash: CanonicalRequestHash,
        kind: ActionKind,
        placement: GatewayActionPlacement,
    ) -> Result<Self, GatewayActionCoordinationError> {
        Ok(Self {
            tenant_id,
            session_id,
            proposed_action_id,
            idempotency_key: validated_idempotency_key(idempotency_key)?,
            request_hash,
            kind,
            result_budget: ActionResultBudget::Standard,
            placement,
            submission_lease: None,
        })
    }

    #[must_use]
    pub fn with_submission_lease(mut self, lease: GatewayActionSubmissionLease) -> Self {
        self.submission_lease = Some(lease);
        self
    }

    /// Set only from the normalized action whose immutable hash is carried by this claim.
    #[must_use]
    pub const fn with_result_budget(mut self, result_budget: ActionResultBudget) -> Self {
        self.result_budget = result_budget;
        self
    }

    #[must_use]
    pub const fn result_budget(&self) -> ActionResultBudget {
        self.result_budget
    }

    #[must_use]
    pub const fn submission_lease(&self) -> Option<&GatewayActionSubmissionLease> {
        self.submission_lease.as_ref()
    }

    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    #[must_use]
    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    #[must_use]
    pub const fn proposed_action_id(&self) -> &ActionId {
        &self.proposed_action_id
    }

    #[must_use]
    pub fn idempotency_key(&self) -> &str {
        self.idempotency_key.as_str()
    }

    #[must_use]
    pub const fn request_hash(&self) -> CanonicalRequestHash {
        self.request_hash
    }

    #[must_use]
    pub const fn kind(&self) -> ActionKind {
        self.kind
    }

    #[must_use]
    pub const fn placement(&self) -> &GatewayActionPlacement {
        &self.placement
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayActionSnapshot {
    tenant_id: TenantId,
    session_id: SessionId,
    action_id: ActionId,
    idempotency_key: IdempotencyKey,
    request_hash: CanonicalRequestHash,
    kind: ActionKind,
    result_budget: ActionResultBudget,
    placement: GatewayActionPlacement,
    evidence: ActionEvidence,
    submission_lease: Option<GatewayActionSubmissionLease>,
    resolution: Option<ResolutionAnnotation>,
    result_content: Option<Vec<u8>>,
    custody: Option<GatewayCustodyState>,
    action_sequence: ActionSequence,
    revision: u64,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    retain_until: DateTime<Utc>,
    last_source_event_sequence: Option<u64>,
    custody_requirement: Option<TerminalCustodyRequirement>,
    original_worker_terminal_revision: Option<u64>,
}

impl GatewayActionSnapshot {
    fn validate_custody_receipt(
        &self,
        receipt: &TerminalCustodyReceipt,
    ) -> Result<(), GatewayActionCoordinationError> {
        if self.custody_requirement == Some(TerminalCustodyRequirement::Unsupported) {
            return Err(GatewayActionCoordinationError::InvalidCustodyReceipt);
        }
        receipt
            .validate()
            .map_err(|_| GatewayActionCoordinationError::InvalidCustodyReceipt)?;
        let fence = self.placement.directory_fence();
        let original = receipt.fence();
        if receipt.tenant_id() != &self.tenant_id
            || receipt.session_id() != &self.session_id
            || receipt.action_id() != &self.action_id
            || receipt.action_sequence() != self.action_sequence
            || receipt.kind() != self.kind
            || receipt.original_worker_id() != fence.worker_id()
            || original.worker_epoch != fence.worker_epoch()
            || original.placement_version != fence.placement_version()
            || original.session_incarnation != fence.session_incarnation()
            || self.terminal().map(|terminal| terminal.detail()) != Some(receipt.terminal())
            || self.resolution.as_ref() != receipt.resolution()
        {
            return Err(GatewayActionCoordinationError::InvalidCustodyReceipt);
        }
        Ok(())
    }

    // Existing ACK proof stays in the action payload, separate from the pending discovery index.
    fn attach_custody(
        &mut self,
        receipt: Option<&TerminalCustodyReceipt>,
    ) -> Result<bool, GatewayActionCoordinationError> {
        let Some(receipt) = receipt else {
            return Ok(false);
        };
        self.validate_custody_receipt(receipt)?;
        self.install_custody(receipt, self.revision)
    }

    fn install_custody(
        &mut self,
        receipt: &TerminalCustodyReceipt,
        action_revision: u64,
    ) -> Result<bool, GatewayActionCoordinationError> {
        if action_revision == 0 || action_revision > self.revision {
            return Err(GatewayActionCoordinationError::InvalidCustodyReceipt);
        }
        if let Some(current) = &self.custody {
            let old = current.entry.receipt();
            if old == receipt {
                return Ok(false);
            }
            if old.scope() != receipt.scope()
                || old.action_id() != receipt.action_id()
                || old.action_sequence() != receipt.action_sequence()
                || old.kind() != receipt.kind()
                || old.request_hash() != receipt.request_hash()
                || old.dispatch_id() != receipt.dispatch_id()
                || old.terminal() != receipt.terminal()
                || old.resolution().is_some()
                || receipt.resolution().is_none()
            {
                return Err(GatewayActionCoordinationError::InvalidCustodyReceipt);
            }
        }
        self.custody = Some(GatewayCustodyState {
            entry: GatewayPendingCustody {
                receipt: receipt.clone(),
                action_revision,
                release: false,
            },
            acknowledged: false,
            released: false,
        });
        Ok(true)
    }

    /// Unsupported is original response evidence, never a late downgrade of legacy ambiguity.
    fn merge_custody_requirement(
        &mut self,
        requirement: Option<TerminalCustodyRequirement>,
        receipt: Option<&TerminalCustodyReceipt>,
        is_first_terminal: bool,
    ) -> Result<bool, GatewayActionCoordinationError> {
        let requirement = match (requirement, receipt.is_some() || self.custody.is_some()) {
            (Some(TerminalCustodyRequirement::Unsupported), true) => {
                return Err(GatewayActionCoordinationError::InvalidCustodyReceipt);
            }
            (None, true) => Some(TerminalCustodyRequirement::Required),
            (requirement, _) => requirement,
        };
        let Some(requirement) = requirement else {
            return Ok(false);
        };
        if self.terminal().map(|terminal| terminal.source()) != Some(ActionTerminalSource::Worker) {
            return Err(GatewayActionCoordinationError::InvalidCustodyReceipt);
        }
        match self.custody_requirement {
            Some(current) if current != requirement => {
                Err(GatewayActionCoordinationError::InvalidCustodyReceipt)
            }
            Some(_) => Ok(false),
            None if requirement == TerminalCustodyRequirement::Unsupported
                && !is_first_terminal =>
            {
                Err(GatewayActionCoordinationError::InvalidCustodyReceipt)
            }
            None => {
                self.custody_requirement = Some(requirement);
                Ok(true)
            }
        }
    }

    /// Attach only WAL custody. Gateway resolution and the terminal's original revision survive.
    fn attach_terminal_custody_receipt(
        &mut self,
        receipt: &TerminalCustodyReceipt,
    ) -> Result<bool, GatewayActionCoordinationError> {
        if self.terminal().map(|terminal| terminal.source()) != Some(ActionTerminalSource::Worker) {
            return Err(GatewayActionCoordinationError::InvalidCustodyReceipt);
        }
        let mut version = self.clone();
        let action_revision = if self.resolution.as_ref() == receipt.resolution() {
            self.revision
        } else if receipt.resolution().is_none()
            && self.resolution.is_some()
            && matches!(
                self.terminal().map(|terminal| terminal.detail()),
                Some(TerminalDetail::OutcomeUnknown(_))
            )
        {
            let revision = self
                .original_worker_terminal_revision
                .filter(|revision| *revision > 0 && *revision < self.revision)
                .ok_or(GatewayActionCoordinationError::InvalidCustodyReceipt)?;
            version.resolution = None;
            revision
        } else {
            return Err(GatewayActionCoordinationError::InvalidCustodyReceipt);
        };
        version.validate_custody_receipt(receipt)?;
        self.install_custody(receipt, action_revision)
    }

    fn adopt_worker_resolution(
        &mut self,
        resolution: Option<&ResolutionAnnotation>,
        mutation: ActionEvidenceMutation,
    ) -> Result<ActionEvidenceMutation, GatewayActionCoordinationError> {
        let Some(resolution) = resolution else {
            return Ok(mutation);
        };
        if !matches!(
            self.terminal().map(|terminal| terminal.detail()),
            Some(TerminalDetail::OutcomeUnknown(_))
        ) {
            return Err(GatewayActionCoordinationError::InvalidCustodyReceipt);
        }
        if let Some(current) = &self.resolution {
            return if current == resolution {
                Ok(mutation)
            } else {
                Err(GatewayActionCoordinationError::ResolutionConflict)
            };
        }
        self.resolution = Some(resolution.clone());
        Ok(ActionEvidenceMutation::Recorded)
    }

    fn validate_stored_custody(&self) -> Result<(), GatewayActionCoordinationError> {
        if (self.custody_requirement.is_some() || self.original_worker_terminal_revision.is_some())
            && self.terminal().map(|terminal| terminal.source())
                != Some(ActionTerminalSource::Worker)
        {
            return Err(GatewayActionCoordinationError::InvalidCustodyReceipt);
        }
        if self
            .original_worker_terminal_revision
            .is_some_and(|revision| revision == 0 || revision > self.revision)
        {
            return Err(GatewayActionCoordinationError::InvalidCustodyReceipt);
        }
        let Some(state) = &self.custody else {
            return Ok(());
        };
        if state.entry.action_revision == 0
            || state.entry.action_revision > self.revision
            || state.acknowledged != state.entry.release
            || (state.released && !state.acknowledged)
        {
            return Err(GatewayActionCoordinationError::InvalidCustodyReceipt);
        }
        let mut version = self.clone();
        // A gateway-only resolution does not fabricate a replacement worker receipt.
        if state.entry.receipt.resolution().is_none()
            && self.resolution.is_some()
            && state.entry.action_revision < self.revision
        {
            version.resolution = None;
        }
        version.validate_custody_receipt(&state.entry.receipt)
    }

    fn copy_custody_ack(
        &mut self,
        entry: &GatewayPendingCustody,
    ) -> Result<bool, GatewayActionCoordinationError> {
        let current = self
            .custody
            .as_mut()
            .ok_or(GatewayActionCoordinationError::CustodyAckConflict)?;
        if entry.release
            || current.entry.receipt != entry.receipt
            || current.entry.action_revision != entry.action_revision
        {
            return Err(GatewayActionCoordinationError::CustodyAckConflict);
        }
        if current.acknowledged {
            return Ok(false);
        }
        current.acknowledged = true;
        current.entry.release = true;
        Ok(true)
    }

    fn complete_custody_release(
        &mut self,
        entry: &GatewayPendingCustody,
    ) -> Result<bool, GatewayActionCoordinationError> {
        let current = self
            .custody
            .as_mut()
            .ok_or(GatewayActionCoordinationError::CustodyAckConflict)?;
        if !entry.release || !current.acknowledged || current.entry != *entry {
            return Err(GatewayActionCoordinationError::CustodyAckConflict);
        }
        if current.released {
            return Ok(false);
        }
        current.released = true;
        Ok(true)
    }

    fn pending_custody(&self) -> Option<&GatewayPendingCustody> {
        self.custody
            .as_ref()
            .filter(|state| !state.released)
            .map(|state| &state.entry)
    }

    fn validate_submission_lease(
        &self,
        lease: &GatewayActionSubmissionLease,
        now: DateTime<Utc>,
        require_expired: bool,
    ) -> Result<(), GatewayActionCoordinationError> {
        lease.validate()?;
        let current = self
            .submission_lease
            .as_ref()
            .ok_or(GatewayActionCoordinationError::SubmissionLeaseRequired)?;
        if current != lease {
            return Err(GatewayActionCoordinationError::SubmissionLeaseMismatch);
        }
        if now < self.created_at || now < self.updated_at {
            return Err(GatewayActionCoordinationError::InvalidSubmissionLease);
        }
        let expired = now >= lease.expires_at;
        if require_expired && !expired {
            return Err(GatewayActionCoordinationError::SubmissionLeaseNotExpired);
        }
        if !require_expired && expired {
            return Err(GatewayActionCoordinationError::SubmissionLeaseExpired);
        }
        Ok(())
    }

    #[must_use]
    pub const fn submission_lease(&self) -> Option<&GatewayActionSubmissionLease> {
        self.submission_lease.as_ref()
    }

    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    #[must_use]
    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    #[must_use]
    pub const fn action_id(&self) -> &ActionId {
        &self.action_id
    }

    #[must_use]
    pub fn idempotency_key(&self) -> &str {
        self.idempotency_key.as_str()
    }

    #[must_use]
    pub const fn request_hash(&self) -> CanonicalRequestHash {
        self.request_hash
    }

    #[must_use]
    pub const fn kind(&self) -> ActionKind {
        self.kind
    }

    #[must_use]
    pub const fn placement(&self) -> &GatewayActionPlacement {
        &self.placement
    }

    #[must_use]
    pub const fn delivery(&self) -> &ActionDeliveryEvidence {
        self.evidence.delivery()
    }

    #[must_use]
    pub fn terminal(&self) -> Option<ActionTerminalEvidence> {
        self.evidence.terminal().copied()
    }

    #[must_use]
    pub fn state(&self) -> ActionState {
        self.evidence.state()
    }

    #[must_use]
    pub const fn resolution(&self) -> Option<&ResolutionAnnotation> {
        self.resolution.as_ref()
    }

    /// Durable copy of a succeeded action's result body.
    ///
    /// Persisted alongside the terminal evidence so that GET, same-key resubmission, and
    /// gateway/worker restart all return the same result bytes the completing receipt carried,
    /// not just the `ResultDigest`. Bounded by the durable accepted action's result profile.
    #[must_use]
    pub fn result_content(&self) -> Option<&[u8]> {
        self.result_content.as_deref()
    }

    #[must_use]
    pub const fn result_budget(&self) -> ActionResultBudget {
        self.result_budget
    }

    #[must_use]
    pub const fn action_sequence(&self) -> ActionSequence {
        self.action_sequence
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
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
    pub const fn retain_until(&self) -> DateTime<Utc> {
        self.retain_until
    }
    /// Exact last durable terminal/resolution source event. Legacy absence never authorizes GC.
    #[must_use]
    pub const fn custody_requirement(&self) -> Option<TerminalCustodyRequirement> {
        self.custody_requirement
    }
    #[must_use]
    pub const fn original_worker_terminal_revision(&self) -> Option<u64> {
        self.original_worker_terminal_revision
    }
    #[must_use]
    pub fn requires_terminal_custody_catchup(&self) -> bool {
        self.terminal()
            .is_some_and(|terminal| terminal.source() == ActionTerminalSource::Worker)
            && self.custody.is_none()
            && self.custody_requirement != Some(TerminalCustodyRequirement::Unsupported)
    }

    #[must_use]
    pub const fn last_source_event_sequence(&self) -> Option<u64> {
        self.last_source_event_sequence
    }

    /// Project this snapshot into the event-outbox append that records its terminal transition, or
    /// `None` while the action has not yet reached a terminal outcome.
    ///
    /// The append carries the durable [`GatewayActionSnapshot::revision`] as the aggregate
    /// revision. Source mutations journal this descriptor atomically with every terminal revision;
    /// recovery reads that immutable journal, since a later resolution can replace this snapshot.
    #[must_use]
    pub fn terminal_outbox_append(&self) -> Option<OutboxAppend> {
        // Notification-capable worker journals own their complete immutable state
        // batches. Their custody receipt persists this capability across recovery.
        if self.worker_owns_notifications() {
            return None;
        }
        if self
            .custody
            .as_ref()
            .is_some_and(|state| state.entry.receipt().notification_source().is_some())
            && let Some(resolution) = &self.resolution
        {
            // A gateway-only reconciliation is its own authority change when the
            // original worker cannot produce a replacement receipt.
            return OutboxAppend::state_changed(
                self.tenant_id.clone(),
                crate::OutboxAggregate::Action {
                    session_id: self.session_id.clone(),
                    action_id: self.action_id.clone(),
                },
                self.revision,
                crate::OutboxEventKind::ActionStateChanged,
                crate::EventStateSummary::Action {
                    state: crate::EventActionState::OutcomeUnknown,
                    resolution: Some(match resolution.kind() {
                        browserd_actions::ResolutionKind::ConfirmedExecuted => {
                            crate::EventActionResolution::ConfirmedExecuted
                        }
                        browserd_actions::ResolutionKind::ConfirmedNotExecuted => {
                            crate::EventActionResolution::ConfirmedNotExecuted
                        }
                        browserd_actions::ResolutionKind::Abandoned => {
                            crate::EventActionResolution::Abandoned
                        }
                    }),
                },
            )
            .ok();
        }
        self.terminal().map(|_| {
            OutboxAppend::action_terminal(
                self.tenant_id.clone(),
                self.session_id.clone(),
                self.action_id.clone(),
                self.revision,
            )
        })
    }

    fn worker_owns_notifications(&self) -> bool {
        self.custody.as_ref().is_some_and(|state| {
            state.entry.receipt().notification_source().is_some()
                && state.entry.receipt().resolution() == self.resolution.as_ref()
        })
    }

    fn derive_worker_loss(&mut self) -> Result<(), GatewayActionCoordinationError> {
        self.evidence.materialize_worker_loss()?;
        Ok(())
    }

    fn requires_reconciliation(&self) -> bool {
        self.kind == ActionKind::Mutating
            && self.resolution.is_none()
            && matches!(
                self.terminal().map(|terminal| terminal.detail()),
                Some(TerminalDetail::OutcomeUnknown(_))
            )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GatewayActionClaimOutcome {
    Created(GatewayActionSnapshot),
    Existing(GatewayActionSnapshot),
}

impl GatewayActionClaimOutcome {
    #[must_use]
    pub const fn snapshot(&self) -> &GatewayActionSnapshot {
        match self {
            Self::Created(snapshot) | Self::Existing(snapshot) => snapshot,
        }
    }

    #[must_use]
    pub fn into_snapshot(self) -> GatewayActionSnapshot {
        match self {
            Self::Created(snapshot) | Self::Existing(snapshot) => snapshot,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SessionLossClaim {
    tenant_id: TenantId,
    session_id: SessionId,
    placement: GatewayActionPlacement,
    loss_id: Uuid,
}

impl SessionLossClaim {
    #[must_use]
    pub const fn new(
        tenant_id: TenantId,
        session_id: SessionId,
        placement: GatewayActionPlacement,
        loss_id: Uuid,
    ) -> Self {
        Self {
            tenant_id,
            session_id,
            placement,
            loss_id,
        }
    }

    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    #[must_use]
    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    #[must_use]
    pub const fn placement(&self) -> &GatewayActionPlacement {
        &self.placement
    }

    #[must_use]
    pub const fn loss_id(&self) -> &Uuid {
        &self.loss_id
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionLossOutcome {
    Recorded,
    AlreadyRecorded,
}

/// The stable loss identity committed for one exact session placement.
///
/// `AlreadyRecorded` does not mean its pending action materialization or event delivery has
/// finished. Both outcomes return the canonical claim needed to resume that work.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionLossReceipt {
    claim: SessionLossClaim,
    outcome: SessionLossOutcome,
}

impl SessionLossReceipt {
    #[must_use]
    pub const fn claim(&self) -> &SessionLossClaim {
        &self.claim
    }

    #[must_use]
    pub const fn outcome(&self) -> SessionLossOutcome {
        self.outcome
    }

    #[must_use]
    pub fn into_claim(self) -> SessionLossClaim {
        self.claim
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum GatewayActionCoordinationError {
    #[error("single-host session directory is unsupported")]
    UnsupportedSessionDirectory,
    #[error("single-host session directory record is invalid")]
    InvalidSessionDirectory,
    #[error("single-host session directory capacity is exhausted")]
    SessionDirectoryCapacity,
    #[error("single-host session directory changed concurrently")]
    SessionDirectoryConflict,
    #[error("managed session admission is unsupported")]
    UnsupportedSessionAdmission,
    #[error("session admission configuration or proof is invalid")]
    InvalidSessionAdmission,
    #[error("session admission capacity is exhausted")]
    AdmissionCapacity,
    #[error("session admission identity or state conflicts")]
    AdmissionConflict,
    #[error("session admission was concurrently changed")]
    AdmissionRevisionMismatch,
    #[error("fleet worker observation is invalid or stale")]
    InvalidFleetObservation,
    #[error("managed session authority is unavailable or expired")]
    SessionAuthorityUnavailable,
    #[error("session activation deadline expired")]
    SessionActivationExpired,
    #[error("managed namespace requires authorized action admission")]
    ManagedActionAdmissionRequired,
    #[error("action retention maintenance is unsupported")]
    UnsupportedActionRetention,
    #[error("action retention scan limit must be between 1 and 256")]
    InvalidRetentionScanLimit,
    #[error("action retention limits are invalid")]
    InvalidRetentionLimits,
    #[error("retained action capacity has been reached")]
    RetainedActionCapacity,
    #[error("gateway action recovery namespace requires offline migration")]
    RecoveryMigrationRequired,
    #[error("gateway action recovery namespace migration is incomplete")]
    RecoveryMigrationInProgress,
    #[error("offline migration requires confirmation that old gateway writers are stopped")]
    OfflineMigrationConfirmationRequired,
    #[error("gateway action store does not support nonterminal recovery")]
    UnsupportedActionRecovery,
    #[error("action recovery scan limit must be between 1 and 256")]
    InvalidRecoveryScanLimit,
    #[error("submission lease is invalid")]
    InvalidSubmissionLease,
    #[error("action requires its immutable submission lease")]
    SubmissionLeaseRequired,
    #[error("submission lease does not match the accepted action")]
    SubmissionLeaseMismatch,
    #[error("submission lease has expired")]
    SubmissionLeaseExpired,
    #[error("submission lease has not expired")]
    SubmissionLeaseNotExpired,
    #[error("another action owns or precedes the session dispatch lane")]
    ActionDispatchInFlight { action_id: ActionId },
    #[error("pending action capacity has been reached")]
    PendingActionCapacity,
    #[error("gateway action store does not support event recovery")]
    UnsupportedEventRecovery,
    #[error("gateway event scan limit must be between 1 and 256")]
    InvalidEventScanLimit,
    #[error("gateway event projection sequence overflowed")]
    EventSequenceOverflow,
    #[error("gateway event acknowledgment does not match the oldest pending projection")]
    EventAckConflict,
    #[error("gateway action idempotency key must be 1-255 trimmed printable characters")]
    InvalidIdempotencyKey,
    #[error("gateway action placement must have a non-zero directory revision")]
    InvalidPlacement,
    #[error("session loss identifier must be a UUIDv7")]
    InvalidSessionLossId,
    #[error("gateway action idempotency key belongs to a different request")]
    IdempotencyConflict { existing_action_id: ActionId },
    #[error("gateway action identifier already belongs to another request")]
    ActionIdentityConflict { action_id: ActionId },
    #[error("gateway action placement does not match the session placement")]
    PlacementMismatch,
    #[error("another mutating action owns the session dispatch lane")]
    MutationInFlight { action_id: ActionId },
    #[error("session mutation is blocked until an uncertain action is reconciled")]
    ReconciliationRequired { action_id: ActionId },
    #[error("session has been fenced as lost")]
    SessionLost,
    #[error("session loss has not been recorded")]
    SessionLossNotRecorded,
    #[error("session loss identifier does not match the recorded loss")]
    SessionLossIdentityConflict,
    #[error("gateway action was not found")]
    NotFound,
    #[error("gateway action was concurrently changed")]
    StaleWrite(Box<GatewayActionSnapshot>),
    #[error("gateway action sequence conflicts with the immutable worker result")]
    ActionSequenceConflict,
    #[error("gateway action sequence must be non-zero")]
    InvalidActionSequence,
    #[error("only an outcome-unknown action may be explicitly resolved")]
    ResolutionNotAllowed,
    #[error("gateway action resolution conflicts with its durable annotation")]
    ResolutionConflict,
    #[error("gateway action sequence overflowed")]
    ActionSequenceOverflow,
    #[error("session loss materialization limit must be between 1 and 1000")]
    InvalidMaterializationLimit,
    #[error("gateway action retention timestamp is outside the supported range")]
    RetentionTimestampOverflow,
    #[error("gateway action revision overflowed")]
    RevisionOverflow,
    #[error("gateway action coordination state is internally inconsistent")]
    CorruptState,
    #[error("gateway action coordination state lock is unavailable")]
    LockUnavailable,
    #[error("Redis gateway action configuration is invalid")]
    InvalidRedisConfig,
    #[error("Redis gateway action coordination is unavailable")]
    RedisUnavailable,
    #[error("Redis gateway action coordination timed out")]
    RedisTimedOut,
    #[error("Redis gateway action coordination returned invalid state")]
    InvalidRedisResponse,
    #[error("gateway action coordination actor could not start")]
    ActorSpawn,
    #[error("gateway action coordination actor queue is full")]
    ActorQueueFull,
    #[error("terminal custody recovery is unsupported")]
    UnsupportedCustodyRecovery,
    #[error("terminal custody receipt does not match the durable action")]
    InvalidCustodyReceipt,
    #[error("terminal custody acknowledgement differs from the current obligation")]
    CustodyAckConflict,
    #[error("terminal custody scan limit must be between 1 and 256")]
    InvalidCustodyScanLimit,
    #[error("terminal custody capacity is exhausted")]
    PendingCustodyCapacity,
    #[error("gateway action coordination actor is disconnected")]
    ActorDisconnected,
    #[error("gateway action coordination query timed out")]
    ActorQueryTimedOut,
    #[error("gateway action coordination mutation timed out after admission")]
    ActorMutationTimedOut,
    #[error(transparent)]
    Evidence(#[from] ActionEvidenceError),
}

#[allow(clippy::too_many_arguments)]
#[async_trait]
pub trait GatewayActionCoordination: Send + Sync {
    async fn list_single_host_directory(
        &self,
        _tenant_id: &TenantId,
        _after: Option<&SessionId>,
        _ceiling: Option<&SessionId>,
        _limit: usize,
    ) -> Result<crate::GatewaySessionDirectoryPage, GatewayActionCoordinationError> {
        Err(GatewayActionCoordinationError::UnsupportedSessionDirectory)
    }
    async fn commit_single_host_directory(
        &self,
        _record: crate::GatewaySessionDirectoryRecord,
        _expected_revision: Option<u64>,
    ) -> Result<crate::GatewaySessionDirectoryRecord, GatewayActionCoordinationError> {
        Err(GatewayActionCoordinationError::UnsupportedSessionDirectory)
    }
    async fn get_single_host_directory(
        &self,
        _tenant_id: &TenantId,
        _session_id: &SessionId,
    ) -> Result<Option<crate::GatewaySessionDirectoryRecord>, GatewayActionCoordinationError> {
        Err(GatewayActionCoordinationError::UnsupportedSessionDirectory)
    }
    async fn get_action_by_idempotency(
        &self,
        _tenant_id: &TenantId,
        _session_id: &SessionId,
        _key: &str,
    ) -> Result<Option<GatewayActionSnapshot>, GatewayActionCoordinationError> {
        Err(GatewayActionCoordinationError::UnsupportedSessionDirectory)
    }
    async fn enqueue_session_admission(
        &self,
        _request: GatewaySessionAdmissionRequest,
    ) -> Result<GatewaySessionAdmissionSnapshot, GatewayActionCoordinationError> {
        Err(GatewayActionCoordinationError::UnsupportedSessionAdmission)
    }
    async fn get_session_admission(
        &self,
        _key: &GatewaySessionAdmissionKey,
    ) -> Result<Option<GatewaySessionAdmissionSnapshot>, GatewayActionCoordinationError> {
        Err(GatewayActionCoordinationError::UnsupportedSessionAdmission)
    }
    async fn observe_fleet_worker(
        &self,
        _observation: GatewayFleetWorkerObservation,
        _advisory_ttl: Duration,
    ) -> Result<(), GatewayActionCoordinationError> {
        Err(GatewayActionCoordinationError::UnsupportedSessionAdmission)
    }
    async fn reserve_next_session(
        &self,
        _reservation_ttl: Duration,
    ) -> Result<Option<GatewaySessionAdmissionSnapshot>, GatewayActionCoordinationError> {
        Err(GatewayActionCoordinationError::UnsupportedSessionAdmission)
    }
    async fn record_session_reservation(
        &self,
        _expected: &GatewaySessionAdmissionSnapshot,
        _proof: GatewaySessionWorkerReservationProof,
    ) -> Result<GatewaySessionAdmissionSnapshot, GatewayActionCoordinationError> {
        Err(GatewayActionCoordinationError::UnsupportedSessionAdmission)
    }
    async fn arm_session_create(
        &self,
        _expected: &GatewaySessionAdmissionSnapshot,
        _dispatch_lease: &DispatchLeaseToken,
        _placement_ttl: Duration,
    ) -> Result<GatewaySessionAdmissionSnapshot, GatewayActionCoordinationError> {
        Err(GatewayActionCoordinationError::UnsupportedSessionAdmission)
    }
    async fn commit_session_placement(
        &self,
        _expected: &GatewaySessionAdmissionSnapshot,
        _proof: GatewaySessionWorkerReadyProof,
    ) -> Result<GatewaySessionPlacementAuthority, GatewayActionCoordinationError> {
        Err(GatewayActionCoordinationError::UnsupportedSessionAdmission)
    }
    async fn resolve_session_placement(
        &self,
        _key: &DirectoryKey,
    ) -> Result<Option<GatewaySessionPlacementAuthority>, GatewayActionCoordinationError> {
        Err(GatewayActionCoordinationError::UnsupportedSessionAdmission)
    }
    async fn validate_session_authority(
        &self,
        _authority: &GatewaySessionAuthorityRef,
    ) -> Result<(), GatewayActionCoordinationError> {
        Err(GatewayActionCoordinationError::UnsupportedSessionAdmission)
    }
    async fn begin_session_renewal(
        &self,
        _expected: &GatewaySessionPlacementAuthority,
        _renewal_nonce: LeaseId,
        _placement_ttl: Duration,
    ) -> Result<GatewaySessionRenewalIntent, GatewayActionCoordinationError> {
        Err(GatewayActionCoordinationError::UnsupportedSessionAdmission)
    }
    async fn finish_session_renewal(
        &self,
        _intent: &GatewaySessionRenewalIntent,
        _proof: GatewaySessionWorkerRenewalProof,
    ) -> Result<GatewaySessionPlacementAuthority, GatewayActionCoordinationError> {
        Err(GatewayActionCoordinationError::UnsupportedSessionAdmission)
    }
    async fn begin_session_close(
        &self,
        _expected: &GatewaySessionPlacementAuthority,
    ) -> Result<GatewaySessionPlacementAuthority, GatewayActionCoordinationError> {
        Err(GatewayActionCoordinationError::UnsupportedSessionAdmission)
    }
    async fn release_session_reservation(
        &self,
        _expected: &GatewaySessionAdmissionSnapshot,
        _proof: GatewaySessionCleanupProof,
    ) -> Result<GatewaySessionAdmissionSnapshot, GatewayActionCoordinationError> {
        Err(GatewayActionCoordinationError::UnsupportedSessionAdmission)
    }
    async fn scan_session_admissions(
        &self,
        _cursor: GatewaySessionAdmissionCursor,
        _limit: usize,
    ) -> Result<GatewaySessionAdmissionPage, GatewayActionCoordinationError> {
        Err(GatewayActionCoordinationError::UnsupportedSessionAdmission)
    }
    async fn ack_session_create_projection(
        &self,
        _expected: &GatewaySessionAdmissionSnapshot,
    ) -> Result<GatewaySessionAdmissionSnapshot, GatewayActionCoordinationError> {
        Err(GatewayActionCoordinationError::UnsupportedSessionAdmission)
    }
    async fn claim_action_authorized(
        &self,
        _claim: ClaimGatewayAction,
        _authority: &GatewaySessionAuthorityRef,
        _now: DateTime<Utc>,
    ) -> Result<GatewayActionClaimOutcome, GatewayActionCoordinationError> {
        Err(GatewayActionCoordinationError::UnsupportedSessionAdmission)
    }
    async fn arm_dispatch_owned_authorized(
        &self,
        _tenant_id: &TenantId,
        _session_id: &SessionId,
        _action_id: &ActionId,
        _expected_revision: u64,
        _placement: &GatewayActionPlacement,
        _dispatch_id: DispatchId,
        _lease: &GatewayActionSubmissionLease,
        _authority: &GatewaySessionAuthorityRef,
        _now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        Err(GatewayActionCoordinationError::UnsupportedSessionAdmission)
    }
    async fn scan_terminal_custody_catchup(
        &self,
        _cursor: GatewayActionRecoveryCursor,
        _limit: usize,
    ) -> Result<GatewayTerminalCustodyCatchupPage, GatewayActionCoordinationError> {
        Err(GatewayActionCoordinationError::UnsupportedCustodyRecovery)
    }
    async fn attach_terminal_custody(
        &self,
        _tenant_id: &TenantId,
        _session_id: &SessionId,
        _action_id: &ActionId,
        _expected_revision: u64,
        _placement: &GatewayActionPlacement,
        _receipt: TerminalCustodyReceipt,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        Err(GatewayActionCoordinationError::UnsupportedCustodyRecovery)
    }

    async fn maintain_action_retention(
        &self,
        _cursor: GatewayActionRetentionCursor,
        _limit: usize,
    ) -> Result<GatewayActionRetentionPage, GatewayActionCoordinationError> {
        Err(GatewayActionCoordinationError::UnsupportedActionRetention)
    }
    async fn scan_pending_custody(
        &self,
        _cursor: GatewayCustodyCursor,
        _limit: usize,
    ) -> Result<GatewayCustodyPage, GatewayActionCoordinationError> {
        Err(GatewayActionCoordinationError::UnsupportedCustodyRecovery)
    }
    async fn ack_pending_custody(
        &self,
        _entry: &GatewayPendingCustody,
        _now: DateTime<Utc>,
    ) -> Result<(), GatewayActionCoordinationError> {
        Err(GatewayActionCoordinationError::UnsupportedCustodyRecovery)
    }

    async fn complete_custody_release(
        &self,
        _entry: &GatewayPendingCustody,
        _now: DateTime<Utc>,
    ) -> Result<(), GatewayActionCoordinationError> {
        Err(GatewayActionCoordinationError::UnsupportedCustodyRecovery)
    }

    async fn scan_pending_actions(
        &self,
        _cursor: GatewayActionRecoveryCursor,
        _limit: usize,
    ) -> Result<GatewayActionRecoveryPage, GatewayActionCoordinationError> {
        Err(GatewayActionCoordinationError::UnsupportedActionRecovery)
    }

    async fn arm_dispatch_owned(
        &self,
        _tenant_id: &TenantId,
        _session_id: &SessionId,
        _action_id: &ActionId,
        _expected_revision: u64,
        _placement: &GatewayActionPlacement,
        _dispatch_id: DispatchId,
        _lease: &GatewayActionSubmissionLease,
        _now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        Err(GatewayActionCoordinationError::UnsupportedActionRecovery)
    }

    async fn expire_unattempted_action(
        &self,
        _tenant_id: &TenantId,
        _session_id: &SessionId,
        _action_id: &ActionId,
        _expected_revision: u64,
        _placement: &GatewayActionPlacement,
        _lease: &GatewayActionSubmissionLease,
        _now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        Err(GatewayActionCoordinationError::UnsupportedActionRecovery)
    }

    async fn scan_event_sessions(
        &self,
        _cursor: GatewayEventScanCursor,
        _limit: usize,
    ) -> Result<GatewayEventScanPage, GatewayActionCoordinationError> {
        Err(GatewayActionCoordinationError::UnsupportedEventRecovery)
    }

    async fn peek_event_projection(
        &self,
        _tenant_id: &TenantId,
        _session_id: &SessionId,
    ) -> Result<Option<GatewayEventProjection>, GatewayActionCoordinationError> {
        Err(GatewayActionCoordinationError::UnsupportedEventRecovery)
    }

    async fn ack_event_projection(
        &self,
        _projection: &GatewayEventProjection,
    ) -> Result<(), GatewayActionCoordinationError> {
        Err(GatewayActionCoordinationError::UnsupportedEventRecovery)
    }

    async fn claim_action(
        &self,
        claim: ClaimGatewayAction,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionClaimOutcome, GatewayActionCoordinationError>;

    async fn get_effective_action(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
    ) -> Result<Option<GatewayActionSnapshot>, GatewayActionCoordinationError>;

    async fn arm_dispatch(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        dispatch_id: DispatchId,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError>;

    async fn mark_exposure_possible(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        dispatch_id: &DispatchId,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError>;

    async fn record_worker_result_with_custody(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        dispatch_id: &DispatchId,
        action_sequence: ActionSequence,
        result: BrowserResult,
        result_body: Option<Vec<u8>>,
        custody: Option<TerminalCustodyReceipt>,
        requirement: Option<TerminalCustodyRequirement>,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        if custody.is_some() || requirement.is_some() {
            return Err(GatewayActionCoordinationError::UnsupportedCustodyRecovery);
        }
        self.record_worker_result(
            tenant_id,
            session_id,
            action_id,
            expected_revision,
            placement,
            dispatch_id,
            action_sequence,
            result,
            result_body,
            now,
        )
        .await
    }

    async fn record_worker_result(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        dispatch_id: &DispatchId,
        action_sequence: ActionSequence,
        result: BrowserResult,
        result_body: Option<Vec<u8>>,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError>;

    async fn record_worker_terminal_with_custody(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        dispatch_id: &DispatchId,
        action_sequence: ActionSequence,
        detail: TerminalDetail,
        custody: Option<TerminalCustodyReceipt>,
        requirement: Option<TerminalCustodyRequirement>,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        if custody.is_some() || requirement.is_some() {
            return Err(GatewayActionCoordinationError::UnsupportedCustodyRecovery);
        }
        self.record_worker_terminal(
            tenant_id,
            session_id,
            action_id,
            expected_revision,
            placement,
            dispatch_id,
            action_sequence,
            detail,
            now,
        )
        .await
    }

    async fn record_worker_terminal(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        dispatch_id: &DispatchId,
        action_sequence: ActionSequence,
        detail: TerminalDetail,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError>;

    async fn record_transport_loss(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        dispatch_id: &DispatchId,
        loss: TransportLoss,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError>;

    async fn cancel_before_dispatch(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError>;

    async fn resolve_unknown_with_custody(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        annotation: ResolutionAnnotation,
        custody: Option<TerminalCustodyReceipt>,
        requirement: Option<TerminalCustodyRequirement>,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        if custody.is_some() || requirement.is_some() {
            return Err(GatewayActionCoordinationError::UnsupportedCustodyRecovery);
        }
        self.resolve_unknown(
            tenant_id,
            session_id,
            action_id,
            expected_revision,
            placement,
            annotation,
            now,
        )
        .await
    }

    async fn resolve_unknown(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        annotation: ResolutionAnnotation,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError>;

    async fn mark_session_lost(
        &self,
        claim: &SessionLossClaim,
        now: DateTime<Utc>,
    ) -> Result<SessionLossOutcome, GatewayActionCoordinationError>;

    /// Records loss once, or returns the already committed identity for the exact placement.
    /// The caller must possess positive ownership-loss or terminal-session evidence. A failed
    /// liveness probe alone is not evidence. The compatibility default preserves strict loss
    /// identity conflicts; backends supporting canonical recovery override it atomically.
    async fn ensure_session_lost(
        &self,
        proposed: &SessionLossClaim,
        now: DateTime<Utc>,
    ) -> Result<SessionLossReceipt, GatewayActionCoordinationError> {
        let outcome = self.mark_session_lost(proposed, now).await?;
        Ok(SessionLossReceipt {
            claim: proposed.clone(),
            outcome,
        })
    }

    async fn materialize_session_loss(
        &self,
        claim: &SessionLossClaim,
        limit: usize,
        now: DateTime<Utc>,
    ) -> Result<usize, GatewayActionCoordinationError>;
}

#[derive(Clone)]
struct RecordedSessionLoss {
    loss_id: Uuid,
}

#[derive(Clone)]
struct GatewayActionSessionState {
    placement: GatewayActionPlacement,
    loss: Option<RecordedSessionLoss>,
    active_mutation: Option<ActionId>,
    active_dispatch: Option<ActionId>,
    pending_sequences: BTreeMap<u64, ActionId>,
    unresolved_mutation: Option<ActionId>,
    last_action_sequence: u64,
    idempotency: HashMap<IdempotencyKey, ActionId>,
    actions: HashMap<ActionId, GatewayActionSnapshot>,
    event_sequence: u64,
    event_ack_sequence: u64,
    events: VecDeque<GatewayEventProjection>,
    event_loss_claim: Option<SessionLossClaim>,
}

impl GatewayActionSessionState {
    fn new(placement: GatewayActionPlacement) -> Self {
        Self {
            placement,
            loss: None,
            active_mutation: None,
            active_dispatch: None,
            pending_sequences: BTreeMap::new(),
            unresolved_mutation: None,
            last_action_sequence: 0,
            idempotency: HashMap::new(),
            actions: HashMap::new(),
            event_sequence: 0,
            event_ack_sequence: 0,
            events: VecDeque::new(),
            event_loss_claim: None,
        }
    }

    fn append_event(
        &mut self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        append: OutboxAppend,
    ) -> Result<(), GatewayActionCoordinationError> {
        let sequence = self
            .event_sequence
            .checked_add(1)
            .filter(|sequence| *sequence <= MAX_EVENT_SEQUENCE)
            .ok_or(GatewayActionCoordinationError::EventSequenceOverflow)?;
        let event =
            GatewayEventProjection::new(tenant_id.clone(), session_id.clone(), sequence, append)?;
        self.events.push_back(event);
        self.event_sequence = sequence;
        Ok(())
    }
}

#[derive(Default)]
pub(crate) struct GatewayActionMemoryState {
    directory: BTreeMap<(TenantId, SessionId), crate::GatewaySessionDirectoryRecord>,
    directory_tenants: BTreeMap<TenantId, BTreeSet<SessionId>>,
    directory_gc_after: Option<(TenantId, SessionId)>,
    fleet: fleet_memory::FleetMemoryState,
    sessions: BTreeMap<(TenantId, SessionId), GatewayActionSessionState>,
    action_owners: HashMap<ActionId, (TenantId, SessionId, IdempotencyKey)>,
    pending: BTreeMap<(TenantId, SessionId, ActionId), ()>,
    pending_custody: BTreeMap<(TenantId, SessionId, ActionId), GatewayPendingCustody>,
    retained_records: BTreeMap<(TenantId, SessionId, ActionId), ()>,
    retention_due: BTreeMap<(u64, TenantId, SessionId, ActionId), ()>,
    retention_by_action: HashMap<ActionId, u64>,
}

#[derive(Clone)]
pub struct MemoryGatewayActionStore {
    database: MemoryCoordinationDatabase,
    config: StoreConfig,
    retention_limits: GatewayActionRetentionLimits,
    retention_clock: Option<Arc<dyn GatewayActionRetentionClock>>,
    fleet_config: Option<Arc<GatewayFleetAdmissionConfig>>,
    fleet_digest: Option<[u8; 32]>,
    fleet_clock: Option<Arc<dyn GatewayFleetAdmissionClock>>,
}

impl MemoryGatewayActionStore {
    #[must_use]
    pub const fn attach(database: MemoryCoordinationDatabase, config: StoreConfig) -> Self {
        Self {
            database,
            config,
            retention_limits: GatewayActionRetentionLimits::DEFAULT,
            retention_clock: None,
            fleet_config: None,
            fleet_digest: None,
            fleet_clock: None,
        }
    }

    #[must_use]
    pub fn with_retention_limits(mut self, limits: GatewayActionRetentionLimits) -> Self {
        self.retention_limits = limits;
        self
    }
    #[must_use]
    pub fn with_retention_clock(mut self, clock: Arc<dyn GatewayActionRetentionClock>) -> Self {
        self.retention_clock = Some(clock);
        self
    }
    fn retention_now(&self) -> DateTime<Utc> {
        self.retention_clock
            .as_ref()
            .map_or_else(Utc::now, |clock| clock.now())
    }
    fn retention_horizon(&self) -> Result<DateTime<Utc>, GatewayActionCoordinationError> {
        self.retention_now()
            .checked_add_signed(
                chrono::Duration::from_std(self.config.retention())
                    .map_err(|_| GatewayActionCoordinationError::RetentionTimestampOverflow)?,
            )
            .ok_or(GatewayActionCoordinationError::RetentionTimestampOverflow)
    }

    #[allow(clippy::too_many_arguments)]
    fn mutate_action(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        now: DateTime<Utc>,
        allow_session_loss: bool,
        mutation: impl FnOnce(
            &mut GatewayActionSnapshot,
        ) -> Result<ActionEvidenceMutation, GatewayActionCoordinationError>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        self.mutate_action_with_custody(
            tenant_id,
            session_id,
            action_id,
            expected_revision,
            placement,
            now,
            allow_session_loss,
            None,
            None,
            mutation,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn mutate_action_with_custody(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        now: DateTime<Utc>,
        allow_session_loss: bool,
        custody: Option<TerminalCustodyReceipt>,
        requirement: Option<TerminalCustodyRequirement>,
        mutation: impl FnOnce(
            &mut GatewayActionSnapshot,
        ) -> Result<ActionEvidenceMutation, GatewayActionCoordinationError>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        let mut state = self
            .database
            .gateway_actions
            .lock()
            .map_err(|_| GatewayActionCoordinationError::LockUnavailable)?;
        self.mutate_action_locked(
            &mut state,
            tenant_id,
            session_id,
            action_id,
            expected_revision,
            placement,
            now,
            allow_session_loss,
            custody,
            requirement,
            mutation,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn mutate_action_locked(
        &self,
        state: &mut GatewayActionMemoryState,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        now: DateTime<Utc>,
        allow_session_loss: bool,
        custody: Option<TerminalCustodyReceipt>,
        requirement: Option<TerminalCustodyRequirement>,
        mutation: impl FnOnce(
            &mut GatewayActionSnapshot,
        ) -> Result<ActionEvidenceMutation, GatewayActionCoordinationError>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        let key = (tenant_id.clone(), session_id.clone(), action_id.clone());
        let occupied = state.pending.len() + state.pending_custody.len();
        let session_occupied = state
            .pending
            .keys()
            .chain(state.pending_custody.keys())
            .filter(|(tenant, session, _)| tenant == tenant_id && session == session_id)
            .count();
        let already_reserved =
            state.pending.contains_key(&key) || state.pending_custody.contains_key(&key);
        let custody_full = !already_reserved
            && (occupied >= MAX_PENDING_ACTIONS_PER_NAMESPACE
                || session_occupied >= MAX_PENDING_ACTIONS_PER_SESSION);
        let prior_deadline = state.retention_by_action.get(action_id).copied();
        let prior_index_present = prior_deadline.is_some_and(|deadline| {
            state.retention_due.contains_key(&(
                deadline,
                tenant_id.clone(),
                session_id.clone(),
                action_id.clone(),
            ))
        });
        let session = state
            .sessions
            .get_mut(&(tenant_id.clone(), session_id.clone()))
            .ok_or(GatewayActionCoordinationError::NotFound)?;
        if session.placement != *placement {
            return Err(GatewayActionCoordinationError::PlacementMismatch);
        }
        let session_lost = session.loss.is_some();
        let current = session
            .actions
            .get_mut(action_id)
            .ok_or(GatewayActionCoordinationError::NotFound)?;
        if current.placement != *placement {
            return Err(GatewayActionCoordinationError::PlacementMismatch);
        }

        if session_lost && !allow_session_loss && current.terminal().is_none() {
            return Err(GatewayActionCoordinationError::SessionLost);
        }
        let mut candidate = current.clone();
        match mutation(&mut candidate) {
            Ok(ActionEvidenceMutation::AlreadyRecorded) => {
                // A lost commit response may attach the same worker proof without publishing another event.
                let origin_changed =
                    candidate.merge_custody_requirement(requirement, custody.as_ref(), false)?;
                let custody_changed = candidate.attach_custody(custody.as_ref())?;
                if origin_changed || custody_changed {
                    if custody_changed && custody_full {
                        return Err(GatewayActionCoordinationError::PendingCustodyCapacity);
                    }
                    *current = candidate.clone();
                    if let Some(entry) = candidate.pending_custody() {
                        state.pending_custody.insert(key, entry.clone());
                    }
                }
                Ok(candidate)
            }
            Ok(ActionEvidenceMutation::Recorded) => {
                if current.revision != expected_revision {
                    return Err(GatewayActionCoordinationError::StaleWrite(Box::new(
                        current.clone(),
                    )));
                }
                let arms_mutation = current.kind == ActionKind::Mutating
                    && matches!(current.delivery(), ActionDeliveryEvidence::NotAttempted)
                    && matches!(
                        candidate.delivery(),
                        ActionDeliveryEvidence::DispatchArmed(_)
                    );
                if arms_mutation {
                    if let Some(unresolved) = &session.unresolved_mutation {
                        return Err(GatewayActionCoordinationError::ReconciliationRequired {
                            action_id: unresolved.clone(),
                        });
                    }
                    if let Some(active) = &session.active_mutation
                        && active != action_id
                    {
                        return Err(GatewayActionCoordinationError::MutationInFlight {
                            action_id: active.clone(),
                        });
                    }
                }
                let arms_dispatch =
                    matches!(current.delivery(), ActionDeliveryEvidence::NotAttempted)
                        && matches!(
                            candidate.delivery(),
                            ActionDeliveryEvidence::DispatchArmed(_)
                        );
                if arms_dispatch {
                    if let Some(active) = &session.active_dispatch
                        && active != action_id
                    {
                        return Err(GatewayActionCoordinationError::ActionDispatchInFlight {
                            action_id: active.clone(),
                        });
                    }
                    // The legacy arm API retains its old ordering contract for unleased fixtures.
                    // Production lease-owned submissions never overtake an earlier accepted action.
                    if candidate.submission_lease.is_some()
                        && let Some((_, first)) = session.pending_sequences.first_key_value()
                        && first != action_id
                    {
                        return Err(GatewayActionCoordinationError::ActionDispatchInFlight {
                            action_id: first.clone(),
                        });
                    }
                }
                let becomes_terminal =
                    current.terminal().is_none() && candidate.terminal().is_some();
                let finishes_dispatch = becomes_terminal
                    && !matches!(current.delivery(), ActionDeliveryEvidence::NotAttempted);
                if finishes_dispatch && session.active_dispatch.as_ref() != Some(action_id) {
                    return Err(GatewayActionCoordinationError::CorruptState);
                }
                let finishes_dispatched_mutation = current.kind == ActionKind::Mutating
                    && !matches!(current.delivery(), ActionDeliveryEvidence::NotAttempted)
                    && current.terminal().is_none()
                    && candidate.terminal().is_some();
                let resolves_mutation = current.kind == ActionKind::Mutating
                    && current.terminal().is_some()
                    && current.resolution.is_none()
                    && candidate.resolution.is_some();
                let invalid_resolution_lane = if session_lost {
                    session
                        .active_mutation
                        .as_ref()
                        .is_some_and(|active| active != action_id)
                        || session
                            .unresolved_mutation
                            .as_ref()
                            .is_some_and(|unresolved| unresolved != action_id)
                } else {
                    session.unresolved_mutation.as_ref() != Some(action_id)
                };
                if (finishes_dispatched_mutation
                    && session.active_mutation.as_ref() != Some(action_id))
                    || (resolves_mutation && invalid_resolution_lane)
                {
                    return Err(GatewayActionCoordinationError::CorruptState);
                }
                let gains_resolution =
                    current.resolution.is_none() && candidate.resolution.is_some();
                let terminal_and_resolution =
                    current.terminal().is_none() && candidate.resolution.is_some();
                if let Some(deadline) = prior_deadline {
                    if !prior_index_present
                        || deadline != Self::retention_deadline(current.retain_until)?
                    {
                        return Err(GatewayActionCoordinationError::CorruptState);
                    }
                } else if current.last_source_event_sequence.is_some() {
                    return Err(GatewayActionCoordinationError::CorruptState);
                }
                if becomes_terminal || gains_resolution {
                    let horizon = self.retention_horizon()?;
                    candidate.retain_until = current.retain_until.max(horizon);
                }
                candidate.revision = candidate
                    .revision
                    .checked_add(if terminal_and_resolution { 2 } else { 1 })
                    .ok_or(GatewayActionCoordinationError::RevisionOverflow)?;
                candidate.updated_at = now;
                if becomes_terminal
                    && candidate
                        .terminal()
                        .is_some_and(|terminal| terminal.source() == ActionTerminalSource::Worker)
                {
                    candidate.original_worker_terminal_revision =
                        Some(candidate.revision - u64::from(terminal_and_resolution));
                }
                candidate.merge_custody_requirement(
                    requirement,
                    custody.as_ref(),
                    becomes_terminal,
                )?;
                if candidate.attach_custody(custody.as_ref())? && custody_full {
                    return Err(GatewayActionCoordinationError::PendingCustodyCapacity);
                }
                let mut events = Vec::new();
                if candidate.terminal_outbox_append().is_some() {
                    let revisions = if terminal_and_resolution {
                        vec![candidate.revision - 1, candidate.revision]
                    } else {
                        vec![candidate.revision]
                    };
                    for revision in revisions {
                        let sequence = session
                            .event_sequence
                            .checked_add(events.len() as u64 + 1)
                            .filter(|sequence| *sequence <= MAX_EVENT_SEQUENCE)
                            .ok_or(GatewayActionCoordinationError::EventSequenceOverflow)?;
                        events.push(GatewayEventProjection::new(
                            tenant_id.clone(),
                            session_id.clone(),
                            sequence,
                            if revision == candidate.revision {
                                candidate
                                    .terminal_outbox_append()
                                    .ok_or(GatewayActionCoordinationError::CorruptState)?
                            } else {
                                OutboxAppend::action_terminal(
                                    tenant_id.clone(),
                                    session_id.clone(),
                                    action_id.clone(),
                                    revision,
                                )
                            },
                        )?);
                    }
                }
                if let Some(event) = events.last() {
                    candidate.last_source_event_sequence = Some(event.sequence);
                }
                let next_deadline = if candidate.terminal().is_some() {
                    Some(Self::retention_deadline(candidate.retain_until)?)
                } else {
                    None
                };
                *current = candidate.clone();
                for event in events {
                    session.event_sequence = event.sequence;
                    session.events.push_back(event);
                }
                if arms_mutation {
                    session.active_mutation = Some(action_id.clone());
                }
                if arms_dispatch {
                    session.active_dispatch = Some(action_id.clone());
                }
                if finishes_dispatch {
                    session.active_dispatch = None;
                }
                if becomes_terminal {
                    session
                        .pending_sequences
                        .remove(&candidate.action_sequence.get());
                }
                if finishes_dispatched_mutation {
                    session.active_mutation = None;
                    if candidate.requires_reconciliation() {
                        session.unresolved_mutation = Some(action_id.clone());
                    }
                }
                if resolves_mutation {
                    if session.unresolved_mutation.as_ref() == Some(action_id) {
                        session.unresolved_mutation = None;
                    }
                    if session_lost && session.active_mutation.as_ref() == Some(action_id) {
                        session.active_mutation = None;
                    }
                }
                if becomes_terminal {
                    state.pending.remove(&(
                        tenant_id.clone(),
                        session_id.clone(),
                        action_id.clone(),
                    ));
                }
                if let Some(entry) = candidate.pending_custody() {
                    state.pending_custody.insert(key, entry.clone());
                }
                if let Some(deadline) = next_deadline {
                    if let Some(prior) = prior_deadline {
                        state.retention_due.remove(&(
                            prior,
                            tenant_id.clone(),
                            session_id.clone(),
                            action_id.clone(),
                        ));
                    }
                    state.retention_due.insert(
                        (
                            deadline,
                            tenant_id.clone(),
                            session_id.clone(),
                            action_id.clone(),
                        ),
                        (),
                    );
                    state
                        .retention_by_action
                        .insert(action_id.clone(), deadline);
                }
                Ok(candidate)
            }
            Err(_) if current.revision != expected_revision => Err(
                GatewayActionCoordinationError::StaleWrite(Box::new(current.clone())),
            ),
            Err(error) => Err(error),
        }
    }

    fn claim_action_locked(
        &self,
        state: &mut GatewayActionMemoryState,
        claim: ClaimGatewayAction,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionClaimOutcome, GatewayActionCoordinationError> {
        if !claim.result_budget.is_valid_for(claim.kind) {
            return Err(GatewayActionCoordinationError::CorruptState);
        }
        let session_key = (claim.tenant_id.clone(), claim.session_id.clone());

        if let Some(session) = state.sessions.get(&session_key) {
            if session.placement != claim.placement {
                return Err(GatewayActionCoordinationError::PlacementMismatch);
            }
            if let Some(existing_action_id) = session.idempotency.get(&claim.idempotency_key) {
                let existing = session
                    .actions
                    .get(existing_action_id)
                    .ok_or(GatewayActionCoordinationError::CorruptState)?;
                if existing.request_hash != claim.request_hash
                    || existing.kind != claim.kind
                    || existing.result_budget != claim.result_budget
                {
                    return Err(GatewayActionCoordinationError::IdempotencyConflict {
                        existing_action_id: existing.action_id.clone(),
                    });
                }
                let mut effective = existing.clone();
                if session.loss.is_some() && effective.terminal().is_none() {
                    effective.derive_worker_loss()?;
                }
                return Ok(GatewayActionClaimOutcome::Existing(effective));
            }
            if session.loss.is_some() {
                return Err(GatewayActionCoordinationError::SessionLost);
            }
            if claim.kind == ActionKind::Mutating
                && let Some(action_id) = &session.unresolved_mutation
            {
                return Err(GatewayActionCoordinationError::ReconciliationRequired {
                    action_id: action_id.clone(),
                });
            }
        }

        if state.retained_records.len() >= self.retention_limits.namespace_records()
            || state.sessions.get(&session_key).is_some_and(|session| {
                session.actions.len() >= self.retention_limits.session_records()
            })
        {
            return Err(GatewayActionCoordinationError::RetainedActionCapacity);
        }
        if let Some(lease) = &claim.submission_lease {
            lease.validate_claim(now)?;
        }
        if state.pending.len() + state.pending_custody.len() >= MAX_PENDING_ACTIONS_PER_NAMESPACE
            || state.sessions.get(&session_key).is_some_and(|session| {
                session.pending_sequences.len()
                    + state
                        .pending_custody
                        .keys()
                        .filter(|(tenant, session, _)| {
                            tenant == &claim.tenant_id && session == &claim.session_id
                        })
                        .count()
                    >= MAX_PENDING_ACTIONS_PER_SESSION
            })
        {
            return Err(GatewayActionCoordinationError::PendingActionCapacity);
        }

        if state.action_owners.contains_key(&claim.proposed_action_id) {
            return Err(GatewayActionCoordinationError::ActionIdentityConflict {
                action_id: claim.proposed_action_id,
            });
        }

        let retention = chrono::Duration::from_std(self.config.retention())
            .map_err(|_| GatewayActionCoordinationError::RetentionTimestampOverflow)?;
        let retain_until = now
            .checked_add_signed(retention)
            .ok_or(GatewayActionCoordinationError::RetentionTimestampOverflow)?;
        let action_sequence = state.sessions.get(&session_key).map_or(Ok(1), |session| {
            session
                .last_action_sequence
                .checked_add(1)
                .ok_or(GatewayActionCoordinationError::ActionSequenceOverflow)
        })?;
        let snapshot = GatewayActionSnapshot {
            tenant_id: claim.tenant_id.clone(),
            session_id: claim.session_id.clone(),
            action_id: claim.proposed_action_id.clone(),
            idempotency_key: claim.idempotency_key.clone(),
            request_hash: claim.request_hash,
            kind: claim.kind,
            result_budget: claim.result_budget,
            placement: claim.placement.clone(),
            evidence: ActionEvidence::new(),
            submission_lease: claim.submission_lease.clone(),
            resolution: None,
            result_content: None,
            custody: None,
            action_sequence: ActionSequence::new(action_sequence),
            revision: 0,
            created_at: now,
            updated_at: now,
            retain_until,
            last_source_event_sequence: None,
            custody_requirement: None,
            original_worker_terminal_revision: None,
        };
        state.retained_records.insert(
            (
                claim.tenant_id.clone(),
                claim.session_id.clone(),
                claim.proposed_action_id.clone(),
            ),
            (),
        );
        state.action_owners.insert(
            claim.proposed_action_id.clone(),
            (
                claim.tenant_id.clone(),
                claim.session_id.clone(),
                claim.idempotency_key.clone(),
            ),
        );
        state.pending.insert(
            (
                claim.tenant_id.clone(),
                claim.session_id.clone(),
                claim.proposed_action_id.clone(),
            ),
            (),
        );
        let session = state
            .sessions
            .entry(session_key)
            .or_insert_with(|| GatewayActionSessionState::new(claim.placement));
        session.last_action_sequence = action_sequence;
        session
            .pending_sequences
            .insert(action_sequence, claim.proposed_action_id.clone());
        session
            .idempotency
            .insert(claim.idempotency_key, claim.proposed_action_id.clone());
        session
            .actions
            .insert(claim.proposed_action_id, snapshot.clone());
        Ok(GatewayActionClaimOutcome::Created(snapshot))
    }

    fn retention_deadline(at: DateTime<Utc>) -> Result<u64, GatewayActionCoordinationError> {
        u64::try_from(at.timestamp_millis())
            .map_err(|_| GatewayActionCoordinationError::RetentionTimestampOverflow)
    }

    fn validate_loss_claim(claim: &SessionLossClaim) -> Result<(), GatewayActionCoordinationError> {
        if claim.loss_id.get_version() != Some(Version::SortRand) {
            return Err(GatewayActionCoordinationError::InvalidSessionLossId);
        }
        Ok(())
    }

    fn record_session_loss(
        &self,
        proposed: &SessionLossClaim,
        canonicalize_existing: bool,
    ) -> Result<SessionLossReceipt, GatewayActionCoordinationError> {
        Self::validate_loss_claim(proposed)?;
        let mut state = self
            .database
            .gateway_actions
            .lock()
            .map_err(|_| GatewayActionCoordinationError::LockUnavailable)?;
        let key = (proposed.tenant_id.clone(), proposed.session_id.clone());
        let session = state
            .sessions
            .entry(key)
            .or_insert_with(|| GatewayActionSessionState::new(proposed.placement.clone()));
        if session.placement != proposed.placement {
            return Err(GatewayActionCoordinationError::PlacementMismatch);
        }
        if let Some(recorded_loss) = &session.loss {
            if !canonicalize_existing && recorded_loss.loss_id != proposed.loss_id {
                return Err(GatewayActionCoordinationError::SessionLossIdentityConflict);
            }
            return Ok(SessionLossReceipt {
                claim: SessionLossClaim::new(
                    proposed.tenant_id.clone(),
                    proposed.session_id.clone(),
                    session.placement.clone(),
                    recorded_loss.loss_id,
                ),
                outcome: SessionLossOutcome::AlreadyRecorded,
            });
        }
        session.append_event(
            proposed.tenant_id(),
            proposed.session_id(),
            OutboxAppend::session_lost(
                proposed.tenant_id.clone(),
                proposed.session_id.clone(),
                proposed.placement.directory_revision,
            ),
        )?;
        if session
            .actions
            .values()
            .any(|snapshot| snapshot.terminal().is_none())
        {
            session.event_loss_claim = Some(proposed.clone());
        }
        session.loss = Some(RecordedSessionLoss {
            loss_id: proposed.loss_id,
        });
        Ok(SessionLossReceipt {
            claim: proposed.clone(),
            outcome: SessionLossOutcome::Recorded,
        })
    }
}

impl Default for MemoryGatewayActionStore {
    fn default() -> Self {
        Self::attach(
            MemoryCoordinationDatabase::default(),
            StoreConfig::default(),
        )
    }
}

#[allow(clippy::too_many_arguments)]
#[async_trait]
impl GatewayActionCoordination for MemoryGatewayActionStore {
    async fn list_single_host_directory(
        &self,
        tenant_id: &TenantId,
        after: Option<&SessionId>,
        ceiling: Option<&SessionId>,
        limit: usize,
    ) -> Result<crate::GatewaySessionDirectoryPage, GatewayActionCoordinationError> {
        if !(1..=crate::MAX_SESSION_DIRECTORY_PAGE).contains(&limit) {
            return Err(GatewayActionCoordinationError::InvalidSessionDirectory);
        }
        let state = self
            .database
            .gateway_actions
            .lock()
            .map_err(|_| GatewayActionCoordinationError::LockUnavailable)?;
        let Some(index) = state.directory_tenants.get(tenant_id) else {
            return crate::GatewaySessionDirectoryPage::new(
                tenant_id,
                Vec::new(),
                ceiling.cloned(),
                false,
            );
        };
        let ceiling = ceiling.cloned().or_else(|| index.last().cloned());
        if after
            .zip(ceiling.as_ref())
            .is_some_and(|(after, ceiling)| after >= ceiling)
        {
            return crate::GatewaySessionDirectoryPage::new(tenant_id, Vec::new(), ceiling, false);
        }
        let mut keys = index
            .range((
                after.map_or(std::ops::Bound::Unbounded, std::ops::Bound::Excluded),
                ceiling
                    .as_ref()
                    .map_or(std::ops::Bound::Unbounded, std::ops::Bound::Included),
            ))
            .peekable();
        let mut records = Vec::with_capacity(limit);
        for _ in 0..limit {
            let Some(session) = keys.next() else {
                break;
            };
            records.push(
                state
                    .directory
                    .get(&(tenant_id.clone(), session.clone()))
                    .cloned()
                    .ok_or(GatewayActionCoordinationError::InvalidSessionDirectory)?,
            );
        }
        let has_more = keys.peek().is_some();
        crate::GatewaySessionDirectoryPage::new(tenant_id, records, ceiling, has_more)
    }
    async fn commit_single_host_directory(
        &self,
        record: crate::GatewaySessionDirectoryRecord,
        expected_revision: Option<u64>,
    ) -> Result<crate::GatewaySessionDirectoryRecord, GatewayActionCoordinationError> {
        record.validate()?;
        let mut state = self
            .database
            .gateway_actions
            .lock()
            .map_err(|_| GatewayActionCoordinationError::LockUnavailable)?;
        let key = (record.tenant_id().clone(), record.session_id().clone());
        if let Some(existing) = state.directory.get(&key) {
            let committed = existing.checked_commit(&record, expected_revision)?;
            state.directory.insert(key, committed.clone());
            return Ok(committed);
        }
        if expected_revision.is_some() {
            return Err(GatewayActionCoordinationError::SessionDirectoryConflict);
        }
        // Reclaim only directory projections, never action/loss/custody/event authority.
        let after = state.directory_gc_after.clone();
        let selected = state
            .directory
            .range((
                after.map_or(std::ops::Bound::Unbounded, std::ops::Bound::Excluded),
                std::ops::Bound::Unbounded,
            ))
            .take(32)
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect::<Vec<_>>();
        state.directory_gc_after = selected.last().map(|(key, _)| key.clone());
        if selected.is_empty() {
            state.directory_gc_after = None;
        }
        let retention = chrono::Duration::from_std(self.config.retention())
            .map_err(|_| GatewayActionCoordinationError::InvalidSessionDirectory)?;
        let now = self.retention_now();
        for (key, value) in selected {
            if value.lifecycle().terminal()
                && now.signed_duration_since(value.updated_at()) >= retention
            {
                state.directory.remove(&key);
                if let Some(index) = state.directory_tenants.get_mut(&key.0) {
                    index.remove(&key.1);
                }
                if state
                    .directory_tenants
                    .get(&key.0)
                    .is_some_and(BTreeSet::is_empty)
                {
                    state.directory_tenants.remove(&key.0);
                }
            }
        }
        if state.directory.len() >= crate::MAX_SESSION_DIRECTORY_RECORDS {
            return Err(GatewayActionCoordinationError::SessionDirectoryCapacity);
        }
        state
            .directory_tenants
            .entry(key.0.clone())
            .or_default()
            .insert(key.1.clone());
        state.directory.insert(key, record.clone());
        Ok(record)
    }
    async fn get_single_host_directory(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
    ) -> Result<Option<crate::GatewaySessionDirectoryRecord>, GatewayActionCoordinationError> {
        self.database
            .gateway_actions
            .lock()
            .map_err(|_| GatewayActionCoordinationError::LockUnavailable)
            .map(|state| {
                state
                    .directory
                    .get(&(tenant_id.clone(), session_id.clone()))
                    .cloned()
            })
    }
    async fn get_action_by_idempotency(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        key: &str,
    ) -> Result<Option<GatewayActionSnapshot>, GatewayActionCoordinationError> {
        let key = validated_idempotency_key(key.to_owned())?;
        let action = {
            let state = self
                .database
                .gateway_actions
                .lock()
                .map_err(|_| GatewayActionCoordinationError::LockUnavailable)?;
            state
                .sessions
                .get(&(tenant_id.clone(), session_id.clone()))
                .and_then(|session| session.idempotency.get(&key))
                .cloned()
        };
        match action {
            Some(action) => {
                self.get_effective_action(tenant_id, session_id, &action)
                    .await
            }
            None => Ok(None),
        }
    }
    async fn enqueue_session_admission(
        &self,
        request: GatewaySessionAdmissionRequest,
    ) -> Result<GatewaySessionAdmissionSnapshot, GatewayActionCoordinationError> {
        self.memory_enqueue_session_admission(request)
    }

    async fn get_session_admission(
        &self,
        key: &GatewaySessionAdmissionKey,
    ) -> Result<Option<GatewaySessionAdmissionSnapshot>, GatewayActionCoordinationError> {
        self.memory_get_session_admission(key)
    }

    async fn observe_fleet_worker(
        &self,
        observation: GatewayFleetWorkerObservation,
        advisory_ttl: Duration,
    ) -> Result<(), GatewayActionCoordinationError> {
        self.memory_observe_fleet_worker(observation, advisory_ttl)
    }

    async fn reserve_next_session(
        &self,
        reservation_ttl: Duration,
    ) -> Result<Option<GatewaySessionAdmissionSnapshot>, GatewayActionCoordinationError> {
        self.memory_reserve_next_session(reservation_ttl)
    }

    async fn record_session_reservation(
        &self,
        expected: &GatewaySessionAdmissionSnapshot,
        proof: GatewaySessionWorkerReservationProof,
    ) -> Result<GatewaySessionAdmissionSnapshot, GatewayActionCoordinationError> {
        self.memory_record_session_reservation(expected, proof)
    }

    async fn arm_session_create(
        &self,
        expected: &GatewaySessionAdmissionSnapshot,
        dispatch_lease: &DispatchLeaseToken,
        placement_ttl: Duration,
    ) -> Result<GatewaySessionAdmissionSnapshot, GatewayActionCoordinationError> {
        self.memory_arm_session_create(expected, dispatch_lease, placement_ttl)
    }

    async fn commit_session_placement(
        &self,
        expected: &GatewaySessionAdmissionSnapshot,
        proof: GatewaySessionWorkerReadyProof,
    ) -> Result<GatewaySessionPlacementAuthority, GatewayActionCoordinationError> {
        self.memory_commit_session_placement(expected, proof)
    }

    async fn resolve_session_placement(
        &self,
        key: &DirectoryKey,
    ) -> Result<Option<GatewaySessionPlacementAuthority>, GatewayActionCoordinationError> {
        self.memory_resolve_session_placement(key)
    }

    async fn validate_session_authority(
        &self,
        authority: &GatewaySessionAuthorityRef,
    ) -> Result<(), GatewayActionCoordinationError> {
        self.memory_validate_session_authority(authority)
    }

    async fn begin_session_renewal(
        &self,
        expected: &GatewaySessionPlacementAuthority,
        renewal_nonce: LeaseId,
        placement_ttl: Duration,
    ) -> Result<GatewaySessionRenewalIntent, GatewayActionCoordinationError> {
        self.memory_begin_session_renewal(expected, renewal_nonce, placement_ttl)
    }

    async fn finish_session_renewal(
        &self,
        intent: &GatewaySessionRenewalIntent,
        proof: GatewaySessionWorkerRenewalProof,
    ) -> Result<GatewaySessionPlacementAuthority, GatewayActionCoordinationError> {
        self.memory_finish_session_renewal(intent, proof)
    }

    async fn begin_session_close(
        &self,
        expected: &GatewaySessionPlacementAuthority,
    ) -> Result<GatewaySessionPlacementAuthority, GatewayActionCoordinationError> {
        self.memory_begin_session_close(expected)
    }

    async fn release_session_reservation(
        &self,
        expected: &GatewaySessionAdmissionSnapshot,
        proof: GatewaySessionCleanupProof,
    ) -> Result<GatewaySessionAdmissionSnapshot, GatewayActionCoordinationError> {
        self.memory_release_session_reservation(expected, proof)
    }

    async fn scan_session_admissions(
        &self,
        cursor: GatewaySessionAdmissionCursor,
        limit: usize,
    ) -> Result<GatewaySessionAdmissionPage, GatewayActionCoordinationError> {
        self.memory_scan_session_admissions(cursor, limit)
    }

    async fn ack_session_create_projection(
        &self,
        expected: &GatewaySessionAdmissionSnapshot,
    ) -> Result<GatewaySessionAdmissionSnapshot, GatewayActionCoordinationError> {
        self.memory_ack_session_create_projection(expected)
    }

    async fn claim_action_authorized(
        &self,
        claim: ClaimGatewayAction,
        authority: &GatewaySessionAuthorityRef,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionClaimOutcome, GatewayActionCoordinationError> {
        let mut state = self
            .database
            .gateway_actions
            .lock()
            .map_err(|_| GatewayActionCoordinationError::LockUnavailable)?;
        let duplicate = state
            .sessions
            .get(&(claim.tenant_id.clone(), claim.session_id.clone()))
            .is_some_and(|session| session.idempotency.contains_key(&claim.idempotency_key));
        self.authorize_session_action_locked(
            &mut state,
            &claim.tenant_id,
            &claim.session_id,
            &claim.placement,
            authority,
            !duplicate,
        )?;
        let now = self.fleet_action_now(&mut state, now)?;
        self.claim_action_locked(&mut state, claim, now)
    }

    async fn arm_dispatch_owned_authorized(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        dispatch_id: DispatchId,
        lease: &GatewayActionSubmissionLease,
        authority: &GatewaySessionAuthorityRef,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        let mut state = self
            .database
            .gateway_actions
            .lock()
            .map_err(|_| GatewayActionCoordinationError::LockUnavailable)?;
        self.authorize_session_action_locked(
            &mut state, tenant_id, session_id, placement, authority, true,
        )?;
        let now = self.fleet_action_now(&mut state, now)?;
        self.mutate_action_locked(
            &mut state,
            tenant_id,
            session_id,
            action_id,
            expected_revision,
            placement,
            now,
            false,
            None,
            None,
            |snapshot| {
                snapshot.validate_submission_lease(lease, now, false)?;
                Ok(snapshot.evidence.arm_dispatch(dispatch_id)?)
            },
        )
    }
    async fn scan_terminal_custody_catchup(
        &self,
        cursor: GatewayActionRecoveryCursor,
        limit: usize,
    ) -> Result<GatewayTerminalCustodyCatchupPage, GatewayActionCoordinationError> {
        if !(1..=MAX_RECOVERY_SCAN_LIMIT).contains(&limit) {
            return Err(GatewayActionCoordinationError::InvalidCustodyScanLimit);
        }
        let state = self
            .database
            .gateway_actions
            .lock()
            .map_err(|_| GatewayActionCoordinationError::LockUnavailable)?;
        use std::ops::Bound::{Excluded, Unbounded};
        let start = cursor.after.as_ref().map_or(Unbounded, Excluded);
        let mut rows: Vec<_> = state
            .retained_records
            .range((start, Unbounded))
            .take(limit + 1)
            .map(|(key, ())| key.clone())
            .collect();
        let complete = rows.len() <= limit;
        rows.truncate(limit);
        let next_cursor = if complete {
            GatewayActionRecoveryCursor::default()
        } else {
            GatewayActionRecoveryCursor {
                after: rows.last().cloned(),
            }
        };
        let mut actions = Vec::new();
        for (tenant, session_id, action_id) in &rows {
            let session = state
                .sessions
                .get(&(tenant.clone(), session_id.clone()))
                .ok_or(GatewayActionCoordinationError::CorruptState)?;
            let snapshot = session
                .actions
                .get(action_id)
                .ok_or(GatewayActionCoordinationError::CorruptState)?;
            if snapshot.tenant_id != *tenant
                || snapshot.session_id != *session_id
                || snapshot.action_id != *action_id
                || snapshot.placement != session.placement
            {
                return Err(GatewayActionCoordinationError::CorruptState);
            }
            snapshot.validate_stored_custody()?;
            if snapshot.requires_terminal_custody_catchup() {
                actions.push(snapshot.clone());
            }
        }
        GatewayTerminalCustodyCatchupPage::new(actions, next_cursor, complete, rows.len())
    }

    async fn attach_terminal_custody(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        receipt: TerminalCustodyReceipt,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        let mut state = self
            .database
            .gateway_actions
            .lock()
            .map_err(|_| GatewayActionCoordinationError::LockUnavailable)?;
        let key = (tenant_id.clone(), session_id.clone(), action_id.clone());
        let session_key = (tenant_id.clone(), session_id.clone());
        let session = state
            .sessions
            .get(&session_key)
            .ok_or(GatewayActionCoordinationError::NotFound)?;
        let current = session
            .actions
            .get(action_id)
            .ok_or(GatewayActionCoordinationError::NotFound)?;
        if session.placement != *placement || current.placement != *placement {
            return Err(GatewayActionCoordinationError::PlacementMismatch);
        }
        if current.tenant_id != *tenant_id
            || current.session_id != *session_id
            || current.action_id != *action_id
            || !state.retained_records.contains_key(&key)
            || session.idempotency.get(&current.idempotency_key) != Some(action_id)
            || state.action_owners.get(action_id)
                != Some(&(
                    tenant_id.clone(),
                    session_id.clone(),
                    current.idempotency_key.clone(),
                ))
        {
            return Err(GatewayActionCoordinationError::CorruptState);
        }
        current.validate_stored_custody()?;
        let mut candidate = current.clone();
        let custody_changed = candidate.attach_terminal_custody_receipt(&receipt)?;
        let origin_changed = candidate.merge_custody_requirement(
            Some(TerminalCustodyRequirement::Required),
            Some(&receipt),
            false,
        )?;
        if !custody_changed && !origin_changed {
            return Ok(current.clone());
        }
        if current.revision != expected_revision {
            return Err(GatewayActionCoordinationError::StaleWrite(Box::new(
                current.clone(),
            )));
        }
        let already_reserved =
            state.pending.contains_key(&key) || state.pending_custody.contains_key(&key);
        if custody_changed
            && !already_reserved
            && (state.pending.len() + state.pending_custody.len()
                >= MAX_PENDING_ACTIONS_PER_NAMESPACE
                || state
                    .pending
                    .keys()
                    .chain(state.pending_custody.keys())
                    .filter(|(tenant, session, _)| tenant == tenant_id && session == session_id)
                    .count()
                    >= MAX_PENDING_ACTIONS_PER_SESSION)
        {
            return Err(GatewayActionCoordinationError::PendingCustodyCapacity);
        }
        state
            .sessions
            .get_mut(&session_key)
            .ok_or(GatewayActionCoordinationError::CorruptState)?
            .actions
            .insert(action_id.clone(), candidate.clone());
        if let Some(entry) = candidate.pending_custody() {
            state.pending_custody.insert(key, entry.clone());
        }
        Ok(candidate)
    }

    async fn maintain_action_retention(
        &self,
        cursor: GatewayActionRetentionCursor,
        limit: usize,
    ) -> Result<GatewayActionRetentionPage, GatewayActionCoordinationError> {
        if !(1..=MAX_RECOVERY_SCAN_LIMIT).contains(&limit) {
            return Err(GatewayActionCoordinationError::InvalidRetentionScanLimit);
        }
        cursor.validate()?;
        let trusted_now = self.retention_now();
        let now = Self::retention_deadline(trusted_now)?;
        let mut state = self
            .database
            .gateway_actions
            .lock()
            .map_err(|_| GatewayActionCoordinationError::LockUnavailable)?;
        use std::ops::Bound::{Excluded, Unbounded};
        let start = cursor.after.as_ref().map_or(Unbounded, Excluded);
        // The due index is ordered across tenants. Blocked rows still advance the cursor;
        // only an explicit completed pass restarts discovery at the beginning.
        let mut rows: Vec<_> = state
            .retention_due
            .range((start, Unbounded))
            .take_while(|(key, ())| key.0 <= now)
            .take(limit + 1)
            .map(|(key, ())| key.clone())
            .collect();
        let complete = rows.len() <= limit;
        rows.truncate(limit);
        let next_cursor = if complete {
            GatewayActionRetentionCursor::default()
        } else {
            let (deadline, tenant, session, action) = rows
                .last()
                .ok_or(GatewayActionCoordinationError::CorruptState)?;
            GatewayActionRetentionCursor::after(
                *deadline,
                tenant.clone(),
                session.clone(),
                action.clone(),
            )
        };
        let mut reclaim = Vec::new();
        // Validate every selected identity before changing any of the related indexes.
        for (deadline, tenant_id, session_id, action_id) in &rows {
            let session = state
                .sessions
                .get(&(tenant_id.clone(), session_id.clone()))
                .ok_or(GatewayActionCoordinationError::CorruptState)?;
            let snapshot = session
                .actions
                .get(action_id)
                .ok_or(GatewayActionCoordinationError::CorruptState)?;
            if snapshot.tenant_id != *tenant_id
                || snapshot.session_id != *session_id
                || snapshot.action_id != *action_id
                || snapshot.placement != session.placement
                || snapshot.action_sequence.get() == 0
                || snapshot.action_sequence.get() > session.last_action_sequence
                || state.retention_by_action.get(action_id) != Some(deadline)
                || Self::retention_deadline(snapshot.retain_until)? != *deadline
                || session.idempotency.get(&snapshot.idempotency_key) != Some(action_id)
                || state.action_owners.get(action_id)
                    != Some(&(
                        tenant_id.clone(),
                        session_id.clone(),
                        snapshot.idempotency_key.clone(),
                    ))
                || !state.retained_records.contains_key(&(
                    tenant_id.clone(),
                    session_id.clone(),
                    action_id.clone(),
                ))
                || snapshot.terminal().is_none()
            {
                return Err(GatewayActionCoordinationError::CorruptState);
            }
            snapshot.validate_stored_custody()?;
            let required_sequence = match snapshot.last_source_event_sequence {
                Some(sequence) => sequence,
                None if snapshot.worker_owns_notifications() => 0,
                // Legacy snapshots without an exact source-write watermark are pinned.
                None => continue,
            };
            if (required_sequence == 0 && !snapshot.worker_owns_notifications())
                || required_sequence > session.event_sequence
                || session.event_ack_sequence > session.event_sequence
            {
                return Err(GatewayActionCoordinationError::CorruptState);
            }
            let key = (tenant_id.clone(), session_id.clone(), action_id.clone());
            if snapshot.retain_until > trusted_now
                || required_sequence > session.event_ack_sequence
                || snapshot.requires_terminal_custody_catchup()
                || snapshot.pending_custody().is_some()
                || state.pending_custody.contains_key(&key)
                || state.pending.contains_key(&key)
                || session
                    .pending_sequences
                    .values()
                    .any(|pending| pending == action_id)
                || session.active_mutation.as_ref() == Some(action_id)
                || session.active_dispatch.as_ref() == Some(action_id)
                || session.unresolved_mutation.as_ref() == Some(action_id)
                || (matches!(
                    snapshot.terminal().map(|terminal| terminal.detail()),
                    Some(TerminalDetail::OutcomeUnknown(_))
                ) && snapshot.resolution.is_none())
            {
                continue;
            }
            reclaim.push((
                (
                    *deadline,
                    tenant_id.clone(),
                    session_id.clone(),
                    action_id.clone(),
                ),
                snapshot.idempotency_key.clone(),
            ));
        }
        for (key, idempotency_key) in &reclaim {
            let session = state
                .sessions
                .get_mut(&(key.1.clone(), key.2.clone()))
                .ok_or(GatewayActionCoordinationError::CorruptState)?;
            session.actions.remove(&key.3);
            session.idempotency.remove(idempotency_key);
            state
                .retained_records
                .remove(&(key.1.clone(), key.2.clone(), key.3.clone()));
            state.retention_by_action.remove(&key.3);
            state.retention_due.remove(key);
            // Session sequence/loss/placement and immutable source events are preserved.
        }
        GatewayActionRetentionPage::new(
            next_cursor,
            complete,
            rows.len(),
            reclaim.len(),
            rows.len() - reclaim.len(),
        )
    }

    async fn scan_pending_custody(
        &self,
        cursor: GatewayCustodyCursor,
        limit: usize,
    ) -> Result<GatewayCustodyPage, GatewayActionCoordinationError> {
        if !(1..=MAX_RECOVERY_SCAN_LIMIT).contains(&limit) {
            return Err(GatewayActionCoordinationError::InvalidCustodyScanLimit);
        }
        let state = self
            .database
            .gateway_actions
            .lock()
            .map_err(|_| GatewayActionCoordinationError::LockUnavailable)?;
        use std::ops::Bound::{Excluded, Unbounded};
        let start = cursor.after.as_ref().map_or(Unbounded, Excluded);
        let entries: Vec<_> = state
            .pending_custody
            .range((start, Unbounded))
            .take(limit)
            .map(|(_, entry)| entry.clone())
            .collect();
        let complete = entries.len() < limit;
        let next_cursor = if complete {
            GatewayCustodyCursor::default()
        } else {
            GatewayCustodyCursor {
                after: entries.last().map(|entry| {
                    (
                        entry.receipt.tenant_id().clone(),
                        entry.receipt.session_id().clone(),
                        entry.receipt.action_id().clone(),
                    )
                }),
            }
        };
        Ok(GatewayCustodyPage {
            entries,
            next_cursor,
            complete,
        })
    }

    async fn ack_pending_custody(
        &self,
        entry: &GatewayPendingCustody,
        _now: DateTime<Utc>,
    ) -> Result<(), GatewayActionCoordinationError> {
        let receipt = entry.receipt();
        let mut state = self
            .database
            .gateway_actions
            .lock()
            .map_err(|_| GatewayActionCoordinationError::LockUnavailable)?;
        let snapshot = state
            .sessions
            .get_mut(&(receipt.tenant_id().clone(), receipt.session_id().clone()))
            .and_then(|session| session.actions.get_mut(receipt.action_id()))
            .ok_or(GatewayActionCoordinationError::NotFound)?;
        if snapshot.copy_custody_ack(entry)? {
            let pending = snapshot
                .pending_custody()
                .cloned()
                .ok_or(GatewayActionCoordinationError::CorruptState)?;
            state.pending_custody.insert(
                (
                    receipt.tenant_id().clone(),
                    receipt.session_id().clone(),
                    receipt.action_id().clone(),
                ),
                pending,
            );
        }
        Ok(())
    }

    async fn complete_custody_release(
        &self,
        entry: &GatewayPendingCustody,
        _now: DateTime<Utc>,
    ) -> Result<(), GatewayActionCoordinationError> {
        let receipt = entry.receipt();
        let mut state = self
            .database
            .gateway_actions
            .lock()
            .map_err(|_| GatewayActionCoordinationError::LockUnavailable)?;
        let snapshot = state
            .sessions
            .get_mut(&(receipt.tenant_id().clone(), receipt.session_id().clone()))
            .and_then(|session| session.actions.get_mut(receipt.action_id()))
            .ok_or(GatewayActionCoordinationError::NotFound)?;
        snapshot.complete_custody_release(entry)?;
        state.pending_custody.remove(&(
            receipt.tenant_id().clone(),
            receipt.session_id().clone(),
            receipt.action_id().clone(),
        ));
        Ok(())
    }

    async fn scan_pending_actions(
        &self,
        cursor: GatewayActionRecoveryCursor,
        limit: usize,
    ) -> Result<GatewayActionRecoveryPage, GatewayActionCoordinationError> {
        if !(1..=MAX_RECOVERY_SCAN_LIMIT).contains(&limit) {
            return Err(GatewayActionCoordinationError::InvalidRecoveryScanLimit);
        }
        let state = self
            .database
            .gateway_actions
            .lock()
            .map_err(|_| GatewayActionCoordinationError::LockUnavailable)?;
        let start = cursor
            .after
            .map_or(std::ops::Bound::Unbounded, std::ops::Bound::Excluded);
        let mut actions = Vec::with_capacity(limit);
        let mut next_cursor = GatewayActionRecoveryCursor::default();
        for (key, ()) in state
            .pending
            .range((start, std::ops::Bound::Unbounded))
            .take(limit)
        {
            let snapshot = state
                .sessions
                .get(&(key.0.clone(), key.1.clone()))
                .and_then(|session| session.actions.get(&key.2))
                .ok_or(GatewayActionCoordinationError::CorruptState)?;
            if snapshot.terminal().is_some() {
                return Err(GatewayActionCoordinationError::CorruptState);
            }
            actions.push(snapshot.clone());
            next_cursor.after = Some(key.clone());
        }
        let complete = actions.len() < limit;
        if complete {
            next_cursor = GatewayActionRecoveryCursor::default();
        }
        Ok(GatewayActionRecoveryPage {
            actions,
            next_cursor,
            complete,
        })
    }

    async fn arm_dispatch_owned(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        dispatch_id: DispatchId,
        lease: &GatewayActionSubmissionLease,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        let mut state = self
            .database
            .gateway_actions
            .lock()
            .map_err(|_| GatewayActionCoordinationError::LockUnavailable)?;
        self.reject_legacy_admission(&state)?;
        self.mutate_action_locked(
            &mut state,
            tenant_id,
            session_id,
            action_id,
            expected_revision,
            placement,
            now,
            false,
            None,
            None,
            |snapshot| {
                snapshot.validate_submission_lease(lease, now, false)?;
                Ok(snapshot.evidence.arm_dispatch(dispatch_id)?)
            },
        )
    }

    async fn expire_unattempted_action(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        lease: &GatewayActionSubmissionLease,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        self.mutate_action(
            tenant_id,
            session_id,
            action_id,
            expected_revision,
            placement,
            now,
            false,
            |snapshot| {
                snapshot.validate_submission_lease(lease, now, true)?;
                Ok(snapshot.evidence.expire_before_dispatch()?)
            },
        )
    }

    async fn scan_event_sessions(
        &self,
        cursor: GatewayEventScanCursor,
        limit: usize,
    ) -> Result<GatewayEventScanPage, GatewayActionCoordinationError> {
        if !(1..=MAX_EVENT_SCAN_LIMIT).contains(&limit) {
            return Err(GatewayActionCoordinationError::InvalidEventScanLimit);
        }
        let state = self
            .database
            .gateway_actions
            .lock()
            .map_err(|_| GatewayActionCoordinationError::LockUnavailable)?;
        let start = cursor
            .memory_after
            .map_or(std::ops::Bound::Unbounded, std::ops::Bound::Excluded);
        let mut scopes = state.sessions.range((start, std::ops::Bound::Unbounded));
        let mut sessions = Vec::new();
        let mut next_cursor = GatewayEventScanCursor::default();
        for (key, session) in scopes.by_ref().take(limit) {
            next_cursor.memory_after = Some(key.clone());
            if !session.events.is_empty() || session.event_loss_claim.is_some() {
                sessions.push(GatewayEventSession {
                    tenant_id: key.0.clone(),
                    session_id: key.1.clone(),
                    loss_claim: session.event_loss_claim.clone(),
                });
            }
        }
        let complete = scopes.next().is_none();
        if complete {
            next_cursor = GatewayEventScanCursor::default();
        }
        Ok(GatewayEventScanPage {
            sessions,
            next_cursor,
            complete,
        })
    }

    async fn peek_event_projection(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
    ) -> Result<Option<GatewayEventProjection>, GatewayActionCoordinationError> {
        let state = self
            .database
            .gateway_actions
            .lock()
            .map_err(|_| GatewayActionCoordinationError::LockUnavailable)?;
        Ok(state
            .sessions
            .get(&(tenant_id.clone(), session_id.clone()))
            .and_then(|session| session.events.front().cloned()))
    }

    async fn ack_event_projection(
        &self,
        projection: &GatewayEventProjection,
    ) -> Result<(), GatewayActionCoordinationError> {
        let mut state = self
            .database
            .gateway_actions
            .lock()
            .map_err(|_| GatewayActionCoordinationError::LockUnavailable)?;
        let session = state
            .sessions
            .get_mut(&(projection.tenant_id.clone(), projection.session_id.clone()))
            .ok_or(GatewayActionCoordinationError::EventAckConflict)?;
        if projection.sequence <= session.event_ack_sequence {
            return Ok(());
        }
        if session.events.front() != Some(projection) {
            return Err(GatewayActionCoordinationError::EventAckConflict);
        }
        session.events.pop_front();
        session.event_ack_sequence = projection.sequence;
        Ok(())
    }

    async fn claim_action(
        &self,
        claim: ClaimGatewayAction,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionClaimOutcome, GatewayActionCoordinationError> {
        let mut state = self
            .database
            .gateway_actions
            .lock()
            .map_err(|_| GatewayActionCoordinationError::LockUnavailable)?;
        self.reject_legacy_admission(&state)?;
        self.claim_action_locked(&mut state, claim, now)
    }

    async fn get_effective_action(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
    ) -> Result<Option<GatewayActionSnapshot>, GatewayActionCoordinationError> {
        let state = self
            .database
            .gateway_actions
            .lock()
            .map_err(|_| GatewayActionCoordinationError::LockUnavailable)?;
        let Some(session) = state.sessions.get(&(tenant_id.clone(), session_id.clone())) else {
            return Ok(None);
        };
        let Some(mut snapshot) = session.actions.get(action_id).cloned() else {
            return Ok(None);
        };
        if session.loss.is_some() && snapshot.terminal().is_none() {
            snapshot.derive_worker_loss()?;
        }
        Ok(Some(snapshot))
    }

    async fn arm_dispatch(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        dispatch_id: DispatchId,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        let mut state = self
            .database
            .gateway_actions
            .lock()
            .map_err(|_| GatewayActionCoordinationError::LockUnavailable)?;
        self.reject_legacy_admission(&state)?;
        self.mutate_action_locked(
            &mut state,
            tenant_id,
            session_id,
            action_id,
            expected_revision,
            placement,
            now,
            false,
            None,
            None,
            move |snapshot| {
                if snapshot.submission_lease.is_some() {
                    return Err(GatewayActionCoordinationError::SubmissionLeaseRequired);
                }
                Ok(snapshot.evidence.arm_dispatch(dispatch_id)?)
            },
        )
    }

    async fn mark_exposure_possible(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        dispatch_id: &DispatchId,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        self.mutate_action(
            tenant_id,
            session_id,
            action_id,
            expected_revision,
            placement,
            now,
            false,
            |snapshot| Ok(snapshot.evidence.mark_exposure_possible(dispatch_id)?),
        )
    }

    async fn record_worker_result(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        dispatch_id: &DispatchId,
        action_sequence: ActionSequence,
        result: BrowserResult,
        result_body: Option<Vec<u8>>,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        self.record_worker_result_with_custody(
            tenant_id,
            session_id,
            action_id,
            expected_revision,
            placement,
            dispatch_id,
            action_sequence,
            result,
            result_body,
            None,
            None,
            now,
        )
        .await
    }

    async fn record_worker_result_with_custody(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        dispatch_id: &DispatchId,
        action_sequence: ActionSequence,
        result: BrowserResult,
        result_body: Option<Vec<u8>>,
        custody: Option<TerminalCustodyReceipt>,
        requirement: Option<TerminalCustodyRequirement>,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        let require_same_body = custody.is_some();
        self.mutate_action_with_custody(
            tenant_id,
            session_id,
            action_id,
            expected_revision,
            placement,
            now,
            false,
            custody,
            requirement,
            move |snapshot| {
                validate_durable_result_body(result, &result_body, snapshot.result_budget)?;
                if action_sequence.get() == 0 {
                    return Err(GatewayActionCoordinationError::InvalidActionSequence);
                }
                if snapshot.action_sequence != action_sequence {
                    return Err(GatewayActionCoordinationError::ActionSequenceConflict);
                }
                let mutation = snapshot
                    .evidence
                    .record_worker_result(dispatch_id, result)?;
                if require_same_body
                    && matches!(mutation, ActionEvidenceMutation::AlreadyRecorded)
                    && snapshot.result_content != result_body
                {
                    return Err(GatewayActionCoordinationError::InvalidCustodyReceipt);
                }
                if matches!(mutation, ActionEvidenceMutation::Recorded) {
                    snapshot.result_content = result_body;
                }
                Ok(mutation)
            },
        )
    }

    async fn record_worker_terminal(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        dispatch_id: &DispatchId,
        action_sequence: ActionSequence,
        detail: TerminalDetail,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        self.record_worker_terminal_with_custody(
            tenant_id,
            session_id,
            action_id,
            expected_revision,
            placement,
            dispatch_id,
            action_sequence,
            detail,
            None,
            None,
            now,
        )
        .await
    }

    async fn record_worker_terminal_with_custody(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        dispatch_id: &DispatchId,
        action_sequence: ActionSequence,
        detail: TerminalDetail,
        custody: Option<TerminalCustodyReceipt>,
        requirement: Option<TerminalCustodyRequirement>,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        let resolution = custody
            .as_ref()
            .and_then(|receipt| receipt.resolution())
            .cloned();
        self.mutate_action_with_custody(
            tenant_id,
            session_id,
            action_id,
            expected_revision,
            placement,
            now,
            false,
            custody,
            requirement,
            |snapshot| {
                if action_sequence.get() == 0 {
                    return Err(GatewayActionCoordinationError::InvalidActionSequence);
                }
                if snapshot.action_sequence != action_sequence {
                    return Err(GatewayActionCoordinationError::ActionSequenceConflict);
                }
                let mutation = snapshot
                    .evidence
                    .record_worker_terminal(dispatch_id, detail)?;
                snapshot.adopt_worker_resolution(resolution.as_ref(), mutation)
            },
        )
    }

    async fn record_transport_loss(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        dispatch_id: &DispatchId,
        loss: TransportLoss,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        self.mutate_action(
            tenant_id,
            session_id,
            action_id,
            expected_revision,
            placement,
            now,
            false,
            |snapshot| Ok(snapshot.evidence.record_transport_loss(dispatch_id, loss)?),
        )
    }

    async fn cancel_before_dispatch(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        self.mutate_action(
            tenant_id,
            session_id,
            action_id,
            expected_revision,
            placement,
            now,
            false,
            |snapshot| Ok(snapshot.evidence.cancel_before_dispatch()?),
        )
    }

    async fn resolve_unknown(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        annotation: ResolutionAnnotation,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        self.resolve_unknown_with_custody(
            tenant_id,
            session_id,
            action_id,
            expected_revision,
            placement,
            annotation,
            None,
            None,
            now,
        )
        .await
    }

    async fn resolve_unknown_with_custody(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        annotation: ResolutionAnnotation,
        custody: Option<TerminalCustodyReceipt>,
        requirement: Option<TerminalCustodyRequirement>,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        self.mutate_action_with_custody(
            tenant_id,
            session_id,
            action_id,
            expected_revision,
            placement,
            now,
            true,
            custody,
            requirement,
            |snapshot| {
                if let Some(existing) = &snapshot.resolution {
                    return if existing == &annotation {
                        Ok(ActionEvidenceMutation::AlreadyRecorded)
                    } else {
                        Err(GatewayActionCoordinationError::ResolutionConflict)
                    };
                }
                if !matches!(
                    snapshot.terminal().map(|terminal| terminal.detail()),
                    Some(TerminalDetail::OutcomeUnknown(_))
                ) {
                    return Err(GatewayActionCoordinationError::ResolutionNotAllowed);
                }
                snapshot.resolution = Some(annotation);
                Ok(ActionEvidenceMutation::Recorded)
            },
        )
    }

    async fn mark_session_lost(
        &self,
        claim: &SessionLossClaim,
        _now: DateTime<Utc>,
    ) -> Result<SessionLossOutcome, GatewayActionCoordinationError> {
        self.record_session_loss(claim, false)
            .map(|receipt| receipt.outcome())
    }

    async fn ensure_session_lost(
        &self,
        proposed: &SessionLossClaim,
        _now: DateTime<Utc>,
    ) -> Result<SessionLossReceipt, GatewayActionCoordinationError> {
        self.record_session_loss(proposed, true)
    }

    async fn materialize_session_loss(
        &self,
        claim: &SessionLossClaim,
        limit: usize,
        now: DateTime<Utc>,
    ) -> Result<usize, GatewayActionCoordinationError> {
        Self::validate_loss_claim(claim)?;
        if !(1..=MAX_MATERIALIZATION_LIMIT).contains(&limit) {
            return Err(GatewayActionCoordinationError::InvalidMaterializationLimit);
        }
        let mut state = self
            .database
            .gateway_actions
            .lock()
            .map_err(|_| GatewayActionCoordinationError::LockUnavailable)?;
        let key = (claim.tenant_id.clone(), claim.session_id.clone());
        let session = state
            .sessions
            .get(&key)
            .ok_or(GatewayActionCoordinationError::SessionLossNotRecorded)?;
        if session.placement != claim.placement {
            return Err(GatewayActionCoordinationError::PlacementMismatch);
        }
        let recorded_loss = session
            .loss
            .as_ref()
            .ok_or(GatewayActionCoordinationError::SessionLossNotRecorded)?;
        if recorded_loss.loss_id != claim.loss_id {
            return Err(GatewayActionCoordinationError::SessionLossIdentityConflict);
        }
        let mut candidate = session.clone();
        let mut pending: Vec<_> = candidate
            .actions
            .values()
            .filter(|snapshot| snapshot.terminal().is_none())
            .map(|snapshot| (snapshot.created_at, snapshot.action_id.clone()))
            .collect();
        pending.sort();
        pending.truncate(limit);
        let materialized = pending.len();
        let horizon = if materialized > 0 {
            Some(self.retention_horizon()?)
        } else {
            None
        };
        let retired_ids: Vec<_> = pending
            .iter()
            .map(|(_, action_id)| action_id.clone())
            .collect();
        for (_, action_id) in pending {
            let snapshot = candidate
                .actions
                .get_mut(&action_id)
                .ok_or(GatewayActionCoordinationError::CorruptState)?;
            snapshot.derive_worker_loss()?;
            snapshot.revision = snapshot
                .revision
                .checked_add(1)
                .ok_or(GatewayActionCoordinationError::RevisionOverflow)?;
            snapshot.updated_at = now;
            snapshot.retain_until = snapshot
                .retain_until
                .max(horizon.ok_or(GatewayActionCoordinationError::CorruptState)?);
            snapshot.last_source_event_sequence = Some(
                candidate
                    .event_sequence
                    .checked_add(1)
                    .filter(|sequence| *sequence <= MAX_EVENT_SEQUENCE)
                    .ok_or(GatewayActionCoordinationError::EventSequenceOverflow)?,
            );
            if state.retention_by_action.contains_key(&action_id) {
                return Err(GatewayActionCoordinationError::CorruptState);
            }
            candidate
                .pending_sequences
                .remove(&snapshot.action_sequence.get());
            if candidate.active_dispatch.as_ref() == Some(&action_id) {
                candidate.active_dispatch = None;
            }
            let append = snapshot
                .terminal_outbox_append()
                .ok_or(GatewayActionCoordinationError::CorruptState)?;
            candidate.append_event(claim.tenant_id(), claim.session_id(), append)?;
        }
        if !candidate
            .actions
            .values()
            .any(|snapshot| snapshot.terminal().is_none())
        {
            candidate.event_loss_claim = None;
        }
        let deadlines: Vec<_> = retired_ids
            .iter()
            .map(|action_id| {
                let snapshot = candidate
                    .actions
                    .get(action_id)
                    .ok_or(GatewayActionCoordinationError::CorruptState)?;
                Ok((
                    action_id.clone(),
                    Self::retention_deadline(snapshot.retain_until)?,
                ))
            })
            .collect::<Result<_, GatewayActionCoordinationError>>()?;
        state.sessions.insert(key, candidate);
        for (action_id, deadline) in deadlines {
            state.pending.remove(&(
                claim.tenant_id.clone(),
                claim.session_id.clone(),
                action_id.clone(),
            ));
            state.retention_due.insert(
                (
                    deadline,
                    claim.tenant_id.clone(),
                    claim.session_id.clone(),
                    action_id.clone(),
                ),
                (),
            );
            state.retention_by_action.insert(action_id, deadline);
        }
        Ok(materialized)
    }
}

#[cfg(test)]
#[path = "gateway_action_retention_tests.rs"]
mod retention_tests;
