//! Exact transfer identity for terminal worker WAL evidence. No browser replay authority.
use browserd_core::{ActionId, PlacementFence, SessionId, TenantId, WorkerId};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    ActionKind, ActionSequence, CanonicalRequestHash, DispatchId, JournalError, LedgerSession,
    ResolutionAnnotation, ResolutionKind, TerminalDetail,
};

/// Original journal capability, reported with an authenticated terminal action result.
/// Absence on a legacy result is ambiguous and cannot authorize custody-free cleanup.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalCustodyRequirement {
    Required,
    Unsupported,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JournalSessionScope {
    tenant_id: TenantId,
    session_id: SessionId,
    original_worker_id: WorkerId,
    worker_epoch: u64,
    placement_version: u64,
    session_incarnation: u64,
}
impl JournalSessionScope {
    pub fn new(
        tenant_id: TenantId,
        session_id: SessionId,
        original_worker_id: WorkerId,
        fence: PlacementFence,
    ) -> Result<Self, JournalError> {
        let scope = Self {
            tenant_id,
            session_id,
            original_worker_id,
            worker_epoch: fence.worker_epoch,
            placement_version: fence.placement_version,
            session_incarnation: fence.session_incarnation,
        };
        scope.validate()?;
        Ok(scope)
    }
    pub fn validate(&self) -> Result<(), JournalError> {
        if self.worker_epoch == 0 || self.placement_version == 0 || self.session_incarnation == 0 {
            return Err(JournalError::new("custody scope fence is invalid"));
        }
        Ok(())
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
    pub const fn original_worker_id(&self) -> &WorkerId {
        &self.original_worker_id
    }
    #[must_use]
    pub const fn fence(&self) -> PlacementFence {
        PlacementFence::new(
            self.worker_epoch,
            self.placement_version,
            self.session_incarnation,
        )
    }
    #[must_use]
    pub fn ledger_session(&self) -> LedgerSession {
        LedgerSession::new(
            self.tenant_id.clone(),
            self.session_id.clone(),
            self.fence(),
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TerminalCustodyReceipt {
    schema_version: u8,
    scope: JournalSessionScope,
    action_id: ActionId,
    action_sequence: ActionSequence,
    action_kind: ActionKind,
    accepted_request_hash: CanonicalRequestHash,
    worker_dispatch_id: Option<DispatchId>,
    terminal_detail: TerminalDetail,
    resolution: Option<ResolutionAnnotation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    notification_source: Option<browserd_core::NotificationSourceScope>,
    digest: [u8; 32],
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptWire {
    schema_version: u8,
    scope: JournalSessionScope,
    action_id: ActionId,
    action_sequence: ActionSequence,
    action_kind: ActionKind,
    accepted_request_hash: CanonicalRequestHash,
    worker_dispatch_id: Option<DispatchId>,
    terminal_detail: TerminalDetail,
    resolution: Option<StrictResolution>,
    #[serde(default)]
    notification_source: Option<browserd_core::NotificationSourceScope>,
    digest: [u8; 32],
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictResolution {
    kind: ResolutionKind,
    resolved_by: browserd_core::PrincipalId,
    resolved_at_millis: u64,
    basis: String,
}
impl<'de> Deserialize<'de> for TerminalCustodyReceipt {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = ReceiptWire::deserialize(deserializer)?;
        let value = Self {
            schema_version: wire.schema_version,
            scope: wire.scope,
            action_id: wire.action_id,
            action_sequence: wire.action_sequence,
            action_kind: wire.action_kind,
            accepted_request_hash: wire.accepted_request_hash,
            worker_dispatch_id: wire.worker_dispatch_id,
            terminal_detail: wire.terminal_detail,
            resolution: wire.resolution.map(|r| {
                ResolutionAnnotation::new(r.kind, r.resolved_by, r.resolved_at_millis, r.basis)
            }),
            notification_source: wire.notification_source,
            digest: wire.digest,
        };
        value.validate().map_err(serde::de::Error::custom)?;
        Ok(value)
    }
}
impl TerminalCustodyReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: JournalSessionScope,
        action_id: ActionId,
        action_sequence: ActionSequence,
        action_kind: ActionKind,
        accepted_request_hash: CanonicalRequestHash,
        worker_dispatch_id: Option<DispatchId>,
        terminal_detail: TerminalDetail,
        resolution: Option<ResolutionAnnotation>,
    ) -> Result<Self, JournalError> {
        let mut receipt = Self {
            schema_version: 1,
            scope,
            action_id,
            action_sequence,
            action_kind,
            accepted_request_hash,
            worker_dispatch_id,
            terminal_detail,
            resolution,
            notification_source: None,
            digest: [0; 32],
        };
        receipt.validate_fields()?;
        receipt.digest = receipt.compute_digest()?;
        receipt.validate()?;
        Ok(receipt)
    }
    pub fn with_notification_source(
        mut self,
        source: browserd_core::NotificationSourceScope,
    ) -> Result<Self, JournalError> {
        self.notification_source = Some(source);
        self.validate_fields()?;
        self.digest = self.compute_digest()?;
        Ok(self)
    }
    fn compute_digest(&self) -> Result<[u8; 32], JournalError> {
        // A fixed field-order tuple, independently versioned and domain separated. Includes None.
        let payload = serde_json::to_vec(&(
            self.schema_version,
            &self.scope,
            &self.action_id,
            self.action_sequence,
            self.action_kind,
            self.accepted_request_hash,
            &self.worker_dispatch_id,
            self.terminal_detail,
            &self.resolution,
        ))
        .map_err(|_| JournalError::new("custody receipt encoding failed"))?;
        if payload.len() > 16 * 1024 {
            return Err(JournalError::new("custody receipt exceeds bound"));
        }
        let mut hash = Sha256::new();
        hash.update(b"browserd-terminal-custody-v1\0");
        hash.update((payload.len() as u64).to_be_bytes());
        hash.update(payload);
        if let Some(source) = &self.notification_source {
            let extension = serde_json::to_vec(source)
                .map_err(|_| JournalError::new("custody notification source encoding failed"))?;
            hash.update(b"\0browserd-terminal-custody-notification-source-v1\0");
            hash.update((extension.len() as u64).to_be_bytes());
            hash.update(extension);
        }
        Ok(hash.finalize().into())
    }
    fn validate_fields(&self) -> Result<(), JournalError> {
        self.scope.validate()?;
        if self.schema_version != 1 || self.action_sequence.get() == 0 {
            return Err(JournalError::new("custody receipt identity is invalid"));
        }
        if let Some(source) = &self.notification_source {
            source
                .validate()
                .map_err(|_| JournalError::new("custody notification source is invalid"))?;
            if source.tenant_id() != self.tenant_id()
                || source.original_worker_id() != self.original_worker_id()
                || source.source_id() != *self.session_id().as_uuid()
                || source.family() != browserd_core::NotificationSourceFamily::ActionJournal
            {
                return Err(JournalError::new(
                    "custody notification source scope mismatch",
                ));
            }
        }
        if let Some(r) = &self.resolution
            && (!matches!(self.terminal_detail, TerminalDetail::OutcomeUnknown(_))
                || !ResolutionAnnotation::is_valid_basis(r.basis()))
        {
            return Err(JournalError::new("custody resolution is invalid"));
        }
        if self.worker_dispatch_id.is_none()
            && !matches!(
                self.terminal_detail,
                TerminalDetail::CancelledBeforeDispatch
                    | TerminalDetail::FailedKnown(
                        crate::KnownFailureReason::ApprovalDenied
                            | crate::KnownFailureReason::ApprovalTimedOut
                    )
            )
        {
            return Err(JournalError::new(
                "custody terminal has no dispatch evidence",
            ));
        }
        if self.worker_dispatch_id.is_some()
            && self.terminal_detail == TerminalDetail::CancelledBeforeDispatch
        {
            return Err(JournalError::new(
                "custody cancellation contradicts dispatch",
            ));
        }
        Ok(())
    }
    pub fn validate(&self) -> Result<(), JournalError> {
        self.validate_fields()?;
        if self.digest != self.compute_digest()? {
            return Err(JournalError::new("custody receipt digest mismatch"));
        }
        Ok(())
    }
    #[must_use]
    pub const fn scope(&self) -> &JournalSessionScope {
        &self.scope
    }
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        self.scope.tenant_id()
    }
    #[must_use]
    pub const fn session_id(&self) -> &SessionId {
        self.scope.session_id()
    }
    #[must_use]
    pub const fn original_worker_id(&self) -> &WorkerId {
        self.scope.original_worker_id()
    }
    #[must_use]
    pub const fn fence(&self) -> PlacementFence {
        self.scope.fence()
    }
    #[must_use]
    pub const fn action_id(&self) -> &ActionId {
        &self.action_id
    }
    #[must_use]
    pub const fn action_sequence(&self) -> ActionSequence {
        self.action_sequence
    }
    #[must_use]
    pub const fn kind(&self) -> ActionKind {
        self.action_kind
    }
    #[must_use]
    pub const fn request_hash(&self) -> CanonicalRequestHash {
        self.accepted_request_hash
    }
    #[must_use]
    pub const fn dispatch_id(&self) -> Option<&DispatchId> {
        self.worker_dispatch_id.as_ref()
    }
    #[must_use]
    pub const fn terminal(&self) -> TerminalDetail {
        self.terminal_detail
    }
    #[must_use]
    pub const fn resolution(&self) -> Option<&ResolutionAnnotation> {
        self.resolution.as_ref()
    }
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }
    #[must_use]
    pub const fn notification_source(&self) -> Option<&browserd_core::NotificationSourceScope> {
        self.notification_source.as_ref()
    }
}
