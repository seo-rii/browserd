use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::SocketAddr;
use std::num::NonZeroU64;

use browserd_core::EgressFence;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DaemonEpoch(NonZeroU64);

impl DaemonEpoch {
    #[must_use]
    pub const fn new(value: u64) -> Option<Self> {
        match NonZeroU64::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BindingDigest([u8; 32]);

impl BindingDigest {
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AttachmentExpiry(u64);

impl AttachmentExpiry {
    #[must_use]
    pub const fn new(daemon_millis: u64) -> Self {
        Self(daemon_millis)
    }

    #[must_use]
    pub const fn daemon_millis(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AttachmentId(NonZeroU64);

impl AttachmentId {
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Receipt for the immutable preparation record.
///
/// Receipt fields cannot be forged outside this crate:
///
/// ```compile_fail
/// fn inspect(receipt: browserd_egress::PreparedAttachmentReceipt) {
///     let browserd_egress::PreparedAttachmentReceipt { fence: _, .. } = receipt;
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedAttachmentReceipt {
    fence: EgressFence,
    binding_digest: BindingDigest,
    daemon_epoch: DaemonEpoch,
    prepare_revision: u64,
}

impl PreparedAttachmentReceipt {
    #[must_use]
    pub const fn fence(&self) -> &EgressFence {
        &self.fence
    }

    #[must_use]
    pub const fn binding_digest(&self) -> BindingDigest {
        self.binding_digest
    }

    #[must_use]
    pub const fn daemon_epoch(&self) -> DaemonEpoch {
        self.daemon_epoch
    }

    #[must_use]
    pub const fn prepare_revision(&self) -> u64 {
        self.prepare_revision
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CancelledAttachmentReceipt {
    prepared: PreparedAttachmentReceipt,
    cancel_revision: u64,
}

impl CancelledAttachmentReceipt {
    #[must_use]
    pub const fn prepared(&self) -> &PreparedAttachmentReceipt {
        &self.prepared
    }

    #[must_use]
    pub const fn fence(&self) -> &EgressFence {
        self.prepared.fence()
    }

    #[must_use]
    pub const fn daemon_epoch(&self) -> DaemonEpoch {
        self.prepared.daemon_epoch()
    }

    #[must_use]
    pub const fn cancel_revision(&self) -> u64 {
        self.cancel_revision
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstallingAttachmentReceipt {
    prepared: PreparedAttachmentReceipt,
    attachment_id: AttachmentId,
    proxy_address: SocketAddr,
    expires_at: AttachmentExpiry,
}

impl InstallingAttachmentReceipt {
    #[must_use]
    pub const fn prepared(&self) -> &PreparedAttachmentReceipt {
        &self.prepared
    }

    #[must_use]
    pub const fn fence(&self) -> &EgressFence {
        self.prepared.fence()
    }

    #[must_use]
    pub const fn daemon_epoch(&self) -> DaemonEpoch {
        self.prepared.daemon_epoch()
    }

    #[must_use]
    pub const fn attachment_id(&self) -> AttachmentId {
        self.attachment_id
    }

    #[must_use]
    pub const fn proxy_address(&self) -> SocketAddr {
        self.proxy_address
    }

    #[must_use]
    pub const fn expires_at(&self) -> AttachmentExpiry {
        self.expires_at
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveAttachmentReceipt {
    installing: InstallingAttachmentReceipt,
    activation_revision: u64,
}

impl ActiveAttachmentReceipt {
    #[must_use]
    pub const fn prepared(&self) -> &PreparedAttachmentReceipt {
        self.installing.prepared()
    }

    #[must_use]
    pub const fn fence(&self) -> &EgressFence {
        self.installing.fence()
    }

    #[must_use]
    pub const fn daemon_epoch(&self) -> DaemonEpoch {
        self.installing.daemon_epoch()
    }

    #[must_use]
    pub const fn attachment_id(&self) -> AttachmentId {
        self.installing.attachment_id()
    }

    #[must_use]
    pub const fn proxy_address(&self) -> SocketAddr {
        self.installing.proxy_address()
    }

    #[must_use]
    pub const fn expires_at(&self) -> AttachmentExpiry {
        self.installing.expires_at()
    }

    #[must_use]
    pub const fn activation_revision(&self) -> u64 {
        self.activation_revision
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleasedAttachmentReceipt {
    prepared: PreparedAttachmentReceipt,
    attachment_id: Option<AttachmentId>,
    release_revision: u64,
}

impl ReleasedAttachmentReceipt {
    #[must_use]
    pub const fn fence(&self) -> &EgressFence {
        self.prepared.fence()
    }

    #[must_use]
    pub const fn binding_digest(&self) -> BindingDigest {
        self.prepared.binding_digest()
    }

    #[must_use]
    pub const fn daemon_epoch(&self) -> DaemonEpoch {
        self.prepared.daemon_epoch()
    }

    #[must_use]
    pub const fn release_revision(&self) -> u64 {
        self.release_revision
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachmentState {
    Absent,
    Prepared,
    Installing,
    Active,
    Revoking,
    Revoked,
    Drained,
    Cancelled,
    Released,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AttachmentStatus {
    Absent,
    Prepared(PreparedAttachmentReceipt),
    Installing(InstallingAttachmentReceipt),
    Active(ActiveAttachmentReceipt),
    Revoking(ActiveAttachmentReceipt),
    Revoked(ActiveAttachmentReceipt),
    Drained(ActiveAttachmentReceipt),
    Cancelled(CancelledAttachmentReceipt),
    Released(ReleasedAttachmentReceipt),
}

impl AttachmentStatus {
    #[must_use]
    pub const fn state(&self) -> AttachmentState {
        match self {
            Self::Absent => AttachmentState::Absent,
            Self::Prepared(_) => AttachmentState::Prepared,
            Self::Installing(_) => AttachmentState::Installing,
            Self::Active(_) => AttachmentState::Active,
            Self::Revoking(_) => AttachmentState::Revoking,
            Self::Revoked(_) => AttachmentState::Revoked,
            Self::Drained(_) => AttachmentState::Drained,
            Self::Cancelled(_) => AttachmentState::Cancelled,
            Self::Released(_) => AttachmentState::Released,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InstallReceipt {
    Installing(InstallingAttachmentReceipt),
    Active(ActiveAttachmentReceipt),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AttachmentError {
    DaemonEpochMismatch {
        expected: DaemonEpoch,
        actual: DaemonEpoch,
    },
    BindingConflict,
    InstallConflict,
    ShardAttachmentConflict,
    InvalidProxyAddress(SocketAddr),
    InvalidExpiry,
    StaleReceipt,
    InvalidTransition {
        state: AttachmentState,
        operation: &'static str,
    },
    Terminal(AttachmentState),
    ListenerCloseNotAcknowledged,
    AcceptedGuardsRemain {
        count: usize,
    },
    NotDrained,
    GuardNotFound,
    IdentifierExhausted,
}

impl fmt::Display for AttachmentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DaemonEpochMismatch { expected, actual } => write!(
                formatter,
                "attachment daemon epoch mismatch: expected {}, got {}",
                expected.get(),
                actual.get()
            ),
            Self::BindingConflict => {
                formatter.write_str("attachment fence has a different immutable binding")
            }
            Self::InstallConflict => {
                formatter.write_str("attachment fence has different immutable install metadata")
            }
            Self::ShardAttachmentConflict => {
                formatter.write_str("dedicated shard already owns another egress attachment")
            }
            Self::InvalidProxyAddress(address) => {
                write!(formatter, "invalid attachment proxy address: {address}")
            }
            Self::InvalidExpiry => {
                formatter.write_str("attachment expiry must be a non-zero daemon instant")
            }
            Self::StaleReceipt => formatter.write_str("attachment receipt is stale or unknown"),
            Self::InvalidTransition { state, operation } => {
                write!(
                    formatter,
                    "cannot {operation} attachment in state {state:?}"
                )
            }
            Self::Terminal(state) => {
                write!(formatter, "attachment is terminal in state {state:?}")
            }
            Self::ListenerCloseNotAcknowledged => {
                formatter.write_str("listener close has not been acknowledged")
            }
            Self::AcceptedGuardsRemain { count } => {
                write!(formatter, "{count} accepted attachment guards remain")
            }
            Self::NotDrained => formatter.write_str("attachment has not entered drained state"),
            Self::GuardNotFound => formatter.write_str("accepted attachment guard is unknown"),
            Self::IdentifierExhausted => {
                formatter.write_str("attachment revision space is exhausted")
            }
        }
    }
}

impl std::error::Error for AttachmentError {}

/// Explicit counter token for the pure lifecycle model.
///
/// This is deliberately not an RAII data-plane guard. The attachment manager must pair it with
/// the existing ingress guard and return it through `AttachmentRegistry::finish_accepted`.
#[derive(Debug)]
pub(crate) struct AcceptedAttachmentToken {
    daemon_epoch: DaemonEpoch,
    fence: EgressFence,
    attachment_id: AttachmentId,
    guard_id: u64,
}

#[derive(Debug)]
struct AttachmentRecord {
    prepared: PreparedAttachmentReceipt,
    cancelled: Option<CancelledAttachmentReceipt>,
    installing: Option<InstallingAttachmentReceipt>,
    active: Option<ActiveAttachmentReceipt>,
    released: Option<ReleasedAttachmentReceipt>,
    state: AttachmentState,
    listener_close_acknowledged: bool,
    accepted_guards: HashSet<u64>,
}

/// Pure lifecycle state is not a public substitute for the data-plane ingress guard.
///
/// ```compile_fail
/// fn reserve(
///     registry: &mut browserd_egress::AttachmentRegistry,
///     receipt: &browserd_egress::ActiveAttachmentReceipt,
/// ) {
///     let _token = registry.begin_accepted(receipt);
/// }
/// ```
#[derive(Debug)]
pub struct AttachmentRegistry {
    daemon_epoch: DaemonEpoch,
    next_sequence: u64,
    records: HashMap<EgressFence, AttachmentRecord>,
}

impl AttachmentRegistry {
    #[must_use]
    pub fn new(daemon_epoch: DaemonEpoch) -> Self {
        Self {
            daemon_epoch,
            next_sequence: 1,
            records: HashMap::new(),
        }
    }

    #[must_use]
    pub const fn daemon_epoch(&self) -> DaemonEpoch {
        self.daemon_epoch
    }

    pub fn status(
        &self,
        daemon_epoch: DaemonEpoch,
        fence: &EgressFence,
    ) -> Result<AttachmentStatus, AttachmentError> {
        self.ensure_daemon_epoch(daemon_epoch)?;
        let Some(record) = self.records.get(fence) else {
            return Ok(AttachmentStatus::Absent);
        };
        let status = match record.state {
            AttachmentState::Absent => AttachmentStatus::Absent,
            AttachmentState::Prepared => AttachmentStatus::Prepared(record.prepared.clone()),
            AttachmentState::Installing => AttachmentStatus::Installing(
                record
                    .installing
                    .clone()
                    .ok_or(AttachmentError::StaleReceipt)?,
            ),
            AttachmentState::Active => AttachmentStatus::Active(
                record.active.clone().ok_or(AttachmentError::StaleReceipt)?,
            ),
            AttachmentState::Revoking => AttachmentStatus::Revoking(
                record.active.clone().ok_or(AttachmentError::StaleReceipt)?,
            ),
            AttachmentState::Revoked => AttachmentStatus::Revoked(
                record.active.clone().ok_or(AttachmentError::StaleReceipt)?,
            ),
            AttachmentState::Drained => AttachmentStatus::Drained(
                record.active.clone().ok_or(AttachmentError::StaleReceipt)?,
            ),
            AttachmentState::Cancelled => AttachmentStatus::Cancelled(
                record
                    .cancelled
                    .clone()
                    .ok_or(AttachmentError::StaleReceipt)?,
            ),
            AttachmentState::Released => AttachmentStatus::Released(
                record
                    .released
                    .clone()
                    .ok_or(AttachmentError::StaleReceipt)?,
            ),
        };
        Ok(status)
    }

    pub fn state(
        &self,
        daemon_epoch: DaemonEpoch,
        fence: &EgressFence,
    ) -> Result<AttachmentState, AttachmentError> {
        self.status(daemon_epoch, fence)
            .map(|status| status.state())
    }

    pub fn prepare(
        &mut self,
        daemon_epoch: DaemonEpoch,
        fence: EgressFence,
        binding_digest: BindingDigest,
    ) -> Result<PreparedAttachmentReceipt, AttachmentError> {
        self.ensure_daemon_epoch(daemon_epoch)?;
        if let Some(record) = self.records.get(&fence) {
            if record.prepared.binding_digest() != binding_digest {
                return Err(AttachmentError::BindingConflict);
            }
            return match record.state {
                AttachmentState::Prepared
                | AttachmentState::Installing
                | AttachmentState::Active => Ok(record.prepared.clone()),
                state => Err(AttachmentError::Terminal(state)),
            };
        }
        if self
            .records
            .values()
            .any(|record| record.prepared.fence().shard() == fence.shard())
        {
            return Err(AttachmentError::ShardAttachmentConflict);
        }

        let prepare_revision = self.allocate_sequence()?;
        let receipt = PreparedAttachmentReceipt {
            fence: fence.clone(),
            binding_digest,
            daemon_epoch,
            prepare_revision,
        };
        self.records.insert(
            fence,
            AttachmentRecord {
                prepared: receipt.clone(),
                cancelled: None,
                installing: None,
                active: None,
                released: None,
                state: AttachmentState::Prepared,
                listener_close_acknowledged: false,
                accepted_guards: HashSet::new(),
            },
        );
        Ok(receipt)
    }

    pub fn begin_install(
        &mut self,
        prepared: &PreparedAttachmentReceipt,
        proxy_address: SocketAddr,
        expires_at: AttachmentExpiry,
    ) -> Result<InstallReceipt, AttachmentError> {
        let state = self.validate_prepared(prepared)?.state;
        if !proxy_address.ip().is_loopback() || proxy_address.port() == 0 {
            return Err(AttachmentError::InvalidProxyAddress(proxy_address));
        }
        if expires_at.daemon_millis() == 0 {
            return Err(AttachmentError::InvalidExpiry);
        }
        match state {
            AttachmentState::Installing => {
                let record = self
                    .records
                    .get(prepared.fence())
                    .ok_or(AttachmentError::StaleReceipt)?;
                let installing = record
                    .installing
                    .clone()
                    .ok_or(AttachmentError::StaleReceipt);
                let installing = installing?;
                if installing.proxy_address() != proxy_address
                    || installing.expires_at() != expires_at
                {
                    return Err(AttachmentError::InstallConflict);
                }
                return Ok(InstallReceipt::Installing(installing));
            }
            AttachmentState::Active => {
                let record = self
                    .records
                    .get(prepared.fence())
                    .ok_or(AttachmentError::StaleReceipt)?;
                let active = record.active.clone().ok_or(AttachmentError::StaleReceipt);
                let active = active?;
                if active.proxy_address() != proxy_address || active.expires_at() != expires_at {
                    return Err(AttachmentError::InstallConflict);
                }
                return Ok(InstallReceipt::Active(active));
            }
            AttachmentState::Prepared => {}
            state => return Err(AttachmentError::Terminal(state)),
        }

        let attachment_sequence = self.allocate_sequence()?;
        let attachment_id = AttachmentId(
            NonZeroU64::new(attachment_sequence).ok_or(AttachmentError::IdentifierExhausted)?,
        );
        let activation_revision = self.allocate_sequence()?;
        let installing = InstallingAttachmentReceipt {
            prepared: prepared.clone(),
            attachment_id,
            proxy_address,
            expires_at,
        };
        let active = ActiveAttachmentReceipt {
            installing: installing.clone(),
            activation_revision,
        };
        let record = self
            .records
            .get_mut(prepared.fence())
            .ok_or(AttachmentError::StaleReceipt)?;
        record.installing = Some(installing.clone());
        record.active = Some(active);
        record.state = AttachmentState::Installing;
        Ok(InstallReceipt::Installing(installing))
    }

    pub fn complete_install(
        &mut self,
        installing: &InstallingAttachmentReceipt,
    ) -> Result<ActiveAttachmentReceipt, AttachmentError> {
        let state = self.validate_installing(installing)?.state;
        let record = self
            .records
            .get_mut(installing.fence())
            .ok_or(AttachmentError::StaleReceipt)?;
        match state {
            AttachmentState::Installing => {
                record.state = AttachmentState::Active;
                record.active.clone().ok_or(AttachmentError::StaleReceipt)
            }
            AttachmentState::Active => record.active.clone().ok_or(AttachmentError::StaleReceipt),
            state => Err(AttachmentError::Terminal(state)),
        }
    }

    pub fn cancel(
        &mut self,
        prepared: &PreparedAttachmentReceipt,
    ) -> Result<CancelledAttachmentReceipt, AttachmentError> {
        let state = self.validate_prepared(prepared)?.state;
        if matches!(
            state,
            AttachmentState::Cancelled | AttachmentState::Released
        ) {
            let record = self
                .records
                .get(prepared.fence())
                .ok_or(AttachmentError::StaleReceipt)?;
            if let Some(cancelled) = record.cancelled.clone() {
                return Ok(cancelled);
            }
            return Err(AttachmentError::Terminal(state));
        }
        if !matches!(
            state,
            AttachmentState::Prepared | AttachmentState::Installing
        ) {
            return Err(AttachmentError::InvalidTransition {
                state,
                operation: "cancel",
            });
        }
        let cancel_revision = self.allocate_sequence()?;
        let cancelled = CancelledAttachmentReceipt {
            prepared: prepared.clone(),
            cancel_revision,
        };
        let record = self
            .records
            .get_mut(prepared.fence())
            .ok_or(AttachmentError::StaleReceipt)?;
        match state {
            AttachmentState::Prepared => {
                record.state = AttachmentState::Cancelled;
                record.listener_close_acknowledged = true;
            }
            AttachmentState::Installing => {
                record.state = AttachmentState::Cancelled;
                record.listener_close_acknowledged = false;
            }
            _ => {
                return Err(AttachmentError::InvalidTransition {
                    state,
                    operation: "cancel",
                });
            }
        }
        record.cancelled = Some(cancelled.clone());
        Ok(cancelled)
    }

    pub fn acknowledge_cancelled_listener_closed(
        &mut self,
        installing: &InstallingAttachmentReceipt,
    ) -> Result<(), AttachmentError> {
        let state = self.validate_installing(installing)?.state;
        let record = self
            .records
            .get_mut(installing.fence())
            .ok_or(AttachmentError::StaleReceipt)?;
        match state {
            AttachmentState::Cancelled => {
                record.listener_close_acknowledged = true;
                Ok(())
            }
            AttachmentState::Released if record.released_attachment_id().is_none() => Ok(()),
            AttachmentState::Released => Err(AttachmentError::Terminal(AttachmentState::Released)),
            state => Err(AttachmentError::InvalidTransition {
                state,
                operation: "acknowledge cancelled listener close",
            }),
        }
    }

    pub fn release_cancelled(
        &mut self,
        cancelled: &CancelledAttachmentReceipt,
    ) -> Result<ReleasedAttachmentReceipt, AttachmentError> {
        let state = self.validate_cancelled(cancelled)?.state;
        if state == AttachmentState::Released {
            let record = self
                .records
                .get(cancelled.fence())
                .ok_or(AttachmentError::StaleReceipt)?;
            if record.released_attachment_id().is_none() {
                return record.released.clone().ok_or(AttachmentError::StaleReceipt);
            }
            return Err(AttachmentError::Terminal(AttachmentState::Released));
        }
        if state != AttachmentState::Cancelled {
            return Err(AttachmentError::InvalidTransition {
                state,
                operation: "release cancelled attachment",
            });
        }
        let listener_close_acknowledged = self
            .records
            .get(cancelled.fence())
            .ok_or(AttachmentError::StaleReceipt)?
            .listener_close_acknowledged;
        if !listener_close_acknowledged {
            return Err(AttachmentError::ListenerCloseNotAcknowledged);
        }
        let release_revision = self.allocate_sequence()?;
        let released = ReleasedAttachmentReceipt {
            prepared: cancelled.prepared().clone(),
            attachment_id: None,
            release_revision,
        };
        let record = self
            .records
            .get_mut(cancelled.fence())
            .ok_or(AttachmentError::StaleReceipt)?;
        record.state = AttachmentState::Released;
        record.released = Some(released.clone());
        Ok(released)
    }

    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "the attachment manager will reserve model tokens at ingress accept"
        )
    )]
    pub(crate) fn begin_accepted(
        &mut self,
        active: &ActiveAttachmentReceipt,
    ) -> Result<AcceptedAttachmentToken, AttachmentError> {
        let state = self.validate_active(active)?.state;
        if state != AttachmentState::Active {
            return Err(AttachmentError::InvalidTransition {
                state,
                operation: "accept ingress",
            });
        }
        let guard_id = self.allocate_sequence()?;
        let record = self
            .records
            .get_mut(active.fence())
            .ok_or(AttachmentError::StaleReceipt)?;
        record.accepted_guards.insert(guard_id);
        Ok(AcceptedAttachmentToken {
            daemon_epoch: active.daemon_epoch(),
            fence: active.fence().clone(),
            attachment_id: active.attachment_id(),
            guard_id,
        })
    }

    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "the attachment manager will return model tokens with its RAII guard"
        )
    )]
    pub(crate) fn finish_accepted(
        &mut self,
        guard: AcceptedAttachmentToken,
    ) -> Result<(), AttachmentError> {
        self.ensure_daemon_epoch(guard.daemon_epoch)?;
        let record = self
            .records
            .get_mut(&guard.fence)
            .ok_or(AttachmentError::StaleReceipt)?;
        let active = record
            .active
            .as_ref()
            .ok_or(AttachmentError::StaleReceipt)?;
        if active.attachment_id() != guard.attachment_id {
            return Err(AttachmentError::StaleReceipt);
        }
        if !record.accepted_guards.remove(&guard.guard_id) {
            return Err(AttachmentError::GuardNotFound);
        }
        Ok(())
    }

    pub fn begin_revoke(
        &mut self,
        active: &ActiveAttachmentReceipt,
    ) -> Result<ActiveAttachmentReceipt, AttachmentError> {
        let state = self.validate_active(active)?.state;
        let record = self
            .records
            .get_mut(active.fence())
            .ok_or(AttachmentError::StaleReceipt)?;
        match state {
            AttachmentState::Installing | AttachmentState::Active => {
                record.state = AttachmentState::Revoking;
                Ok(active.clone())
            }
            AttachmentState::Revoking | AttachmentState::Revoked | AttachmentState::Drained => {
                Ok(active.clone())
            }
            state => Err(AttachmentError::Terminal(state)),
        }
    }

    pub fn begin_revoke_installing(
        &mut self,
        installing: &InstallingAttachmentReceipt,
    ) -> Result<ActiveAttachmentReceipt, AttachmentError> {
        let state = self.validate_installing(installing)?.state;
        let record = self
            .records
            .get_mut(installing.fence())
            .ok_or(AttachmentError::StaleReceipt)?;
        match state {
            AttachmentState::Installing | AttachmentState::Active => {
                record.state = AttachmentState::Revoking;
                record.active.clone().ok_or(AttachmentError::StaleReceipt)
            }
            AttachmentState::Revoking | AttachmentState::Revoked | AttachmentState::Drained => {
                record.active.clone().ok_or(AttachmentError::StaleReceipt)
            }
            state => Err(AttachmentError::Terminal(state)),
        }
    }

    pub fn acknowledge_listener_closed(
        &mut self,
        active: &ActiveAttachmentReceipt,
    ) -> Result<(), AttachmentError> {
        let state = self.validate_active(active)?.state;
        let record = self
            .records
            .get_mut(active.fence())
            .ok_or(AttachmentError::StaleReceipt)?;
        match state {
            AttachmentState::Revoking => {
                record.listener_close_acknowledged = true;
                record.state = AttachmentState::Revoked;
                Ok(())
            }
            AttachmentState::Revoked | AttachmentState::Drained => Ok(()),
            state => Err(AttachmentError::InvalidTransition {
                state,
                operation: "acknowledge listener close",
            }),
        }
    }

    pub fn mark_drained(
        &mut self,
        active: &ActiveAttachmentReceipt,
    ) -> Result<(), AttachmentError> {
        let state = self.validate_active(active)?.state;
        let record = self
            .records
            .get_mut(active.fence())
            .ok_or(AttachmentError::StaleReceipt)?;
        match state {
            AttachmentState::Revoking => Err(AttachmentError::ListenerCloseNotAcknowledged),
            AttachmentState::Revoked if !record.accepted_guards.is_empty() => {
                Err(AttachmentError::AcceptedGuardsRemain {
                    count: record.accepted_guards.len(),
                })
            }
            AttachmentState::Revoked => {
                record.state = AttachmentState::Drained;
                Ok(())
            }
            AttachmentState::Drained => Ok(()),
            state => Err(AttachmentError::InvalidTransition {
                state,
                operation: "mark drained",
            }),
        }
    }

    pub fn release(
        &mut self,
        active: &ActiveAttachmentReceipt,
    ) -> Result<ReleasedAttachmentReceipt, AttachmentError> {
        let state = self.validate_active(active)?.state;
        if state == AttachmentState::Released {
            let record = self
                .records
                .get(active.fence())
                .ok_or(AttachmentError::StaleReceipt)?;
            if record.released_attachment_id() == Some(active.attachment_id()) {
                return record.released.clone().ok_or(AttachmentError::StaleReceipt);
            }
            return Err(AttachmentError::Terminal(AttachmentState::Released));
        }
        let record = self
            .records
            .get(active.fence())
            .ok_or(AttachmentError::StaleReceipt)?;
        match state {
            AttachmentState::Revoking | AttachmentState::Installing | AttachmentState::Active => {
                return Err(AttachmentError::ListenerCloseNotAcknowledged);
            }
            AttachmentState::Revoked if !record.accepted_guards.is_empty() => {
                return Err(AttachmentError::AcceptedGuardsRemain {
                    count: record.accepted_guards.len(),
                });
            }
            AttachmentState::Revoked => return Err(AttachmentError::NotDrained),
            AttachmentState::Drained => {}
            state => return Err(AttachmentError::Terminal(state)),
        }
        let release_revision = self.allocate_sequence()?;
        let released = ReleasedAttachmentReceipt {
            prepared: active.prepared().clone(),
            attachment_id: Some(active.attachment_id()),
            release_revision,
        };
        let record = self
            .records
            .get_mut(active.fence())
            .ok_or(AttachmentError::StaleReceipt)?;
        record.state = AttachmentState::Released;
        record.released = Some(released.clone());
        Ok(released)
    }

    fn ensure_daemon_epoch(&self, actual: DaemonEpoch) -> Result<(), AttachmentError> {
        if actual == self.daemon_epoch {
            Ok(())
        } else {
            Err(AttachmentError::DaemonEpochMismatch {
                expected: self.daemon_epoch,
                actual,
            })
        }
    }

    fn validate_prepared(
        &self,
        prepared: &PreparedAttachmentReceipt,
    ) -> Result<&AttachmentRecord, AttachmentError> {
        self.ensure_daemon_epoch(prepared.daemon_epoch())?;
        let record = self
            .records
            .get(prepared.fence())
            .ok_or(AttachmentError::StaleReceipt)?;
        if record.prepared == *prepared {
            Ok(record)
        } else {
            Err(AttachmentError::StaleReceipt)
        }
    }

    fn validate_installing(
        &self,
        installing: &InstallingAttachmentReceipt,
    ) -> Result<&AttachmentRecord, AttachmentError> {
        self.ensure_daemon_epoch(installing.daemon_epoch())?;
        let record = self
            .records
            .get(installing.fence())
            .ok_or(AttachmentError::StaleReceipt)?;
        if record.installing.as_ref() == Some(installing) {
            Ok(record)
        } else {
            Err(AttachmentError::StaleReceipt)
        }
    }

    fn validate_cancelled(
        &self,
        cancelled: &CancelledAttachmentReceipt,
    ) -> Result<&AttachmentRecord, AttachmentError> {
        self.ensure_daemon_epoch(cancelled.daemon_epoch())?;
        let record = self
            .records
            .get(cancelled.fence())
            .ok_or(AttachmentError::StaleReceipt)?;
        if record.cancelled.as_ref() == Some(cancelled) {
            Ok(record)
        } else {
            Err(AttachmentError::StaleReceipt)
        }
    }

    fn validate_active(
        &self,
        active: &ActiveAttachmentReceipt,
    ) -> Result<&AttachmentRecord, AttachmentError> {
        self.ensure_daemon_epoch(active.daemon_epoch())?;
        let record = self
            .records
            .get(active.fence())
            .ok_or(AttachmentError::StaleReceipt)?;
        if record.active.as_ref() == Some(active) {
            Ok(record)
        } else {
            Err(AttachmentError::StaleReceipt)
        }
    }

    fn allocate_sequence(&mut self) -> Result<u64, AttachmentError> {
        let sequence = self.next_sequence;
        self.next_sequence = sequence
            .checked_add(1)
            .ok_or(AttachmentError::IdentifierExhausted)?;
        Ok(sequence)
    }
}

impl AttachmentRecord {
    fn released_attachment_id(&self) -> Option<AttachmentId> {
        self.released
            .as_ref()
            .and_then(|receipt| receipt.attachment_id)
    }
}
