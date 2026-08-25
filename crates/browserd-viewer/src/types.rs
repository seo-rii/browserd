use std::fmt;
use std::time::Duration;

use browserd_core::{LeaseId, PageId, SessionId, TenantId};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ViewerScopes {
    read: bool,
    control: bool,
    admin: bool,
}

impl ViewerScopes {
    #[must_use]
    pub const fn new(read: bool, control: bool, admin: bool) -> Self {
        Self {
            read,
            control,
            admin,
        }
    }

    #[must_use]
    pub const fn can_read(self) -> bool {
        self.read
    }

    #[must_use]
    pub const fn can_control(self) -> bool {
        self.control
    }

    #[must_use]
    pub const fn can_admin(self) -> bool {
        self.admin
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ViewerTicket(pub(crate) LeaseId);

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ConnectionId(pub(crate) LeaseId);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ViewerConnection {
    pub(crate) id: ConnectionId,
    pub(crate) tenant_id: TenantId,
    pub(crate) session_id: SessionId,
    pub(crate) session_incarnation: u64,
    pub(crate) scopes: ViewerScopes,
}

impl ViewerConnection {
    #[must_use]
    pub const fn id(&self) -> &ConnectionId {
        &self.id
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
    pub const fn session_incarnation(&self) -> u64 {
        self.session_incarnation
    }

    #[must_use]
    pub const fn scopes(&self) -> ViewerScopes {
        self.scopes
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TicketPolicy {
    pub(crate) max_ttl_millis: u64,
    pub(crate) allowed_origins: Vec<String>,
}

impl TicketPolicy {
    pub fn new<I, S>(max_ttl: Duration, allowed_origins: I) -> Result<Self, TicketError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let max_ttl_millis =
            u64::try_from(max_ttl.as_millis()).map_err(|_| TicketError::InvalidPolicy)?;
        let allowed_origins: Vec<_> = allowed_origins.into_iter().map(Into::into).collect();
        if max_ttl_millis == 0
            || allowed_origins.is_empty()
            || allowed_origins.iter().any(|origin| origin.is_empty())
        {
            return Err(TicketError::InvalidPolicy);
        }
        Ok(Self {
            max_ttl_millis,
            allowed_origins,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TicketError {
    InvalidPolicy,
    ReadScopeRequired,
    TtlOutOfRange,
    TimeOverflow,
    UnknownTicket,
    AlreadyConsumed,
    BindingMismatch,
    OriginDenied,
    Expired,
    StateUnavailable,
}

impl fmt::Display for TicketError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "viewer ticket error: {self:?}")
    }
}

impl std::error::Error for TicketError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlLease {
    pub(crate) connection_id: ConnectionId,
    pub(crate) epoch: u64,
    pub(crate) page_id: PageId,
    pub(crate) expires_at_millis: u64,
    pub(crate) last_input_sequence: u64,
}

impl ControlLease {
    #[must_use]
    pub const fn connection_id(&self) -> &ConnectionId {
        &self.connection_id
    }

    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    #[must_use]
    pub const fn page_id(&self) -> &PageId {
        &self.page_id
    }

    #[must_use]
    pub const fn expires_at_millis(&self) -> u64 {
        self.expires_at_millis
    }

    #[must_use]
    pub const fn last_input_sequence(&self) -> u64 {
        self.last_input_sequence
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcquireOutcome {
    pub(crate) lease: ControlLease,
    pub(crate) replaced_controller: Option<ConnectionId>,
}

impl AcquireOutcome {
    #[must_use]
    pub const fn lease(&self) -> &ControlLease {
        &self.lease
    }

    #[must_use]
    pub const fn replaced_controller(&self) -> Option<&ConnectionId> {
        self.replaced_controller.as_ref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlSnapshot {
    pub(crate) epoch: u64,
    pub(crate) lease: Option<ControlLease>,
}

impl ControlSnapshot {
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    #[must_use]
    pub const fn lease(&self) -> Option<&ControlLease> {
        self.lease.as_ref()
    }

    #[must_use]
    pub const fn is_agent_control(&self) -> bool {
        self.lease.is_none()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ControlError {
    InvalidPolicy,
    InvalidLeaseTtl,
    TimeOverflow,
    EpochExhausted,
    StateUnavailable,
    ConnectionBindingMismatch,
    ConnectionAlreadyAttached,
    ConnectionNotFound,
    ControlScopeRequired,
    AdminScopeRequired,
    AlreadyControlled,
    NoActiveControl,
    NotController,
    StaleLeaseEpoch,
    LeaseExpired,
    ObserverLimitExceeded,
}

impl fmt::Display for ControlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "viewer control error: {self:?}")
    }
}

impl std::error::Error for ControlError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControlPolicy {
    pub(crate) max_observers: usize,
    pub(crate) lease_ttl_millis: u64,
    pub(crate) input_rate_limit: usize,
    pub(crate) input_rate_window_millis: u64,
}

impl ControlPolicy {
    pub fn new(
        max_observers: usize,
        lease_ttl: Duration,
        input_rate_limit: usize,
        input_rate_window: Duration,
    ) -> Result<Self, ControlError> {
        let lease_ttl_millis =
            u64::try_from(lease_ttl.as_millis()).map_err(|_| ControlError::InvalidPolicy)?;
        let input_rate_window_millis = u64::try_from(input_rate_window.as_millis())
            .map_err(|_| ControlError::InvalidPolicy)?;
        if max_observers == 0
            || lease_ttl_millis == 0
            || input_rate_limit == 0
            || input_rate_window_millis == 0
        {
            return Err(ControlError::InvalidPolicy);
        }
        Ok(Self {
            max_observers,
            lease_ttl_millis,
            input_rate_limit,
            input_rate_window_millis,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlInput {
    pub(crate) lease_epoch: u64,
    pub(crate) input_sequence: u64,
    pub(crate) page_id: PageId,
    pub(crate) transform_epoch: u64,
    pub(crate) kind: InputKind,
}

impl ControlInput {
    #[must_use]
    pub const fn new(
        lease_epoch: u64,
        input_sequence: u64,
        page_id: PageId,
        transform_epoch: u64,
        kind: InputKind,
    ) -> Self {
        Self {
            lease_epoch,
            input_sequence,
            page_id,
            transform_epoch,
            kind,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InputKind {
    MouseDown(u8),
    MouseUp(u8),
    MouseMove,
    Wheel,
    KeyDown(String),
    KeyUp(String),
    InsertText(String),
    CompositionStart,
    CompositionUpdate(String),
    CompositionCommit(String),
    CompositionCancel,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InputEffect {
    None,
    TextInserted(String),
    CompositionCommitted(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputDiscardReason {
    NoActiveControl,
    NotController,
    StaleLeaseEpoch,
    LeaseExpired,
    ReplaySequence,
    PageMismatch,
    StaleTransform,
    CompositionNotActive,
    CompositionAlreadyActive,
    RateLimited,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InputDecision {
    Accepted(InputEffect),
    Discarded(InputDiscardReason),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InputCleanup {
    pub(crate) connection_id: ConnectionId,
    pub(crate) lease_epoch: u64,
    pub(crate) released_mouse_buttons: Vec<u8>,
    pub(crate) released_keys: Vec<String>,
    pub(crate) drag_cancelled: bool,
    pub(crate) cancelled_composition: Option<String>,
}

impl InputCleanup {
    #[must_use]
    pub const fn connection_id(&self) -> &ConnectionId {
        &self.connection_id
    }

    #[must_use]
    pub const fn lease_epoch(&self) -> u64 {
        self.lease_epoch
    }

    #[must_use]
    pub fn released_mouse_buttons(&self) -> &[u8] {
        &self.released_mouse_buttons
    }

    #[must_use]
    pub fn released_keys(&self) -> &[String] {
        &self.released_keys
    }

    #[must_use]
    pub const fn drag_cancelled(&self) -> bool {
        self.drag_cancelled
    }

    #[must_use]
    pub fn cancelled_composition(&self) -> Option<&str> {
        self.cancelled_composition.as_deref()
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct InputStateSnapshot {
    pub(crate) pressed_mouse_buttons: Vec<u8>,
    pub(crate) pressed_keys: Vec<String>,
    pub(crate) drag_active: bool,
    pub(crate) composition_preedit: Option<String>,
}

impl InputStateSnapshot {
    #[must_use]
    pub fn pressed_mouse_buttons(&self) -> &[u8] {
        &self.pressed_mouse_buttons
    }

    #[must_use]
    pub fn pressed_keys(&self) -> &[String] {
        &self.pressed_keys
    }

    #[must_use]
    pub const fn drag_active(&self) -> bool {
        self.drag_active
    }

    #[must_use]
    pub fn composition_preedit(&self) -> Option<&str> {
        self.composition_preedit.as_deref()
    }
}
