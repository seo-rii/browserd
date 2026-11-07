//! Durable, ordered event outbox for at-least-once tenant notification (BRD-017).
//!
//! The polling/event channel needs a durable substrate that is loaded from the same authority as
//! the durable action/session transitions, so a consumer that fell behind can resume exactly and
//! detect a gap rather than silently miss a transition. This module provides that substrate: a
//! per-tenant, monotonically sequenced log of terminal transitions with
//!
//! * a stable delivery identity ([`OutboxEvent::event_id`], a UUIDv7) so a sink can suppress a
//!   duplicate *effect* even though duplicate *delivery* is allowed,
//! * an ordered [`EventCursor`] (a per-tenant sequence, unlike a UUIDv7 which is only
//!   approximately time-ordered) so a consumer resumes deterministically and a pruned prefix is
//!   reported as [`OutboxPage::cursor_expired`] instead of a silent hole,
//! * the durable [`OutboxEvent::aggregate_revision`] at the transition, so a consumer can reconcile
//!   an event against the polling source-of-truth, and
//! * an **idempotent append** keyed on `(aggregate, aggregate_revision, kind)`, so a terminal
//!   commit that is re-driven (for example by the gateway's periodic reconcile pass after a crash
//!   between the durable commit and the outbox append) does not append a second event.
//!
//! The ordinary append's idempotency index is pruned with its event. Durable source relays must
//! instead use [`EventOutbox::append_projection`]: its permanent per-session watermark commits
//! atomically with the event, so a lost source acknowledgement cannot recreate an expired event.
//! Projection watermarks share the lifetime of the source's permanent session fence and must not
//! be aged out with notification payloads. The immutable source journal is trusted to bind each
//! session sequence to exactly one payload; old acknowledged payloads need not remain in the sink.
//!
//! [`MemoryEventOutbox`] is the single-host backend used by tests and the in-memory deployment; a
//! Redis-backed store mirrors it for the multi-host deployment.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use browserd_core::{
    ActionId, ApprovalId, ArtifactId, NotificationAck, NotificationCommit, NotificationSourceScope,
    OperationId, SessionId, TenantId,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::{EventProjectionSource, GatewayEventProjection};

mod model;
pub use model::*;

mod notification_import;
mod postgres;
mod redis;

pub use notification_import::{NOTIFICATION_IMPORT_RECEIPTS_PER_SOURCE, NotificationImportConfig};

pub use postgres::PostgresEventOutbox;
pub use redis::{RedisEventOutbox, RedisEventOutboxConfig};

/// Minimum event retention, matching the durable action/idempotency retention floor: a consumer
/// that reconnects within a day must never observe a pruned-prefix gap for a transition it had
/// not yet seen.
pub const MINIMUM_EVENT_RETENTION: Duration = Duration::from_secs(24 * 60 * 60);

/// Largest page a single [`EventOutbox::read_from`] may return, bounding a consumer's per-poll
/// work and the store's per-call allocation.
pub const MAX_EVENT_PAGE_LIMIT: usize = 256;

/// An ordered position in a tenant's durable event stream.
///
/// The value is a per-tenant sequence number: the first event a tenant ever records has sequence
/// `1`, and [`EventCursor::start`] (`0`) is the position *before* the first event. A consumer
/// resumes by asking for events strictly after its cursor, so ordering and gap detection are
/// exact — a property a UUIDv7 event id cannot provide, since two ids minted in the same
/// millisecond are not totally ordered.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EventCursor(u64);

impl EventCursor {
    /// The position before a tenant's first event; reading after it returns the whole stream.
    #[must_use]
    pub const fn start() -> Self {
        Self(0)
    }

    /// A cursor at an explicit sequence position, for a consumer restoring a persisted cursor.
    /// Reading after it returns events whose sequence is strictly greater.
    #[must_use]
    pub const fn from_position(position: u64) -> Self {
        Self(position)
    }

    /// The raw per-tenant sequence position.
    #[must_use]
    pub const fn position(self) -> u64 {
        self.0
    }
}

/// The durable aggregate whose terminal transition an event records.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub enum OutboxAggregate {
    /// An action reached a terminal outcome within its session.
    Action {
        session_id: SessionId,
        action_id: ActionId,
    },
    /// A session was fenced as lost.
    Session {
        session_id: SessionId,
    },
    Operation {
        operation_id: OperationId,
    },
    Approval {
        session_id: SessionId,
        action_id: ActionId,
        approval_id: ApprovalId,
    },
    Artifact {
        session_id: SessionId,
        artifact_id: ArtifactId,
    },
}

/// Durable notification taxonomy. The three original variants retain their serialized forms;
/// new kinds carry a strictly typed state summary from their committing authority.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum OutboxEventKind {
    /// An action settled into a terminal state (succeeded, failed, or otherwise resolved).
    ActionTerminal,
    /// A session was fenced as lost, terminalizing its unresolved work.
    SessionLost,
    /// The worker durably committed a change between agent and human control.
    ControlChanged,
    OperationStateChanged,
    SessionLifecycleChanged,
    SessionExecutionChanged,
    ActionStateChanged,
    ActionApprovalRequired,
    ApprovalDecided,
    BrowserControlChanged,
    DownloadCompleted,
    ArtifactStateChanged,
}

/// A single durable notification: one terminal transition of one aggregate, positioned in its
/// tenant's ordered stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboxEvent {
    event_id: Uuid,
    tenant_id: TenantId,
    tenant_seq: u64,
    aggregate: OutboxAggregate,
    aggregate_revision: u64,
    kind: OutboxEventKind,
    created_at: DateTime<Utc>,
    summary: Option<EventStateSummary>,
}

impl OutboxEvent {
    /// Stable delivery identity (UUIDv7). Two deliveries of the same transition carry the same
    /// id, so a sink deduplicates by it to avoid a duplicate effect.
    #[must_use]
    pub const fn event_id(&self) -> Uuid {
        self.event_id
    }

    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// The event's ordered position, as a resumable cursor.
    #[must_use]
    pub const fn cursor(&self) -> EventCursor {
        EventCursor(self.tenant_seq)
    }

    #[must_use]
    pub const fn aggregate(&self) -> &OutboxAggregate {
        &self.aggregate
    }

    /// The durable revision of the aggregate at the recorded transition, for reconciling the
    /// event against the polling source-of-truth.
    #[must_use]
    pub const fn aggregate_revision(&self) -> u64 {
        self.aggregate_revision
    }

    #[must_use]
    pub const fn kind(&self) -> OutboxEventKind {
        self.kind
    }

    #[must_use]
    pub const fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
}

/// A page of events resumed from a cursor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboxPage {
    events: Vec<OutboxEvent>,
    next_cursor: EventCursor,
    cursor_expired: bool,
}

impl OutboxPage {
    /// Events strictly after the requested cursor, in ascending order.
    #[must_use]
    pub fn events(&self) -> &[OutboxEvent] {
        &self.events
    }

    /// The cursor to resume the next poll from: the last returned event's position, or the
    /// requested cursor when the page is empty.
    #[must_use]
    pub const fn next_cursor(&self) -> EventCursor {
        self.next_cursor
    }

    /// `true` when the requested cursor sits before an event that retention has already pruned,
    /// so the consumer has missed at least one transition and must fall back to the polling
    /// source-of-truth to reconcile the gap.
    #[must_use]
    pub const fn cursor_expired(&self) -> bool {
        self.cursor_expired
    }
}

/// A description of a terminal transition to record, minted by the coordination authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OutboxAppend {
    tenant_id: TenantId,
    aggregate: OutboxAggregate,
    aggregate_revision: u64,
    kind: OutboxEventKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    summary: Option<EventStateSummary>,
}

impl<'de> Deserialize<'de> for OutboxAppend {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Raw {
            tenant_id: TenantId,
            aggregate: OutboxAggregate,
            aggregate_revision: u64,
            kind: OutboxEventKind,
            #[serde(default)]
            summary: Option<EventStateSummary>,
        }
        let raw = Raw::deserialize(deserializer)?;
        let value = Self {
            tenant_id: raw.tenant_id,
            aggregate: raw.aggregate,
            aggregate_revision: raw.aggregate_revision,
            kind: raw.kind,
            summary: raw.summary,
        };
        value.validate().map_err(serde::de::Error::custom)?;
        Ok(value)
    }
}

impl OutboxAppend {
    #[must_use]
    pub const fn kind(&self) -> OutboxEventKind {
        self.kind
    }

    #[must_use]
    pub const fn aggregate_revision(&self) -> u64 {
        self.aggregate_revision
    }

    /// The revision is the persistent control journal sequence, not a transient lease epoch.
    #[must_use]
    pub const fn control_changed(
        tenant_id: TenantId,
        session_id: SessionId,
        aggregate_revision: u64,
    ) -> Self {
        Self {
            tenant_id,
            aggregate: OutboxAggregate::Session { session_id },
            aggregate_revision,
            kind: OutboxEventKind::ControlChanged,
            summary: None,
        }
    }
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    #[must_use]
    pub const fn session_id(&self) -> Option<&SessionId> {
        match &self.aggregate {
            OutboxAggregate::Action { session_id, .. }
            | OutboxAggregate::Approval { session_id, .. }
            | OutboxAggregate::Artifact { session_id, .. }
            | OutboxAggregate::Session { session_id } => Some(session_id),
            OutboxAggregate::Operation { .. } => None,
        }
    }

    /// Record an action's terminal transition at its durable revision.
    #[must_use]
    pub const fn action_terminal(
        tenant_id: TenantId,
        session_id: SessionId,
        action_id: ActionId,
        aggregate_revision: u64,
    ) -> Self {
        Self {
            tenant_id,
            aggregate: OutboxAggregate::Action {
                session_id,
                action_id,
            },
            aggregate_revision,
            kind: OutboxEventKind::ActionTerminal,
            summary: None,
        }
    }

    /// Record a session-lost fence at its durable revision.
    #[must_use]
    pub const fn session_lost(
        tenant_id: TenantId,
        session_id: SessionId,
        aggregate_revision: u64,
    ) -> Self {
        Self {
            tenant_id,
            aggregate: OutboxAggregate::Session { session_id },
            aggregate_revision,
            kind: OutboxEventKind::SessionLost,
            summary: None,
        }
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum EventOutboxError {
    #[error("event descriptor is invalid")]
    InvalidEvent,
    #[error("event identity already names a different immutable descriptor")]
    ConflictingEvent,
    #[error("event retention must be at least 24 hours")]
    RetentionBelowMinimum,
    #[error("event page limit must be between 1 and {MAX_EVENT_PAGE_LIMIT}")]
    InvalidPageLimit,
    #[error("delivered cursor must not run ahead of the recorded stream")]
    DeliveryCursorAhead,
    #[error("event outbox sequence overflowed")]
    SequenceOverflow,
    #[error("event outbox retention timestamp is outside the supported range")]
    RetentionTimestampOverflow,
    #[error("event outbox state lock is unavailable")]
    LockUnavailable,
    #[error("event outbox blocking client could not start")]
    ClientSpawn,
    #[error("Redis event outbox configuration is invalid")]
    InvalidRedisConfig,
    #[error("Redis event outbox is unavailable")]
    RedisUnavailable,
    #[error("Redis event outbox timed out")]
    RedisTimedOut,
    #[error("Redis event outbox returned invalid state")]
    InvalidRedisResponse,
    #[error("Postgres event outbox is unavailable")]
    PostgresUnavailable,
    #[error("Postgres event outbox returned invalid state")]
    InvalidPostgresState,
    #[error("event outbox does not support durable source projections")]
    UnsupportedProjection,
    #[error("event projection sequence must be between 1 and i64::MAX")]
    InvalidProjectionSequence,
    #[error("event projection scope does not match its payload")]
    ProjectionScopeMismatch,
    #[error("event projection has an unacknowledged predecessor")]
    ProjectionGap,
    #[error("worker notification commit is invalid")]
    InvalidNotificationCommit,
    #[error("worker notification source digest conflicts with its committed sequence")]
    NotificationDigestMismatch,
    #[error("worker notification receipt is outside the retained exact-digest window")]
    NotificationReceiptExpired,
    #[error("worker notification import configuration is invalid or differs from authority")]
    InvalidNotificationImportConfig,
    #[error("worker notification source lifetime capacity is exhausted")]
    NotificationSourceCapacity,
}

/// A durable, ordered, per-tenant event outbox providing at-least-once notification.
#[async_trait]
pub trait EventOutbox: Send + Sync {
    /// Append a terminal transition, assigning it the next per-tenant sequence, and return the
    /// recorded event. The call is **idempotent** on `(aggregate, aggregate_revision, kind)`: a
    /// re-driven terminal commit returns the already-recorded event unchanged rather than minting
    /// a second one, so a consumer never sees a duplicate transition even though the append may be
    /// retried after a crash.
    async fn append(
        &self,
        append: OutboxAppend,
        now: DateTime<Utc>,
    ) -> Result<OutboxEvent, EventOutboxError>;

    /// Atomically append the source's next contiguous per-session projection and retain its
    /// watermark independently of event retention. A retry at or below that watermark succeeds
    /// without appending, even when its event payload has expired. A gap fails without admitting
    /// the later event. The source journal must permanently bind each sequence to its payload.
    /// Backends without this transaction must reject it rather than silently use ordinary append.
    async fn append_projection(
        &self,
        _projection: GatewayEventProjection,
        _now: DateTime<Utc>,
    ) -> Result<(), EventOutboxError> {
        Err(EventOutboxError::UnsupportedProjection)
    }

    /// Atomically import one original worker authority commit and return its exact source ACK.
    /// Stable event IDs and original timestamps are preserved; retention starts at import time.
    /// Permanent source watermarks and the last 64 exact sequence digests survive event pruning.
    /// The authenticated relay must ACK the oldest pending commit before advancing that source.
    async fn append_notification_commit(
        &self,
        _commit: NotificationCommit,
        _trusted_now: DateTime<Utc>,
    ) -> Result<NotificationAck, EventOutboxError> {
        Err(EventOutboxError::UnsupportedProjection)
    }

    /// Return up to `limit` events strictly after `after`, in ascending order, pruning events
    /// older than the configured retention first. When `after` points before an already-pruned
    /// event the page is flagged [`OutboxPage::cursor_expired`].
    async fn read_from(
        &self,
        tenant_id: &TenantId,
        after: EventCursor,
        limit: usize,
        now: DateTime<Utc>,
    ) -> Result<OutboxPage, EventOutboxError>;

    /// Resume after the event named by the stable id `after` (or from the beginning when `None`).
    ///
    /// This is the anchor a public API keyed on an opaque event id uses, while the store keeps the
    /// ordered sequence internally for exact resumption. When `after` names an event that retention
    /// has pruned — or one that never existed for this tenant — the page is flagged
    /// [`OutboxPage::cursor_expired`] and returns from the oldest retained event, so a lagging
    /// consumer recovers forward rather than stalling on a cursor the store can no longer place.
    async fn read_after_event_id(
        &self,
        tenant_id: &TenantId,
        after: Option<Uuid>,
        limit: usize,
        now: DateTime<Utc>,
    ) -> Result<OutboxPage, EventOutboxError>;

    /// Advance the tenant's delivered watermark to `cursor` (a no-op when it is already at or past
    /// it). A consumer commits its progress here after a successful dispatch; on restart it
    /// resumes from [`EventOutbox::delivered_cursor`], redelivering any un-acked tail.
    async fn mark_delivered(
        &self,
        tenant_id: &TenantId,
        cursor: EventCursor,
    ) -> Result<(), EventOutboxError>;

    /// The tenant's committed delivery watermark; [`EventCursor::start`] when nothing has been
    /// acknowledged.
    async fn delivered_cursor(&self, tenant_id: &TenantId)
    -> Result<EventCursor, EventOutboxError>;
}

fn retention_floor(retention: Duration) -> Result<Duration, EventOutboxError> {
    if retention < MINIMUM_EVENT_RETENTION {
        Err(EventOutboxError::RetentionBelowMinimum)
    } else {
        Ok(retention)
    }
}

fn validated_limit(limit: usize) -> Result<usize, EventOutboxError> {
    if (1..=MAX_EVENT_PAGE_LIMIT).contains(&limit) {
        Ok(limit)
    } else {
        Err(EventOutboxError::InvalidPageLimit)
    }
}

fn validated_projection(projection: &GatewayEventProjection) -> Result<(), EventOutboxError> {
    projection.append().validate()?;
    if projection.sequence() == 0 || projection.sequence() > i64::MAX as u64 {
        return Err(EventOutboxError::InvalidProjectionSequence);
    }
    if projection.tenant_id() != projection.append().tenant_id()
        || Some(projection.session_id()) != projection.append().session_id()
        || (projection.source() == EventProjectionSource::ViewerControl)
            != (projection.append().kind == OutboxEventKind::ControlChanged)
        || (projection.source() == EventProjectionSource::ViewerControl
            && projection.append().aggregate_revision != projection.sequence())
    {
        return Err(EventOutboxError::ProjectionScopeMismatch);
    }
    Ok(())
}

#[derive(Default)]
struct TenantOutbox {
    /// Highest sequence assigned so far; the next append is `next_seq + 1`.
    next_seq: u64,
    /// Highest sequence removed by retention, so a resume from at-or-before it is a reported gap.
    pruned_through: u64,
    /// Committed delivery watermark.
    delivered_through: u64,
    events: VecDeque<OutboxEvent>,
    /// Idempotency index: `(aggregate, revision, kind)` -> assigned sequence, for the retained
    /// window. An append whose key is present returns the existing event.
    dedup: HashMap<(OutboxAggregate, u64, OutboxEventKind), u64>,
    /// Permanent while the source session fence exists; never included in event pruning.
    projection_watermarks: HashMap<(EventProjectionSource, SessionId), u64>,
    /// Original occurrence time is public; imported notification retention starts at commit time.
    retention_started: HashMap<u64, DateTime<Utc>>,
    notification_watermarks:
        HashMap<NotificationSourceScope, notification_import::NotificationWatermark>,
}

impl TenantOutbox {
    fn append(
        &mut self,
        append: OutboxAppend,
        retention: Duration,
        now: DateTime<Utc>,
    ) -> Result<OutboxEvent, EventOutboxError> {
        append.validate()?;
        self.prune(retention, now)?;
        let key = (
            append.aggregate.clone(),
            append.aggregate_revision,
            append.kind,
        );
        if let Some(existing_seq) = self.dedup.get(&key).copied()
            && let Some(event) = self
                .events
                .iter()
                .find(|event| event.tenant_seq == existing_seq)
        {
            if !event.matches_append(&append) {
                return Err(EventOutboxError::ConflictingEvent);
            }
            return Ok(event.clone());
        }
        let tenant_seq = self
            .next_seq
            .checked_add(1)
            .ok_or(EventOutboxError::SequenceOverflow)?;
        let event = OutboxEvent {
            event_id: Uuid::now_v7(),
            tenant_id: append.tenant_id,
            tenant_seq,
            aggregate: append.aggregate,
            aggregate_revision: append.aggregate_revision,
            kind: append.kind,
            created_at: now,
            summary: append.summary,
        };
        self.next_seq = tenant_seq;
        self.dedup.insert(key, tenant_seq);
        self.events.push_back(event.clone());
        Ok(event)
    }

    /// Drop events older than `retention`, advancing `pruned_through` (so a resume from at-or-
    /// before it is reported as a gap) and evicting each pruned event's dedup entry (so the index
    /// stays bounded). Durable source replays use the independent projection watermark.
    fn prune(&mut self, retention: Duration, now: DateTime<Utc>) -> Result<(), EventOutboxError> {
        loop {
            let Some(front) = self.events.front() else {
                break;
            };
            let retained_at = self
                .retention_started
                .get(&front.tenant_seq)
                .copied()
                .unwrap_or(front.created_at);
            let age = now
                .signed_duration_since(retained_at)
                .to_std()
                .map_err(|_| EventOutboxError::RetentionTimestampOverflow)?;
            if age < retention {
                break;
            }
            // `front()` just yielded `Some` under this same borrow, so the queue is non-empty.
            let Some(pruned) = self.events.pop_front() else {
                break;
            };
            self.pruned_through = self.pruned_through.max(pruned.tenant_seq);
            self.retention_started.remove(&pruned.tenant_seq);
            self.dedup.remove(&(
                pruned.aggregate.clone(),
                pruned.aggregate_revision,
                pruned.kind,
            ));
        }
        Ok(())
    }
}

/// Single-host, in-memory [`EventOutbox`]. Appends and reads are serialized by one lock, so an
/// event is visible to a reader exactly when — and only when — the append has committed, which is
/// the atomicity the transactional-outbox contract requires on this backend.
#[derive(Clone)]
pub struct MemoryEventOutbox {
    retention: Duration,
    state: Arc<Mutex<HashMap<TenantId, TenantOutbox>>>,
    webhook_state: Arc<Mutex<crate::webhooks::memory::WebhookMemoryState>>,
    notification_namespace: Arc<Mutex<notification_import::NotificationMemoryNamespace>>,
    notification_import_config: NotificationImportConfig,
}

impl MemoryEventOutbox {
    /// Build a store retaining events for `retention`, which must be at least
    /// [`MINIMUM_EVENT_RETENTION`].
    pub fn new(retention: Duration) -> Result<Self, EventOutboxError> {
        Ok(Self {
            retention: retention_floor(retention)?,
            state: Arc::new(Mutex::new(HashMap::new())),
            webhook_state: Arc::new(Mutex::new(Default::default())),
            notification_namespace: Arc::new(Mutex::new(Default::default())),
            notification_import_config: NotificationImportConfig::default(),
        })
    }

    pub(crate) fn webhook_state(&self) -> Arc<Mutex<crate::webhooks::memory::WebhookMemoryState>> {
        Arc::clone(&self.webhook_state)
    }
}

pub(crate) struct WebhookOutboxSource {
    pub tail: EventCursor,
    pub pruned_through: EventCursor,
    pub next_event: Option<OutboxEvent>,
}
pub(crate) struct WebhookOutboxSourceReader<'a> {
    tenant: &'a mut TenantOutbox,
    retention: Duration,
}

impl WebhookOutboxSourceReader<'_> {
    pub(crate) fn read(
        &mut self,
        after: Option<EventCursor>,
        now: DateTime<Utc>,
    ) -> Result<WebhookOutboxSource, EventOutboxError> {
        self.tenant.prune(self.retention, now)?;
        Ok(WebhookOutboxSource {
            tail: EventCursor::from_position(self.tenant.next_seq),
            pruned_through: EventCursor::from_position(self.tenant.pruned_through),
            next_event: after.and_then(|cursor| {
                self.tenant
                    .events
                    .iter()
                    .find(|event| event.tenant_seq > cursor.position())
                    .cloned()
            }),
        })
    }
}

impl MemoryEventOutbox {
    /// Keep source authority locked while the caller acquires webhook authority and samples its
    /// current cursor and clock. All callers use source -> webhook lock order.
    pub(crate) fn with_webhook_authority<R>(
        &self,
        tenant: &TenantId,
        f: impl FnOnce(&mut WebhookOutboxSourceReader<'_>) -> R,
    ) -> Result<R, EventOutboxError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| EventOutboxError::LockUnavailable)?;
        let mut source = WebhookOutboxSourceReader {
            tenant: state.entry(tenant.clone()).or_default(),
            retention: self.retention,
        };
        Ok(f(&mut source))
    }
}

impl Default for MemoryEventOutbox {
    fn default() -> Self {
        Self {
            retention: MINIMUM_EVENT_RETENTION,
            state: Arc::new(Mutex::new(HashMap::new())),
            webhook_state: Arc::new(Mutex::new(Default::default())),
            notification_namespace: Arc::new(Mutex::new(Default::default())),
            notification_import_config: NotificationImportConfig::default(),
        }
    }
}

#[async_trait]
impl EventOutbox for MemoryEventOutbox {
    async fn append_notification_commit(
        &self,
        commit: NotificationCommit,
        trusted_now: DateTime<Utc>,
    ) -> Result<NotificationAck, EventOutboxError> {
        self.import_notification(commit, trusted_now)
    }

    async fn append(
        &self,
        append: OutboxAppend,
        now: DateTime<Utc>,
    ) -> Result<OutboxEvent, EventOutboxError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| EventOutboxError::LockUnavailable)?;
        let tenant = state.entry(append.tenant_id.clone()).or_default();
        tenant.append(append, self.retention, now)
    }

    async fn append_projection(
        &self,
        projection: GatewayEventProjection,
        now: DateTime<Utc>,
    ) -> Result<(), EventOutboxError> {
        validated_projection(&projection)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| EventOutboxError::LockUnavailable)?;
        let tenant = state.entry(projection.tenant_id().clone()).or_default();
        let highwater = tenant
            .projection_watermarks
            .get(&(projection.source(), projection.session_id().clone()))
            .copied()
            .unwrap_or(0);
        if projection.sequence() <= highwater {
            return Ok(());
        }
        if projection.sequence() != highwater + 1 {
            return Err(EventOutboxError::ProjectionGap);
        }
        tenant.append(projection.append().clone(), self.retention, now)?;
        tenant.projection_watermarks.insert(
            (projection.source(), projection.session_id().clone()),
            projection.sequence(),
        );
        Ok(())
    }

    async fn read_from(
        &self,
        tenant_id: &TenantId,
        after: EventCursor,
        limit: usize,
        now: DateTime<Utc>,
    ) -> Result<OutboxPage, EventOutboxError> {
        let limit = validated_limit(limit)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| EventOutboxError::LockUnavailable)?;
        let Some(tenant) = state.get_mut(tenant_id) else {
            return Ok(OutboxPage {
                events: Vec::new(),
                next_cursor: after,
                cursor_expired: false,
            });
        };
        tenant.prune(self.retention, now)?;

        // The next event the consumer expects is `after + 1`. If retention has already dropped a
        // sequence at or before that position, the consumer has missed a transition: report a gap.
        let cursor_expired = tenant.pruned_through > after.position();

        let events: Vec<OutboxEvent> = tenant
            .events
            .iter()
            .filter(|event| event.tenant_seq > after.position())
            .take(limit)
            .cloned()
            .collect();
        let next_cursor = events
            .last()
            .map_or(after, |event| EventCursor(event.tenant_seq));
        Ok(OutboxPage {
            events,
            next_cursor,
            cursor_expired,
        })
    }

    async fn read_after_event_id(
        &self,
        tenant_id: &TenantId,
        after: Option<Uuid>,
        limit: usize,
        now: DateTime<Utc>,
    ) -> Result<OutboxPage, EventOutboxError> {
        let limit = validated_limit(limit)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| EventOutboxError::LockUnavailable)?;
        let Some(tenant) = state.get_mut(tenant_id) else {
            return Ok(OutboxPage {
                events: Vec::new(),
                next_cursor: EventCursor::start(),
                cursor_expired: false,
            });
        };
        tenant.prune(self.retention, now)?;

        // Resolve the opaque event id to an ordered position.
        let (after_seq, cursor_expired) = match after {
            // From the beginning: a gap only if retention already dropped the earliest events.
            None => (0, tenant.pruned_through > 0),
            Some(event_id) => match tenant
                .events
                .iter()
                .find(|event| event.event_id == event_id)
            {
                // The anchor is still retained: resume strictly after it, no gap.
                Some(event) => (event.tenant_seq, false),
                // Pruned or unknown: recover from the oldest retained event and report the gap.
                None => (0, true),
            },
        };

        let events: Vec<OutboxEvent> = tenant
            .events
            .iter()
            .filter(|event| event.tenant_seq > after_seq)
            .take(limit)
            .cloned()
            .collect();
        let next_cursor = events.last().map_or(EventCursor(after_seq), |event| {
            EventCursor(event.tenant_seq)
        });
        Ok(OutboxPage {
            events,
            next_cursor,
            cursor_expired,
        })
    }

    async fn mark_delivered(
        &self,
        tenant_id: &TenantId,
        cursor: EventCursor,
    ) -> Result<(), EventOutboxError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| EventOutboxError::LockUnavailable)?;
        let tenant = state.entry(tenant_id.clone()).or_default();
        if cursor.position() > tenant.next_seq {
            return Err(EventOutboxError::DeliveryCursorAhead);
        }
        tenant.delivered_through = tenant.delivered_through.max(cursor.position());
        Ok(())
    }

    async fn delivered_cursor(
        &self,
        tenant_id: &TenantId,
    ) -> Result<EventCursor, EventOutboxError> {
        let state = self
            .state
            .lock()
            .map_err(|_| EventOutboxError::LockUnavailable)?;
        Ok(state.get(tenant_id).map_or(EventCursor::start(), |tenant| {
            EventCursor(tenant.delivered_through)
        }))
    }
}

/// A synchronous facade over an async [`EventOutbox`], for callers on a blocking execution path
/// (the gateway records terminal transitions from inside `spawn_blocking`, where it cannot `await`).
///
/// It owns a dedicated multi-threaded Tokio runtime and drives each call to completion on it with
/// `block_on`. That runtime is never entered reentrantly — the outbox futures do not call back into
/// it — and the caller is always a blocking thread (a `spawn_blocking` worker or a plain thread),
/// so `block_on` neither panics nor deadlocks. Cloning shares the one runtime and outbox.
#[derive(Clone)]
pub struct EventOutboxBlockingClient {
    runtime: Arc<tokio::runtime::Runtime>,
    outbox: Arc<dyn EventOutbox>,
}

impl EventOutboxBlockingClient {
    /// Build a blocking client backed by `worker_threads` runtime threads (at least one).
    pub fn spawn(
        outbox: Arc<dyn EventOutbox>,
        worker_threads: usize,
    ) -> Result<Self, EventOutboxError> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(worker_threads.max(1))
            .enable_all()
            .build()
            .map_err(|_| EventOutboxError::ClientSpawn)?;
        Ok(Self {
            runtime: Arc::new(runtime),
            outbox,
        })
    }

    /// Blocking [`EventOutbox::append`].
    pub fn append(
        &self,
        append: OutboxAppend,
        now: DateTime<Utc>,
    ) -> Result<OutboxEvent, EventOutboxError> {
        self.runtime.block_on(self.outbox.append(append, now))
    }

    /// Blocking [`EventOutbox::append_projection`].
    pub fn append_projection(
        &self,
        projection: GatewayEventProjection,
        now: DateTime<Utc>,
    ) -> Result<(), EventOutboxError> {
        self.runtime
            .block_on(self.outbox.append_projection(projection, now))
    }

    /// Blocking [`EventOutbox::append_notification_commit`].
    pub fn append_notification_commit(
        &self,
        commit: NotificationCommit,
        trusted_now: DateTime<Utc>,
    ) -> Result<NotificationAck, EventOutboxError> {
        self.runtime
            .block_on(self.outbox.append_notification_commit(commit, trusted_now))
    }

    /// Blocking [`EventOutbox::read_from`].
    pub fn read_from(
        &self,
        tenant_id: &TenantId,
        after: EventCursor,
        limit: usize,
        now: DateTime<Utc>,
    ) -> Result<OutboxPage, EventOutboxError> {
        self.runtime
            .block_on(self.outbox.read_from(tenant_id, after, limit, now))
    }

    /// Blocking [`EventOutbox::read_after_event_id`].
    pub fn read_after_event_id(
        &self,
        tenant_id: &TenantId,
        after: Option<Uuid>,
        limit: usize,
        now: DateTime<Utc>,
    ) -> Result<OutboxPage, EventOutboxError> {
        self.runtime.block_on(
            self.outbox
                .read_after_event_id(tenant_id, after, limit, now),
        )
    }

    /// Blocking [`EventOutbox::mark_delivered`].
    pub fn mark_delivered(
        &self,
        tenant_id: &TenantId,
        cursor: EventCursor,
    ) -> Result<(), EventOutboxError> {
        self.runtime
            .block_on(self.outbox.mark_delivered(tenant_id, cursor))
    }

    /// Blocking [`EventOutbox::delivered_cursor`].
    pub fn delivered_cursor(&self, tenant_id: &TenantId) -> Result<EventCursor, EventOutboxError> {
        self.runtime
            .block_on(self.outbox.delivered_cursor(tenant_id))
    }
}
