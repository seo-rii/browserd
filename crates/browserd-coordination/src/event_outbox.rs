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
//! The idempotency index is pruned together with its event, so it stays bounded. That is safe
//! only because a re-drive is sourced by scanning *durable actions*, which are pruned on the same
//! retention floor ([`MINIMUM_EVENT_RETENTION`]) or longer: once an action is gone there is
//! nothing left to re-drive an append from, so every legitimate re-drive falls inside the window
//! where the dedup entry still exists. Callers must therefore keep the outbox retention at least
//! as long as the durable action retention.
//!
//! [`MemoryEventOutbox`] is the single-host backend used by tests and the in-memory deployment; a
//! Redis-backed store mirrors it for the multi-host deployment.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use browserd_core::{ActionId, SessionId, TenantId};
use chrono::{DateTime, Utc};
use thiserror::Error;
use uuid::Uuid;

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
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum OutboxAggregate {
    /// An action reached a terminal outcome within its session.
    Action {
        session_id: SessionId,
        action_id: ActionId,
    },
    /// A session was fenced as lost.
    Session { session_id: SessionId },
}

/// The class of terminal transition an event records. Kept intentionally narrow: the outbox
/// records only durable *terminal* transitions of the coordination authority, which a consumer
/// maps to the richer public event taxonomy when serving a resume request.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum OutboxEventKind {
    /// An action settled into a terminal state (succeeded, failed, or otherwise resolved).
    ActionTerminal,
    /// A session was fenced as lost, terminalizing its unresolved work.
    SessionLost,
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
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboxAppend {
    tenant_id: TenantId,
    aggregate: OutboxAggregate,
    aggregate_revision: u64,
    kind: OutboxEventKind,
}

impl OutboxAppend {
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
        }
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum EventOutboxError {
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
}

impl TenantOutbox {
    /// Drop events older than `retention`, advancing `pruned_through` (so a resume from at-or-
    /// before it is reported as a gap) and evicting each pruned event's dedup entry (so the index
    /// stays bounded). Evicting the dedup entry is safe under the retention-alignment invariant
    /// documented on the module: no re-drive can arrive for an aggregate whose durable record has
    /// already been pruned.
    fn prune(&mut self, retention: Duration, now: DateTime<Utc>) -> Result<(), EventOutboxError> {
        loop {
            let Some(front) = self.events.front() else {
                break;
            };
            let age = now
                .signed_duration_since(front.created_at)
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
pub struct MemoryEventOutbox {
    retention: Duration,
    state: Mutex<HashMap<TenantId, TenantOutbox>>,
}

impl MemoryEventOutbox {
    /// Build a store retaining events for `retention`, which must be at least
    /// [`MINIMUM_EVENT_RETENTION`].
    pub fn new(retention: Duration) -> Result<Self, EventOutboxError> {
        Ok(Self {
            retention: retention_floor(retention)?,
            state: Mutex::new(HashMap::new()),
        })
    }
}

impl Default for MemoryEventOutbox {
    fn default() -> Self {
        Self {
            retention: MINIMUM_EVENT_RETENTION,
            state: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl EventOutbox for MemoryEventOutbox {
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
        tenant.prune(self.retention, now)?;

        let key = (
            append.aggregate.clone(),
            append.aggregate_revision,
            append.kind,
        );
        if let Some(existing_seq) = tenant.dedup.get(&key).copied()
            && let Some(event) = tenant
                .events
                .iter()
                .find(|event| event.tenant_seq == existing_seq)
        {
            return Ok(event.clone());
        }

        let tenant_seq = tenant
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
        };
        tenant.next_seq = tenant_seq;
        tenant.dedup.insert(key, tenant_seq);
        tenant.events.push_back(event.clone());
        Ok(event)
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
