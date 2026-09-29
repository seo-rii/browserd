//! Redis-backed [`EventOutbox`] for the multi-host deployment (BRD-017).
//!
//! Mirrors the semantics of the in-memory backend against a shared Redis, so a consumer resumes
//! exactly and detects a gap across gateway restarts and across hosts. Each tenant's stream lives
//! under one hash-tagged namespace so all of its keys co-locate on a cluster:
//!
//! * `…:meta`  — hash of `next_seq`, `delivered_through`, `pruned_through`.
//! * `…:events` — hash mapping each `seq` to its serialized event, plus reverse indexes prefixed
//!   `@dedup:` (dedup key → seq), `@dk:` (seq → dedup key), `@byid:` (event id → seq) and `@eid:`
//!   (seq → event id) so the idempotency, id-anchored resume and prune paths stay O(1) per entry.
//! * `…:index`  — sorted set scored by `seq`, for ordered range reads.
//! * `…:bytime` — sorted set scored by `created_at` millis, for age-based pruning.
//!
//! Append, read and delivery each run as a single Lua script so the multi-key update is atomic
//! against concurrent gateways. Retention is enforced two ways: active age pruning (matching the
//! memory backend, so an active tenant's stream stays bounded) and a whole-namespace TTL extended
//! on each append (so an idle tenant's keys are reclaimed).

use std::fmt;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use browserd_core::TenantId;
use chrono::{DateTime, Utc};
use redis::Script;
use redis::aio::ConnectionManager;
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;
use tokio::time::timeout;
use uuid::{Uuid, Version};

use super::{
    EventCursor, EventOutbox, EventOutboxError, MAX_EVENT_PAGE_LIMIT, OutboxAggregate,
    OutboxAppend, OutboxEvent, OutboxEventKind, OutboxPage,
};
use crate::StoreConfig;

/// Largest value Lua's number type (an f64) represents exactly. Sequences and millisecond
/// timestamps stay well within it, so the store uses ordinary Lua arithmetic rather than the
/// string-based u64 math the action store needs for its full-range sequences.
const MAX_SAFE_REDIS_INTEGER: u64 = 9_007_199_254_740_991;

/// Shared prune preamble: drop every event whose `created_at` is at or before the retention cutoff,
/// clean its indexes, and advance `pruned_through`. `now`/`retention` come from ARGV as noted per
/// script.
const PRUNE_FRAGMENT: &str = r#"
local function prune(meta, events, index, bytime, now, retention)
  local cutoff = now - retention
  local stale = redis.call('ZRANGEBYSCORE', bytime, '-inf', cutoff)
  if #stale == 0 then return end
  local max_pruned = 0
  for _, seq in ipairs(stale) do
    local numeric = tonumber(seq)
    if numeric and numeric > max_pruned then max_pruned = numeric end
    local dedup_key = redis.call('HGET', events, '@dk:' .. seq)
    if dedup_key then
      redis.call('HDEL', events, '@dedup:' .. dedup_key)
    end
    local event_id = redis.call('HGET', events, '@eid:' .. seq)
    if event_id then
      redis.call('HDEL', events, '@byid:' .. event_id)
    end
    redis.call('HDEL', events, seq, '@dk:' .. seq, '@eid:' .. seq)
    redis.call('ZREM', index, seq)
    redis.call('ZREM', bytime, seq)
  end
  local pruned_through = tonumber(redis.call('HGET', meta, 'pruned_through') or '0')
  if max_pruned > pruned_through then
    redis.call('HSET', meta, 'pruned_through', max_pruned)
  end
end
"#;

/// Append one terminal transition, idempotent on the dedup key.
///
/// KEYS: meta, events, index, bytime.
/// ARGV: dedup_key, event_id, event_json, created_at_millis, retention_millis, now_millis, max_seq.
/// Returns `{'1', json, seq}` on a fresh append, `{'2', json, seq}` on an idempotent hit,
/// `{'5'}` on sequence overflow, `{'6'}` on corrupt state.
fn append_script() -> String {
    format!(
        "{PRUNE_FRAGMENT}{}",
        r#"
prune(KEYS[1], KEYS[2], KEYS[3], KEYS[4], tonumber(ARGV[6]), tonumber(ARGV[5]))
local existing = redis.call('HGET', KEYS[2], '@dedup:' .. ARGV[1])
if existing then
  local json = redis.call('HGET', KEYS[2], existing)
  if not json then return {'6'} end
  return {'2', json, existing}
end
local next_seq = tonumber(redis.call('HGET', KEYS[1], 'next_seq') or '0') + 1
if next_seq > tonumber(ARGV[7]) then return {'5'} end
redis.call('HSET', KEYS[1], 'next_seq', next_seq)
local seq = tostring(next_seq)
redis.call('HSET', KEYS[2], seq, ARGV[3], '@dedup:' .. ARGV[1], seq, '@dk:' .. seq, ARGV[1], '@byid:' .. ARGV[2], seq, '@eid:' .. seq, ARGV[2])
redis.call('ZADD', KEYS[3], next_seq, seq)
redis.call('ZADD', KEYS[4], tonumber(ARGV[4]), seq)
local ttl = tonumber(ARGV[5])
redis.call('PEXPIRE', KEYS[1], ttl)
redis.call('PEXPIRE', KEYS[2], ttl)
redis.call('PEXPIRE', KEYS[3], ttl)
redis.call('PEXPIRE', KEYS[4], ttl)
return {'1', ARGV[3], seq}
"#
    )
}

/// Read a page after an anchor, pruning first.
///
/// KEYS: meta, events, index, bytime.
/// ARGV: mode ('seq'|'id'), anchor, limit, retention_millis, now_millis.
/// Returns `{'1', cursor_expired, next_cursor, json1, seq1, …}` or `{'6'}` on corrupt state.
fn read_script() -> String {
    format!(
        "{PRUNE_FRAGMENT}{}",
        r#"
prune(KEYS[1], KEYS[2], KEYS[3], KEYS[4], tonumber(ARGV[5]), tonumber(ARGV[4]))
local pruned_through = tonumber(redis.call('HGET', KEYS[1], 'pruned_through') or '0')
local after_seq = 0
local cursor_expired = 0
if ARGV[1] == 'seq' then
  after_seq = tonumber(ARGV[2])
  if not after_seq then return {'6'} end
  if pruned_through > after_seq then cursor_expired = 1 end
elseif ARGV[1] == 'id' then
  local seq = redis.call('HGET', KEYS[2], '@byid:' .. ARGV[2])
  if seq then
    after_seq = tonumber(seq)
  else
    after_seq = 0
    cursor_expired = 1
  end
else
  return {'6'}
end
local seqs = redis.call('ZRANGEBYSCORE', KEYS[3], '(' .. after_seq, '+inf', 'LIMIT', 0, tonumber(ARGV[3]))
local response = {'1', tostring(cursor_expired), tostring(after_seq)}
local last = after_seq
for _, seq in ipairs(seqs) do
  local json = redis.call('HGET', KEYS[2], seq)
  if not json then return {'6'} end
  table.insert(response, json)
  table.insert(response, seq)
  last = tonumber(seq)
end
response[3] = tostring(last)
return response
"#
    )
}

/// Advance the delivered watermark.
///
/// KEYS: meta. ARGV: cursor, retention_millis.
/// Returns `{'1'}` on success, `{'2'}` when the cursor runs ahead of the recorded stream.
const MARK_DELIVERED_SCRIPT: &str = r#"
local next_seq = tonumber(redis.call('HGET', KEYS[1], 'next_seq') or '0')
local cursor = tonumber(ARGV[1])
if not cursor then return {'2'} end
if cursor > next_seq then return {'2'} end
local delivered = tonumber(redis.call('HGET', KEYS[1], 'delivered_through') or '0')
if cursor > delivered then
  redis.call('HSET', KEYS[1], 'delivered_through', cursor)
  redis.call('PEXPIRE', KEYS[1], tonumber(ARGV[2]))
end
return {'1'}
"#;

/// Connection settings for a [`RedisEventOutbox`].
#[derive(Clone)]
pub struct RedisEventOutboxConfig {
    endpoint: String,
    key_prefix: String,
    store: StoreConfig,
    max_in_flight: usize,
    command_timeout: Duration,
}

impl RedisEventOutboxConfig {
    /// Build a validated configuration. `store.retention()` is the event retention floor (at least
    /// 24 hours, matching the durable action retention so the idempotency window stays aligned).
    pub fn new(
        endpoint: impl Into<String>,
        key_prefix: impl Into<String>,
        store: StoreConfig,
        max_in_flight: usize,
        command_timeout: Duration,
    ) -> Result<Self, EventOutboxError> {
        let endpoint = endpoint.into();
        let key_prefix = key_prefix.into();
        if endpoint.is_empty()
            || endpoint.trim() != endpoint
            || endpoint.chars().any(char::is_control)
            || key_prefix.is_empty()
            || key_prefix.len() > 128
            || !key_prefix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-_:".contains(&byte))
            || max_in_flight == 0
            || max_in_flight > 1024
            || command_timeout.is_zero()
            || command_timeout > Duration::from_secs(30)
            || store.retention().as_millis() > u128::from(MAX_SAFE_REDIS_INTEGER)
        {
            return Err(EventOutboxError::InvalidRedisConfig);
        }
        Ok(Self {
            endpoint,
            key_prefix,
            store,
            max_in_flight,
            command_timeout,
        })
    }
}

impl fmt::Debug for RedisEventOutboxConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedisEventOutboxConfig")
            .field("endpoint", &"[REDACTED]")
            .field("key_prefix", &self.key_prefix)
            .field("store", &self.store)
            .field("max_in_flight", &self.max_in_flight)
            .field("command_timeout", &self.command_timeout)
            .finish()
    }
}

/// Redis-backed durable event outbox.
#[derive(Clone)]
pub struct RedisEventOutbox {
    connection: ConnectionManager,
    config: RedisEventOutboxConfig,
    permits: Arc<Semaphore>,
}

struct OutboxKeys {
    meta: String,
    events: String,
    index: String,
    bytime: String,
}

/// The persisted form of an event. The ordered sequence is *not* stored here — it is the hash
/// field name / sorted-set score — so it is reattached on read, exactly as the action store
/// reattaches its sequence.
#[derive(Serialize, Deserialize)]
struct PersistedOutboxEvent {
    event_id: Uuid,
    tenant_id: TenantId,
    aggregate: OutboxAggregate,
    aggregate_revision: u64,
    kind: OutboxEventKind,
    created_at: DateTime<Utc>,
}

impl PersistedOutboxEvent {
    fn from_append(append: &OutboxAppend, event_id: Uuid, now: DateTime<Utc>) -> Self {
        Self {
            event_id,
            tenant_id: append.tenant_id.clone(),
            aggregate: append.aggregate.clone(),
            aggregate_revision: append.aggregate_revision,
            kind: append.kind,
            created_at: now,
        }
    }

    fn into_event(self, tenant_seq: u64) -> OutboxEvent {
        OutboxEvent {
            event_id: self.event_id,
            tenant_id: self.tenant_id,
            tenant_seq,
            aggregate: self.aggregate,
            aggregate_revision: self.aggregate_revision,
            kind: self.kind,
            created_at: self.created_at,
        }
    }
}

impl RedisEventOutbox {
    /// Connect to Redis and prepare the store.
    pub async fn connect(config: RedisEventOutboxConfig) -> Result<Self, EventOutboxError> {
        let client = redis::Client::open(config.endpoint.as_str())
            .map_err(|_| EventOutboxError::RedisUnavailable)?;
        let connection = timeout(config.command_timeout, client.get_connection_manager())
            .await
            .map_err(|_| EventOutboxError::RedisTimedOut)?
            .map_err(|_| EventOutboxError::RedisUnavailable)?;
        Ok(Self {
            connection,
            permits: Arc::new(Semaphore::new(config.max_in_flight)),
            config,
        })
    }

    async fn execute<T, F, Fut>(&self, operation: F) -> Result<T, EventOutboxError>
    where
        F: FnOnce(ConnectionManager) -> Fut,
        Fut: Future<Output = redis::RedisResult<T>>,
    {
        let permit = timeout(
            self.config.command_timeout,
            Arc::clone(&self.permits).acquire_owned(),
        )
        .await
        .map_err(|_| EventOutboxError::RedisTimedOut)?
        .map_err(|_| EventOutboxError::RedisUnavailable)?;
        let connection = self.connection.clone();
        let result = timeout(self.config.command_timeout, operation(connection))
            .await
            .map_err(|_| EventOutboxError::RedisTimedOut)?
            .map_err(|_| EventOutboxError::RedisUnavailable);
        drop(permit);
        result
    }

    fn keys(&self, tenant_id: &TenantId) -> OutboxKeys {
        let namespace = format!("{}:event-outbox:{{{tenant_id}}}", self.config.key_prefix);
        OutboxKeys {
            meta: format!("{namespace}:meta"),
            events: format!("{namespace}:events"),
            index: format!("{namespace}:index"),
            bytime: format!("{namespace}:bytime"),
        }
    }

    fn dedup_key(aggregate: &OutboxAggregate, revision: u64, kind: OutboxEventKind) -> String {
        let aggregate = match aggregate {
            OutboxAggregate::Action {
                session_id,
                action_id,
            } => format!("A:{session_id}:{action_id}"),
            OutboxAggregate::Session { session_id } => format!("S:{session_id}"),
        };
        let kind = match kind {
            OutboxEventKind::ActionTerminal => "t",
            OutboxEventKind::SessionLost => "l",
        };
        format!("{aggregate}:{revision}:{kind}")
    }

    fn retention_millis(&self) -> Result<u64, EventOutboxError> {
        u64::try_from(self.config.store.retention().as_millis())
            .map_err(|_| EventOutboxError::RetentionTimestampOverflow)
    }

    fn epoch_millis(now: DateTime<Utc>) -> Result<u64, EventOutboxError> {
        u64::try_from(now.timestamp_millis())
            .map_err(|_| EventOutboxError::RetentionTimestampOverflow)
    }

    fn decode_seq(raw: &str) -> Result<u64, EventOutboxError> {
        if raw.is_empty()
            || (raw.len() > 1 && raw.starts_with('0'))
            || !raw.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(EventOutboxError::InvalidRedisResponse);
        }
        raw.parse::<u64>()
            .map_err(|_| EventOutboxError::InvalidRedisResponse)
    }

    fn decode_event(raw: &str, seq: u64) -> Result<OutboxEvent, EventOutboxError> {
        let persisted = serde_json::from_str::<PersistedOutboxEvent>(raw)
            .map_err(|_| EventOutboxError::InvalidRedisResponse)?;
        if persisted.event_id.get_version() != Some(Version::SortRand) {
            return Err(EventOutboxError::InvalidRedisResponse);
        }
        Ok(persisted.into_event(seq))
    }

    fn decode_page(
        response: Vec<String>,
        default_cursor: u64,
    ) -> Result<OutboxPage, EventOutboxError> {
        let mut fields = response.into_iter();
        match fields.next().as_deref() {
            Some("1") => {}
            _ => return Err(EventOutboxError::InvalidRedisResponse),
        }
        let cursor_expired = match fields.next().as_deref() {
            Some("1") => true,
            Some("0") => false,
            _ => return Err(EventOutboxError::InvalidRedisResponse),
        };
        let next_cursor = match fields.next() {
            Some(raw) => Self::decode_seq(&raw)?,
            None => default_cursor,
        };
        let mut events = Vec::new();
        while let Some(json) = fields.next() {
            let seq = fields
                .next()
                .ok_or(EventOutboxError::InvalidRedisResponse)?;
            let seq = Self::decode_seq(&seq)?;
            events.push(Self::decode_event(&json, seq)?);
        }
        Ok(OutboxPage {
            events,
            next_cursor: EventCursor::from_position(next_cursor),
            cursor_expired,
        })
    }

    async fn read_with_anchor(
        &self,
        tenant_id: &TenantId,
        mode: &str,
        anchor: String,
        default_cursor: u64,
        limit: usize,
        now: DateTime<Utc>,
    ) -> Result<OutboxPage, EventOutboxError> {
        if !(1..=MAX_EVENT_PAGE_LIMIT).contains(&limit) {
            return Err(EventOutboxError::InvalidPageLimit);
        }
        let keys = self.keys(tenant_id);
        let retention = self.retention_millis()?;
        let now_millis = Self::epoch_millis(now)?;
        let mode = mode.to_owned();
        let response: Vec<String> = self
            .execute(move |mut connection| async move {
                Script::new(&read_script())
                    .key(keys.meta)
                    .key(keys.events)
                    .key(keys.index)
                    .key(keys.bytime)
                    .arg(mode)
                    .arg(anchor)
                    .arg(limit)
                    .arg(retention)
                    .arg(now_millis)
                    .invoke_async(&mut connection)
                    .await
            })
            .await?;
        Self::decode_page(response, default_cursor)
    }
}

#[async_trait]
impl EventOutbox for RedisEventOutbox {
    async fn append(
        &self,
        append: OutboxAppend,
        now: DateTime<Utc>,
    ) -> Result<OutboxEvent, EventOutboxError> {
        let keys = self.keys(&append.tenant_id);
        let dedup_key = Self::dedup_key(&append.aggregate, append.aggregate_revision, append.kind);
        let event_id = Uuid::now_v7();
        let persisted = PersistedOutboxEvent::from_append(&append, event_id, now);
        let event_json = serde_json::to_string(&persisted)
            .map_err(|_| EventOutboxError::InvalidRedisResponse)?;
        let created_at = Self::epoch_millis(now)?;
        let retention = self.retention_millis()?;
        let now_millis = created_at;
        let response: Vec<String> = self
            .execute(move |mut connection| async move {
                Script::new(&append_script())
                    .key(keys.meta)
                    .key(keys.events)
                    .key(keys.index)
                    .key(keys.bytime)
                    .arg(dedup_key)
                    .arg(event_id.to_string())
                    .arg(event_json)
                    .arg(created_at)
                    .arg(retention)
                    .arg(now_millis)
                    .arg(MAX_SAFE_REDIS_INTEGER)
                    .invoke_async(&mut connection)
                    .await
            })
            .await?;
        let mut fields = response.into_iter();
        match fields.next().as_deref() {
            Some("1" | "2") => {}
            Some("5") => return Err(EventOutboxError::SequenceOverflow),
            _ => return Err(EventOutboxError::InvalidRedisResponse),
        }
        let json = fields
            .next()
            .ok_or(EventOutboxError::InvalidRedisResponse)?;
        let seq = fields
            .next()
            .ok_or(EventOutboxError::InvalidRedisResponse)?;
        Self::decode_event(&json, Self::decode_seq(&seq)?)
    }

    async fn read_from(
        &self,
        tenant_id: &TenantId,
        after: EventCursor,
        limit: usize,
        now: DateTime<Utc>,
    ) -> Result<OutboxPage, EventOutboxError> {
        self.read_with_anchor(
            tenant_id,
            "seq",
            after.position().to_string(),
            after.position(),
            limit,
            now,
        )
        .await
    }

    async fn read_after_event_id(
        &self,
        tenant_id: &TenantId,
        after: Option<Uuid>,
        limit: usize,
        now: DateTime<Utc>,
    ) -> Result<OutboxPage, EventOutboxError> {
        match after {
            None => {
                self.read_with_anchor(tenant_id, "seq", "0".to_owned(), 0, limit, now)
                    .await
            }
            Some(event_id) => {
                self.read_with_anchor(tenant_id, "id", event_id.to_string(), 0, limit, now)
                    .await
            }
        }
    }

    async fn mark_delivered(
        &self,
        tenant_id: &TenantId,
        cursor: EventCursor,
    ) -> Result<(), EventOutboxError> {
        let keys = self.keys(tenant_id);
        let retention = self.retention_millis()?;
        let cursor = cursor.position();
        let response: Vec<String> = self
            .execute(move |mut connection| async move {
                Script::new(MARK_DELIVERED_SCRIPT)
                    .key(keys.meta)
                    .arg(cursor)
                    .arg(retention)
                    .invoke_async(&mut connection)
                    .await
            })
            .await?;
        match response.first().map(String::as_str) {
            Some("1") => Ok(()),
            Some("2") => Err(EventOutboxError::DeliveryCursorAhead),
            _ => Err(EventOutboxError::InvalidRedisResponse),
        }
    }

    async fn delivered_cursor(
        &self,
        tenant_id: &TenantId,
    ) -> Result<EventCursor, EventOutboxError> {
        let keys = self.keys(tenant_id);
        let raw: Option<String> = self
            .execute(move |mut connection| async move {
                redis::cmd("HGET")
                    .arg(keys.meta)
                    .arg("delivered_through")
                    .query_async(&mut connection)
                    .await
            })
            .await?;
        match raw {
            None => Ok(EventCursor::start()),
            Some(value) => Ok(EventCursor::from_position(Self::decode_seq(&value)?)),
        }
    }
}
