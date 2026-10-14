//! Fixed terminal horizons and bounded per-action reclamation. No runtime SCAN and no hash TTL.
use super::*;

// Keys 10/11/12 are respectively the per-session metadata hash, namespace inventory, and due
// index. All scores are zero; every u64 is compared as canonical decimal, never as a Lua double.
pub(super) const RETENTION_SCRIPT: &str = r#"
local function retention_decimal(value)
  return value and string.match(value, '^[0-9]+$') and (value == '0' or string.sub(value, 1, 1) ~= '0') and (#value < 20 or (#value == 20 and value <= '18446744073709551615'))
end
local function retention_member(deadline, member)
  return string.rep('0', 20 - #deadline) .. deadline .. '|' .. member
end
local function pending_member(action)
  local sequence = redis.call('HGET', KEYS[2], '@sequence:' .. action)
  if not retention_decimal(sequence) or sequence == '0' then return nil end
  return string.rep('0', 20 - #sequence) .. sequence .. '|' .. action
end
local function pending_lookup(action)
  local member = pending_member(action)
  local score = member and redis.call('ZSCORE', KEYS[4], member) or false
  if score and score ~= '0' then error('invalid pending index score') end
  return score
end
local function pending_range(limit)
  local members = redis.call('ZRANGE', KEYS[4], 0, limit - 1)
  local actions = {}
  for _, member in ipairs(members) do
    local action = string.sub(member, 22)
    if pending_member(action) ~= member or redis.call('ZSCORE', KEYS[4], member) ~= '0' then return nil end
    table.insert(actions, action)
  end
  return actions
end
local function retention_valid()
  for index = 10, 12 do
    local kind = redis.call('TYPE', KEYS[index])['ok']
    local expected = index == 10 and 'hash' or 'zset'
    if kind ~= 'none' and (kind ~= expected or redis.call('PTTL', KEYS[index]) ~= -1) then return false end
  end
  local global = tonumber(redis.call('HGET', KEYS[7], 'retained_global'))
  local session = tonumber(redis.call('HGET', KEYS[7], 'retained_session'))
  return global and session and global >= 1 and global <= 1048576 and session >= 1 and session <= 65536 and session <= global and redis.call('ZCARD', KEYS[11]) <= global and redis.call('HLEN', KEYS[10]) <= session
end
local function retention_read(action, member)
  local metadata = redis.call('HGET', KEYS[10], action)
  if not metadata or redis.call('ZSCORE', KEYS[11], member) ~= '0' then return nil end
  local deadline, sequence = string.match(metadata, '^([0-9]+)|([0-9]+)$')
  if not retention_decimal(deadline) or not retention_decimal(sequence) then return nil end
  if deadline == '0' and sequence ~= '0' then return nil end
  if deadline ~= '0' and redis.call('ZSCORE', KEYS[12], retention_member(deadline, member)) ~= '0' then return nil end
  return metadata, deadline, sequence
end
local function retention_prepare(action, member, horizon)
  local old, deadline = retention_read(action, member)
  if not old then return nil end
  local next_deadline = recovery_now() + tonumber(horizon)
  if next_deadline <= 0 or next_deadline > 9007199254740991 then return nil end
  local next_value = string.format('%.0f', next_deadline)
  if #deadline > #next_value or (#deadline == #next_value and deadline > next_value) then next_value = deadline end
  return next_value, deadline
end
local function retention_write(action, member, deadline, old_deadline, sequence)
  if old_deadline ~= '0' then redis.call('ZREM', KEYS[12], retention_member(old_deadline, member)) end
  redis.call('HSET', KEYS[10], action, deadline .. '|' .. sequence)
  redis.call('ZADD', KEYS[12], 0, retention_member(deadline, member))
end
"#;

const RECLAIM: &str = r#"
if not recovery_valid() or not custody_valid() or not retention_valid() then return {'invalid'} end
local present = redis.call('ZSCORE', KEYS[12], ARGV[1])
if not present then return {'deferred'} end
if redis.call('TYPE', KEYS[1])['ok'] ~= 'hash' or redis.call('PTTL', KEYS[1]) ~= -1 then return {'invalid'} end
if redis.call('TYPE', KEYS[2])['ok'] ~= 'hash' or redis.call('PTTL', KEYS[2]) ~= -1 or redis.call('TYPE', KEYS[3])['ok'] ~= 'hash' or redis.call('PTTL', KEYS[3]) ~= -1 then return {'invalid'} end
local metadata, deadline, sequence = retention_read(ARGV[2], ARGV[3])
if not metadata or metadata ~= ARGV[4] or ARGV[1] ~= retention_member(deadline, ARGV[3]) then return {'invalid'} end
local current = redis.call('HGET', KEYS[2], ARGV[2])
if not current then return {'invalid'} end
if current ~= ARGV[5] then return {'deferred'} end
if redis.call('HGET', KEYS[1], 'placement') ~= ARGV[6] or redis.call('HGET', KEYS[2], '@sequence:' .. ARGV[2]) ~= ARGV[7] or redis.call('HGET', KEYS[2], '@idempotency:' .. ARGV[2]) ~= ARGV[8] or redis.call('HGET', KEYS[3], ARGV[8]) ~= ARGV[2] then return {'invalid'} end
if (sequence == '0' and ARGV[9] ~= 'worker_notifications') or tonumber(deadline) > recovery_now() then return {'deferred'} end
local ack = redis.call('HGET', KEYS[1], 'event_ack_sequence') or '0'
if not retention_decimal(ack) then return {'invalid'} end
local highwater = redis.call('HGET', KEYS[1], 'event_sequence') or '0'
if not retention_decimal(highwater) or #ack > #highwater or (#ack == #highwater and ack > highwater) then return {'invalid'} end
local event_kind = redis.call('TYPE', KEYS[5])['ok']
if event_kind ~= 'none' and (event_kind ~= 'zset' or redis.call('PTTL', KEYS[5]) ~= -1) then return {'invalid'} end
local head = redis.call('ZRANGEBYLEX', KEYS[5], '[0', '+', 'LIMIT', 0, 1)
if #head == 0 then
  if ack ~= highwater then return {'invalid'} end
else
  local expected = event_increment(ack)
  if not expected or string.sub(head[1], 1, 21) ~= string.rep('0', 20 - #expected) .. expected .. '|' then return {'invalid'} end
end
if #ack < #sequence or (#ack == #sequence and ack < sequence) then return {'deferred'} end
if pending_lookup(ARGV[2]) or redis.call('ZSCORE', KEYS[6], ARGV[3]) or redis.call('ZSCORE', KEYS[8], ARGV[3]) or redis.call('ZSCORE', KEYS[9], ARGV[2]) or redis.call('HGET', KEYS[1], '@dispatch:' .. ARGV[2]) then return {'deferred'} end
for _, field in ipairs({'active_mutation', 'unresolved_mutation', 'active_dispatch'}) do
  if redis.call('HGET', KEYS[1], field) == ARGV[2] then return {'deferred'} end
end
redis.call('HDEL', KEYS[2], ARGV[2], '@sequence:' .. ARGV[2], '@idempotency:' .. ARGV[2])
redis.call('HDEL', KEYS[3], ARGV[8])
redis.call('HDEL', KEYS[10], ARGV[2])
redis.call('ZREM', KEYS[11], ARGV[3])
redis.call('ZREM', KEYS[12], ARGV[1])
return {'reclaimed'}
"#;

impl RedisGatewayActionStore {
    pub(super) fn retained_index_key(&self) -> String {
        format!("{}:gateway-action:retained-v3", self.config.key_prefix)
    }

    pub(super) fn retention_index_key(&self) -> String {
        format!("{}:gateway-action:retention-v3", self.config.key_prefix)
    }

    pub(super) fn apply_retention_metadata(
        snapshot: &mut GatewayActionSnapshot,
        metadata: &str,
    ) -> Result<(), GatewayActionCoordinationError> {
        let (deadline, sequence) = metadata
            .split_once('|')
            .ok_or(GatewayActionCoordinationError::InvalidRedisResponse)?;
        let deadline: u64 = deadline
            .parse()
            .map_err(|_| GatewayActionCoordinationError::InvalidRedisResponse)?;
        let sequence: u64 = sequence
            .parse()
            .map_err(|_| GatewayActionCoordinationError::InvalidRedisResponse)?;
        if metadata != format!("{deadline}|{sequence}")
            || (deadline == 0 && sequence != 0)
            || snapshot.terminal().is_some() != (deadline != 0)
            || sequence > MAX_EVENT_SEQUENCE
        {
            return Err(GatewayActionCoordinationError::InvalidRedisResponse);
        }
        snapshot.last_source_event_sequence = (sequence != 0).then_some(sequence);
        if deadline != 0 {
            snapshot.retain_until = i64::try_from(deadline)
                .ok()
                .and_then(DateTime::from_timestamp_millis)
                .ok_or(GatewayActionCoordinationError::InvalidRedisResponse)?;
        }
        Ok(())
    }

    pub(super) async fn maintain_retention(
        &self,
        cursor: GatewayActionRetentionCursor,
        limit: usize,
    ) -> Result<GatewayActionRetentionPage, GatewayActionCoordinationError> {
        cursor.validate()?;
        if !(1..=MAX_RECOVERY_SCAN_LIMIT).contains(&limit) {
            return Err(GatewayActionCoordinationError::InvalidRetentionScanLimit);
        }
        let Ok(_running) = Arc::clone(&self.retention_permit).try_acquire_owned() else {
            return GatewayActionRetentionPage::new(cursor, false, 0, 0, 0);
        };
        // A timeout returns no advanced cursor. The bounded atomic Redis transaction may have
        // committed, and its exact retry is safe; the next pass rechecks every source obligation.
        timeout(
            self.config.command_timeout,
            self.maintain_retention_inner(cursor, limit),
        )
        .await
        .map_err(|_| GatewayActionCoordinationError::RedisTimedOut)?
    }

    async fn maintain_retention_inner(
        &self,
        cursor: GatewayActionRetentionCursor,
        limit: usize,
    ) -> Result<GatewayActionRetentionPage, GatewayActionCoordinationError> {
        if !(1..=MAX_RECOVERY_SCAN_LIMIT).contains(&limit) {
            return Err(GatewayActionCoordinationError::InvalidRetentionScanLimit);
        }
        let after = cursor.after.as_ref().map_or_else(
            || "-".to_owned(),
            |(deadline, tenant, session, action)| {
                format!(
                    "({deadline:020}|{}",
                    Self::recovery_member(tenant, session, action)
                )
            },
        );
        let index = self.retention_index_key();
        let format = self.recovery_format_key();
        let members: Vec<String> = self.execute(move |mut connection| async move {
            Script::new(r#"
if redis.call('TYPE', KEYS[2])['ok'] ~= 'hash' or redis.call('PTTL', KEYS[2]) ~= -1 or redis.call('HGET', KEYS[2], 'version') ~= '5' or redis.call('HGET', KEYS[2], 'state') ~= 'ready' then return {'invalid'} end
local kind = redis.call('TYPE', KEYS[1])['ok']
if kind ~= 'none' and (kind ~= 'zset' or redis.call('PTTL', KEYS[1]) ~= -1) then return {'invalid'} end
local clock = redis.call('TIME')
local now = string.format('%020.0f', tonumber(clock[1]) * 1000 + math.floor(tonumber(clock[2]) / 1000))
return redis.call('ZRANGEBYLEX', KEYS[1], ARGV[1], '[' .. now .. '|~', 'LIMIT', 0, ARGV[2])
"#).key(index).key(format).arg(after).arg(limit).invoke_async(&mut connection).await
        }).await?;
        if members.len() > limit {
            return Err(GatewayActionCoordinationError::InvalidRedisResponse);
        }
        let complete = members.len() < limit;
        let examined = members.len();
        let mut reclaimed = 0;
        let mut next = GatewayActionRetentionCursor::default();
        for member in members {
            let (deadline, scope) = member
                .split_once('|')
                .ok_or(GatewayActionCoordinationError::InvalidRedisResponse)?;
            let deadline: u64 = deadline
                .parse()
                .map_err(|_| GatewayActionCoordinationError::InvalidRedisResponse)?;
            let (tenant, session, action) = Self::parse_recovery_member(scope)?;
            if member != format!("{deadline:020}|{scope}") {
                return Err(GatewayActionCoordinationError::InvalidRedisResponse);
            }
            next = GatewayActionRetentionCursor::after(
                deadline,
                tenant.clone(),
                session.clone(),
                action.clone(),
            );
            let Some(row) = self.read_action(&tenant, &session, &action).await? else {
                let index = self.retention_index_key();
                let present: Option<f64> = self
                    .execute(move |mut connection| async move {
                        redis::cmd("ZSCORE")
                            .arg(index)
                            .arg(member)
                            .query_async(&mut connection)
                            .await
                    })
                    .await?;
                if present.is_some() {
                    return Err(GatewayActionCoordinationError::InvalidRedisResponse);
                }
                continue;
            };
            if row.snapshot.terminal().is_none()
                || row.snapshot.pending_custody().is_some()
                || row.snapshot.requires_terminal_custody_catchup()
            {
                continue;
            }
            let sequence = match row.snapshot.last_source_event_sequence {
                Some(sequence) => sequence,
                None if row.snapshot.worker_owns_notifications() => 0,
                None => continue,
            };
            // A newer resolution can move the deadline between page discovery and this read.
            if row.snapshot.retain_until.timestamp_millis() != i64::try_from(deadline).unwrap_or(-1)
            {
                continue;
            }
            let keys = self.keys(&tenant, &session);
            let metadata = format!("{deadline}|{sequence}");
            let placement = Self::serialize_placement(row.snapshot.placement())?;
            let action_sequence = row.snapshot.action_sequence().get().to_string();
            let idempotency = row.snapshot.idempotency_key().to_owned();
            let notification_owner = if row.snapshot.worker_owns_notifications() {
                "worker_notifications"
            } else {
                "legacy"
            };
            let scope = scope.to_owned();
            let result: Vec<String> = self
                .execute(move |mut connection| async move {
                    Script::new(&format!(
                        "{RECOVERY_SCRIPT}{CUSTODY_SCRIPT}{RETENTION_SCRIPT}{EVENT_JOURNAL_SCRIPT}{RECLAIM}"
                    ))
                    .key(keys.session)
                    .key(keys.actions)
                    .key(keys.idempotency)
                    .key(keys.pending)
                    .key(keys.events)
                    .key(keys.recovery)
                    .key(keys.format)
                    .key(keys.custody)
                    .key(keys.session_custody)
                    .key(keys.retention)
                    .key(keys.retained)
                    .key(keys.retention_due)
                    .arg(member)
                    .arg(action.to_string())
                    .arg(scope)
                    .arg(metadata)
                    .arg(row.raw)
                    .arg(placement)
                    .arg(action_sequence)
                    .arg(idempotency)
                    .arg(notification_owner)
                    .invoke_async(&mut connection)
                    .await
                })
                .await?;
            match result.as_slice() {
                [value] if value == "reclaimed" => reclaimed += 1,
                [value] if value == "deferred" => {}
                _ => return Err(GatewayActionCoordinationError::InvalidRedisResponse),
            }
        }
        GatewayActionRetentionPage::new(
            if complete {
                GatewayActionRetentionCursor::default()
            } else {
                next
            },
            complete,
            examined,
            reclaimed,
            examined - reclaimed,
        )
    }
}

// Runs only after the v2 cursor completed. Cursor and every row/index write commit together;
// replay preserves a previously assigned horizon rather than extending it after interruption.
pub(super) const MIGRATE_RETENTION_STEP: &str = r#"
local function kind(key) return redis.call('TYPE', key)['ok'] end
if kind(KEYS[7]) ~= 'hash' or redis.call('PTTL', KEYS[7]) ~= -1 or redis.call('HGET', KEYS[7], 'version') ~= '5' or redis.call('HGET', KEYS[7], 'state') ~= 'migrating' then return {'6'} end
if redis.call('HGET', KEYS[7], 'cursor') ~= ARGV[1] then return {'2'} end
if not retention_valid() then return {'6'} end
for _, index in ipairs({4, 6, 8, 9, 13}) do
  if kind(KEYS[index]) ~= 'none' and (kind(KEYS[index]) ~= 'zset' or redis.call('PTTL', KEYS[index]) ~= -1) then return {'6'} end
end
local count = tonumber(ARGV[5])
if not count or count < 0 or count > 64 or #ARGV ~= 7 + count * 9 then return {'6'} end
local session_step = ARGV[4] == 'pin' or ARGV[4] == 'finish'
if session_step then
  if kind(KEYS[1]) ~= 'hash' or redis.call('PTTL', KEYS[1]) ~= -1 then return {'6'} end
  if kind(KEYS[2]) ~= 'none' and (kind(KEYS[2]) ~= 'hash' or redis.call('PTTL', KEYS[2]) ~= -1) then return {'6'} end
  if kind(KEYS[3]) ~= 'none' and (kind(KEYS[3]) ~= 'hash' or redis.call('PTTL', KEYS[3]) ~= -1) then return {'6'} end
  for _, field in ipairs({'active_mutation', 'unresolved_mutation', 'active_dispatch'}) do
    local action = redis.call('HGET', KEYS[1], field)
    if action and not redis.call('HGET', KEYS[2], action) then return {'6'} end
  end
  if (redis.call('ZCARD', KEYS[4]) > 0 or redis.call('ZCARD', KEYS[9]) > 0 or redis.call('ZCARD', KEYS[13]) > 0) and kind(KEYS[2]) == 'none' then return {'6'} end
  if tostring(redis.call('HLEN', KEYS[2])) ~= ARGV[6] or tostring(redis.call('HLEN', KEYS[3])) ~= ARGV[7] or tonumber(ARGV[6]) ~= tonumber(ARGV[7]) * 3 then return {'6'} end
end
local global_limit = tonumber(redis.call('HGET', KEYS[7], 'retained_global'))
local session_limit = tonumber(redis.call('HGET', KEYS[7], 'retained_session'))
if session_step and tonumber(ARGV[7]) > session_limit then return {'15'} end
local horizon = recovery_now() + tonumber(ARGV[3])
if horizon <= 0 or horizon > 9007199254740991 then return {'6'} end
local deadline = string.format('%.0f', horizon)
local event_sequence = session_step and (redis.call('HGET', KEYS[1], 'event_sequence') or '0') or '0'
if not retention_decimal(event_sequence) or #event_sequence > 19 or (#event_sequence == 19 and event_sequence > '9223372036854775807') then return {'6'} end
local added, added_pending = 0, 0
local metadata_rows = {}
for index = 0, count - 1 do
  local offset = 8 + index * 9
  local action, raw, sequence, idempotency, member = ARGV[offset], ARGV[offset + 1], ARGV[offset + 3], ARGV[offset + 4], ARGV[offset + 5]
  if redis.call('HGET', KEYS[2], action) ~= raw or redis.call('HGET', KEYS[2], '@sequence:' .. action) ~= sequence then return {'2'} end
  if redis.call('HGET', KEYS[2], '@idempotency:' .. action) ~= idempotency or redis.call('HGET', KEYS[3], idempotency) ~= action then return {'6'} end
  if not retention_decimal(sequence) or sequence == '0' then return {'6'} end
  local pending = ARGV[offset + 6] == '1'
  local custody = ARGV[offset + 8] == '1'
  local indexed_custody = redis.call('ZSCORE', KEYS[9], action)
  local global_custody = redis.call('ZSCORE', KEYS[8], member)
  if custody ~= (indexed_custody ~= false) or custody ~= (global_custody ~= false) then return {'6'} end
  if pending ~= (redis.call('ZSCORE', KEYS[6], member) ~= false) then return {'6'} end
  local metadata = redis.call('HGET', KEYS[10], action)
  local indexed = redis.call('ZSCORE', KEYS[11], member)
  if (metadata and not indexed) or (indexed and not metadata) then return {'6'} end
  if metadata then
    local value, old_deadline, old_sequence = retention_read(action, member)
    if not value or pending ~= (old_deadline == '0') then return {'6'} end
    metadata_rows[index + 1] = {old_deadline, old_sequence}
  else
    added = added + 1
    metadata_rows[index + 1] = {pending and '0' or deadline, pending and '0' or event_sequence}
  end
  if pending and not pending_lookup(action) then added_pending = added_pending + 1 end
end
if redis.call('ZCARD', KEYS[11]) + added > global_limit or (session_step and redis.call('HLEN', KEYS[10]) + added > session_limit) then return {'15'} end
if session_step and redis.call('ZCARD', KEYS[4]) + added_pending + redis.call('ZCARD', KEYS[9]) > 256 then return {'9'} end
if ARGV[4] == 'finish' and redis.call('HLEN', KEYS[10]) + added ~= tonumber(ARGV[7]) then return {'6'} end
for index = 0, count - 1 do
  local offset = 8 + index * 9
  local action, member = ARGV[offset], ARGV[offset + 5]
  local metadata = metadata_rows[index + 1]
  redis.call('HSET', KEYS[10], action, metadata[1] .. '|' .. metadata[2])
  redis.call('ZADD', KEYS[11], 0, member)
  if metadata[1] ~= '0' then redis.call('ZADD', KEYS[12], 0, retention_member(metadata[1], member)) end
  if ARGV[offset + 6] == '1' then redis.call('ZADD', KEYS[4], 0, pending_member(action)) end
end
if ARGV[4] == 'finish' then redis.call('DEL', KEYS[13]) end
if ARGV[4] == 'ready' and tostring(redis.call('ZCARD', KEYS[11])) ~= redis.call('HGET', KEYS[7], 'retention_backfilled') then return {'6'} end
redis.call('HSET', KEYS[7], 'cursor', ARGV[2])
redis.call('HINCRBY', KEYS[7], 'retention_backfilled', added)
if ARGV[4] == 'discovered' then redis.call('HDEL', KEYS[7], 'discovered') end
if ARGV[4] == 'ready' then
  redis.call('HSET', KEYS[7], 'state', 'ready')
end
return {'1', redis.call('HGET', KEYS[7], 'retention_backfilled')}
"#;
