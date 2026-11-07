//! Bounded recovery discovery and explicit, resumable offline format migration.
//! Global index updates intentionally require standalone Redis, not Redis Cluster.
use std::collections::VecDeque;

use super::retention::MIGRATE_RETENTION_STEP;
use super::*;

pub(super) const RECOVERY_SCRIPT: &str = r#"
local function recovery_valid()
  if redis.call('TYPE', KEYS[7])['ok'] ~= 'hash' or redis.call('PTTL', KEYS[7]) ~= -1 then return false end
  if redis.call('HGET', KEYS[7], 'version') ~= '5' or redis.call('HGET', KEYS[7], 'state') ~= 'ready' then return false end
  local kind = redis.call('TYPE', KEYS[6])['ok']
  return kind == 'none' or (kind == 'zset' and redis.call('PTTL', KEYS[6]) == -1)
end
local function recovery_now()
  local clock = redis.call('TIME')
  local now = tonumber(clock[1]) * 1000 + math.floor(tonumber(clock[2]) / 1000)
  local floor = tonumber(redis.call('HGET', KEYS[7], 'clock_floor') or '0')
  if not floor or floor < 0 or floor > 9007199254740991 then return nil end
  now = math.max(now, floor)
  redis.call('HSET', KEYS[7], 'clock_floor', string.format('%.0f', now))
  return now
end
"#;

const MAX_MIGRATION_KEYS: usize = 256;
const MAX_MIGRATION_FIELDS: usize = 64;
const MAX_MIGRATION_BYTES: usize = 8 * 1024 * 1024;

const INITIALIZE: &str = r#"
local kind = redis.call('TYPE', KEYS[1])['ok']
if kind == 'none' then
  local version = ARGV[1] == 'ready' and '5' or '2'
  redis.call('HSET', KEYS[1], 'version', version, 'state', ARGV[1], 'cursor', ARGV[2], 'migrated', '0', 'retention_backfilled', '0', 'retained_global', ARGV[3], 'retained_session', ARGV[4])
elseif kind ~= 'hash' then return {'invalid'} end
if redis.call('PTTL', KEYS[1]) ~= -1 then return {'invalid'} end
local version = redis.call('HGET', KEYS[1], 'version')
local state = redis.call('HGET', KEYS[1], 'state')
if version ~= '2' and version ~= '3' and version ~= '4' and version ~= '5' then return {'invalid'} end
if (version == '2' or version == '3' or version == '4') and ARGV[1] == 'ready' then return {(state == 'migrating' or state == 'validating') and 'in_progress' or 'required'} end
if version == '2' and state == 'ready' then
  -- A second complete session walk is essential: an interrupted v2 cursor may have already
  -- passed some sessions. Preserve its journal separately and rebuild every retained record.
  redis.call('HSET', KEYS[1], 'legacy_cursor', redis.call('HGET', KEYS[1], 'cursor') or '', 'version', '5', 'state', 'migrating', 'cursor', ARGV[2], 'retention_backfilled', '0', 'retained_global', ARGV[3], 'retained_session', ARGV[4])
  redis.call('HDEL', KEYS[1], 'discovered')
  version, state = '5', 'migrating'
end
if version == '3' or version == '4' then
  if state == 'ready' then
    local kind = redis.call('TYPE', KEYS[2])['ok']
    if kind ~= 'none' and (kind ~= 'zset' or redis.call('PTTL', KEYS[2]) ~= -1) then return {'invalid'} end
    redis.call('HSET', KEYS[1], 'version', '5', 'state', 'validating', 'legacy_cursor', redis.call('HGET', KEYS[1], 'cursor') or '', 'cursor', '', 'catalog_total', tostring(redis.call('ZCARD', KEYS[2])), 'catalog_validated', '0')
    version, state = '5', 'validating'
  elseif state == 'migrating' or state == 'validating' then
    -- Preserve an interrupted v3 inventory/backfill cursor and its assigned horizons.
    redis.call('HSET', KEYS[1], 'version', '5')
    version = '5'
  else return {'invalid'} end
end
if version == '5' then
  local global, session = redis.call('HGET', KEYS[1], 'retained_global'), redis.call('HGET', KEYS[1], 'retained_session')
  if global ~= ARGV[3] or session ~= ARGV[4] then
    if (state ~= 'migrating' and state ~= 'validating') or ARGV[1] ~= 'migrating' or not tonumber(global) or not tonumber(session) or tonumber(ARGV[3]) < tonumber(global) or tonumber(ARGV[4]) < tonumber(session) then return {'limits'} end
    redis.call('HSET', KEYS[1], 'retained_global', ARGV[3], 'retained_session', ARGV[4])
  end
end
return {state or '', redis.call('HGET', KEYS[1], 'cursor') or '', redis.call('HGET', KEYS[1], 'migrated') or '', version, redis.call('HGET', KEYS[1], 'retention_backfilled') or '0'}
"#;

// The cached page is part of the migration journal: interruption after discovery cannot lose
// its inventory or leave any discovered payload subject to expiry before the next CLI call.
const DISCOVER: &str = r#"
local function kind(key) return redis.call('TYPE', key)['ok'] end
if kind(KEYS[1]) ~= 'hash' or redis.call('HGET', KEYS[1], 'state') ~= 'migrating' or redis.call('HGET', KEYS[1], 'cursor') ~= ARGV[1] then return {'changed'} end
local cached = redis.call('HGET', KEYS[1], 'discovered')
if cached then return cjson.decode(cached) end
local scanned = redis.call('SCAN', ARGV[2], 'MATCH', ARGV[3], 'COUNT', 128)
if #scanned[2] > 256 then return {'invalid'} end
local response = {scanned[1]}
local payload_keys = {}
for _, session in ipairs(scanned[2]) do
  if kind(session) ~= 'hash' or redis.call('PTTL', session) ~= -1 then return {'invalid'} end
  local namespace = string.sub(session, 1, #session - 8)
  local actions, idempotency, pending = namespace .. ':actions', namespace .. ':idempotency', namespace .. ':pending'
  if kind(actions) ~= 'none' and kind(actions) ~= 'hash' then return {'invalid'} end
  if kind(idempotency) ~= 'none' and kind(idempotency) ~= 'hash' then return {'invalid'} end
  if kind(pending) ~= 'none' and kind(pending) ~= 'zset' then return {'invalid'} end
  if redis.call('EXISTS', actions) ~= redis.call('EXISTS', idempotency) then return {'invalid'} end
  if kind(actions) == 'none' and kind(pending) ~= 'none' then return {'invalid'} end
  local action_fields, identity_fields = redis.call('HLEN', actions), redis.call('HLEN', idempotency)
  table.insert(response, session)
  table.insert(response, tostring(action_fields))
  table.insert(response, tostring(identity_fields))
  table.insert(payload_keys, actions)
  table.insert(payload_keys, idempotency)
  table.insert(payload_keys, pending)
  local v3_pending = namespace .. ':pending-v3'
  if kind(v3_pending) ~= 'none' and kind(v3_pending) ~= 'zset' then return {'invalid'} end
  table.insert(payload_keys, v3_pending)
end
for _, key in ipairs(payload_keys) do redis.call('PERSIST', key) end
redis.call('HSET', KEYS[1], 'discovered', cjson.encode(response))
return response
"#;

const MIGRATE_STEP: &str = r#"
local function kind(key) return redis.call('TYPE', key)['ok'] end
if kind(KEYS[7]) ~= 'hash' or redis.call('PTTL', KEYS[7]) ~= -1 or redis.call('HGET', KEYS[7], 'version') ~= '2' or redis.call('HGET', KEYS[7], 'state') ~= 'migrating' then return {'6'} end
if redis.call('HGET', KEYS[7], 'cursor') ~= ARGV[1] then return {'2'} end
if kind(KEYS[6]) ~= 'none' and (kind(KEYS[6]) ~= 'zset' or redis.call('PTTL', KEYS[6]) ~= -1) then return {'6'} end
local migrated = tonumber(redis.call('HGET', KEYS[7], 'migrated'))
if not migrated or migrated < 0 or migrated > 65536 then return {'6'} end
local count = tonumber(ARGV[5])
if not count or count < 0 or count > 64 or #ARGV ~= 7 + count * 9 then return {'6'} end
local session_step = ARGV[4] == 'pin' or ARGV[4] == 'finish'
if session_step then
  if kind(KEYS[1]) ~= 'hash' or redis.call('PTTL', KEYS[1]) ~= -1 then return {'6'} end
  if kind(KEYS[2]) ~= 'none' and kind(KEYS[2]) ~= 'hash' then return {'6'} end
  if kind(KEYS[3]) ~= 'none' and kind(KEYS[3]) ~= 'hash' then return {'6'} end
  if redis.call('EXISTS', KEYS[2]) ~= redis.call('EXISTS', KEYS[3]) then return {'6'} end
  if tostring(redis.call('HLEN', KEYS[2])) ~= ARGV[6] or tostring(redis.call('HLEN', KEYS[3])) ~= ARGV[7] then return {'6'} end
  if kind(KEYS[4]) ~= 'none' and kind(KEYS[4]) ~= 'zset' then return {'6'} end
  local held = redis.call('HGET', KEYS[1], 'active_mutation') or redis.call('HGET', KEYS[1], 'unresolved_mutation')
  if held and kind(KEYS[2]) == 'none' then return {'6'} end
end
local added_session, added_global = 0, 0
local active_dispatch, active_sequence = nil, nil
if session_step then
  active_dispatch = redis.call('HGET', KEYS[1], 'active_dispatch')
  if active_dispatch then
    active_sequence = redis.call('HGET', KEYS[2], '@sequence:' .. active_dispatch)
    if not active_sequence or not string.match(active_sequence, '^[1-9][0-9]*$') or #active_sequence > 20 or (#active_sequence == 20 and active_sequence > '18446744073709551615') then return {'6'} end
  end
end
for index = 0, count - 1 do
  local offset = 8 + index * 9
  local action = ARGV[offset]
  if redis.call('HGET', KEYS[2], action) ~= ARGV[offset + 1] or redis.call('HGET', KEYS[2], '@sequence:' .. action) ~= ARGV[offset + 3] then return {'2'} end
  if redis.call('HGET', KEYS[2], '@idempotency:' .. action) ~= ARGV[offset + 4] or redis.call('HGET', KEYS[3], ARGV[offset + 4]) ~= action then return {'6'} end
  if ARGV[offset + 6] == '1' then
    if not redis.call('ZSCORE', KEYS[4], action) then added_session = added_session + 1 end
    if not redis.call('ZSCORE', KEYS[6], ARGV[offset + 5]) then added_global = added_global + 1 end
    if ARGV[offset + 7] == '1' then
      local sequence = ARGV[offset + 3]
      if not active_sequence or #sequence < #active_sequence or (#sequence == #active_sequence and sequence < active_sequence) then active_dispatch, active_sequence = action, sequence end
    end
  end
end
if (session_step and redis.call('ZCARD', KEYS[4]) + added_session > 256) or redis.call('ZCARD', KEYS[6]) + added_global > 65536 then return {'9'} end
for index = 0, count - 1 do
  local offset = 8 + index * 9
  local action = ARGV[offset]
  redis.call('HSET', KEYS[2], action, ARGV[offset + 2])
  if ARGV[offset + 6] == '1' then
    redis.call('ZADD', KEYS[4], ARGV[offset + 3], action)
    redis.call('ZADD', KEYS[6], 0, ARGV[offset + 5])
    if ARGV[offset + 7] == '1' then
      redis.call('HSET', KEYS[1], '@dispatch:' .. action, '1')
    end
  else
    redis.call('ZREM', KEYS[4], action)
    redis.call('ZREM', KEYS[6], ARGV[offset + 5])
  end
end
if session_step then
  if active_dispatch then redis.call('HSET', KEYS[1], 'active_dispatch', active_dispatch) end
  local held = redis.call('ZCARD', KEYS[4]) > 0 or redis.call('HGET', KEYS[1], 'loss_id') or redis.call('HGET', KEYS[1], 'active_mutation') or redis.call('HGET', KEYS[1], 'unresolved_mutation') or redis.call('HGET', KEYS[1], 'active_dispatch')
  for index = 2, 4 do
    redis.call('PERSIST', KEYS[index])
  end
end
redis.call('HSET', KEYS[7], 'cursor', ARGV[2])
if ARGV[4] == 'discovered' then redis.call('HDEL', KEYS[7], 'discovered') end
redis.call('HINCRBY', KEYS[7], 'migrated', added_global)
if ARGV[4] == 'ready' then redis.call('HSET', KEYS[7], 'state', 'ready') end
return {'1', redis.call('HGET', KEYS[7], 'migrated')}
"#;

#[derive(Clone, Debug)]
pub struct RedisGatewayActionMigrationProgress {
    complete: bool,
    migrated_actions: u64,
    retention_backfilled_actions: u64,
}

impl RedisGatewayActionMigrationProgress {
    pub(super) const fn from_catalog(
        complete: bool,
        migrated_actions: u64,
        retention_backfilled_actions: u64,
    ) -> Self {
        Self {
            complete,
            migrated_actions,
            retention_backfilled_actions,
        }
    }

    #[must_use]
    pub const fn complete(&self) -> bool {
        self.complete
    }
    #[must_use]
    pub const fn retention_backfilled_actions(&self) -> u64 {
        self.retention_backfilled_actions
    }

    /// Number of pending actions added to the permanent recovery index.
    #[must_use]
    pub const fn migrated_actions(&self) -> u64 {
        self.migrated_actions
    }
}

#[derive(Default, Serialize, Deserialize)]
struct MigrationCursor {
    scan_cursor: u64,
    scan_started: bool,
    sessions: VecDeque<MigrationSession>,
    current: Option<MigrationSession>,
}

#[derive(Serialize, Deserialize)]
struct MigrationSession {
    tenant: TenantId,
    session: SessionId,
    fields_cursor: u64,
    started: bool,
    action_fields: usize,
    identity_fields: usize,
}

impl RedisGatewayActionStore {
    pub(super) fn recovery_index_key(&self) -> String {
        format!(
            "{}:gateway-action:recovery-v2:pending",
            self.config.key_prefix
        )
    }

    pub(super) fn recovery_format_key(&self) -> String {
        format!("{}:gateway-action:recovery-format", self.config.key_prefix)
    }

    pub(super) fn recovery_member(
        tenant: &TenantId,
        session: &SessionId,
        action: &ActionId,
    ) -> String {
        format!("{tenant}|{session}|{action}")
    }

    pub(super) fn parse_recovery_member(
        member: &str,
    ) -> Result<(TenantId, SessionId, ActionId), GatewayActionCoordinationError> {
        let mut fields = member.split('|');
        let tenant = fields
            .next()
            .and_then(|value| value.parse().ok())
            .ok_or(GatewayActionCoordinationError::InvalidRedisResponse)?;
        let session = fields
            .next()
            .and_then(|value| value.parse().ok())
            .ok_or(GatewayActionCoordinationError::InvalidRedisResponse)?;
        let action = fields
            .next()
            .and_then(|value| value.parse().ok())
            .ok_or(GatewayActionCoordinationError::InvalidRedisResponse)?;
        if fields.next().is_some() || Self::recovery_member(&tenant, &session, &action) != member {
            return Err(GatewayActionCoordinationError::InvalidRedisResponse);
        }
        Ok((tenant, session, action))
    }

    fn parse_session_key(
        &self,
        key: &str,
    ) -> Result<(TenantId, SessionId), GatewayActionCoordinationError> {
        let scope = key
            .strip_prefix(&format!("{}:gateway-action:{{", self.config.key_prefix))
            .and_then(|value| value.strip_suffix("}:session"))
            .ok_or(GatewayActionCoordinationError::InvalidRedisResponse)?;
        let (tenant, session) = scope
            .split_once(':')
            .ok_or(GatewayActionCoordinationError::InvalidRedisResponse)?;
        let tenant = tenant
            .parse()
            .map_err(|_| GatewayActionCoordinationError::InvalidRedisResponse)?;
        let session = session
            .parse()
            .map_err(|_| GatewayActionCoordinationError::InvalidRedisResponse)?;
        if self.keys(&tenant, &session).session != key {
            return Err(GatewayActionCoordinationError::InvalidRedisResponse);
        }
        Ok((tenant, session))
    }

    pub(super) async fn ensure_recovery_format(
        &self,
    ) -> Result<(), GatewayActionCoordinationError> {
        let format_key = self.recovery_format_key();
        let state: Option<String> = self
            .execute(move |mut connection| async move {
                redis::cmd("HGET")
                    .arg(format_key)
                    .arg("state")
                    .query_async(&mut connection)
                    .await
            })
            .await?;
        if state.is_none() {
            // Only brand-new namespaces initialize automatically. Old data is never silently
            // ignored or declared undelivered; its explicit offline migration must finish first.
            let pattern = format!("{}:gateway-action:*", self.config.key_prefix);
            timeout(self.config.command_timeout, async {
                let mut cursor = 0_u64;
                loop {
                    let pattern = pattern.clone();
                    let (next, keys): (u64, Vec<String>) = self
                        .execute(move |mut connection| async move {
                            redis::cmd("SCAN")
                                .arg(cursor)
                                .arg("MATCH")
                                .arg(pattern)
                                .arg("COUNT")
                                .arg(128_u16)
                                .query_async(&mut connection)
                                .await
                        })
                        .await?;
                    if !keys.is_empty() {
                        let format_key = self.recovery_format_key();
                        let state: Option<String> = self
                            .execute(move |mut connection| async move {
                                redis::cmd("HGET")
                                    .arg(format_key)
                                    .arg("state")
                                    .query_async(&mut connection)
                                    .await
                            })
                            .await?;
                        return match state.as_deref() {
                            Some("ready") => Ok(()),
                            Some("migrating" | "validating") => {
                                Err(GatewayActionCoordinationError::RecoveryMigrationInProgress)
                            }
                            _ => Err(GatewayActionCoordinationError::RecoveryMigrationRequired),
                        };
                    }
                    cursor = next;
                    if cursor == 0 {
                        return Ok(());
                    }
                }
            })
            .await
            .map_err(|_| GatewayActionCoordinationError::RedisTimedOut)??;
        }
        let status = self.initialize_recovery("ready").await?;
        match status.0.as_str() {
            "ready" => Ok(()),
            "migrating" | "validating" => {
                Err(GatewayActionCoordinationError::RecoveryMigrationInProgress)
            }
            _ => Err(GatewayActionCoordinationError::InvalidRedisResponse),
        }
    }

    async fn initialize_recovery(
        &self,
        state: &str,
    ) -> Result<(String, String, u64, u8, u64), GatewayActionCoordinationError> {
        let key = self.recovery_format_key();
        let state = state.to_owned();
        let cursor = serde_json::to_string(&MigrationCursor::default())
            .map_err(|_| GatewayActionCoordinationError::InvalidRedisResponse)?;
        let limits = self.config.retention_limits;
        let retained_index = self.retained_index_key();
        let response: Vec<String> = self
            .execute(move |mut connection| async move {
                Script::new(INITIALIZE)
                    .key(key)
                    .key(retained_index)
                    .arg(state)
                    .arg(cursor)
                    .arg(limits.namespace_records())
                    .arg(limits.session_records())
                    .invoke_async(&mut connection)
                    .await
            })
            .await?;
        match response.as_slice() {
            [state, cursor, count, version, retained] => Ok((
                state.clone(),
                cursor.clone(),
                count
                    .parse()
                    .map_err(|_| GatewayActionCoordinationError::InvalidRedisResponse)?,
                version
                    .parse()
                    .map_err(|_| GatewayActionCoordinationError::InvalidRedisResponse)?,
                retained
                    .parse()
                    .map_err(|_| GatewayActionCoordinationError::InvalidRedisResponse)?,
            )),
            [code] if code == "required" => {
                Err(GatewayActionCoordinationError::RecoveryMigrationRequired)
            }
            [code] if code == "in_progress" => {
                Err(GatewayActionCoordinationError::RecoveryMigrationInProgress)
            }
            [code] if code == "limits" => {
                Err(GatewayActionCoordinationError::InvalidRetentionLimits)
            }
            _ => Err(GatewayActionCoordinationError::InvalidRedisResponse),
        }
    }

    pub(super) async fn scan_recovery(
        &self,
        cursor: GatewayActionRecoveryCursor,
        limit: usize,
    ) -> Result<GatewayActionRecoveryPage, GatewayActionCoordinationError> {
        if !(1..=MAX_RECOVERY_SCAN_LIMIT).contains(&limit) {
            return Err(GatewayActionCoordinationError::InvalidRecoveryScanLimit);
        }
        let lower = cursor.after.as_ref().map_or_else(
            || "-".to_owned(),
            |(tenant, session, action)| {
                format!("({}", Self::recovery_member(tenant, session, action))
            },
        );
        let index = self.recovery_index_key();
        let marker = self.recovery_format_key();
        let members: Vec<String> = self.execute(move |mut connection| async move {
            Script::new(&format!("{RECOVERY_SCRIPT}\nif not recovery_valid() then return {{'invalid'}} end\nreturn redis.call('ZRANGEBYLEX', KEYS[6], ARGV[1], '+', 'LIMIT', 0, ARGV[2])"))
                .key(&index).key(&index).key(&index).key(&index).key(&index).key(&index).key(marker)
                .arg(lower).arg(limit).invoke_async(&mut connection).await
        }).await?;
        if members.len() > limit {
            return Err(GatewayActionCoordinationError::InvalidRedisResponse);
        }
        let complete = members.len() < limit;
        let mut after = None;
        let mut actions = Vec::with_capacity(members.len());
        for member in members {
            let (tenant, session, action) = Self::parse_recovery_member(&member)?;
            after = Some((tenant.clone(), session.clone(), action.clone()));
            // Terminalization can remove a member between this bounded index read and the row
            // read. A surviving terminal row is skipped; an absent indexed row is corruption.
            let Some(row) = self.read_action(&tenant, &session, &action).await? else {
                let index = self.recovery_index_key();
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
            if row.snapshot.terminal().is_none() {
                actions.push(row.snapshot);
            }
        }
        Ok(GatewayActionRecoveryPage {
            actions,
            next_cursor: GatewayActionRecoveryCursor {
                after: if complete { None } else { after },
            },
            complete,
        })
    }

    /// Performs one bounded, restartable migration step. The caller must first stop every old
    /// gateway writer. This is an offline data operation: runtime startup remains closed until
    /// the final cursor is committed. Repeating a completed migration is harmless.
    ///
    /// Redis SCAN/HSCAN COUNT is a hint. Each returned page is also checked against explicit
    /// count/byte caps and rejected without advancing the durable cursor when oversized.
    pub async fn migrate_recovery_format(
        config: RedisGatewayActionConfig,
        old_gateway_writers_stopped: bool,
        now: DateTime<Utc>,
    ) -> Result<RedisGatewayActionMigrationProgress, GatewayActionCoordinationError> {
        if !old_gateway_writers_stopped {
            return Err(GatewayActionCoordinationError::OfflineMigrationConfirmationRequired);
        }
        let store = Self::connect_unchecked(config).await?;
        timeout(
            store.config.command_timeout,
            store.migrate_recovery_step(now),
        )
        .await
        .map_err(|_| GatewayActionCoordinationError::RedisTimedOut)?
    }

    async fn migrate_recovery_step(
        &self,
        now: DateTime<Utc>,
    ) -> Result<RedisGatewayActionMigrationProgress, GatewayActionCoordinationError> {
        let (state, old_cursor, migrated, version, retained) =
            self.initialize_recovery("migrating").await?;
        if state == "ready" {
            return Ok(RedisGatewayActionMigrationProgress {
                complete: true,
                migrated_actions: migrated,
                retention_backfilled_actions: retained,
            });
        }
        if state == "validating" {
            return self
                .validate_retained_catalog_step(old_cursor, migrated, retained)
                .await;
        }
        if state != "migrating" {
            return Err(GatewayActionCoordinationError::InvalidRedisResponse);
        }
        let mut cursor: MigrationCursor = serde_json::from_str(&old_cursor)
            .map_err(|_| GatewayActionCoordinationError::InvalidRedisResponse)?;
        if cursor.sessions.len() > MAX_MIGRATION_KEYS {
            return Err(GatewayActionCoordinationError::InvalidRedisResponse);
        }
        let mut rows = Vec::new();
        let mut mode = "none";
        let mut expected_fields = (0, 0);
        let mut keys = RedisActionKeys {
            session: self.recovery_format_key(),
            actions: self.recovery_format_key(),
            idempotency: self.recovery_format_key(),
            pending: self.recovery_index_key(),
            events: self.recovery_format_key(),
            recovery: self.recovery_index_key(),
            format: self.recovery_format_key(),
            custody: self.custody_index_key(),
            // Discovery has no session keys; the exact session builder replaces this before
            // any pin/materialization step. The legacy migration script does not use custody.
            session_custody: self.custody_index_key(),
            retention: format!("{}:migration-empty-retention", self.recovery_format_key()),
            retained: self.retained_index_key(),
            retention_due: self.retention_index_key(),
        };
        if let Some(current) = cursor.current.as_mut() {
            keys = self.keys(&current.tenant, &current.session);
            if version == 2 {
                keys.pending = keys.pending.trim_end_matches("-v3").to_owned();
            }
            expected_fields = (current.action_fields, current.identity_fields);
            if !current.started {
                // Commit a separate pinning step before reading any action values.
                current.started = true;
                mode = "pin";
            } else {
                let action_key = keys.actions.clone();
                let scan = current.fields_cursor;
                let (next, fields): (u64, Vec<(String, String)>) = self
                    .execute(move |mut connection| async move {
                        redis::cmd("HSCAN")
                            .arg(action_key)
                            .arg(scan)
                            .arg("COUNT")
                            .arg(8_u8)
                            .query_async(&mut connection)
                            .await
                    })
                    .await?;
                if fields.len() > MAX_MIGRATION_FIELDS
                    || fields
                        .iter()
                        .map(|(key, value)| key.len().saturating_add(value.len()))
                        .sum::<usize>()
                        > MAX_MIGRATION_BYTES
                {
                    return Err(GatewayActionCoordinationError::InvalidRedisResponse);
                }
                let session_key = keys.session.clone();
                let placement_raw: String = self
                    .execute(move |mut connection| async move {
                        redis::cmd("HGET")
                            .arg(session_key)
                            .arg("placement")
                            .query_async(&mut connection)
                            .await
                    })
                    .await?;
                let authoritative_placement = Self::decode_placement(&placement_raw)?;
                for (field, raw) in fields {
                    if field.starts_with('@') {
                        continue;
                    }
                    let action: ActionId = field
                        .parse()
                        .map_err(|_| GatewayActionCoordinationError::InvalidRedisResponse)?;
                    let action_key = keys.actions.clone();
                    let sequence_field = format!("@sequence:{action}");
                    let sequence: String = self
                        .execute(move |mut connection| async move {
                            redis::cmd("HGET")
                                .arg(action_key)
                                .arg(sequence_field)
                                .query_async(&mut connection)
                                .await
                        })
                        .await?;
                    let mut snapshot = Self::decode_snapshot(&raw, &sequence)?;
                    Self::validate_scope(&snapshot, &current.tenant, &current.session, &action)?;
                    if snapshot.placement() != &authoritative_placement {
                        return Err(GatewayActionCoordinationError::InvalidRedisResponse);
                    }
                    let pending = snapshot.terminal().is_none();
                    let armed = pending
                        && !matches!(snapshot.delivery(), ActionDeliveryEvidence::NotAttempted);
                    let sealing =
                        version == 2 && pending && !armed && snapshot.submission_lease().is_none();
                    if sealing {
                        let expiry = now
                            .checked_sub_signed(chrono::Duration::milliseconds(1))
                            .ok_or(GatewayActionCoordinationError::InvalidSubmissionLease)?;
                        snapshot.submission_lease = Some(GatewayActionSubmissionLease::new(
                            Uuid::now_v7(),
                            1,
                            expiry,
                            expiry,
                        )?);
                        snapshot.revision = snapshot
                            .revision
                            .checked_add(1)
                            .ok_or(GatewayActionCoordinationError::RevisionOverflow)?;
                        snapshot.updated_at = now.max(snapshot.updated_at);
                    }
                    let candidate = if sealing {
                        Self::serialize_snapshot(&snapshot)?
                    } else {
                        raw.clone()
                    };
                    rows.extend([
                        field,
                        raw,
                        candidate,
                        sequence,
                        snapshot.idempotency_key().to_owned(),
                        Self::recovery_member(&current.tenant, &current.session, &action),
                        if pending { "1" } else { "0" }.to_owned(),
                        if armed { "1" } else { "0" }.to_owned(),
                        if snapshot.pending_custody().is_some() {
                            "1"
                        } else {
                            "0"
                        }
                        .to_owned(),
                    ]);
                }
                current.fields_cursor = next;
                mode = if next == 0 { "finish" } else { "pin" };
                if next == 0 {
                    cursor.current = None;
                }
            }
        } else if let Some(session) = cursor.sessions.pop_front() {
            cursor.current = Some(session);
        } else if !cursor.scan_started || cursor.scan_cursor != 0 {
            let scan = cursor.scan_cursor;
            let pattern = format!("{}:gateway-action:{{*}}:session", self.config.key_prefix);
            let format_key = self.recovery_format_key();
            let expected_cursor = old_cursor.clone();
            let discovered: Vec<String> = self
                .execute(move |mut connection| async move {
                    Script::new(DISCOVER)
                        .key(format_key)
                        .arg(expected_cursor)
                        .arg(scan)
                        .arg(pattern)
                        .invoke_async(&mut connection)
                        .await
                })
                .await?;
            if discovered.first().is_some_and(|value| value == "changed") {
                return Ok(RedisGatewayActionMigrationProgress {
                    complete: false,
                    migrated_actions: migrated,
                    retention_backfilled_actions: retained,
                });
            }
            if discovered.is_empty()
                || !(discovered.len() - 1).is_multiple_of(3)
                || (discovered.len() - 1) / 3 > MAX_MIGRATION_KEYS
            {
                return Err(GatewayActionCoordinationError::InvalidRedisResponse);
            }
            let next = discovered[0]
                .parse()
                .map_err(|_| GatewayActionCoordinationError::InvalidRedisResponse)?;
            for fields in discovered[1..].chunks_exact(3) {
                let (tenant, session) = self.parse_session_key(&fields[0])?;
                cursor.sessions.push_back(MigrationSession {
                    tenant,
                    session,
                    fields_cursor: 0,
                    started: false,
                    action_fields: fields[1]
                        .parse()
                        .map_err(|_| GatewayActionCoordinationError::InvalidRedisResponse)?,
                    identity_fields: fields[2]
                        .parse()
                        .map_err(|_| GatewayActionCoordinationError::InvalidRedisResponse)?,
                });
            }
            cursor.scan_started = true;
            cursor.scan_cursor = next;
            mode = "discovered";
        } else {
            mode = "ready";
        }
        let next_cursor = serde_json::to_string(&cursor)
            .map_err(|_| GatewayActionCoordinationError::InvalidRedisResponse)?;
        let retention = self.config.store.retention().as_millis().to_string();
        let response: Vec<String> = self
            .execute(move |mut connection| async move {
                let script = if version == 2 {
                    MIGRATE_STEP.to_owned()
                } else {
                    format!("{RECOVERY_SCRIPT}{RETENTION_SCRIPT}{MIGRATE_RETENTION_STEP}")
                };
                let legacy_pending = keys.pending.trim_end_matches("-v3").to_owned();
                Script::new(&script)
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
                    .key(legacy_pending)
                    .arg(old_cursor)
                    .arg(next_cursor)
                    .arg(retention)
                    .arg(mode)
                    .arg(rows.len() / 9)
                    .arg(expected_fields.0)
                    .arg(expected_fields.1)
                    .arg(rows)
                    .invoke_async(&mut connection)
                    .await
            })
            .await?;
        match response.as_slice() {
            [code, count] if code == "1" => Ok(RedisGatewayActionMigrationProgress {
                complete: mode == "ready" && version == 5,
                migrated_actions: if version == 2 {
                    count
                        .parse()
                        .map_err(|_| GatewayActionCoordinationError::InvalidRedisResponse)?
                } else {
                    migrated
                },
                retention_backfilled_actions: if version == 5 {
                    count
                        .parse()
                        .map_err(|_| GatewayActionCoordinationError::InvalidRedisResponse)?
                } else {
                    retained
                },
            }),
            [code] if code == "2" => Ok(RedisGatewayActionMigrationProgress {
                complete: false,
                migrated_actions: migrated,
                retention_backfilled_actions: retained,
            }),
            [code] if code == "9" => Err(GatewayActionCoordinationError::PendingActionCapacity),
            [code] if code == "15" => Err(GatewayActionCoordinationError::RetainedActionCapacity),
            _ => Err(GatewayActionCoordinationError::InvalidRedisResponse),
        }
    }
}

// v3 already has a bounded permanent catalog. Upgrade it without SCAN, reindexing, horizon
// resets, or fabricated requirement/receipt fields. Page verification and its cursor are atomic.
const VALIDATE_CATALOG: &str = r#"
local function kind(key) return redis.call('TYPE', key)['ok'] end
if kind(KEYS[1]) ~= 'hash' or redis.call('PTTL', KEYS[1]) ~= -1 or redis.call('HGET', KEYS[1], 'version') ~= '5' or redis.call('HGET', KEYS[1], 'state') ~= 'validating' then return {'invalid'} end
if redis.call('HGET', KEYS[1], 'cursor') ~= ARGV[1] then return {'changed'} end
for _, key in ipairs({KEYS[2], KEYS[3], KEYS[4], KEYS[5]}) do
  if kind(key) ~= 'none' and (kind(key) ~= 'zset' or redis.call('PTTL', key) ~= -1) then return {'invalid'} end
end
local total, seen, count = tonumber(redis.call('HGET', KEYS[1], 'catalog_total')), tonumber(redis.call('HGET', KEYS[1], 'catalog_validated')), tonumber(ARGV[3])
if not total or not seen or not count or total < 0 or total > 1048576 or seen < 0 or seen + count > total or count > 64 or #ARGV ~= 4 + count * 10 or redis.call('ZCARD', KEYS[2]) ~= total then return {'invalid'} end
local lower = ARGV[1] == '' and '-' or '(' .. ARGV[1]
local page = redis.call('ZRANGEBYLEX', KEYS[2], lower, '+', 'LIMIT', 0, 64)
if #page ~= count or (count > 0 and page[count] ~= ARGV[2]) or (ARGV[4] == '1') ~= (count < 64) then return {'invalid'} end
for index = 0, count - 1 do
  local offset = 5 + index * 10
  local namespace, action, raw, sequence, idempotency = ARGV[offset], ARGV[offset+1], ARGV[offset+2], ARGV[offset+3], ARGV[offset+4]
  local placement, metadata, pending, custody, member = ARGV[offset+5], ARGV[offset+6], ARGV[offset+7] == '1', ARGV[offset+8] == '1', ARGV[offset+9]
  if page[index+1] ~= member or redis.call('ZSCORE', KEYS[2], member) ~= '0' then return {'invalid'} end
  local session, actions, identities, retained = namespace .. ':session', namespace .. ':actions', namespace .. ':idempotency', namespace .. ':retention-v1'
  for _, key in ipairs({session, actions, identities, retained}) do
    if kind(key) ~= 'hash' or redis.call('PTTL', key) ~= -1 then return {'invalid'} end
  end
  if redis.call('HGET', session, 'placement') ~= placement or redis.call('HGET', actions, action) ~= raw or redis.call('HGET', actions, '@sequence:' .. action) ~= sequence or redis.call('HGET', actions, '@idempotency:' .. action) ~= idempotency or redis.call('HGET', identities, idempotency) ~= action or redis.call('HGET', retained, action) ~= metadata then return {'invalid'} end
  local deadline, source = string.match(metadata, '^([0-9]+)|([0-9]+)$')
  if not deadline or not source then return {'invalid'} end
  if deadline ~= '0' and redis.call('ZSCORE', KEYS[5], string.rep('0', 20-#deadline) .. deadline .. '|' .. member) ~= '0' then return {'invalid'} end
  local pending_key, custody_key = namespace .. ':pending-v3', namespace .. ':custody-v1'
  for _, key in ipairs({pending_key, custody_key}) do
    if kind(key) ~= 'none' and (kind(key) ~= 'zset' or redis.call('PTTL', key) ~= -1) then return {'invalid'} end
  end
  local pending_score = redis.call('ZSCORE', pending_key, string.rep('0', 20-#sequence) .. sequence .. '|' .. action)
  local recovery_score = redis.call('ZSCORE', KEYS[3], member)
  local custody_score, session_custody_score = redis.call('ZSCORE', KEYS[4], member), redis.call('ZSCORE', custody_key, action)
  if pending then
    if pending_score ~= '0' or recovery_score ~= '0' then return {'invalid'} end
  elseif pending_score or recovery_score then return {'invalid'} end
  if custody then
    if custody_score ~= '0' or session_custody_score ~= '0' then return {'invalid'} end
  elseif custody_score or session_custody_score then return {'invalid'} end
end
if ARGV[4] == '1' and seen + count ~= total then return {'invalid'} end
redis.call('HSET', KEYS[1], 'cursor', ARGV[2], 'catalog_validated', tostring(seen + count))
if ARGV[4] == '1' then redis.call('HSET', KEYS[1], 'state', 'ready') end
return {'ok'}
"#;

impl RedisGatewayActionStore {
    async fn validate_retained_catalog_step(
        &self,
        old_cursor: String,
        migrated: u64,
        retained: u64,
    ) -> Result<RedisGatewayActionMigrationProgress, GatewayActionCoordinationError> {
        if !old_cursor.is_empty() {
            Self::parse_recovery_member(&old_cursor)?;
        }
        let key = self.retained_index_key();
        let marker = self.recovery_format_key();
        let lower = if old_cursor.is_empty() {
            "-".to_owned()
        } else {
            format!("({old_cursor}")
        };
        let members: Vec<String> = self.execute(move |mut connection| async move {
            Script::new(r#"
if redis.call('TYPE', KEYS[2])['ok'] ~= 'hash' or redis.call('PTTL', KEYS[2]) ~= -1 or redis.call('HGET', KEYS[2], 'version') ~= '5' or redis.call('HGET', KEYS[2], 'state') ~= 'validating' then return {'invalid'} end
local kind = redis.call('TYPE', KEYS[1])['ok']
if kind ~= 'none' and (kind ~= 'zset' or redis.call('PTTL', KEYS[1]) ~= -1) then return {'invalid'} end
return redis.call('ZRANGEBYLEX', KEYS[1], ARGV[1], '+', 'LIMIT', 0, 64)
"#).key(key).key(marker).arg(lower).invoke_async(&mut connection).await
        }).await?;
        if members.len() > MAX_MIGRATION_FIELDS {
            return Err(GatewayActionCoordinationError::InvalidRedisResponse);
        }
        let complete = members.len() < MAX_MIGRATION_FIELDS;
        let count = members.len();
        let next = members
            .last()
            .cloned()
            .unwrap_or_else(|| old_cursor.clone());
        let mut rows = Vec::new();
        let mut bytes = 0_usize;
        for member in members {
            let (tenant, session, action) = Self::parse_recovery_member(&member)?;
            let row = self
                .read_action_in_format(&tenant, &session, &action, true)
                .await?
                .ok_or(GatewayActionCoordinationError::InvalidRedisResponse)?;
            bytes = bytes.saturating_add(row.raw.len());
            if bytes > MAX_MIGRATION_BYTES {
                return Err(GatewayActionCoordinationError::InvalidRedisResponse);
            }
            let metadata = if row.snapshot.terminal().is_some() {
                format!(
                    "{}|{}",
                    row.snapshot.retain_until.timestamp_millis(),
                    row.snapshot.last_source_event_sequence.unwrap_or(0)
                )
            } else {
                "0|0".to_owned()
            };
            rows.extend([
                self.keys(&tenant, &session)
                    .session
                    .trim_end_matches(":session")
                    .to_owned(),
                action.to_string(),
                row.raw,
                row.snapshot.action_sequence().get().to_string(),
                row.snapshot.idempotency_key().to_owned(),
                Self::serialize_placement(row.snapshot.placement())?,
                metadata,
                if row.snapshot.terminal().is_none() {
                    "1"
                } else {
                    "0"
                }
                .to_owned(),
                if row.snapshot.pending_custody().is_some() {
                    "1"
                } else {
                    "0"
                }
                .to_owned(),
                member,
            ]);
        }
        let marker = self.recovery_format_key();
        let retained_key = self.retained_index_key();
        let recovery = self.recovery_index_key();
        let custody = self.custody_index_key();
        let due = self.retention_index_key();
        let response: Vec<String> = self
            .execute(move |mut connection| async move {
                Script::new(VALIDATE_CATALOG)
                    .key(marker)
                    .key(retained_key)
                    .key(recovery)
                    .key(custody)
                    .key(due)
                    .arg(old_cursor)
                    .arg(next)
                    .arg(count)
                    .arg(if complete { "1" } else { "0" })
                    .arg(rows)
                    .invoke_async(&mut connection)
                    .await
            })
            .await?;
        match response.as_slice() {
            [code] if code == "ok" => Ok(RedisGatewayActionMigrationProgress::from_catalog(
                complete, migrated, retained,
            )),
            [code] if code == "changed" => Ok(RedisGatewayActionMigrationProgress::from_catalog(
                false, migrated, retained,
            )),
            _ => Err(GatewayActionCoordinationError::InvalidRedisResponse),
        }
    }
}
