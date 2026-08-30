use std::fmt;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use browserd_actions::{
    ActionDeliveryEvidence, ActionEvidence, ActionEvidenceMutation, ActionKind, ActionSequence,
    BrowserResult, CanonicalRequestHash, DispatchId, ResolutionAnnotation, TerminalDetail,
    TransportLoss,
};
use browserd_core::{ActionId, SessionId, TenantId};
use chrono::{DateTime, Utc};
use redis::Script;
use redis::aio::ConnectionManager;
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;
use tokio::time::timeout;
use uuid::{Uuid, Version};

use super::{
    ClaimGatewayAction, GatewayActionClaimOutcome, GatewayActionCoordination,
    GatewayActionCoordinationError, GatewayActionPlacement, GatewayActionSnapshot,
    MAX_MATERIALIZATION_LIMIT, SessionLossClaim, SessionLossOutcome, validated_idempotency_key,
};
use crate::{DirectoryFence, StoreConfig};

const MAX_SAFE_REDIS_INTEGER: u128 = 9_007_199_254_740_991;
const MAX_CAS_ATTEMPTS: usize = 16;

const CLAIM_SCRIPT: &str = r#"
local function key_type(key) return redis.call('TYPE', key)['ok'] end
local function valid_u64(value)
  return value and string.match(value, '^[0-9]+$') and (value == '0' or string.sub(value, 1, 1) ~= '0') and (#value < 20 or (#value == 20 and value <= '18446744073709551615'))
end
local function increment_u64(value)
  if not valid_u64(value) or value == '18446744073709551615' then return nil end
  local output, carry = '', 1
  for index = #value, 1, -1 do
    local digit = string.byte(value, index) - 48 + carry
    if digit == 10 then digit = 0 else carry = 0 end
    output = string.char(digit + 48) .. output
  end
  if carry == 1 then output = '1' .. output end
  return output
end
local function extend_ttl(key, ttl)
  local current = redis.call('PTTL', key)
  if current < ttl then redis.call('PEXPIRE', key, ARGV[5]) end
end
if key_type(KEYS[1]) ~= 'none' and key_type(KEYS[1]) ~= 'hash' then return {'6'} end
if key_type(KEYS[2]) ~= 'none' and key_type(KEYS[2]) ~= 'hash' then return {'6'} end
if key_type(KEYS[3]) ~= 'none' and key_type(KEYS[3]) ~= 'hash' then return {'6'} end
if key_type(KEYS[4]) ~= 'none' and key_type(KEYS[4]) ~= 'zset' then return {'6'} end
local session_exists = redis.call('EXISTS', KEYS[1])
local action_exists = redis.call('EXISTS', KEYS[2])
local idempotency_exists = redis.call('EXISTS', KEYS[3])
if action_exists ~= idempotency_exists then return {'6'} end
if action_exists == 0 and redis.call('EXISTS', KEYS[4]) == 1 then return {'6'} end
local last_sequence = '0'
local active_mutation = nil
local unresolved_mutation = nil
local loss_id = nil
if session_exists == 1 then
  if redis.call('PTTL', KEYS[1]) ~= -1 then return {'6'} end
  local current_placement = redis.call('HGET', KEYS[1], 'placement')
  last_sequence = redis.call('HGET', KEYS[1], 'last_action_sequence')
  if not current_placement or not valid_u64(last_sequence) then return {'6'} end
  if current_placement ~= ARGV[1] then return {'0'} end
  active_mutation = redis.call('HGET', KEYS[1], 'active_mutation')
  unresolved_mutation = redis.call('HGET', KEYS[1], 'unresolved_mutation')
  loss_id = redis.call('HGET', KEYS[1], 'loss_id')
elseif action_exists == 1 or redis.call('EXISTS', KEYS[4]) == 1 then
  return {'6'}
end
local held = active_mutation or unresolved_mutation or loss_id
if held and action_exists == 0 then return {'6'} end
if action_exists == 1 then
  local action_ttl = redis.call('PTTL', KEYS[2])
  local idempotency_ttl = redis.call('PTTL', KEYS[3])
  if held then
    if action_ttl ~= -1 or idempotency_ttl ~= -1 then return {'6'} end
  elseif action_ttl < 0 or idempotency_ttl < 0 then
    return {'6'}
  end
end
if redis.call('EXISTS', KEYS[4]) == 1 then
  local pending_ttl = redis.call('PTTL', KEYS[4])
  if held and pending_ttl ~= -1 then return {'6'} end
  if not held and pending_ttl < 0 then return {'6'} end
end
local existing_action_id = redis.call('HGET', KEYS[3], ARGV[2])
if existing_action_id then
  local payload = redis.call('HGET', KEYS[2], existing_action_id)
  local sequence = redis.call('HGET', KEYS[2], '@sequence:' .. existing_action_id)
  local reverse = redis.call('HGET', KEYS[2], '@idempotency:' .. existing_action_id)
  if not payload or not valid_u64(sequence) or sequence == '0' or reverse ~= ARGV[2] then return {'6'} end
  return {'2', payload, sequence, loss_id or '', existing_action_id}
end
if loss_id then return {'3'} end
if ARGV[6] == '1' and unresolved_mutation then return {'7', unresolved_mutation} end
local proposed_payload = redis.call('HGET', KEYS[2], ARGV[3])
local proposed_sequence = redis.call('HGET', KEYS[2], '@sequence:' .. ARGV[3])
local proposed_reverse = redis.call('HGET', KEYS[2], '@idempotency:' .. ARGV[3])
if proposed_payload or proposed_sequence or proposed_reverse then
  if not proposed_payload or not valid_u64(proposed_sequence) or proposed_sequence == '0' or not proposed_reverse or redis.call('HGET', KEYS[3], proposed_reverse) ~= ARGV[3] then return {'6'} end
  return {'4'}
end
local next_sequence = increment_u64(last_sequence)
if not next_sequence then return {'5'} end
if session_exists == 0 then
  redis.call('HSET', KEYS[1], 'placement', ARGV[1], 'last_action_sequence', next_sequence)
else
  redis.call('HSET', KEYS[1], 'last_action_sequence', next_sequence)
end
redis.call('HSET', KEYS[2], ARGV[3], ARGV[4], '@sequence:' .. ARGV[3], next_sequence, '@idempotency:' .. ARGV[3], ARGV[2])
redis.call('HSET', KEYS[3], ARGV[2], ARGV[3])
redis.call('ZADD', KEYS[4], next_sequence, ARGV[3])
local ttl = ARGV[5] + 0
if held then
  redis.call('PERSIST', KEYS[2])
  redis.call('PERSIST', KEYS[3])
  redis.call('PERSIST', KEYS[4])
else
  extend_ttl(KEYS[2], ttl)
  extend_ttl(KEYS[3], ttl)
  extend_ttl(KEYS[4], ttl)
end
return {'1', ARGV[4], next_sequence, ''}
"#;

const READ_SCRIPT: &str = r#"
local function key_type(key) return redis.call('TYPE', key)['ok'] end
local function valid_u64(value)
  return value and string.match(value, '^[0-9]+$') and (value == '0' or string.sub(value, 1, 1) ~= '0') and (#value < 20 or (#value == 20 and value <= '18446744073709551615'))
end
if key_type(KEYS[1]) ~= 'none' and key_type(KEYS[1]) ~= 'hash' then return {'6'} end
if key_type(KEYS[2]) ~= 'none' and key_type(KEYS[2]) ~= 'hash' then return {'6'} end
if key_type(KEYS[3]) ~= 'none' and key_type(KEYS[3]) ~= 'hash' then return {'6'} end
if key_type(KEYS[4]) ~= 'none' and key_type(KEYS[4]) ~= 'zset' then return {'6'} end
if redis.call('EXISTS', KEYS[1]) == 0 then
  if redis.call('EXISTS', KEYS[2]) == 1 or redis.call('EXISTS', KEYS[3]) == 1 or redis.call('EXISTS', KEYS[4]) == 1 then return {'6'} end
  return {'0'}
end
if redis.call('PTTL', KEYS[1]) ~= -1 then return {'6'} end
local placement = redis.call('HGET', KEYS[1], 'placement')
local last_sequence = redis.call('HGET', KEYS[1], 'last_action_sequence')
if not placement or not valid_u64(last_sequence) then return {'6'} end
local action_exists = redis.call('EXISTS', KEYS[2])
local idempotency_exists = redis.call('EXISTS', KEYS[3])
if action_exists ~= idempotency_exists then return {'6'} end
local loss_id = redis.call('HGET', KEYS[1], 'loss_id')
local active_mutation = redis.call('HGET', KEYS[1], 'active_mutation')
local unresolved_mutation = redis.call('HGET', KEYS[1], 'unresolved_mutation')
if action_exists == 0 then
  if active_mutation or unresolved_mutation then return {'6'} end
  return {'0'}
end
local held = active_mutation or unresolved_mutation or loss_id
local action_ttl = redis.call('PTTL', KEYS[2])
local idempotency_ttl = redis.call('PTTL', KEYS[3])
if held then
  if action_ttl ~= -1 or idempotency_ttl ~= -1 then return {'6'} end
elseif action_ttl < 0 or idempotency_ttl < 0 then
  return {'6'}
end
if redis.call('EXISTS', KEYS[4]) == 1 then
  local pending_ttl = redis.call('PTTL', KEYS[4])
  if held and pending_ttl ~= -1 then return {'6'} end
  if not held and pending_ttl < 0 then return {'6'} end
end
local payload = redis.call('HGET', KEYS[2], ARGV[1])
local sequence = redis.call('HGET', KEYS[2], '@sequence:' .. ARGV[1])
local reverse = redis.call('HGET', KEYS[2], '@idempotency:' .. ARGV[1])
if not payload and not sequence and not reverse then return {'0'} end
if not payload or not valid_u64(sequence) or sequence == '0' or not reverse or redis.call('HGET', KEYS[3], reverse) ~= ARGV[1] then return {'6'} end
return {'1', payload, sequence, placement, loss_id or '', reverse}
"#;

const MUTATE_SCRIPT: &str = r#"
local function key_type(key) return redis.call('TYPE', key)['ok'] end
local function valid_u64(value)
  return value and string.match(value, '^[0-9]+$') and value ~= '0' and string.sub(value, 1, 1) ~= '0' and (#value < 20 or (#value == 20 and value <= '18446744073709551615'))
end
if key_type(KEYS[1]) ~= 'hash' then return {'6'} end
if redis.call('PTTL', KEYS[1]) ~= -1 then return {'6'} end
local placement = redis.call('HGET', KEYS[1], 'placement')
if not placement or placement ~= ARGV[1] then return {'0'} end
local effect = ARGV[6]
local session_lost = redis.call('HGET', KEYS[1], 'loss_id')
if ARGV[7] == '1' and effect ~= 'resolve_mutation' and effect ~= 'resolve_read_only' then return {'6'} end
if session_lost and ARGV[7] ~= '1' then return {'4'} end
local action_type = key_type(KEYS[2])
local idempotency_type = key_type(KEYS[3])
if action_type == 'none' and idempotency_type == 'none' then return {'3'} end
if action_type ~= 'hash' or idempotency_type ~= 'hash' then return {'6'} end
if key_type(KEYS[4]) ~= 'none' and key_type(KEYS[4]) ~= 'zset' then return {'6'} end
local active_mutation = redis.call('HGET', KEYS[1], 'active_mutation')
local unresolved_mutation = redis.call('HGET', KEYS[1], 'unresolved_mutation')
local held_before = active_mutation or unresolved_mutation or session_lost
local action_ttl = redis.call('PTTL', KEYS[2])
local idempotency_ttl = redis.call('PTTL', KEYS[3])
if held_before then
  if action_ttl ~= -1 or idempotency_ttl ~= -1 then return {'6'} end
elseif action_ttl < 0 or idempotency_ttl < 0 then
  return {'6'}
end
if redis.call('EXISTS', KEYS[4]) == 1 then
  local pending_ttl = redis.call('PTTL', KEYS[4])
  if held_before and pending_ttl ~= -1 then return {'6'} end
  if not held_before and pending_ttl < 0 then return {'6'} end
end
local current = redis.call('HGET', KEYS[2], ARGV[2])
if not current then return {'3'} end
local sequence = redis.call('HGET', KEYS[2], '@sequence:' .. ARGV[2])
local reverse = redis.call('HGET', KEYS[2], '@idempotency:' .. ARGV[2])
if not valid_u64(sequence) or not reverse or redis.call('HGET', KEYS[3], reverse) ~= ARGV[2] then return {'6'} end
if current ~= ARGV[3] then return {'2'} end
local pending_type = key_type(KEYS[4])
local pending_score = nil
if pending_type == 'zset' then pending_score = redis.call('ZSCORE', KEYS[4], ARGV[2]) end
if effect == 'resolve_mutation' or effect == 'resolve_read_only' then
  if pending_score then return {'6'} end
elseif pending_type ~= 'zset' or not pending_score then
  return {'6'}
end
if effect == 'arm_mutation' then
  if unresolved_mutation then return {'7', unresolved_mutation} end
  if active_mutation then return {'8', active_mutation} end
  redis.call('HSET', KEYS[1], 'active_mutation', ARGV[2])
elseif effect == 'finish_mutation' or effect == 'unknown_mutation' then
  if active_mutation ~= ARGV[2] then return {'6'} end
  if effect == 'unknown_mutation' and unresolved_mutation and unresolved_mutation ~= ARGV[2] then return {'6'} end
elseif effect == 'resolve_mutation' then
  if session_lost then
    if active_mutation and active_mutation ~= ARGV[2] then return {'6'} end
    if unresolved_mutation and unresolved_mutation ~= ARGV[2] then return {'6'} end
  elseif unresolved_mutation ~= ARGV[2] then
    return {'6'}
  end
  if unresolved_mutation == ARGV[2] then redis.call('HDEL', KEYS[1], 'unresolved_mutation') end
  if session_lost and active_mutation == ARGV[2] then redis.call('HDEL', KEYS[1], 'active_mutation') end
elseif effect == 'resolve_read_only' then
  if active_mutation == ARGV[2] or unresolved_mutation == ARGV[2] then return {'6'} end
elseif effect ~= 'none' then
  return {'6'}
end
if effect == 'finish_mutation' or effect == 'unknown_mutation' then
  redis.call('HDEL', KEYS[1], 'active_mutation')
  if effect == 'unknown_mutation' then redis.call('HSET', KEYS[1], 'unresolved_mutation', ARGV[2]) end
end
redis.call('HSET', KEYS[2], ARGV[2], ARGV[4])
if ARGV[5] == '1' then redis.call('ZREM', KEYS[4], ARGV[2]) end
local held_after = redis.call('HGET', KEYS[1], 'active_mutation') or redis.call('HGET', KEYS[1], 'unresolved_mutation') or session_lost
if held_after then
  redis.call('PERSIST', KEYS[2])
  redis.call('PERSIST', KEYS[3])
  if redis.call('EXISTS', KEYS[4]) == 1 then redis.call('PERSIST', KEYS[4]) end
else
  redis.call('PEXPIRE', KEYS[2], ARGV[8])
  redis.call('PEXPIRE', KEYS[3], ARGV[8])
  if redis.call('EXISTS', KEYS[4]) == 1 then redis.call('PEXPIRE', KEYS[4], ARGV[8]) end
end
return {'1', ARGV[4], sequence}
"#;

const MARK_LOSS_SCRIPT: &str = r#"
local function key_type(key) return redis.call('TYPE', key)['ok'] end
local function valid_u64(value)
  return value and string.match(value, '^[0-9]+$') and (value == '0' or string.sub(value, 1, 1) ~= '0') and (#value < 20 or (#value == 20 and value <= '18446744073709551615'))
end
if key_type(KEYS[1]) ~= 'none' and key_type(KEYS[1]) ~= 'hash' then return {'6'} end
if key_type(KEYS[2]) ~= 'none' and key_type(KEYS[2]) ~= 'hash' then return {'6'} end
if key_type(KEYS[3]) ~= 'none' and key_type(KEYS[3]) ~= 'hash' then return {'6'} end
if key_type(KEYS[4]) ~= 'none' and key_type(KEYS[4]) ~= 'zset' then return {'6'} end
local exists = redis.call('EXISTS', KEYS[1])
local action_exists = redis.call('EXISTS', KEYS[2])
local idempotency_exists = redis.call('EXISTS', KEYS[3])
if action_exists ~= idempotency_exists then return {'6'} end
if exists == 1 then
  if redis.call('PTTL', KEYS[1]) ~= -1 then return {'6'} end
  local placement = redis.call('HGET', KEYS[1], 'placement')
  local last_sequence = redis.call('HGET', KEYS[1], 'last_action_sequence')
  if not placement or not valid_u64(last_sequence) then return {'6'} end
  if placement ~= ARGV[1] then return {'0'} end
  local active_mutation = redis.call('HGET', KEYS[1], 'active_mutation')
  local unresolved_mutation = redis.call('HGET', KEYS[1], 'unresolved_mutation')
  local current_loss = redis.call('HGET', KEYS[1], 'loss_id')
  local held = active_mutation or unresolved_mutation or current_loss
  if held and action_exists == 0 then return {'6'} end
  if action_exists == 1 then
    local action_ttl = redis.call('PTTL', KEYS[2])
    local idempotency_ttl = redis.call('PTTL', KEYS[3])
    if held then
      if action_ttl ~= -1 or idempotency_ttl ~= -1 then return {'6'} end
    elseif action_ttl < 0 or idempotency_ttl < 0 then
      return {'6'}
    end
  end
  if redis.call('EXISTS', KEYS[4]) == 1 then
    local pending_ttl = redis.call('PTTL', KEYS[4])
    if held and pending_ttl ~= -1 then return {'6'} end
    if not held and pending_ttl < 0 then return {'6'} end
  end
  if current_loss then
    if current_loss == ARGV[2] then return {'2'} end
    return {'3'}
  end
else
  if action_exists == 1 or redis.call('EXISTS', KEYS[4]) == 1 then return {'6'} end
  redis.call('HSET', KEYS[1], 'placement', ARGV[1], 'last_action_sequence', '0')
end
redis.call('HSET', KEYS[1], 'loss_id', ARGV[2], 'loss_at', ARGV[3])
redis.call('PERSIST', KEYS[1])
if action_exists == 1 then
  redis.call('PERSIST', KEYS[2])
  redis.call('PERSIST', KEYS[3])
end
if redis.call('EXISTS', KEYS[4]) == 1 then redis.call('PERSIST', KEYS[4]) end
return {'1'}
"#;

const MATERIALIZE_CANDIDATES_SCRIPT: &str = r#"
local function key_type(key) return redis.call('TYPE', key)['ok'] end
local function valid_u64(value)
  return value and string.match(value, '^[0-9]+$') and value ~= '0' and string.sub(value, 1, 1) ~= '0' and (#value < 20 or (#value == 20 and value <= '18446744073709551615'))
end
if key_type(KEYS[1]) == 'none' then return {'1'} end
if key_type(KEYS[1]) ~= 'hash' then return {'6'} end
if redis.call('PTTL', KEYS[1]) ~= -1 then return {'6'} end
local placement = redis.call('HGET', KEYS[1], 'placement')
if not placement or placement ~= ARGV[1] then return {'0'} end
local loss_id = redis.call('HGET', KEYS[1], 'loss_id')
if not loss_id then return {'1'} end
if loss_id ~= ARGV[2] then return {'2'} end
if key_type(KEYS[2]) == 'none' and key_type(KEYS[3]) == 'none' and key_type(KEYS[4]) == 'none' then return {'3'} end
if key_type(KEYS[2]) ~= 'hash' or key_type(KEYS[3]) ~= 'hash' then return {'6'} end
if key_type(KEYS[4]) == 'none' then return {'3'} end
if key_type(KEYS[4]) ~= 'zset' then return {'6'} end
if redis.call('PTTL', KEYS[2]) ~= -1 or redis.call('PTTL', KEYS[3]) ~= -1 or redis.call('PTTL', KEYS[4]) ~= -1 then return {'6'} end
local action_ids = redis.call('ZRANGE', KEYS[4], 0, (ARGV[3] + 0) - 1)
local response = {'3'}
for _, action_id in ipairs(action_ids) do
  local payload = redis.call('HGET', KEYS[2], action_id)
  local sequence = redis.call('HGET', KEYS[2], '@sequence:' .. action_id)
  local reverse = redis.call('HGET', KEYS[2], '@idempotency:' .. action_id)
  if not payload or not valid_u64(sequence) or not reverse or redis.call('HGET', KEYS[3], reverse) ~= action_id then return {'6'} end
  table.insert(response, action_id)
  table.insert(response, payload)
  table.insert(response, sequence)
  table.insert(response, reverse)
end
return response
"#;

const MATERIALIZE_BATCH_SCRIPT: &str = r#"
local function key_type(key) return redis.call('TYPE', key)['ok'] end
if key_type(KEYS[1]) ~= 'hash' then return {'6'} end
if redis.call('PTTL', KEYS[1]) ~= -1 then return {'6'} end
local placement = redis.call('HGET', KEYS[1], 'placement')
if not placement or placement ~= ARGV[1] then return {'0'} end
local loss_id = redis.call('HGET', KEYS[1], 'loss_id')
if not loss_id then return {'1'} end
if loss_id ~= ARGV[2] then return {'2'} end
local count = ARGV[3] + 0
if count < 0 or count > 1000 or #ARGV ~= 3 + count * 4 then return {'6'} end
if count == 0 then return {'3', '0'} end
if key_type(KEYS[2]) == 'none' and key_type(KEYS[3]) == 'none' then return {'4'} end
if key_type(KEYS[2]) ~= 'hash' or key_type(KEYS[3]) ~= 'hash' then return {'6'} end
if key_type(KEYS[4]) == 'none' then return {'4'} end
if key_type(KEYS[4]) ~= 'zset' then return {'6'} end
if redis.call('PTTL', KEYS[2]) ~= -1 or redis.call('PTTL', KEYS[3]) ~= -1 or redis.call('PTTL', KEYS[4]) ~= -1 then return {'6'} end
for index = 0, count - 1 do
  local offset = 4 + index * 4
  local action_id = ARGV[offset]
  local expected_sequence = ARGV[offset + 1]
  local expected_payload = ARGV[offset + 2]
  local current = redis.call('HGET', KEYS[2], action_id)
  local sequence = redis.call('HGET', KEYS[2], '@sequence:' .. action_id)
  local reverse = redis.call('HGET', KEYS[2], '@idempotency:' .. action_id)
  if not current or sequence ~= expected_sequence or not reverse or redis.call('HGET', KEYS[3], reverse) ~= action_id then return {'6'} end
  if current ~= expected_payload or not redis.call('ZSCORE', KEYS[4], action_id) then return {'4'} end
end
for index = 0, count - 1 do
  local offset = 4 + index * 4
  local action_id = ARGV[offset]
  redis.call('HSET', KEYS[2], action_id, ARGV[offset + 3])
  redis.call('ZREM', KEYS[4], action_id)
end
return {'3', tostring(count)}
"#;

#[derive(Clone)]
pub struct RedisGatewayActionConfig {
    endpoint: String,
    key_prefix: String,
    store: StoreConfig,
    max_in_flight: usize,
    command_timeout: Duration,
}

impl RedisGatewayActionConfig {
    pub fn new(
        endpoint: impl Into<String>,
        key_prefix: impl Into<String>,
        store: StoreConfig,
        max_in_flight: usize,
        command_timeout: Duration,
    ) -> Result<Self, GatewayActionCoordinationError> {
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
            || store.retention().as_millis() > MAX_SAFE_REDIS_INTEGER
        {
            return Err(GatewayActionCoordinationError::InvalidRedisConfig);
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

impl fmt::Debug for RedisGatewayActionConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedisGatewayActionConfig")
            .field("endpoint", &"[REDACTED]")
            .field("key_prefix", &self.key_prefix)
            .field("store", &self.store)
            .field("max_in_flight", &self.max_in_flight)
            .field("command_timeout", &self.command_timeout)
            .finish()
    }
}

#[derive(Clone)]
pub struct RedisGatewayActionStore {
    connection: ConnectionManager,
    config: RedisGatewayActionConfig,
    permits: Arc<Semaphore>,
}

#[derive(Serialize, Deserialize)]
struct PersistedPlacement {
    directory_fence: DirectoryFence,
    directory_revision: u64,
}

impl From<&GatewayActionPlacement> for PersistedPlacement {
    fn from(value: &GatewayActionPlacement) -> Self {
        Self {
            directory_fence: value.directory_fence().clone(),
            directory_revision: value.directory_revision(),
        }
    }
}

impl PersistedPlacement {
    fn into_placement(self) -> Result<GatewayActionPlacement, GatewayActionCoordinationError> {
        GatewayActionPlacement::new(self.directory_fence, self.directory_revision)
            .map_err(|_| GatewayActionCoordinationError::InvalidRedisResponse)
    }
}

#[derive(Serialize, Deserialize)]
struct PersistedGatewayAction {
    tenant_id: TenantId,
    session_id: SessionId,
    action_id: ActionId,
    idempotency_key: String,
    request_hash: CanonicalRequestHash,
    kind: ActionKind,
    placement: PersistedPlacement,
    evidence: ActionEvidence,
    resolution: Option<ResolutionAnnotation>,
    revision: u64,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    retain_until: DateTime<Utc>,
}

impl PersistedGatewayAction {
    fn from_claim(
        claim: &ClaimGatewayAction,
        now: DateTime<Utc>,
        retain_until: DateTime<Utc>,
    ) -> Self {
        Self {
            tenant_id: claim.tenant_id().clone(),
            session_id: claim.session_id().clone(),
            action_id: claim.proposed_action_id().clone(),
            idempotency_key: claim.idempotency_key().to_owned(),
            request_hash: claim.request_hash(),
            kind: claim.kind(),
            placement: PersistedPlacement::from(claim.placement()),
            evidence: ActionEvidence::new(),
            resolution: None,
            revision: 0,
            created_at: now,
            updated_at: now,
            retain_until,
        }
    }

    fn from_snapshot(snapshot: &GatewayActionSnapshot) -> Self {
        Self {
            tenant_id: snapshot.tenant_id.clone(),
            session_id: snapshot.session_id.clone(),
            action_id: snapshot.action_id.clone(),
            idempotency_key: snapshot.idempotency_key.as_str().to_owned(),
            request_hash: snapshot.request_hash,
            kind: snapshot.kind,
            placement: PersistedPlacement::from(&snapshot.placement),
            evidence: snapshot.evidence.clone(),
            resolution: snapshot.resolution.clone(),
            revision: snapshot.revision,
            created_at: snapshot.created_at,
            updated_at: snapshot.updated_at,
            retain_until: snapshot.retain_until,
        }
    }

    fn into_snapshot(
        self,
        action_sequence: ActionSequence,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        if action_sequence.get() == 0 || self.retain_until <= self.created_at {
            return Err(GatewayActionCoordinationError::InvalidRedisResponse);
        }
        Ok(GatewayActionSnapshot {
            tenant_id: self.tenant_id,
            session_id: self.session_id,
            action_id: self.action_id,
            idempotency_key: validated_idempotency_key(self.idempotency_key)
                .map_err(|_| GatewayActionCoordinationError::InvalidRedisResponse)?,
            request_hash: self.request_hash,
            kind: self.kind,
            placement: self.placement.into_placement()?,
            evidence: self.evidence,
            resolution: self.resolution,
            action_sequence,
            revision: self.revision,
            created_at: self.created_at,
            updated_at: self.updated_at,
            retain_until: self.retain_until,
        })
    }
}

struct RedisActionKeys {
    session: String,
    actions: String,
    idempotency: String,
    pending: String,
}

struct RawActionRead {
    raw: String,
    snapshot: GatewayActionSnapshot,
    session_lost: bool,
}

enum CasMutation {
    Applied(Box<GatewayActionSnapshot>),
    Changed,
}

#[derive(Clone, Copy)]
enum SessionMutation {
    None,
    ArmMutation,
    FinishMutation,
    UnknownMutation,
    ResolveMutation,
    ResolveReadOnly,
}

impl SessionMutation {
    const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::ArmMutation => "arm_mutation",
            Self::FinishMutation => "finish_mutation",
            Self::UnknownMutation => "unknown_mutation",
            Self::ResolveMutation => "resolve_mutation",
            Self::ResolveReadOnly => "resolve_read_only",
        }
    }
}

impl RedisGatewayActionStore {
    pub async fn connect(
        config: RedisGatewayActionConfig,
    ) -> Result<Self, GatewayActionCoordinationError> {
        let client = redis::Client::open(config.endpoint.as_str())
            .map_err(|_| GatewayActionCoordinationError::RedisUnavailable)?;
        let connection = timeout(config.command_timeout, client.get_connection_manager())
            .await
            .map_err(|_| GatewayActionCoordinationError::RedisTimedOut)?
            .map_err(|_| GatewayActionCoordinationError::RedisUnavailable)?;
        Ok(Self {
            connection,
            permits: Arc::new(Semaphore::new(config.max_in_flight)),
            config,
        })
    }

    async fn execute<T, F, Fut>(&self, operation: F) -> Result<T, GatewayActionCoordinationError>
    where
        F: FnOnce(ConnectionManager) -> Fut,
        Fut: Future<Output = redis::RedisResult<T>>,
    {
        let permit = timeout(
            self.config.command_timeout,
            Arc::clone(&self.permits).acquire_owned(),
        )
        .await
        .map_err(|_| GatewayActionCoordinationError::RedisTimedOut)?
        .map_err(|_| GatewayActionCoordinationError::RedisUnavailable)?;
        let connection = self.connection.clone();
        let result = timeout(self.config.command_timeout, operation(connection))
            .await
            .map_err(|_| GatewayActionCoordinationError::RedisTimedOut)?
            .map_err(|_| GatewayActionCoordinationError::RedisUnavailable);
        drop(permit);
        result
    }

    fn keys(&self, tenant_id: &TenantId, session_id: &SessionId) -> RedisActionKeys {
        let namespace = format!(
            "{}:gateway-action:{{{tenant_id}:{session_id}}}",
            self.config.key_prefix
        );
        RedisActionKeys {
            session: format!("{namespace}:session"),
            actions: format!("{namespace}:actions"),
            idempotency: format!("{namespace}:idempotency"),
            pending: format!("{namespace}:pending"),
        }
    }

    fn serialize_placement(
        placement: &GatewayActionPlacement,
    ) -> Result<String, GatewayActionCoordinationError> {
        serde_json::to_string(&PersistedPlacement::from(placement))
            .map_err(|_| GatewayActionCoordinationError::InvalidRedisResponse)
    }

    fn decode_placement(
        raw: &str,
    ) -> Result<GatewayActionPlacement, GatewayActionCoordinationError> {
        serde_json::from_str::<PersistedPlacement>(raw)
            .map_err(|_| GatewayActionCoordinationError::InvalidRedisResponse)?
            .into_placement()
    }

    fn serialize_snapshot(
        snapshot: &GatewayActionSnapshot,
    ) -> Result<String, GatewayActionCoordinationError> {
        serde_json::to_string(&PersistedGatewayAction::from_snapshot(snapshot))
            .map_err(|_| GatewayActionCoordinationError::InvalidRedisResponse)
    }

    fn decode_snapshot(
        raw: &str,
        sequence: &str,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        if sequence.is_empty()
            || sequence.starts_with('0')
            || !sequence.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(GatewayActionCoordinationError::InvalidRedisResponse);
        }
        let sequence = sequence
            .parse::<u64>()
            .map_err(|_| GatewayActionCoordinationError::InvalidRedisResponse)?;
        let persisted = serde_json::from_str::<PersistedGatewayAction>(raw)
            .map_err(|_| GatewayActionCoordinationError::InvalidRedisResponse)?;
        persisted.into_snapshot(ActionSequence::new(sequence))
    }

    fn validate_scope(
        snapshot: &GatewayActionSnapshot,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
    ) -> Result<(), GatewayActionCoordinationError> {
        if snapshot.tenant_id() != tenant_id
            || snapshot.session_id() != session_id
            || snapshot.action_id() != action_id
        {
            return Err(GatewayActionCoordinationError::InvalidRedisResponse);
        }
        Ok(())
    }

    fn loss_is_recorded(raw: &str) -> Result<bool, GatewayActionCoordinationError> {
        if raw.is_empty() {
            return Ok(false);
        }
        let loss_id = Uuid::parse_str(raw)
            .map_err(|_| GatewayActionCoordinationError::InvalidRedisResponse)?;
        if loss_id.get_version() != Some(Version::SortRand) {
            return Err(GatewayActionCoordinationError::InvalidRedisResponse);
        }
        Ok(true)
    }

    fn decode_action_id(raw: &str) -> Result<ActionId, GatewayActionCoordinationError> {
        raw.parse()
            .map_err(|_| GatewayActionCoordinationError::InvalidRedisResponse)
    }

    async fn read_action(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
    ) -> Result<Option<RawActionRead>, GatewayActionCoordinationError> {
        let keys = self.keys(tenant_id, session_id);
        let action_id_argument = action_id.to_string();
        let response: Vec<String> = self
            .execute(move |mut connection| async move {
                Script::new(READ_SCRIPT)
                    .key(keys.session)
                    .key(keys.actions)
                    .key(keys.idempotency)
                    .key(keys.pending)
                    .arg(action_id_argument)
                    .invoke_async(&mut connection)
                    .await
            })
            .await?;
        match response.as_slice() {
            [code] if code == "0" => Ok(None),
            [code, raw, sequence, placement, loss_id, reverse] if code == "1" => {
                let snapshot = Self::decode_snapshot(raw, sequence)?;
                Self::validate_scope(&snapshot, tenant_id, session_id, action_id)?;
                let session_placement = Self::decode_placement(placement)?;
                if snapshot.placement() != &session_placement
                    || snapshot.idempotency_key() != reverse.as_str()
                {
                    return Err(GatewayActionCoordinationError::InvalidRedisResponse);
                }
                Ok(Some(RawActionRead {
                    raw: raw.clone(),
                    snapshot,
                    session_lost: Self::loss_is_recorded(loss_id)?,
                }))
            }
            [code] if code == "6" => Err(GatewayActionCoordinationError::InvalidRedisResponse),
            _ => Err(GatewayActionCoordinationError::InvalidRedisResponse),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn cas_action(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        placement: &GatewayActionPlacement,
        current_raw: String,
        candidate: GatewayActionSnapshot,
        session_mutation: SessionMutation,
        allow_session_loss: bool,
    ) -> Result<CasMutation, GatewayActionCoordinationError> {
        let keys = self.keys(tenant_id, session_id);
        let placement = Self::serialize_placement(placement)?;
        let action_id = action_id.to_string();
        let candidate_raw = Self::serialize_snapshot(&candidate)?;
        let terminal = if candidate.terminal().is_some() {
            "1"
        } else {
            "0"
        };
        let retention_millis = self.config.store.retention().as_millis().to_string();
        let response: Vec<String> = self
            .execute(move |mut connection| async move {
                Script::new(MUTATE_SCRIPT)
                    .key(keys.session)
                    .key(keys.actions)
                    .key(keys.idempotency)
                    .key(keys.pending)
                    .arg(placement)
                    .arg(action_id)
                    .arg(current_raw)
                    .arg(candidate_raw)
                    .arg(terminal)
                    .arg(session_mutation.as_str())
                    .arg(if allow_session_loss { "1" } else { "0" })
                    .arg(retention_millis)
                    .invoke_async(&mut connection)
                    .await
            })
            .await?;
        match response.as_slice() {
            [code, raw, sequence] if code == "1" => {
                let stored = Self::decode_snapshot(raw, sequence)?;
                Self::validate_scope(&stored, tenant_id, session_id, candidate.action_id())?;
                if stored != candidate {
                    return Err(GatewayActionCoordinationError::InvalidRedisResponse);
                }
                Ok(CasMutation::Applied(Box::new(stored)))
            }
            [code] if code == "2" => Ok(CasMutation::Changed),
            [code] if code == "0" => Err(GatewayActionCoordinationError::PlacementMismatch),
            [code] if code == "3" => Err(GatewayActionCoordinationError::NotFound),
            [code] if code == "4" => Err(GatewayActionCoordinationError::SessionLost),
            [code, action_id] if code == "7" => {
                Err(GatewayActionCoordinationError::ReconciliationRequired {
                    action_id: Self::decode_action_id(action_id)?,
                })
            }
            [code, action_id] if code == "8" => {
                Err(GatewayActionCoordinationError::MutationInFlight {
                    action_id: Self::decode_action_id(action_id)?,
                })
            }
            [code] if code == "6" => Err(GatewayActionCoordinationError::InvalidRedisResponse),
            _ => Err(GatewayActionCoordinationError::InvalidRedisResponse),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn mutate_action<F>(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        expected_revision: u64,
        placement: &GatewayActionPlacement,
        now: DateTime<Utc>,
        allow_session_loss: bool,
        mutation: F,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError>
    where
        F: Fn(
                &mut GatewayActionSnapshot,
            ) -> Result<ActionEvidenceMutation, GatewayActionCoordinationError>
            + Send
            + Sync,
    {
        for _ in 0..MAX_CAS_ATTEMPTS {
            let current = self
                .read_action(tenant_id, session_id, action_id)
                .await?
                .ok_or(GatewayActionCoordinationError::NotFound)?;
            if current.snapshot.placement() != placement {
                return Err(GatewayActionCoordinationError::PlacementMismatch);
            }
            if current.session_lost && !allow_session_loss {
                return Err(GatewayActionCoordinationError::SessionLost);
            }
            let mut candidate = current.snapshot.clone();
            let attempted = mutation(&mut candidate);
            match attempted {
                Ok(ActionEvidenceMutation::AlreadyRecorded) => return Ok(current.snapshot),
                Ok(ActionEvidenceMutation::Recorded) => {
                    if current.snapshot.revision() != expected_revision {
                        return Err(GatewayActionCoordinationError::StaleWrite(Box::new(
                            current.snapshot,
                        )));
                    }
                }
                Err(_) if current.snapshot.revision() != expected_revision => {
                    return Err(GatewayActionCoordinationError::StaleWrite(Box::new(
                        current.snapshot,
                    )));
                }
                Err(error) => return Err(error),
            }
            candidate.revision = candidate
                .revision
                .checked_add(1)
                .ok_or(GatewayActionCoordinationError::RevisionOverflow)?;
            candidate.updated_at = now;
            let session_mutation = if current.snapshot.kind() == ActionKind::Mutating
                && matches!(
                    current.snapshot.delivery(),
                    ActionDeliveryEvidence::NotAttempted
                )
                && matches!(
                    candidate.delivery(),
                    ActionDeliveryEvidence::DispatchArmed(_)
                ) {
                SessionMutation::ArmMutation
            } else if current.snapshot.kind() == ActionKind::Mutating
                && !matches!(
                    current.snapshot.delivery(),
                    ActionDeliveryEvidence::NotAttempted
                )
                && current.snapshot.terminal().is_none()
                && candidate.terminal().is_some()
            {
                if candidate.requires_reconciliation() {
                    SessionMutation::UnknownMutation
                } else {
                    SessionMutation::FinishMutation
                }
            } else if current.snapshot.resolution().is_none() && candidate.resolution().is_some() {
                if current.snapshot.kind() == ActionKind::Mutating {
                    SessionMutation::ResolveMutation
                } else {
                    SessionMutation::ResolveReadOnly
                }
            } else {
                SessionMutation::None
            };
            match self
                .cas_action(
                    tenant_id,
                    session_id,
                    action_id,
                    placement,
                    current.raw,
                    candidate,
                    session_mutation,
                    allow_session_loss,
                )
                .await?
            {
                CasMutation::Applied(snapshot) => return Ok(*snapshot),
                CasMutation::Changed => {}
            }
        }
        let current = self
            .read_action(tenant_id, session_id, action_id)
            .await?
            .ok_or(GatewayActionCoordinationError::NotFound)?;
        if current.snapshot.placement() != placement {
            return Err(GatewayActionCoordinationError::PlacementMismatch);
        }
        if current.session_lost && !allow_session_loss {
            return Err(GatewayActionCoordinationError::SessionLost);
        }
        Err(GatewayActionCoordinationError::StaleWrite(Box::new(
            current.snapshot,
        )))
    }

    fn validate_loss_claim(claim: &SessionLossClaim) -> Result<(), GatewayActionCoordinationError> {
        if claim.loss_id().get_version() != Some(Version::SortRand) {
            return Err(GatewayActionCoordinationError::InvalidSessionLossId);
        }
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
#[async_trait]
impl GatewayActionCoordination for RedisGatewayActionStore {
    async fn claim_action(
        &self,
        claim: ClaimGatewayAction,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionClaimOutcome, GatewayActionCoordinationError> {
        let retention = chrono::Duration::from_std(self.config.store.retention())
            .map_err(|_| GatewayActionCoordinationError::RetentionTimestampOverflow)?;
        let retain_until = now
            .checked_add_signed(retention)
            .ok_or(GatewayActionCoordinationError::RetentionTimestampOverflow)?;
        let raw = serde_json::to_string(&PersistedGatewayAction::from_claim(
            &claim,
            now,
            retain_until,
        ))
        .map_err(|_| GatewayActionCoordinationError::InvalidRedisResponse)?;
        let placement = Self::serialize_placement(claim.placement())?;
        let keys = self.keys(claim.tenant_id(), claim.session_id());
        let idempotency_key = claim.idempotency_key().to_owned();
        let proposed_action_id = claim.proposed_action_id().to_string();
        let retention_millis = self.config.store.retention().as_millis().to_string();
        let mutating = if claim.kind() == ActionKind::Mutating {
            "1"
        } else {
            "0"
        };
        let response: Vec<String> = self
            .execute(move |mut connection| async move {
                Script::new(CLAIM_SCRIPT)
                    .key(keys.session)
                    .key(keys.actions)
                    .key(keys.idempotency)
                    .key(keys.pending)
                    .arg(placement)
                    .arg(idempotency_key)
                    .arg(proposed_action_id)
                    .arg(raw)
                    .arg(retention_millis)
                    .arg(mutating)
                    .invoke_async(&mut connection)
                    .await
            })
            .await?;
        let (created, raw, sequence, loss_id, mapped_action_id) = match response.as_slice() {
            [code, raw, sequence, loss_id] if code == "1" => (
                true,
                raw,
                sequence,
                loss_id,
                claim.proposed_action_id().to_string(),
            ),
            [code, raw, sequence, loss_id, mapped_action_id] if code == "2" => {
                (false, raw, sequence, loss_id, mapped_action_id.clone())
            }
            [code] if code == "0" => {
                return Err(GatewayActionCoordinationError::PlacementMismatch);
            }
            [code] if code == "3" => {
                return Err(GatewayActionCoordinationError::SessionLost);
            }
            [code] if code == "4" => {
                return Err(GatewayActionCoordinationError::ActionIdentityConflict {
                    action_id: claim.proposed_action_id().clone(),
                });
            }
            [code] if code == "5" => {
                return Err(GatewayActionCoordinationError::ActionSequenceOverflow);
            }
            [code] if code == "6" => {
                return Err(GatewayActionCoordinationError::InvalidRedisResponse);
            }
            [code, action_id] if code == "7" => {
                return Err(GatewayActionCoordinationError::ReconciliationRequired {
                    action_id: Self::decode_action_id(action_id)?,
                });
            }
            _ => return Err(GatewayActionCoordinationError::InvalidRedisResponse),
        };
        let mut snapshot = Self::decode_snapshot(raw, sequence)?;
        if snapshot.tenant_id() != claim.tenant_id()
            || snapshot.session_id() != claim.session_id()
            || snapshot.action_id().to_string() != mapped_action_id
            || snapshot.idempotency_key() != claim.idempotency_key()
            || snapshot.placement() != claim.placement()
        {
            return Err(GatewayActionCoordinationError::InvalidRedisResponse);
        }
        if snapshot.request_hash() != claim.request_hash() || snapshot.kind() != claim.kind() {
            return Err(GatewayActionCoordinationError::IdempotencyConflict {
                existing_action_id: snapshot.action_id().clone(),
            });
        }
        let session_lost = Self::loss_is_recorded(loss_id)?;
        if created {
            if session_lost {
                return Err(GatewayActionCoordinationError::InvalidRedisResponse);
            }
            Ok(GatewayActionClaimOutcome::Created(snapshot))
        } else {
            if session_lost && snapshot.terminal().is_none() {
                snapshot.derive_worker_loss()?;
            }
            Ok(GatewayActionClaimOutcome::Existing(snapshot))
        }
    }

    async fn get_effective_action(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
    ) -> Result<Option<GatewayActionSnapshot>, GatewayActionCoordinationError> {
        let Some(mut current) = self.read_action(tenant_id, session_id, action_id).await? else {
            return Ok(None);
        };
        if current.session_lost && current.snapshot.terminal().is_none() {
            current.snapshot.derive_worker_loss()?;
        }
        Ok(Some(current.snapshot))
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
        self.mutate_action(
            tenant_id,
            session_id,
            action_id,
            expected_revision,
            placement,
            now,
            false,
            move |snapshot| Ok(snapshot.evidence.arm_dispatch(dispatch_id.clone())?),
        )
        .await
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
                if action_sequence.get() == 0 {
                    return Err(GatewayActionCoordinationError::InvalidActionSequence);
                }
                if snapshot.action_sequence() != action_sequence {
                    return Err(GatewayActionCoordinationError::ActionSequenceConflict);
                }
                Ok(snapshot
                    .evidence
                    .record_worker_result(dispatch_id, result)?)
            },
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
                if action_sequence.get() == 0 {
                    return Err(GatewayActionCoordinationError::InvalidActionSequence);
                }
                if snapshot.action_sequence() != action_sequence {
                    return Err(GatewayActionCoordinationError::ActionSequenceConflict);
                }
                Ok(snapshot
                    .evidence
                    .record_worker_terminal(dispatch_id, detail)?)
            },
        )
        .await
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
        .await
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
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        self.mutate_action(
            tenant_id,
            session_id,
            action_id,
            expected_revision,
            placement,
            now,
            true,
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
                snapshot.resolution = Some(annotation.clone());
                Ok(ActionEvidenceMutation::Recorded)
            },
        )
        .await
    }

    async fn mark_session_lost(
        &self,
        claim: &SessionLossClaim,
        now: DateTime<Utc>,
    ) -> Result<SessionLossOutcome, GatewayActionCoordinationError> {
        Self::validate_loss_claim(claim)?;
        let keys = self.keys(claim.tenant_id(), claim.session_id());
        let placement = Self::serialize_placement(claim.placement())?;
        let loss_id = claim.loss_id().to_string();
        let loss_at = now.to_rfc3339();
        let response: Vec<String> = self
            .execute(move |mut connection| async move {
                Script::new(MARK_LOSS_SCRIPT)
                    .key(keys.session)
                    .key(keys.actions)
                    .key(keys.idempotency)
                    .key(keys.pending)
                    .arg(placement)
                    .arg(loss_id)
                    .arg(loss_at)
                    .invoke_async(&mut connection)
                    .await
            })
            .await?;
        match response.as_slice() {
            [code] if code == "1" => Ok(SessionLossOutcome::Recorded),
            [code] if code == "2" => Ok(SessionLossOutcome::AlreadyRecorded),
            [code] if code == "0" => Err(GatewayActionCoordinationError::PlacementMismatch),
            [code] if code == "3" => {
                Err(GatewayActionCoordinationError::SessionLossIdentityConflict)
            }
            [code] if code == "6" => Err(GatewayActionCoordinationError::InvalidRedisResponse),
            _ => Err(GatewayActionCoordinationError::InvalidRedisResponse),
        }
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
        let keys = self.keys(claim.tenant_id(), claim.session_id());
        let placement = Self::serialize_placement(claim.placement())?;
        let loss_id = claim.loss_id().to_string();
        let limit_argument = limit.to_string();
        let response: Vec<String> = self
            .execute(move |mut connection| async move {
                Script::new(MATERIALIZE_CANDIDATES_SCRIPT)
                    .key(keys.session)
                    .key(keys.actions)
                    .key(keys.idempotency)
                    .key(keys.pending)
                    .arg(placement)
                    .arg(loss_id)
                    .arg(limit_argument)
                    .invoke_async(&mut connection)
                    .await
            })
            .await?;
        let candidates = match response.as_slice() {
            [code, values @ ..] if code == "3" && values.len().is_multiple_of(4) => values,
            [code] if code == "0" => {
                return Err(GatewayActionCoordinationError::PlacementMismatch);
            }
            [code] if code == "1" => {
                return Err(GatewayActionCoordinationError::SessionLossNotRecorded);
            }
            [code] if code == "2" => {
                return Err(GatewayActionCoordinationError::SessionLossIdentityConflict);
            }
            [code] if code == "6" => {
                return Err(GatewayActionCoordinationError::InvalidRedisResponse);
            }
            _ => return Err(GatewayActionCoordinationError::InvalidRedisResponse),
        };
        if candidates.len() / 4 > limit {
            return Err(GatewayActionCoordinationError::InvalidRedisResponse);
        }

        let prepared_count = candidates.len() / 4;
        let mut materialization_arguments = Vec::with_capacity(3 + prepared_count * 4);
        materialization_arguments.push(Self::serialize_placement(claim.placement())?);
        materialization_arguments.push(claim.loss_id().to_string());
        materialization_arguments.push(prepared_count.to_string());
        for fields in candidates.chunks_exact(4) {
            let action_id = &fields[0];
            let current_raw = &fields[1];
            let sequence = &fields[2];
            let reverse = &fields[3];
            let mut candidate = Self::decode_snapshot(current_raw, sequence)?;
            if candidate.tenant_id() != claim.tenant_id()
                || candidate.session_id() != claim.session_id()
                || candidate.action_id().to_string() != action_id.as_str()
                || candidate.idempotency_key() != reverse.as_str()
                || candidate.placement() != claim.placement()
                || candidate.terminal().is_some()
            {
                return Err(GatewayActionCoordinationError::InvalidRedisResponse);
            }
            candidate.derive_worker_loss()?;
            candidate.revision = candidate
                .revision
                .checked_add(1)
                .ok_or(GatewayActionCoordinationError::RevisionOverflow)?;
            candidate.updated_at = now;
            let candidate_raw = Self::serialize_snapshot(&candidate)?;
            materialization_arguments.push(action_id.clone());
            materialization_arguments.push(sequence.clone());
            materialization_arguments.push(current_raw.clone());
            materialization_arguments.push(candidate_raw);
        }
        let keys = self.keys(claim.tenant_id(), claim.session_id());
        let result: Vec<String> = self
            .execute(move |mut connection| async move {
                Script::new(MATERIALIZE_BATCH_SCRIPT)
                    .key(keys.session)
                    .key(keys.actions)
                    .key(keys.idempotency)
                    .key(keys.pending)
                    .arg(materialization_arguments)
                    .invoke_async(&mut connection)
                    .await
            })
            .await?;
        match result.as_slice() {
            [code, applied] if code == "3" => {
                let applied = applied
                    .parse::<usize>()
                    .map_err(|_| GatewayActionCoordinationError::InvalidRedisResponse)?;
                if applied != prepared_count {
                    return Err(GatewayActionCoordinationError::InvalidRedisResponse);
                }
                Ok(applied)
            }
            [code] if code == "4" => Ok(0),
            [code] if code == "0" => Err(GatewayActionCoordinationError::PlacementMismatch),
            [code] if code == "1" => Err(GatewayActionCoordinationError::SessionLossNotRecorded),
            [code] if code == "2" => {
                Err(GatewayActionCoordinationError::SessionLossIdentityConflict)
            }
            [code] if code == "6" => Err(GatewayActionCoordinationError::InvalidRedisResponse),
            _ => Err(GatewayActionCoordinationError::InvalidRedisResponse),
        }
    }
}
