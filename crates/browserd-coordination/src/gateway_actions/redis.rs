use std::fmt;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use browserd_actions::{
    ActionDeliveryEvidence, ActionEvidence, ActionEvidenceMutation, ActionKind, ActionSequence,
    ActionTerminalSource, BrowserResult, CanonicalRequestHash, DispatchId, ResolutionAnnotation,
    TerminalCustodyReceipt, TerminalCustodyRequirement, TerminalDetail, TransportLoss,
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
    GatewayActionCoordinationError, GatewayActionPlacement, GatewayActionRecoveryCursor,
    GatewayActionRecoveryPage, GatewayActionRetentionCursor, GatewayActionRetentionLimits,
    GatewayActionRetentionPage, GatewayActionSnapshot, GatewayActionSubmissionLease,
    GatewayCustodyCursor, GatewayCustodyPage, GatewayCustodyState, GatewayEventProjection,
    GatewayEventScanCursor, GatewayEventScanPage, GatewayEventSession, GatewayPendingCustody,
    GatewayTerminalCustodyCatchupPage, MAX_EVENT_SCAN_LIMIT, MAX_EVENT_SEQUENCE,
    MAX_MATERIALIZATION_LIMIT, MAX_RECOVERY_SCAN_LIMIT, SessionLossClaim, SessionLossOutcome,
    SessionLossReceipt, validate_durable_result_body, validated_idempotency_key,
};
use crate::session_admission::*;
use crate::{DirectoryFence, OutboxAppend, StoreConfig};

#[cfg(test)]
mod result_budget_tests;

mod fleet;
use fleet::FLEET_ACTION_SCRIPT;
mod custody;
use custody::CUSTODY_SCRIPT;
mod recovery;
use recovery::RECOVERY_SCRIPT;
pub use recovery::RedisGatewayActionMigrationProgress;
mod retention;
use retention::RETENTION_SCRIPT;

const MAX_SAFE_REDIS_INTEGER: u128 = 9_007_199_254_740_991;
const MAX_CAS_ATTEMPTS: usize = 16;
const MIN_EVENT_SCAN_COUNT: usize = 128;

// KEYS[5] is a persistent same-slot journal. Score zero + padded decimal members preserves the
// full integer range without Lua/ZSET floating point rounding. Validate before any source write.
const EVENT_JOURNAL_SCRIPT: &str = r#"
local function event_increment(value)
  if not value or not string.match(value, '^[0-9]+$') or (#value > 1 and string.sub(value, 1, 1) == '0') or #value > 19 or (#value == 19 and value >= '9223372036854775807') then return nil end
  local output, carry = '', 1
  for index = #value, 1, -1 do
    local digit = string.byte(value, index) - 48 + carry
    if digit == 10 then digit = 0 else carry = 0 end
    output = string.char(digit + 48) .. output
  end
  if carry == 1 then output = '1' .. output end
  return output
end
local function event_prepare(count)
  local kind = redis.call('TYPE', KEYS[5])['ok']
  if kind ~= 'none' and kind ~= 'zset' then return nil end
  if kind == 'zset' and redis.call('PTTL', KEYS[5]) ~= -1 then return nil end
  local sequence = redis.call('HGET', KEYS[1], 'event_sequence') or '0'
  local sequences = {}
  for index = 1, count do
    sequence = event_increment(sequence)
    if not sequence then return nil end
    sequences[index] = sequence
  end
  return sequences
end
local function event_write(sequence, payload)
  redis.call('HSET', KEYS[1], 'event_sequence', sequence)
  redis.call('ZADD', KEYS[5], 0, string.rep('0', 20 - #sequence) .. sequence .. '|' .. payload)
end
"#;

const CLAIM_SCRIPT: &str = r#"
local admission = fleet_action_gate(ARGV[11], ARGV[1], false)
if admission ~= 0 then return {tostring(admission)} end
if not recovery_valid() or not custody_valid() or not retention_valid() then return {'6'} end
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
if key_type(KEYS[1]) ~= 'none' and key_type(KEYS[1]) ~= 'hash' then return {'6'} end
if key_type(KEYS[2]) ~= 'none' and key_type(KEYS[2]) ~= 'hash' then return {'6'} end
if key_type(KEYS[3]) ~= 'none' and key_type(KEYS[3]) ~= 'hash' then return {'6'} end
if key_type(KEYS[4]) ~= 'none' and key_type(KEYS[4]) ~= 'zset' then return {'6'} end
local session_exists = redis.call('EXISTS', KEYS[1])
local action_exists = redis.call('EXISTS', KEYS[2])
local idempotency_exists = redis.call('EXISTS', KEYS[3])
if action_exists ~= idempotency_exists then return {'6'} end
if redis.call('HLEN', KEYS[3]) ~= redis.call('HLEN', KEYS[10]) or redis.call('HLEN', KEYS[2]) ~= redis.call('HLEN', KEYS[10]) * 3 then return {'6'} end
if action_exists == 0 and redis.call('EXISTS', KEYS[4]) == 1 then return {'6'} end
local last_sequence = '0'
local active_mutation = nil
local unresolved_mutation = nil
local active_dispatch = nil
local loss_id = nil
if session_exists == 1 then
  if redis.call('PTTL', KEYS[1]) ~= -1 then return {'6'} end
  local current_placement = redis.call('HGET', KEYS[1], 'placement')
  last_sequence = redis.call('HGET', KEYS[1], 'last_action_sequence')
  if not current_placement or not valid_u64(last_sequence) then return {'6'} end
  if current_placement ~= ARGV[1] then return {'0'} end
  active_mutation = redis.call('HGET', KEYS[1], 'active_mutation')
  unresolved_mutation = redis.call('HGET', KEYS[1], 'unresolved_mutation')
  active_dispatch = redis.call('HGET', KEYS[1], 'active_dispatch')
  loss_id = redis.call('HGET', KEYS[1], 'loss_id')
elseif action_exists == 1 or redis.call('EXISTS', KEYS[4]) == 1 then
  return {'6'}
end
local obligation = active_mutation or unresolved_mutation or active_dispatch or redis.call('ZCARD', KEYS[4]) > 0 or redis.call('ZCARD', KEYS[9]) > 0
if obligation and action_exists == 0 then return {'6'} end
local held = obligation or loss_id
if action_exists == 1 then
  local action_ttl = redis.call('PTTL', KEYS[2])
  local idempotency_ttl = redis.call('PTTL', KEYS[3])
  if action_ttl ~= -1 or idempotency_ttl ~= -1 then return {'6'} end
end
if redis.call('EXISTS', KEYS[4]) == 1 then
  local pending_ttl = redis.call('PTTL', KEYS[4])
  if pending_ttl ~= -1 then return {'6'} end
end
local existing_action_id = redis.call('HGET', KEYS[3], ARGV[2])
if existing_action_id then
  local payload = redis.call('HGET', KEYS[2], existing_action_id)
  local sequence = redis.call('HGET', KEYS[2], '@sequence:' .. existing_action_id)
  local reverse = redis.call('HGET', KEYS[2], '@idempotency:' .. existing_action_id)
  if not payload or not valid_u64(sequence) or sequence == '0' or reverse ~= ARGV[2] then return {'6'} end
  if pending_lookup(existing_action_id) and not redis.call('ZSCORE', KEYS[6], string.sub(ARGV[7], 1, #ARGV[7] - 36) .. existing_action_id) then return {'6'} end
  local indexed = redis.call('ZSCORE', KEYS[9], existing_action_id)
  local globally_indexed = redis.call('ZSCORE', KEYS[8], string.sub(ARGV[7], 1, #ARGV[7] - 36) .. existing_action_id)
  if (indexed and not globally_indexed) or (globally_indexed and not indexed) then return {'6'} end
  local metadata = retention_read(existing_action_id, string.sub(ARGV[7], 1, #ARGV[7] - 36) .. existing_action_id)
  if not metadata then return {'6'} end
  return {'2', payload, sequence, loss_id or '', existing_action_id, indexed and '1' or '0', metadata}
end
local admission = fleet_action_gate(ARGV[11], ARGV[1], true)
if admission ~= 0 then return {tostring(admission)} end
if loss_id then return {'3'} end
if ARGV[8] == 'expired' then return {'10'} end
if ARGV[8] == 'invalid' then return {'11'} end
if ARGV[9] ~= '0' then
  local expiry = tonumber(ARGV[9])
  if not expiry or expiry <= 0 or expiry > 9007199254740991 then return {'11'} end
  local now = recovery_now()
  local deadline = tonumber(ARGV[10])
  if not deadline or deadline < expiry or deadline > 9007199254740991 or deadline - now > 300000 then return {'11'} end
  if now >= expiry then return {'10'} end
end
if ARGV[6] == '1' and unresolved_mutation then return {'7', unresolved_mutation} end
local proposed_payload = redis.call('HGET', KEYS[2], ARGV[3])
local proposed_sequence = redis.call('HGET', KEYS[2], '@sequence:' .. ARGV[3])
local proposed_reverse = redis.call('HGET', KEYS[2], '@idempotency:' .. ARGV[3])
if proposed_payload or proposed_sequence or proposed_reverse then
  if not proposed_payload or not valid_u64(proposed_sequence) or proposed_sequence == '0' or not proposed_reverse or redis.call('HGET', KEYS[3], proposed_reverse) ~= ARGV[3] then return {'6'} end
  return {'4'}
end
if redis.call('ZCARD', KEYS[4]) + redis.call('ZCARD', KEYS[9]) >= 256 or redis.call('ZCARD', KEYS[6]) + redis.call('ZCARD', KEYS[8]) >= 65536 then return {'9'} end
if redis.call('HLEN', KEYS[10]) >= tonumber(redis.call('HGET', KEYS[7], 'retained_session')) or redis.call('ZCARD', KEYS[11]) >= tonumber(redis.call('HGET', KEYS[7], 'retained_global')) then return {'15'} end
if redis.call('HGET', KEYS[10], ARGV[3]) or redis.call('ZSCORE', KEYS[11], ARGV[7]) then return {'6'} end
local next_sequence = increment_u64(last_sequence)
if not next_sequence then return {'5'} end
if session_exists == 0 then
  redis.call('HSET', KEYS[1], 'placement', ARGV[1], 'last_action_sequence', next_sequence)
else
  redis.call('HSET', KEYS[1], 'last_action_sequence', next_sequence)
end
redis.call('HSET', KEYS[2], ARGV[3], ARGV[4], '@sequence:' .. ARGV[3], next_sequence, '@idempotency:' .. ARGV[3], ARGV[2])
redis.call('HSET', KEYS[3], ARGV[2], ARGV[3])
redis.call('ZADD', KEYS[4], 0, string.rep('0', 20 - #next_sequence) .. next_sequence .. '|' .. ARGV[3])
redis.call('HSET', KEYS[10], ARGV[3], '0|0')
redis.call('ZADD', KEYS[11], 0, ARGV[7])
redis.call('ZADD', KEYS[6], 0, ARGV[7])
redis.call('PERSIST', KEYS[2])
redis.call('PERSIST', KEYS[3])
redis.call('PERSIST', KEYS[4])
return {'1', ARGV[4], next_sequence, '', '0|0'}
"#;

const READ_SCRIPT: &str = r#"
if not recovery_valid() or not custody_valid() or not retention_valid() then return {'6'} end
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
if redis.call('HLEN', KEYS[3]) ~= redis.call('HLEN', KEYS[10]) or redis.call('HLEN', KEYS[2]) ~= redis.call('HLEN', KEYS[10]) * 3 then return {'6'} end
local loss_id = redis.call('HGET', KEYS[1], 'loss_id')
local active_mutation = redis.call('HGET', KEYS[1], 'active_mutation')
local unresolved_mutation = redis.call('HGET', KEYS[1], 'unresolved_mutation')
local active_dispatch = redis.call('HGET', KEYS[1], 'active_dispatch')
local obligation = active_mutation or unresolved_mutation or active_dispatch or redis.call('ZCARD', KEYS[4]) > 0 or redis.call('ZCARD', KEYS[9]) > 0
if action_exists == 0 then
  if obligation then return {'6'} end
  return {'0'}
end
local held = obligation or loss_id
local action_ttl = redis.call('PTTL', KEYS[2])
local idempotency_ttl = redis.call('PTTL', KEYS[3])
if action_ttl ~= -1 or idempotency_ttl ~= -1 then return {'6'} end
if redis.call('EXISTS', KEYS[4]) == 1 then
  local pending_ttl = redis.call('PTTL', KEYS[4])
  if pending_ttl ~= -1 then return {'6'} end
end
local payload = redis.call('HGET', KEYS[2], ARGV[1])
local sequence = redis.call('HGET', KEYS[2], '@sequence:' .. ARGV[1])
local reverse = redis.call('HGET', KEYS[2], '@idempotency:' .. ARGV[1])
if not payload and not sequence and not reverse then
  if redis.call('HGET', KEYS[10], ARGV[1]) or redis.call('ZSCORE', KEYS[11], ARGV[2]) or redis.call('ZSCORE', KEYS[9], ARGV[1]) or redis.call('ZSCORE', KEYS[8], ARGV[2]) then return {'6'} end
  return {'0'}
end
if not payload or not valid_u64(sequence) or sequence == '0' or not reverse or redis.call('HGET', KEYS[3], reverse) ~= ARGV[1] then return {'6'} end
if pending_lookup(ARGV[1]) and not redis.call('ZSCORE', KEYS[6], ARGV[2]) then return {'6'} end
local indexed = redis.call('ZSCORE', KEYS[9], ARGV[1])
local globally_indexed = redis.call('ZSCORE', KEYS[8], ARGV[2])
if (indexed and not globally_indexed) or (globally_indexed and not indexed) then return {'6'} end
local metadata = retention_read(ARGV[1], ARGV[2])
if not metadata then return {'6'} end
return {'1', payload, sequence, placement, loss_id or '', reverse, indexed and '1' or '0', metadata}
"#;

const MUTATE_SCRIPT: &str = r#"
if not recovery_valid() or not custody_valid() or not retention_valid() then return {'6'} end
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
if ARGV[7] == '1' and effect ~= 'resolve_mutation' and effect ~= 'resolve_read_only' and effect ~= 'custody' then return {'6'} end
if session_lost and ARGV[7] ~= '1' then return {'4'} end
local action_type = key_type(KEYS[2])
local idempotency_type = key_type(KEYS[3])
if action_type == 'none' and idempotency_type == 'none' then return {'3'} end
if action_type ~= 'hash' or idempotency_type ~= 'hash' then return {'6'} end
if key_type(KEYS[4]) ~= 'none' and key_type(KEYS[4]) ~= 'zset' then return {'6'} end
local active_mutation = redis.call('HGET', KEYS[1], 'active_mutation')
local unresolved_mutation = redis.call('HGET', KEYS[1], 'unresolved_mutation')
local held_before = active_mutation or unresolved_mutation or session_lost or redis.call('ZCARD', KEYS[4]) > 0 or redis.call('ZCARD', KEYS[9]) > 0
local action_ttl = redis.call('PTTL', KEYS[2])
local idempotency_ttl = redis.call('PTTL', KEYS[3])
if action_ttl ~= -1 or idempotency_ttl ~= -1 then return {'6'} end
if redis.call('EXISTS', KEYS[4]) == 1 then
  local pending_ttl = redis.call('PTTL', KEYS[4])
  if pending_ttl ~= -1 then return {'6'} end
end
local current = redis.call('HGET', KEYS[2], ARGV[2])
if not current then return {'3'} end
local sequence = redis.call('HGET', KEYS[2], '@sequence:' .. ARGV[2])
local reverse = redis.call('HGET', KEYS[2], '@idempotency:' .. ARGV[2])
if not valid_u64(sequence) or not reverse or redis.call('HGET', KEYS[3], reverse) ~= ARGV[2] then return {'6'} end
if current ~= ARGV[3] then return {'2'} end
local pending_type = key_type(KEYS[4])
local pending_score = nil
if pending_type == 'zset' then pending_score = pending_lookup(ARGV[2]) end
if effect == 'resolve_mutation' or effect == 'resolve_read_only' or effect == 'custody' then
  if pending_score then return {'6'} end
elseif pending_type ~= 'zset' or not pending_score then
  return {'6'}
end
if ARGV[11] ~= 'none' then
  local expiry = tonumber(ARGV[12])
  if not expiry or expiry <= 0 or expiry > 9007199254740991 then return {'6'} end
  local now = recovery_now()
  if ARGV[11] == 'arm' then
    local deadline = tonumber(ARGV[13])
    if not deadline or deadline < expiry or deadline > 9007199254740991 or deadline - now > 300000 then return {'13'} end
    if now >= expiry then return {'10'} end
  end
  if ARGV[11] == 'expire' and now < expiry then return {'11'} end
end
local arming = effect == 'arm_mutation' or effect == 'arm_read_only'
if arming then
  local admission = fleet_action_gate(ARGV[17], ARGV[1], true)
  if admission ~= 0 then return {tostring(admission)} end
end
local active_dispatch = redis.call('HGET', KEYS[1], 'active_dispatch')
if arming then
  if effect == 'arm_mutation' and unresolved_mutation then return {'7', unresolved_mutation} end
  if effect == 'arm_mutation' and active_mutation then return {'8', active_mutation} end
  if active_dispatch then return {'12', active_dispatch} end
  if ARGV[11] == 'arm' then
    local pending = pending_range(257)
    if not pending or #pending > 256 then return {'6'} end
    local oldest, oldest_sequence = ARGV[2], sequence
    for _, other in ipairs(pending) do
      local other_sequence = redis.call('HGET', KEYS[2], '@sequence:' .. other)
      if not valid_u64(other_sequence) then return {'6'} end
      if #other_sequence < #oldest_sequence or (#other_sequence == #oldest_sequence and other_sequence < oldest_sequence) then oldest, oldest_sequence = other, other_sequence end
    end
    if oldest ~= ARGV[2] then return {'12', oldest} end
  end
end
if pending_lookup(ARGV[2]) and not redis.call('ZSCORE', KEYS[6], ARGV[10]) then return {'6'} end
local next_active_dispatch, next_active_sequence = nil, nil
if ARGV[5] == '1' and active_dispatch == ARGV[2] then
  local pending = pending_range(257)
  if not pending or #pending > 256 then return {'6'} end
  for _, other in ipairs(pending) do
    if other ~= ARGV[2] and redis.call('HGET', KEYS[1], '@dispatch:' .. other) then
      local other_sequence = redis.call('HGET', KEYS[2], '@sequence:' .. other)
      if not valid_u64(other_sequence) then return {'6'} end
      if not next_active_sequence or #other_sequence < #next_active_sequence or (#other_sequence == #next_active_sequence and other_sequence < next_active_sequence) then next_active_dispatch, next_active_sequence = other, other_sequence end
    end
  end
end
local indexed = redis.call('ZSCORE', KEYS[9], ARGV[2])
local global_indexed = redis.call('ZSCORE', KEYS[8], ARGV[10])
if (indexed and not global_indexed) or (global_indexed and not indexed) then return {'6'} end
if (ARGV[14] == '1') ~= (indexed ~= false) then return {'6'} end
if ARGV[15] == '1' and not indexed and not pending_score then
  if redis.call('ZCARD', KEYS[4]) + redis.call('ZCARD', KEYS[9]) >= 256 or redis.call('ZCARD', KEYS[6]) + redis.call('ZCARD', KEYS[8]) >= 65536 then return {'14'} end
end
local metadata, _, prior_event_sequence = retention_read(ARGV[2], ARGV[10])
if not metadata then return {'6'} end
local deadline, old_deadline = nil, nil
if ARGV[5] == '1' then
  deadline, old_deadline = retention_prepare(ARGV[2], ARGV[10], ARGV[8])
  if not deadline then return {'6'} end
end
local event_count = ARGV[5] == '1' and ARGV[9] ~= '' and (ARGV[16] ~= '' and 2 or 1) or 0
local event_sequences = event_prepare(event_count)
if not event_sequences then return {'6'} end
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
elseif effect ~= 'none' and effect ~= 'arm_read_only' and effect ~= 'finish_read_only' and effect ~= 'custody' then
  return {'6'}
end
if effect == 'finish_mutation' or effect == 'unknown_mutation' then
  redis.call('HDEL', KEYS[1], 'active_mutation')
  if effect == 'unknown_mutation' then redis.call('HSET', KEYS[1], 'unresolved_mutation', ARGV[2]) end
end
if arming then
  redis.call('HSET', KEYS[1], 'active_dispatch', ARGV[2])
  redis.call('HSET', KEYS[1], '@dispatch:' .. ARGV[2], '1')
end
if ARGV[5] == '1' then
  redis.call('HDEL', KEYS[1], '@dispatch:' .. ARGV[2])
  if active_dispatch == ARGV[2] then
    redis.call('HDEL', KEYS[1], 'active_dispatch')
    if next_active_dispatch then redis.call('HSET', KEYS[1], 'active_dispatch', next_active_dispatch) end
  end
end
redis.call('HSET', KEYS[2], ARGV[2], ARGV[4])
if event_count == 2 then event_write(event_sequences[1], ARGV[16]) end
if event_count > 0 then
  event_write(event_sequences[event_count], ARGV[9])
end
if ARGV[5] == '1' then
  local retained_sequence = event_count > 0 and event_sequences[event_count] or prior_event_sequence
  retention_write(ARGV[2], ARGV[10], deadline, old_deadline, retained_sequence)
end
if ARGV[5] == '1' then
  redis.call('ZREM', KEYS[4], pending_member(ARGV[2]))
  redis.call('ZREM', KEYS[6], ARGV[10])
end
if ARGV[15] == '1' then
  redis.call('ZADD', KEYS[9], 0, ARGV[2])
  redis.call('ZADD', KEYS[8], 0, ARGV[10])
else
  redis.call('ZREM', KEYS[9], ARGV[2])
  redis.call('ZREM', KEYS[8], ARGV[10])
end
return {'1', ARGV[4], sequence, redis.call('HGET', KEYS[10], ARGV[2])}
"#;

const MARK_LOSS_SCRIPT: &str = r#"
if not recovery_valid() or not custody_valid() or not retention_valid() then return {'6'} end
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
if redis.call('HLEN', KEYS[3]) ~= redis.call('HLEN', KEYS[10]) or redis.call('HLEN', KEYS[2]) ~= redis.call('HLEN', KEYS[10]) * 3 then return {'6'} end
if exists == 1 then
  if redis.call('PTTL', KEYS[1]) ~= -1 then return {'6'} end
  local placement = redis.call('HGET', KEYS[1], 'placement')
  local last_sequence = redis.call('HGET', KEYS[1], 'last_action_sequence')
  if not placement or not valid_u64(last_sequence) then return {'6'} end
  if placement ~= ARGV[1] then return {'0'} end
  local active_mutation = redis.call('HGET', KEYS[1], 'active_mutation')
  local unresolved_mutation = redis.call('HGET', KEYS[1], 'unresolved_mutation')
  local current_loss = redis.call('HGET', KEYS[1], 'loss_id')
  local active_dispatch = redis.call('HGET', KEYS[1], 'active_dispatch')
  local obligation = active_mutation or unresolved_mutation or active_dispatch or redis.call('ZCARD', KEYS[4]) > 0 or redis.call('ZCARD', KEYS[9]) > 0
  if obligation and action_exists == 0 then return {'6'} end
  local held = obligation or current_loss
  if action_exists == 1 then
    local action_ttl = redis.call('PTTL', KEYS[2])
    local idempotency_ttl = redis.call('PTTL', KEYS[3])
    if action_ttl ~= -1 or idempotency_ttl ~= -1 then return {'6'} end
  end
  if redis.call('EXISTS', KEYS[4]) == 1 then
    local pending_ttl = redis.call('PTTL', KEYS[4])
    if pending_ttl ~= -1 then return {'6'} end
  end
  if current_loss then
    if current_loss == ARGV[2] or ARGV[6] == 'canonical' then return {'2', current_loss} end
    return {'3'}
  end
else
  if action_exists == 1 or redis.call('EXISTS', KEYS[4]) == 1 then return {'6'} end
end
local event_sequences = event_prepare(1)
if not event_sequences then return {'6'} end
if exists == 0 then redis.call('HSET', KEYS[1], 'placement', ARGV[1], 'last_action_sequence', '0') end
redis.call('HSET', KEYS[1], 'loss_id', ARGV[2], 'loss_at', ARGV[3])
event_write(event_sequences[1], ARGV[4])
if redis.call('ZCARD', KEYS[4]) > 0 or redis.call('ZCARD', KEYS[9]) > 0 then
  redis.call('HSET', KEYS[1], 'event_loss_claim', ARGV[5])
  redis.call('ZADD', KEYS[5], 0, '!loss')
end
redis.call('PERSIST', KEYS[1])
if action_exists == 1 then
  redis.call('PERSIST', KEYS[2])
  redis.call('PERSIST', KEYS[3])
end
if redis.call('EXISTS', KEYS[4]) == 1 then redis.call('PERSIST', KEYS[4]) end
return {'1', ARGV[2]}
"#;

const MATERIALIZE_CANDIDATES_SCRIPT: &str = r#"
if not recovery_valid() or not custody_valid() or not retention_valid() then return {'6'} end
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
local action_ids = pending_range(ARGV[3] + 0)
if not action_ids then return {'6'} end
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
if not recovery_valid() or not custody_valid() or not retention_valid() then return {'6'} end
local function key_type(key) return redis.call('TYPE', key)['ok'] end
if key_type(KEYS[1]) ~= 'hash' then return {'6'} end
if redis.call('PTTL', KEYS[1]) ~= -1 then return {'6'} end
local placement = redis.call('HGET', KEYS[1], 'placement')
if not placement or placement ~= ARGV[1] then return {'0'} end
local loss_id = redis.call('HGET', KEYS[1], 'loss_id')
if not loss_id then return {'1'} end
if loss_id ~= ARGV[2] then return {'2'} end
local count = ARGV[3] + 0
if count < 0 or count > 1000 or #ARGV ~= 4 + count * 6 then return {'6'} end
if count == 0 then return {'3', '0'} end
if key_type(KEYS[2]) == 'none' and key_type(KEYS[3]) == 'none' then return {'4'} end
if key_type(KEYS[2]) ~= 'hash' or key_type(KEYS[3]) ~= 'hash' then return {'6'} end
if key_type(KEYS[4]) == 'none' then return {'4'} end
if key_type(KEYS[4]) ~= 'zset' then return {'6'} end
if redis.call('PTTL', KEYS[2]) ~= -1 or redis.call('PTTL', KEYS[3]) ~= -1 or redis.call('PTTL', KEYS[4]) ~= -1 then return {'6'} end
local horizons = {}
for index = 0, count - 1 do
  local offset = 4 + index * 6
  local action_id = ARGV[offset]
  local expected_sequence = ARGV[offset + 1]
  local expected_payload = ARGV[offset + 2]
  local current = redis.call('HGET', KEYS[2], action_id)
  local sequence = redis.call('HGET', KEYS[2], '@sequence:' .. action_id)
  local reverse = redis.call('HGET', KEYS[2], '@idempotency:' .. action_id)
  if not current or sequence ~= expected_sequence or not reverse or redis.call('HGET', KEYS[3], reverse) ~= action_id then return {'6'} end
  if current ~= expected_payload or not pending_lookup(action_id) then return {'4'} end
  if not redis.call('ZSCORE', KEYS[6], ARGV[offset + 5]) then return {'6'} end
  local deadline, previous = retention_prepare(action_id, ARGV[offset + 5], ARGV[#ARGV])
  if not deadline or previous ~= '0' then return {'6'} end
  horizons[index + 1] = deadline
end
local event_sequences = event_prepare(count)
if not event_sequences then return {'6'} end
for index = 0, count - 1 do
  local offset = 4 + index * 6
  local action_id = ARGV[offset]
  redis.call('HSET', KEYS[2], action_id, ARGV[offset + 3])
  redis.call('ZREM', KEYS[4], pending_member(action_id))
  redis.call('ZREM', KEYS[6], ARGV[offset + 5])
  redis.call('HDEL', KEYS[1], '@dispatch:' .. action_id)
  if redis.call('HGET', KEYS[1], 'active_dispatch') == action_id then redis.call('HDEL', KEYS[1], 'active_dispatch') end
  event_write(event_sequences[index + 1], ARGV[offset + 4])
  retention_write(action_id, ARGV[offset + 5], horizons[index + 1], '0', event_sequences[index + 1])
end
if redis.call('ZCARD', KEYS[4]) == 0 then
  redis.call('HDEL', KEYS[1], 'event_loss_claim')
  redis.call('ZREM', KEYS[5], '!loss')
end
return {'3', tostring(count)}
"#;

const ACK_EVENT_SCRIPT: &str = r#"
if redis.call('TYPE', KEYS[1])['ok'] ~= 'hash' or redis.call('PTTL', KEYS[1]) ~= -1 then return {'6'} end
local ack = redis.call('HGET', KEYS[1], 'event_ack_sequence') or '0'
local sequence = ARGV[1]
if #sequence < #ack or (#sequence == #ack and sequence <= ack) then return {'1'} end
local kind = redis.call('TYPE', KEYS[2])['ok']
if kind ~= 'zset' or redis.call('PTTL', KEYS[2]) ~= -1 then return {'6'} end
local head = redis.call('ZRANGEBYLEX', KEYS[2], '[0', '+', 'LIMIT', 0, 1)
if #head ~= 1 or head[1] ~= ARGV[2] then return {'0'} end
redis.call('ZREM', KEYS[2], ARGV[2])
redis.call('HSET', KEYS[1], 'event_ack_sequence', sequence)
return {'1'}
"#;

const PEEK_EVENT_SCRIPT: &str = r#"
local session_type = redis.call('TYPE', KEYS[1])['ok']
local event_type = redis.call('TYPE', KEYS[2])['ok']
if session_type == 'none' and event_type == 'none' then return {'0'} end
if session_type ~= 'hash' or redis.call('PTTL', KEYS[1]) ~= -1 then return {'6'} end
local sequence = redis.call('HGET', KEYS[1], 'event_sequence') or '0'
local ack = redis.call('HGET', KEYS[1], 'event_ack_sequence') or '0'
if event_type == 'none' then
  if sequence ~= ack then return {'6'} end
  return {'0'}
end
if event_type ~= 'zset' or redis.call('PTTL', KEYS[2]) ~= -1 then return {'6'} end
local head = redis.call('ZRANGEBYLEX', KEYS[2], '[0', '+', 'LIMIT', 0, 1)
if #head == 0 then
  if sequence ~= ack then return {'6'} end
  return {'0'}
end
local expected = event_increment(ack)
if not expected or string.sub(head[1], 1, 21) ~= string.rep('0', 20 - #expected) .. expected .. '|' then return {'6'} end
return {'1', head[1]}
"#;

#[derive(Clone)]
pub struct RedisGatewayActionConfig {
    endpoint: String,
    key_prefix: String,
    store: StoreConfig,
    max_in_flight: usize,
    command_timeout: Duration,
    retention_limits: GatewayActionRetentionLimits,
    fleet_admission: Option<GatewayFleetAdmissionConfig>,
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
            retention_limits: GatewayActionRetentionLimits::default(),
            fleet_admission: None,
        })
    }
}

impl RedisGatewayActionConfig {
    #[must_use]
    pub fn with_fleet_admission(mut self, config: GatewayFleetAdmissionConfig) -> Self {
        self.fleet_admission = Some(config);
        self
    }

    #[must_use]
    pub fn with_retention_limits(mut self, limits: GatewayActionRetentionLimits) -> Self {
        self.retention_limits = limits;
        self
    }
}

impl fmt::Debug for RedisGatewayActionConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedisGatewayActionConfig")
            .field("endpoint", &"[REDACTED]")
            .field("key_prefix", &self.key_prefix)
            .field("store", &self.store)
            .field("retention_limits", &self.retention_limits)
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
    retention_permit: Arc<Semaphore>,
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
    #[serde(default)]
    result_budget: browserd_actions::ActionResultBudget,
    placement: PersistedPlacement,
    evidence: ActionEvidence,
    resolution: Option<ResolutionAnnotation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    custody: Option<GatewayCustodyState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    custody_requirement: Option<TerminalCustodyRequirement>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    original_worker_terminal_revision: Option<u64>,
    #[serde(default)]
    result_content: Option<Vec<u8>>,
    #[serde(default)]
    submission_lease: Option<GatewayActionSubmissionLease>,
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
            result_budget: claim.result_budget(),
            placement: PersistedPlacement::from(claim.placement()),
            evidence: ActionEvidence::new(),
            resolution: None,
            custody: None,
            custody_requirement: None,
            original_worker_terminal_revision: None,
            result_content: None,
            submission_lease: claim.submission_lease().cloned(),
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
            result_budget: snapshot.result_budget,
            placement: PersistedPlacement::from(&snapshot.placement),
            evidence: snapshot.evidence.clone(),
            resolution: snapshot.resolution.clone(),
            custody: snapshot.custody.clone(),
            custody_requirement: snapshot.custody_requirement,
            original_worker_terminal_revision: snapshot.original_worker_terminal_revision,
            result_content: snapshot.result_content.clone(),
            submission_lease: snapshot.submission_lease.clone(),
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
        if action_sequence.get() == 0
            || self.retain_until.timestamp_millis() <= 0
            || (self.evidence.terminal().is_none() && self.retain_until <= self.created_at)
        {
            return Err(GatewayActionCoordinationError::InvalidRedisResponse);
        }
        if !self.result_budget.is_valid_for(self.kind)
            || self
                .result_content
                .as_ref()
                .is_some_and(|body| body.is_empty() || body.len() > self.result_budget.max_bytes())
        {
            return Err(GatewayActionCoordinationError::InvalidRedisResponse);
        }
        if let Some(lease) = &self.submission_lease {
            lease
                .validate()
                .map_err(|_| GatewayActionCoordinationError::InvalidRedisResponse)?;
        }
        let snapshot = GatewayActionSnapshot {
            tenant_id: self.tenant_id,
            session_id: self.session_id,
            action_id: self.action_id,
            idempotency_key: validated_idempotency_key(self.idempotency_key)
                .map_err(|_| GatewayActionCoordinationError::InvalidRedisResponse)?,
            request_hash: self.request_hash,
            kind: self.kind,
            result_budget: self.result_budget,
            placement: self.placement.into_placement()?,
            evidence: self.evidence,
            resolution: self.resolution,
            custody: self.custody,
            custody_requirement: self.custody_requirement,
            original_worker_terminal_revision: self.original_worker_terminal_revision,
            result_content: self.result_content,
            submission_lease: self.submission_lease,
            action_sequence,
            revision: self.revision,
            created_at: self.created_at,
            updated_at: self.updated_at,
            retain_until: self.retain_until,
            last_source_event_sequence: None,
        };
        snapshot
            .validate_stored_custody()
            .map_err(|_| GatewayActionCoordinationError::InvalidRedisResponse)?;
        Ok(snapshot)
    }
}

struct RedisActionKeys {
    session: String,
    actions: String,
    idempotency: String,
    pending: String,
    events: String,
    recovery: String,
    format: String,
    custody: String,
    session_custody: String,
    retention: String,
    retained: String,
    retention_due: String,
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
    Custody,
    ArmMutation,
    ArmReadOnly,
    FinishReadOnly,
    FinishMutation,
    UnknownMutation,
    ResolveMutation,
    ResolveReadOnly,
}

impl SessionMutation {
    const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Custody => "custody",
            Self::ArmMutation => "arm_mutation",
            Self::ArmReadOnly => "arm_read_only",
            Self::FinishReadOnly => "finish_read_only",
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
        let store = Self::connect_unchecked(config).await?;
        store.ensure_recovery_format().await?;
        store.initialize_fleet().await?;
        Ok(store)
    }

    async fn connect_unchecked(
        config: RedisGatewayActionConfig,
    ) -> Result<Self, GatewayActionCoordinationError> {
        let client = redis::Client::open(config.endpoint.as_str())
            .map_err(|_| GatewayActionCoordinationError::RedisUnavailable)?;
        let connection = timeout(config.command_timeout, client.get_connection_manager())
            .await
            .map_err(|_| GatewayActionCoordinationError::RedisTimedOut)?
            .map_err(|_| GatewayActionCoordinationError::RedisUnavailable)?;
        let mut probe = connection.clone();
        let cluster: String = timeout(
            config.command_timeout,
            redis::cmd("INFO").arg("cluster").query_async(&mut probe),
        )
        .await
        .map_err(|_| GatewayActionCoordinationError::RedisTimedOut)?
        .map_err(|_| GatewayActionCoordinationError::RedisUnavailable)?;
        if !cluster
            .lines()
            .any(|line| line.trim() == "cluster_enabled:0")
        {
            return Err(GatewayActionCoordinationError::InvalidRedisConfig);
        }
        Ok(Self {
            connection,
            permits: Arc::new(Semaphore::new(config.max_in_flight)),
            retention_permit: Arc::new(Semaphore::new(1)),
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
            pending: format!("{namespace}:pending-v3"),
            events: format!("{namespace}:events-v1"),
            recovery: self.recovery_index_key(),
            format: self.recovery_format_key(),
            custody: self.custody_index_key(),
            session_custody: format!("{namespace}:custody-v1"),
            retention: format!("{namespace}:retention-v1"),
            retained: self.retained_index_key(),
            retention_due: self.retention_index_key(),
        }
    }

    async fn claim_action_inner(
        &self,
        claim: ClaimGatewayAction,
        now: DateTime<Utc>,
        authority: Option<&GatewaySessionAuthorityRef>,
    ) -> Result<GatewayActionClaimOutcome, GatewayActionCoordinationError> {
        if !claim.result_budget().is_valid_for(claim.kind()) {
            return Err(GatewayActionCoordinationError::CorruptState);
        }
        if let Some(authority) = authority {
            authority.validate()?;
            if authority.key().tenant_id() != claim.tenant_id()
                || authority.key().session_id() != claim.session_id()
                || authority.action_placement()? != *claim.placement()
            {
                return Err(GatewayActionCoordinationError::SessionAuthorityUnavailable);
            }
        }
        let authority_raw = self.action_authority_argument(authority)?;
        let fleet_state_key = self.fleet_state_key();
        let authority_key = self.fleet_authority_key(claim.tenant_id(), claim.session_id());
        if let Some(lease) = claim.submission_lease() {
            lease.validate()?;
        }
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
        let member = Self::recovery_member(
            claim.tenant_id(),
            claim.session_id(),
            claim.proposed_action_id(),
        );
        let lease_check = match claim
            .submission_lease()
            .map(|lease| lease.validate_claim(now))
        {
            Some(Err(GatewayActionCoordinationError::SubmissionLeaseExpired)) => "expired",
            Some(Err(_)) => "invalid",
            _ => "valid",
        };
        let expiry = claim
            .submission_lease()
            .map_or(0, |lease| lease.expires_at().timestamp_millis());
        let deadline = claim
            .submission_lease()
            .map_or(0, |lease| lease.admission_deadline().timestamp_millis());
        let mutating = if claim.kind() == ActionKind::Mutating {
            "1"
        } else {
            "0"
        };
        let response: Vec<String> = self
            .execute(move |mut connection| async move {
                Script::new(&format!(
                    "{RECOVERY_SCRIPT}{CUSTODY_SCRIPT}{RETENTION_SCRIPT}{FLEET_ACTION_SCRIPT}{CLAIM_SCRIPT}"
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
                .key(authority_key)
                .key(fleet_state_key)
                .arg(placement)
                .arg(idempotency_key)
                .arg(proposed_action_id)
                .arg(raw)
                .arg(retention_millis)
                .arg(mutating)
                .arg(member)
                .arg(lease_check)
                .arg(expiry)
                .arg(deadline)
                .arg(authority_raw)
                .invoke_async(&mut connection)
                .await
            })
            .await?;
        let (created, raw, sequence, loss_id, mapped_action_id, custody_pending, metadata) =
            match response.as_slice() {
                [code, raw, sequence, loss_id, metadata] if code == "1" => (
                    true,
                    raw,
                    sequence,
                    loss_id,
                    claim.proposed_action_id().to_string(),
                    false,
                    metadata,
                ),
                [
                    code,
                    raw,
                    sequence,
                    loss_id,
                    mapped_action_id,
                    custody_pending,
                    metadata,
                ] if code == "2" && matches!(custody_pending.as_str(), "0" | "1") => (
                    false,
                    raw,
                    sequence,
                    loss_id,
                    mapped_action_id.clone(),
                    custody_pending == "1",
                    metadata,
                ),
                [code] if code == "16" => {
                    return Err(GatewayActionCoordinationError::ManagedActionAdmissionRequired);
                }
                [code] if code == "17" => {
                    return Err(GatewayActionCoordinationError::SessionAuthorityUnavailable);
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
                [code] if code == "15" => {
                    return Err(GatewayActionCoordinationError::RetainedActionCapacity);
                }
                [code] if code == "9" => {
                    return Err(GatewayActionCoordinationError::PendingActionCapacity);
                }
                [code] if code == "10" => {
                    return Err(GatewayActionCoordinationError::SubmissionLeaseExpired);
                }
                [code] if code == "11" => {
                    return Err(GatewayActionCoordinationError::InvalidSubmissionLease);
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
        Self::apply_retention_metadata(&mut snapshot, metadata)?;
        if snapshot.pending_custody().is_some() != custody_pending {
            return Err(GatewayActionCoordinationError::InvalidRedisResponse);
        }
        if snapshot.tenant_id() != claim.tenant_id()
            || snapshot.session_id() != claim.session_id()
            || snapshot.action_id().to_string() != mapped_action_id
            || snapshot.idempotency_key() != claim.idempotency_key()
            || snapshot.placement() != claim.placement()
        {
            return Err(GatewayActionCoordinationError::InvalidRedisResponse);
        }
        if snapshot.request_hash() != claim.request_hash()
            || snapshot.kind() != claim.kind()
            || snapshot.result_budget() != claim.result_budget()
        {
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
        self.read_action_in_format(tenant_id, session_id, action_id, false)
            .await
    }

    async fn read_action_in_format(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        action_id: &ActionId,
        validating_catalog: bool,
    ) -> Result<Option<RawActionRead>, GatewayActionCoordinationError> {
        let keys = self.keys(tenant_id, session_id);
        let action_id_argument = action_id.to_string();
        let member = Self::recovery_member(tenant_id, session_id, action_id);
        let recovery_script = if validating_catalog {
            RECOVERY_SCRIPT.replace("'state') ~= 'ready'", "'state') ~= 'validating'")
        } else {
            RECOVERY_SCRIPT.to_owned()
        };
        let response: Vec<String> = self
            .execute(move |mut connection| async move {
                Script::new(&format!(
                    "{recovery_script}{CUSTODY_SCRIPT}{RETENTION_SCRIPT}{READ_SCRIPT}"
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
                .arg(action_id_argument)
                .arg(member)
                .invoke_async(&mut connection)
                .await
            })
            .await?;
        match response.as_slice() {
            [code] if code == "0" => Ok(None),
            [
                code,
                raw,
                sequence,
                placement,
                loss_id,
                reverse,
                custody_pending,
                retention_metadata,
            ] if code == "1" => {
                let mut snapshot = Self::decode_snapshot(raw, sequence)?;
                Self::apply_retention_metadata(&mut snapshot, retention_metadata)?;
                Self::validate_scope(&snapshot, tenant_id, session_id, action_id)?;
                if !matches!(custody_pending.as_str(), "0" | "1")
                    || snapshot.pending_custody().is_some() != (custody_pending == "1")
                {
                    return Err(GatewayActionCoordinationError::InvalidRedisResponse);
                }
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
        previous_custody_pending: bool,
        mut candidate: GatewayActionSnapshot,
        session_mutation: SessionMutation,
        allow_session_loss: bool,
        terminal_and_resolution: bool,
        authority: Option<&GatewaySessionAuthorityRef>,
    ) -> Result<CasMutation, GatewayActionCoordinationError> {
        let keys = self.keys(tenant_id, session_id);
        let authority_key = self.fleet_authority_key(tenant_id, session_id);
        let authority_raw = self.action_authority_argument(authority)?;
        let fleet_state_key = self.fleet_state_key();
        let placement = Self::serialize_placement(placement)?;
        let action_id = action_id.to_string();
        let candidate_raw = Self::serialize_snapshot(&candidate)?;
        let terminal = if candidate.terminal().is_some()
            && !matches!(session_mutation, SessionMutation::Custody)
        {
            "1"
        } else {
            "0"
        };
        let retention_millis = self.config.store.retention().as_millis().to_string();
        let event_append = candidate
            .terminal_outbox_append()
            .map(|append| serde_json::to_string(&append))
            .transpose()
            .map_err(|_| GatewayActionCoordinationError::InvalidRedisResponse)?
            .unwrap_or_default();
        let intermediate_event = if terminal_and_resolution && !event_append.is_empty() {
            serde_json::to_string(&OutboxAppend::action_terminal(
                tenant_id.clone(),
                session_id.clone(),
                candidate.action_id().clone(),
                candidate.revision - 1,
            ))
            .map_err(|_| GatewayActionCoordinationError::InvalidRedisResponse)?
        } else {
            String::new()
        };
        let member = Self::recovery_member(tenant_id, session_id, candidate.action_id());
        let custody_pending = candidate.pending_custody().is_some();
        let lease_mode = if candidate.submission_lease().is_some()
            && !matches!(session_mutation, SessionMutation::Custody)
        {
            match session_mutation {
                SessionMutation::ArmMutation | SessionMutation::ArmReadOnly => "arm",
                _ if matches!(candidate.delivery(), ActionDeliveryEvidence::NotAttempted)
                    && matches!(
                        candidate.terminal().map(|terminal| terminal.detail()),
                        Some(TerminalDetail::FailedKnown(
                            browserd_actions::KnownFailureReason::NotDispatched
                        ))
                    ) =>
                {
                    "expire"
                }
                _ => "none",
            }
        } else {
            "none"
        };
        let expiry = candidate
            .submission_lease()
            .map_or(0, |lease| lease.expires_at().timestamp_millis());
        let deadline = candidate
            .submission_lease()
            .map_or(0, |lease| lease.admission_deadline().timestamp_millis());
        let response: Vec<String> = self
            .execute(move |mut connection| async move {
                Script::new(&format!(
                    "{RECOVERY_SCRIPT}{CUSTODY_SCRIPT}{RETENTION_SCRIPT}{EVENT_JOURNAL_SCRIPT}{FLEET_ACTION_SCRIPT}{MUTATE_SCRIPT}"
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
                .key(authority_key)
                .key(fleet_state_key)
                .arg(placement)
                .arg(action_id)
                .arg(current_raw)
                .arg(candidate_raw)
                .arg(terminal)
                .arg(session_mutation.as_str())
                .arg(if allow_session_loss { "1" } else { "0" })
                .arg(retention_millis)
                .arg(event_append)
                .arg(member)
                .arg(lease_mode)
                .arg(expiry)
                .arg(deadline)
                .arg(if previous_custody_pending { "1" } else { "0" })
                .arg(if custody_pending { "1" } else { "0" })
                .arg(intermediate_event)
                .arg(authority_raw)
                .invoke_async(&mut connection)
                .await
            })
            .await?;
        match response.as_slice() {
            [code, raw, sequence, metadata] if code == "1" => {
                let mut stored = Self::decode_snapshot(raw, sequence)?;
                Self::apply_retention_metadata(&mut stored, metadata)?;
                Self::apply_retention_metadata(&mut candidate, metadata)?;
                Self::validate_scope(&stored, tenant_id, session_id, candidate.action_id())?;
                if stored != candidate {
                    return Err(GatewayActionCoordinationError::InvalidRedisResponse);
                }
                Ok(CasMutation::Applied(Box::new(stored)))
            }
            [code] if code == "16" => {
                Err(GatewayActionCoordinationError::ManagedActionAdmissionRequired)
            }
            [code] if code == "17" => {
                Err(GatewayActionCoordinationError::SessionAuthorityUnavailable)
            }
            [code] if code == "2" => Ok(CasMutation::Changed),
            [code] if code == "10" => Err(GatewayActionCoordinationError::SubmissionLeaseExpired),
            [code] if code == "11" => {
                Err(GatewayActionCoordinationError::SubmissionLeaseNotExpired)
            }
            [code] if code == "13" => Err(GatewayActionCoordinationError::InvalidSubmissionLease),
            [code, action_id] if code == "12" => {
                Err(GatewayActionCoordinationError::ActionDispatchInFlight {
                    action_id: Self::decode_action_id(action_id)?,
                })
            }
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
            [code] if code == "14" => Err(GatewayActionCoordinationError::PendingCustodyCapacity),
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
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn mutate_action_with_custody<F>(
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
        mutation: F,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError>
    where
        F: Fn(
                &mut GatewayActionSnapshot,
            ) -> Result<ActionEvidenceMutation, GatewayActionCoordinationError>
            + Send
            + Sync,
    {
        self.mutate_action_with_authority(
            tenant_id,
            session_id,
            action_id,
            expected_revision,
            placement,
            now,
            allow_session_loss,
            custody,
            requirement,
            None,
            mutation,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn mutate_action_with_authority<F>(
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
        authority: Option<&GatewaySessionAuthorityRef>,
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
            if current.session_lost && !allow_session_loss && current.snapshot.terminal().is_none()
            {
                return Err(GatewayActionCoordinationError::SessionLost);
            }
            let mut candidate = current.snapshot.clone();
            let attempted = mutation(&mut candidate);
            let recorded = matches!(attempted, Ok(ActionEvidenceMutation::Recorded));
            match attempted {
                Ok(ActionEvidenceMutation::AlreadyRecorded) => {
                    let changed = candidate.merge_custody_requirement(
                        requirement,
                        custody.as_ref(),
                        false,
                    )?;
                    if !candidate.attach_custody(custody.as_ref())? && !changed {
                        return Ok(current.snapshot);
                    }
                }
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
            let terminal_and_resolution =
                recorded && current.snapshot.terminal().is_none() && candidate.resolution.is_some();
            if recorded {
                candidate.revision = candidate
                    .revision
                    .checked_add(if terminal_and_resolution { 2 } else { 1 })
                    .ok_or(GatewayActionCoordinationError::RevisionOverflow)?;
                candidate.updated_at = now;
                if current.snapshot.terminal().is_none()
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
                    current.snapshot.terminal().is_none() && candidate.terminal().is_some(),
                )?;
                candidate.attach_custody(custody.as_ref())?;
            }
            let session_mutation = if !recorded {
                SessionMutation::Custody
            } else if matches!(
                current.snapshot.delivery(),
                ActionDeliveryEvidence::NotAttempted
            ) && matches!(
                candidate.delivery(),
                ActionDeliveryEvidence::DispatchArmed(_)
            ) {
                if current.snapshot.kind() == ActionKind::Mutating {
                    SessionMutation::ArmMutation
                } else {
                    SessionMutation::ArmReadOnly
                }
            } else if !matches!(
                current.snapshot.delivery(),
                ActionDeliveryEvidence::NotAttempted
            ) && current.snapshot.terminal().is_none()
                && candidate.terminal().is_some()
            {
                if current.snapshot.kind() == ActionKind::ReadOnly {
                    SessionMutation::FinishReadOnly
                } else if candidate.requires_reconciliation() {
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
                    current.snapshot.pending_custody().is_some(),
                    candidate,
                    session_mutation,
                    allow_session_loss || current.session_lost,
                    terminal_and_resolution,
                    authority,
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
        if current.session_lost && !allow_session_loss && current.snapshot.terminal().is_none() {
            return Err(GatewayActionCoordinationError::SessionLost);
        }
        Err(GatewayActionCoordinationError::StaleWrite(Box::new(
            current.snapshot,
        )))
    }

    async fn record_session_loss(
        &self,
        claim: &SessionLossClaim,
        now: DateTime<Utc>,
        strict_identity: bool,
    ) -> Result<SessionLossReceipt, GatewayActionCoordinationError> {
        Self::validate_loss_claim(claim)?;
        let keys = self.keys(claim.tenant_id(), claim.session_id());
        let placement = Self::serialize_placement(claim.placement())?;
        let loss_id = claim.loss_id().to_string();
        let loss_at = now.to_rfc3339();
        let event_append = serde_json::to_string(&OutboxAppend::session_lost(
            claim.tenant_id().clone(),
            claim.session_id().clone(),
            claim.placement().directory_revision(),
        ))
        .map_err(|_| GatewayActionCoordinationError::InvalidRedisResponse)?;
        let loss_claim = serde_json::to_string(claim)
            .map_err(|_| GatewayActionCoordinationError::InvalidRedisResponse)?;
        let response: Vec<String> = self
            .execute(move |mut connection| async move {
                Script::new(&format!(
                    "{RECOVERY_SCRIPT}{CUSTODY_SCRIPT}{RETENTION_SCRIPT}{EVENT_JOURNAL_SCRIPT}{MARK_LOSS_SCRIPT}"
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
                .arg(placement)
                .arg(loss_id)
                .arg(loss_at)
                .arg(event_append)
                .arg(loss_claim)
                .arg(if strict_identity {
                    "strict"
                } else {
                    "canonical"
                })
                .invoke_async(&mut connection)
                .await
            })
            .await?;
        match response.as_slice() {
            [code, canonical_id] if code == "1" || code == "2" => {
                let loss_id = Uuid::parse_str(canonical_id)
                    .map_err(|_| GatewayActionCoordinationError::InvalidRedisResponse)?;
                if loss_id.get_version() != Some(Version::SortRand)
                    || loss_id.to_string() != *canonical_id
                    || ((code == "1" || strict_identity) && &loss_id != claim.loss_id())
                {
                    return Err(GatewayActionCoordinationError::InvalidRedisResponse);
                }
                Ok(SessionLossReceipt {
                    claim: SessionLossClaim::new(
                        claim.tenant_id().clone(),
                        claim.session_id().clone(),
                        claim.placement().clone(),
                        loss_id,
                    ),
                    outcome: if code == "1" {
                        SessionLossOutcome::Recorded
                    } else {
                        SessionLossOutcome::AlreadyRecorded
                    },
                })
            }
            [code] if code == "0" => Err(GatewayActionCoordinationError::PlacementMismatch),
            [code] if code == "3" => {
                Err(GatewayActionCoordinationError::SessionLossIdentityConflict)
            }
            [code] if code == "6" => Err(GatewayActionCoordinationError::InvalidRedisResponse),
            _ => Err(GatewayActionCoordinationError::InvalidRedisResponse),
        }
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
        const LIST: &str = r#"
local records=redis.call('TYPE',KEYS[1])['ok']; local index=redis.call('TYPE',KEYS[2])['ok']
if (records~='none' and records~='hash') or (index~='none' and index~='zset') then return {'invalid'} end
if (records~='none' and redis.call('PTTL',KEYS[1])~=-1) or (index~='none' and redis.call('PTTL',KEYS[2])~=-1) then return {'invalid'} end
local ceiling=ARGV[2]; if ceiling=='' then ceiling=(redis.call('ZREVRANGE',KEYS[2],0,0)[1] or '') end
if ceiling=='' or (ARGV[1]~='' and ARGV[1]>=ceiling) then return {'ok',ceiling,'0'} end
local lower='-'; if ARGV[1]~='' then lower='('..ARGV[1] end
local sessions=redis.call('ZRANGEBYLEX',KEYS[2],lower,'['..ceiling,'LIMIT',0,tonumber(ARGV[3])+1)
local more='0'; if #sessions>tonumber(ARGV[3]) then more='1'; table.remove(sessions) end
local result={'ok',ceiling,more}
for _,session in ipairs(sessions) do local raw=redis.call('HGET',KEYS[1],ARGV[4]..':'..session); if not raw then return {'invalid'} end; table.insert(result,session); table.insert(result,raw) end
return result
"#;
        let records = format!(
            "{}:gateway-directory:{{single-host-v1}}:records",
            self.config.key_prefix
        );
        let index = format!(
            "{}:gateway-directory:{{single-host-v1}}:tenant:{}:sessions",
            self.config.key_prefix, tenant_id
        );
        let after = after.map_or_else(String::new, ToString::to_string);
        let ceiling = ceiling.map_or_else(String::new, ToString::to_string);
        let tenant = tenant_id.to_string();
        let raw: Vec<String> = self
            .execute(move |mut connection| async move {
                Script::new(LIST)
                    .key(records)
                    .key(index)
                    .arg(after)
                    .arg(ceiling)
                    .arg(limit)
                    .arg(tenant)
                    .invoke_async(&mut connection)
                    .await
            })
            .await?;
        if raw.len() < 3
            || raw[0] != "ok"
            || !matches!(raw[2].as_str(), "0" | "1")
            || raw.len() > limit * 2 + 3
            || !(raw.len() - 3).is_multiple_of(2)
        {
            return Err(GatewayActionCoordinationError::InvalidSessionDirectory);
        }
        let ceiling = if raw[1].is_empty() {
            None
        } else {
            Some(
                raw[1]
                    .parse::<SessionId>()
                    .map_err(|_| GatewayActionCoordinationError::InvalidSessionDirectory)?,
            )
        };
        let records = raw[3..]
            .chunks_exact(2)
            .map(|pair| {
                if pair[1].len() > crate::MAX_SESSION_DIRECTORY_BYTES {
                    return Err(GatewayActionCoordinationError::InvalidSessionDirectory);
                }
                let record: crate::GatewaySessionDirectoryRecord =
                    serde_json::from_str(&pair[1])
                        .map_err(|_| GatewayActionCoordinationError::InvalidSessionDirectory)?;
                if record.session_id().to_string() != pair[0] {
                    return Err(GatewayActionCoordinationError::InvalidSessionDirectory);
                }
                Ok(record)
            })
            .collect::<Result<Vec<crate::GatewaySessionDirectoryRecord>, _>>()?;
        crate::GatewaySessionDirectoryPage::new(tenant_id, records, ceiling, raw[2] == "1")
    }
    async fn get_single_host_directory(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
    ) -> Result<Option<crate::GatewaySessionDirectoryRecord>, GatewayActionCoordinationError> {
        let records = format!(
            "{}:gateway-directory:{{single-host-v1}}:records",
            self.config.key_prefix
        );
        let field = format!("{tenant_id}:{session_id}");
        let raw: Option<String> = self
            .execute(|mut connection| async move {
                redis::cmd("HGET")
                    .arg(records)
                    .arg(field)
                    .query_async(&mut connection)
                    .await
            })
            .await?;
        raw.map(|raw| {
            if raw.len() > crate::MAX_SESSION_DIRECTORY_BYTES {
                return Err(GatewayActionCoordinationError::InvalidSessionDirectory);
            }
            let record: crate::GatewaySessionDirectoryRecord = serde_json::from_str(&raw)
                .map_err(|_| GatewayActionCoordinationError::InvalidSessionDirectory)?;
            if record.tenant_id() != tenant_id || record.session_id() != session_id {
                return Err(GatewayActionCoordinationError::PlacementMismatch);
            }
            Ok(record)
        })
        .transpose()
    }
    async fn commit_single_host_directory(
        &self,
        record: crate::GatewaySessionDirectoryRecord,
        expected_revision: Option<u64>,
    ) -> Result<crate::GatewaySessionDirectoryRecord, GatewayActionCoordinationError> {
        record.validate()?;
        let records = format!(
            "{}:gateway-directory:{{single-host-v1}}:records",
            self.config.key_prefix
        );
        let expiry = format!(
            "{}:gateway-directory:{{single-host-v1}}:expiry",
            self.config.key_prefix
        );
        let tenant_index_prefix = format!(
            "{}:gateway-directory:{{single-host-v1}}:tenant:",
            self.config.key_prefix
        );
        let index = format!("{tenant_index_prefix}{}:sessions", record.tenant_id());
        let field = format!("{}:{}", record.tenant_id(), record.session_id());
        const COMMIT: &str = r#"
local kind=redis.call('TYPE',KEYS[1])['ok']; local due=redis.call('TYPE',KEYS[2])['ok']; local index=redis.call('TYPE',KEYS[3])['ok']
if (kind~='none' and kind~='hash') or (due~='none' and due~='zset') or (index~='none' and index~='zset') then return {'invalid'} end
if (kind~='none' and redis.call('PTTL',KEYS[1])~=-1) or (due~='none' and redis.call('PTTL',KEYS[2])~=-1) or (index~='none' and redis.call('PTTL',KEYS[3])~=-1) then return {'invalid'} end
if (redis.call('HGET',KEYS[1],ARGV[1]) or '') ~= ARGV[2] then return {'changed'} end
local time=redis.call('TIME'); local now=time[1]*1000+math.floor(time[2]/1000)
local expired=redis.call('ZRANGEBYSCORE',KEYS[2],'-inf',now,'LIMIT',0,32)
local expired_indices={}
for _,member in ipairs(expired) do
 local tenant,session=string.match(member,'^([^:]+):([^:]+)$'); if not tenant or not session then return {'invalid'} end
 local key=ARGV[6]..tenant..':sessions'; local t=redis.call('TYPE',key)['ok']
 if (t~='none' and t~='zset') or (t~='none' and redis.call('PTTL',key)~=-1) then return {'invalid'} end
 table.insert(expired_indices,{key,session})
end
for i,member in ipairs(expired) do redis.call('HDEL',KEYS[1],member); redis.call('ZREM',KEYS[2],member); redis.call('ZREM',expired_indices[i][1],expired_indices[i][2]) end
if redis.call('HEXISTS',KEYS[1],ARGV[1])==0 and redis.call('HLEN',KEYS[1])>=tonumber(ARGV[5]) then return {'capacity'} end
redis.call('HSET',KEYS[1],ARGV[1],ARGV[3])
redis.call('ZADD',KEYS[3],0,ARGV[7])
if ARGV[4]~='0' then redis.call('ZADD',KEYS[2],ARGV[4],ARGV[1]) else redis.call('ZREM',KEYS[2],ARGV[1]) end
return {'ok'}
"#;
        for _ in 0..MAX_CAS_ATTEMPTS {
            let old = self
                .get_single_host_directory(record.tenant_id(), record.session_id())
                .await?;
            let committed = if let Some(old) = &old {
                old.checked_commit(&record, expected_revision)?
            } else {
                if expected_revision.is_some() {
                    return Err(GatewayActionCoordinationError::SessionDirectoryConflict);
                }
                record.clone()
            };
            if old.as_ref() == Some(&committed) {
                return Ok(committed);
            }
            let expected = old
                .as_ref()
                .map(serde_json::to_string)
                .transpose()
                .map_err(|_| GatewayActionCoordinationError::InvalidSessionDirectory)?
                .unwrap_or_default();
            let raw = serde_json::to_string(&committed)
                .map_err(|_| GatewayActionCoordinationError::InvalidSessionDirectory)?;
            if raw.len() > crate::MAX_SESSION_DIRECTORY_BYTES {
                return Err(GatewayActionCoordinationError::InvalidSessionDirectory);
            }
            let deadline = if committed.lifecycle().terminal() {
                committed
                    .updated_at()
                    .timestamp_millis()
                    .checked_add(
                        i64::try_from(self.config.store.retention().as_millis())
                            .map_err(|_| GatewayActionCoordinationError::InvalidSessionDirectory)?,
                    )
                    .ok_or(GatewayActionCoordinationError::RevisionOverflow)?
            } else {
                0
            };
            let records_key = records.clone();
            let expiry_key = expiry.clone();
            let record_field = field.clone();
            let index_key = index.clone();
            let index_prefix = tenant_index_prefix.clone();
            let session = record.session_id().to_string();
            let result: Vec<String> = self
                .execute(move |mut connection| async move {
                    Script::new(COMMIT)
                        .key(records_key)
                        .key(expiry_key)
                        .key(index_key)
                        .arg(record_field)
                        .arg(expected)
                        .arg(raw)
                        .arg(deadline)
                        .arg(crate::MAX_SESSION_DIRECTORY_RECORDS)
                        .arg(index_prefix)
                        .arg(session)
                        .invoke_async(&mut connection)
                        .await
                })
                .await?;
            match result.first().map(String::as_str) {
                Some("ok") => return Ok(committed),
                Some("changed") => continue,
                Some("capacity") => {
                    return Err(GatewayActionCoordinationError::SessionDirectoryCapacity);
                }
                _ => return Err(GatewayActionCoordinationError::InvalidSessionDirectory),
            }
        }
        Err(GatewayActionCoordinationError::SessionDirectoryConflict)
    }
    async fn get_action_by_idempotency(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        key: &str,
    ) -> Result<Option<GatewayActionSnapshot>, GatewayActionCoordinationError> {
        let key = validated_idempotency_key(key.to_owned())?;
        let keys = self.keys(tenant_id, session_id);
        let id: Option<String> = self
            .execute(|mut connection| async move {
                redis::cmd("HGET")
                    .arg(keys.idempotency)
                    .arg(key.as_str())
                    .query_async(&mut connection)
                    .await
            })
            .await?;
        let Some(id) = id else {
            return Ok(None);
        };
        let id = ActionId::from_uuid(
            Uuid::parse_str(&id)
                .map_err(|_| GatewayActionCoordinationError::InvalidRedisResponse)?,
        )
        .map_err(|_| GatewayActionCoordinationError::InvalidRedisResponse)?;
        self.get_effective_action(tenant_id, session_id, &id).await
    }
    async fn enqueue_session_admission(
        &self,
        request: GatewaySessionAdmissionRequest,
    ) -> Result<GatewaySessionAdmissionSnapshot, GatewayActionCoordinationError> {
        self.fleet_enqueue(request).await
    }
    async fn get_session_admission(
        &self,
        key: &GatewaySessionAdmissionKey,
    ) -> Result<Option<GatewaySessionAdmissionSnapshot>, GatewayActionCoordinationError> {
        self.fleet_get(key).await
    }
    async fn observe_fleet_worker(
        &self,
        observation: GatewayFleetWorkerObservation,
        ttl: Duration,
    ) -> Result<(), GatewayActionCoordinationError> {
        self.fleet_observe(observation, ttl).await
    }
    async fn reserve_next_session(
        &self,
        ttl: Duration,
    ) -> Result<Option<GatewaySessionAdmissionSnapshot>, GatewayActionCoordinationError> {
        self.fleet_reserve(ttl).await
    }
    async fn record_session_reservation(
        &self,
        expected: &GatewaySessionAdmissionSnapshot,
        proof: GatewaySessionWorkerReservationProof,
    ) -> Result<GatewaySessionAdmissionSnapshot, GatewayActionCoordinationError> {
        self.fleet_record_reservation(expected, proof).await
    }
    async fn arm_session_create(
        &self,
        expected: &GatewaySessionAdmissionSnapshot,
        dispatch: &crate::DispatchLeaseToken,
        ttl: Duration,
    ) -> Result<GatewaySessionAdmissionSnapshot, GatewayActionCoordinationError> {
        self.fleet_arm(expected, dispatch, ttl).await
    }
    async fn commit_session_placement(
        &self,
        expected: &GatewaySessionAdmissionSnapshot,
        proof: GatewaySessionWorkerReadyProof,
    ) -> Result<GatewaySessionPlacementAuthority, GatewayActionCoordinationError> {
        self.fleet_commit(expected, proof).await
    }
    async fn resolve_session_placement(
        &self,
        key: &crate::DirectoryKey,
    ) -> Result<Option<GatewaySessionPlacementAuthority>, GatewayActionCoordinationError> {
        self.fleet_resolve(key).await
    }
    async fn validate_session_authority(
        &self,
        authority: &GatewaySessionAuthorityRef,
    ) -> Result<(), GatewayActionCoordinationError> {
        self.fleet_validate_authority(authority).await
    }

    async fn begin_session_renewal(
        &self,
        expected: &GatewaySessionPlacementAuthority,
        nonce: browserd_core::LeaseId,
        ttl: Duration,
    ) -> Result<GatewaySessionRenewalIntent, GatewayActionCoordinationError> {
        self.fleet_begin_renewal(expected, nonce, ttl).await
    }
    async fn finish_session_renewal(
        &self,
        intent: &GatewaySessionRenewalIntent,
        proof: GatewaySessionWorkerRenewalProof,
    ) -> Result<GatewaySessionPlacementAuthority, GatewayActionCoordinationError> {
        self.fleet_finish_renewal(intent, proof).await
    }
    async fn begin_session_close(
        &self,
        expected: &GatewaySessionPlacementAuthority,
    ) -> Result<GatewaySessionPlacementAuthority, GatewayActionCoordinationError> {
        self.fleet_close(expected).await
    }
    async fn release_session_reservation(
        &self,
        expected: &GatewaySessionAdmissionSnapshot,
        proof: GatewaySessionCleanupProof,
    ) -> Result<GatewaySessionAdmissionSnapshot, GatewayActionCoordinationError> {
        self.fleet_release(expected, proof).await
    }
    async fn scan_session_admissions(
        &self,
        cursor: GatewaySessionAdmissionCursor,
        limit: usize,
    ) -> Result<GatewaySessionAdmissionPage, GatewayActionCoordinationError> {
        self.fleet_scan(cursor, limit).await
    }
    async fn ack_session_create_projection(
        &self,
        expected: &GatewaySessionAdmissionSnapshot,
    ) -> Result<GatewaySessionAdmissionSnapshot, GatewayActionCoordinationError> {
        self.fleet_ack_projection(expected).await
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
        self.fleet_config()?;
        if authority.key().tenant_id() != tenant_id
            || authority.key().session_id() != session_id
            || authority.action_placement()? != *placement
        {
            return Err(GatewayActionCoordinationError::SessionAuthorityUnavailable);
        }
        self.mutate_action_with_authority(
            tenant_id,
            session_id,
            action_id,
            expected_revision,
            placement,
            now,
            false,
            None,
            None,
            Some(authority),
            |snapshot| {
                snapshot.validate_submission_lease(lease, now, false)?;
                Ok(snapshot.evidence.arm_dispatch(dispatch_id.clone())?)
            },
        )
        .await
    }

    async fn maintain_action_retention(
        &self,
        cursor: GatewayActionRetentionCursor,
        limit: usize,
    ) -> Result<GatewayActionRetentionPage, GatewayActionCoordinationError> {
        self.maintain_retention(cursor, limit).await
    }

    async fn scan_terminal_custody_catchup(
        &self,
        cursor: GatewayActionRecoveryCursor,
        limit: usize,
    ) -> Result<GatewayTerminalCustodyCatchupPage, GatewayActionCoordinationError> {
        self.scan_custody_catchup(cursor, limit).await
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
        self.attach_custody_catchup(
            tenant_id,
            session_id,
            action_id,
            expected_revision,
            placement,
            receipt,
        )
        .await
    }

    async fn scan_pending_custody(
        &self,
        cursor: GatewayCustodyCursor,
        limit: usize,
    ) -> Result<GatewayCustodyPage, GatewayActionCoordinationError> {
        self.scan_custody(cursor, limit).await
    }
    async fn ack_pending_custody(
        &self,
        entry: &GatewayPendingCustody,
        _now: DateTime<Utc>,
    ) -> Result<(), GatewayActionCoordinationError> {
        self.ack_custody(entry, false).await
    }

    async fn complete_custody_release(
        &self,
        entry: &GatewayPendingCustody,
        _now: DateTime<Utc>,
    ) -> Result<(), GatewayActionCoordinationError> {
        self.ack_custody(entry, true).await
    }

    async fn scan_pending_actions(
        &self,
        cursor: GatewayActionRecoveryCursor,
        limit: usize,
    ) -> Result<GatewayActionRecoveryPage, GatewayActionCoordinationError> {
        self.scan_recovery(cursor, limit).await
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
        self.require_legacy_admission().await?;
        self.mutate_action(
            tenant_id,
            session_id,
            action_id,
            expected_revision,
            placement,
            now,
            false,
            |snapshot| {
                snapshot.validate_submission_lease(lease, now, false)?;
                Ok(snapshot.evidence.arm_dispatch(dispatch_id.clone())?)
            },
        )
        .await
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
        .await
    }

    async fn scan_event_sessions(
        &self,
        mut cursor: GatewayEventScanCursor,
        limit: usize,
    ) -> Result<GatewayEventScanPage, GatewayActionCoordinationError> {
        if !(1..=MAX_EVENT_SCAN_LIMIT).contains(&limit) {
            return Err(GatewayActionCoordinationError::InvalidEventScanLimit);
        }
        if cursor.redis_pending.is_empty() {
            let pattern = format!("{}:gateway-action:{{*}}:events-v1", self.config.key_prefix);
            let scan_cursor = cursor.redis_cursor;
            // One SCAN command per page: COUNT bounds effort approximately, not its response size.
            // A small result limit must not reduce progress through unrelated shared keys to
            // one key per round trip. Keep scan work bounded independently of the result page.
            let scan_count = limit.max(MIN_EVENT_SCAN_COUNT);
            // Preserve all returned scopes in the opaque cursor so a large Redis page loses none.
            let (next, keys): (u64, Vec<String>) = self
                .execute(move |mut connection| async move {
                    redis::cmd("SCAN")
                        .arg(scan_cursor)
                        .arg("MATCH")
                        .arg(pattern)
                        .arg("COUNT")
                        .arg(scan_count)
                        .query_async(&mut connection)
                        .await
                })
                .await?;
            cursor.redis_cursor = next;
            let prefix = format!("{}:gateway-action:{{", self.config.key_prefix);
            for key in keys {
                let scope = key
                    .strip_prefix(&prefix)
                    .and_then(|value| value.strip_suffix("}:events-v1"))
                    .and_then(|value| value.split_once(':'))
                    .ok_or(GatewayActionCoordinationError::InvalidRedisResponse)?;
                let tenant = scope
                    .0
                    .parse()
                    .map_err(|_| GatewayActionCoordinationError::InvalidRedisResponse)?;
                let session = scope
                    .1
                    .parse()
                    .map_err(|_| GatewayActionCoordinationError::InvalidRedisResponse)?;
                cursor.redis_pending.push_back((tenant, session));
            }
        }
        let mut sessions = Vec::new();
        for _ in 0..limit {
            let Some((tenant_id, session_id)) = cursor.redis_pending.pop_front() else {
                break;
            };
            let keys = self.keys(&tenant_id, &session_id);
            let raw: Option<String> = self
                .execute(move |mut connection| async move {
                    redis::cmd("HGET")
                        .arg(keys.session)
                        .arg("event_loss_claim")
                        .query_async(&mut connection)
                        .await
                })
                .await?;
            let loss_claim = raw
                .map(|value| serde_json::from_str::<SessionLossClaim>(&value))
                .transpose()
                .map_err(|_| GatewayActionCoordinationError::InvalidRedisResponse)?;
            if let Some(claim) = &loss_claim {
                Self::validate_loss_claim(claim)?;
                if claim.tenant_id() != &tenant_id
                    || claim.session_id() != &session_id
                    || claim.placement().directory_revision() == 0
                {
                    return Err(GatewayActionCoordinationError::InvalidRedisResponse);
                }
            }
            sessions.push(GatewayEventSession {
                tenant_id,
                session_id,
                loss_claim,
            });
        }
        let complete = cursor.redis_cursor == 0 && cursor.redis_pending.is_empty();
        Ok(GatewayEventScanPage {
            sessions,
            next_cursor: cursor,
            complete,
        })
    }

    async fn peek_event_projection(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
    ) -> Result<Option<GatewayEventProjection>, GatewayActionCoordinationError> {
        let keys = self.keys(tenant_id, session_id);
        let raw: Vec<String> = self
            .execute(move |mut connection| async move {
                Script::new(&format!("{EVENT_JOURNAL_SCRIPT}{PEEK_EVENT_SCRIPT}"))
                    .key(keys.session)
                    .key(keys.events)
                    .invoke_async(&mut connection)
                    .await
            })
            .await?;
        let raw = match raw.as_slice() {
            [code] if code == "0" => return Ok(None),
            [code, raw] if code == "1" => raw,
            _ => return Err(GatewayActionCoordinationError::InvalidRedisResponse),
        };
        let (sequence, payload) = raw
            .split_once('|')
            .ok_or(GatewayActionCoordinationError::InvalidRedisResponse)?;
        let parsed_sequence: u64 = sequence
            .parse()
            .map_err(|_| GatewayActionCoordinationError::InvalidRedisResponse)?;
        if sequence != format!("{parsed_sequence:020}") || parsed_sequence > MAX_EVENT_SEQUENCE {
            return Err(GatewayActionCoordinationError::InvalidRedisResponse);
        }
        let append: OutboxAppend = serde_json::from_str(payload)
            .map_err(|_| GatewayActionCoordinationError::InvalidRedisResponse)?;
        GatewayEventProjection::new(
            tenant_id.clone(),
            session_id.clone(),
            parsed_sequence,
            append,
        )
        .map(Some)
        .map_err(|_| GatewayActionCoordinationError::InvalidRedisResponse)
    }

    async fn ack_event_projection(
        &self,
        projection: &GatewayEventProjection,
    ) -> Result<(), GatewayActionCoordinationError> {
        let keys = self.keys(projection.tenant_id(), projection.session_id());
        let payload = serde_json::to_string(projection.append())
            .map_err(|_| GatewayActionCoordinationError::InvalidRedisResponse)?;
        let sequence = projection.sequence().to_string();
        let member = format!("{:020}|{payload}", projection.sequence());
        let result: Vec<String> = self
            .execute(move |mut connection| async move {
                Script::new(ACK_EVENT_SCRIPT)
                    .key(keys.session)
                    .key(keys.events)
                    .arg(sequence)
                    .arg(member)
                    .invoke_async(&mut connection)
                    .await
            })
            .await?;
        match result.as_slice() {
            [code] if code == "1" => Ok(()),
            [code] if code == "0" => Err(GatewayActionCoordinationError::EventAckConflict),
            _ => Err(GatewayActionCoordinationError::InvalidRedisResponse),
        }
    }

    async fn claim_action(
        &self,
        claim: ClaimGatewayAction,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionClaimOutcome, GatewayActionCoordinationError> {
        self.claim_action_inner(claim, now, None).await
    }

    async fn claim_action_authorized(
        &self,
        claim: ClaimGatewayAction,
        authority: &GatewaySessionAuthorityRef,
        now: DateTime<Utc>,
    ) -> Result<GatewayActionClaimOutcome, GatewayActionCoordinationError> {
        self.claim_action_inner(claim, now, Some(authority)).await
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
        self.require_legacy_admission().await?;
        self.mutate_action(
            tenant_id,
            session_id,
            action_id,
            expected_revision,
            placement,
            now,
            false,
            move |snapshot| {
                if snapshot.submission_lease().is_some() {
                    return Err(GatewayActionCoordinationError::SubmissionLeaseRequired);
                }
                Ok(snapshot.evidence.arm_dispatch(dispatch_id.clone())?)
            },
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
                validate_durable_result_body(result, &result_body, snapshot.result_budget())?;
                if action_sequence.get() == 0 {
                    return Err(GatewayActionCoordinationError::InvalidActionSequence);
                }
                if snapshot.action_sequence() != action_sequence {
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
                    snapshot.result_content = result_body.clone();
                }
                Ok(mutation)
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
                if snapshot.action_sequence() != action_sequence {
                    return Err(GatewayActionCoordinationError::ActionSequenceConflict);
                }
                let mutation = snapshot
                    .evidence
                    .record_worker_terminal(dispatch_id, detail)?;
                snapshot.adopt_worker_resolution(resolution.as_ref(), mutation)
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
        Ok(self.record_session_loss(claim, now, true).await?.outcome())
    }

    async fn ensure_session_lost(
        &self,
        proposed: &SessionLossClaim,
        now: DateTime<Utc>,
    ) -> Result<SessionLossReceipt, GatewayActionCoordinationError> {
        self.record_session_loss(proposed, now, false).await
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
                Script::new(&format!(
                    "{RECOVERY_SCRIPT}{CUSTODY_SCRIPT}{RETENTION_SCRIPT}{MATERIALIZE_CANDIDATES_SCRIPT}"
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
        let mut materialization_arguments = Vec::with_capacity(3 + prepared_count * 6);
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
            materialization_arguments.push(
                serde_json::to_string(
                    &candidate
                        .terminal_outbox_append()
                        .ok_or(GatewayActionCoordinationError::InvalidRedisResponse)?,
                )
                .map_err(|_| GatewayActionCoordinationError::InvalidRedisResponse)?,
            );
            materialization_arguments.push(Self::recovery_member(
                claim.tenant_id(),
                claim.session_id(),
                candidate.action_id(),
            ));
        }
        let keys = self.keys(claim.tenant_id(), claim.session_id());
        materialization_arguments.push(self.config.store.retention().as_millis().to_string());
        let result: Vec<String> = self
            .execute(move |mut connection| async move {
                Script::new(&format!(
                    "{RECOVERY_SCRIPT}{CUSTODY_SCRIPT}{RETENTION_SCRIPT}{EVENT_JOURNAL_SCRIPT}{MATERIALIZE_BATCH_SCRIPT}"
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
