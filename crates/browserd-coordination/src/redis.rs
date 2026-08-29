use std::collections::BTreeSet;
use std::fmt;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use redis::Script;
use redis::aio::ConnectionManager;
use sha2::{Digest, Sha256};
use tokio::sync::Semaphore;
use tokio::time::timeout;

use crate::ephemeral::{MAX_EPHEMERAL_TTL_MILLIS, ttl_millis};
use crate::{
    DirectoryEntry, DirectoryKey, DirectoryMutation, DirectorySnapshot, EphemeralCoordinationError,
    EphemeralCoordinationStore, OneTimeCapability, OneTimeConsume, OneTimeIssue, WorkerHeartbeat,
    WorkerLeaseMutation, WorkerLeaseStore, WorkerReadiness, WorkerRegistration,
    WorkerRegistrationQuery, WorkerRegistrationSnapshot, WorkerReservationGrant,
    WorkerReservationMutation, WorkerReservationOutcome, WorkerReservationRequest,
    WorkerReservationSnapshot, WorkerReservationStore,
};

const REGISTER_SCRIPT: &str = r#"
local function valid_u64(value)
  return value and value ~= '0' and string.match(value, '^[0-9]+$') and string.sub(value, 1, 1) ~= '0' and (#value < 20 or (#value == 20 and value <= '18446744073709551615'))
end
local function compare_u64(left, right)
  if #left ~= #right then return #left < #right and -1 or 1 end
  if left == right then return 0 end
  return left < right and -1 or 1
end
local function increment_u64(value)
  if value == '18446744073709551615' then return nil end
  local output = ''
  local carry = 1
  for index = #value, 1, -1 do
    local digit = string.byte(value, index) - 48 + carry
    if digit == 10 then digit = 0 else carry = 0 end
    output = string.char(digit + 48) .. output
  end
  if carry == 1 then output = '1' .. output end
  return output
end
if not valid_u64(ARGV[2]) or not valid_u64(ARGV[3]) or not valid_u64(ARGV[4]) then return 6 end
local current_worker = redis.call('HGET', KEYS[1], 'worker_id')
local current_epoch = redis.call('HGET', KEYS[1], 'worker_epoch')
local current_placement = redis.call('HGET', KEYS[1], 'placement_version')
local current_incarnation = redis.call('HGET', KEYS[1], 'session_incarnation')
local current_entry = redis.call('HGET', KEYS[1], 'entry')
local old_revision = redis.call('HGET', KEYS[1], 'revision')
local exists = redis.call('EXISTS', KEYS[1])
local existing_ttl = redis.call('PTTL', KEYS[1])
if exists == 1 and existing_ttl <= 0 then return 6 end
if exists == 1 and (not current_worker or not current_entry or not valid_u64(current_epoch) or not valid_u64(current_placement) or not valid_u64(current_incarnation) or not valid_u64(old_revision)) then return 6 end
if current_entry then
  if current_entry == ARGV[5] then return 5 end
  if compare_u64(ARGV[4], current_incarnation) < 0 or compare_u64(ARGV[3], current_placement) <= 0 or (ARGV[1] == current_worker and compare_u64(ARGV[2], current_epoch) < 0) then return 0 end
end
local revision = old_revision and increment_u64(old_revision) or '1'
if not revision then return 4 end
local now = redis.call('TIME')
redis.call('HSET', KEYS[1], 'worker_id', ARGV[1], 'worker_epoch', ARGV[2], 'placement_version', ARGV[3], 'session_incarnation', ARGV[4],
  'revision', revision, 'entry', ARGV[5], 'expires_at', now[1] * 1000 + math.floor(now[2] / 1000) + (ARGV[6] + 0))
redis.call('PEXPIRE', KEYS[1], ARGV[6])
return 1
"#;

const RESOLVE_SCRIPT: &str = r#"
local ttl = redis.call('PTTL', KEYS[1])
if ttl <= 0 then return {} end
return {redis.call('HGET', KEYS[1], 'entry'), redis.call('HGET', KEYS[1], 'revision'), redis.call('HGET', KEYS[1], 'expires_at')}
"#;

const RENEW_SCRIPT: &str = r#"
local function valid_u64(value)
  return value and value ~= '0' and string.match(value, '^[0-9]+$') and string.sub(value, 1, 1) ~= '0' and (#value < 20 or (#value == 20 and value <= '18446744073709551615'))
end
local function increment_u64(value)
  if value == '18446744073709551615' then return nil end
  local output = ''
  local carry = 1
  for index = #value, 1, -1 do
    local digit = string.byte(value, index) - 48 + carry
    if digit == 10 then digit = 0 else carry = 0 end
    output = string.char(digit + 48) .. output
  end
  if carry == 1 then output = '1' .. output end
  return output
end
if redis.call('EXISTS', KEYS[1]) == 0 then return 3 end
if redis.call('PTTL', KEYS[1]) <= 0 then return 6 end
if not valid_u64(ARGV[1]) or not valid_u64(redis.call('HGET', KEYS[1], 'revision')) or not redis.call('HGET', KEYS[1], 'entry') or not redis.call('HGET', KEYS[1], 'worker_id') or not valid_u64(redis.call('HGET', KEYS[1], 'worker_epoch')) or not valid_u64(redis.call('HGET', KEYS[1], 'placement_version')) or not valid_u64(redis.call('HGET', KEYS[1], 'session_incarnation')) then return 6 end
if redis.call('HGET', KEYS[1], 'revision') ~= ARGV[1] or redis.call('HGET', KEYS[1], 'entry') ~= ARGV[2] then return 2 end
local revision = increment_u64(ARGV[1])
if not revision then return 4 end
local now = redis.call('TIME')
redis.call('HSET', KEYS[1], 'revision', revision, 'expires_at', now[1] * 1000 + math.floor(now[2] / 1000) + (ARGV[3] + 0))
redis.call('PEXPIRE', KEYS[1], ARGV[3])
return 1
"#;

const REMOVE_SCRIPT: &str = r#"
local function valid_u64(value)
  return value and value ~= '0' and string.match(value, '^[0-9]+$') and string.sub(value, 1, 1) ~= '0' and (#value < 20 or (#value == 20 and value <= '18446744073709551615'))
end
if redis.call('EXISTS', KEYS[1]) == 0 then return 3 end
if redis.call('PTTL', KEYS[1]) <= 0 then return 6 end
if not valid_u64(ARGV[1]) or not valid_u64(redis.call('HGET', KEYS[1], 'revision')) or not redis.call('HGET', KEYS[1], 'entry') or not redis.call('HGET', KEYS[1], 'worker_id') or not valid_u64(redis.call('HGET', KEYS[1], 'worker_epoch')) or not valid_u64(redis.call('HGET', KEYS[1], 'placement_version')) or not valid_u64(redis.call('HGET', KEYS[1], 'session_incarnation')) then return 6 end
if redis.call('HGET', KEYS[1], 'revision') ~= ARGV[1] or redis.call('HGET', KEYS[1], 'entry') ~= ARGV[2] then return 2 end
redis.call('DEL', KEYS[1])
return 1
"#;

const ISSUE_SCRIPT: &str = r#"
local current = redis.call('GET', KEYS[1])
if current == 'consumed' then return 3 end
if current == 'issued' then return 2 end
if current ~= false then return 6 end
local stored = redis.call('SET', KEYS[1], 'issued', 'PX', ARGV[1], 'NX')
if not stored then return 6 end
return 1
"#;

const CONSUME_SCRIPT: &str = r#"
if redis.call('GET', KEYS[1]) == 'issued' then redis.call('SET', KEYS[1], 'consumed', 'PX', ARGV[1]); return 1 end
return 0
"#;

const WORKER_REGISTER_OBSERVE_SCRIPT: &str = r#"
if redis.call('EXISTS', KEYS[1]) == 0 then return {'0'} end
if redis.call('PTTL', KEYS[1]) <= 0 then return {'6'} end
return {'1', redis.call('HGET', KEYS[1], 'worker_epoch'), redis.call('HGET', KEYS[1], 'revision'), redis.call('HGET', KEYS[1], 'entry'), redis.call('HGET', KEYS[1], 'heartbeat'), redis.call('HGET', KEYS[1], 'region'), redis.call('HGET', KEYS[1], 'compatibility'), redis.call('HGET', KEYS[1], 'readiness'), redis.call('HGET', KEYS[1], 'expires_at')}
"#;

const WORKER_REGISTER_SCRIPT: &str = r#"
local function valid_u64(value)
  return value and value ~= '0' and string.match(value, '^[0-9]+$') and string.sub(value, 1, 1) ~= '0' and (#value < 20 or (#value == 20 and value <= '18446744073709551615'))
end
local function compare_u64(left, right)
  if #left ~= #right then return #left < #right and -1 or 1 end
  if left == right then return 0 end
  return left < right and -1 or 1
end
local function increment_u64(value)
  if value == '18446744073709551615' then return nil end
  local output, carry = '', 1
  for index = #value, 1, -1 do
    local digit = string.byte(value, index) - 48 + carry
    if digit == 10 then digit = 0 else carry = 0 end
    output = string.char(digit + 48) .. output
  end
  if carry == 1 then output = '1' .. output end
  return output
end
local function valid_safe_positive_integer(value)
  return value and string.match(value, '^[0-9]+$') and string.sub(value, 1, 1) ~= '0' and (#value < 16 or (#value == 16 and value <= '9007199254740991'))
end
if not valid_u64(ARGV[1]) then return {'6'} end
local old_count = ARGV[22] + 0
for index = 4, #KEYS do
  local key_type = redis.call('TYPE', KEYS[index])['ok']
  if key_type ~= 'none' and key_type ~= 'zset' then return {'6'} end
end
local high_water = redis.call('GET', KEYS[2])
if high_water and not valid_u64(high_water) then return {'6'} end
if high_water and compare_u64(ARGV[1], high_water) < 0 then return {'0'} end
local exists = redis.call('EXISTS', KEYS[1])
if exists == 0 and high_water and compare_u64(ARGV[1], high_water) <= 0 then return {'0'} end
local current_epoch = redis.call('HGET', KEYS[1], 'worker_epoch')
local current_revision = redis.call('HGET', KEYS[1], 'revision')
local current_entry = redis.call('HGET', KEYS[1], 'entry')
if exists == 1 and redis.call('PTTL', KEYS[1]) <= 0 then return {'6'} end
if exists == 1 and (not valid_u64(current_epoch) or not valid_u64(current_revision) or not current_entry or not redis.call('HGET', KEYS[1], 'heartbeat') or not redis.call('HGET', KEYS[1], 'region') or not redis.call('HGET', KEYS[1], 'compatibility') or not redis.call('HGET', KEYS[1], 'readiness') or not valid_u64(redis.call('HGET', KEYS[1], 'expires_at'))) then return {'6'} end
if tostring(exists) ~= ARGV[23] then return {'9'} end
if exists == 1 and (current_epoch ~= ARGV[24] or current_revision ~= ARGV[25] or current_entry ~= ARGV[26]) then return {'9'} end
if exists == 1 then
  local ordering = compare_u64(ARGV[1], current_epoch)
  if ordering < 0 then return {'0'} end
  if ordering == 0 then
    if current_entry == ARGV[2] then return {'5'} end
    return {'0'}
  end
end
local revision = exists == 1 and increment_u64(current_revision) or '1'
if not revision then return {'4'} end
local now = redis.call('TIME')
local expires_at = tostring(now[1] * 1000 + math.floor(now[2] / 1000) + (ARGV[7] + 0))
if not valid_safe_positive_integer(expires_at) then return {'6'} end
local planned_expiry = {}
for index = 4, #KEYS do
  local top = redis.call('ZREVRANGE', KEYS[index], 0, 1, 'WITHSCORES')
  local other = nil
  for offset = 1, #top, 2 do if top[offset] ~= KEYS[1] and not other then other = top[offset + 1] end end
  if other and not valid_safe_positive_integer(other) then return {'6'} end
  if index > 3 + old_count and ARGV[6] == 'ready' and (not other or #expires_at > #other or (#expires_at == #other and expires_at > other)) then planned_expiry[index] = expires_at else planned_expiry[index] = other end
end
redis.call('DEL', KEYS[3])
redis.call('SET', KEYS[2], ARGV[1])
redis.call('HSET', KEYS[1], 'worker_epoch', ARGV[1], 'revision', revision, 'entry', ARGV[2], 'heartbeat', ARGV[3], 'region', ARGV[4], 'compatibility', ARGV[5], 'readiness', ARGV[6], 'expires_at', expires_at)
redis.call('HSET', KEYS[1], 'free_memory_bytes', ARGV[8], 'free_cpu_millis', ARGV[9], 'free_pids', ARGV[10], 'free_disk_bytes', ARGV[11], 'free_contexts', ARGV[12], 'free_targets', ARGV[13], 'capacity_memory_bytes', ARGV[14], 'capacity_cpu_millis', ARGV[15], 'capacity_pids', ARGV[16], 'capacity_disk_bytes', ARGV[17], 'capacity_contexts', ARGV[18], 'capacity_targets', ARGV[19], 'queue_depth', ARGV[20], 'active_shards', ARGV[21])
redis.call('HSET', KEYS[1], 'reserved_memory_bytes', '0', 'reserved_cpu_millis', '0', 'reserved_pids', '0', 'reserved_disk_bytes', '0', 'reserved_contexts', '0', 'reserved_targets', '0')
redis.call('PEXPIRE', KEYS[1], ARGV[7])
for index = 4, 3 + old_count do
  redis.call('ZREM', KEYS[index], KEYS[1])
  if not planned_expiry[index] then redis.call('DEL', KEYS[index]) else redis.call('PEXPIREAT', KEYS[index], planned_expiry[index]) end
end
for index = 4 + old_count, #KEYS do
  if ARGV[6] == 'ready' then redis.call('ZADD', KEYS[index], expires_at, KEYS[1]) else redis.call('ZREM', KEYS[index], KEYS[1]) end
  if not planned_expiry[index] then redis.call('DEL', KEYS[index]) else redis.call('PEXPIREAT', KEYS[index], planned_expiry[index]) end
end
return {'1', revision, expires_at}
"#;

const WORKER_HEARTBEAT_SCRIPT: &str = r#"
local function valid_u64(value)
  return value and value ~= '0' and string.match(value, '^[0-9]+$') and string.sub(value, 1, 1) ~= '0' and (#value < 20 or (#value == 20 and value <= '18446744073709551615'))
end
local function valid_safe_positive_integer(value)
  return value and string.match(value, '^[0-9]+$') and string.sub(value, 1, 1) ~= '0' and (#value < 16 or (#value == 16 and value <= '9007199254740991'))
end
local function valid_decimal(value)
  return value and string.match(value, '^[0-9]+$') and (#value == 1 or string.sub(value, 1, 1) ~= '0') and (#value < 20 or (#value == 20 and value <= '18446744073709551615'))
end
local function compare_decimal(left, right)
  if #left ~= #right then return #left < #right and -1 or 1 end
  if left == right then return 0 end
  return left < right and -1 or 1
end
local function subtract_u64(left, right)
  if not valid_decimal(left) or not valid_decimal(right) or compare_decimal(left, right) < 0 then return nil end
  local output, borrow, right_index = '', 0, #right
  for left_index = #left, 1, -1 do
    local digit = string.byte(left, left_index) - 48 - borrow
    local other = right_index > 0 and string.byte(right, right_index) - 48 or 0
    if digit < other then digit = digit + 10; borrow = 1 else borrow = 0 end
    output = string.char(digit - other + 48) .. output
    right_index = right_index - 1
  end
  output = string.gsub(output, '^0+', '')
  return output == '' and '0' or output
end
local function add_u64(left, right)
  if not valid_decimal(left) or not valid_decimal(right) then return nil end
  local output, carry = '', 0
  local left_index, right_index = #left, #right
  while left_index > 0 or right_index > 0 or carry > 0 do
    local a = left_index > 0 and string.byte(left, left_index) - 48 or 0
    local b = right_index > 0 and string.byte(right, right_index) - 48 or 0
    local sum = a + b + carry
    output = string.char((sum % 10) + 48) .. output
    carry = math.floor(sum / 10)
    left_index, right_index = left_index - 1, right_index - 1
  end
  if #output > 20 or (#output == 20 and output > '18446744073709551615') then return nil end
  return output
end
local function increment_u64(value)
  if value == '18446744073709551615' then return nil end
  local output, carry = '', 1
  for index = #value, 1, -1 do
    local digit = string.byte(value, index) - 48 + carry
    if digit == 10 then digit = 0 else carry = 0 end
    output = string.char(digit + 48) .. output
  end
  if carry == 1 then output = '1' .. output end
  return output
end
if redis.call('EXISTS', KEYS[1]) == 0 then return {'3'} end
if redis.call('PTTL', KEYS[1]) <= 0 then return {'6'} end
local current_epoch = redis.call('HGET', KEYS[1], 'worker_epoch')
local current_revision = redis.call('HGET', KEYS[1], 'revision')
local current_entry = redis.call('HGET', KEYS[1], 'entry')
local current_heartbeat = redis.call('HGET', KEYS[1], 'heartbeat')
local current_expiry = redis.call('HGET', KEYS[1], 'expires_at')
if not valid_u64(current_epoch) or not valid_u64(current_revision) or not valid_u64(current_expiry) or not current_entry or not current_heartbeat then return {'6'} end
if current_epoch ~= ARGV[1] then return {'0'} end
if current_revision ~= ARGV[2] or current_entry ~= ARGV[3] or current_heartbeat ~= ARGV[4] or current_expiry ~= ARGV[5] then return {'2'} end
local expired_count = ARGV[18] + 0
if expired_count < 0 or expired_count > 64 or #KEYS < 2 + expired_count then return {'6'} end
local ready_offset = 3 + expired_count
local active_type = redis.call('TYPE', KEYS[2])['ok']
if active_type ~= 'none' and active_type ~= 'zset' then return {'6'} end
for index = ready_offset, #KEYS do
  local key_type = redis.call('TYPE', KEYS[index])['ok']
  if key_type ~= 'none' and key_type ~= 'zset' then return {'6'} end
end
local names = {'memory_bytes', 'cpu_millis', 'pids', 'disk_bytes', 'contexts', 'targets'}
local capacity, reserved, reclaimed, remaining_reserved, free = {}, {}, {}, {}, {}
for index, name in ipairs(names) do
  local stored_free = redis.call('HGET', KEYS[1], 'free_' .. name)
  capacity[index] = redis.call('HGET', KEYS[1], 'capacity_' .. name)
  reserved[index] = redis.call('HGET', KEYS[1], 'reserved_' .. name)
  reclaimed[index] = '0'
  if not valid_decimal(stored_free) or not valid_decimal(capacity[index]) or not valid_decimal(reserved[index]) or not valid_decimal(ARGV[8 + index]) then return {'6'} end
  if compare_decimal(ARGV[8 + index], capacity[index]) > 0 then return {'6'} end
end
local now = redis.call('TIME')
local now_millis = tostring(now[1] * 1000 + math.floor(now[2] / 1000))
local current_expired_candidates = redis.call('ZRANGEBYSCORE', KEYS[2], '-inf', now_millis, 'WITHSCORES', 'LIMIT', 0, 64)
if #current_expired_candidates ~= expired_count * 2 then return {'9'} end
for index = 1, expired_count do
  local key_offset = 2 + index
  local current_offset = (index - 1) * 2 + 1
  local prepared_score = ARGV[18 + index]
  if current_expired_candidates[current_offset] ~= KEYS[key_offset] or current_expired_candidates[current_offset + 1] ~= prepared_score then return {'9'} end
  if not valid_safe_positive_integer(prepared_score) then return {'6'} end
  local reason = redis.call('HGET', KEYS[key_offset], 'terminal_reason')
  local worker_id = redis.call('HGET', KEYS[key_offset], 'acquisition_worker_id')
  local worker_epoch = redis.call('HGET', KEYS[key_offset], 'acquisition_worker_epoch')
  local reservation_expiry = redis.call('HGET', KEYS[key_offset], 'reservation_expires_at')
  if reason ~= 'active' or worker_id ~= ARGV[17] or not valid_u64(worker_epoch) or reservation_expiry ~= prepared_score or compare_decimal(reservation_expiry, now_millis) > 0 then return {'6'} end
  local candidate_resources = {}
  for resource_index, name in ipairs(names) do
    candidate_resources[resource_index] = redis.call('HGET', KEYS[key_offset], 'resource_' .. name)
    if not valid_decimal(candidate_resources[resource_index]) then return {'6'} end
  end
  if worker_epoch == current_epoch then
    for resource_index, _ in ipairs(names) do
      reclaimed[resource_index] = add_u64(reclaimed[resource_index], candidate_resources[resource_index])
      if not reclaimed[resource_index] then return {'6'} end
    end
  end
end
for index, _ in ipairs(names) do
  remaining_reserved[index] = subtract_u64(reserved[index], reclaimed[index])
  free[index] = subtract_u64(ARGV[8 + index], remaining_reserved[index])
  if not remaining_reserved[index] or not free[index] then return {'6'} end
end
local revision = increment_u64(current_revision)
if not revision then return {'4'} end
local rebuilt_heartbeat = '{"free":{"memory_bytes":' .. free[1] .. ',"cpu_millis":' .. free[2] .. ',"pids":' .. free[3] .. ',"disk_bytes":' .. free[4] .. ',"contexts":' .. free[5] .. ',"targets":' .. free[6] .. '},"queue_depth":' .. ARGV[15] .. ',"active_shards":' .. ARGV[16] .. ',"readiness":"' .. ARGV[7] .. '"}'
local expires_at = tostring(now[1] * 1000 + math.floor(now[2] / 1000) + (ARGV[8] + 0))
if not valid_safe_positive_integer(expires_at) then return {'6'} end
local planned_expiry = {}
for index = ready_offset, #KEYS do
  local top = redis.call('ZREVRANGE', KEYS[index], 0, 1, 'WITHSCORES')
  local other = nil
  for offset = 1, #top, 2 do if top[offset] ~= KEYS[1] and not other then other = top[offset + 1] end end
  if other and not valid_safe_positive_integer(other) then return {'6'} end
  if ARGV[7] == 'ready' and (not other or #expires_at > #other or (#expires_at == #other and expires_at > other)) then planned_expiry[index] = expires_at else planned_expiry[index] = other end
end
for index = 1, expired_count do
  local key_offset = 2 + index
  redis.call('HSET', KEYS[key_offset], 'terminal_reason', 'expired')
  redis.call('PEXPIRE', KEYS[key_offset], 300000)
  redis.call('ZREM', KEYS[2], KEYS[key_offset])
end
redis.call('HSET', KEYS[1], 'revision', revision, 'heartbeat', rebuilt_heartbeat, 'readiness', ARGV[7], 'expires_at', expires_at)
for index, name in ipairs(names) do redis.call('HSET', KEYS[1], 'free_' .. name, free[index]) end
for index, name in ipairs(names) do redis.call('HSET', KEYS[1], 'reserved_' .. name, remaining_reserved[index]) end
redis.call('HSET', KEYS[1], 'queue_depth', ARGV[15], 'active_shards', ARGV[16])
redis.call('PEXPIRE', KEYS[1], ARGV[8])
for index = ready_offset, #KEYS do
  if ARGV[7] == 'ready' then redis.call('ZADD', KEYS[index], expires_at, KEYS[1]) else redis.call('ZREM', KEYS[index], KEYS[1]) end
  if not planned_expiry[index] then redis.call('DEL', KEYS[index]) else redis.call('PEXPIREAT', KEYS[index], planned_expiry[index]) end
end
return {'1', revision, expires_at, rebuilt_heartbeat}
"#;

const WORKER_QUERY_CANDIDATES_SCRIPT: &str = r#"
local now = redis.call('TIME')
local now_millis = now[1] * 1000 + math.floor(now[2] / 1000)
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now_millis)
local output = {'1'}
local candidates = redis.call('ZRANGE', KEYS[1], 0, (ARGV[1] + 0) - 1)
for _, candidate in ipairs(candidates) do table.insert(output, candidate) end
return output
"#;

const WORKER_EXPIRED_CANDIDATES_SCRIPT: &str = r#"
local key_type = redis.call('TYPE', KEYS[1])['ok']
if key_type ~= 'none' and key_type ~= 'zset' then return {'6'} end
local now = redis.call('TIME')
local now_millis = now[1] * 1000 + math.floor(now[2] / 1000)
local output = {'1'}
local candidates = redis.call('ZRANGEBYSCORE', KEYS[1], '-inf', now_millis, 'WITHSCORES', 'LIMIT', 0, 64)
for _, value in ipairs(candidates) do table.insert(output, value) end
return output
"#;

const WORKER_QUERY_VALIDATE_SCRIPT: &str = r#"
local function valid_u64(value)
  return value and value ~= '0' and string.match(value, '^[0-9]+$') and string.sub(value, 1, 1) ~= '0' and (#value < 20 or (#value == 20 and value <= '18446744073709551615'))
end
local validated = {}
for index = 2, #KEYS do
  if not redis.call('ZSCORE', KEYS[1], KEYS[index]) or redis.call('PTTL', KEYS[index]) <= 0 then return {'9'} end
  local entry = redis.call('HGET', KEYS[index], 'entry')
  local heartbeat = redis.call('HGET', KEYS[index], 'heartbeat')
  local revision = redis.call('HGET', KEYS[index], 'revision')
  local expires_at = redis.call('HGET', KEYS[index], 'expires_at')
  local region = redis.call('HGET', KEYS[index], 'region')
  local compatibility = redis.call('HGET', KEYS[index], 'compatibility')
  local readiness = redis.call('HGET', KEYS[index], 'readiness')
  if not entry or not heartbeat or not valid_u64(revision) or not valid_u64(expires_at) or region ~= ARGV[1] or readiness ~= 'ready' then return {'6'} end
  local decoded_ok, decoded = pcall(cjson.decode, compatibility)
  if not decoded_ok or type(decoded) ~= 'table' then return {'6'} end
  local compatible = false
  for _, value in ipairs(decoded) do if value == ARGV[2] then compatible = true end end
  if not compatible then return {'6'} end
  table.insert(validated, {KEYS[index], entry, heartbeat, revision, expires_at})
end
local output = {'1'}
for index, value in ipairs(validated) do
  if index > (ARGV[3] + 0) then break end
  table.insert(output, value[1])
  table.insert(output, value[2])
  table.insert(output, value[3])
  table.insert(output, value[4])
  table.insert(output, value[5])
end
return output
"#;

const RESERVE_WORKER_SCRIPT: &str = r#"
local function valid_u64(value)
  return value and value ~= '0' and string.match(value, '^[0-9]+$') and string.sub(value, 1, 1) ~= '0' and (#value < 20 or (#value == 20 and value <= '18446744073709551615'))
end
local function increment_u64(value)
  if value == '18446744073709551615' then return nil end
  local output, carry = '', 1
  for index = #value, 1, -1 do
    local digit = string.byte(value, index) - 48 + carry
    if digit == 10 then digit = 0 else carry = 0 end
    output = string.char(digit + 48) .. output
  end
  if carry == 1 then output = '1' .. output end
  return output
end
local function compare_u64(left, right)
  if #left ~= #right then return #left < #right and -1 or 1 end
  if left == right then return 0 end
  return left < right and -1 or 1
end
local function subtract_u64(left, right)
  local function valid_decimal(value) return value and string.match(value, '^[0-9]+$') and (#value == 1 or string.sub(value, 1, 1) ~= '0') and (#value < 20 or (#value == 20 and value <= '18446744073709551615')) end
  if not valid_decimal(left) or not valid_decimal(right) or compare_u64(left, right) < 0 then return nil end
  local output, borrow, right_index = '', 0, #right
  for left_index = #left, 1, -1 do
    local digit = string.byte(left, left_index) - 48 - borrow
    local other = right_index > 0 and string.byte(right, right_index) - 48 or 0
    if digit < other then digit = digit + 10; borrow = 1 else borrow = 0 end
    output = string.char(digit - other + 48) .. output
    right_index = right_index - 1
  end
  output = string.gsub(output, '^0+', '')
  return output == '' and '0' or output
end
local function add_u64(left, right)
  local function valid_decimal(value) return value and string.match(value, '^[0-9]+$') and (#value == 1 or string.sub(value, 1, 1) ~= '0') and (#value < 20 or (#value == 20 and value <= '18446744073709551615')) end
  if not valid_decimal(left) or not valid_decimal(right) then return nil end
  local output, carry = '', 0
  local left_index, right_index = #left, #right
  while left_index > 0 or right_index > 0 or carry > 0 do
    local a = left_index > 0 and string.byte(left, left_index) - 48 or 0
    local b = right_index > 0 and string.byte(right, right_index) - 48 or 0
    local sum = a + b + carry
    output = string.char((sum % 10) + 48) .. output
    carry = math.floor(sum / 10)
    left_index, right_index = left_index - 1, right_index - 1
  end
  if #output > 20 or (#output == 20 and output > '18446744073709551615') then return nil end
  return output
end
local resource_names = {'memory_bytes', 'cpu_millis', 'pids', 'disk_bytes', 'contexts', 'targets'}
local function valid_decimal(value)
  return value and string.match(value, '^[0-9]+$') and (#value == 1 or string.sub(value, 1, 1) ~= '0') and (#value < 20 or (#value == 20 and value <= '18446744073709551615'))
end
local function valid_safe_positive_integer(value)
  return value and string.match(value, '^[0-9]+$') and string.sub(value, 1, 1) ~= '0' and (#value < 16 or (#value == 16 and value <= '9007199254740991'))
end
local function build_heartbeat(free, queue_depth, active_shards, readiness)
  return '{"free":{"memory_bytes":' .. free[1] .. ',"cpu_millis":' .. free[2] .. ',"pids":' .. free[3] .. ',"disk_bytes":' .. free[4] .. ',"contexts":' .. free[5] .. ',"targets":' .. free[6] .. '},"queue_depth":' .. queue_depth .. ',"active_shards":' .. active_shards .. ',"readiness":"' .. readiness .. '"}'
end
local operation_exists = redis.call('EXISTS', KEYS[2])
local operation_id = redis.call('HGET', KEYS[2], 'operation_id')
if operation_exists == 1 and not operation_id then return {'6'} end
if operation_id then
  if redis.call('PTTL', KEYS[2]) <= 0 then return {'6'} end
  if operation_id ~= ARGV[5] or redis.call('HGET', KEYS[2], 'tenant_id') ~= ARGV[6] or redis.call('HGET', KEYS[2], 'resources') ~= ARGV[7] then return {'8'} end
  local terminal_reason = redis.call('HGET', KEYS[2], 'terminal_reason')
  if terminal_reason == 'released' then return {'8'} end
  if terminal_reason == 'expired' then return {'3'} end
  if terminal_reason ~= 'active' then return {'6'} end
  local operation_now = redis.call('TIME')
  local operation_now_millis = tostring(operation_now[1] * 1000 + math.floor(operation_now[2] / 1000))
  local stored_expiry = redis.call('HGET', KEYS[2], 'reservation_expires_at')
  if not valid_u64(stored_expiry) then return {'6'} end
  if compare_u64(stored_expiry, operation_now_millis) <= 0 then
    return {'3'}
  end
  local function return_stored_grant()
    return {'5', redis.call('HGET', KEYS[2], 'reservation'), redis.call('HGET', KEYS[2], 'stored_worker_entry'), redis.call('HGET', KEYS[2], 'stored_worker_heartbeat'), redis.call('HGET', KEYS[2], 'acquisition_worker_revision'), redis.call('HGET', KEYS[2], 'acquisition_worker_expires_at'), redis.call('HGET', KEYS[2], 'reservation_expires_at')}
  end
  return return_stored_grant()
end
if redis.call('PTTL', KEYS[1]) <= 0 then return {'6'} end
local worker_epoch = redis.call('HGET', KEYS[1], 'worker_epoch')
local revision = redis.call('HGET', KEYS[1], 'revision')
local current_entry = redis.call('HGET', KEYS[1], 'entry')
local heartbeat = redis.call('HGET', KEYS[1], 'heartbeat')
local readiness = redis.call('HGET', KEYS[1], 'readiness')
local queue_depth = redis.call('HGET', KEYS[1], 'queue_depth')
local active_shards = redis.call('HGET', KEYS[1], 'active_shards')
local worker_expires_at = redis.call('HGET', KEYS[1], 'expires_at')
if not valid_u64(worker_epoch) or not valid_u64(revision) or not current_entry or not heartbeat or not valid_decimal(queue_depth) or not valid_decimal(active_shards) or not valid_u64(worker_expires_at) or (readiness ~= 'ready' and readiness ~= 'unready' and readiness ~= 'draining') then return {'6'} end
local free, capacity, reserved = {}, {}, {}
for index, name in ipairs(resource_names) do
  free[index] = redis.call('HGET', KEYS[1], 'free_' .. name)
  capacity[index] = redis.call('HGET', KEYS[1], 'capacity_' .. name)
  reserved[index] = redis.call('HGET', KEYS[1], 'reserved_' .. name)
  if not valid_decimal(free[index]) or not valid_decimal(capacity[index]) or not valid_decimal(reserved[index]) or compare_u64(free[index], capacity[index]) > 0 or compare_u64(reserved[index], capacity[index]) > 0 then return {'6'} end
end
if worker_epoch ~= ARGV[1] then return {'0'} end
if revision ~= ARGV[2] or current_entry ~= ARGV[3] or heartbeat ~= ARGV[4] then return {'2'} end
if readiness ~= 'ready' then return {'7'} end
local expired_count = ARGV[19] + 0
if expired_count < 0 or expired_count > 64 or #KEYS ~= 3 + expired_count then return {'6'} end
local active_type = redis.call('TYPE', KEYS[3])['ok']
if active_type ~= 'none' and active_type ~= 'zset' then return {'6'} end
local now = redis.call('TIME')
local now_millis = tostring(now[1] * 1000 + math.floor(now[2] / 1000))
local current_expired_candidates = redis.call('ZRANGEBYSCORE', KEYS[3], '-inf', now_millis, 'WITHSCORES', 'LIMIT', 0, 64)
if #current_expired_candidates ~= expired_count * 2 then return {'9'} end
local reclaimed = false
for candidate_index = 1, expired_count do
  local key_offset = 3 + candidate_index
  local current_offset = (candidate_index - 1) * 2 + 1
  local prepared_score = ARGV[19 + candidate_index]
  if current_expired_candidates[current_offset] ~= KEYS[key_offset] or current_expired_candidates[current_offset + 1] ~= prepared_score then return {'9'} end
  if not valid_safe_positive_integer(prepared_score) then return {'6'} end
  local expired_reason = redis.call('HGET', KEYS[key_offset], 'terminal_reason')
  local expired_worker = redis.call('HGET', KEYS[key_offset], 'acquisition_worker_id')
  local expired_epoch = redis.call('HGET', KEYS[key_offset], 'acquisition_worker_epoch')
  local expired_at = redis.call('HGET', KEYS[key_offset], 'reservation_expires_at')
  if expired_reason ~= 'active' or expired_worker ~= ARGV[11] or not valid_u64(expired_epoch) or expired_at ~= prepared_score or compare_u64(expired_at, now_millis) > 0 then return {'6'} end
  for resource_index, name in ipairs(resource_names) do
    local resource = redis.call('HGET', KEYS[key_offset], 'resource_' .. name)
    if not valid_decimal(resource) then return {'6'} end
    if expired_epoch == worker_epoch then
      local restored = add_u64(free[resource_index], resource)
      if not restored or compare_u64(restored, capacity[resource_index]) > 0 then return {'6'} end
      local remaining_reserved = subtract_u64(reserved[resource_index], resource)
      if not remaining_reserved then return {'6'} end
      free[resource_index] = restored
      reserved[resource_index] = remaining_reserved
    end
  end
  if expired_epoch == worker_epoch then reclaimed = true end
end
if reclaimed then
  local reclaimed_revision = increment_u64(revision)
  if not reclaimed_revision then return {'4'} end
  revision = reclaimed_revision
end
for index, _ in ipairs(resource_names) do
  if not valid_decimal(ARGV[12 + index]) then return {'6'} end
  local remaining = subtract_u64(free[index], ARGV[12 + index])
  if not remaining then return {'10'} end
  local next_reserved = add_u64(reserved[index], ARGV[12 + index])
  if not next_reserved or compare_u64(next_reserved, capacity[index]) > 0 then return {'6'} end
  free[index] = remaining
  reserved[index] = next_reserved
end
local next_revision = increment_u64(revision)
if not next_revision then return {'4'} end
local expires_at = tostring(now[1] * 1000 + math.floor(now[2] / 1000) + (ARGV[10] + 0))
if not valid_safe_positive_integer(expires_at) or compare_u64(expires_at, worker_expires_at) > 0 then return {'6'} end
local rebuilt_heartbeat = build_heartbeat(free, queue_depth, active_shards, readiness)
local operation_ttl = add_u64(ARGV[10], '300000')
if not operation_ttl then return {'6'} end
for candidate_index = 1, expired_count do
  local key_offset = 3 + candidate_index
  redis.call('HSET', KEYS[key_offset], 'terminal_reason', 'expired')
  redis.call('PEXPIRE', KEYS[key_offset], 300000)
  redis.call('ZREM', KEYS[3], KEYS[key_offset])
end
for index, name in ipairs(resource_names) do redis.call('HSET', KEYS[1], 'free_' .. name, free[index]) end
for index, name in ipairs(resource_names) do redis.call('HSET', KEYS[1], 'reserved_' .. name, reserved[index]) end
redis.call('HSET', KEYS[1], 'revision', next_revision, 'heartbeat', rebuilt_heartbeat)
redis.call('HSET', KEYS[2], 'operation_id', ARGV[5], 'tenant_id', ARGV[6], 'resources', ARGV[7], 'reservation', ARGV[9], 'acquisition_worker_id', ARGV[11], 'acquisition_worker_epoch', worker_epoch, 'acquisition_worker_revision', next_revision, 'acquisition_worker_expires_at', worker_expires_at, 'reservation_expires_at', expires_at, 'stored_worker_entry', current_entry, 'stored_worker_heartbeat', rebuilt_heartbeat, 'terminal_reason', 'active')
for index, name in ipairs(resource_names) do redis.call('HSET', KEYS[2], 'resource_' .. name, ARGV[12 + index]) end
redis.call('PEXPIRE', KEYS[2], operation_ttl)
redis.call('ZADD', KEYS[3], expires_at, KEYS[2])
local function return_current_worker(code) return {code, current_entry, rebuilt_heartbeat, next_revision, worker_expires_at, expires_at} end
return return_current_worker('1')
"#;

const RELEASE_WORKER_RESERVATION_SCRIPT: &str = r#"
local function valid_u64(value)
  return value and value ~= '0' and string.match(value, '^[0-9]+$') and string.sub(value, 1, 1) ~= '0' and (#value < 20 or (#value == 20 and value <= '18446744073709551615'))
end
local function add_u64(left, right)
  local function valid_decimal(value) return value and string.match(value, '^[0-9]+$') and (#value == 1 or string.sub(value, 1, 1) ~= '0') and (#value < 20 or (#value == 20 and value <= '18446744073709551615')) end
  if not valid_decimal(left) or not valid_decimal(right) then return nil end
  local output, carry = '', 0
  local left_index, right_index = #left, #right
  while left_index > 0 or right_index > 0 or carry > 0 do
    local a = left_index > 0 and string.byte(left, left_index) - 48 or 0
    local b = right_index > 0 and string.byte(right, right_index) - 48 or 0
    local sum = a + b + carry
    output = string.char((sum % 10) + 48) .. output
    carry = math.floor(sum / 10)
    left_index, right_index = left_index - 1, right_index - 1
  end
  if #output > 20 or (#output == 20 and output > '18446744073709551615') then return nil end
  return output
end
local function subtract_u64(left, right)
  local function valid_decimal(value) return value and string.match(value, '^[0-9]+$') and (#value == 1 or string.sub(value, 1, 1) ~= '0') and (#value < 20 or (#value == 20 and value <= '18446744073709551615')) end
  if not valid_decimal(left) or not valid_decimal(right) or #left < #right or (#left == #right and left < right) then return nil end
  local output, borrow, right_index = '', 0, #right
  for left_index = #left, 1, -1 do
    local digit = string.byte(left, left_index) - 48 - borrow
    local other = right_index > 0 and string.byte(right, right_index) - 48 or 0
    if digit < other then digit = digit + 10; borrow = 1 else borrow = 0 end
    output = string.char(digit - other + 48) .. output
    right_index = right_index - 1
  end
  output = string.gsub(output, '^0+', '')
  return output == '' and '0' or output
end
local function increment_u64(value)
  if value == '18446744073709551615' then return nil end
  local output, carry = '', 1
  for index = #value, 1, -1 do
    local digit = string.byte(value, index) - 48 + carry
    if digit == 10 then digit = 0 else carry = 0 end
    output = string.char(digit + 48) .. output
  end
  if carry == 1 then output = '1' .. output end
  return output
end
local resource_names = {'memory_bytes', 'cpu_millis', 'pids', 'disk_bytes', 'contexts', 'targets'}
local function valid_decimal(value)
  return value and string.match(value, '^[0-9]+$') and (#value == 1 or string.sub(value, 1, 1) ~= '0') and (#value < 20 or (#value == 20 and value <= '18446744073709551615'))
end
local function build_heartbeat(free, queue_depth, active_shards, readiness)
  return '{"free":{"memory_bytes":' .. free[1] .. ',"cpu_millis":' .. free[2] .. ',"pids":' .. free[3] .. ',"disk_bytes":' .. free[4] .. ',"contexts":' .. free[5] .. ',"targets":' .. free[6] .. '},"queue_depth":' .. queue_depth .. ',"active_shards":' .. active_shards .. ',"readiness":"' .. readiness .. '"}'
end
if redis.call('PTTL', KEYS[2]) <= 0 then return {'3'} end
local terminal_reason = redis.call('HGET', KEYS[2], 'terminal_reason')
if terminal_reason == 'released' then return {'5'} end
if terminal_reason == 'expired' then return {'3'} end
if terminal_reason ~= 'active' then return {'6'} end
if redis.call('HGET', KEYS[2], 'acquisition_worker_id') ~= ARGV[7] then return {'0'} end
if redis.call('HGET', KEYS[2], 'reservation') ~= ARGV[4] then return {'2'} end
local active_type = redis.call('TYPE', KEYS[3])['ok']
if active_type ~= 'none' and active_type ~= 'zset' then return {'6'} end
if redis.call('PTTL', KEYS[1]) <= 0 then return {'6'} end
local worker_epoch = redis.call('HGET', KEYS[1], 'worker_epoch')
local revision = redis.call('HGET', KEYS[1], 'revision')
local current_entry = redis.call('HGET', KEYS[1], 'entry')
local current_heartbeat = redis.call('HGET', KEYS[1], 'heartbeat')
local worker_expires_at = redis.call('HGET', KEYS[1], 'expires_at')
local queue_depth = redis.call('HGET', KEYS[1], 'queue_depth')
local active_shards = redis.call('HGET', KEYS[1], 'active_shards')
local readiness = redis.call('HGET', KEYS[1], 'readiness')
if not valid_u64(worker_epoch) or not valid_u64(revision) or not valid_u64(worker_expires_at) or not current_entry or not current_heartbeat or not valid_decimal(queue_depth) or not valid_decimal(active_shards) or (readiness ~= 'ready' and readiness ~= 'unready' and readiness ~= 'draining') then return {'6'} end
if worker_epoch ~= ARGV[1] then return {'0'} end
if current_entry ~= ARGV[3] then return {'2'} end
local now = redis.call('TIME')
local now_millis = tostring(now[1] * 1000 + math.floor(now[2] / 1000))
local operation_expiry = redis.call('HGET', KEYS[2], 'reservation_expires_at')
if not valid_u64(operation_expiry) then return {'6'} end
local expired = (#operation_expiry < #now_millis) or (#operation_expiry == #now_millis and operation_expiry <= now_millis)
local next_revision = increment_u64(revision)
if not next_revision then return {'4'} end
local free, reserved = {}, {}
for index, name in ipairs(resource_names) do
  local current_free = redis.call('HGET', KEYS[1], 'free_' .. name)
  local capacity = redis.call('HGET', KEYS[1], 'capacity_' .. name)
  local resource = redis.call('HGET', KEYS[2], 'resource_' .. name)
  local current_reserved = redis.call('HGET', KEYS[1], 'reserved_' .. name)
  local restored = add_u64(current_free, resource)
  local remaining_reserved = subtract_u64(current_reserved, resource)
  if not restored or not remaining_reserved or not valid_decimal(capacity) or #restored > #capacity or (#restored == #capacity and restored > capacity) then return {'6'} end
  free[index] = restored
  reserved[index] = remaining_reserved
end
local rebuilt_heartbeat = build_heartbeat(free, queue_depth, active_shards, readiness)
for index, name in ipairs(resource_names) do
  redis.call('HSET', KEYS[1], 'free_' .. name, free[index], 'reserved_' .. name, reserved[index])
end
redis.call('HSET', KEYS[1], 'revision', next_revision, 'heartbeat', rebuilt_heartbeat)
if expired then
  redis.call('HSET', KEYS[2], 'terminal_reason', 'expired')
else
  redis.call('HSET', KEYS[2], 'terminal_reason', 'released')
end
redis.call('PEXPIRE', KEYS[2], 300000)
redis.call('ZREM', KEYS[3], KEYS[2])
local function return_current_worker(code) return {code, current_entry, rebuilt_heartbeat, next_revision, worker_expires_at} end
if expired then return {'3'} end
return return_current_worker('1')
"#;

#[derive(Clone)]
pub struct RedisEphemeralConfig {
    endpoint: String,
    key_prefix: String,
    max_in_flight: usize,
    command_timeout: Duration,
}

impl RedisEphemeralConfig {
    pub fn new(
        endpoint: impl Into<String>,
        key_prefix: impl Into<String>,
        max_in_flight: usize,
        command_timeout: Duration,
    ) -> Result<Self, EphemeralCoordinationError> {
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
        {
            return Err(EphemeralCoordinationError::InvalidInput);
        }
        Ok(Self {
            endpoint,
            key_prefix,
            max_in_flight,
            command_timeout,
        })
    }
}

impl fmt::Debug for RedisEphemeralConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedisEphemeralConfig")
            .field("endpoint", &"[REDACTED]")
            .field("key_prefix", &self.key_prefix)
            .field("max_in_flight", &self.max_in_flight)
            .field("command_timeout", &self.command_timeout)
            .finish()
    }
}

pub struct RedisEphemeralCoordinationStore {
    connection: ConnectionManager,
    config: RedisEphemeralConfig,
    permits: Arc<Semaphore>,
}

impl RedisEphemeralCoordinationStore {
    pub async fn connect(config: RedisEphemeralConfig) -> Result<Self, EphemeralCoordinationError> {
        let client = redis::Client::open(config.endpoint.as_str())
            .map_err(|_| EphemeralCoordinationError::Unavailable)?;
        let connection = timeout(config.command_timeout, client.get_connection_manager())
            .await
            .map_err(|_| EphemeralCoordinationError::TimedOut)?
            .map_err(|_| EphemeralCoordinationError::Unavailable)?;
        Ok(Self {
            permits: Arc::new(Semaphore::new(config.max_in_flight)),
            connection,
            config,
        })
    }

    async fn execute<T, F, Fut>(&self, operation: F) -> Result<T, EphemeralCoordinationError>
    where
        F: FnOnce(ConnectionManager) -> Fut,
        Fut: Future<Output = redis::RedisResult<T>>,
    {
        let permit = timeout(
            self.config.command_timeout,
            Arc::clone(&self.permits).acquire_owned(),
        )
        .await
        .map_err(|_| EphemeralCoordinationError::TimedOut)?
        .map_err(|_| EphemeralCoordinationError::Unavailable)?;
        let connection = self.connection.clone();
        let result = timeout(self.config.command_timeout, operation(connection))
            .await
            .map_err(|_| EphemeralCoordinationError::TimedOut)?
            .map_err(|_| EphemeralCoordinationError::Unavailable);
        drop(permit);
        result
    }

    fn directory_key(&self, key: &DirectoryKey) -> String {
        format!(
            "{}:directory:{{{}:{}}}",
            self.config.key_prefix,
            key.tenant_id(),
            key.session_id()
        )
    }
    fn capability_key(&self, capability: &OneTimeCapability) -> String {
        format!(
            "{}:once:{{{}:{}}}:{}",
            self.config.key_prefix,
            capability.tenant_id(),
            capability.session_id(),
            hex::encode(capability.secret_hash())
        )
    }
    fn worker_key(&self, worker_id: &browserd_core::WorkerId) -> String {
        format!(
            "{}:{{browserd-worker}}:worker:{worker_id}:lease",
            self.config.key_prefix
        )
    }
    fn parse_worker_candidate_key(
        &self,
        candidate: &str,
    ) -> Result<browserd_core::WorkerId, EphemeralCoordinationError> {
        let prefix = format!("{}:{{browserd-worker}}:worker:", self.config.key_prefix);
        let worker = candidate
            .strip_prefix(&prefix)
            .and_then(|value| value.strip_suffix(":lease"))
            .ok_or(EphemeralCoordinationError::InvalidResponse)?;
        let worker_id = browserd_core::WorkerId::new(worker)
            .map_err(|_| EphemeralCoordinationError::InvalidResponse)?;
        if self.worker_key(&worker_id) != candidate {
            return Err(EphemeralCoordinationError::InvalidResponse);
        }
        Ok(worker_id)
    }
    fn parse_operation_candidate_key(
        &self,
        candidate: &str,
    ) -> Result<browserd_core::OperationId, EphemeralCoordinationError> {
        let prefix = format!("{}:{{browserd-worker}}:operation:", self.config.key_prefix);
        let value = candidate
            .strip_prefix(&prefix)
            .ok_or(EphemeralCoordinationError::InvalidResponse)?;
        let operation_id: browserd_core::OperationId = value
            .parse()
            .map_err(|_| EphemeralCoordinationError::InvalidResponse)?;
        if self.worker_reservation_key(&operation_id) != candidate {
            return Err(EphemeralCoordinationError::InvalidResponse);
        }
        Ok(operation_id)
    }
    async fn prepare_expired_candidates(
        &self,
        active_key: String,
    ) -> Result<Vec<(String, String)>, EphemeralCoordinationError> {
        let values: Vec<String> = self
            .execute(move |mut connection| async move {
                Script::new(WORKER_EXPIRED_CANDIDATES_SCRIPT)
                    .key(active_key)
                    .invoke_async(&mut connection)
                    .await
            })
            .await?;
        if values.first().map(String::as_str) != Some("1")
            || !(values.len() - 1).is_multiple_of(2)
            || (values.len() - 1) / 2 > 64
        {
            return Err(EphemeralCoordinationError::InvalidResponse);
        }
        let mut prepared_expired_candidates = Vec::new();
        for pair in values[1..].chunks_exact(2) {
            let operation_id = self.parse_operation_candidate_key(&pair[0])?;
            let valid_score = pair[1]
                .parse::<u64>()
                .is_ok_and(|score| score != 0 && score <= 9_007_199_254_740_991)
                && pair[1].bytes().all(|byte| byte.is_ascii_digit())
                && !pair[1].starts_with('0');
            if self.worker_reservation_key(&operation_id) != pair[0] || !valid_score {
                return Err(EphemeralCoordinationError::InvalidResponse);
            }
            prepared_expired_candidates.push((pair[0].clone(), pair[1].clone()));
        }
        Ok(prepared_expired_candidates)
    }
    fn worker_epoch_high_water_key(&self, worker_id: &browserd_core::WorkerId) -> String {
        format!(
            "{}:{{browserd-worker}}:worker:{worker_id}:epoch",
            self.config.key_prefix
        )
    }
    fn worker_ready_index_key(&self, region: &str, compatibility: &str) -> String {
        let mut digest = Sha256::new();
        digest.update(b"browserd-worker-ready-index-v1\0");
        digest.update(region.as_bytes());
        digest.update(b"\0");
        digest.update(compatibility.as_bytes());
        format!(
            "{}:{{browserd-worker}}:ready:{}",
            self.config.key_prefix,
            hex::encode(digest.finalize())
        )
    }
    fn worker_reservation_key(&self, operation_id: &browserd_core::OperationId) -> String {
        format!(
            "{}:{{browserd-worker}}:operation:{operation_id}",
            self.config.key_prefix
        )
    }
    fn worker_active_reservations_key(&self, worker_id: &browserd_core::WorkerId) -> String {
        format!(
            "{}:{{browserd-worker}}:worker:{worker_id}:active",
            self.config.key_prefix
        )
    }
}

#[cfg(test)]
fn worker_atomic_keys_for_test(prefix: &str, worker: &str, operation: &str) -> Vec<String> {
    vec![
        format!("{prefix}:{{browserd-worker}}:worker:{worker}:lease"),
        format!("{prefix}:{{browserd-worker}}:worker:{worker}:epoch"),
        format!("{prefix}:{{browserd-worker}}:operation:{operation}"),
        format!("{prefix}:{{browserd-worker}}:worker:{worker}:active"),
    ]
}

fn mutation(code: i64) -> Result<DirectoryMutation, EphemeralCoordinationError> {
    match code {
        0 => Ok(DirectoryMutation::FenceMismatch),
        1 => Ok(DirectoryMutation::Applied),
        2 => Ok(DirectoryMutation::CasMismatch),
        3 => Ok(DirectoryMutation::Expired),
        4 => Err(EphemeralCoordinationError::RevisionExhausted),
        5 => Ok(DirectoryMutation::AlreadyApplied),
        _ => Err(EphemeralCoordinationError::InvalidResponse),
    }
}

fn valid_u64_decimal(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && (value == "0" || !value.starts_with('0'))
        && (value.len() < 20 || (value.len() == 20 && value <= "18446744073709551615"))
}

#[cfg(test)]
fn subtract_u64_decimal(left: &str, right: &str) -> Option<String> {
    let left = left.parse::<u64>().ok()?;
    let right = right.parse::<u64>().ok()?;
    left.checked_sub(right).map(|value| value.to_string())
}

#[cfg(test)]
fn add_u64_decimal(left: &str, right: &str) -> Option<String> {
    let left = left.parse::<u64>().ok()?;
    let right = right.parse::<u64>().ok()?;
    left.checked_add(right).map(|value| value.to_string())
}

#[cfg(test)]
fn valid_nonzero_u64_decimal(value: &str) -> bool {
    valid_u64_decimal(value) && value != "0"
}

#[cfg(test)]
fn compare_u64_decimal(
    left: &str,
    right: &str,
) -> Result<std::cmp::Ordering, EphemeralCoordinationError> {
    if !valid_u64_decimal(left) || !valid_u64_decimal(right) {
        return Err(EphemeralCoordinationError::InvalidResponse);
    }
    Ok(left.len().cmp(&right.len()).then_with(|| left.cmp(right)))
}

#[cfg(test)]
fn increment_u64_decimal(value: &str) -> Result<String, EphemeralCoordinationError> {
    if !valid_u64_decimal(value) {
        return Err(EphemeralCoordinationError::InvalidResponse);
    }
    value
        .parse::<u64>()
        .map_err(|_| EphemeralCoordinationError::InvalidResponse)?
        .checked_add(1)
        .map(|next| next.to_string())
        .ok_or(EphemeralCoordinationError::RevisionExhausted)
}

fn decode_snapshot_values(
    values: &[String],
) -> Result<DirectorySnapshot, EphemeralCoordinationError> {
    if values.len() != 3 {
        return Err(EphemeralCoordinationError::InvalidResponse);
    }
    let decoded: DirectoryEntry = serde_json::from_str(&values[0])
        .map_err(|_| EphemeralCoordinationError::InvalidResponse)?;
    let fence = crate::DirectoryFence::new(
        decoded.fence().worker_id().clone(),
        decoded.fence().worker_epoch(),
        decoded.fence().placement_version(),
        decoded.fence().session_incarnation(),
    )
    .map_err(|_| EphemeralCoordinationError::InvalidResponse)?;
    let entry = DirectoryEntry::new(decoded.key().clone(), fence, decoded.endpoint())
        .map_err(|_| EphemeralCoordinationError::InvalidResponse)?;
    if !valid_u64_decimal(&values[1]) || !valid_u64_decimal(&values[2]) {
        return Err(EphemeralCoordinationError::InvalidResponse);
    }
    let revision = values[1]
        .parse::<u64>()
        .map_err(|_| EphemeralCoordinationError::InvalidResponse)?;
    let expires = values[2]
        .parse::<u64>()
        .map_err(|_| EphemeralCoordinationError::InvalidResponse)?;
    DirectorySnapshot::from_persisted(entry, revision, expires)
        .map_err(|_| EphemeralCoordinationError::InvalidResponse)
}

fn readiness_wire(readiness: WorkerReadiness) -> &'static str {
    match readiness {
        WorkerReadiness::Ready => "ready",
        WorkerReadiness::Draining => "draining",
        WorkerReadiness::Unready => "unready",
    }
}

fn decode_worker_snapshot(
    registration_json: &str,
    heartbeat_json: &str,
    revision: &str,
    expires_at: &str,
) -> Result<WorkerRegistrationSnapshot, EphemeralCoordinationError> {
    if !valid_u64_decimal(revision)
        || revision == "0"
        || !valid_u64_decimal(expires_at)
        || expires_at == "0"
    {
        return Err(EphemeralCoordinationError::InvalidResponse);
    }
    let registration = serde_json::from_str(registration_json)
        .map_err(|_| EphemeralCoordinationError::InvalidResponse)?;
    let heartbeat = serde_json::from_str(heartbeat_json)
        .map_err(|_| EphemeralCoordinationError::InvalidResponse)?;
    WorkerRegistrationSnapshot::from_persisted(
        registration,
        heartbeat,
        revision
            .parse()
            .map_err(|_| EphemeralCoordinationError::InvalidResponse)?,
        expires_at
            .parse()
            .map_err(|_| EphemeralCoordinationError::InvalidResponse)?,
    )
    .map_err(|_| EphemeralCoordinationError::InvalidResponse)
}

fn worker_mutation(
    values: &[String],
    registration: Option<&WorkerRegistration>,
    heartbeat: Option<&WorkerHeartbeat>,
) -> Result<WorkerLeaseMutation, EphemeralCoordinationError> {
    let Some(code) = values.first().map(String::as_str) else {
        return Err(EphemeralCoordinationError::InvalidResponse);
    };
    match code {
        "0" => Ok(WorkerLeaseMutation::FenceMismatch),
        "1" if values.len() == 3 => {
            let registration = registration.ok_or(EphemeralCoordinationError::InvalidResponse)?;
            let heartbeat = heartbeat.ok_or(EphemeralCoordinationError::InvalidResponse)?;
            let registration_json = serde_json::to_string(registration)
                .map_err(|_| EphemeralCoordinationError::InvalidResponse)?;
            let heartbeat_json = serde_json::to_string(heartbeat)
                .map_err(|_| EphemeralCoordinationError::InvalidResponse)?;
            decode_worker_snapshot(&registration_json, &heartbeat_json, &values[1], &values[2])
                .map(Box::new)
                .map(WorkerLeaseMutation::Applied)
        }
        "2" => Ok(WorkerLeaseMutation::CasMismatch),
        "3" => Ok(WorkerLeaseMutation::Expired),
        "4" => Err(EphemeralCoordinationError::RevisionExhausted),
        "5" => Ok(WorkerLeaseMutation::AlreadyApplied),
        _ => Err(EphemeralCoordinationError::InvalidResponse),
    }
}

#[async_trait]
impl EphemeralCoordinationStore for RedisEphemeralCoordinationStore {
    async fn register_directory(
        &self,
        entry: DirectoryEntry,
        ttl: Duration,
    ) -> Result<DirectoryMutation, EphemeralCoordinationError> {
        let key = self.directory_key(entry.key());
        let ttl = ttl_millis(ttl)?;
        let epoch = entry.fence().worker_epoch();
        let placement = entry.fence().placement_version();
        let worker_id = entry.fence().worker_id().as_str().to_owned();
        let incarnation = entry.fence().session_incarnation();
        let json =
            serde_json::to_string(&entry).map_err(|_| EphemeralCoordinationError::InvalidInput)?;
        mutation(
            self.execute(move |mut connection| async move {
                Script::new(REGISTER_SCRIPT)
                    .key(key)
                    .arg(worker_id)
                    .arg(epoch)
                    .arg(placement)
                    .arg(incarnation)
                    .arg(json)
                    .arg(ttl)
                    .invoke_async(&mut connection)
                    .await
            })
            .await?,
        )
    }
    async fn resolve_directory(
        &self,
        key: &DirectoryKey,
    ) -> Result<Option<DirectorySnapshot>, EphemeralCoordinationError> {
        let key = self.directory_key(key);
        let values: Vec<String> = self
            .execute(move |mut connection| async move {
                Script::new(RESOLVE_SCRIPT)
                    .key(key)
                    .invoke_async(&mut connection)
                    .await
            })
            .await?;
        if values.is_empty() {
            return Ok(None);
        }
        decode_snapshot_values(&values).map(Some)
    }
    async fn renew_directory(
        &self,
        snapshot: &DirectorySnapshot,
        ttl: Duration,
    ) -> Result<DirectoryMutation, EphemeralCoordinationError> {
        let key = self.directory_key(snapshot.entry().key());
        let revision = snapshot.revision();
        let json = serde_json::to_string(snapshot.entry())
            .map_err(|_| EphemeralCoordinationError::InvalidInput)?;
        let ttl = ttl_millis(ttl)?;
        mutation(
            self.execute(move |mut connection| async move {
                Script::new(RENEW_SCRIPT)
                    .key(key)
                    .arg(revision)
                    .arg(json)
                    .arg(ttl)
                    .invoke_async(&mut connection)
                    .await
            })
            .await?,
        )
    }
    async fn remove_directory(
        &self,
        snapshot: &DirectorySnapshot,
    ) -> Result<DirectoryMutation, EphemeralCoordinationError> {
        let key = self.directory_key(snapshot.entry().key());
        let revision = snapshot.revision();
        let json = serde_json::to_string(snapshot.entry())
            .map_err(|_| EphemeralCoordinationError::InvalidInput)?;
        mutation(
            self.execute(move |mut connection| async move {
                Script::new(REMOVE_SCRIPT)
                    .key(key)
                    .arg(revision)
                    .arg(json)
                    .invoke_async(&mut connection)
                    .await
            })
            .await?,
        )
    }
    async fn issue_one_time(
        &self,
        capability: OneTimeCapability,
        ttl: Duration,
    ) -> Result<OneTimeIssue, EphemeralCoordinationError> {
        let key = self.capability_key(&capability);
        let ttl = ttl_millis(ttl)?;
        let code: i64 = self
            .execute(move |mut connection| async move {
                Script::new(ISSUE_SCRIPT)
                    .key(key)
                    .arg(ttl)
                    .invoke_async(&mut connection)
                    .await
            })
            .await?;
        match code {
            1 => Ok(OneTimeIssue::Issued),
            2 => Ok(OneTimeIssue::AlreadyIssued),
            3 => Ok(OneTimeIssue::AlreadyConsumed),
            _ => Err(EphemeralCoordinationError::InvalidResponse),
        }
    }
    async fn consume_one_time(
        &self,
        capability: &OneTimeCapability,
    ) -> Result<OneTimeConsume, EphemeralCoordinationError> {
        let key = self.capability_key(capability);
        let code: i64 = self
            .execute(move |mut connection| async move {
                Script::new(CONSUME_SCRIPT)
                    .key(key)
                    .arg(MAX_EPHEMERAL_TTL_MILLIS)
                    .invoke_async(&mut connection)
                    .await
            })
            .await?;
        match code {
            0 => Ok(OneTimeConsume::AlreadyConsumed),
            1 => Ok(OneTimeConsume::Consumed),
            _ => Err(EphemeralCoordinationError::InvalidResponse),
        }
    }
}

#[async_trait]
impl WorkerLeaseStore for RedisEphemeralCoordinationStore {
    async fn register_worker(
        &self,
        registration: WorkerRegistration,
        heartbeat: WorkerHeartbeat,
        ttl: Duration,
    ) -> Result<WorkerLeaseMutation, EphemeralCoordinationError> {
        if !heartbeat.free().fits_within(registration.capacity()) {
            return Err(EphemeralCoordinationError::InvalidInput);
        }
        let key = self.worker_key(registration.worker_id());
        let high_water_key = self.worker_epoch_high_water_key(registration.worker_id());
        let active_key = self.worker_active_reservations_key(registration.worker_id());
        let desired_ready_keys = registration
            .compatibility()
            .iter()
            .map(|compatibility| self.worker_ready_index_key(registration.region(), compatibility))
            .collect::<Vec<_>>();
        let ttl = ttl_millis(ttl)?;
        let epoch = registration.worker_epoch();
        let region = registration.region().to_owned();
        let compatibility = serde_json::to_string(registration.compatibility())
            .map_err(|_| EphemeralCoordinationError::InvalidInput)?;
        let readiness = readiness_wire(heartbeat.readiness());
        let registration_json = serde_json::to_string(&registration)
            .map_err(|_| EphemeralCoordinationError::InvalidInput)?;
        let heartbeat_json = serde_json::to_string(&heartbeat)
            .map_err(|_| EphemeralCoordinationError::InvalidInput)?;
        let script_registration = registration_json.clone();
        let script_heartbeat = heartbeat_json.clone();
        let free = heartbeat.free().components();
        let capacity = registration.capacity().components();
        let queue_depth = heartbeat.queue_depth();
        let active_shards = heartbeat.active_shards();
        for _ in 0..8 {
            let observe_key = key.clone();
            let observed: Vec<String> = self
                .execute(move |mut connection| async move {
                    Script::new(WORKER_REGISTER_OBSERVE_SCRIPT)
                        .key(observe_key)
                        .invoke_async(&mut connection)
                        .await
                })
                .await?;
            let (
                observed_exists,
                observed_epoch,
                observed_revision,
                observed_entry,
                old_ready_keys,
            ) = match observed.first().map(String::as_str) {
                Some("0") if observed.len() == 1 => (
                    "0".to_owned(),
                    String::new(),
                    String::new(),
                    String::new(),
                    Vec::new(),
                ),
                Some("1") if observed.len() == 9 => {
                    let old: WorkerRegistration = serde_json::from_str(&observed[3])
                        .map_err(|_| EphemeralCoordinationError::InvalidResponse)?;
                    let snapshot = decode_worker_snapshot(
                        &observed[3],
                        &observed[4],
                        &observed[2],
                        &observed[8],
                    )?;
                    let encoded_entry = serde_json::to_string(&old)
                        .map_err(|_| EphemeralCoordinationError::InvalidResponse)?;
                    let encoded_heartbeat = serde_json::to_string(snapshot.heartbeat())
                        .map_err(|_| EphemeralCoordinationError::InvalidResponse)?;
                    let encoded_compatibility = serde_json::to_string(old.compatibility())
                        .map_err(|_| EphemeralCoordinationError::InvalidResponse)?;
                    if old.worker_id() != registration.worker_id()
                        || snapshot.registration() != &old
                        || snapshot.worker_epoch().to_string() != observed[1]
                        || encoded_entry != observed[3]
                        || encoded_heartbeat != observed[4]
                        || old.region() != observed[5]
                        || encoded_compatibility != observed[6]
                        || readiness_wire(snapshot.heartbeat().readiness()) != observed[7]
                    {
                        return Err(EphemeralCoordinationError::InvalidResponse);
                    }
                    let keys = old
                        .compatibility()
                        .iter()
                        .map(|compatibility| {
                            self.worker_ready_index_key(old.region(), compatibility)
                        })
                        .collect::<Vec<_>>();
                    (
                        "1".to_owned(),
                        observed[1].clone(),
                        observed[2].clone(),
                        observed[3].clone(),
                        keys,
                    )
                }
                _ => return Err(EphemeralCoordinationError::InvalidResponse),
            };
            let desired = desired_ready_keys.iter().cloned().collect::<BTreeSet<_>>();
            let old_only = old_ready_keys
                .into_iter()
                .filter(|key| !desired.contains(key))
                .collect::<BTreeSet<_>>();
            let old_count = old_only.len();
            let key = key.clone();
            let high_water_key = high_water_key.clone();
            let active_key = active_key.clone();
            let desired_ready_keys = desired_ready_keys.clone();
            let script_registration = script_registration.clone();
            let script_heartbeat = script_heartbeat.clone();
            let region = region.clone();
            let compatibility = compatibility.clone();
            let readiness = readiness.to_owned();
            let values: Vec<String> = self
                .execute(move |mut connection| async move {
                    let script = Script::new(WORKER_REGISTER_SCRIPT);
                    let mut invocation = script.prepare_invoke();
                    invocation.key(key).key(high_water_key).key(active_key);
                    for ready_key in old_only {
                        invocation.key(ready_key);
                    }
                    for ready_key in desired_ready_keys {
                        invocation.key(ready_key);
                    }
                    invocation
                        .arg(epoch)
                        .arg(script_registration)
                        .arg(script_heartbeat)
                        .arg(region)
                        .arg(compatibility)
                        .arg(readiness)
                        .arg(ttl)
                        .arg(free[0])
                        .arg(free[1])
                        .arg(free[2])
                        .arg(free[3])
                        .arg(free[4])
                        .arg(free[5])
                        .arg(capacity[0])
                        .arg(capacity[1])
                        .arg(capacity[2])
                        .arg(capacity[3])
                        .arg(capacity[4])
                        .arg(capacity[5])
                        .arg(queue_depth)
                        .arg(active_shards)
                        .arg(old_count)
                        .arg(observed_exists)
                        .arg(observed_epoch)
                        .arg(observed_revision)
                        .arg(observed_entry)
                        .invoke_async(&mut connection)
                        .await
                })
                .await?;
            if values.first().map(String::as_str) == Some("9") {
                continue;
            }
            return worker_mutation(&values, Some(&registration), Some(&heartbeat));
        }
        Err(EphemeralCoordinationError::TimedOut)
    }

    async fn heartbeat_worker(
        &self,
        expected: &WorkerRegistrationSnapshot,
        heartbeat: WorkerHeartbeat,
        ttl: Duration,
    ) -> Result<WorkerLeaseMutation, EphemeralCoordinationError> {
        if !heartbeat
            .free()
            .fits_within(expected.registration().capacity())
        {
            return Err(EphemeralCoordinationError::InvalidInput);
        }
        let key = self.worker_key(expected.registration().worker_id());
        let active_key = self.worker_active_reservations_key(expected.registration().worker_id());
        let ready_keys = expected
            .registration()
            .compatibility()
            .iter()
            .map(|compatibility| {
                self.worker_ready_index_key(expected.registration().region(), compatibility)
            })
            .collect::<Vec<_>>();
        let ttl = ttl_millis(ttl)?;
        let registration_json = serde_json::to_string(expected.registration())
            .map_err(|_| EphemeralCoordinationError::InvalidInput)?;
        let old_heartbeat_json = serde_json::to_string(expected.heartbeat())
            .map_err(|_| EphemeralCoordinationError::InvalidInput)?;
        let heartbeat_json = serde_json::to_string(&heartbeat)
            .map_err(|_| EphemeralCoordinationError::InvalidInput)?;
        let readiness = readiness_wire(heartbeat.readiness());
        let epoch = expected.worker_epoch();
        let revision = expected.revision();
        let expiry = expected.expires_at_millis();
        let script_registration = registration_json.clone();
        let script_heartbeat = heartbeat_json.clone();
        let free = heartbeat.free().components();
        let queue_depth = heartbeat.queue_depth();
        let active_shards = heartbeat.active_shards();
        let worker_id = expected.registration().worker_id().to_string();
        for _ in 0..8 {
            let prepared_expired_candidates =
                self.prepare_expired_candidates(active_key.clone()).await?;
            let expired_count = prepared_expired_candidates.len();
            let script_key = key.clone();
            let script_active_key = active_key.clone();
            let script_ready_keys = ready_keys.clone();
            let script_registration = script_registration.clone();
            let old_heartbeat_json = old_heartbeat_json.clone();
            let script_heartbeat = script_heartbeat.clone();
            let worker_id = worker_id.clone();
            let values: Vec<String> = self
                .execute(move |mut connection| async move {
                    let script = Script::new(WORKER_HEARTBEAT_SCRIPT);
                    let mut invocation = script.prepare_invoke();
                    invocation.key(script_key).key(script_active_key);
                    for (candidate_key, _) in &prepared_expired_candidates {
                        invocation.key(candidate_key);
                    }
                    for ready_key in script_ready_keys {
                        invocation.key(ready_key);
                    }
                    invocation
                        .arg(epoch)
                        .arg(revision)
                        .arg(script_registration)
                        .arg(old_heartbeat_json)
                        .arg(expiry)
                        .arg(script_heartbeat)
                        .arg(readiness)
                        .arg(ttl)
                        .arg(free[0])
                        .arg(free[1])
                        .arg(free[2])
                        .arg(free[3])
                        .arg(free[4])
                        .arg(free[5])
                        .arg(queue_depth)
                        .arg(active_shards)
                        .arg(worker_id)
                        .arg(expired_count);
                    for (_, score) in prepared_expired_candidates {
                        invocation.arg(score);
                    }
                    invocation.invoke_async(&mut connection).await
                })
                .await?;
            if values.first().map(String::as_str) == Some("9") {
                continue;
            }
            if values.first().map(String::as_str) == Some("1") && values.len() == 4 {
                let applied_heartbeat: WorkerHeartbeat = serde_json::from_str(&values[3])
                    .map_err(|_| EphemeralCoordinationError::InvalidResponse)?;
                let snapshot = WorkerRegistrationSnapshot::from_persisted(
                    expected.registration().clone(),
                    applied_heartbeat,
                    values[1]
                        .parse()
                        .map_err(|_| EphemeralCoordinationError::InvalidResponse)?,
                    values[2]
                        .parse()
                        .map_err(|_| EphemeralCoordinationError::InvalidResponse)?,
                )?;
                return Ok(WorkerLeaseMutation::Applied(Box::new(snapshot)));
            }
            return worker_mutation(&values, Some(expected.registration()), Some(&heartbeat));
        }
        Err(EphemeralCoordinationError::TimedOut)
    }

    async fn query_ready_workers(
        &self,
        query: &WorkerRegistrationQuery,
    ) -> Result<Vec<WorkerRegistrationSnapshot>, EphemeralCoordinationError> {
        let region = query.region().to_owned();
        let compatibility = query.compatibility().to_owned();
        let limit = query.limit();
        let ready_index_key = self.worker_ready_index_key(&region, &compatibility);
        let candidate_limit = limit.saturating_add(64).min(1088);
        for _ in 0..8 {
            let candidate_index = ready_index_key.clone();
            let candidates: Vec<String> = self
                .execute(move |mut connection| async move {
                    Script::new(WORKER_QUERY_CANDIDATES_SCRIPT)
                        .key(candidate_index)
                        .arg(candidate_limit)
                        .invoke_async(&mut connection)
                        .await
                })
                .await?;
            if candidates.first().map(String::as_str) != Some("1") {
                return Err(EphemeralCoordinationError::InvalidResponse);
            }
            let candidate_keys = candidates[1..].to_vec();
            if !candidate_keys
                .iter()
                .all(|candidate| self.parse_worker_candidate_key(candidate).is_ok())
            {
                return Err(EphemeralCoordinationError::InvalidResponse);
            }
            if candidate_keys.is_empty() {
                return Ok(Vec::new());
            }
            let validation_index = ready_index_key.clone();
            let validation_candidates = candidate_keys.clone();
            let script_region = region.clone();
            let script_compatibility = compatibility.clone();
            let values: Vec<String> = self
                .execute(move |mut connection| async move {
                    let script = Script::new(WORKER_QUERY_VALIDATE_SCRIPT);
                    let mut invocation = script.prepare_invoke();
                    invocation.key(validation_index);
                    for candidate_key in validation_candidates {
                        invocation.key(candidate_key);
                    }
                    invocation
                        .arg(script_region)
                        .arg(script_compatibility)
                        .arg(limit)
                        .invoke_async(&mut connection)
                        .await
                })
                .await?;
            if values.first().map(String::as_str) == Some("9") {
                continue;
            }
            if values.first().map(String::as_str) != Some("1")
                || !(values.len() - 1).is_multiple_of(5)
            {
                return Err(EphemeralCoordinationError::InvalidResponse);
            }
            let mut snapshots = Vec::with_capacity((values.len() - 1) / 5);
            for chunk in values[1..].chunks_exact(5) {
                let worker_id = self.parse_worker_candidate_key(&chunk[0])?;
                let snapshot = decode_worker_snapshot(&chunk[1], &chunk[2], &chunk[3], &chunk[4])?;
                if snapshot.registration().worker_id() != &worker_id
                    || snapshot.registration().region() != region
                    || snapshot.heartbeat().readiness() != WorkerReadiness::Ready
                    || !snapshot
                        .registration()
                        .compatibility()
                        .iter()
                        .any(|value| value == &compatibility)
                {
                    return Err(EphemeralCoordinationError::InvalidResponse);
                }
                snapshots.push(snapshot);
            }
            return Ok(snapshots);
        }
        Err(EphemeralCoordinationError::TimedOut)
    }
}

#[async_trait]
impl WorkerReservationStore for RedisEphemeralCoordinationStore {
    async fn reserve_worker(
        &self,
        expected_worker: &WorkerRegistrationSnapshot,
        request: WorkerReservationRequest,
        ttl: Duration,
    ) -> Result<WorkerReservationOutcome, EphemeralCoordinationError> {
        let ttl = ttl_millis(ttl)?;
        let worker_key = self.worker_key(expected_worker.registration().worker_id());
        let reservation_key = self.worker_reservation_key(request.operation_id());
        let active_key =
            self.worker_active_reservations_key(expected_worker.registration().worker_id());
        let epoch = expected_worker.worker_epoch();
        let revision = expected_worker.revision();
        let registration_json = serde_json::to_string(expected_worker.registration())
            .map_err(|_| EphemeralCoordinationError::InvalidInput)?;
        let old_heartbeat_json = serde_json::to_string(expected_worker.heartbeat())
            .map_err(|_| EphemeralCoordinationError::InvalidInput)?;
        let heartbeat_json = String::new();
        let request_json = serde_json::to_string(&request)
            .map_err(|_| EphemeralCoordinationError::InvalidInput)?;
        let operation_id = request.operation_id().to_string();
        let tenant_id = request.tenant_id().to_string();
        let resources_json = serde_json::to_string(&request.resources())
            .map_err(|_| EphemeralCoordinationError::InvalidInput)?;
        let worker_id = expected_worker
            .registration()
            .worker_id()
            .as_str()
            .to_owned();
        let requested = request.resources().components();
        for _ in 0..8 {
            let prepared_expired_candidates =
                self.prepare_expired_candidates(active_key.clone()).await?;
            let expired_count = prepared_expired_candidates.len();
            let script_worker_key = worker_key.clone();
            let script_reservation_key = reservation_key.clone();
            let script_active_key = active_key.clone();
            let registration_json = registration_json.clone();
            let old_heartbeat_json = old_heartbeat_json.clone();
            let heartbeat_json = heartbeat_json.clone();
            let operation_id = operation_id.clone();
            let tenant_id = tenant_id.clone();
            let resources_json = resources_json.clone();
            let request_json = request_json.clone();
            let worker_id = worker_id.clone();
            let values: Vec<String> = self
                .execute(move |mut connection| async move {
                    let script = Script::new(RESERVE_WORKER_SCRIPT);
                    let mut invocation = script.prepare_invoke();
                    invocation
                        .key(script_worker_key)
                        .key(script_reservation_key)
                        .key(script_active_key);
                    for (candidate_key, _) in &prepared_expired_candidates {
                        invocation.key(candidate_key);
                    }
                    invocation
                        .arg(epoch)
                        .arg(revision)
                        .arg(registration_json)
                        .arg(old_heartbeat_json)
                        .arg(operation_id)
                        .arg(tenant_id)
                        .arg(resources_json)
                        .arg(heartbeat_json)
                        .arg(request_json)
                        .arg(ttl)
                        .arg(worker_id)
                        .arg(64_u8)
                        .arg(requested[0])
                        .arg(requested[1])
                        .arg(requested[2])
                        .arg(requested[3])
                        .arg(requested[4])
                        .arg(requested[5])
                        .arg(expired_count);
                    for (_, score) in prepared_expired_candidates {
                        invocation.arg(score);
                    }
                    invocation.invoke_async(&mut connection).await
                })
                .await?;
            match values.first().map(String::as_str) {
                Some("0") => return Ok(WorkerReservationOutcome::FenceMismatch),
                Some("1") if values.len() == 6 => {
                    let worker =
                        decode_worker_snapshot(&values[1], &values[2], &values[3], &values[4])?;
                    let reservation = WorkerReservationSnapshot::from_persisted(
                        request.clone(),
                        worker.clone(),
                        values[5]
                            .parse()
                            .map_err(|_| EphemeralCoordinationError::InvalidResponse)?,
                    )?;
                    return Ok(WorkerReservationOutcome::Acquired(Box::new(
                        WorkerReservationGrant::new(reservation, worker),
                    )));
                }
                Some("2") => return Ok(WorkerReservationOutcome::CasMismatch),
                Some("3") => return Ok(WorkerReservationOutcome::Expired),
                Some("4") => return Err(EphemeralCoordinationError::RevisionExhausted),
                Some("5") if values.len() == 7 => {
                    let stored_request: WorkerReservationRequest = serde_json::from_str(&values[1])
                        .map_err(|_| EphemeralCoordinationError::InvalidResponse)?;
                    let worker =
                        decode_worker_snapshot(&values[2], &values[3], &values[4], &values[5])?;
                    let reservation = WorkerReservationSnapshot::from_persisted(
                        stored_request,
                        worker.clone(),
                        values[6]
                            .parse()
                            .map_err(|_| EphemeralCoordinationError::InvalidResponse)?,
                    )?;
                    return Ok(WorkerReservationOutcome::Existing(Box::new(
                        WorkerReservationGrant::new(reservation, worker),
                    )));
                }
                Some("7") => return Ok(WorkerReservationOutcome::WorkerUnavailable),
                Some("8") => return Ok(WorkerReservationOutcome::Conflict),
                Some("9") => continue,
                Some("10") => return Ok(WorkerReservationOutcome::CapacityExhausted),
                _ => return Err(EphemeralCoordinationError::InvalidResponse),
            }
        }
        Err(EphemeralCoordinationError::TimedOut)
    }

    async fn release_worker_reservation(
        &self,
        expected: &WorkerReservationSnapshot,
    ) -> Result<WorkerReservationMutation, EphemeralCoordinationError> {
        let worker_key = self.worker_key(expected.worker_id());
        let reservation_key = self.worker_reservation_key(expected.operation_id());
        let active_key = self.worker_active_reservations_key(expected.worker_id());
        let current = expected.worker();
        let registration_json = serde_json::to_string(current.registration())
            .map_err(|_| EphemeralCoordinationError::InvalidInput)?;
        let expected_json = serde_json::to_string(expected.request())
            .map_err(|_| EphemeralCoordinationError::InvalidInput)?;
        let values: Vec<String> = self
            .execute(move |mut connection| async move {
                Script::new(RELEASE_WORKER_RESERVATION_SCRIPT)
                    .key(worker_key)
                    .key(reservation_key)
                    .key(active_key)
                    .arg(expected.worker_epoch())
                    .arg(expected.worker_revision())
                    .arg(registration_json)
                    .arg(expected_json)
                    .arg("")
                    .arg("")
                    .arg(expected.worker_id().as_str())
                    .invoke_async(&mut connection)
                    .await
            })
            .await?;
        match values.first().map(String::as_str) {
            Some("0") => Ok(WorkerReservationMutation::FenceMismatch),
            Some("1") if values.len() == 5 => {
                let worker =
                    decode_worker_snapshot(&values[1], &values[2], &values[3], &values[4])?;
                Ok(WorkerReservationMutation::Released(Box::new(worker)))
            }
            Some("2") => Ok(WorkerReservationMutation::CasMismatch),
            Some("3") => Ok(WorkerReservationMutation::Expired),
            Some("5") => Ok(WorkerReservationMutation::AlreadyReleased),
            _ => Err(EphemeralCoordinationError::InvalidResponse),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use browserd_core::{SessionId, TenantId, WorkerId};
    use std::cmp::Ordering;
    #[test]
    fn scripts_use_redis_time_ttl_and_atomic_cas() {
        assert!(REGISTER_SCRIPT.contains("redis.call('TIME')"));
        assert!(REGISTER_SCRIPT.contains("PEXPIRE"));
        assert!(RENEW_SCRIPT.contains("revision"));
        assert!(REMOVE_SCRIPT.contains("DEL"));
        assert!(CONSUME_SCRIPT.contains("GET"));
        assert!(CONSUME_SCRIPT.contains("'PX', ARGV[1]"));
        assert!(ISSUE_SCRIPT.contains("NX"));
    }

    #[test]
    fn issue_script_only_reports_issued_after_successful_nx_write() {
        assert!(ISSUE_SCRIPT.contains("if current ~= false then return 6 end"));
        assert!(ISSUE_SCRIPT.contains("local stored = redis.call('SET'"));
        assert!(ISSUE_SCRIPT.contains("if not stored then return 6 end"));
    }

    #[test]
    fn worker_lease_scripts_use_store_time_ttl_and_full_u64_fencing() {
        for script in [WORKER_REGISTER_SCRIPT, WORKER_HEARTBEAT_SCRIPT] {
            assert!(script.contains("redis.call('TIME')"));
            assert!(script.contains("PTTL"));
            assert!(!script.contains("tonumber"));
            assert!(script.contains("valid_u64"));
            assert!(script.contains("return {'6'}"));
        }
        assert!(WORKER_REGISTER_SCRIPT.contains("worker_epoch"));
        assert!(WORKER_REGISTER_SCRIPT.contains("PEXPIRE"));
        assert!(WORKER_HEARTBEAT_SCRIPT.contains("revision"));
        assert!(WORKER_HEARTBEAT_SCRIPT.contains("entry"));
    }

    #[test]
    fn worker_registration_rejects_corrupt_or_non_expiring_existing_hashes() {
        assert!(WORKER_REGISTER_SCRIPT.contains("redis.call('PTTL', KEYS[1]) <= 0"));
        assert!(WORKER_REGISTER_SCRIPT.contains("valid_u64(current_epoch)"));
        assert!(WORKER_REGISTER_SCRIPT.contains("valid_u64(current_revision)"));
        assert!(WORKER_HEARTBEAT_SCRIPT.contains("redis.call('PTTL', KEYS[1]) <= 0"));
    }

    #[test]
    fn worker_registration_retains_a_non_expiring_epoch_high_water_mark() {
        assert!(WORKER_REGISTER_SCRIPT.contains("redis.call('GET', KEYS[2])"));
        assert!(WORKER_REGISTER_SCRIPT.contains("redis.call('SET', KEYS[2], ARGV[1])"));
        assert!(!WORKER_REGISTER_SCRIPT.contains("PEXPIRE', KEYS[2]"));
    }

    #[test]
    fn worker_ready_query_is_cursor_and_result_bounded() {
        assert!(WORKER_QUERY_CANDIDATES_SCRIPT.contains("ZRANGE"));
        assert!(WORKER_QUERY_CANDIDATES_SCRIPT.contains("ZREMRANGEBYSCORE"));
        assert!(!WORKER_QUERY_CANDIDATES_SCRIPT.contains("SCAN"));
        assert!(WORKER_QUERY_VALIDATE_SCRIPT.contains("PTTL"));
        assert!(WORKER_QUERY_VALIDATE_SCRIPT.contains("ready"));
    }

    #[test]
    fn worker_ready_query_uses_an_atomic_same_slot_ready_index() {
        let source = include_str!("redis.rs");
        assert!(source.contains("fn worker_ready_index_key"));
        assert!(source.contains("{browserd-worker}"));
        assert!(WORKER_QUERY_CANDIDATES_SCRIPT.contains("ZRANGE"));
        assert!(!WORKER_QUERY_CANDIDATES_SCRIPT.contains("SCAN"));
        assert!(WORKER_REGISTER_SCRIPT.contains("index = 4, #KEYS"));
        assert!(WORKER_REGISTER_SCRIPT.contains("'DEL', KEYS[3]"));
        assert!(WORKER_REGISTER_SCRIPT.contains("ZADD"));
        assert!(WORKER_HEARTBEAT_SCRIPT.contains("index = ready_offset, #KEYS"));
        assert!(WORKER_HEARTBEAT_SCRIPT.contains("ZADD"));
        assert!(WORKER_QUERY_VALIDATE_SCRIPT.contains("KEYS[1]"));
    }

    #[test]
    fn worker_ready_query_declares_every_cluster_key_before_validation() {
        let source = include_str!("redis.rs");
        assert!(source.contains("const WORKER_QUERY_CANDIDATES_SCRIPT"));
        assert!(source.contains("const WORKER_QUERY_VALIDATE_SCRIPT"));
        let legacy_script = ["const WORKER_QUERY_", "SCRIPT: &str"].concat();
        assert!(!source.contains(&legacy_script));
        assert!(source.contains("fn parse_worker_candidate_key"));
        assert!(source.contains("candidate_keys.iter().all"));
        assert!(source.contains("invocation.key(validation_index)"));
        assert!(source.contains("invocation.key(candidate_key)"));
        assert!(source.contains("{browserd-worker}"));
        assert!(source.contains("ZREMRANGEBYSCORE', KEYS[1]"));
        assert!(source.contains("ZRANGE', KEYS[1]"));
        let undeclared_read = ["redis.call('HGET', ", "key, 'entry')"].concat();
        assert!(!source.contains(&undeclared_read));
    }

    #[test]
    fn worker_expiry_sweeps_declare_every_operation_key_before_mutation() {
        let source = include_str!("redis.rs");
        assert!(source.contains("const WORKER_EXPIRED_CANDIDATES_SCRIPT"));
        assert!(source.contains("fn parse_operation_candidate_key"));
        assert!(source.contains("prepared_expired_candidates"));
        assert!(source.contains("invocation.key(candidate_key)"));
        assert!(source.contains("WORKER_HEARTBEAT_SCRIPT"));
        assert!(source.contains("RESERVE_WORKER_SCRIPT"));
        assert!(source.contains("{browserd-worker}"));

        let direct_hget = ["redis.call('HGET', ", "expired_key"].concat();
        let direct_hset = ["redis.call('HSET', ", "expired_key"].concat();
        let direct_expire = ["redis.call('PEXPIRE', ", "expired_key"].concat();
        assert!(!source.contains(&direct_hget));
        assert!(!source.contains(&direct_hset));
        assert!(!source.contains(&direct_expire));
        assert!(source.contains("KEYS[key_offset]"));
    }

    #[test]
    fn worker_expiry_sweep_preparation_is_exactly_cas_rechecked_and_bounded() {
        let source = include_str!("redis.rs");
        assert!(source.contains("ZRANGEBYSCORE"));
        assert!(source.contains("'LIMIT', 0, 64"));
        assert!(source.contains("prepared_expired_candidates"));
        assert!(source.contains("current_expired_candidates"));
        assert!(source.contains("current_expired_candidates[current_offset] ~= KEYS[key_offset]"));
        assert!(
            source.contains("current_expired_candidates[current_offset + 1] ~= prepared_score")
        );
        assert!(source.contains("return {'9'}"));
        assert!(source.contains("for _ in 0..8"));
        assert!(source.contains("self.worker_reservation_key(&operation_id) != pair[0]"));
    }

    #[test]
    fn worker_reservation_scripts_are_atomic_full_u64_cas() {
        for script in [RESERVE_WORKER_SCRIPT, RELEASE_WORKER_RESERVATION_SCRIPT] {
            assert!(script.contains("redis.call('TIME')"));
            assert!(script.contains("PTTL"));
            assert!(script.contains("valid_u64"));
            assert!(!script.contains("tonumber"));
            assert!(script.contains("worker_epoch"));
            assert!(script.contains("revision"));
            assert!(script.contains("return {'6'}"));
        }
        assert!(RESERVE_WORKER_SCRIPT.contains("operation_id"));
        assert!(RESERVE_WORKER_SCRIPT.contains("tenant_id"));
        assert!(RESERVE_WORKER_SCRIPT.contains("resources"));
        assert!(RELEASE_WORKER_RESERVATION_SCRIPT.contains("ZREM"));
    }

    #[test]
    fn worker_reservation_rejects_corrupt_non_expiring_or_draining_workers() {
        assert!(RESERVE_WORKER_SCRIPT.contains("redis.call('PTTL', KEYS[1]) <= 0"));
        assert!(RESERVE_WORKER_SCRIPT.contains("redis.call('PTTL', KEYS[2])"));
        assert!(RESERVE_WORKER_SCRIPT.contains("readiness ~= 'ready'"));
        assert!(RESERVE_WORKER_SCRIPT.contains("current_entry ~= ARGV"));
        assert!(RELEASE_WORKER_RESERVATION_SCRIPT.contains("current_entry ~= ARGV"));
    }

    #[test]
    fn worker_reservation_keys_share_one_cluster_hash_slot() {
        let keys = worker_atomic_keys_for_test("browserd", "worker-1", "operation-1");
        assert_eq!(keys.len(), 4);
        assert!(keys.iter().all(|key| key.contains("{browserd-worker}")));
        assert_ne!(keys[0], keys[1]);
        assert_ne!(keys[1], keys[2]);
    }

    #[test]
    fn reservation_idempotency_precedes_worker_revision_cas() {
        let operation_lookup = RESERVE_WORKER_SCRIPT
            .find("redis.call('HGET', KEYS[2], 'operation_id')")
            .expect("script must inspect the global operation record");
        let worker_cas = RESERVE_WORKER_SCRIPT
            .find("revision ~= ARGV[2]")
            .expect("script must CAS the worker revision for a new reservation");
        assert!(operation_lookup < worker_cas);
    }

    #[test]
    fn reservation_expiry_reclaim_is_store_timed_indexed_and_bounded() {
        assert!(RESERVE_WORKER_SCRIPT.contains("redis.call('TIME')"));
        assert!(RESERVE_WORKER_SCRIPT.contains("ZRANGEBYSCORE"));
        assert!(RESERVE_WORKER_SCRIPT.contains("'LIMIT', 0, 64"));
        assert!(RESERVE_WORKER_SCRIPT.contains("ZADD"));
        assert!(RESERVE_WORKER_SCRIPT.contains("expires_at"));
        assert!(RELEASE_WORKER_RESERVATION_SCRIPT.contains("expires_at"));
        assert!(RELEASE_WORKER_RESERVATION_SCRIPT.contains("terminal"));
    }

    #[test]
    fn reservation_capacity_math_uses_current_decimal_worker_state() {
        for script in [RESERVE_WORKER_SCRIPT, RELEASE_WORKER_RESERVATION_SCRIPT] {
            assert!(!script.contains("tonumber"));
            assert!(!script.contains("cjson.decode"));
            assert!(script.contains("valid_u64"));
        }
        assert!(RESERVE_WORKER_SCRIPT.contains("subtract_u64"));
        assert!(RELEASE_WORKER_RESERVATION_SCRIPT.contains("add_u64"));
        assert!(RELEASE_WORKER_RESERVATION_SCRIPT.contains("redis.call('HGET', KEYS[1]"));
    }

    #[test]
    fn decimal_resource_arithmetic_is_exact_through_u64_max() {
        for (left, right, expected) in [
            ("0", "0", Some("0")),
            ("9007199254740993", "1", Some("9007199254740992")),
            ("18446744073709551615", "18446744073709551615", Some("0")),
            ("1", "2", None),
        ] {
            assert_eq!(
                subtract_u64_decimal(left, right).as_deref(),
                expected,
                "decimal subtraction must not round through a Lua number"
            );
        }
        for (left, right, expected) in [
            ("0", "0", Some("0")),
            ("9007199254740992", "1", Some("9007199254740993")),
            ("18446744073709551614", "1", Some("18446744073709551615")),
            ("18446744073709551615", "1", None),
        ] {
            assert_eq!(
                add_u64_decimal(left, right).as_deref(),
                expected,
                "decimal addition must fail closed on overflow"
            );
        }
    }

    #[test]
    fn worker_scripts_persist_all_authoritative_resource_dimensions() {
        for field in [
            "free_memory_bytes",
            "free_cpu_millis",
            "free_pids",
            "free_disk_bytes",
            "free_contexts",
            "free_targets",
            "capacity_memory_bytes",
            "capacity_cpu_millis",
            "capacity_pids",
            "capacity_disk_bytes",
            "capacity_contexts",
            "capacity_targets",
        ] {
            assert!(WORKER_REGISTER_SCRIPT.contains(field));
        }
        assert!(WORKER_HEARTBEAT_SCRIPT.contains("'free_' .. name"));
        assert!(WORKER_HEARTBEAT_SCRIPT.contains("'reserved_' .. name"));
        assert!(RESERVE_WORKER_SCRIPT.contains("HGET', KEYS[1], 'free_' .. name"));
        assert!(RELEASE_WORKER_RESERVATION_SCRIPT.contains("HGET', KEYS[1], 'free_' .. name"));
    }

    #[test]
    fn reservation_scripts_rebuild_heartbeat_from_current_resource_fields() {
        assert!(RESERVE_WORKER_SCRIPT.contains("build_heartbeat"));
        assert!(RELEASE_WORKER_RESERVATION_SCRIPT.contains("build_heartbeat"));
        assert!(!RELEASE_WORKER_RESERVATION_SCRIPT.contains("'heartbeat', ARGV[6]"));
        assert!(RESERVE_WORKER_SCRIPT.contains("return_current_worker"));
        assert!(RELEASE_WORKER_RESERVATION_SCRIPT.contains("return_current_worker"));
    }

    #[test]
    fn expired_reclaim_uses_exact_record_resources_and_epoch_once() {
        assert!(RESERVE_WORKER_SCRIPT.contains("ZRANGEBYSCORE"));
        assert!(RESERVE_WORKER_SCRIPT.contains("'LIMIT', 0, 64"));
        assert!(
            RESERVE_WORKER_SCRIPT.contains("HGET', KEYS[key_offset], 'acquisition_worker_epoch'")
        );
        assert!(RESERVE_WORKER_SCRIPT.contains("HGET', KEYS[key_offset], 'resource_' .. name"));
        assert!(RESERVE_WORKER_SCRIPT.contains("if expired_epoch == worker_epoch"));
        assert!(RESERVE_WORKER_SCRIPT.contains("terminal_reason', 'expired'"));
        assert!(RESERVE_WORKER_SCRIPT.contains("ZREM"));
    }

    #[test]
    fn operation_record_persists_the_original_grant_and_terminal_reason() {
        for field in [
            "acquisition_worker_id",
            "acquisition_worker_epoch",
            "acquisition_worker_revision",
            "acquisition_worker_expires_at",
            "reservation_expires_at",
            "stored_worker_entry",
            "stored_worker_heartbeat",
            "terminal_reason",
        ] {
            assert!(RESERVE_WORKER_SCRIPT.contains(field));
        }
        assert!(RESERVE_WORKER_SCRIPT.contains("return_stored_grant"));
        assert!(
            !RESERVE_WORKER_SCRIPT
                .contains("return {'5', redis.call('HGET', KEYS[2], 'reservation'), current_entry")
        );
    }

    #[test]
    fn operation_tombstone_outlives_maximum_reservation_ttl() {
        assert!(RESERVE_WORKER_SCRIPT.contains("add_u64(ARGV[10], '300000')"));
        assert!(RESERVE_WORKER_SCRIPT.contains("redis.call('PEXPIRE', KEYS[2], operation_ttl)"));
    }

    #[test]
    fn reclaim_checks_reason_worker_and_epoch_before_crediting_capacity() {
        assert!(RESERVE_WORKER_SCRIPT.contains("HGET', KEYS[key_offset], 'terminal_reason'"));
        assert!(RESERVE_WORKER_SCRIPT.contains("HGET', KEYS[key_offset], 'acquisition_worker_id'"));
        assert!(
            RESERVE_WORKER_SCRIPT.contains("HGET', KEYS[key_offset], 'acquisition_worker_epoch'")
        );
        assert!(RESERVE_WORKER_SCRIPT.contains("terminal_reason', 'expired'"));
        assert!(RELEASE_WORKER_RESERVATION_SCRIPT.contains("terminal_reason', 'released'"));
    }

    #[test]
    fn tombstone_idempotency_is_checked_before_worker_lease_liveness() {
        let reserve_operation = RESERVE_WORKER_SCRIPT
            .find("redis.call('HGET', KEYS[2], 'operation_id')")
            .expect("reserve must inspect operation tombstone");
        let reserve_worker = RESERVE_WORKER_SCRIPT
            .find("redis.call('PTTL', KEYS[1])")
            .expect("reserve must eventually validate worker lease");
        assert!(reserve_operation < reserve_worker);

        let release_terminal = RELEASE_WORKER_RESERVATION_SCRIPT
            .find("redis.call('HGET', KEYS[2], 'terminal_reason')")
            .expect("release must inspect terminal reason");
        let release_worker = RELEASE_WORKER_RESERVATION_SCRIPT
            .find("redis.call('PTTL', KEYS[1])")
            .expect("release must eventually validate worker lease");
        assert!(release_terminal < release_worker);
    }
    #[test]
    fn redis_debug_redacts_endpoint_credentials() {
        let config = RedisEphemeralConfig::new(
            "redis://user:secret@127.0.0.1/",
            "browserd",
            4,
            Duration::from_secs(1),
        )
        .expect("config");
        let debug = format!("{config:?}");
        assert!(!debug.contains("secret"));
        assert!(!debug.contains("user"));
        assert!(debug.contains("REDACTED"));
    }

    #[test]
    fn redis_u64_fencing_never_rounds_through_lua_numbers() {
        assert!(!REGISTER_SCRIPT.contains("tonumber"));
        assert!(!RENEW_SCRIPT.contains("tonumber"));
        assert_eq!(
            compare_u64_decimal("9007199254740992", "9007199254740993")
                .expect("decimal comparison should work"),
            Ordering::Less
        );
        assert_eq!(
            compare_u64_decimal("18446744073709551614", "18446744073709551615")
                .expect("decimal comparison should work"),
            Ordering::Less
        );
        assert_eq!(
            increment_u64_decimal("18446744073709551614")
                .expect("last representable increment should work"),
            "18446744073709551615"
        );
        assert_eq!(
            increment_u64_decimal("18446744073709551615"),
            Err(EphemeralCoordinationError::RevisionExhausted)
        );
    }

    #[test]
    fn redis_config_rejects_ambiguous_endpoints_and_unbounded_admission() {
        for endpoint in [
            " redis://127.0.0.1/",
            "redis://127.0.0.1/ ",
            "redis://127.0.0.1/\n",
        ] {
            assert!(matches!(
                RedisEphemeralConfig::new(endpoint, "browserd", 4, Duration::from_secs(1)),
                Err(EphemeralCoordinationError::InvalidInput)
            ));
        }
        assert!(matches!(
            RedisEphemeralConfig::new(
                "redis://127.0.0.1/",
                "browserd",
                1025,
                Duration::from_secs(1),
            ),
            Err(EphemeralCoordinationError::InvalidInput)
        ));
    }

    #[test]
    fn redis_resolve_revalidates_private_directory_fields() {
        let entry = DirectoryEntry::new(
            DirectoryKey::new(TenantId::new(), SessionId::new()),
            crate::DirectoryFence::new(
                WorkerId::new("redis-response-worker").expect("worker should validate"),
                3,
                4,
                5,
            )
            .expect("fence should validate"),
            "worker-rpc://valid",
        )
        .expect("entry should validate");
        let mut corrupt_fence = serde_json::to_value(&entry).expect("entry should serialize");
        corrupt_fence["fence"]["worker_epoch"] = serde_json::json!(0);
        let corrupt_fence_values = vec![corrupt_fence.to_string(), "1".into(), "100".into()];
        assert_eq!(
            decode_snapshot_values(&corrupt_fence_values),
            Err(EphemeralCoordinationError::InvalidResponse)
        );

        let mut bad_endpoint = serde_json::to_value(&entry).expect("entry should serialize");
        bad_endpoint["endpoint"] = serde_json::json!("worker-rpc://bad\nendpoint");
        let bad_endpoint_values = vec![bad_endpoint.to_string(), "1".into(), "100".into()];
        assert_eq!(
            decode_snapshot_values(&bad_endpoint_values),
            Err(EphemeralCoordinationError::InvalidResponse)
        );
        let zero_revision_values = vec![
            serde_json::to_string(&entry).expect("entry should serialize"),
            "0".into(),
            "100".into(),
        ];
        assert_eq!(
            decode_snapshot_values(&zero_revision_values),
            Err(EphemeralCoordinationError::InvalidResponse)
        );
    }

    #[test]
    fn redis_existing_directory_requires_live_ttl_and_nonzero_persisted_counters() {
        assert!(REGISTER_SCRIPT.contains("redis.call('PTTL', KEYS[1])"));
        assert!(REGISTER_SCRIPT.contains("existing_ttl <= 0 then return 6"));
        assert!(!valid_nonzero_u64_decimal("0"));
        assert!(!valid_nonzero_u64_decimal("00"));
        assert!(valid_nonzero_u64_decimal("1"));
        assert!(valid_nonzero_u64_decimal("18446744073709551615"));
    }
}
