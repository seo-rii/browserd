use std::fmt;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use redis::Script;
use redis::aio::ConnectionManager;
use tokio::sync::Semaphore;
use tokio::time::timeout;

use crate::ephemeral::{MAX_EPHEMERAL_TTL_MILLIS, ttl_millis};
use crate::{
    DirectoryEntry, DirectoryKey, DirectoryMutation, DirectorySnapshot, EphemeralCoordinationError,
    EphemeralCoordinationStore, OneTimeCapability, OneTimeConsume, OneTimeIssue,
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
