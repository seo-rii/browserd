use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use redis::aio::ConnectionManager;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use uuid::Uuid;

use super::state::{Command, Outcome, State, decode, encode, transition};
use super::{
    SafetyAuditAck, SafetyAuditIntent, SafetyAuthority, SafetyAuthorityConfig,
    SafetyAuthorityError, SafetyAuthoritySnapshot, SafetyInitializeRequest, SafetyMutationReceipt,
    SafetyMutationRequest,
};

// Every write is one SET of the entire prevalidated envelope. No version is parsed by Lua.
const READ: &str = r#"
local t = redis.call('TYPE', KEYS[1])
if type(t) == 'table' then t = t['ok'] end
local now = redis.call('TIME')
if t == 'none' then return {'missing', now[1], now[2]} end
if t ~= 'string' or redis.call('PTTL', KEYS[1]) ~= -1 then return {'corrupt'} end
if redis.call('STRLEN', KEYS[1]) > tonumber(ARGV[1]) then return {'corrupt'} end
return {'ready', now[1], now[2], redis.call('GET', KEYS[1])}
"#;
const CAS: &str = r#"
local t = redis.call('TYPE', KEYS[1])
if type(t) == 'table' then t = t['ok'] end
if t ~= 'none' and (t ~= 'string' or redis.call('PTTL', KEYS[1]) ~= -1) then return -1 end
if ARGV[1] == 'missing' then
  if t ~= 'none' then return 0 end
else
  if t == 'none' then return 0 end
  if redis.call('GET', KEYS[1]) ~= ARGV[2] then return 0 end
end
redis.call('SET', KEYS[1], ARGV[3])
return 1
"#;

#[derive(Clone)]
pub struct RedisSafetyAuthorityConfig {
    endpoint: String,
    key_prefix: String,
    authority: SafetyAuthorityConfig,
    max_in_flight: usize,
    command_timeout: Duration,
}
impl RedisSafetyAuthorityConfig {
    pub fn new(
        endpoint: impl Into<String>,
        key_prefix: impl Into<String>,
        authority: SafetyAuthorityConfig,
        max_in_flight: usize,
        command_timeout: Duration,
    ) -> Result<Self, SafetyAuthorityError> {
        let endpoint = endpoint.into();
        let key_prefix = key_prefix.into();
        if endpoint.is_empty()
            || endpoint.trim() != endpoint
            || endpoint.chars().any(char::is_control)
            || key_prefix.is_empty()
            || key_prefix.len() > 128
            || !key_prefix
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_:".contains(&b))
            || !(1..=1_024).contains(&max_in_flight)
            || command_timeout.is_zero()
            || command_timeout > Duration::from_secs(30)
        {
            return Err(SafetyAuthorityError::InvalidConfig);
        }
        Ok(Self {
            endpoint,
            key_prefix,
            authority,
            max_in_flight,
            command_timeout,
        })
    }
}
impl fmt::Debug for RedisSafetyAuthorityConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RedisSafetyAuthorityConfig")
            .field("endpoint", &"[REDACTED]")
            .field("key_prefix", &self.key_prefix)
            .field("authority", &self.authority)
            .field("max_in_flight", &self.max_in_flight)
            .field("command_timeout", &self.command_timeout)
            .finish()
    }
}

#[derive(Clone)]
pub struct RedisSafetyAuthority {
    config: RedisSafetyAuthorityConfig,
    connection: ConnectionManager,
    permits: Arc<Semaphore>,
}
struct Observed {
    bytes: Option<Vec<u8>>,
    state: Option<State>,
    now: u64,
}

impl RedisSafetyAuthority {
    pub async fn connect(config: RedisSafetyAuthorityConfig) -> Result<Self, SafetyAuthorityError> {
        let client = redis::Client::open(config.endpoint.as_str())
            .map_err(|_| SafetyAuthorityError::Unavailable)?;
        let connection = timeout(config.command_timeout, client.get_connection_manager())
            .await
            .map_err(|_| SafetyAuthorityError::TimedOut)?
            .map_err(|_| SafetyAuthorityError::Unavailable)?;
        let store = Self {
            permits: Arc::new(Semaphore::new(config.max_in_flight)),
            config,
            connection,
        };
        // Verify an existing namespace, but do not manufacture a default if it is absent.
        timeout(store.config.command_timeout, store.load())
            .await
            .map_err(|_| SafetyAuthorityError::TimedOut)??;
        Ok(store)
    }
    fn key(&self) -> String {
        format!(
            "{}:safety:{{browserd-safety}}:authority",
            self.config.key_prefix
        )
    }
    async fn load(&self) -> Result<Observed, SafetyAuthorityError> {
        let mut connection = self.connection.clone();
        let fields: Vec<Vec<u8>> = redis::Script::new(READ)
            .key(self.key())
            .arg(self.config.authority.max_encoded_bytes())
            .invoke_async(&mut connection)
            .await
            .map_err(|_| SafetyAuthorityError::Unavailable)?;
        match fields.first().map(Vec::as_slice) {
            Some(b"corrupt") => Err(SafetyAuthorityError::CorruptState),
            Some(b"ready" | b"missing") => {
                let number = |index: usize| {
                    fields
                        .get(index)
                        .map(Vec::as_slice)
                        .and_then(|bytes| std::str::from_utf8(bytes).ok())
                        .and_then(|text| text.parse::<u64>().ok())
                        .ok_or(SafetyAuthorityError::CorruptState)
                };
                let micros = number(2)?;
                let now = number(1)?
                    .checked_mul(1_000)
                    .and_then(|seconds| seconds.checked_add(micros / 1_000))
                    .filter(|now| *now <= i64::MAX as u64)
                    .ok_or(SafetyAuthorityError::CorruptState)?;
                if micros >= 1_000_000 {
                    return Err(SafetyAuthorityError::CorruptState);
                }
                if fields[0] == b"missing" {
                    if fields.len() != 3 {
                        return Err(SafetyAuthorityError::CorruptState);
                    }
                    Ok(Observed {
                        bytes: None,
                        state: None,
                        now,
                    })
                } else {
                    if fields.len() != 4 {
                        return Err(SafetyAuthorityError::CorruptState);
                    }
                    let bytes = fields[3].clone();
                    let state = decode(&bytes, self.config.authority)?;
                    Ok(Observed {
                        bytes: Some(bytes),
                        state: Some(state),
                        now,
                    })
                }
            }
            _ => Err(SafetyAuthorityError::CorruptState),
        }
    }
    async fn apply(&self, command: Command) -> Result<Outcome, SafetyAuthorityError> {
        let _permit = timeout(
            self.config.command_timeout,
            Arc::clone(&self.permits).acquire_owned(),
        )
        .await
        .map_err(|_| SafetyAuthorityError::TimedOut)?
        .map_err(|_| SafetyAuthorityError::Unavailable)?;
        timeout(self.config.command_timeout, async {
            for _ in 0..16 {
                let observed = self.load().await?;
                let next = transition(
                    observed.state.as_ref(),
                    &command,
                    observed.now,
                    self.config.authority,
                )?;
                let bytes = encode(&next.state, self.config.authority)?;
                if observed.bytes.as_ref() == Some(&bytes) {
                    return Ok(next.outcome);
                }
                let mut connection = self.connection.clone();
                let status: i64 = redis::Script::new(CAS)
                    .key(self.key())
                    .arg(if observed.bytes.is_some() {
                        "ready"
                    } else {
                        "missing"
                    })
                    .arg(observed.bytes.as_deref().unwrap_or_default())
                    .arg(bytes)
                    .invoke_async(&mut connection)
                    .await
                    .map_err(|_| SafetyAuthorityError::Unavailable)?;
                match status {
                    1 => return Ok(next.outcome),
                    0 => tokio::task::yield_now().await,
                    _ => return Err(SafetyAuthorityError::CorruptState),
                }
            }
            Err(SafetyAuthorityError::Unavailable)
        })
        .await
        .map_err(|_| SafetyAuthorityError::TimedOut)?
    }
    async fn observed(&self) -> Result<State, SafetyAuthorityError> {
        let _permit = timeout(
            self.config.command_timeout,
            Arc::clone(&self.permits).acquire_owned(),
        )
        .await
        .map_err(|_| SafetyAuthorityError::TimedOut)?
        .map_err(|_| SafetyAuthorityError::Unavailable)?;
        timeout(self.config.command_timeout, self.load())
            .await
            .map_err(|_| SafetyAuthorityError::TimedOut)??
            .state
            .ok_or(SafetyAuthorityError::MissingAuthority)
    }
}

#[async_trait]
impl SafetyAuthority for RedisSafetyAuthority {
    async fn initialize(
        &self,
        request: SafetyInitializeRequest,
    ) -> Result<SafetyMutationReceipt, SafetyAuthorityError> {
        match self
            .apply(Command::Initialize(request, Uuid::now_v7(), Uuid::now_v7()))
            .await?
        {
            Outcome::Receipt(receipt) => Ok(receipt),
            _ => Err(SafetyAuthorityError::CorruptState),
        }
    }
    async fn read(&self) -> Result<SafetyAuthoritySnapshot, SafetyAuthorityError> {
        Ok(self.observed().await?.authority)
    }
    async fn mutate(
        &self,
        request: SafetyMutationRequest,
    ) -> Result<SafetyMutationReceipt, SafetyAuthorityError> {
        match self.apply(Command::Mutate(request, Uuid::now_v7())).await? {
            Outcome::Receipt(receipt) => Ok(receipt),
            _ => Err(SafetyAuthorityError::CorruptState),
        }
    }
    async fn pending_audits(
        &self,
        limit: usize,
    ) -> Result<Vec<SafetyAuditIntent>, SafetyAuthorityError> {
        if !(1..=32).contains(&limit) {
            return Err(SafetyAuthorityError::InvalidInput);
        }
        self.observed().await?.pending_audits(limit)
    }
    async fn ack_audit(&self, ack: SafetyAuditAck) -> Result<(), SafetyAuthorityError> {
        match self.apply(Command::Ack(ack)).await? {
            Outcome::Ack => Ok(()),
            _ => Err(SafetyAuthorityError::CorruptState),
        }
    }
    async fn prune_receipts(&self) -> Result<usize, SafetyAuthorityError> {
        match self.apply(Command::Prune).await? {
            Outcome::Pruned(count) => Ok(count),
            _ => Err(SafetyAuthorityError::CorruptState),
        }
    }
}
