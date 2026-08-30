use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

const MAX_TEXT_BYTES: usize = 255;
const MAX_SECRET_BYTES: usize = 4_096;
const MAX_DATABASE_URL_BYTES: usize = 4_096;
const MAX_QUEUE_CAPACITY: usize = 65_536;
const MAX_IN_FLIGHT: usize = 64;
const MAX_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const MIN_LEASE_HEADROOM: Duration = Duration::from_secs(1);

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GatewayProcessConfigError {
    Missing(&'static str),
    Invalid(&'static str),
    UntrustedPublicBind,
}

impl fmt::Display for GatewayProcessConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(name) => write!(
                formatter,
                "required environment variable is missing: {name}"
            ),
            Self::Invalid(name) => write!(formatter, "environment variable is invalid: {name}"),
            Self::UntrustedPublicBind => {
                formatter.write_str("public bind requires an explicitly trusted TLS terminator")
            }
        }
    }
}

impl std::error::Error for GatewayProcessConfigError {}

#[derive(Clone, Eq, PartialEq)]
pub struct GatewayProcessConfig {
    bind_address: SocketAddr,
    trust_tls_terminator: bool,
    auth_issuer: String,
    auth_audience: String,
    auth_key_id: String,
    auth_hmac_secret: Vec<u8>,
    worker_socket: PathBuf,
    worker_uid: u32,
    worker_epoch: u64,
    placement_version: u64,
    postgres_url: String,
    redis_url: String,
    redis_prefix: String,
    viewer_origins: Vec<String>,
    worker_rpc_queue: usize,
    worker_rpc_in_flight: usize,
    worker_rpc_timeout: Duration,
    coordination_queue: usize,
    coordination_in_flight: usize,
    coordination_query_timeout: Duration,
    coordination_mutation_timeout: Duration,
    create_lease_duration: Duration,
    postgres_max_connections: u32,
}

impl fmt::Debug for GatewayProcessConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GatewayProcessConfig")
            .field("bind_address", &self.bind_address)
            .field("trust_tls_terminator", &self.trust_tls_terminator)
            .field("auth_issuer", &self.auth_issuer)
            .field("auth_audience", &self.auth_audience)
            .field("auth_key_id", &self.auth_key_id)
            .field("auth_hmac_secret", &"[REDACTED]")
            .field("worker_socket", &self.worker_socket)
            .field("worker_uid", &self.worker_uid)
            .field("worker_epoch", &self.worker_epoch)
            .field("placement_version", &self.placement_version)
            .field("postgres_url", &"[REDACTED]")
            .field("redis_url", &"[REDACTED]")
            .field("redis_prefix", &self.redis_prefix)
            .field("viewer_origins", &self.viewer_origins)
            .field("worker_rpc_queue", &self.worker_rpc_queue)
            .field("worker_rpc_in_flight", &self.worker_rpc_in_flight)
            .field("worker_rpc_timeout", &self.worker_rpc_timeout)
            .field("coordination_queue", &self.coordination_queue)
            .field("coordination_in_flight", &self.coordination_in_flight)
            .field(
                "coordination_query_timeout",
                &self.coordination_query_timeout,
            )
            .field(
                "coordination_mutation_timeout",
                &self.coordination_mutation_timeout,
            )
            .field("create_lease_duration", &self.create_lease_duration)
            .field("postgres_max_connections", &self.postgres_max_connections)
            .finish()
    }
}

impl GatewayProcessConfig {
    pub fn from_lookup(
        mut lookup: impl FnMut(&str) -> Option<String>,
    ) -> Result<Self, GatewayProcessConfigError> {
        let bind_address = lookup("BROWSERD_BIND")
            .unwrap_or_else(|| "127.0.0.1:8080".to_owned())
            .parse::<SocketAddr>()
            .map_err(|_| GatewayProcessConfigError::Invalid("BROWSERD_BIND"))?;
        let trust_tls_terminator = optional_bool(
            lookup("BROWSERD_TRUST_TLS_TERMINATOR"),
            "BROWSERD_TRUST_TLS_TERMINATOR",
            false,
        )?;
        if !bind_address.ip().is_loopback() && !trust_tls_terminator {
            return Err(GatewayProcessConfigError::UntrustedPublicBind);
        }

        let auth_issuer = required_text(&mut lookup, "BROWSERD_AUTH_ISSUER")?;
        let auth_audience = required_text(&mut lookup, "BROWSERD_AUTH_AUDIENCE")?;
        let auth_key_id = required_text(&mut lookup, "BROWSERD_AUTH_KEY_ID")?;
        let auth_hmac_secret = required(&mut lookup, "BROWSERD_AUTH_HMAC_SECRET")?.into_bytes();
        if !(32..=MAX_SECRET_BYTES).contains(&auth_hmac_secret.len()) {
            return Err(GatewayProcessConfigError::Invalid(
                "BROWSERD_AUTH_HMAC_SECRET",
            ));
        }

        let worker_socket = PathBuf::from(required(&mut lookup, "BROWSERD_WORKER_SOCKET")?);
        if !worker_socket.is_absolute() || worker_socket.as_os_str().is_empty() {
            return Err(GatewayProcessConfigError::Invalid("BROWSERD_WORKER_SOCKET"));
        }
        let worker_uid = required_number::<u32>(&mut lookup, "BROWSERD_WORKER_UID")?;
        let worker_epoch = nonzero_u64(&mut lookup, "BROWSERD_WORKER_EPOCH")?;
        let placement_version = nonzero_u64(&mut lookup, "BROWSERD_PLACEMENT_VERSION")?;

        let postgres_url = required(&mut lookup, "BROWSERD_POSTGRES_URL")?;
        if postgres_url.len() > MAX_DATABASE_URL_BYTES
            || postgres_url.chars().any(char::is_whitespace)
            || !(postgres_url.starts_with("postgres://")
                || postgres_url.starts_with("postgresql://"))
        {
            return Err(GatewayProcessConfigError::Invalid("BROWSERD_POSTGRES_URL"));
        }
        let redis_url = required(&mut lookup, "BROWSERD_REDIS_URL")?;
        if redis_url.len() > MAX_DATABASE_URL_BYTES
            || redis_url.chars().any(char::is_whitespace)
            || !(redis_url.starts_with("redis://") || redis_url.starts_with("rediss://"))
        {
            return Err(GatewayProcessConfigError::Invalid("BROWSERD_REDIS_URL"));
        }
        let redis_prefix = required_text(&mut lookup, "BROWSERD_REDIS_PREFIX")?;
        if redis_prefix.len() > 128
            || !redis_prefix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-_:".contains(&byte))
        {
            return Err(GatewayProcessConfigError::Invalid("BROWSERD_REDIS_PREFIX"));
        }
        let viewer_origins = parse_origins(required(&mut lookup, "BROWSERD_VIEWER_ORIGINS")?)?;

        let worker_rpc_queue = bounded_usize(
            &mut lookup,
            "BROWSERD_WORKER_RPC_QUEUE",
            256,
            MAX_QUEUE_CAPACITY,
        )?;
        let worker_rpc_in_flight = bounded_usize(
            &mut lookup,
            "BROWSERD_WORKER_RPC_IN_FLIGHT",
            16,
            MAX_IN_FLIGHT,
        )?;
        let worker_rpc_timeout = milliseconds(
            &mut lookup,
            "BROWSERD_WORKER_RPC_TIMEOUT_MS",
            Duration::from_secs(5),
        )?;
        let coordination_queue = bounded_usize(
            &mut lookup,
            "BROWSERD_COORDINATION_QUEUE",
            256,
            MAX_QUEUE_CAPACITY,
        )?;
        let coordination_in_flight = bounded_usize(
            &mut lookup,
            "BROWSERD_COORDINATION_IN_FLIGHT",
            16,
            MAX_IN_FLIGHT,
        )?;
        let coordination_query_timeout = milliseconds(
            &mut lookup,
            "BROWSERD_COORDINATION_QUERY_TIMEOUT_MS",
            Duration::from_secs(5),
        )?;
        let coordination_mutation_timeout = milliseconds(
            &mut lookup,
            "BROWSERD_COORDINATION_MUTATION_TIMEOUT_MS",
            Duration::from_secs(15),
        )?;
        if coordination_mutation_timeout < coordination_query_timeout {
            return Err(GatewayProcessConfigError::Invalid(
                "BROWSERD_COORDINATION_MUTATION_TIMEOUT_MS",
            ));
        }
        let create_lease_duration = milliseconds(
            &mut lookup,
            "BROWSERD_CREATE_LEASE_MS",
            Duration::from_secs(30),
        )?;
        let minimum_lease = worker_rpc_timeout.checked_add(MIN_LEASE_HEADROOM).ok_or(
            GatewayProcessConfigError::Invalid("BROWSERD_CREATE_LEASE_MS"),
        )?;
        if create_lease_duration <= minimum_lease {
            return Err(GatewayProcessConfigError::Invalid(
                "BROWSERD_CREATE_LEASE_MS",
            ));
        }
        let postgres_max_connections =
            optional_number::<u32>(&mut lookup, "BROWSERD_POSTGRES_MAX_CONNECTIONS", 8)?;
        if postgres_max_connections == 0 || postgres_max_connections > 256 {
            return Err(GatewayProcessConfigError::Invalid(
                "BROWSERD_POSTGRES_MAX_CONNECTIONS",
            ));
        }

        Ok(Self {
            bind_address,
            trust_tls_terminator,
            auth_issuer,
            auth_audience,
            auth_key_id,
            auth_hmac_secret,
            worker_socket,
            worker_uid,
            worker_epoch,
            placement_version,
            postgres_url,
            redis_url,
            redis_prefix,
            viewer_origins,
            worker_rpc_queue,
            worker_rpc_in_flight,
            worker_rpc_timeout,
            coordination_queue,
            coordination_in_flight,
            coordination_query_timeout,
            coordination_mutation_timeout,
            create_lease_duration,
            postgres_max_connections,
        })
    }

    #[must_use]
    pub const fn bind_address(&self) -> SocketAddr {
        self.bind_address
    }

    #[must_use]
    pub const fn trust_tls_terminator(&self) -> bool {
        self.trust_tls_terminator
    }

    #[must_use]
    pub fn auth_issuer(&self) -> &str {
        &self.auth_issuer
    }

    #[must_use]
    pub fn auth_audience(&self) -> &str {
        &self.auth_audience
    }

    #[must_use]
    pub fn auth_key_id(&self) -> &str {
        &self.auth_key_id
    }

    #[must_use]
    pub fn auth_hmac_secret(&self) -> &[u8] {
        &self.auth_hmac_secret
    }

    #[must_use]
    pub fn worker_socket(&self) -> &Path {
        &self.worker_socket
    }

    #[must_use]
    pub const fn worker_uid(&self) -> u32 {
        self.worker_uid
    }

    #[must_use]
    pub const fn worker_epoch(&self) -> u64 {
        self.worker_epoch
    }

    #[must_use]
    pub const fn placement_version(&self) -> u64 {
        self.placement_version
    }

    #[must_use]
    pub fn postgres_url(&self) -> &str {
        &self.postgres_url
    }

    #[must_use]
    pub fn redis_url(&self) -> &str {
        &self.redis_url
    }

    #[must_use]
    pub fn redis_prefix(&self) -> &str {
        &self.redis_prefix
    }

    #[must_use]
    pub fn viewer_origins(&self) -> &[String] {
        &self.viewer_origins
    }

    #[must_use]
    pub const fn worker_rpc_queue(&self) -> usize {
        self.worker_rpc_queue
    }

    #[must_use]
    pub const fn worker_rpc_in_flight(&self) -> usize {
        self.worker_rpc_in_flight
    }

    #[must_use]
    pub const fn worker_rpc_timeout(&self) -> Duration {
        self.worker_rpc_timeout
    }

    #[must_use]
    pub const fn coordination_queue(&self) -> usize {
        self.coordination_queue
    }

    #[must_use]
    pub const fn coordination_in_flight(&self) -> usize {
        self.coordination_in_flight
    }

    #[must_use]
    pub const fn coordination_query_timeout(&self) -> Duration {
        self.coordination_query_timeout
    }

    #[must_use]
    pub const fn coordination_mutation_timeout(&self) -> Duration {
        self.coordination_mutation_timeout
    }

    #[must_use]
    pub const fn create_lease_duration(&self) -> Duration {
        self.create_lease_duration
    }

    #[must_use]
    pub const fn postgres_max_connections(&self) -> u32 {
        self.postgres_max_connections
    }
}

fn required(
    lookup: &mut impl FnMut(&str) -> Option<String>,
    name: &'static str,
) -> Result<String, GatewayProcessConfigError> {
    lookup(name).ok_or(GatewayProcessConfigError::Missing(name))
}

fn required_text(
    lookup: &mut impl FnMut(&str) -> Option<String>,
    name: &'static str,
) -> Result<String, GatewayProcessConfigError> {
    let value = required(lookup, name)?;
    if value.is_empty()
        || value.len() > MAX_TEXT_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(GatewayProcessConfigError::Invalid(name));
    }
    Ok(value)
}

fn required_number<T: std::str::FromStr>(
    lookup: &mut impl FnMut(&str) -> Option<String>,
    name: &'static str,
) -> Result<T, GatewayProcessConfigError> {
    required(lookup, name)?
        .parse::<T>()
        .map_err(|_| GatewayProcessConfigError::Invalid(name))
}

fn optional_number<T: std::str::FromStr>(
    lookup: &mut impl FnMut(&str) -> Option<String>,
    name: &'static str,
    default: T,
) -> Result<T, GatewayProcessConfigError> {
    match lookup(name) {
        Some(value) => value
            .parse::<T>()
            .map_err(|_| GatewayProcessConfigError::Invalid(name)),
        None => Ok(default),
    }
}

fn nonzero_u64(
    lookup: &mut impl FnMut(&str) -> Option<String>,
    name: &'static str,
) -> Result<u64, GatewayProcessConfigError> {
    let value = required_number::<u64>(lookup, name)?;
    if value == 0 {
        return Err(GatewayProcessConfigError::Invalid(name));
    }
    Ok(value)
}

fn optional_bool(
    value: Option<String>,
    name: &'static str,
    default: bool,
) -> Result<bool, GatewayProcessConfigError> {
    match value.as_deref() {
        None => Ok(default),
        Some("true") => Ok(true),
        Some("false") => Ok(false),
        Some(_) => Err(GatewayProcessConfigError::Invalid(name)),
    }
}

fn bounded_usize(
    lookup: &mut impl FnMut(&str) -> Option<String>,
    name: &'static str,
    default: usize,
    maximum: usize,
) -> Result<usize, GatewayProcessConfigError> {
    let value = optional_number::<usize>(lookup, name, default)?;
    if value == 0 || value > maximum {
        return Err(GatewayProcessConfigError::Invalid(name));
    }
    Ok(value)
}

fn milliseconds(
    lookup: &mut impl FnMut(&str) -> Option<String>,
    name: &'static str,
    default: Duration,
) -> Result<Duration, GatewayProcessConfigError> {
    let default_millis =
        u64::try_from(default.as_millis()).map_err(|_| GatewayProcessConfigError::Invalid(name))?;
    let millis = optional_number::<u64>(lookup, name, default_millis)?;
    let duration = Duration::from_millis(millis);
    if duration.is_zero() || duration > MAX_TIMEOUT {
        return Err(GatewayProcessConfigError::Invalid(name));
    }
    Ok(duration)
}

fn parse_origins(value: String) -> Result<Vec<String>, GatewayProcessConfigError> {
    let origins = value.split(',').map(str::to_owned).collect::<Vec<_>>();
    if origins.is_empty()
        || origins.len() > 32
        || origins.iter().any(|origin| !valid_origin(origin))
    {
        return Err(GatewayProcessConfigError::Invalid(
            "BROWSERD_VIEWER_ORIGINS",
        ));
    }
    Ok(origins)
}

fn valid_origin(origin: &str) -> bool {
    if origin.is_empty()
        || origin.len() > 2_048
        || origin.trim() != origin
        || origin.chars().any(char::is_control)
    {
        return false;
    }
    let authority = origin
        .strip_prefix("https://")
        .or_else(|| origin.strip_prefix("http://"));
    let Some(authority) = authority else {
        return false;
    };
    if authority.is_empty()
        || authority.contains(['/', '?', '#', '@'])
        || authority.chars().any(char::is_whitespace)
    {
        return false;
    }
    if let Some(ipv6) = authority.strip_prefix('[') {
        let Some(end) = ipv6.find(']') else {
            return false;
        };
        let host = &ipv6[..end];
        let suffix = &ipv6[end + 1..];
        return host.parse::<std::net::Ipv6Addr>().is_ok()
            && (suffix.is_empty() || valid_port(suffix));
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    };
    !host.is_empty()
        && host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
        && port.is_none_or(|port| valid_port(&format!(":{port}")))
}

fn valid_port(suffix: &str) -> bool {
    suffix
        .strip_prefix(':')
        .and_then(|port| port.parse::<u16>().ok())
        .is_some_and(|port| port != 0)
}
