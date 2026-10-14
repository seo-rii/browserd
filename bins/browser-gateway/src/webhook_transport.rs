//! Signed control-plane notifications with fresh DNS inspection and pinned HTTPS.
//! Browser egress grants cannot relax this independent public-address policy.

use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use browserd_api::WebhookSigningSecret;
use browserd_coordination::{WebhookAttemptLease, WebhookAttemptOutcome};
use browserd_egress::{
    CanonicalUrl, ConnectPlan, ConnectionPlanner, DnsResolution, EgressPolicy, IpPolicy,
};
use hmac::{Hmac, Mac};
use reqwest::dns::{Name, Resolve, Resolving};
use sha2::Sha256;
use tokio::sync::Semaphore;
use uuid::Uuid;

pub const WEBHOOK_TIMESTAMP_HEADER: &str = "browserd-webhook-timestamp";
pub const WEBHOOK_SIGNATURE_HEADER: &str = "browserd-webhook-signature";
pub const WEBHOOK_EVENT_ID_HEADER: &str = "browserd-webhook-event-id";
pub const WEBHOOK_KEY_ID_HEADER: &str = "browserd-webhook-key-id";
pub const WEBHOOK_REPLAY_WINDOW_SECONDS: u64 = 300;
const SEND_BUDGET: Duration = Duration::from_secs(5);
const MAX_DNS_CANDIDATES: usize = 16;
const MAX_BODY_BYTES: usize = 512 * 1024;
const MAX_RESPONSE_BYTES: usize = 4096;

#[async_trait]
pub trait WebhookTransport: Send + Sync {
    async fn send(
        &self,
        attempt: &WebhookAttemptLease,
        secret: &WebhookSigningSecret,
    ) -> WebhookAttemptOutcome;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TransportError {
    PolicyDenied,
    Unavailable,
}

#[async_trait]
trait WebhookResolver: Send + Sync {
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<IpAddr>, TransportError>;
}

struct SystemWebhookResolver {
    in_flight: Arc<Semaphore>,
}

#[async_trait]
impl WebhookResolver for SystemWebhookResolver {
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<IpAddr>, TransportError> {
        let permit = self
            .in_flight
            .clone()
            .try_acquire_owned()
            .map_err(|_| TransportError::Unavailable)?;
        let host = host.to_owned();
        // A timed-out caller must not release capacity while libc's blocking resolver
        // still runs. The detached task owns its permit through actual completion.
        tokio::spawn(async move {
            let _permit = permit;
            let answers = tokio::net::lookup_host((host.as_str(), port))
                .await
                .map_err(|_| TransportError::Unavailable)?;
            let addresses: Vec<_> = answers
                .take(MAX_DNS_CANDIDATES + 1)
                .map(|address| address.ip())
                .collect();
            if addresses.is_empty() || addresses.len() > MAX_DNS_CANDIDATES {
                return Err(TransportError::PolicyDenied);
            }
            Ok(addresses)
        })
        .await
        .map_err(|_| TransportError::Unavailable)?
    }
}

struct PreparedWebhook {
    url: String,
    body: Vec<u8>,
    event_id: Uuid,
    key_id: Uuid,
    timestamp: String,
    signature: String,
}

impl fmt::Debug for PreparedWebhook {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedWebhook")
            .field("event_id", &self.event_id)
            .field("key_id", &self.key_id)
            .field("body_bytes", &self.body.len())
            .finish_non_exhaustive()
    }
}

#[async_trait]
trait PinnedWebhookPoster: Send + Sync {
    async fn post(
        &self,
        request: PreparedWebhook,
        plan: ConnectPlan,
    ) -> Result<u16, TransportError>;
}

struct ReqwestPinnedPoster;

struct RejectUninspectedDns;

impl Resolve for RejectUninspectedDns {
    fn resolve(&self, _name: Name) -> Resolving {
        Box::pin(async { Err(Box::new(std::io::Error::other("uninspected webhook address")) as _) })
    }
}

#[async_trait]
impl PinnedWebhookPoster for ReqwestPinnedPoster {
    async fn post(
        &self,
        request: PreparedWebhook,
        plan: ConnectPlan,
    ) -> Result<u16, TransportError> {
        let client = reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(3))
            .timeout(SEND_BUDGET)
            .pool_max_idle_per_host(0)
            .dns_resolver(Arc::new(RejectUninspectedDns))
            .resolve(
                plan.declared_host(),
                plan.inspected_socket_addr().as_socket_addr(),
            )
            .build()
            .map_err(|_| TransportError::Unavailable)?;
        // The URL keeps its original host for Host/SNI. The only DNS override is
        // numeric and already inspected; any fallback resolution fails closed.
        post_signed(&client, request).await
    }
}

async fn post_signed(
    client: &reqwest::Client,
    request: PreparedWebhook,
) -> Result<u16, TransportError> {
    let mut response = client
        .post(&request.url)
        .header("content-type", "application/json")
        .header(WEBHOOK_TIMESTAMP_HEADER, &request.timestamp)
        .header(WEBHOOK_SIGNATURE_HEADER, &request.signature)
        .header(WEBHOOK_EVENT_ID_HEADER, request.event_id.to_string())
        .header(WEBHOOK_KEY_ID_HEADER, request.key_id.to_string())
        .body(request.body)
        .send()
        .await
        .map_err(|_| TransportError::Unavailable)?;
    // The status line is the receiver's answer. The reply body carries no meaning, so
    // it is drained only up to the cap and its size or a read error never reclassifies
    // an accepted delivery as a retry.
    let status = response.status().as_u16();
    let mut drained = 0_usize;
    while drained <= MAX_RESPONSE_BYTES {
        let Ok(Some(chunk)) = response.chunk().await else {
            break;
        };
        drained = drained.saturating_add(chunk.len());
    }
    Ok(status)
}

pub struct ReqwestWebhookTransport {
    resolver: Arc<dyn WebhookResolver>,
    poster: Arc<dyn PinnedWebhookPoster>,
    budget: Duration,
}

impl Default for ReqwestWebhookTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl ReqwestWebhookTransport {
    #[must_use]
    pub fn new() -> Self {
        Self {
            resolver: Arc::new(SystemWebhookResolver {
                in_flight: Arc::new(Semaphore::new(4)),
            }),
            poster: Arc::new(ReqwestPinnedPoster),
            budget: SEND_BUDGET,
        }
    }

    async fn send_prepared(&self, request: PreparedWebhook) -> WebhookAttemptOutcome {
        let result = tokio::time::timeout(self.budget, async {
            let url = validated_webhook_url(&request.url)?;
            let addresses = self.resolver.resolve(url.host(), url.port()).await?;
            let plan = inspect_webhook_destination(&url, addresses)?;
            self.poster.post(request, plan).await
        })
        .await;
        match result {
            Ok(Ok(status_code @ 200..=299)) => WebhookAttemptOutcome::Delivered { status_code },
            Ok(Ok(status_code)) if matches!(status_code, 408 | 425 | 429 | 500..=599) => {
                WebhookAttemptOutcome::TransientFailure {
                    status_code: Some(status_code),
                }
            }
            Ok(Ok(status_code)) if !(100..=599).contains(&status_code) => {
                WebhookAttemptOutcome::TransportUnknown
            }
            Ok(Ok(status_code)) => WebhookAttemptOutcome::PermanentFailure {
                status_code: Some(status_code),
            },
            Ok(Err(TransportError::PolicyDenied)) => {
                WebhookAttemptOutcome::PermanentFailure { status_code: None }
            }
            Ok(Err(TransportError::Unavailable)) | Err(_) => {
                WebhookAttemptOutcome::TransportUnknown
            }
        }
    }
}

#[async_trait]
impl WebhookTransport for ReqwestWebhookTransport {
    async fn send(
        &self,
        attempt: &WebhookAttemptLease,
        secret: &WebhookSigningSecret,
    ) -> WebhookAttemptOutcome {
        let body = attempt.payload().as_bytes();
        let timestamp = attempt.send_timestamp_seconds();
        if body.is_empty() || body.len() > MAX_BODY_BYTES || timestamp < 0 {
            return WebhookAttemptOutcome::PermanentFailure { status_code: None };
        }
        let Some(signature) = webhook_signature(secret, timestamp, body) else {
            return WebhookAttemptOutcome::TransportUnknown;
        };
        self.send_prepared(PreparedWebhook {
            url: attempt.spec().endpoint_url().to_owned(),
            body: body.to_vec(),
            event_id: attempt.event_id(),
            key_id: attempt.signing_key_ref().key_id(),
            timestamp: timestamp.to_string(),
            signature,
        })
        .await
    }
}

fn validated_webhook_url(raw: &str) -> Result<CanonicalUrl, TransportError> {
    if raw.is_empty()
        || raw.len() > 2048
        || raw.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(TransportError::PolicyDenied);
    }
    let parsed = url::Url::parse(raw).map_err(|_| TransportError::PolicyDenied)?;
    let authority = raw
        .split_once("://")
        .map(|(_, rest)| rest.split(['/', '?', '#']).next().unwrap_or(""));
    if parsed.scheme() != "https"
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
        || authority.is_some_and(|value| value.contains('@'))
    {
        return Err(TransportError::PolicyDenied);
    }
    CanonicalUrl::parse(parsed.as_str()).map_err(|_| TransportError::PolicyDenied)
}

fn inspect_webhook_destination(
    url: &CanonicalUrl,
    addresses: Vec<IpAddr>,
) -> Result<ConnectPlan, TransportError> {
    if addresses.is_empty() || addresses.len() > MAX_DNS_CANDIDATES {
        return Err(TransportError::PolicyDenied);
    }
    let addresses = addresses
        .into_iter()
        .map(|address| {
            let address = IpPolicy::public_web_default()
                .check(address)
                .map_err(|_| TransportError::PolicyDenied)?;
            if let IpAddr::V6(address) = address {
                let segments = address.segments();
                // This independent policy allows ordinary native global unicast,
                // conservatively excluding translation and protocol assignments.
                // https://www.iana.org/assignments/iana-ipv6-special-registry
                if segments[0] & 0xe000 != 0x2000
                    || (segments[0] == 0x2001 && segments[1] < 0x0200)
                    || segments[0] == 0x2002
                    || (segments[0] == 0x3fff && segments[1] & 0xf000 == 0)
                {
                    return Err(TransportError::PolicyDenied);
                }
            }
            Ok(address)
        })
        .collect::<Result<Vec<_>, _>>()?;
    ConnectionPlanner::new(EgressPolicy::public_web_default())
        .plan(url, DnsResolution::new(url.host(), addresses))
        .map_err(|_| TransportError::PolicyDenied)
}

fn webhook_signature(secret: &WebhookSigningSecret, timestamp: i64, body: &[u8]) -> Option<String> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).ok()?;
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    Some(format!("v1={}", hex::encode(mac.finalize().into_bytes())))
}

/// Verify exact received bytes in constant time. Receivers must additionally deduplicate
/// the signed body's event_id; a valid signature does not imply first delivery.
#[must_use]
pub fn verify_webhook_signature(
    secret: &WebhookSigningSecret,
    timestamp_header: &str,
    signature_header: &str,
    body: &[u8],
    now_seconds: i64,
) -> bool {
    if timestamp_header.is_empty()
        || timestamp_header.len() > 19
        || !timestamp_header.bytes().all(|byte| byte.is_ascii_digit())
        || body.is_empty()
        || body.len() > MAX_BODY_BYTES
        || now_seconds < 0
    {
        return false;
    }
    let Ok(timestamp) = timestamp_header.parse::<i64>() else {
        return false;
    };
    if timestamp.to_string() != timestamp_header
        || now_seconds.abs_diff(timestamp) > WEBHOOK_REPLAY_WINDOW_SECONDS
    {
        return false;
    }
    let Some(encoded) = signature_header.strip_prefix("v1=") else {
        return false;
    };
    let mut received = [0; 32];
    if encoded.len() != 64 || hex::decode_to_slice(encoded, &mut received).is_err() {
        return false;
    }
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(secret.as_bytes()) else {
        return false;
    };
    mac.update(timestamp_header.as_bytes());
    mac.update(b".");
    mac.update(body);
    mac.verify_slice(&received).is_ok()
}

#[cfg(test)]
mod tests;
