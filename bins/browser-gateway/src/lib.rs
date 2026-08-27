//! Production-facing gateway adapters that are independent of HTTP routing.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use browserd_auth::{AuthConfig, RevocationRegistry, ServiceTokenVerifier, VerificationKeySet};
use browserd_core::{SessionId, TenantId};
use browserd_http::{
    AuthenticationError, Authenticator, Readiness, ViewerGateError, ViewerTransport,
};
use browserd_viewer::{TicketError, TicketPolicy, TicketRegistry, ViewerScopes, ViewerTicket};
use jsonwebtoken::Algorithm;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayConfigurationError {
    InvalidAuthentication,
    InvalidViewerPolicy,
}

impl fmt::Display for GatewayConfigurationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "gateway configuration error: {self:?}")
    }
}

impl std::error::Error for GatewayConfigurationError {}

pub struct GatewayAuthenticator {
    verifier: ServiceTokenVerifier,
}

impl GatewayAuthenticator {
    pub fn from_hmac_parts(
        issuer: &str,
        audience: &str,
        key_id: &str,
        secret: &[u8],
        clock_skew_seconds: u64,
    ) -> Result<Self, GatewayConfigurationError> {
        let invalid_text = |value: &str| {
            value.is_empty()
                || value.len() > 255
                || value.trim() != value
                || value.chars().any(char::is_control)
        };
        if invalid_text(issuer)
            || invalid_text(audience)
            || invalid_text(key_id)
            || !(32..=4_096).contains(&secret.len())
            || clock_skew_seconds > 300
        {
            return Err(GatewayConfigurationError::InvalidAuthentication);
        }
        let mut keys = VerificationKeySet::new();
        keys.insert_hmac(key_id, Algorithm::HS256, secret)
            .map_err(|_| GatewayConfigurationError::InvalidAuthentication)?;
        Ok(Self {
            verifier: ServiceTokenVerifier::new(
                AuthConfig::new(
                    issuer,
                    audience,
                    [Algorithm::HS256],
                    clock_skew_seconds,
                    false,
                ),
                keys,
                RevocationRegistry::default(),
            ),
        })
    }
}

impl Authenticator for GatewayAuthenticator {
    fn authenticate(
        &self,
        bearer: &str,
    ) -> Result<browserd_auth::AuthenticatedPrincipal, AuthenticationError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|duration| i64::try_from(duration.as_secs()).ok())
            .ok_or(AuthenticationError)?;
        self.verifier
            .verify_at(bearer, None, now)
            .map_err(|_| AuthenticationError)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayViewerError {
    InvalidPolicy,
    CapacityExceeded,
    ClockUnavailable,
    TicketRejected,
    StateUnavailable,
}

impl fmt::Display for GatewayViewerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "gateway viewer error: {self:?}")
    }
}

impl std::error::Error for GatewayViewerError {}

struct PresentedTicket {
    ticket: ViewerTicket,
    tenant_id: TenantId,
    session_id: SessionId,
    session_incarnation: u64,
    expires_at_millis: u64,
}

#[derive(Default)]
struct ViewerPresentationState {
    by_ticket: HashMap<ViewerTicket, String>,
    by_secret: HashMap<String, PresentedTicket>,
}

pub struct GatewayViewer {
    tickets: TicketRegistry,
    max_outstanding: usize,
    state: Mutex<ViewerPresentationState>,
}

impl GatewayViewer {
    pub fn new<I, S>(
        max_ttl: Duration,
        allowed_origins: I,
        max_outstanding: usize,
    ) -> Result<Self, GatewayConfigurationError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        if max_outstanding == 0 {
            return Err(GatewayConfigurationError::InvalidViewerPolicy);
        }
        let policy = TicketPolicy::new(max_ttl, allowed_origins)
            .map_err(|_| GatewayConfigurationError::InvalidViewerPolicy)?;
        Ok(Self {
            tickets: TicketRegistry::new(policy),
            max_outstanding,
            state: Mutex::new(ViewerPresentationState::default()),
        })
    }

    pub fn issue(
        &self,
        tenant_id: TenantId,
        session_id: SessionId,
        session_incarnation: u64,
        scopes: ViewerScopes,
        ttl: Duration,
    ) -> Result<ViewerTicket, GatewayViewerError> {
        if session_incarnation == 0 {
            return Err(GatewayViewerError::TicketRejected);
        }
        let now_millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|duration| u64::try_from(duration.as_millis()).ok())
            .ok_or(GatewayViewerError::ClockUnavailable)?;
        let ttl_millis =
            u64::try_from(ttl.as_millis()).map_err(|_| GatewayViewerError::TicketRejected)?;
        let expires_at_millis = now_millis
            .checked_add(ttl_millis)
            .ok_or(GatewayViewerError::TicketRejected)?;
        let mut state = lock_viewer_state(&self.state)?;
        let expired = state
            .by_secret
            .iter()
            .filter(|(_, record)| record.expires_at_millis <= now_millis)
            .map(|(secret, record)| (secret.clone(), record.ticket.clone()))
            .collect::<Vec<_>>();
        for (secret, ticket) in expired {
            state.by_secret.remove(&secret);
            state.by_ticket.remove(&ticket);
            self.tickets
                .discard(&ticket)
                .map_err(|_| GatewayViewerError::StateUnavailable)?;
        }
        if state.by_secret.len() >= self.max_outstanding {
            return Err(GatewayViewerError::CapacityExceeded);
        }
        let ticket = self
            .tickets
            .issue(
                tenant_id.clone(),
                session_id.clone(),
                session_incarnation,
                scopes,
                now_millis,
                ttl,
            )
            .map_err(|_| GatewayViewerError::TicketRejected)?;
        let secret = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        state.by_ticket.insert(ticket.clone(), secret.clone());
        state.by_secret.insert(
            secret,
            PresentedTicket {
                ticket: ticket.clone(),
                tenant_id,
                session_id,
                session_incarnation,
                expires_at_millis,
            },
        );
        Ok(ticket)
    }
}

impl ViewerTransport for GatewayViewer {
    fn consume_ticket(
        &self,
        session_id: &SessionId,
        origin: &str,
        presented: &str,
    ) -> Result<(), ViewerGateError> {
        let now_millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|duration| u64::try_from(duration.as_millis()).ok())
            .ok_or(ViewerGateError::TicketDenied)?;
        let mut state =
            lock_viewer_state(&self.state).map_err(|_| ViewerGateError::TicketDenied)?;
        let record = state
            .by_secret
            .get(presented)
            .ok_or(ViewerGateError::TicketDenied)?;
        if &record.session_id != session_id {
            return Err(ViewerGateError::TicketDenied);
        }
        let ticket = record.ticket.clone();
        let result = self.tickets.consume(
            &ticket,
            &record.tenant_id,
            &record.session_id,
            record.session_incarnation,
            origin,
            now_millis,
        );
        match result {
            Ok(_) => {
                state.by_secret.remove(presented);
                state.by_ticket.remove(&ticket);
                self.tickets
                    .discard(&ticket)
                    .map_err(|_| ViewerGateError::TicketDenied)?;
                Ok(())
            }
            Err(TicketError::OriginDenied) => Err(ViewerGateError::OriginDenied),
            Err(_) => {
                state.by_secret.remove(presented);
                state.by_ticket.remove(&ticket);
                self.tickets
                    .discard(&ticket)
                    .map_err(|_| ViewerGateError::TicketDenied)?;
                Err(ViewerGateError::TicketDenied)
            }
        }
    }

    fn connected(&self, _session_id: SessionId) {}

    fn present_viewer_ticket(&self, ticket: &ViewerTicket) -> Option<String> {
        lock_viewer_state(&self.state)
            .ok()
            .and_then(|state| state.by_ticket.get(ticket).cloned())
    }
}

fn lock_viewer_state(
    state: &Mutex<ViewerPresentationState>,
) -> Result<MutexGuard<'_, ViewerPresentationState>, GatewayViewerError> {
    state
        .lock()
        .map_err(|_| GatewayViewerError::StateUnavailable)
}

#[derive(Default)]
pub struct GatewayReadiness {
    worker_ready: AtomicBool,
    coordination_ready: AtomicBool,
}

impl GatewayReadiness {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            worker_ready: AtomicBool::new(false),
            coordination_ready: AtomicBool::new(false),
        }
    }

    pub fn set_worker_ready(&self, ready: bool) {
        self.worker_ready.store(ready, Ordering::Release);
    }

    pub fn set_coordination_ready(&self, ready: bool) {
        self.coordination_ready.store(ready, Ordering::Release);
    }
}

impl Readiness for GatewayReadiness {
    fn ready(&self) -> bool {
        self.worker_ready.load(Ordering::Acquire) && self.coordination_ready.load(Ordering::Acquire)
    }
}
