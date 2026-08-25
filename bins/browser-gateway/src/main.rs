use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, bail};
use browserd_api::InMemoryApiService;
use browserd_auth::AuthenticatedPrincipal;
use browserd_core::SessionId;
use browserd_http::{
    AuthenticationError, Authenticator, HttpConfig, Readiness, ViewerGateError, ViewerTransport,
    router,
};

struct BindConfig {
    address: SocketAddr,
}

impl BindConfig {
    fn from_parts(value: Option<&str>, trust_tls_terminator: bool) -> anyhow::Result<Self> {
        let address = value
            .unwrap_or("127.0.0.1:8080")
            .parse::<SocketAddr>()
            .context("BROWSERD_BIND must be an IP socket address")?;
        if !address.ip().is_loopback() && !trust_tls_terminator {
            bail!("public bind requires BROWSERD_TRUST_TLS_TERMINATOR=true");
        }
        Ok(Self { address })
    }

    const fn address(&self) -> SocketAddr {
        self.address
    }
}

struct RejectAllAuth;

impl Authenticator for RejectAllAuth {
    fn authenticate(&self, _bearer: &str) -> Result<AuthenticatedPrincipal, AuthenticationError> {
        Err(AuthenticationError)
    }
}

struct RejectAllViewer;

impl ViewerTransport for RejectAllViewer {
    fn consume_ticket(
        &self,
        _session_id: &SessionId,
        _origin: &str,
        _ticket: &str,
    ) -> Result<(), ViewerGateError> {
        Err(ViewerGateError::TicketDenied)
    }

    fn connected(&self, _session_id: SessionId) {}
}

struct NotReady;

impl Readiness for NotReady {
    fn ready(&self) -> bool {
        false
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let bind_value = std::env::var("BROWSERD_BIND").ok();
    let trust_tls_terminator = std::env::var("BROWSERD_TRUST_TLS_TERMINATOR")
        .ok()
        .is_some_and(|value| value == "true");
    let bind = BindConfig::from_parts(bind_value.as_deref(), trust_tls_terminator)?;
    let listener = tokio::net::TcpListener::bind(bind.address())
        .await
        .context("failed to bind browser gateway")?;
    let app = router(
        HttpConfig::default(),
        Arc::new(InMemoryApiService::default()),
        Arc::new(RejectAllAuth),
        Arc::new(RejectAllViewer),
        Arc::new(NotReady),
    );
    axum::serve(listener, app)
        .await
        .context("browser gateway server failed")
}

#[cfg(test)]
mod tests {
    use super::BindConfig;

    #[test]
    fn loopback_is_default_and_public_bind_requires_explicit_tls_terminator_trust()
    -> anyhow::Result<()> {
        let default = BindConfig::from_parts(None, false)?;
        assert!(default.address().ip().is_loopback());
        assert!(BindConfig::from_parts(Some("0.0.0.0:8080"), false).is_err());
        assert!(BindConfig::from_parts(Some("0.0.0.0:8080"), true).is_ok());
        Ok(())
    }
}
