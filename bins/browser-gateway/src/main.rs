use std::sync::Arc;

use anyhow::Context;
use browser_gateway::config::GatewayProcessConfig;
use browserd_api::InMemoryApiService;
use browserd_auth::AuthenticatedPrincipal;
use browserd_core::SessionId;
use browserd_http::{
    AuthenticationError, Authenticator, HttpConfig, Readiness, ViewerGateError, ViewerTransport,
    router,
};

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
    let config = GatewayProcessConfig::from_lookup(|name| std::env::var(name).ok())?;
    let listener = tokio::net::TcpListener::bind(config.bind_address())
        .await
        .context("failed to bind browser gateway")?;

    // This startup slice stops at validated process configuration. Runtime dependencies remain
    // explicitly unavailable until durable coordination, authenticated policy, worker routing,
    // and viewer transport are composed here.
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
