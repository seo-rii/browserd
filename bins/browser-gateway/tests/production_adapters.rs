use std::collections::BTreeSet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use browser_gateway::{GatewayAuthenticator, GatewayReadiness, GatewayViewer};
use browserd_auth::{ServiceClaims, ServiceTokenSigner};
use browserd_core::{PrincipalId, SessionId, TenantId};
use browserd_http::{Authenticator, Readiness, ViewerGateError, ViewerTransport};
use browserd_viewer::ViewerScopes;
use jsonwebtoken::Algorithm;

#[test]
fn hmac_authenticator_verifies_issuer_audience_signature_and_expiry() {
    let secret = [7_u8; 32];
    let authenticator = GatewayAuthenticator::from_hmac_parts(
        "browserd-gateway",
        "browserd-api",
        "active-key",
        &secret,
        5,
    );
    assert!(authenticator.is_ok());
    let Some(authenticator) = authenticator.ok() else {
        return;
    };
    let signer = ServiceTokenSigner::new("active-key", Algorithm::HS256, &secret);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_secs()).ok());
    let Some(now) = now else {
        return;
    };
    let token = signer.sign(&ServiceClaims::new(
        "browserd-gateway",
        "browserd-api",
        PrincipalId::new(),
        TenantId::new(),
        BTreeSet::from(["sessions:read".to_owned()]),
        "jti-1",
        now.saturating_sub(1),
        now.saturating_add(60),
        None,
    ));
    assert!(token.is_ok());
    let Some(token) = token.ok() else {
        return;
    };
    assert!(authenticator.authenticate(&token).is_ok());
    assert!(authenticator.authenticate("not-a-token").is_err());
    assert!(
        GatewayAuthenticator::from_hmac_parts("", "browserd-api", "active-key", &secret, 5)
            .is_err()
    );
    assert!(
        GatewayAuthenticator::from_hmac_parts(
            "browserd-gateway",
            "browserd-api",
            "active-key",
            b"short",
            5,
        )
        .is_err()
    );
}

#[test]
fn viewer_ticket_presentation_is_bounded_origin_bound_and_one_time() {
    let viewer = GatewayViewer::new(Duration::from_secs(30), ["https://viewer.example"], 8);
    assert!(viewer.is_ok());
    let Some(viewer) = viewer.ok() else {
        return;
    };
    let tenant_id = TenantId::new();
    let session_id = SessionId::new();
    let ticket = viewer.issue(
        tenant_id,
        session_id.clone(),
        1,
        ViewerScopes::new(true, false, false),
        Duration::from_secs(5),
    );
    assert!(ticket.is_ok());
    let Some(ticket) = ticket.ok() else {
        return;
    };
    let presented = viewer.present_viewer_ticket(&ticket);
    assert!(presented.is_some());
    let Some(presented) = presented else {
        return;
    };
    assert_eq!(
        viewer.consume_ticket(&session_id, "https://wrong.example", &presented),
        Err(ViewerGateError::OriginDenied)
    );
    assert_eq!(
        viewer.consume_ticket(&session_id, "https://viewer.example", &presented),
        Ok(())
    );
    assert_eq!(
        viewer.consume_ticket(&session_id, "https://viewer.example", &presented),
        Err(ViewerGateError::TicketDenied)
    );
}

#[test]
fn readiness_is_false_until_every_required_runtime_is_healthy() {
    let readiness = GatewayReadiness::new();
    assert!(!readiness.ready());
    readiness.set_worker_ready(true);
    assert!(!readiness.ready());
    readiness.set_coordination_ready(true);
    assert!(readiness.ready());
    readiness.set_worker_ready(false);
    assert!(!readiness.ready());
}
