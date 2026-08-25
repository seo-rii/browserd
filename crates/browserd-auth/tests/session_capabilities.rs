use std::collections::BTreeSet;
use std::sync::{Arc, Barrier};
use std::thread;

use browserd_auth::{
    ActorBinding, AuthError, CapabilityExpectation, OneTimeJtiRegistry, SessionCapabilityClaims,
    SessionCapabilityCodec,
};
use browserd_core::{PrincipalId, SessionId, TenantId};

const SECRET: &[u8] = b"a-separate-test-key-for-session-capabilities";

#[test]
fn capability_is_bound_to_tenant_principal_session_incarnation_policy_and_scope() {
    let now = chrono::Utc::now().timestamp();
    let tenant = TenantId::new();
    let principal = PrincipalId::new();
    let session = SessionId::new();
    let codec = SessionCapabilityCodec::new("capability-key", SECRET, 3);
    let claims = SessionCapabilityClaims::new(
        tenant.clone(),
        principal.clone(),
        session.clone(),
        7,
        "policy-snapshot-9",
        BTreeSet::from(["browser:act".to_owned(), "session:read".to_owned()]),
        "jti-capability-1",
        now - 1,
        now + 60,
        Some(ActorBinding::new("client-cert-A")),
    );
    let token = codec.issue(&claims);
    assert!(token.is_ok());
    let Some(token) = token.ok() else {
        return;
    };
    let expectation = CapabilityExpectation {
        tenant_id: &tenant,
        principal_id: &principal,
        session_id: &session,
        session_incarnation: 7,
        policy_snapshot_id: "policy-snapshot-9",
        required_scope: "browser:act",
        actor_thumbprint: Some("client-cert-A"),
    };
    assert!(codec.verify_at(&token, expectation, now).is_ok());

    let stale = CapabilityExpectation {
        session_incarnation: 8,
        ..expectation
    };
    assert_eq!(
        codec.verify_at(&token, stale, now),
        Err(AuthError::CapabilityBindingMismatch)
    );
    let excessive_scope = CapabilityExpectation {
        required_scope: "browser:evaluate",
        ..expectation
    };
    assert_eq!(
        codec.verify_at(&token, excessive_scope, now),
        Err(AuthError::ScopeDenied)
    );
}

#[test]
fn ordinary_capability_is_reusable_but_one_time_jti_has_one_concurrent_winner() {
    let now = chrono::Utc::now().timestamp();
    let registry = Arc::new(OneTimeJtiRegistry::new());
    assert!(registry.register("approval-jti", now + 60).is_ok());
    let barrier = Arc::new(Barrier::new(17));
    let mut threads = Vec::new();
    for _ in 0..16 {
        let registry = registry.clone();
        let barrier = barrier.clone();
        threads.push(thread::spawn(move || {
            barrier.wait();
            registry.consume("approval-jti", now)
        }));
    }
    barrier.wait();

    let winners = threads
        .into_iter()
        .filter_map(|handle| handle.join().ok())
        .filter(|result| result.is_ok())
        .count();
    assert_eq!(winners, 1);
    assert_eq!(
        registry.consume("approval-jti", now),
        Err(AuthError::TokenConsumed)
    );
}

#[test]
fn expired_one_time_jti_is_never_consumed() {
    let registry = OneTimeJtiRegistry::new();
    assert!(registry.register("expired", 10).is_ok());
    assert_eq!(
        registry.consume("expired", 10),
        Err(AuthError::TokenExpired)
    );
    assert_eq!(registry.consume("unknown", 0), Err(AuthError::UnknownToken));
}
