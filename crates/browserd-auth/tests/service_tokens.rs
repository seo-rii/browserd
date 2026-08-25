#![allow(clippy::expect_used)]

use std::collections::BTreeSet;

use browserd_auth::{
    ActorBinding, AuthConfig, AuthError, RevocationRegistry, ServiceClaims, ServiceTokenSigner,
    ServiceTokenVerifier, VerificationKeySet,
};
use browserd_core::{PrincipalId, TenantId};
use jsonwebtoken::Algorithm;

const SECRET: &[u8] = b"a-test-key-that-is-long-enough-for-hmac-sha256";

fn setup(require_actor_binding: bool) -> (ServiceTokenSigner, ServiceTokenVerifier) {
    let mut keys = VerificationKeySet::new();
    assert!(
        keys.insert_hmac("active-key", Algorithm::HS256, SECRET)
            .is_ok()
    );
    let config = AuthConfig::new(
        "browser-auth",
        "browserd",
        [Algorithm::HS256],
        5,
        require_actor_binding,
    );
    (
        ServiceTokenSigner::new("active-key", Algorithm::HS256, SECRET),
        ServiceTokenVerifier::new(config, keys, RevocationRegistry::new()),
    )
}

fn claims(now: i64, actor: Option<&str>) -> ServiceClaims {
    ServiceClaims::new(
        "browser-auth",
        "browserd",
        PrincipalId::new(),
        TenantId::new(),
        BTreeSet::from(["browser:act".to_owned(), "session:create".to_owned()]),
        "jti-service-1",
        now - 1,
        now + 60,
        actor.map(ActorBinding::new),
    )
}

#[test]
fn exact_issuer_audience_algorithm_and_kid_are_required() {
    let now = chrono::Utc::now().timestamp();
    let (signer, verifier) = setup(false);
    let valid = signer.sign(&claims(now, None));
    assert!(valid.is_ok());
    let Some(valid) = valid.ok() else {
        return;
    };
    assert!(verifier.verify_at(&valid, None, now).is_ok());

    for bad_claims in [
        ServiceClaims::new(
            "other-issuer",
            "browserd",
            PrincipalId::new(),
            TenantId::new(),
            BTreeSet::from(["browser:act".to_owned()]),
            "jti-bad-iss",
            now - 1,
            now + 60,
            None,
        ),
        ServiceClaims::new(
            "browser-auth",
            "other-audience",
            PrincipalId::new(),
            TenantId::new(),
            BTreeSet::from(["browser:act".to_owned()]),
            "jti-bad-aud",
            now - 1,
            now + 60,
            None,
        ),
    ] {
        let token = signer.sign(&bad_claims);
        assert!(token.is_ok());
        let Some(token) = token.ok() else {
            continue;
        };
        assert_eq!(
            verifier.verify_at(&token, None, now),
            Err(AuthError::InvalidToken)
        );
    }

    let unknown_signer = ServiceTokenSigner::new("retired-key", Algorithm::HS256, SECRET);
    let unknown = unknown_signer.sign(&claims(now, None));
    assert!(unknown.is_ok());
    let Some(unknown) = unknown.ok() else {
        return;
    };
    assert_eq!(
        verifier.verify_at(&unknown, None, now),
        Err(AuthError::UnknownKey)
    );

    let wrong_algorithm = ServiceTokenSigner::new("active-key", Algorithm::HS384, SECRET);
    let wrong = wrong_algorithm.sign(&claims(now, None));
    assert!(wrong.is_ok());
    let Some(wrong) = wrong.ok() else {
        return;
    };
    assert_eq!(
        verifier.verify_at(&wrong, None, now),
        Err(AuthError::AlgorithmDenied)
    );
}

#[test]
fn temporal_claims_and_nonempty_jti_are_fail_closed() {
    let now = chrono::Utc::now().timestamp();
    let (signer, verifier) = setup(false);
    for invalid in [
        claims(now - 120, None),
        ServiceClaims::new(
            "browser-auth",
            "browserd",
            PrincipalId::new(),
            TenantId::new(),
            BTreeSet::from(["browser:act".to_owned()]),
            "future",
            now + 30,
            now + 60,
            None,
        ),
        ServiceClaims::new(
            "browser-auth",
            "browserd",
            PrincipalId::new(),
            TenantId::new(),
            BTreeSet::from(["browser:act".to_owned()]),
            "",
            now - 1,
            now + 60,
            None,
        ),
    ] {
        let token = signer.sign(&invalid);
        assert!(token.is_ok());
        let Some(token) = token.ok() else {
            continue;
        };
        assert!(verifier.verify_at(&token, None, now).is_err());
    }
}

#[test]
fn required_mtls_binding_uses_the_presented_certificate_thumbprint() {
    let now = chrono::Utc::now().timestamp();
    let (signer, verifier) = setup(true);
    let token = signer.sign(&claims(now, Some("thumbprint-A")));
    assert!(token.is_ok());
    let Some(token) = token.ok() else {
        return;
    };
    assert!(
        verifier
            .verify_at(&token, Some("thumbprint-A"), now)
            .is_ok()
    );
    assert_eq!(
        verifier.verify_at(&token, Some("thumbprint-B"), now),
        Err(AuthError::ActorBindingMismatch)
    );
    assert_eq!(
        verifier.verify_at(&token, None, now),
        Err(AuthError::ActorBindingRequired)
    );
}

#[test]
fn revocation_and_scope_checks_do_not_mutate_the_principal() {
    let now = chrono::Utc::now().timestamp();
    let (signer, verifier) = setup(false);
    let token = signer.sign(&claims(now, None));
    assert!(token.is_ok());
    let Some(token) = token.ok() else {
        return;
    };
    let principal = verifier.verify_at(&token, None, now);
    assert!(principal.is_ok());
    let Some(principal) = principal.ok() else {
        return;
    };
    assert!(principal.require_scope("browser:act").is_ok());
    assert_eq!(
        principal.require_scope("browser:evaluate"),
        Err(AuthError::ScopeDenied)
    );

    verifier.revocations().revoke("jti-service-1");
    assert_eq!(
        verifier.verify_at(&token, None, now),
        Err(AuthError::TokenRevoked)
    );
}
