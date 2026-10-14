#![allow(clippy::expect_used)]

use std::sync::{Arc, mpsc};
use std::thread;
use std::time::Duration;

use browserd_core::{SessionId, TenantId};
use browserd_policy::{EmergencyDenyReason, EmergencyPolicy, Origin, SecretDispatchAdmissionError};

#[test]
fn revoked_credentials_never_commit_a_dispatch() {
    let policy = EmergencyPolicy::default();
    let tenant = TenantId::new();
    let session = SessionId::new();
    let origin = Origin::parse("https://login.example.test").expect("origin");
    policy.revoke_secret("login-ref").expect("revoke");
    let mut committed = false;
    assert_eq!(
        policy.authorize_secret_dispatch(&tenant, &session, "login-ref", &origin, || {
            committed = true;
        }),
        Err(SecretDispatchAdmissionError::Denied(
            EmergencyDenyReason::SecretRevoked
        ))
    );
    assert!(!committed);
    assert_eq!(
        policy.authorize_secret_dispatch(&tenant, &session, "other-ref", &origin, || 7),
        Ok(7)
    );
}

#[test]
fn tenant_session_domain_and_feature_emergency_denials_apply_to_secret_fill() {
    let tenant = TenantId::new();
    let session = SessionId::new();
    let origin = Origin::parse("https://login.example.test:8443").expect("origin");
    for reason in [
        EmergencyDenyReason::TenantDisabled,
        EmergencyDenyReason::SessionDisabled,
        EmergencyDenyReason::DomainDenied,
        EmergencyDenyReason::FeatureKillSwitch,
    ] {
        let policy = EmergencyPolicy::default();
        match reason {
            EmergencyDenyReason::TenantDisabled => {
                policy.disable_tenant(tenant.clone()).expect("disable");
            }
            EmergencyDenyReason::SessionDisabled => {
                policy.disable_session(session.clone()).expect("disable");
            }
            EmergencyDenyReason::DomainDenied => {
                policy.deny_domain("example.test").expect("deny domain");
            }
            EmergencyDenyReason::FeatureKillSwitch => {
                policy.deny_feature("browser:fill_secret").expect("feature");
            }
            _ => unreachable!("the test enumerates the supported mutations"),
        }
        let mut committed = false;
        assert_eq!(
            policy.authorize_secret_dispatch(&tenant, &session, "login-ref", &origin, || {
                committed = true;
            }),
            Err(SecretDispatchAdmissionError::Denied(reason))
        );
        assert!(!committed);
    }
}

#[test]
fn domain_denial_requires_a_domain_label_boundary() {
    let policy = EmergencyPolicy::default();
    policy.deny_domain("example.test").expect("deny domain");
    let tenant = TenantId::new();
    let session = SessionId::new();
    let other = Origin::parse("https://notexample.test").expect("origin");
    assert_eq!(
        policy.authorize_secret_dispatch(&tenant, &session, "login-ref", &other, || ()),
        Ok(())
    );
}

#[test]
fn emergency_revoke_and_secret_commit_share_the_same_linearization_lock() {
    let policy = Arc::new(EmergencyPolicy::default());
    let tenant = TenantId::new();
    let session = SessionId::new();
    let origin = Origin::parse("https://login.example.test").expect("origin");
    let (admitting_tx, admitting_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let worker_policy = policy.clone();
    let worker_tenant = tenant.clone();
    let worker_session = session.clone();
    let worker_origin = origin.clone();
    let admitted = thread::spawn(move || {
        worker_policy.authorize_secret_dispatch(
            &worker_tenant,
            &worker_session,
            "login-ref",
            &worker_origin,
            || {
                admitting_tx.send(()).expect("admission signal");
                // A controlled test barrier makes the lock boundary observable; production commit
                // callbacks are short/non-blocking and contain no browser I/O.
                release_rx
                    .recv_timeout(Duration::from_secs(3))
                    .expect("release admission");
            },
        )
    });
    admitting_rx
        .recv_timeout(Duration::from_secs(3))
        .expect("admission entered");
    let (revoking_tx, revoking_rx) = mpsc::channel();
    let (revoked_tx, revoked_rx) = mpsc::channel();
    let revoke_policy = policy.clone();
    let revoking = thread::spawn(move || {
        revoking_tx.send(()).expect("revoke started");
        revoke_policy.revoke_secret("login-ref").expect("revoke");
        revoked_tx.send(()).expect("revoke completed");
    });
    revoking_rx
        .recv_timeout(Duration::from_secs(3))
        .expect("revoke attempt");
    assert!(matches!(
        revoked_rx.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    release_tx.send(()).expect("release");
    assert_eq!(admitted.join().expect("admission thread"), Ok(()));
    revoked_rx
        .recv_timeout(Duration::from_secs(3))
        .expect("revoke completed");
    revoking.join().expect("revoke thread");
    assert_eq!(
        policy.authorize_secret_dispatch(&tenant, &session, "login-ref", &origin, || ()),
        Err(SecretDispatchAdmissionError::Denied(
            EmergencyDenyReason::SecretRevoked
        ))
    );
}
