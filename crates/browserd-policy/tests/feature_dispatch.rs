#![allow(clippy::expect_used, clippy::panic)]

use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::Duration;

use browserd_core::{IsolationProfile, PageId, PrincipalId, SessionId, TenantId};
use browserd_policy::{
    EmergencyDenyReason, EmergencyPolicy, ExecutionContext, Origin, SecretDispatchAdmissionError,
};

fn context() -> ExecutionContext {
    ExecutionContext {
        tenant_id: TenantId::new(),
        requester_principal_id: PrincipalId::new(),
        session_id: SessionId::new(),
        session_incarnation: 7,
        page_id: PageId::new(),
        target_incarnation: 11,
        frame_document_epoch: 13,
        current_origin: Origin::parse("https://app.example.test:8443").expect("origin"),
        url_revision: 17,
        node_ref: None,
        node_valid: true,
        placement_owned: true,
        resolved_ips: vec![
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
        ],
        credential_refs: vec!["unrelated-ref".to_owned(), "app-ref".to_owned()],
        feature: "browser:evaluate".to_owned(),
        chromium_build: "sha256:test-build".to_owned(),
        effective_isolation: IsolationProfile::SharedContext,
    }
}

fn deny(policy: &EmergencyPolicy, context: &ExecutionContext, reason: EmergencyDenyReason) {
    match reason {
        EmergencyDenyReason::TenantDisabled => {
            policy
                .disable_tenant(context.tenant_id.clone())
                .expect("deny");
        }
        EmergencyDenyReason::SessionDisabled => {
            policy
                .disable_session(context.session_id.clone())
                .expect("deny");
        }
        EmergencyDenyReason::DomainDenied => {
            policy.deny_domain("example.test").expect("deny");
        }
        EmergencyDenyReason::IpDenied => {
            policy.deny_ip(context.resolved_ips[1]).expect("deny");
        }
        EmergencyDenyReason::SecretRevoked => {
            policy.revoke_secret("app-ref").expect("deny");
        }
        EmergencyDenyReason::FeatureKillSwitch => {
            policy.deny_feature(&context.feature).expect("deny");
        }
        EmergencyDenyReason::ChromiumBuildKillSwitch => {
            policy
                .kill_chromium_build(&context.chromium_build)
                .expect("deny");
        }
        EmergencyDenyReason::ForceDedicatedProcess => {
            policy
                .force_dedicated_process(context.tenant_id.clone())
                .expect("deny");
        }
    }
}

#[test]
fn every_emergency_field_prevents_feature_dispatch_commit() {
    let context = context();
    for reason in [
        EmergencyDenyReason::TenantDisabled,
        EmergencyDenyReason::SessionDisabled,
        EmergencyDenyReason::DomainDenied,
        EmergencyDenyReason::IpDenied,
        EmergencyDenyReason::SecretRevoked,
        EmergencyDenyReason::FeatureKillSwitch,
        EmergencyDenyReason::ChromiumBuildKillSwitch,
        EmergencyDenyReason::ForceDedicatedProcess,
    ] {
        let policy = EmergencyPolicy::default();
        deny(&policy, &context, reason);
        let mut committed = 0;
        assert_eq!(
            policy.authorize_feature_dispatch(&context, || committed += 1),
            Err(SecretDispatchAdmissionError::Denied(reason))
        );
        assert_eq!(committed, 0);
    }
}

#[test]
fn unrelated_emergency_entries_leave_the_exact_execution_context_allowed() {
    let policy = EmergencyPolicy::default();
    policy.disable_tenant(TenantId::new()).expect("tenant");
    policy.disable_session(SessionId::new()).expect("session");
    policy.deny_domain("different.test").expect("domain");
    policy
        .deny_ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3)))
        .expect("IP");
    policy.revoke_secret("different-ref").expect("secret");
    policy.deny_feature("browser:fill_secret").expect("feature");
    policy
        .kill_chromium_build("sha256:different-build")
        .expect("build");
    policy
        .force_dedicated_process(TenantId::new())
        .expect("isolation");
    assert_eq!(policy.authorize_feature_dispatch(&context(), || 29), Ok(29));
}

#[test]
fn feature_domain_denial_observes_exact_dns_label_boundaries() {
    let policy = EmergencyPolicy::default();
    policy.deny_domain("example.test").expect("domain");
    let mut context = context();
    for origin in ["https://example.test", "https://a.b.example.test:8443"] {
        context.current_origin = Origin::parse(origin).expect("origin");
        assert_eq!(
            policy.authorize_feature_dispatch(&context, || ()),
            Err(SecretDispatchAdmissionError::Denied(
                EmergencyDenyReason::DomainDenied
            ))
        );
    }
    for origin in [
        "https://notexample.test",
        "https://example.test.attacker.test",
    ] {
        context.current_origin = Origin::parse(origin).expect("origin");
        assert_eq!(policy.authorize_feature_dispatch(&context, || ()), Ok(()));
    }
}

#[test]
fn forced_dedicated_requires_at_least_a_dedicated_process() {
    let policy = EmergencyPolicy::default();
    let mut context = context();
    policy
        .force_dedicated_process(context.tenant_id.clone())
        .expect("isolation");
    for isolation in [
        IsolationProfile::SharedContext,
        IsolationProfile::TenantDedicatedShard,
    ] {
        context.effective_isolation = isolation;
        assert_eq!(
            policy.authorize_feature_dispatch(&context, || ()),
            Err(SecretDispatchAdmissionError::Denied(
                EmergencyDenyReason::ForceDedicatedProcess
            ))
        );
    }
    for isolation in [
        IsolationProfile::DedicatedProcess,
        IsolationProfile::DedicatedWorker,
    ] {
        context.effective_isolation = isolation;
        assert_eq!(policy.authorize_feature_dispatch(&context, || ()), Ok(()));
    }
}

#[test]
fn denial_precedence_matches_existing_approval_admission() {
    let policy = EmergencyPolicy::default();
    let context = context();
    for reason in [
        EmergencyDenyReason::ForceDedicatedProcess,
        EmergencyDenyReason::ChromiumBuildKillSwitch,
        EmergencyDenyReason::FeatureKillSwitch,
        EmergencyDenyReason::SecretRevoked,
        EmergencyDenyReason::IpDenied,
        EmergencyDenyReason::DomainDenied,
        EmergencyDenyReason::SessionDisabled,
        EmergencyDenyReason::TenantDisabled,
    ] {
        deny(&policy, &context, reason);
        assert_eq!(
            policy.authorize_feature_dispatch(&context, || ()),
            Err(SecretDispatchAdmissionError::Denied(reason))
        );
    }
}

#[test]
fn feature_commit_and_later_revocation_share_the_linearization_lock() {
    let policy = Arc::new(EmergencyPolicy::default());
    let context = context();
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let admitting_policy = policy.clone();
    let admitting_context = context.clone();
    let admitting = thread::spawn(move || {
        admitting_policy.authorize_feature_dispatch(&admitting_context, || {
            entered_tx.send(()).expect("entered");
            // Only this test holds admission open, to expose the lock ordering deterministically.
            release_rx
                .recv_timeout(Duration::from_secs(3))
                .expect("release");
            31
        })
    });
    entered_rx
        .recv_timeout(Duration::from_secs(3))
        .expect("entered");
    let (attempt_tx, attempt_rx) = mpsc::channel();
    let (revoked_tx, revoked_rx) = mpsc::channel();
    let revoking_policy = policy.clone();
    let revoking = thread::spawn(move || {
        attempt_tx.send(()).expect("attempt");
        revoking_policy.revoke_secret("app-ref").expect("revoke");
        revoked_tx.send(()).expect("revoked");
    });
    attempt_rx
        .recv_timeout(Duration::from_secs(3))
        .expect("attempt");
    assert!(matches!(
        revoked_rx.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    release_tx.send(()).expect("release");
    assert_eq!(admitting.join().expect("admission"), Ok(31));
    revoked_rx
        .recv_timeout(Duration::from_secs(3))
        .expect("revoked");
    revoking.join().expect("revoke thread");
    let mut committed = false;
    assert_eq!(
        policy.authorize_feature_dispatch(&context, || committed = true),
        Err(SecretDispatchAdmissionError::Denied(
            EmergencyDenyReason::SecretRevoked
        ))
    );
    assert!(!committed);
}

#[test]
fn poisoned_policy_coordination_never_commits_another_feature() {
    let policy = Arc::new(EmergencyPolicy::default());
    let failed_policy = policy.clone();
    assert!(
        thread::spawn(move || {
            failed_policy
                .authorize_feature_dispatch(&context(), || -> () { panic!("test lock poison") })
        })
        .join()
        .is_err()
    );
    let mut committed = false;
    assert_eq!(
        policy.authorize_feature_dispatch(&context(), || committed = true),
        Err(SecretDispatchAdmissionError::Unavailable)
    );
    assert!(!committed);
}
