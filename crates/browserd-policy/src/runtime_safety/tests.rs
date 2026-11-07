use super::*;
use crate::{
    ActionArgumentsHash, ActionType, ApprovalDecision, ApprovalError, ApprovalRequest,
    CanonicalActionProposal, CredentialRefsHash, PageId, PrincipalId, StaleApprovalReason,
};
use browserd_core::{SafetySwitchMutation, SafetySwitchSnapshot};
use std::time::Duration;

fn context(feature: &str) -> ExecutionContext {
    ExecutionContext {
        tenant_id: TenantId::new(),
        requester_principal_id: PrincipalId::new(),
        session_id: SessionId::new(),
        session_incarnation: 1,
        page_id: PageId::new(),
        target_incarnation: 1,
        frame_document_epoch: 1,
        current_origin: Origin::parse("https://sub.example.test/").expect("origin"),
        url_revision: 1,
        node_ref: None,
        node_valid: true,
        placement_owned: true,
        resolved_ips: vec!["::ffff:192.0.2.1".parse().expect("IP")],
        credential_refs: vec![],
        feature: feature.to_owned(),
        chromium_build: "fixture-build".to_owned(),
        effective_isolation: IsolationProfile::DedicatedProcess,
    }
}
fn approved(context: &ExecutionContext, action_type: ActionType) -> ApprovalRequest {
    let proposal = CanonicalActionProposal::new(
        context.tenant_id.clone(),
        context.requester_principal_id.clone(),
        context.session_id.clone(),
        1,
        context.page_id.clone(),
        1,
        1,
        context.current_origin.clone(),
        1,
        action_type,
        ActionArgumentsHash::digest(b"action"),
        None,
        CredentialRefsHash::digest(std::iter::empty()),
        10_000,
    );
    let request = ApprovalRequest::new(proposal, true);
    request
        .decide(PrincipalId::new(), ApprovalDecision::Approve, 0)
        .expect("approve");
    request
}
#[test]
fn unavailable_safety_blocks_feature_secret_and_approval_before_any_commit() {
    let cache = Arc::new(RuntimeSafetyCache::new());
    let policy = EmergencyPolicy::default();
    policy.attach_runtime_safety_cache(cache).expect("bind");
    let context = context("browser:click");
    let mut commits = 0;
    assert!(
        policy
            .authorize_feature_dispatch(&context, || commits += 1)
            .is_err()
    );
    assert!(
        policy
            .authorize_secret_dispatch(
                &context.tenant_id,
                &context.session_id,
                "ref",
                &context.current_origin,
                || commits += 1
            )
            .is_err()
    );
    assert!(
        approved(&context, ActionType::Click)
            .authorize_and_dispatch(&policy, &context, 1, || commits += 1)
            .is_err()
    );
    assert_eq!(commits, 0);
}
#[test]
fn runtime_deny_consumes_approved_token_and_allow_rechecks_latest_snapshot() {
    let cache = Arc::new(RuntimeSafetyCache::new());
    let namespace = *SessionId::new().as_uuid();
    let initial = SafetySwitchSnapshot::default();
    cache
        .install(namespace, initial.clone(), Duration::from_secs(30))
        .expect("install");
    let policy = EmergencyPolicy::default();
    policy
        .attach_runtime_safety_cache(cache.clone())
        .expect("bind");
    let context = context("browser:evaluate");
    let request = approved(&context, ActionType::Evaluate);
    let mut effects = 0;
    assert!(matches!(
        request.authorize_and_dispatch(&policy, &context, 1, || effects += 1),
        Err(ApprovalError::ApprovalStale(
            StaleApprovalReason::EmergencyDenied(EmergencyDenyReason::FeatureKillSwitch)
        ))
    ));
    let enabled = initial
        .apply(&SafetySwitchMutation::DisableEvaluate(false))
        .expect("enable");
    cache
        .install(namespace, enabled.clone(), Duration::from_secs(30))
        .expect("update");
    assert!(matches!(
        request.authorize_and_dispatch(&policy, &context, 1, || effects += 1),
        Err(ApprovalError::ApprovalStale(
            StaleApprovalReason::TokenConsumed
        ))
    ));
    policy
        .authorize_feature_dispatch(&context, || effects += 1)
        .expect("allow current feature");
    let denied = enabled
        .apply(&SafetySwitchMutation::SetDeniedDomain {
            domain: "example.test".to_owned(),
            denied: true,
        })
        .expect("deny");
    cache
        .install(namespace, denied, Duration::from_secs(30))
        .expect("update");
    assert_eq!(
        policy.authorize_feature_dispatch(&context, || effects += 1),
        Err(SecretDispatchAdmissionError::Denied(
            EmergencyDenyReason::DomainDenied
        ))
    );
    assert_eq!(effects, 1);
}
#[test]
fn mapped_ip_and_trusted_launch_digest_block_actual_feature_and_secret_markers() {
    let cache = Arc::new(RuntimeSafetyCache::new());
    let namespace = *SessionId::new().as_uuid();
    let initial = SafetySwitchSnapshot::default()
        .apply(&SafetySwitchMutation::SetDeniedIp {
            ip: "192.0.2.1".parse().expect("IP"),
            denied: true,
        })
        .expect("deny IP");
    cache
        .install(namespace, initial.clone(), Duration::from_secs(30))
        .expect("install");
    let policy = EmergencyPolicy::default();
    policy
        .attach_runtime_safety_cache_with_build(cache.clone(), "17".repeat(32))
        .expect("trusted build");
    let context = context("browser:click");
    let mut effects = 0;
    assert_eq!(
        policy.authorize_feature_dispatch(&context, || effects += 1),
        Err(SecretDispatchAdmissionError::Denied(
            EmergencyDenyReason::IpDenied
        ))
    );
    cache
        .install(
            namespace,
            initial
                .apply(&SafetySwitchMutation::SetChromiumBuildDisabled {
                    digest: "17".repeat(32),
                    disabled: true,
                })
                .expect("kill build"),
            Duration::from_secs(30),
        )
        .expect("update");
    assert_eq!(
        policy.authorize_secret_dispatch(
            &context.tenant_id,
            &context.session_id,
            "ref",
            &context.current_origin,
            || effects += 1
        ),
        Err(SecretDispatchAdmissionError::Denied(
            EmergencyDenyReason::ChromiumBuildKillSwitch
        ))
    );
    assert_eq!(effects, 0);
}
#[test]
fn dispatch_callback_runs_after_emergency_cache_and_approval_locks_release() {
    let cache = Arc::new(RuntimeSafetyCache::new());
    let namespace = *SessionId::new().as_uuid();
    let snapshot = SafetySwitchSnapshot::default();
    cache
        .install(namespace, snapshot.clone(), Duration::from_secs(30))
        .expect("install");
    let policy = Arc::new(EmergencyPolicy::default());
    policy
        .attach_runtime_safety_cache(cache.clone())
        .expect("bind");
    let context = context("browser:click");
    approved(&context, ActionType::Click)
        .authorize_and_dispatch(&policy, &context, 1, || {
            let (sent, received) = std::sync::mpsc::channel();
            let policy = policy.clone();
            let handle = std::thread::spawn(move || {
                policy
                    .disable_tenant(TenantId::new())
                    .expect("policy update");
                cache
                    .install(
                        namespace,
                        snapshot
                            .apply(&SafetySwitchMutation::DisableDownloads(true))
                            .expect("next"),
                        Duration::from_secs(30),
                    )
                    .expect("runtime update");
                sent.send(()).expect("send");
            });
            received
                .recv_timeout(Duration::from_secs(2))
                .expect("updates during effect");
            handle.join().expect("update");
        })
        .expect("admitted effect");
}
