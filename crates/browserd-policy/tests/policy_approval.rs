#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::error::Error;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;

use browserd_core::{IsolationProfile, PageId, PrincipalId, SessionId, TenantId};
use browserd_policy::{
    ActionArgumentsHash, ActionType, ApprovalDecision, ApprovalError, ApprovalRequest,
    ApprovalState, CanonicalActionProposal, CredentialRefsHash, DecisionOutcome,
    EmergencyDenyReason, EmergencyPolicy, ExecutionContext, NodeReference, NormalPolicy, Origin,
    PolicySnapshot, StaleApprovalReason,
};

fn proposal(
    tenant_id: TenantId,
    requester: PrincipalId,
    session_id: SessionId,
    page_id: PageId,
) -> CanonicalActionProposal {
    CanonicalActionProposal::new(
        tenant_id,
        requester,
        session_id,
        7,
        page_id,
        11,
        13,
        Origin::parse("https://example.com").expect("valid origin"),
        17,
        ActionType::Click,
        ActionArgumentsHash::digest(b"{\"button\":\"submit\"}"),
        Some(NodeReference::new("node-opaque-42").expect("valid node reference")),
        CredentialRefsHash::digest(["secret/login"].iter().copied()),
        10_000,
    )
}

fn execution_context(proposal: &CanonicalActionProposal) -> ExecutionContext {
    ExecutionContext {
        tenant_id: proposal.tenant_id().clone(),
        requester_principal_id: proposal.requester_principal_id().clone(),
        session_id: proposal.session_id().clone(),
        session_incarnation: proposal.session_incarnation(),
        page_id: proposal.page_id().clone(),
        target_incarnation: proposal.target_incarnation(),
        frame_document_epoch: proposal.frame_document_epoch(),
        current_origin: proposal.current_origin().clone(),
        url_revision: proposal.url_revision(),
        node_ref: proposal.node_ref().cloned(),
        node_valid: true,
        placement_owned: true,
        resolved_ips: vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
        credential_refs: vec!["secret/login".to_owned()],
        feature: "browser:click".to_owned(),
        chromium_build: "sha256:known-good".to_owned(),
        effective_isolation: IsolationProfile::SharedContext,
    }
}

fn approved_request(
    proposal: CanonicalActionProposal,
    approver: PrincipalId,
) -> Result<ApprovalRequest, ApprovalError> {
    let request = ApprovalRequest::new(proposal, true);
    assert!(matches!(
        request.decide(approver, ApprovalDecision::Approve, 100)?,
        DecisionOutcome::Recorded(ApprovalState::Approved { .. })
    ));
    Ok(request)
}

#[test]
fn normal_policy_is_an_immutable_owned_snapshot() {
    let mut allowlist = vec!["example.com".to_owned()];
    let policy = NormalPolicy {
        plan: "pro".to_owned(),
        feature_profile: "standard".to_owned(),
        isolation: IsolationProfile::SharedContext,
        network_allowlist: allowlist.clone(),
        ttl_seconds: 1_800,
    };
    let snapshot = PolicySnapshot::new(policy);
    let digest = snapshot.digest();

    allowlist.push("attacker.invalid".to_owned());
    assert_eq!(snapshot.policy().network_allowlist, vec!["example.com"]);
    assert_eq!(snapshot.digest(), digest);
}

#[test]
fn proposal_hash_binds_every_security_relevant_field() {
    let tenant = TenantId::new();
    let requester = PrincipalId::new();
    let session = SessionId::new();
    let page = PageId::new();
    let original = proposal(tenant, requester, session, page);
    let original_hash = original.hash();

    let variants = [
        original.clone().with_session_incarnation(8),
        original.clone().with_target_incarnation(12),
        original.clone().with_frame_document_epoch(14),
        original
            .clone()
            .with_current_origin(Origin::parse("https://other.example").unwrap()),
        original.clone().with_url_revision(18),
        original.clone().with_action_type(ActionType::Fill),
        original
            .clone()
            .with_arguments_hash(ActionArgumentsHash::digest(b"different")),
        original
            .clone()
            .with_node_ref(Some(NodeReference::new("other-node").unwrap())),
        original
            .clone()
            .with_credential_refs_hash(CredentialRefsHash::digest(["other-secret"])),
        original.clone().with_expires_at_unix_ms(10_001),
    ];

    for variant in variants {
        assert_ne!(variant.hash(), original_hash);
    }
}

#[test]
fn internal_token_binding_contains_exact_identity_and_a_unique_jti() {
    let tenant = TenantId::new();
    let requester = PrincipalId::new();
    let session = SessionId::new();
    let proposal = proposal(
        tenant.clone(),
        requester.clone(),
        session.clone(),
        PageId::new(),
    );
    let expected_hash = proposal.hash();
    let first = ApprovalRequest::new(proposal.clone(), true).token_binding();
    let second = ApprovalRequest::new(proposal, true).token_binding();

    assert_eq!(first.proposal_hash(), expected_hash);
    assert_eq!(first.tenant_id(), &tenant);
    assert_eq!(first.requester_principal_id(), &requester);
    assert_eq!(first.session_id(), &session);
    assert_eq!(first.session_incarnation(), 7);
    assert_eq!(first.expires_at_unix_ms(), 10_000);
    assert_ne!(first.jti(), second.jti());
}

#[test]
fn four_eyes_rejects_the_requesting_principal_without_consuming_decision()
-> Result<(), Box<dyn Error>> {
    let requester = PrincipalId::new();
    let request = ApprovalRequest::new(
        proposal(
            TenantId::new(),
            requester.clone(),
            SessionId::new(),
            PageId::new(),
        ),
        true,
    );

    assert_eq!(
        request.decide(requester, ApprovalDecision::Approve, 100),
        Err(ApprovalError::FourEyesViolation)
    );
    assert_eq!(request.state()?, ApprovalState::Pending);
    assert!(matches!(
        request.decide(PrincipalId::new(), ApprovalDecision::Approve, 100)?,
        DecisionOutcome::Recorded(ApprovalState::Approved { .. })
    ));
    Ok(())
}

#[test]
fn same_decision_is_idempotent_and_opposite_decision_conflicts() -> Result<(), Box<dyn Error>> {
    let requester = PrincipalId::new();
    let request = ApprovalRequest::new(
        proposal(TenantId::new(), requester, SessionId::new(), PageId::new()),
        true,
    );
    let approver = PrincipalId::new();

    let first = request.decide(approver.clone(), ApprovalDecision::Approve, 100)?;
    let retry = request.decide(approver, ApprovalDecision::Approve, 100)?;
    assert!(matches!(first, DecisionOutcome::Recorded(_)));
    assert!(matches!(retry, DecisionOutcome::Existing(_)));
    assert!(matches!(
        request.decide(PrincipalId::new(), ApprovalDecision::Deny, 100),
        Err(ApprovalError::DecisionConflict {
            existing: ApprovalDecision::Approve
        })
    ));
    Ok(())
}

#[test]
fn concurrent_decisions_have_one_winner_and_never_overwrite_it() -> Result<(), Box<dyn Error>> {
    const CALLERS: usize = 32;
    let requester = PrincipalId::new();
    let request = Arc::new(ApprovalRequest::new(
        proposal(TenantId::new(), requester, SessionId::new(), PageId::new()),
        true,
    ));
    let approver = PrincipalId::new();
    let barrier = Arc::new(Barrier::new(CALLERS));
    let mut handles = Vec::new();

    for index in 0..CALLERS {
        let request = Arc::clone(&request);
        let approver = approver.clone();
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            let decision = if index % 2 == 0 {
                ApprovalDecision::Approve
            } else {
                ApprovalDecision::Deny
            };
            request.decide(approver, decision, 100)
        }));
    }

    let outcomes = handles
        .into_iter()
        .map(|handle| {
            handle
                .join()
                .map_err(|_| std::io::Error::other("decision panic"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, Ok(DecisionOutcome::Recorded(_))))
            .count(),
        1
    );
    let terminal = request.state()?;
    assert!(matches!(
        terminal,
        ApprovalState::Approved { .. } | ApprovalState::Denied { .. }
    ));
    assert!(outcomes.iter().all(|outcome| matches!(
        (&terminal, outcome),
        (
            ApprovalState::Approved { .. },
            Ok(DecisionOutcome::Recorded(ApprovalState::Approved { .. })
                | DecisionOutcome::Existing(ApprovalState::Approved { .. }),),
        ) | (
            ApprovalState::Approved { .. },
            Err(ApprovalError::DecisionConflict {
                existing: ApprovalDecision::Approve,
            }),
        ) | (
            ApprovalState::Denied { .. },
            Ok(DecisionOutcome::Recorded(ApprovalState::Denied { .. })
                | DecisionOutcome::Existing(ApprovalState::Denied { .. }),),
        ) | (
            ApprovalState::Denied { .. },
            Err(ApprovalError::DecisionConflict {
                existing: ApprovalDecision::Deny,
            }),
        )
    )));
    Ok(())
}

#[test]
fn expired_approval_fails_known_and_cannot_be_decided() {
    let requester = PrincipalId::new();
    let request = ApprovalRequest::new(
        proposal(TenantId::new(), requester, SessionId::new(), PageId::new()),
        true,
    );
    assert_eq!(
        request.decide(PrincipalId::new(), ApprovalDecision::Approve, 10_000),
        Err(ApprovalError::ApprovalExpired)
    );
    assert_eq!(request.state(), Ok(ApprovalState::Expired));
}

#[test]
fn an_approved_but_expired_token_is_stale_and_never_dispatched() -> Result<(), Box<dyn Error>> {
    let proposal = proposal(
        TenantId::new(),
        PrincipalId::new(),
        SessionId::new(),
        PageId::new(),
    );
    let context = execution_context(&proposal);
    let request = approved_request(proposal, PrincipalId::new())?;
    let dispatches = AtomicUsize::new(0);

    assert_eq!(
        request.authorize_and_dispatch(&EmergencyPolicy::default(), &context, 10_000, || {
            dispatches.fetch_add(1, Ordering::SeqCst);
        }),
        Err(ApprovalError::ApprovalStale(StaleApprovalReason::Expired))
    );
    assert_eq!(dispatches.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn approval_token_is_consumed_once_even_under_dispatch_race() -> Result<(), Box<dyn Error>> {
    const CALLERS: usize = 24;
    let proposal = proposal(
        TenantId::new(),
        PrincipalId::new(),
        SessionId::new(),
        PageId::new(),
    );
    let context = execution_context(&proposal);
    let request = Arc::new(approved_request(proposal, PrincipalId::new())?);
    let emergency = Arc::new(EmergencyPolicy::default());
    let barrier = Arc::new(Barrier::new(CALLERS));
    let dispatches = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::new();

    for _ in 0..CALLERS {
        let request = Arc::clone(&request);
        let emergency = Arc::clone(&emergency);
        let barrier = Arc::clone(&barrier);
        let dispatches = Arc::clone(&dispatches);
        let context = context.clone();
        handles.push(thread::spawn(move || {
            barrier.wait();
            request.authorize_and_dispatch(&emergency, &context, 200, || {
                dispatches.fetch_add(1, Ordering::SeqCst);
            })
        }));
    }

    let outcomes = handles
        .into_iter()
        .map(|handle| {
            handle
                .join()
                .map_err(|_| std::io::Error::other("dispatch panic"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(dispatches.load(Ordering::SeqCst), 1);
    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(
                outcome,
                Err(ApprovalError::ApprovalStale(
                    StaleApprovalReason::TokenConsumed
                ))
            ))
            .count(),
        CALLERS - 1
    );
    Ok(())
}

#[test]
fn execution_revalidation_fails_closed_for_each_stale_binding() -> Result<(), Box<dyn Error>> {
    let cases = [
        ("principal", StaleApprovalReason::RequesterPrincipal),
        ("session", StaleApprovalReason::SessionIncarnation),
        ("placement", StaleApprovalReason::PlacementOwnership),
        ("document", StaleApprovalReason::DocumentEpoch),
        ("origin", StaleApprovalReason::Origin),
        ("url", StaleApprovalReason::UrlRevision),
        ("node", StaleApprovalReason::Node),
        ("target", StaleApprovalReason::TargetIncarnation),
    ];

    for (case, expected) in cases {
        let proposal = proposal(
            TenantId::new(),
            PrincipalId::new(),
            SessionId::new(),
            PageId::new(),
        );
        let mut context = execution_context(&proposal);
        match case {
            "principal" => context.requester_principal_id = PrincipalId::new(),
            "session" => context.session_incarnation += 1,
            "placement" => context.placement_owned = false,
            "document" => context.frame_document_epoch += 1,
            "origin" => context.current_origin = Origin::parse("https://other.example")?,
            "url" => context.url_revision += 1,
            "node" => context.node_valid = false,
            "target" => context.target_incarnation += 1,
            _ => unreachable!(),
        }
        let request = approved_request(proposal, PrincipalId::new())?;
        let dispatches = AtomicUsize::new(0);
        assert_eq!(
            request.authorize_and_dispatch(&EmergencyPolicy::default(), &context, 200, || {
                dispatches.fetch_add(1, Ordering::SeqCst);
            }),
            Err(ApprovalError::ApprovalStale(expected))
        );
        assert_eq!(dispatches.load(Ordering::SeqCst), 0);
    }
    Ok(())
}

#[test]
fn emergency_kill_switch_is_mutable_and_checked_at_dispatch_time() -> Result<(), Box<dyn Error>> {
    let proposal = proposal(
        TenantId::new(),
        PrincipalId::new(),
        SessionId::new(),
        PageId::new(),
    );
    let context = execution_context(&proposal);
    let request = approved_request(proposal, PrincipalId::new())?;
    let emergency = EmergencyPolicy::default();
    emergency.deny_feature("browser:click")?;

    let dispatches = AtomicUsize::new(0);
    assert_eq!(
        request.authorize_and_dispatch(&emergency, &context, 200, || {
            dispatches.fetch_add(1, Ordering::SeqCst);
        }),
        Err(ApprovalError::ApprovalStale(
            StaleApprovalReason::EmergencyDenied(EmergencyDenyReason::FeatureKillSwitch)
        ))
    );
    assert_eq!(dispatches.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn a_stale_attempt_permanently_invalidates_the_one_time_approval() -> Result<(), Box<dyn Error>> {
    let proposal = proposal(
        TenantId::new(),
        PrincipalId::new(),
        SessionId::new(),
        PageId::new(),
    );
    let valid_context = execution_context(&proposal);
    let mut stale_context = valid_context.clone();
    stale_context.url_revision += 1;
    let request = approved_request(proposal, PrincipalId::new())?;
    let emergency = EmergencyPolicy::default();

    assert_eq!(
        request.authorize_and_dispatch(&emergency, &stale_context, 200, || {}),
        Err(ApprovalError::ApprovalStale(
            StaleApprovalReason::UrlRevision
        ))
    );
    assert_eq!(
        request.authorize_and_dispatch(&emergency, &valid_context, 200, || {}),
        Err(ApprovalError::ApprovalStale(
            StaleApprovalReason::TokenConsumed
        ))
    );
    Ok(())
}

#[test]
fn emergency_domain_deny_uses_uts46_canonical_hostnames() -> Result<(), Box<dyn Error>> {
    let mut proposal = proposal(
        TenantId::new(),
        PrincipalId::new(),
        SessionId::new(),
        PageId::new(),
    );
    proposal = proposal.with_current_origin(Origin::parse("https://bücher.example")?);
    let context = execution_context(&proposal);
    let request = approved_request(proposal, PrincipalId::new())?;
    let emergency = EmergencyPolicy::default();
    emergency.deny_domain("BÜCHER.example.")?;

    assert_eq!(
        request.authorize_and_dispatch(&emergency, &context, 200, || {}),
        Err(ApprovalError::ApprovalStale(
            StaleApprovalReason::EmergencyDenied(EmergencyDenyReason::DomainDenied)
        ))
    );
    Ok(())
}

#[test]
fn emergency_denies_cover_tenant_session_domain_ip_secret_build_and_isolation()
-> Result<(), Box<dyn Error>> {
    let cases = vec![
        EmergencyDenyReason::TenantDisabled,
        EmergencyDenyReason::SessionDisabled,
        EmergencyDenyReason::DomainDenied,
        EmergencyDenyReason::IpDenied,
        EmergencyDenyReason::SecretRevoked,
        EmergencyDenyReason::ChromiumBuildKillSwitch,
        EmergencyDenyReason::ForceDedicatedProcess,
    ];

    for reason in cases {
        let proposal = proposal(
            TenantId::new(),
            PrincipalId::new(),
            SessionId::new(),
            PageId::new(),
        );
        let context = execution_context(&proposal);
        let request = approved_request(proposal, PrincipalId::new())?;
        let emergency = EmergencyPolicy::default();
        match reason {
            EmergencyDenyReason::TenantDisabled => {
                emergency.disable_tenant(context.tenant_id.clone())?
            }
            EmergencyDenyReason::SessionDisabled => {
                emergency.disable_session(context.session_id.clone())?
            }
            EmergencyDenyReason::DomainDenied => emergency.deny_domain("example.com")?,
            EmergencyDenyReason::IpDenied => emergency.deny_ip(context.resolved_ips[0])?,
            EmergencyDenyReason::SecretRevoked => emergency.revoke_secret("secret/login")?,
            EmergencyDenyReason::ChromiumBuildKillSwitch => {
                emergency.kill_chromium_build("sha256:known-good")?
            }
            EmergencyDenyReason::ForceDedicatedProcess => {
                emergency.force_dedicated_process(context.tenant_id.clone())?
            }
            EmergencyDenyReason::FeatureKillSwitch => unreachable!(),
        };
        assert_eq!(
            request.authorize_and_dispatch(&emergency, &context, 200, || {}),
            Err(ApprovalError::ApprovalStale(
                StaleApprovalReason::EmergencyDenied(reason)
            ))
        );
    }
    Ok(())
}
