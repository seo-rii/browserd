#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::error::Error;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::sync::atomic::{AtomicUsize, Ordering};

use browserd_core::{
    ActionId, ArtifactId, IsolationProfile, PageId, PrincipalId, SessionId, TenantId, WorkerId,
};
use browserd_policy::{
    ActionApprovalGrant, ActionApprovalOutcome, ActionApprovalPolicy, ActionApprovalPolicyError,
    ActionArgumentsHash, ActionType, ApprovalActionKind, ApprovalArtifactBinding,
    ApprovalContextScope, ApprovalDecision, ApprovalError, ApprovalNodeBinding, ApprovalRequest,
    ApprovalWorkerFence, CanonicalActionProposal, CredentialRefsHash, EmergencyPolicy,
    ExecutionContext, MAX_ACTION_APPROVAL_GRANTS, MAX_ACTION_APPROVAL_POLICY_BYTES, NodeReference,
    Origin, StaleApprovalReason, TypedActionPayload, TypedActionProposalBinding,
};

fn http(value: &str) -> ApprovalContextScope {
    ApprovalContextScope::HttpOrigin {
        origin: value.to_owned(),
    }
}

fn grant(
    tenant: &TenantId,
    principal: &PrincipalId,
    outcome: ActionApprovalOutcome,
) -> ActionApprovalGrant {
    ActionApprovalGrant {
        tenant_id: tenant.clone(),
        principal_id: principal.clone(),
        action: ApprovalActionKind::Click,
        context_scope: http("https://example.test"),
        navigation_destination: None,
        outcome,
        require_four_eyes: true,
    }
}

fn binding(policy: &ActionApprovalPolicy) -> TypedActionProposalBinding {
    TypedActionProposalBinding {
        schema_version: 2,
        action_id: ActionId::new(),
        sequence: 1,
        fence: ApprovalWorkerFence {
            worker_id: WorkerId::new("policy-worker").expect("worker id"),
            worker_epoch: 2,
            placement_version: 3,
            session_incarnation: 4,
        },
        policy_digest: policy.digest(),
        target_binding_sha256: [11; 32],
        context_scope: http("https://example.test"),
        payload: TypedActionPayload::Browser {
            action: ApprovalActionKind::Click,
            arguments_sha256: *ActionArgumentsHash::digest(b"public click command").as_bytes(),
            node: Some(ApprovalNodeBinding {
                node_ref: "opaque-node".to_owned(),
                binding_sha256: [13; 32],
                role: None,
                name: None,
            }),
            navigation_destination: None,
        },
    }
}

fn proposal(
    binding: TypedActionProposalBinding,
    tenant: &TenantId,
    principal: &PrincipalId,
) -> CanonicalActionProposal {
    let origin = match &binding.context_scope {
        ApprovalContextScope::HttpOrigin { origin } => {
            Origin::parse(origin).expect("canonical HTTP")
        }
        ApprovalContextScope::OpaqueDocument => Origin::opaque_document_scope(),
        ApprovalContextScope::BrowserContext => Origin::browser_context_scope(),
    };
    let arguments = match &binding.payload {
        TypedActionPayload::Browser {
            arguments_sha256, ..
        } => ActionArgumentsHash::from_bytes(arguments_sha256).expect("hash"),
        other => ActionArgumentsHash::digest(serde_json::to_vec(other).expect("public metadata")),
    };
    let credentials = match &binding.payload {
        TypedActionPayload::FillSecret { secret_ref, .. } => {
            CredentialRefsHash::digest([secret_ref.as_str()])
        }
        _ => CredentialRefsHash::digest(std::iter::empty::<&str>()),
    };
    CanonicalActionProposal::new(
        tenant.clone(),
        principal.clone(),
        SessionId::new(),
        binding.fence.session_incarnation,
        PageId::new(),
        5,
        6,
        origin,
        7,
        binding.payload.legacy_action_type(),
        arguments,
        binding
            .payload
            .node()
            .map(|node| NodeReference::new(&node.node_ref).expect("node")),
        credentials,
        1000,
    )
    .with_typed_binding(binding)
    .expect("v2 proposal")
}

fn context(proposal: &CanonicalActionProposal) -> ExecutionContext {
    let feature = match proposal.action_type() {
        ActionType::Click => "browser:click",
        ActionType::Fill => "browser:fill",
        ActionType::Navigate => "browser:navigate",
        ActionType::Evaluate => "browser:evaluate",
        ActionType::Upload => "browser:upload",
        ActionType::Download => "browser:download",
        ActionType::Custom(value) => value,
    };
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
        resolved_ips: vec![],
        credential_refs: match &proposal.typed_binding().expect("v2").payload {
            TypedActionPayload::FillSecret { secret_ref, .. } => vec![secret_ref.clone()],
            _ => vec![],
        },
        feature: feature.to_owned(),
        chromium_build: "trusted-build".to_owned(),
        effective_isolation: IsolationProfile::SharedContext,
    }
}

#[test]
fn policy_digest_is_order_independent_and_covers_decisions_and_four_eyes()
-> Result<(), Box<dyn Error>> {
    let tenant = TenantId::new();
    let principal = PrincipalId::new();
    let allow = grant(&tenant, &principal, ActionApprovalOutcome::Allow);
    let deny = grant(&tenant, &principal, ActionApprovalOutcome::Deny);
    let first = ActionApprovalPolicy::new(vec![allow.clone(), deny.clone()])?;
    let second = ActionApprovalPolicy::new(vec![deny, allow.clone()])?;
    assert_eq!(first.digest(), second.digest());
    assert_ne!(
        first.digest(),
        ActionApprovalPolicy::new(vec![allow.clone()])?.digest()
    );
    assert_ne!(
        ActionApprovalPolicy::default().digest(),
        ActionApprovalPolicy::new_with_four_eyes(vec![], false)?.digest()
    );
    let mut no_four_eyes = allow.clone();
    no_four_eyes.require_four_eyes = false;
    assert_ne!(
        ActionApprovalPolicy::new(vec![allow.clone()])?.digest(),
        ActionApprovalPolicy::new(vec![no_four_eyes])?.digest()
    );
    assert_eq!(
        ActionApprovalPolicy::new(vec![allow.clone(), allow]),
        Err(ActionApprovalPolicyError::Rejected)
    );
    Ok(())
}

#[test]
fn exact_tenant_principal_origin_and_destination_rules_never_wildcard() -> Result<(), Box<dyn Error>>
{
    let tenant = TenantId::new();
    let principal = PrincipalId::new();
    let policy = ActionApprovalPolicy::new(vec![grant(
        &tenant,
        &principal,
        ActionApprovalOutcome::Allow,
    )])?;
    assert_eq!(
        policy
            .evaluate(
                &tenant,
                &principal,
                &http("https://example.test"),
                ApprovalActionKind::Click,
                None
            )?
            .outcome,
        ActionApprovalOutcome::Allow
    );
    for (t, p, s) in [
        (
            TenantId::new(),
            principal.clone(),
            http("https://example.test"),
        ),
        (
            tenant.clone(),
            PrincipalId::new(),
            http("https://example.test"),
        ),
        (
            tenant.clone(),
            principal.clone(),
            http("https://example.test:8443"),
        ),
        (
            tenant.clone(),
            principal.clone(),
            http("https://sub.example.test"),
        ),
        (
            tenant.clone(),
            principal.clone(),
            http("http://example.test"),
        ),
    ] {
        assert_eq!(
            policy
                .evaluate(&t, &p, &s, ApprovalActionKind::Click, None)?
                .outcome,
            ActionApprovalOutcome::Manual
        );
    }
    let mut navigation = grant(&tenant, &principal, ActionApprovalOutcome::Allow);
    navigation.action = ApprovalActionKind::Navigate;
    navigation.context_scope = ApprovalContextScope::OpaqueDocument;
    navigation.navigation_destination =
        Some("https://example.test/account?mode=1#submit".to_owned());
    let policy = ActionApprovalPolicy::new(vec![navigation])?;
    assert_eq!(
        policy
            .evaluate(
                &tenant,
                &principal,
                &ApprovalContextScope::OpaqueDocument,
                ApprovalActionKind::Navigate,
                Some("https://example.test/account?mode=1#submit")
            )?
            .outcome,
        ActionApprovalOutcome::Allow
    );
    for destination in [
        "https://example.test/account?mode=2#submit",
        "https://example.test/account?mode=1#other",
        "https://example.test:8443/account?mode=1#submit",
    ] {
        assert_eq!(
            policy
                .evaluate(
                    &tenant,
                    &principal,
                    &ApprovalContextScope::OpaqueDocument,
                    ApprovalActionKind::Navigate,
                    Some(destination)
                )?
                .outcome,
            ActionApprovalOutcome::Manual
        );
    }
    assert!(
        policy
            .evaluate(
                &tenant,
                &principal,
                &ApprovalContextScope::OpaqueDocument,
                ApprovalActionKind::Navigate,
                Some("javascript:alert(1)")
            )
            .is_err()
    );
    let mut wildcard = grant(&tenant, &principal, ActionApprovalOutcome::Allow);
    wildcard.context_scope = http("https://*.example.test");
    assert!(ActionApprovalPolicy::new(vec![wildcard]).is_err());
    Ok(())
}

#[test]
fn deny_and_manual_precedence_and_safe_defaults_are_conservative() -> Result<(), Box<dyn Error>> {
    let t = TenantId::new();
    let p = PrincipalId::new();
    let allow = grant(&t, &p, ActionApprovalOutcome::Allow);
    let manual = grant(&t, &p, ActionApprovalOutcome::Manual);
    let deny = grant(&t, &p, ActionApprovalOutcome::Deny);
    assert_eq!(
        ActionApprovalPolicy::new(vec![allow.clone(), manual.clone()])?
            .evaluate(
                &t,
                &p,
                &http("https://example.test"),
                ApprovalActionKind::Click,
                None
            )?
            .outcome,
        ActionApprovalOutcome::Manual
    );
    for grants in [
        vec![allow.clone(), manual.clone(), deny.clone()],
        vec![deny, manual, allow],
    ] {
        assert_eq!(
            ActionApprovalPolicy::new(grants)?
                .evaluate(
                    &t,
                    &p,
                    &http("https://example.test"),
                    ApprovalActionKind::Click,
                    None
                )?
                .outcome,
            ActionApprovalOutcome::Deny
        );
    }
    let policy = ActionApprovalPolicy::default();
    for action in [
        ApprovalActionKind::Click,
        ApprovalActionKind::Fill,
        ApprovalActionKind::FillSecret,
        ApprovalActionKind::SetFiles,
        ApprovalActionKind::Evaluate,
    ] {
        let decision = policy.evaluate(&t, &p, &http("https://example.test"), action, None)?;
        assert_eq!(decision.outcome, ActionApprovalOutcome::Manual);
        assert!(decision.require_four_eyes);
    }
    assert_eq!(
        policy
            .evaluate(
                &t,
                &p,
                &ApprovalContextScope::OpaqueDocument,
                ApprovalActionKind::GetUrl,
                None
            )?
            .outcome,
        ActionApprovalOutcome::Allow
    );
    assert_eq!(
        policy
            .evaluate(
                &t,
                &p,
                &ApprovalContextScope::BrowserContext,
                ApprovalActionKind::Checkpoint,
                None
            )?
            .outcome,
        ActionApprovalOutcome::Manual
    );
    assert!(
        policy
            .evaluate(
                &t,
                &p,
                &ApprovalContextScope::OpaqueDocument,
                ApprovalActionKind::FillSecret,
                None
            )
            .is_err()
    );
    assert!(
        policy
            .evaluate(
                &t,
                &p,
                &ApprovalContextScope::BrowserContext,
                ApprovalActionKind::Evaluate,
                None
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn strict_schema_and_bounded_config_reject_ambiguous_authority() {
    for value in [
        serde_json::json!({"schema_version":2,"grants":[]}),
        serde_json::json!({"schema_version":1,"grants":[],"wildcard":true}),
        serde_json::json!({"schema_version":1,"grants":null}),
    ] {
        assert_eq!(
            ActionApprovalPolicy::from_bytes(&serde_json::to_vec(&value).unwrap()),
            Err(ActionApprovalPolicyError::Rejected)
        );
    }
    let t = TenantId::new();
    let p = PrincipalId::new();
    let mut value = serde_json::to_value(grant(&t, &p, ActionApprovalOutcome::Allow)).unwrap();
    value["tenant_id"] = serde_json::json!("00000000-0000-0000-0000-000000000000");
    assert!(
        ActionApprovalPolicy::from_bytes(
            &serde_json::to_vec(&serde_json::json!({"schema_version":1,"grants":[value]})).unwrap()
        )
        .is_err()
    );
    assert!(
        ActionApprovalPolicy::new(vec![
            grant(&t, &p, ActionApprovalOutcome::Allow);
            MAX_ACTION_APPROVAL_GRANTS + 1
        ])
        .is_err()
    );
    assert!(
        ActionApprovalPolicy::from_bytes(&vec![b' '; MAX_ACTION_APPROVAL_POLICY_BYTES + 1])
            .is_err()
    );
    let mut bad = serde_json::to_value(binding(&ActionApprovalPolicy::default())).unwrap();
    bad["raw_expression"] = serde_json::json!("should not be accepted");
    assert!(serde_json::from_value::<TypedActionProposalBinding>(bad).is_err());
}

#[test]
fn private_loader_rejects_mode_links_fifo_and_relative_paths() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700))?;
    let path = dir.path().join("policy.json");
    fs::write(&path, b"{\"schema_version\":1,\"grants\":[]}")?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    assert_eq!(
        ActionApprovalPolicy::open(&path)?.digest(),
        ActionApprovalPolicy::default().digest()
    );
    assert!(ActionApprovalPolicy::open(std::path::Path::new("relative.json")).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o640))?;
    assert!(ActionApprovalPolicy::open(&path).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    let linked = dir.path().join("linked");
    fs::hard_link(&path, &linked)?;
    assert!(ActionApprovalPolicy::open(&path).is_err());
    fs::remove_file(linked)?;
    let symlinked = dir.path().join("symbolic");
    symlink(&path, &symlinked)?;
    assert!(ActionApprovalPolicy::open(&symlinked).is_err());
    let fifo = dir.path().join("fifo");
    nix::unistd::mkfifo(
        &fifo,
        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
    )?;
    assert!(ActionApprovalPolicy::open(&fifo).is_err());
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o750))?;
    assert!(ActionApprovalPolicy::open(&path).is_err());
    Ok(())
}

#[test]
fn v2_hash_binds_action_sequence_every_fence_policy_and_trusted_target() {
    let policy = ActionApprovalPolicy::default();
    let b = binding(&policy);
    let t = TenantId::new();
    let p = PrincipalId::new();
    let original = proposal(b.clone(), &t, &p);
    let hash = original.hash();
    let mut variants = vec![];
    let mut changed = b.clone();
    changed.action_id = ActionId::new();
    variants.push(changed);
    let mut changed = b.clone();
    changed.sequence += 1;
    variants.push(changed);
    let mut changed = b.clone();
    changed.fence.worker_id = WorkerId::new("replacement-policy-worker").expect("worker id");
    variants.push(changed);
    let mut changed = b.clone();
    changed.fence.worker_epoch += 1;
    variants.push(changed);
    let mut changed = b.clone();
    changed.fence.placement_version += 1;
    variants.push(changed);
    let mut changed = b.clone();
    changed.policy_digest = [99; 32];
    variants.push(changed);
    let mut changed = b.clone();
    changed.target_binding_sha256 = [99; 32];
    variants.push(changed);
    let mut changed = b.clone();
    if let TypedActionPayload::Browser {
        node: Some(node), ..
    } = &mut changed.payload
    {
        node.binding_sha256 = [99; 32];
    }
    variants.push(changed);
    for changed in variants {
        assert_ne!(
            original.clone().with_typed_binding(changed).unwrap().hash(),
            hash
        );
    }
    let mut changed_incarnation = b.clone();
    changed_incarnation.fence.session_incarnation += 1;
    assert_ne!(
        original
            .clone()
            .with_session_incarnation(changed_incarnation.fence.session_incarnation)
            .with_typed_binding(changed_incarnation)
            .unwrap()
            .hash(),
        hash
    );
    assert_eq!(original.schema_version(), 2);
    let text = serde_json::to_string(&b).unwrap();
    assert!(!text.contains("public click command"));
    let mut invalid = b.clone();
    invalid.sequence = 0;
    assert!(invalid.validate().is_err());
    let mut invalid = b;
    invalid.fence.worker_epoch = 0;
    assert!(invalid.validate().is_err());
}

#[test]
fn secret_file_and_checkpoint_bindings_preserve_exact_ordered_metadata() {
    let policy = ActionApprovalPolicy::default();
    let t = TenantId::new();
    let p = PrincipalId::new();
    let mut b = binding(&policy);
    let node = b.payload.node().unwrap().clone();
    b.payload = TypedActionPayload::FillSecret {
        node: node.clone(),
        secret_ref: "credential/ref-only".to_owned(),
        grant_metadata_sha256: [17; 32],
    };
    let original = proposal(b.clone(), &t, &p);
    let mut changed = b.clone();
    if let TypedActionPayload::FillSecret {
        grant_metadata_sha256,
        ..
    } = &mut changed.payload
    {
        *grant_metadata_sha256 = [18; 32];
    }
    assert_ne!(
        original.clone().with_typed_binding(changed).unwrap().hash(),
        original.hash()
    );
    b.payload = TypedActionPayload::SetFiles {
        node,
        files: vec![
            ApprovalArtifactBinding {
                artifact_id: ArtifactId::new(),
                object_generation: [1; 32],
                size_bytes: 40,
                checksum_sha256: [2; 32],
                effective_filename: "scan.txt".to_owned(),
                publication_sha256: [3; 32],
                scan_evidence_sha256: Some([4; 32]),
            },
            ApprovalArtifactBinding {
                artifact_id: ArtifactId::new(),
                object_generation: [5; 32],
                size_bytes: 60,
                checksum_sha256: [6; 32],
                effective_filename: "generated.txt".to_owned(),
                publication_sha256: [7; 32],
                scan_evidence_sha256: None,
            },
        ],
    };
    let original = proposal(b.clone(), &t, &p);
    let mut changed = b.clone();
    if let TypedActionPayload::SetFiles { files, .. } = &mut changed.payload {
        files.reverse();
    }
    assert_ne!(
        original.clone().with_typed_binding(changed).unwrap().hash(),
        original.hash()
    );
    let mut changed = b.clone();
    if let TypedActionPayload::SetFiles { files, .. } = &mut changed.payload {
        files[0].effective_filename = "renamed.txt".to_owned();
    }
    assert_ne!(
        original.clone().with_typed_binding(changed).unwrap().hash(),
        original.hash()
    );
    for field in 0..6 {
        let mut changed = b.clone();
        if let TypedActionPayload::SetFiles { files, .. } = &mut changed.payload {
            match field {
                0 => files[0].artifact_id = ArtifactId::new(),
                1 => files[0].object_generation = [9; 32],
                2 => files[0].size_bytes += 1,
                3 => files[0].checksum_sha256 = [9; 32],
                4 => files[0].publication_sha256 = [9; 32],
                _ => files[0].scan_evidence_sha256 = Some([9; 32]),
            }
        }
        assert_ne!(
            original.clone().with_typed_binding(changed).unwrap().hash(),
            original.hash()
        );
    }
    b.context_scope = ApprovalContextScope::BrowserContext;
    b.payload = TypedActionPayload::Checkpoint {
        origins: vec!["https://a.test".to_owned(), "https://b.test".to_owned()],
        build_identity_sha256: [23; 32],
    };
    let original = proposal(b.clone(), &t, &p);
    assert!(original.current_origin().is_browser_context_scope());
    assert!(Origin::parse(original.current_origin().as_str()).is_err());
    let mut changed = b.clone();
    if let TypedActionPayload::Checkpoint { origins, .. } = &mut changed.payload {
        origins.reverse();
    }
    assert_ne!(
        original.clone().with_typed_binding(changed).unwrap().hash(),
        original.hash()
    );
    b.payload = TypedActionPayload::Checkpoint {
        origins: vec![],
        build_identity_sha256: [23; 32],
    };
    assert!(b.validate().is_ok());
    b.context_scope = ApprovalContextScope::OpaqueDocument;
    assert!(b.validate().is_err());
}

#[test]
fn typed_consume_requires_fresh_binding_policy_and_one_shot_approval() -> Result<(), Box<dyn Error>>
{
    let policy = ActionApprovalPolicy::default();
    let b = binding(&policy);
    let proposal = proposal(b.clone(), &TenantId::new(), &PrincipalId::new());
    let ctx = context(&proposal);
    let request = ApprovalRequest::new(proposal, true);
    request.decide(PrincipalId::new(), ApprovalDecision::Approve, 100)?;
    let calls = AtomicUsize::new(0);
    let emergency = EmergencyPolicy::default();
    assert!(
        request
            .authorize_typed_and_dispatch_with_clock(
                &emergency,
                &ctx,
                &b,
                &policy,
                || Ok::<_, ()>(200),
                || {
                    calls.fetch_add(1, Ordering::SeqCst);
                }
            )
            .is_ok()
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(
        request
            .authorize_typed_and_dispatch_with_clock(
                &emergency,
                &ctx,
                &b,
                &policy,
                || Ok::<_, ()>(201),
                || {
                    calls.fetch_add(1, Ordering::SeqCst);
                }
            )
            .is_err()
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn typed_stale_and_legacy_api_cannot_dispatch_v2_and_policy_four_eyes_cannot_downgrade()
-> Result<(), Box<dyn Error>> {
    let policy = ActionApprovalPolicy::default();
    let b = binding(&policy);
    for scenario in 0..4 {
        let proposal = proposal(b.clone(), &TenantId::new(), &PrincipalId::new());
        let ctx = context(&proposal);
        let request = ApprovalRequest::new(proposal, scenario != 2);
        request.decide(PrincipalId::new(), ApprovalDecision::Approve, 100)?;
        let mut observed = b.clone();
        if scenario == 0 {
            observed.target_binding_sha256 = [99; 32];
        }
        let replacement = ActionApprovalPolicy::new_with_four_eyes(vec![], false)?;
        let calls = AtomicUsize::new(0);
        let emergency = EmergencyPolicy::default();
        if scenario == 3 {
            assert_eq!(
                request.authorize_and_dispatch(&emergency, &ctx, 200, || {
                    calls.fetch_add(1, Ordering::SeqCst);
                }),
                Err(ApprovalError::ApprovalStale(
                    StaleApprovalReason::ActionBinding
                ))
            );
        } else {
            assert!(
                request
                    .authorize_typed_and_dispatch_with_clock(
                        &emergency,
                        &ctx,
                        &observed,
                        if scenario == 1 { &replacement } else { &policy },
                        || Ok::<_, ()>(200),
                        || {
                            calls.fetch_add(1, Ordering::SeqCst);
                        }
                    )
                    .is_err()
            );
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
    Ok(())
}

#[test]
fn approved_token_never_overrides_deny_or_emergency_secret_revoke() -> Result<(), Box<dyn Error>> {
    let tenant = TenantId::new();
    let principal = PrincipalId::new();
    let policy = ActionApprovalPolicy::new(vec![grant(
        &tenant,
        &principal,
        ActionApprovalOutcome::Deny,
    )])?;
    let b = binding(&policy);
    let canonical = proposal(b.clone(), &tenant, &principal);
    let ctx = context(&canonical);
    let request = ApprovalRequest::new(canonical, true);
    request.decide(PrincipalId::new(), ApprovalDecision::Approve, 100)?;
    let calls = AtomicUsize::new(0);
    let emergency = EmergencyPolicy::default();
    assert!(
        request
            .authorize_typed_and_dispatch_with_clock(
                &emergency,
                &ctx,
                &b,
                &policy,
                || Ok::<_, ()>(200),
                || {
                    calls.fetch_add(1, Ordering::SeqCst);
                }
            )
            .is_err()
    );
    let policy = ActionApprovalPolicy::default();
    let mut b = binding(&policy);
    b.payload = TypedActionPayload::FillSecret {
        node: b.payload.node().unwrap().clone(),
        secret_ref: "revoked/ref".to_owned(),
        grant_metadata_sha256: [19; 32],
    };
    let canonical = proposal(b.clone(), &tenant, &principal);
    let ctx = context(&canonical);
    let request = ApprovalRequest::new(canonical, true);
    request.decide(PrincipalId::new(), ApprovalDecision::Approve, 100)?;
    emergency.revoke_secret("revoked/ref")?;
    assert!(
        request
            .authorize_typed_and_dispatch_with_clock(
                &emergency,
                &ctx,
                &b,
                &policy,
                || Ok::<_, ()>(200),
                || {
                    calls.fetch_add(1, Ordering::SeqCst);
                }
            )
            .is_err()
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn max_ordered_file_bindings_and_untrusted_display_hints_are_bounded() {
    let policy = ActionApprovalPolicy::default();
    let mut b = binding(&policy);
    let mut node = b.payload.node().unwrap().clone();
    node.role = Some("button".to_owned());
    node.name = Some("untrusted title".to_owned());
    b.payload = TypedActionPayload::SetFiles {
        node,
        files: (0..128)
            .map(|_| ApprovalArtifactBinding {
                artifact_id: ArtifactId::new(),
                object_generation: [255; 32],
                size_bytes: u64::MAX,
                checksum_sha256: [255; 32],
                effective_filename: "\"".repeat(255),
                publication_sha256: [255; 32],
                scan_evidence_sha256: Some([255; 32]),
            })
            .collect(),
    };
    assert!(b.validate().is_ok());
    assert!(serde_json::to_vec(&b).unwrap().len() > 64 * 1024);
    let mut oversized = b.clone();
    if let TypedActionPayload::SetFiles { files, .. } = &mut oversized.payload {
        files[0].effective_filename = "x".repeat(300 * 1024);
    }
    assert!(oversized.validate().is_err());
    let mut excessive = b.clone();
    if let TypedActionPayload::SetFiles { files, .. } = &mut excessive.payload {
        let mut extra = files[0].clone();
        extra.artifact_id = ArtifactId::new();
        files.push(extra);
    }
    assert!(excessive.validate().is_err());
    for hint in ["x".repeat(257), "untrusted\ncontrol".to_owned()] {
        let mut invalid = b.clone();
        if let TypedActionPayload::SetFiles { node, .. } = &mut invalid.payload {
            node.name = Some(hint);
        }
        assert!(invalid.validate().is_err());
    }
    let original = proposal(b.clone(), &TenantId::new(), &PrincipalId::new());
    if let TypedActionPayload::SetFiles { node, .. } = &mut b.payload {
        node.name = Some("changed untrusted title".to_owned());
    }
    assert_ne!(
        original.clone().with_typed_binding(b).unwrap().hash(),
        original.hash()
    );
}
