#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::error::Error;

use browserd_api::{
    ActionPayload, ActionSubmitCommand, ActionSubmitRequest, ApiRequest, ApprovalCatalog,
    ApprovalDecisionBody, ApprovalDecisionRequest, ApprovalListQuery, ApprovalResource,
    ApprovalStateFilter, ArtifactUploadBody, ArtifactUploadRequest, PUBLIC_ROUTES,
    PageActivateRequest, PageCreateBody, PageCreateRequest, PageListRequest, SessionCatalog,
    SessionListQuery, SessionResource, ViewerScopeRequest, ViewerTicketBody, WaitCondition,
    WaitUntil, decode_approval_decision, decode_artifact_upload, decode_page_create,
    decode_session_create, public_approval_id,
};
use browserd_auth::{
    AuthConfig, AuthenticatedPrincipal, RevocationRegistry, ServiceClaims, ServiceTokenSigner,
    ServiceTokenVerifier, VerificationKeySet,
};
use browserd_core::{
    ArtifactId, IsolationProfile, PageId, PrincipalId, SessionId, SessionLifecycle, TenantId,
};
use browserd_policy::{
    ActionArgumentsHash, ActionType, ApprovalState, CanonicalActionProposal, CredentialRefsHash,
    Origin,
};
use jsonwebtoken::Algorithm;
use uuid::Uuid;

fn principal_with_scopes(
    tenant_id: TenantId,
    scopes: &[&str],
) -> Result<AuthenticatedPrincipal, Box<dyn Error>> {
    let secret = b"browserd-api-extended-scope-test";
    let mut keys = VerificationKeySet::new();
    keys.insert_hmac("test", Algorithm::HS256, secret)?;
    let verifier = ServiceTokenVerifier::new(
        AuthConfig::new("issuer", "audience", [Algorithm::HS256], 0, false),
        keys,
        RevocationRegistry::new(),
    );
    let claims = ServiceClaims::new(
        "issuer",
        "audience",
        PrincipalId::new(),
        tenant_id,
        scopes
            .iter()
            .map(|scope| (*scope).to_owned())
            .collect::<BTreeSet<_>>(),
        Uuid::new_v4().to_string(),
        1,
        100,
        None,
    );
    let token = ServiceTokenSigner::new("test", Algorithm::HS256, secret).sign(&claims)?;
    Ok(verifier.verify_at(&token, None, 10)?)
}

#[test]
fn required_extended_v1_routes_are_manifested() {
    let routes = PUBLIC_ROUTES.iter().copied().collect::<HashSet<_>>();
    for route in [
        "GET /v1/sessions",
        "GET /v1/sessions/{session_id}/pages",
        "POST /v1/sessions/{session_id}/pages",
        "DELETE /v1/sessions/{session_id}/pages/{page_id}",
        "POST /v1/sessions/{session_id}/pages/{page_id}/activate",
        "POST /v1/sessions/{session_id}/artifacts/uploads",
        "GET /v1/approvals",
        "GET /v1/approvals/{approval_id}",
        "POST /v1/approvals/{approval_id}/decision",
    ] {
        assert!(routes.contains(route), "missing route {route}");
    }
}

#[test]
fn session_metadata_has_count_key_value_and_aggregate_byte_bounds() {
    let base =
        serde_json::from_str::<serde_json::Value>(include_str!("session_create_fixture.json"))
            .expect("fixture is JSON");

    let mut too_many = base.clone();
    too_many["metadata"] = serde_json::Value::Object(
        (0..33)
            .map(|index| {
                (
                    format!("key-{index}"),
                    serde_json::Value::String("v".to_owned()),
                )
            })
            .collect(),
    );
    assert!(decode_session_create(&too_many.to_string()).is_err());

    let mut long_key = base.clone();
    long_key["metadata"] = serde_json::json!({"k".repeat(65): "v"});
    assert!(decode_session_create(&long_key.to_string()).is_err());

    let mut long_value = base.clone();
    long_value["metadata"] = serde_json::json!({"key": "v".repeat(257)});
    assert!(decode_session_create(&long_value.to_string()).is_err());

    let mut aggregate = base;
    aggregate["metadata"] = serde_json::Value::Object(
        (0..17)
            .map(|index| {
                (
                    format!("key-{index:02}"),
                    serde_json::Value::String("v".repeat(250)),
                )
            })
            .collect(),
    );
    assert!(decode_session_create(&aggregate.to_string()).is_err());
}

#[test]
fn session_create_strings_and_viewport_area_are_bounded() {
    let base =
        serde_json::from_str::<serde_json::Value>(include_str!("session_create_fixture.json"))
            .expect("fixture is JSON");
    for (field, value) in [
        ("workload_class_hint", "w".repeat(129)),
        ("locale", "l".repeat(65)),
        ("timezone", "t".repeat(129)),
        ("user_agent", "u".repeat(4_097)),
        ("network_policy_id", "p".repeat(257)),
        ("network_class", "n".repeat(65)),
        ("checkpoint_ref", "c".repeat(1_025)),
        ("feature_profile", "f".repeat(129)),
    ] {
        let mut request = base.clone();
        request[field] = serde_json::Value::String(value);
        assert!(
            decode_session_create(&request.to_string()).is_err(),
            "{field}"
        );
    }
    let mut request = base;
    request["viewport"]["width"] = 5_000.into();
    request["viewport"]["height"] = 5_000.into();
    assert!(decode_session_create(&request.to_string()).is_err());
}

#[test]
fn action_variants_enforce_field_cardinality_numeric_and_total_body_bounds() {
    let request = |action| ActionSubmitRequest {
        page_id: PageId::new(),
        if_session_incarnation: 1,
        execution_timeout_ms: 30_000,
        action,
    };
    let oversized_node = "n".repeat(1_025);
    for action in [
        ActionPayload::Click {
            node_ref: oversized_node.clone(),
        },
        ActionPayload::DoubleClick {
            node_ref: oversized_node.clone(),
        },
        ActionPayload::Hover {
            node_ref: oversized_node.clone(),
        },
        ActionPayload::Focus {
            node_ref: oversized_node.clone(),
        },
        ActionPayload::Blur {
            node_ref: oversized_node.clone(),
        },
        ActionPayload::Check {
            node_ref: oversized_node.clone(),
        },
        ActionPayload::Uncheck {
            node_ref: oversized_node.clone(),
        },
        ActionPayload::GetText {
            node_ref: oversized_node.clone(),
        },
        ActionPayload::GetHtml {
            node_ref: Some(oversized_node.clone()),
        },
        ActionPayload::GetProperties {
            node_ref: oversized_node.clone(),
        },
        ActionPayload::GetComputedStyle {
            node_ref: oversized_node.clone(),
        },
        ActionPayload::ExtractTable {
            node_ref: oversized_node.clone(),
        },
    ] {
        assert!(request(action).validate().is_err());
    }
    for action in [
        ActionPayload::Navigate {
            url: format!("https://example.com/{}", "x".repeat(8_193)),
            wait_until: WaitUntil::Load,
        },
        ActionPayload::Fill {
            node_ref: "node".to_owned(),
            value: "v".repeat(65_537),
        },
        ActionPayload::FillSecret {
            node_ref: "node".to_owned(),
            secret_ref: "s".repeat(1_025),
        },
        ActionPayload::TypeText {
            text: "t".repeat(65_537),
        },
        ActionPayload::PressKey {
            key: "k".repeat(257),
        },
        ActionPayload::Scroll {
            delta_x: 1_000_001,
            delta_y: 0,
        },
        ActionPayload::SelectOption {
            node_ref: "node".to_owned(),
            values: (0..129).map(|index| index.to_string()).collect(),
        },
        ActionPayload::SetFiles {
            node_ref: "node".to_owned(),
            artifact_ids: (0..129).map(|_| ArtifactId::new()).collect(),
        },
        ActionPayload::HandleDialog {
            accept: true,
            prompt_text: Some("p".repeat(65_537)),
        },
        ActionPayload::GetAttribute {
            node_ref: "node".to_owned(),
            name: "a".repeat(257),
        },
        ActionPayload::QueryAll {
            selector: "s".repeat(8_193),
        },
        ActionPayload::NewPage {
            url: Some(format!("https://example.com/{}", "x".repeat(8_193))),
        },
        ActionPayload::WaitFor {
            condition: WaitCondition::SelectorAttached {
                selector: "s".repeat(8_193),
            },
        },
        ActionPayload::WaitFor {
            condition: WaitCondition::SelectorVisible {
                selector: "s".repeat(8_193),
            },
        },
        ActionPayload::WaitFor {
            condition: WaitCondition::SelectorHidden {
                selector: "s".repeat(8_193),
            },
        },
        ActionPayload::WaitFor {
            condition: WaitCondition::UrlMatches {
                pattern: "p".repeat(8_193),
            },
        },
        ActionPayload::WaitFor {
            condition: WaitCondition::NetworkQuiet { quiet_ms: 30_001 },
        },
        ActionPayload::Evaluate {
            expression: "e".repeat(65_537),
        },
    ] {
        assert!(request(action).validate().is_err());
    }
    assert!(
        request(ActionPayload::SelectOption {
            node_ref: "node".to_owned(),
            values: (0..128).map(|_| "v".repeat(1_100)).collect(),
        })
        .validate()
        .is_err()
    );
    assert!(
        request(ActionPayload::SelectOption {
            node_ref: "node".to_owned(),
            values: Vec::new(),
        })
        .validate()
        .is_err()
    );
}

#[test]
fn privileged_actions_require_base_and_conditional_scopes() -> Result<(), Box<dyn Error>> {
    let tenant = TenantId::new();
    let command = |action| {
        ApiRequest::SubmitAction(ActionSubmitCommand {
            session_id: SessionId::new(),
            idempotency_key: Uuid::new_v4(),
            body: ActionSubmitRequest {
                page_id: PageId::new(),
                if_session_incarnation: 1,
                execution_timeout_ms: 30_000,
                action,
            },
        })
    };
    let base = principal_with_scopes(tenant.clone(), &["browser:act"])?;
    assert!(
        command(ActionPayload::Evaluate {
            expression: "1 + 1".to_owned(),
        })
        .authorize(&base)
        .is_err()
    );
    assert!(
        command(ActionPayload::FillSecret {
            node_ref: "node".to_owned(),
            secret_ref: "secret".to_owned(),
        })
        .authorize(&base)
        .is_err()
    );
    assert!(command(ActionPayload::Checkpoint).authorize(&base).is_err());
    assert!(
        command(ActionPayload::SetFiles {
            node_ref: "node".to_owned(),
            artifact_ids: vec![ArtifactId::new()],
        })
        .authorize(&base)
        .is_err()
    );

    for (scope, action) in [
        (
            "browser:evaluate",
            ActionPayload::Evaluate {
                expression: "1 + 1".to_owned(),
            },
        ),
        (
            "secret:use",
            ActionPayload::FillSecret {
                node_ref: "node".to_owned(),
                secret_ref: "secret".to_owned(),
            },
        ),
        ("checkpoint:create", ActionPayload::Checkpoint),
        (
            "artifact:read",
            ActionPayload::SetFiles {
                node_ref: "node".to_owned(),
                artifact_ids: vec![ArtifactId::new()],
            },
        ),
    ] {
        let conditional_only = principal_with_scopes(tenant.clone(), &[scope])?;
        assert!(
            command(action.clone())
                .authorize(&conditional_only)
                .is_err()
        );
        let authorized = principal_with_scopes(tenant.clone(), &["browser:act", scope])?;
        assert!(command(action).authorize(&authorized).is_ok());
    }
    Ok(())
}

#[test]
fn viewer_admin_scope_requires_control_scope() -> Result<(), Box<dyn Error>> {
    let body = ViewerTicketBody {
        scopes: ViewerScopeRequest {
            read: true,
            control: false,
            admin: true,
        },
        ttl_seconds: 30,
    };
    assert!(body.into_request(SessionId::new(), 1).is_err());
    let valid = ViewerTicketBody {
        scopes: ViewerScopeRequest {
            read: true,
            control: true,
            admin: true,
        },
        ttl_seconds: 30,
    }
    .into_request(SessionId::new(), 1)?;
    let principal = principal_with_scopes(
        TenantId::new(),
        &["viewer:read", "viewer:control", "admin:force-control"],
    )?;
    assert!(
        ApiRequest::IssueViewerTicket(valid)
            .authorize(&principal)
            .is_ok()
    );
    Ok(())
}

#[test]
fn session_catalog_pagination_is_deterministic_tenant_scoped_and_filter_bound()
-> Result<(), Box<dyn Error>> {
    let catalog = SessionCatalog::default();
    let tenant_a = TenantId::new();
    let tenant_b = TenantId::new();
    let session_resource = |metadata| SessionResource {
        id: SessionId::new(),
        lifecycle: SessionLifecycle::Ready,
        incarnation: 1,
        requested_isolation: IsolationProfile::SharedContext,
        effective_isolation: IsolationProfile::SharedContext,
        metadata,
    };
    let mut expected = Vec::new();
    for index in 0..3 {
        let mut metadata = BTreeMap::new();
        metadata.insert("group".to_owned(), "a".to_owned());
        metadata.insert(format!("item-{index}"), "present".to_owned());
        let resource = session_resource(metadata);
        expected.push(resource.id.clone());
        catalog.upsert(tenant_a.clone(), resource)?;
    }
    catalog.upsert(tenant_b.clone(), session_resource(BTreeMap::new()))?;
    expected.sort();

    let first = catalog.list(
        &tenant_a,
        &SessionListQuery {
            lifecycle: Some(SessionLifecycle::Ready),
            isolation: Some(IsolationProfile::SharedContext),
            metadata_key: Some("group".to_owned()),
            limit: 2,
            page_token: None,
        },
    )?;
    assert_eq!(
        first
            .items()
            .iter()
            .map(|session| session.id.clone())
            .collect::<Vec<_>>(),
        expected[..2]
    );
    let token = first
        .next_page_token()
        .ok_or("missing page token")?
        .to_owned();
    assert!(!token.contains(&expected[1].to_string()));
    let mut late_metadata = BTreeMap::new();
    late_metadata.insert("group".to_owned(), "a".to_owned());
    catalog.upsert(tenant_a.clone(), session_resource(late_metadata))?;

    let second = catalog.list(
        &tenant_a,
        &SessionListQuery {
            lifecycle: Some(SessionLifecycle::Ready),
            isolation: Some(IsolationProfile::SharedContext),
            metadata_key: Some("group".to_owned()),
            limit: 2,
            page_token: Some(token.clone()),
        },
    )?;
    assert_eq!(
        second
            .items()
            .iter()
            .map(|session| session.id.clone())
            .collect::<Vec<_>>(),
        expected[2..]
    );
    assert!(second.next_page_token().is_none());
    assert!(
        catalog
            .list(
                &tenant_b,
                &SessionListQuery {
                    lifecycle: None,
                    isolation: None,
                    metadata_key: Some("group".to_owned()),
                    limit: 50,
                    page_token: None,
                },
            )?
            .items()
            .is_empty()
    );
    assert!(
        catalog
            .list(
                &tenant_a,
                &SessionListQuery {
                    lifecycle: Some(SessionLifecycle::Ready),
                    isolation: None,
                    metadata_key: Some("different".to_owned()),
                    limit: 2,
                    page_token: Some(token),
                },
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn approval_catalog_pagination_is_deterministic_tenant_scoped_and_filter_bound()
-> Result<(), Box<dyn Error>> {
    let catalog = ApprovalCatalog::default();
    let tenant_a = TenantId::new();
    let tenant_b = TenantId::new();
    let session_id = SessionId::new();
    let resource =
        |tenant_id: TenantId, session_id: SessionId| -> Result<ApprovalResource, Box<dyn Error>> {
            Ok(ApprovalResource {
                approval_id: Uuid::now_v7(),
                tenant_id: tenant_id.clone(),
                session_id: session_id.clone(),
                action_id: browserd_core::ActionId::new(),
                state: ApprovalState::Pending,
                proposal: CanonicalActionProposal::new(
                    tenant_id,
                    PrincipalId::new(),
                    session_id,
                    1,
                    PageId::new(),
                    1,
                    1,
                    Origin::parse("https://example.com")?,
                    1,
                    ActionType::Click,
                    ActionArgumentsHash::digest(b"{}"),
                    None,
                    CredentialRefsHash::digest([]),
                    u64::MAX,
                ),
            })
        };
    let mut expected = Vec::new();
    for _ in 0..3 {
        let approval = resource(tenant_a.clone(), session_id.clone())?;
        expected.push(approval.approval_id);
        catalog.upsert(approval)?;
    }
    catalog.upsert(resource(tenant_b, session_id.clone())?)?;
    expected.sort();
    assert_eq!(
        catalog.get(&tenant_a, expected[0])?.approval_id,
        expected[0]
    );
    assert!(catalog.get(&TenantId::new(), expected[0]).is_err());

    let first = catalog.list(
        &tenant_a,
        &ApprovalListQuery {
            state: Some(ApprovalStateFilter::Pending),
            session_id: Some(session_id.clone()),
            limit: 2,
            page_token: None,
        },
    )?;
    assert_eq!(
        first
            .items()
            .iter()
            .map(|item| item.approval_id)
            .collect::<Vec<_>>(),
        expected[..2]
    );
    let token = first.next_page_token().ok_or("missing token")?.to_owned();
    let second = catalog.list(
        &tenant_a,
        &ApprovalListQuery {
            state: Some(ApprovalStateFilter::Pending),
            session_id: Some(session_id),
            limit: 2,
            page_token: Some(token.clone()),
        },
    )?;
    assert_eq!(
        second
            .items()
            .iter()
            .map(|item| item.approval_id)
            .collect::<Vec<_>>(),
        expected[2..]
    );
    assert!(
        catalog
            .list(
                &tenant_a,
                &ApprovalListQuery {
                    state: Some(ApprovalStateFilter::Denied),
                    session_id: None,
                    limit: 2,
                    page_token: Some(token),
                },
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn page_upload_and_approval_bodies_are_strict_and_bounded() {
    assert!(decode_page_create(r#"{"url":"https://example.com"}"#).is_ok());
    assert!(decode_page_create(r#"{"url":"https://example.com","popup":true}"#).is_err());
    assert!(
        decode_page_create(&format!(
            r#"{{"url":"https://example.com/{}"}}"#,
            "x".repeat(4096)
        ))
        .is_err()
    );

    assert!(decode_artifact_upload(
        r#"{"display_filename":"input.txt","declared_content_type":"text/plain","expected_size_bytes":32}"#
    )
    .is_ok());
    assert!(decode_artifact_upload(
        r#"{"display_filename":"input.txt","declared_content_type":"text/plain","expected_size_bytes":0}"#
    )
    .is_err());
    assert!(decode_artifact_upload(
        r#"{"display_filename":"input.txt","declared_content_type":"text/plain","expected_size_bytes":32,"local_path":"/tmp/input"}"#
    )
    .is_err());

    assert!(decode_approval_decision(r#"{"decision":"approve","reason":"verified"}"#).is_ok());
    assert!(decode_approval_decision(r#"{"decision":"approve","reason":""}"#).is_err());
    assert!(
        decode_approval_decision(
            r#"{"decision":"approve","reason":"verified","token":"forbidden"}"#
        )
        .is_err()
    );
}

#[test]
fn extended_requests_apply_endpoint_specific_scopes() -> Result<(), Box<dyn Error>> {
    let tenant = TenantId::new();
    let session_reader = principal_with_scopes(tenant.clone(), &["session:read"])?;
    assert!(
        ApiRequest::ListSessions(SessionListQuery::default())
            .authorize(&session_reader)
            .is_ok()
    );
    assert!(
        ApiRequest::ListPages(PageListRequest {
            session_id: SessionId::new()
        })
        .authorize(&session_reader)
        .is_ok()
    );
    assert!(
        ApiRequest::CreatePage(PageCreateRequest {
            session_id: SessionId::new(),
            body: PageCreateBody { url: None },
        })
        .authorize(&session_reader)
        .is_err()
    );

    let artifact_reader = principal_with_scopes(tenant.clone(), &["artifact:read"])?;
    assert!(
        ApiRequest::UploadArtifact(ArtifactUploadRequest {
            session_id: SessionId::new(),
            body: ArtifactUploadBody {
                display_filename: "input.txt".to_owned(),
                declared_content_type: Some("text/plain".to_owned()),
                expected_size_bytes: 32,
            },
        })
        .authorize(&artifact_reader)
        .is_err()
    );

    let approval_reader = principal_with_scopes(tenant, &["approval:read"])?;
    assert!(
        ApiRequest::ListApprovals(ApprovalListQuery {
            state: Some(ApprovalStateFilter::Pending),
            session_id: None,
            limit: 50,
            page_token: None,
        })
        .authorize(&approval_reader)
        .is_ok()
    );
    assert!(
        ApiRequest::DecideApproval {
            approval_id: Uuid::now_v7(),
            body: ApprovalDecisionBody {
                decision: ApprovalDecisionRequest::Approve,
                reason: "verified".to_owned(),
            },
        }
        .authorize(&approval_reader)
        .is_err()
    );

    let browser_actor = principal_with_scopes(TenantId::new(), &["browser:act"])?;
    assert!(
        ApiRequest::ActivatePage(PageActivateRequest {
            session_id: SessionId::new(),
            page_id: PageId::new(),
        })
        .authorize(&browser_actor)
        .is_ok()
    );
    Ok(())
}

#[test]
fn public_approval_uuid_is_validated_as_the_domain_approval_id() {
    let public = Uuid::now_v7();
    let approval_id = public_approval_id(public);

    assert!(approval_id.is_ok());
    assert_eq!(approval_id.ok().map(|id| *id.as_uuid()), Some(public));
    assert!(public_approval_id(Uuid::new_v4()).is_err());
}
