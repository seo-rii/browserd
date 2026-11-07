#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "support/action_acceptance.rs"]
mod action_acceptance;
#[path = "support/safety.rs"]
mod safety;
#[path = "support/webhooks.rs"]
mod webhooks;

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
use chrono::{Duration as ChronoDuration, TimeZone, Utc};
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
fn query_all_frame_path_preserves_legacy_canonical_hash_and_orders_frame_selection()
-> Result<(), Box<dyn Error>> {
    let legacy = serde_json::json!({
        "page_id":PageId::new(),"if_session_incarnation":1,"execution_timeout_ms":30000,
        "action":{"type":"query_all","selector":"input[name=email]"},
    });
    let canonical_hash = |value: &serde_json::Value| {
        *browserd_operations::CanonicalRequestHash::from_json(value).as_bytes()
    };
    let decoded = browserd_api::decode_action_submit(&legacy.to_string())?;
    assert_eq!(serde_json::to_value(&decoded)?, legacy);
    let mut explicit_empty = legacy.clone();
    explicit_empty["action"]["frame_path"] = serde_json::json!([]);
    let empty = browserd_api::decode_action_submit(&explicit_empty.to_string())?;
    assert_eq!(
        canonical_hash(&serde_json::to_value(empty)?),
        canonical_hash(&legacy)
    );

    let mut nested = legacy.clone();
    nested["action"]["frame_path"] = serde_json::json!(["iframe#outer", "iframe#inner"]);
    let decoded = browserd_api::decode_action_submit(&nested.to_string())?;
    assert_eq!(serde_json::to_value(&decoded)?, nested);
    assert_ne!(canonical_hash(&nested), canonical_hash(&legacy));
    let mut reversed = nested.clone();
    reversed["action"]["frame_path"] = serde_json::json!(["iframe#inner", "iframe#outer"]);
    assert_ne!(canonical_hash(&nested), canonical_hash(&reversed));
    Ok(())
}

#[test]
fn query_all_frame_path_bounds_utf8_depth_and_total_bytes_without_accepting_raw_routes()
-> Result<(), Box<dyn Error>> {
    let body = |frame_path| {
        serde_json::json!({
            "page_id":PageId::new(),"if_session_incarnation":1,"execution_timeout_ms":30000,
            "action":{"type":"query_all","selector":"input","frame_path":frame_path},
        })
    };
    for path in [
        vec![],
        vec!["iframe".to_owned(); 8],
        vec!["a".repeat(8192); 4],
        vec!["é".repeat(4096); 4],
        vec!["iframe#outer".to_owned(), "iframe#inner".to_owned()],
    ] {
        assert!(
            browserd_api::decode_action_submit(&body(serde_json::json!(path)).to_string()).is_ok()
        );
    }
    for path in [
        serde_json::json!([""]),
        serde_json::json!(["iframe\n"]),
        serde_json::json!(["a".repeat(8193)]),
        serde_json::json!(["é".repeat(4097)]),
        serde_json::json!(vec!["iframe"; 9]),
        serde_json::json!(vec!["a".repeat(8192); 5]),
        serde_json::json!([
            "a".repeat(8192),
            "b".repeat(8192),
            "c".repeat(8192),
            "d".repeat(8192),
            "e"
        ]),
        serde_json::Value::Null,
        serde_json::json!("iframe"),
        serde_json::json!([1]),
    ] {
        assert!(browserd_api::decode_action_submit(&body(path).to_string()).is_err());
    }
    for forbidden in ["frame_ref", "frame_id", "cdp_session_id"] {
        let mut invalid = body(serde_json::json!([]));
        invalid["action"][forbidden] = serde_json::json!("caller-route");
        assert!(browserd_api::decode_action_submit(&invalid.to_string()).is_err());
    }
    Ok(())
}

#[test]
fn checkpoint_origins_are_explicit_bounded_and_legacy_requests_capture_only_cookies()
-> Result<(), Box<dyn Error>> {
    let body = |action| {
        serde_json::json!({
            "page_id":PageId::new(),"if_session_incarnation":1,
            "execution_timeout_ms":30000,"action":action,
        })
        .to_string()
    };
    let legacy =
        browserd_api::decode_action_submit(&body(serde_json::json!({"type":"checkpoint"})))?;
    assert!(matches!(legacy.action, ActionPayload::Checkpoint { origins } if origins.is_empty()));
    for origins in [
        vec![],
        vec![
            "https://example.test".to_owned(),
            "http://example.test:8080".to_owned(),
            "https://[::1]".to_owned(),
        ],
        (0..16)
            .map(|i| format!("https://origin-{i}.test"))
            .collect(),
    ] {
        let decoded = browserd_api::decode_action_submit(&body(
            serde_json::json!({"type":"checkpoint","origins":origins}),
        ))?;
        assert!(
            matches!(decoded.action, ActionPayload::Checkpoint { origins: actual } if actual == origins)
        );
    }
    for origins in [
        vec![String::new()],
        vec!["https://example.test/".to_owned()],
        vec!["https://example.test/path".to_owned()],
        vec!["https://example.test?".to_owned()],
        vec!["https://example.test#".to_owned()],
        vec!["https://user:pass@example.test".to_owned()],
        vec!["https://EXAMPLE.test".to_owned()],
        vec!["https://example.test:443".to_owned()],
        vec!["file:///tmp/private".to_owned()],
        vec!["null".to_owned()],
        vec![" https://example.test".to_owned()],
        vec!["https://example.test\n".to_owned()],
        vec![format!("https://{}", "a".repeat(2041))],
        vec!["https://example.test".to_owned(); 2],
        (0..17)
            .map(|i| format!("https://origin-{i}.test"))
            .collect(),
    ] {
        assert!(
            browserd_api::decode_action_submit(&body(
                serde_json::json!({"type":"checkpoint","origins":origins})
            ))
            .is_err(),
            "{origins:?}"
        );
    }
    for action in [
        serde_json::json!({"type":"checkpoint","origins":null}),
        serde_json::json!({"type":"checkpoint","origins":"https://example.test"}),
        serde_json::json!({"type":"checkpoint","cookies":[]}),
        serde_json::json!({"type":"checkpoint","local_storage":{"password":"fixture"}}),
    ] {
        assert!(browserd_api::decode_action_submit(&body(action)).is_err());
    }
    Ok(())
}

#[test]
fn checkpoint_restore_requires_create_and_read_scopes_before_admission()
-> Result<(), Box<dyn Error>> {
    let tenant = TenantId::new();
    let create = |checkpoint_ref| -> Result<ApiRequest, Box<dyn Error>> {
        let mut body = decode_session_create(include_str!("session_create_fixture.json"))?;
        body.checkpoint_ref = checkpoint_ref;
        Ok(ApiRequest::CreateSession {
            body,
            idempotency_key: Uuid::new_v4().to_string(),
            received_at: std::time::Instant::now(),
        })
    };
    let ordinary = principal_with_scopes(tenant.clone(), &["session:create"])?;
    assert!(create(None)?.authorize(&ordinary).is_ok());
    for scopes in [
        &["session:create"][..],
        &["checkpoint:read"][..],
        &["session:create", "checkpoint:create"][..],
    ] {
        assert!(
            create(Some("opaque-checkpoint".to_owned()))?
                .authorize(&principal_with_scopes(tenant.clone(), scopes)?)
                .is_err()
        );
    }
    assert!(
        create(Some("opaque-checkpoint".to_owned()))?
            .authorize(&principal_with_scopes(
                tenant,
                &["session:create", "checkpoint:read"]
            )?)
            .is_ok()
    );
    Ok(())
}

#[test]
fn privileged_session_creation_requires_evaluate_scope_and_accumulates_restore_scope()
-> Result<(), Box<dyn Error>> {
    let tenant = TenantId::new();
    for restore in [false, true] {
        let mut body = decode_session_create(include_str!("session_create_fixture.json"))?;
        body.feature_profile = "privileged".to_owned();
        body.checkpoint_ref = restore.then(|| "opaque-checkpoint".to_owned());
        let request = ApiRequest::CreateSession {
            body,
            idempotency_key: Uuid::new_v4().to_string(),
            received_at: std::time::Instant::now(),
        };
        for scopes in [
            vec![],
            vec!["session:create"],
            vec!["browser:evaluate"],
            vec!["session:create", "checkpoint:read"],
            vec!["browser:evaluate", "checkpoint:read"],
            vec!["session:create", "browser:act", "browser:*"],
        ] {
            assert!(
                request
                    .authorize(&principal_with_scopes(tenant.clone(), &scopes)?)
                    .is_err(),
                "restore={restore}, scopes={scopes:?}"
            );
        }
        let evaluate =
            principal_with_scopes(tenant.clone(), &["session:create", "browser:evaluate"])?;
        assert_eq!(request.authorize(&evaluate).is_ok(), !restore);
        let full = principal_with_scopes(
            tenant.clone(),
            &["session:create", "browser:evaluate", "checkpoint:read"],
        )?;
        assert!(request.authorize(&full).is_ok());
    }
    let ordinary = ApiRequest::CreateSession {
        body: decode_session_create(include_str!("session_create_fixture.json"))?,
        idempotency_key: Uuid::new_v4().to_string(),
        received_at: std::time::Instant::now(),
    };
    assert!(
        ordinary
            .authorize(&principal_with_scopes(tenant, &["session:create"])?)
            .is_ok()
    );
    Ok(())
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
        "GET /v1/sessions/{session_id}/artifacts",
        "GET /v1/approvals",
        "GET /v1/approvals/{approval_id}",
        "POST /v1/approvals/{approval_id}/decision",
    ] {
        assert!(routes.contains(route), "missing route {route}");
    }
}

#[test]
fn artifact_discovery_requires_artifact_scope_and_bounded_typed_cursor()
-> Result<(), Box<dyn Error>> {
    let tenant = TenantId::new();
    let reader = principal_with_scopes(tenant.clone(), &["artifact:read"])?;
    let session_reader = principal_with_scopes(tenant, &["session:read"])?;
    for limit in [1, 50, 100] {
        let request = ApiRequest::ListArtifacts(browserd_api::ArtifactListRequest {
            session_id: SessionId::new(),
            after: Some(ArtifactId::new()),
            limit,
        });
        assert!(request.validate().is_ok());
        assert!(request.authorize(&reader).is_ok());
        assert!(request.authorize(&session_reader).is_err());
    }
    for limit in [0, 101, usize::MAX] {
        assert!(
            ApiRequest::ListArtifacts(browserd_api::ArtifactListRequest {
                session_id: SessionId::new(),
                after: None,
                limit,
            })
            .validate()
            .is_err()
        );
    }
    Ok(())
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
            frame_path: Vec::new(),
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
    assert!(
        command(ActionPayload::Checkpoint { origins: vec![] })
            .authorize(&base)
            .is_err()
    );
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
        (
            "checkpoint:create",
            ActionPayload::Checkpoint { origins: vec![] },
        ),
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
fn fill_secret_public_body_rejects_plaintext_fields_and_invalid_references() {
    let request = |reference: &str| {
        serde_json::json!({
            "page_id":PageId::new(), "if_session_incarnation":1, "execution_timeout_ms":30000,
            "action":{"type":"fill_secret","node_ref":"0000000000000001","secret_ref":reference}
        })
    };
    for reference in ["credential.login".to_owned(), "s".repeat(1024)] {
        assert!(browserd_api::decode_action_submit(&request(&reference).to_string()).is_ok());
    }
    for reference in [
        "".to_owned(),
        " secret".to_owned(),
        "secret ".to_owned(),
        "sec\nret".to_owned(),
        "s".repeat(1025),
        "한".repeat(342),
    ] {
        assert!(browserd_api::decode_action_submit(&request(&reference).to_string()).is_err());
    }
    for field in ["value", "secret_value", "resolved_value", "password"] {
        let mut body = request("credential.login");
        body["action"][field] = serde_json::json!("synthetic-plaintext-not-a-secret");
        assert!(browserd_api::decode_action_submit(&body.to_string()).is_err());
    }
}

#[test]
fn set_files_public_body_requires_unique_typed_artifact_ids() {
    let valid = |ids: Vec<ArtifactId>| {
        serde_json::json!({
            "page_id":PageId::new(), "if_session_incarnation":1, "execution_timeout_ms":30000,
            "action":{"type":"set_files", "node_ref":"0000000000000001", "artifact_ids":ids}
        })
    };
    for count in [1, 128] {
        assert!(
            browserd_api::decode_action_submit(
                &valid((0..count).map(|_| ArtifactId::new()).collect()).to_string()
            )
            .is_ok()
        );
    }
    let id = ArtifactId::new();
    for ids in [
        Vec::new(),
        vec![id.clone(), id],
        (0..129).map(|_| ArtifactId::new()).collect(),
    ] {
        assert!(browserd_api::decode_action_submit(&valid(ids).to_string()).is_err());
    }
    for field in ["files", "paths", "local_path"] {
        let mut body = valid(vec![ArtifactId::new()]);
        body["action"][field] = serde_json::json!(["/tmp/file"]);
        assert!(browserd_api::decode_action_submit(&body.to_string()).is_err());
    }
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
        catalog.upsert(tenant_a.clone(), resource, Utc::now())?;
    }
    catalog.upsert(
        tenant_b.clone(),
        session_resource(BTreeMap::new()),
        Utc::now(),
    )?;
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
    catalog.upsert(
        tenant_a.clone(),
        session_resource(late_metadata),
        Utc::now(),
    )?;

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
fn session_catalog_reclaims_terminal_entries_after_retention() -> Result<(), Box<dyn Error>> {
    // BRD-018: the listing catalog drops terminal entries past the retention window, keeps active
    // ones regardless of age, and keeps a recently-closed one listable within the window.
    let catalog = SessionCatalog::default();
    let tenant = TenantId::new();
    let session = |lifecycle| SessionResource {
        id: SessionId::new(),
        lifecycle,
        incarnation: 1,
        requested_isolation: IsolationProfile::SharedContext,
        effective_isolation: IsolationProfile::SharedContext,
        metadata: BTreeMap::new(),
    };
    let t0 = Utc.timestamp_opt(1_700_000_000, 0).single().expect("t0");
    let retention = ChronoDuration::hours(24);

    let ready = session(SessionLifecycle::Ready);
    let closed = session(SessionLifecycle::Closed);
    catalog.upsert(tenant.clone(), ready.clone(), t0)?;
    catalog.upsert(tenant.clone(), closed.clone(), t0)?;

    let query = SessionListQuery {
        lifecycle: None,
        isolation: None,
        metadata_key: None,
        limit: 50,
        page_token: None,
    };

    // Within the retention window the closed entry is still listable.
    assert_eq!(
        catalog.reclaim(t0 + ChronoDuration::hours(1), retention)?,
        0
    );
    assert_eq!(catalog.list(&tenant, &query)?.items().len(), 2);

    // Past retention the closed entry is reclaimed; the active one is kept regardless of age.
    assert_eq!(
        catalog.reclaim(t0 + ChronoDuration::hours(25), retention)?,
        1
    );
    let survivors = catalog.list(&tenant, &query)?;
    assert_eq!(
        survivors
            .items()
            .iter()
            .map(|item| item.id.clone())
            .collect::<Vec<_>>(),
        vec![ready.id.clone()]
    );

    // Idempotent: a later pass finds nothing more to reclaim.
    assert_eq!(
        catalog.reclaim(t0 + ChronoDuration::hours(48), retention)?,
        0
    );
    Ok(())
}

#[test]
fn session_catalog_gc_is_bounded_and_advances_across_an_active_prefix() -> Result<(), Box<dyn Error>>
{
    let catalog = SessionCatalog::default();
    let tenant = TenantId::new();
    let t0 = Utc.timestamp_opt(1_700_000_000, 0).single().expect("t0");
    for index in 0..128 {
        catalog.upsert(
            tenant.clone(),
            SessionResource {
                id: SessionId::from_uuid(Uuid::from_u128(
                    0x0000_0000_0000_7000_8000_0000_0000_0000 | (index + 1),
                ))?,
                lifecycle: if index < 32 {
                    SessionLifecycle::Ready
                } else {
                    SessionLifecycle::Closed
                },
                incarnation: 1,
                requested_isolation: IsolationProfile::DedicatedProcess,
                effective_isolation: IsolationProfile::DedicatedProcess,
                metadata: BTreeMap::new(),
            },
            t0,
        )?;
    }
    let mut reclaimed = 0;
    for _ in 0..8 {
        let count = catalog.reclaim(t0 + ChronoDuration::hours(25), ChronoDuration::hours(24))?;
        assert!(
            count <= 32,
            "one catalog maintenance pass must not sweep every session"
        );
        reclaimed += count;
    }
    assert_eq!(
        reclaimed, 96,
        "cursor must not starve terminal rows behind active sessions"
    );
    let page = catalog.list(
        &tenant,
        &SessionListQuery {
            limit: 100,
            ..SessionListQuery::default()
        },
    )?;
    assert_eq!(page.items().len(), 32);
    assert!(
        page.items()
            .iter()
            .all(|item| item.lifecycle == SessionLifecycle::Ready)
    );
    Ok(())
}

#[test]
fn session_catalog_terminal_polling_does_not_extend_retention() -> Result<(), Box<dyn Error>> {
    let catalog = SessionCatalog::default();
    let tenant = TenantId::new();
    let t0 = Utc.timestamp_opt(1_700_000_000, 0).single().expect("t0");
    let session = SessionResource {
        id: SessionId::new(),
        lifecycle: SessionLifecycle::Closed,
        incarnation: 1,
        requested_isolation: IsolationProfile::DedicatedProcess,
        effective_isolation: IsolationProfile::DedicatedProcess,
        metadata: BTreeMap::new(),
    };
    catalog.upsert(tenant.clone(), session.clone(), t0)?;
    catalog.upsert(tenant.clone(), session, t0 + ChronoDuration::hours(23))?;
    assert_eq!(
        catalog.reclaim(t0 + ChronoDuration::hours(25), ChronoDuration::hours(24))?,
        1
    );
    assert!(
        catalog
            .list(&tenant, &SessionListQuery::default())?
            .items()
            .is_empty()
    );
    Ok(())
}

#[test]
fn session_catalog_sparse_pages_have_bounded_progress_and_tenant_scoped_cursors()
-> Result<(), Box<dyn Error>> {
    let catalog = SessionCatalog::default();
    let tenant = TenantId::new();
    let other_tenant = TenantId::new();
    for index in 1..=800 {
        let session = SessionResource {
            id: SessionId::from_uuid(Uuid::from_u128(
                0x0000_0000_0000_7000_8000_0000_0000_0000 | index,
            ))?,
            lifecycle: if index == 800 {
                SessionLifecycle::Closed
            } else {
                SessionLifecycle::Ready
            },
            incarnation: 1,
            requested_isolation: IsolationProfile::DedicatedProcess,
            effective_isolation: IsolationProfile::DedicatedProcess,
            metadata: BTreeMap::new(),
        };
        catalog.upsert(tenant.clone(), session.clone(), Utc::now())?;
        catalog.upsert(other_tenant.clone(), session, Utc::now())?;
    }
    let mut query = SessionListQuery {
        lifecycle: Some(SessionLifecycle::Closed),
        limit: 10,
        ..SessionListQuery::default()
    };
    let first = catalog.list(&tenant, &query)?;
    assert!(
        first.items().is_empty(),
        "bounded scan may return an empty page for a sparse filter"
    );
    let token = first
        .next_page_token()
        .ok_or("bounded progress token")?
        .to_owned();
    assert!(
        catalog
            .list(
                &other_tenant,
                &SessionListQuery {
                    page_token: Some(token.clone()),
                    ..query.clone()
                }
            )
            .is_err()
    );
    query.page_token = Some(token);
    let mut total = 0;
    for _ in 0..4 {
        let page = catalog.list(&tenant, &query)?;
        total += page.items().len();
        let Some(next) = page.next_page_token() else {
            assert_eq!(total, 1);
            return Ok(());
        };
        assert_ne!(query.page_token.as_deref(), Some(next));
        query.page_token = Some(next.to_owned());
    }
    Err("bounded pagination did not finish".into())
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
        assert_eq!(
            approval.summary().page_id,
            Some(approval.proposal.page_id())
        );
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
                data_base64: None,
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

#[test]
fn typed_approval_summary_exposes_review_metadata_without_action_contents()
-> Result<(), Box<dyn Error>> {
    use browserd_policy::{
        ApprovalActionKind, ApprovalArtifactBinding, ApprovalContextScope, ApprovalNodeBinding,
        ApprovalWorkerFence, TypedActionPayload, TypedActionProposalBinding,
    };
    let node = ApprovalNodeBinding {
        node_ref: "opaque-node".to_owned(),
        binding_sha256: [3; 32],
        role: Some("textbox".to_owned()),
        name: Some("Account login".to_owned()),
    };
    let files = vec![
        ApprovalArtifactBinding {
            artifact_id: ArtifactId::new(),
            object_generation: [4; 32],
            size_bytes: 12,
            checksum_sha256: [5; 32],
            effective_filename: "first.txt".to_owned(),
            publication_sha256: [6; 32],
            scan_evidence_sha256: Some([7; 32]),
        },
        ApprovalArtifactBinding {
            artifact_id: ArtifactId::new(),
            object_generation: [8; 32],
            size_bytes: 4,
            checksum_sha256: [9; 32],
            effective_filename: "second.txt".to_owned(),
            publication_sha256: [10; 32],
            scan_evidence_sha256: None,
        },
    ];
    let hidden = b"secret-plaintext; arbitrary_script(); file bytes";
    let hash = ActionArgumentsHash::digest(hidden);
    let payloads = [
        TypedActionPayload::Browser {
            action: ApprovalActionKind::Fill,
            arguments_sha256: *hash.as_bytes(),
            node: Some(node.clone()),
            navigation_destination: None,
        },
        TypedActionPayload::Browser {
            action: ApprovalActionKind::Evaluate,
            arguments_sha256: *hash.as_bytes(),
            node: None,
            navigation_destination: None,
        },
        TypedActionPayload::FillSecret {
            node: node.clone(),
            secret_ref: "credential/login".to_owned(),
            grant_metadata_sha256: [11; 32],
        },
        TypedActionPayload::SetFiles {
            node: node.clone(),
            files,
        },
        TypedActionPayload::Checkpoint {
            origins: vec![
                "https://second.test".to_owned(),
                "https://first.test".to_owned(),
            ],
            build_identity_sha256: [12; 32],
        },
        TypedActionPayload::Checkpoint {
            origins: vec![],
            build_identity_sha256: [12; 32],
        },
    ];
    for payload in payloads {
        let tenant_id = TenantId::new();
        let session_id = SessionId::new();
        let action_id = browserd_core::ActionId::new();
        let context = if matches!(payload, TypedActionPayload::Checkpoint { .. }) {
            ApprovalContextScope::BrowserContext
        } else {
            ApprovalContextScope::HttpOrigin {
                origin: "https://example.test".to_owned(),
            }
        };
        let credentials = match &payload {
            TypedActionPayload::FillSecret { secret_ref, .. } => {
                CredentialRefsHash::digest([secret_ref.as_str()])
            }
            _ => CredentialRefsHash::digest([]),
        };
        let proposal = CanonicalActionProposal::new(
            tenant_id.clone(),
            PrincipalId::new(),
            session_id.clone(),
            1,
            PageId::new(),
            2,
            3,
            if matches!(context, ApprovalContextScope::BrowserContext) {
                Origin::browser_context_scope()
            } else {
                Origin::parse("https://example.test")?
            },
            4,
            payload.action_kind().legacy_action_type(),
            hash,
            payload
                .node()
                .map(|node| browserd_policy::NodeReference::new(&node.node_ref))
                .transpose()?,
            credentials,
            5000,
        )
        .with_typed_binding(TypedActionProposalBinding {
            schema_version: 2,
            action_id: action_id.clone(),
            sequence: 1,
            fence: ApprovalWorkerFence {
                worker_id: browserd_core::WorkerId::new("summary-worker")?,
                worker_epoch: 2,
                placement_version: 3,
                session_incarnation: 1,
            },
            policy_digest: [13; 32],
            target_binding_sha256: [14; 32],
            context_scope: context.clone(),
            payload: payload.clone(),
        })?;
        let approval = ApprovalResource {
            approval_id: Uuid::now_v7(),
            tenant_id,
            session_id,
            action_id,
            state: ApprovalState::Pending,
            proposal,
        };
        let summary = serde_json::to_value(approval.summary())?;
        let encoded = summary.to_string();
        for forbidden in [
            "secret-plaintext",
            "arbitrary_script",
            "file bytes",
            "arguments_sha256",
            "grant_metadata_sha256",
            "binding_sha256",
            "publication_sha256",
        ] {
            assert!(!encoded.contains(forbidden), "{forbidden}");
        }
        if payload.node().is_some() {
            assert_eq!(summary["node_role"], "textbox");
            assert_eq!(summary["node_name"], "Account login");
        } else {
            assert!(summary.get("node_role").is_none());
            assert!(summary.get("node_name").is_none());
        }
        if matches!(context, ApprovalContextScope::BrowserContext) {
            assert!(summary.get("page_id").is_none());
            assert_eq!(summary["context"]["kind"], "browser_context");
        } else {
            assert_eq!(summary["page_id"], approval.proposal.page_id().to_string());
        }
        assert_eq!(summary["action_kind"], payload.action_kind().as_str());
        assert_eq!(summary["context"], serde_json::to_value(context)?);
        assert_eq!(summary["expires_at_unix_millis"], 5000);
        assert_eq!(summary["policy_digest"], "0d".repeat(32));
        match payload {
            TypedActionPayload::FillSecret { .. } => {
                assert_eq!(summary["secret_ref"], "credential/login")
            }
            TypedActionPayload::SetFiles { files, .. } => {
                assert_eq!(
                    summary["files"][0]["artifact_id"],
                    files[0].artifact_id.to_string()
                );
                assert_eq!(summary["files"][1]["display_filename"], "second.txt");
                assert_eq!(summary["files"][0]["size_bytes"], 12);
            }
            TypedActionPayload::Checkpoint { origins, .. } => {
                assert_eq!(summary["checkpoint_origins"], serde_json::json!(origins))
            }
            _ => assert!(summary.get("secret_ref").is_none()),
        }
        let mut wrong_action = approval.clone();
        wrong_action.action_id = browserd_core::ActionId::new();
        assert!(ApprovalCatalog::default().upsert(wrong_action).is_err());
        ApprovalCatalog::default().upsert(approval)?;
    }
    Ok(())
}
