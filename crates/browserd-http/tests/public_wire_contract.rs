#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::sync::Arc;
use std::time::{Duration, Instant};

use browserd_actions::{
    ActionKind, ActionSequence, ActionSnapshot, ActionSnapshotFacts,
    CanonicalRequestHash as ActionHash, IdempotencyKey, OutcomeUnknownReason, TerminalDetail,
};
use browserd_api::{
    ApiEnvelope, ApiError, ApiRequest, ApiResponse, ApiService, CreateAuthority, DurableApiRouter,
    EventKind, EventResource, EventStore, InMemoryApiService, PageResource, RuntimeApiBackend,
    RuntimeCreateResult, SessionCatalog, SessionCreateDispatch, SessionCreateRequest,
    SessionListQuery, SessionResource, decode_session_create,
};
use browserd_auth::{
    AuthConfig, AuthenticatedPrincipal, RevocationRegistry, ServiceClaims, ServiceTokenSigner,
    ServiceTokenVerifier, VerificationKeySet,
};
use browserd_coordination::{
    CanonicalRequestHash, ClaimCreateOperation, CoordinationActorConfig,
    CoordinationBlockingClient, MemoryCoordinationDatabase, MemoryCreateSessionStore,
    RecoverableCreateIntent, StoreConfig,
};
use browserd_core::{
    ActionState, ErrorCode, IsolationProfile, OperationId, PageId, PrincipalId, SessionLifecycle,
    TenantId,
};
use browserd_http::render_api_response;
use chrono::{TimeZone, Utc};
use http::Method;
use http_body_util::BodyExt;
use jsonwebtoken::Algorithm;
use serde_json::{Value, json};
use uuid::Uuid;

fn fixture() -> Value {
    serde_json::from_str(include_str!("../../../sdk/fixtures/http_contract.json"))
        .expect("shared fixture")
}

fn session() -> SessionResource {
    SessionResource {
        id: fixture()["ids"]["session"]
            .as_str()
            .expect("session ID")
            .parse()
            .expect("UUIDv7"),
        lifecycle: SessionLifecycle::Ready,
        incarnation: 3,
        requested_isolation: IsolationProfile::SharedContext,
        effective_isolation: IsolationProfile::DedicatedProcess,
        metadata: BTreeMap::from([("run".into(), "contract".into())]),
    }
}

fn page() -> PageResource {
    PageResource {
        session_id: session().id,
        page_id: fixture()["ids"]["page"]
            .as_str()
            .expect("page ID")
            .parse::<PageId>()
            .expect("UUIDv4"),
        active: true,
        target_incarnation: 2,
        document_epoch: 7,
        url_revision: 9,
    }
}

async fn rendered(response: ApiResponse, method: Method, path: &str) -> Value {
    let bytes = render_api_response(response, method, path)
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let mut value: Value = serde_json::from_slice(&bytes).expect("actual HTTP JSON");
    assert!(Uuid::parse_str(value["trace_id"].as_str().expect("real trace ID")).is_ok());
    value["trace_id"] = fixture()["ids"]["trace"].clone();
    value
}

#[tokio::test]
async fn session_and_page_http_resources_match_the_shared_sdk_fixture() -> Result<(), Box<dyn Error>>
{
    let value = rendered(
        ApiResponse::Session(ApiEnvelope::new(session())),
        Method::GET,
        "/v1/sessions/id",
    )
    .await;
    assert_eq!(value, fixture()["responses"]["session"]);
    let catalog = SessionCatalog::default();
    let tenant = TenantId::new();
    catalog.upsert(tenant.clone(), session(), Utc::now())?;
    let value = rendered(
        ApiResponse::Sessions(ApiEnvelope::new(
            catalog.list(&tenant, &SessionListQuery::default())?,
        )),
        Method::GET,
        "/v1/sessions",
    )
    .await;
    assert_eq!(value, fixture()["responses"]["sessions"]);
    assert_eq!(
        rendered(
            ApiResponse::Page(ApiEnvelope::new(page())),
            Method::POST,
            "/v1/sessions/id/pages"
        )
        .await,
        fixture()["responses"]["page"]
    );
    assert_eq!(
        rendered(
            ApiResponse::Pages(ApiEnvelope::new(vec![page()])),
            Method::GET,
            "/v1/sessions/id/pages"
        )
        .await,
        fixture()["responses"]["pages"]
    );
    Ok(())
}

#[tokio::test]
async fn successful_create_and_poll_preserve_the_same_operation_resource()
-> Result<(), Box<dyn Error>> {
    let service = InMemoryApiService::default();
    let tenant = TenantId::new();
    let request = decode_session_create(include_str!(
        "../../browserd-api/tests/session_create_fixture.json"
    ))?;
    let create = service.create_session_for_tenant_with_runtime(
        tenant.clone(),
        request,
        &Uuid::new_v4().to_string(),
        Instant::now(),
        |_, _| Ok(session()),
    )?;
    let id = create.data().operation().id().clone();
    let poll = service.get_operation_for_tenant(&tenant, &id)?;
    for response in [
        ApiResponse::SessionCreate(create),
        ApiResponse::Operation(poll),
    ] {
        let mut value = rendered(response, Method::GET, "/v1/operations/id").await;
        value["data"]["operation"]["id"] = fixture()["ids"]["operation"].clone();
        value["data"]["operation"]["poll_url"] =
            fixture()["responses"]["operation_succeeded"]["data"]["operation"]["poll_url"].clone();
        assert_eq!(value, fixture()["responses"]["operation_succeeded"]);
    }
    Ok(())
}

struct UnusedRuntime;
impl RuntimeApiBackend for UnusedRuntime {
    fn create_session(
        &self,
        _: &CreateAuthority,
        _: &SessionCreateDispatch,
        _: &SessionCreateRequest,
    ) -> RuntimeCreateResult {
        RuntimeCreateResult::ConfirmedFailure(ApiError::new(ErrorCode::Internal, "unused"))
    }
    fn execute_runtime(
        &self,
        _: &AuthenticatedPrincipal,
        _: ApiRequest,
    ) -> Result<ApiResponse, ApiError> {
        Err(ApiError::new(ErrorCode::Internal, "unused"))
    }
}

fn principal(tenant: TenantId) -> Result<AuthenticatedPrincipal, Box<dyn Error>> {
    let key = b"shared-wire-fixture-test-only";
    let mut keys = VerificationKeySet::new();
    keys.insert_hmac("test", Algorithm::HS256, key)?;
    let verifier = ServiceTokenVerifier::new(
        AuthConfig::new("issuer", "audience", [Algorithm::HS256], 0, false),
        keys,
        RevocationRegistry::new(),
    );
    let token =
        ServiceTokenSigner::new("test", Algorithm::HS256, key).sign(&ServiceClaims::new(
            "issuer",
            "audience",
            PrincipalId::new(),
            tenant,
            BTreeSet::from(["session:read".into()]),
            Uuid::new_v4().to_string(),
            1,
            100,
            None,
        ))?;
    Ok(verifier.verify_at(&token, None, 10)?)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_admission_timeout_has_a_snake_case_state_and_failure_resource()
-> Result<(), Box<dyn Error>> {
    let actor = CoordinationBlockingClient::spawn(
        Arc::new(MemoryCreateSessionStore::attach(
            MemoryCoordinationDatabase::default(),
            StoreConfig::default(),
        )),
        CoordinationActorConfig::new(8, 2, Duration::from_secs(2), Duration::from_secs(2))?,
    )?;
    let tenant = TenantId::new();
    let principal = principal(tenant.clone())?;
    let id = fixture()["ids"]["operation"]
        .as_str()
        .ok_or("ID")?
        .parse::<OperationId>()?;
    let accepted = Utc::now() - chrono::Duration::seconds(2);
    let body = decode_session_create(include_str!(
        "../../browserd-api/tests/session_create_fixture.json"
    ))?;
    let intent = RecoverableCreateIntent::new(
        &id,
        serde_json::to_value(body)?,
        accepted,
        accepted + chrono::Duration::seconds(1),
        json!({}),
    )?;
    actor.claim_create(
        ClaimCreateOperation::new(
            tenant,
            principal.principal_id().clone(),
            id.clone(),
            "deadline-fixture",
            CanonicalRequestHash::new([44; 32]),
            intent,
        )?,
        Utc::now(),
    )?;
    let response = DurableApiRouter::new(Arc::new(UnusedRuntime), actor)
        .execute(&principal, ApiRequest::GetOperation(id))?;
    assert_eq!(
        rendered(response, Method::GET, "/v1/operations/id").await,
        fixture()["responses"]["operation_timed_out"]
    );
    Ok(())
}

#[tokio::test]
async fn actual_unknown_action_and_event_page_use_the_shared_wire_fixture()
-> Result<(), Box<dyn Error>> {
    let action = ActionSnapshot::from_facts(ActionSnapshotFacts {
        action_id: fixture()["ids"]["action"]
            .as_str()
            .ok_or("action")?
            .parse()?,
        action_sequence: ActionSequence::new(1),
        idempotency_key: IdempotencyKey::new("wire-contract"),
        canonical_request_hash: ActionHash::new([1; 32]),
        kind: ActionKind::Mutating,
        state: ActionState::OutcomeUnknown,
        dispatch_acknowledged: false,
        approval_decision: None,
        terminal_detail: Some(TerminalDetail::OutcomeUnknown(
            OutcomeUnknownReason::AmbiguousTransportLoss,
        )),
        resolution: None,
        result_content: None,
    })?;
    assert_eq!(
        rendered(
            ApiResponse::Action(ApiEnvelope::new(action)),
            Method::GET,
            "/v1/sessions/id/actions/id"
        )
        .await,
        fixture()["responses"]["action_unknown"]
    );
    let store = EventStore::default();
    let tenant = TenantId::new();
    let now = Utc
        .with_ymd_and_hms(2026, 10, 12, 0, 0, 0)
        .single()
        .ok_or("date")?;
    store.publish(
        tenant.clone(),
        EventKind::OperationStateChanged,
        EventResource::Operation(
            fixture()["ids"]["operation"]
                .as_str()
                .ok_or("op")?
                .parse()?,
        ),
        now,
    )?;
    let mut value = rendered(
        ApiResponse::Events(ApiEnvelope::new(store.resume(&tenant, None, 50, now)?)),
        Method::GET,
        "/v1/events",
    )
    .await;
    value["data"]["events"][0]["event_id"] = fixture()["ids"]["event"].clone();
    value["data"]["next_cursor"] = fixture()["ids"]["event"].clone();
    assert_eq!(value, fixture()["responses"]["event_page"]);
    Ok(())
}
