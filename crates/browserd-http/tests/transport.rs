#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::error::Error;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use axum::body::Body;
use browserd_actions::{
    ActionKind, ActionSequence, ActionSnapshot, ActionSnapshotFacts, CanonicalRequestHash,
    IdempotencyKey, KnownFailureReason, OutcomeUnknownReason, TerminalDetail,
};
use browserd_api::{
    ApiEnvelope, ApiError, ApiRequest, ApiResponse, ApiService, InMemoryApiService,
};
use browserd_artifacts::{ArtifactKey, DownloadToken, OneTimeDownloadTokenRegistry};
use browserd_auth::{
    AuthConfig, AuthenticatedPrincipal, RevocationRegistry, ServiceClaims, ServiceTokenSigner,
    ServiceTokenVerifier, VerificationKeySet,
};
use browserd_core::{ActionId, ErrorCode, PrincipalId, SessionId, TenantId};
use browserd_http::{
    AuthenticationError, Authenticator, HttpConfig, Readiness, ViewerGateError, ViewerTransport,
    router,
};
use browserd_viewer::{TicketPolicy, TicketRegistry, ViewerScopes, ViewerTicket};
use chrono::{Duration as ChronoDuration, Utc};
use http::{Method, Request, StatusCode};
use http_body_util::BodyExt;
use jsonwebtoken::Algorithm;
use tower::ServiceExt;
use uuid::Uuid;

#[derive(Clone)]
struct StaticAuth {
    principal: AuthenticatedPrincipal,
}

impl Authenticator for StaticAuth {
    fn authenticate(&self, bearer: &str) -> Result<AuthenticatedPrincipal, AuthenticationError> {
        if bearer == "valid" {
            Ok(self.principal.clone())
        } else {
            Err(AuthenticationError)
        }
    }
}

#[derive(Default)]
struct RejectViewer;

impl ViewerTransport for RejectViewer {
    fn consume_ticket(
        &self,
        _session_id: &SessionId,
        origin: &str,
        ticket: &str,
    ) -> Result<(), ViewerGateError> {
        if origin != "https://console.example" {
            return Err(ViewerGateError::OriginDenied);
        }
        if ticket != "valid-ticket" {
            return Err(ViewerGateError::TicketDenied);
        }
        Ok(())
    }

    fn connected(&self, _session_id: SessionId) {}
}

struct StaticReadiness(bool);

impl Readiness for StaticReadiness {
    fn ready(&self) -> bool {
        self.0
    }
}

struct CountingViewer {
    consumed: Arc<AtomicBool>,
}

impl ViewerTransport for CountingViewer {
    fn consume_ticket(
        &self,
        _session_id: &SessionId,
        _origin: &str,
        _ticket: &str,
    ) -> Result<(), ViewerGateError> {
        self.consumed.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn connected(&self, _session_id: SessionId) {}
}

struct ErrorService(ErrorCode);

impl ApiService for ErrorService {
    fn execute(
        &self,
        principal: &AuthenticatedPrincipal,
        request: ApiRequest,
    ) -> Result<ApiResponse, ApiError> {
        request.authorize(principal)?;
        request.validate()?;
        Err(ApiError::new(self.0, "sensitive backend detail"))
    }
}

struct ActionSnapshotService(ActionSnapshot);

impl ApiService for ActionSnapshotService {
    fn execute(
        &self,
        principal: &AuthenticatedPrincipal,
        request: ApiRequest,
    ) -> Result<ApiResponse, ApiError> {
        request.authorize(principal)?;
        request.validate()?;
        Ok(ApiResponse::Action(ApiEnvelope::new(self.0.clone())))
    }
}

fn terminal_action_snapshot(
    action_id: ActionId,
    terminal_detail: TerminalDetail,
) -> Result<ActionSnapshot, Box<dyn Error>> {
    Ok(ActionSnapshot::from_facts(ActionSnapshotFacts {
        action_id,
        action_sequence: ActionSequence::new(42),
        idempotency_key: IdempotencyKey::new(Uuid::new_v4().to_string()),
        canonical_request_hash: CanonicalRequestHash::new([7; 32]),
        kind: ActionKind::Mutating,
        state: terminal_detail.state(),
        dispatch_acknowledged: false,
        approval_decision: None,
        terminal_detail: Some(terminal_detail),
        resolution: None,
    })?)
}

struct CapabilityService {
    viewer_ticket: ViewerTicket,
    download_token: DownloadToken,
}

impl ApiService for CapabilityService {
    fn execute(
        &self,
        principal: &AuthenticatedPrincipal,
        request: ApiRequest,
    ) -> Result<ApiResponse, ApiError> {
        request.authorize(principal)?;
        request.validate()?;
        match request {
            ApiRequest::IssueViewerTicket(_) => Ok(ApiResponse::ViewerTicket(ApiEnvelope::new(
                self.viewer_ticket.clone(),
            ))),
            ApiRequest::DownloadArtifact(_) => Ok(ApiResponse::ArtifactDownload(ApiEnvelope::new(
                self.download_token.clone(),
            ))),
            _ => Err(ApiError::new(ErrorCode::Internal, "unexpected request")),
        }
    }
}

struct CapabilityViewer {
    viewer_ticket: ViewerTicket,
    download_token: DownloadToken,
}

impl ViewerTransport for CapabilityViewer {
    fn consume_ticket(
        &self,
        _session_id: &SessionId,
        _origin: &str,
        _ticket: &str,
    ) -> Result<(), ViewerGateError> {
        Ok(())
    }

    fn connected(&self, _session_id: SessionId) {}

    fn present_viewer_ticket(&self, ticket: &ViewerTicket) -> Option<String> {
        (ticket == &self.viewer_ticket).then(|| "viewer-capability".to_owned())
    }

    fn present_download_token(&self, token: &DownloadToken) -> Option<String> {
        (token == &self.download_token).then(|| "download-capability".to_owned())
    }
}

fn principal_for_tenant(
    tenant_id: TenantId,
    scopes: &[&str],
) -> Result<AuthenticatedPrincipal, Box<dyn Error>> {
    let secret = b"browserd-http-test-secret";
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

fn principal(scopes: &[&str]) -> Result<AuthenticatedPrincipal, Box<dyn Error>> {
    principal_for_tenant(TenantId::new(), scopes)
}

fn app(service: Arc<dyn ApiService>, principal: AuthenticatedPrincipal) -> axum::Router {
    router(
        HttpConfig::default(),
        service,
        Arc::new(StaticAuth { principal }),
        Arc::new(RejectViewer),
        Arc::new(StaticReadiness(false)),
    )
}

async fn body_json(response: axum::response::Response) -> serde_json::Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn health_request_ids_and_fail_closed_readiness_are_exposed() -> Result<(), Box<dyn Error>> {
    let app = app(Arc::new(InMemoryApiService::default()), principal(&[])?);
    let live = app
        .clone()
        .oneshot(Request::builder().uri("/health/live").body(Body::empty())?)
        .await?;
    assert_eq!(live.status(), StatusCode::OK);
    assert!(live.headers().contains_key("x-request-id"));

    let ready = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/health/ready")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(ready.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(body_json(ready).await.get("trace_id").is_some());

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/sessions")
                .header("authorization", "Bearer invalid")
                .header("x-request-id", "caller-request-7")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(response.headers()["x-request-id"], "caller-request-7");
    let json = body_json(response).await;
    assert_eq!(json["error"]["message"], "request failed");
    assert!(json.get("trace_id").is_some());
    assert_eq!(json["error"]["trace_id"], json["trace_id"]);
    assert!(json["error"]["retryable"].is_boolean());
    assert!(json["error"]["details"].is_object());
    Ok(())
}

#[tokio::test]
async fn create_session_is_strict_bounded_and_returns_202() -> Result<(), Box<dyn Error>> {
    let app = app(
        Arc::new(InMemoryApiService::default()),
        principal(&["session:create"])?,
    );
    let valid = include_str!("../../browserd-api/tests/session_create_fixture.json");
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/sessions")
                .header("authorization", "Bearer valid")
                .header("content-type", "application/json")
                .header("idempotency-key", Uuid::new_v4().to_string())
                .body(Body::from(valid))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert!(body_json(response).await.get("trace_id").is_some());

    let malformed = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/sessions")
                .header("authorization", "Bearer valid")
                .header("content-type", "application/json")
                .header("idempotency-key", Uuid::new_v4().to_string())
                .body(Body::from(r#"{"unknown":true}"#))?,
        )
        .await?;
    assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);

    let oversized = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/sessions")
                .header("authorization", "Bearer valid")
                .header("content-type", "application/json")
                .header("idempotency-key", Uuid::new_v4().to_string())
                .body(Body::from(vec![b'x'; 70_000]))?,
        )
        .await?;
    assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
    Ok(())
}

#[tokio::test]
async fn scope_errors_are_non_leaking() -> Result<(), Box<dyn Error>> {
    let session_id = SessionId::new();
    let action_body = format!(
        r#"{{"page_id":"{}","if_session_incarnation":1,"execution_timeout_ms":30000,"action":{{"type":"evaluate","expression":"1+1"}}}}"#,
        browserd_core::PageId::new()
    );
    let denied = app(
        Arc::new(ErrorService(ErrorCode::Internal)),
        principal(&["browser:act"])?,
    )
    .oneshot(
        Request::builder()
            .method(Method::POST)
            .uri(format!("/v1/sessions/{session_id}/actions"))
            .header("authorization", "Bearer valid")
            .header("content-type", "application/json")
            .header("idempotency-key", Uuid::new_v4().to_string())
            .header("prefer", "wait=100")
            .body(Body::from(action_body))?,
    )
    .await?;
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    Ok(())
}

#[tokio::test]
async fn outcome_unknown_is_http_200_with_non_retryable_public_reason() -> Result<(), Box<dyn Error>>
{
    let session_id = SessionId::new();
    let unknown_id = ActionId::new();
    let unknown = app(
        Arc::new(ActionSnapshotService(terminal_action_snapshot(
            unknown_id.clone(),
            TerminalDetail::OutcomeUnknown(OutcomeUnknownReason::WorkerLost),
        )?)),
        principal(&["session:read"])?,
    )
    .oneshot(
        Request::builder()
            .uri(format!("/v1/sessions/{session_id}/actions/{unknown_id}"))
            .header("authorization", "Bearer valid")
            .body(Body::empty())?,
    )
    .await?;
    assert_eq!(unknown.status(), StatusCode::OK);
    let json = body_json(unknown).await;
    assert_eq!(json["data"]["action_id"], unknown_id.to_string());
    assert_eq!(json["data"]["status"], "outcome_unknown");
    assert_eq!(json["data"]["reason"], "worker_lost");
    assert_eq!(json["data"]["retryable"], false);
    Ok(())
}

#[tokio::test]
async fn failed_known_exposes_not_dispatched_reason() -> Result<(), Box<dyn Error>> {
    let session_id = SessionId::new();
    let not_dispatched_id = ActionId::new();
    let not_dispatched = app(
        Arc::new(ActionSnapshotService(terminal_action_snapshot(
            not_dispatched_id.clone(),
            TerminalDetail::FailedKnown(KnownFailureReason::NotDispatched),
        )?)),
        principal(&["session:read"])?,
    )
    .oneshot(
        Request::builder()
            .uri(format!(
                "/v1/sessions/{session_id}/actions/{not_dispatched_id}"
            ))
            .header("authorization", "Bearer valid")
            .body(Body::empty())?,
    )
    .await?;
    assert_eq!(not_dispatched.status(), StatusCode::OK);
    let json = body_json(not_dispatched).await;
    assert_eq!(json["data"]["action_id"], not_dispatched_id.to_string());
    assert_eq!(json["data"]["status"], "failed_known");
    assert_eq!(json["data"]["reason"], "not_dispatched");
    Ok(())
}

#[tokio::test]
async fn viewer_websocket_rejects_origin_protocol_and_ticket_before_upgrade()
-> Result<(), Box<dyn Error>> {
    let session_id = SessionId::new();
    let base = format!("/v1/sessions/{session_id}/viewer");
    let missing_origin = app(Arc::new(InMemoryApiService::default()), principal(&[])?)
        .oneshot(
            Request::builder()
                .uri(&base)
                .header("connection", "upgrade")
                .header("upgrade", "websocket")
                .header("sec-websocket-version", "13")
                .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
                .header("sec-websocket-protocol", "browser-viewer.v1")
                .header("cookie", "browserd_viewer_ticket=valid-ticket")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(missing_origin.status(), StatusCode::FORBIDDEN);

    let bad_ticket = app(Arc::new(InMemoryApiService::default()), principal(&[])?)
        .oneshot(
            Request::builder()
                .uri(base)
                .header("origin", "https://console.example")
                .header("connection", "upgrade")
                .header("upgrade", "websocket")
                .header("sec-websocket-version", "13")
                .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
                .header("sec-websocket-protocol", "browser-viewer.v1")
                .header("cookie", "browserd_viewer_ticket=bad")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(bad_ticket.status(), StatusCode::BAD_REQUEST);

    let wrong_protocol = app(Arc::new(InMemoryApiService::default()), principal(&[])?)
        .oneshot(
            Request::builder()
                .uri(format!("/v1/sessions/{}/viewer", SessionId::new()))
                .header("origin", "https://console.example")
                .header("connection", "upgrade")
                .header("upgrade", "websocket")
                .header("sec-websocket-version", "13")
                .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
                .header("sec-websocket-protocol", "raw-cdp")
                .header("cookie", "browserd_viewer_ticket=valid-ticket")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(wrong_protocol.status(), StatusCode::BAD_REQUEST);

    let query_ticket = app(Arc::new(InMemoryApiService::default()), principal(&[])?)
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/v1/sessions/{}/viewer?ticket=valid-ticket",
                    SessionId::new()
                ))
                .header("origin", "https://console.example")
                .header("connection", "upgrade")
                .header("upgrade", "websocket")
                .header("sec-websocket-version", "13")
                .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
                .header("sec-websocket-protocol", "browser-viewer.v1")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(query_ticket.status(), StatusCode::BAD_REQUEST);

    Ok(())
}

#[tokio::test]
async fn malformed_websocket_handshake_cannot_consume_a_one_time_ticket()
-> Result<(), Box<dyn Error>> {
    let consumed = Arc::new(AtomicBool::new(false));
    let app = router(
        HttpConfig::default(),
        Arc::new(InMemoryApiService::default()),
        Arc::new(StaticAuth {
            principal: principal(&[])?,
        }),
        Arc::new(CountingViewer {
            consumed: Arc::clone(&consumed),
        }),
        Arc::new(StaticReadiness(true)),
    );
    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/v1/sessions/{}/viewer", SessionId::new()))
                .header("origin", "https://console.example")
                .header("sec-websocket-protocol", "browser-viewer.v1")
                .header("cookie", "browserd_viewer_ticket=one-time")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(!consumed.load(Ordering::SeqCst));
    Ok(())
}

#[tokio::test]
async fn unavailable_websocket_upgrade_cannot_consume_a_one_time_ticket()
-> Result<(), Box<dyn Error>> {
    let consumed = Arc::new(AtomicBool::new(false));
    let app = router(
        HttpConfig::default(),
        Arc::new(InMemoryApiService::default()),
        Arc::new(StaticAuth {
            principal: principal(&[])?,
        }),
        Arc::new(CountingViewer {
            consumed: Arc::clone(&consumed),
        }),
        Arc::new(StaticReadiness(true)),
    );
    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/v1/sessions/{}/viewer", SessionId::new()))
                .header("origin", "https://console.example")
                .header("connection", "upgrade")
                .header("upgrade", "websocket")
                .header("sec-websocket-version", "13")
                .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
                .header("sec-websocket-protocol", "browser-viewer.v1")
                .header("cookie", "browserd_viewer_ticket=one-time")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(!consumed.load(Ordering::SeqCst));
    Ok(())
}

#[tokio::test]
async fn operation_lookup_is_tenant_isolated() -> Result<(), Box<dyn Error>> {
    let service = Arc::new(InMemoryApiService::default());
    let tenant_a = TenantId::new();
    let tenant_b = TenantId::new();
    let valid = include_str!("../../browserd-api/tests/session_create_fixture.json");
    let created = app(
        service.clone(),
        principal_for_tenant(tenant_a, &["session:create"])?,
    )
    .oneshot(
        Request::builder()
            .method(Method::POST)
            .uri("/v1/sessions")
            .header("authorization", "Bearer valid")
            .header("content-type", "application/json")
            .header("idempotency-key", Uuid::new_v4().to_string())
            .body(Body::from(valid))?,
    )
    .await?;
    let operation_id = body_json(created).await["data"]["operation"]["id"]
        .as_str()
        .ok_or("operation id missing")?
        .to_owned();

    let hidden = app(service, principal_for_tenant(tenant_b, &["session:read"])?)
        .oneshot(
            Request::builder()
                .uri(format!("/v1/operations/{operation_id}"))
                .header("authorization", "Bearer valid")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(hidden.status(), StatusCode::NOT_FOUND);
    Ok(())
}

struct SlowService {
    completed: Arc<AtomicBool>,
}

impl ApiService for SlowService {
    fn execute(
        &self,
        principal: &AuthenticatedPrincipal,
        request: ApiRequest,
    ) -> Result<ApiResponse, ApiError> {
        request.authorize(principal)?;
        request.validate()?;
        std::thread::sleep(Duration::from_millis(50));
        self.completed.store(true, Ordering::SeqCst);
        Err(ApiError::new(
            ErrorCode::WorkerUnavailable,
            "backend unavailable",
        ))
    }
}

#[tokio::test]
async fn dropping_prefer_wait_request_does_not_cancel_admitted_action() -> Result<(), Box<dyn Error>>
{
    let completed = Arc::new(AtomicBool::new(false));
    let service = Arc::new(SlowService {
        completed: Arc::clone(&completed),
    });
    let session_id = SessionId::new();
    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("/v1/sessions/{session_id}/actions"))
        .header("authorization", "Bearer valid")
        .header("content-type", "application/json")
        .header("idempotency-key", Uuid::new_v4().to_string())
        .header("prefer", "wait=1")
        .body(Body::from(format!(
            r#"{{"page_id":"{}","if_session_incarnation":1,"execution_timeout_ms":30000,"action":{{"type":"get_url"}}}}"#,
            browserd_core::PageId::new()
        )))?;
    let task = tokio::spawn(app(service, principal(&["browser:act"])?).oneshot(request));
    tokio::time::sleep(Duration::from_millis(10)).await;
    task.abort();
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert!(completed.load(Ordering::SeqCst));
    Ok(())
}

#[tokio::test]
async fn metrics_have_only_fixed_low_cardinality_series() -> Result<(), Box<dyn Error>> {
    let response = app(Arc::new(InMemoryApiService::default()), principal(&[])?)
        .oneshot(Request::builder().uri("/metrics").body(Body::empty())?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await?.to_bytes();
    let body = std::str::from_utf8(&bytes)?;
    assert!(body.contains("browserd_gateway_up 1"));
    assert!(!body.contains('{'));
    Ok(())
}

#[tokio::test]
async fn every_public_v1_route_is_registered_and_unknown_queries_fail_strictly()
-> Result<(), Box<dyn Error>> {
    let scopes = [
        "session:create",
        "session:read",
        "session:close",
        "admin:force-close",
        "browser:act",
        "browser:evaluate",
        "secret:use",
        "checkpoint:create",
        "viewer:read",
        "viewer:control",
        "admin:force-control",
        "artifact:upload",
        "artifact:read",
        "approval:read",
        "approval:decide",
        "events:read",
    ];
    let app = app(
        Arc::new(ErrorService(ErrorCode::Internal)),
        principal(&scopes)?,
    );
    let session_id = SessionId::new().to_string();
    let operation_id = browserd_core::OperationId::new().to_string();
    let page_id = browserd_core::PageId::new().to_string();
    let action_id = browserd_core::ActionId::new().to_string();
    let artifact_id = browserd_core::ArtifactId::new().to_string();
    let approval_id = Uuid::now_v7().to_string();
    for route in browserd_api::PUBLIC_V1_ROUTES {
        let (method, template) = route.split_once(' ').ok_or("invalid route manifest")?;
        let uri = template
            .replace("{session_id}", &session_id)
            .replace("{operation_id}", &operation_id)
            .replace("{page_id}", &page_id)
            .replace("{action_id}", &action_id)
            .replace("{artifact_id}", &artifact_id)
            .replace("{approval_id}", &approval_id);
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::from_bytes(method.as_bytes())?)
                    .uri(uri)
                    .header("authorization", "Bearer valid")
                    .header("content-type", "application/json")
                    .header("idempotency-key", Uuid::new_v4().to_string())
                    .body(Body::empty())?,
            )
            .await?;
        assert_ne!(response.status(), StatusCode::NOT_FOUND, "{route}");
        assert!(response.headers().contains_key("x-request-id"), "{route}");
    }

    let strict_query = app
        .oneshot(
            Request::builder()
                .uri(format!("/v1/sessions/{session_id}?unknown=true"))
                .header("authorization", "Bearer valid")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(strict_query.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

#[tokio::test]
async fn global_body_limit_and_prefer_are_strict_and_return_trace_ids() -> Result<(), Box<dyn Error>>
{
    let app = app(
        Arc::new(ErrorService(ErrorCode::Internal)),
        principal(&["session:create", "browser:act"])?,
    );
    let oversized = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/sessions")
                .header("authorization", "Bearer valid")
                .header("content-type", "application/json")
                .header("idempotency-key", Uuid::new_v4().to_string())
                .body(Body::from(vec![b'x'; 300_000]))?,
        )
        .await?;
    assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert!(body_json(oversized).await.get("trace_id").is_some());

    let invalid_prefer = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/v1/sessions/{}/actions", SessionId::new()))
                .header("authorization", "Bearer valid")
                .header("content-type", "application/json")
                .header("idempotency-key", Uuid::new_v4().to_string())
                .header("prefer", "wait=30001")
                .body(Body::from("{}"))?,
        )
        .await?;
    assert_eq!(invalid_prefer.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

#[tokio::test]
async fn opaque_capabilities_are_presented_only_through_the_injected_adapter()
-> Result<(), Box<dyn Error>> {
    let tenant_id = TenantId::new();
    let session_id = SessionId::new();
    let ticket_registry = TicketRegistry::new(TicketPolicy::new(
        Duration::from_secs(30),
        ["https://console.example"],
    )?);
    let viewer_ticket = ticket_registry.issue(
        tenant_id.clone(),
        session_id.clone(),
        1,
        ViewerScopes::new(true, false, false),
        1,
        Duration::from_secs(30),
    )?;
    let artifact_id = browserd_core::ArtifactId::new();
    let key = ArtifactKey::new(tenant_id.clone(), session_id.clone(), artifact_id.clone());
    let download_token = OneTimeDownloadTokenRegistry::new()
        .issue(&key, Utc::now() + ChronoDuration::minutes(1))
        .await;
    let service = Arc::new(CapabilityService {
        viewer_ticket: viewer_ticket.clone(),
        download_token: download_token.clone(),
    });
    let viewer = Arc::new(CapabilityViewer {
        viewer_ticket,
        download_token,
    });
    let app = router(
        HttpConfig::default(),
        service,
        Arc::new(StaticAuth {
            principal: principal_for_tenant(tenant_id, &["viewer:read", "artifact:read"])?,
        }),
        viewer,
        Arc::new(StaticReadiness(true)),
    );
    let issued = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/v1/sessions/{session_id}/viewer-ticket"))
                .header("authorization", "Bearer valid")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"session_incarnation":1,"scopes":{"read":true,"control":false,"admin":false},"ttl_seconds":30}"#,
                ))?,
        )
        .await?;
    assert_eq!(issued.status(), StatusCode::CREATED);
    let cookie = issued.headers()["set-cookie"].to_str()?;
    assert!(cookie.contains("viewer-capability"));
    assert!(cookie.contains(&format!("Path=/v1/sessions/{session_id}/viewer")));
    assert!(cookie.contains("Secure; HttpOnly; SameSite=Strict"));
    assert_eq!(issued.headers()["cache-control"], "no-store");
    let issued_body = body_json(issued).await;
    assert_eq!(issued_body["data"]["ticket_issued"], true);
    assert!(issued_body.get("ticket").is_none());
    assert!(issued_body["data"].get("ticket").is_none());

    let download = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!(
                    "/v1/sessions/{session_id}/artifacts/{artifact_id}/download"
                ))
                .header("authorization", "Bearer valid")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(download.status(), StatusCode::OK);
    assert_eq!(
        body_json(download).await["data"]["download_token"],
        "download-capability"
    );
    Ok(())
}
