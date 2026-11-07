use super::*;
use axum::http::HeaderValue;
use browserd_api::{
    ApiRouter, CreateAuthority, RuntimeApiBackend, RuntimeCreateResult, SafetyApi,
    SessionCreateDispatch, SessionCreateRequest,
};
use browserd_coordination::{
    CoordinationActorConfig, MemorySafetyAuthority, SafetyAuthorityBlockingClient,
    SafetyAuthorityError,
};

struct NoBrowser;
impl RuntimeApiBackend for NoBrowser {
    fn create_session(
        &self,
        _: &CreateAuthority,
        _: &SessionCreateDispatch,
        _: &SessionCreateRequest,
    ) -> RuntimeCreateResult {
        RuntimeCreateResult::ConfirmedFailure(ApiError::new(
            ErrorCode::WorkerUnavailable,
            "unavailable",
        ))
    }
    fn execute_runtime(
        &self,
        _: &AuthenticatedPrincipal,
        _: ApiRequest,
    ) -> Result<ApiResponse, ApiError> {
        Err(ApiError::new(ErrorCode::WorkerUnavailable, "unavailable"))
    }
}
fn service() -> (Arc<dyn ApiService>, SafetyAuthorityBlockingClient) {
    let client = SafetyAuthorityBlockingClient::spawn(
        Arc::new(MemorySafetyAuthority::default()),
        CoordinationActorConfig::new(16, 4, Duration::from_secs(2), Duration::from_secs(2))
            .unwrap(),
    )
    .unwrap();
    (
        Arc::new(ApiRouter::new(Arc::new(NoBrowser)).with_safety(SafetyApi::new(client.clone()))),
        client,
    )
}
fn request(method: Method, suffix: &str, key: Option<Uuid>, body: &str) -> Request<Body> {
    let mut request = Request::builder()
        .method(method)
        .uri(format!("/v1/admin/safety-switches{suffix}"))
        .header("authorization", "Bearer valid");
    if let Some(key) = key {
        request = request.header("idempotency-key", key.to_string());
    }
    if !body.is_empty() {
        request = request.header("content-type", "application/json");
    }
    request.body(Body::from(body.to_owned())).unwrap()
}
async fn json(response: axum::response::Response) -> serde_json::Value {
    serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
}

#[tokio::test]
async fn operator_scope_precedes_invalid_body_and_no_authority_is_created() {
    let (service, client) = service();
    let app = app(service, principal(&["session:create"]).unwrap());
    let response = app
        .oneshot(request(Method::POST, "/initialize", None, "invalid JSON"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(
        client.read().unwrap_err(),
        SafetyAuthorityError::MissingAuthority
    );
}

#[tokio::test]
async fn safety_http_initialize_cas_and_retry_work_without_browser() {
    let (service, client) = service();
    let app = app(
        service,
        principal(&["admin:safety:read", "admin:safety:write"]).unwrap(),
    );
    let missing = app
        .clone()
        .oneshot(request(Method::GET, "", None, ""))
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(missing.headers()["cache-control"], "no-store");
    let key = Uuid::new_v4();
    let body = r#"{"reason":"first conservative policy"}"#;
    let first = app
        .clone()
        .oneshot(request(Method::POST, "/initialize", Some(key), body))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(first.headers()["cache-control"], "no-store");
    let first = json(first).await;
    let again = json(
        app.clone()
            .oneshot(request(Method::POST, "/initialize", Some(key), body))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(first["data"], again["data"]);
    let key = Uuid::new_v4();
    let body = r#"{"expected_version":0,"mutation":{"type":"disable_evaluate","value":false},"reason":"verified local grant remains required"}"#;
    let first = app
        .clone()
        .oneshot(request(Method::PATCH, "", Some(key), body))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    let first = json(first).await;
    let again = json(
        app.clone()
            .oneshot(request(Method::PATCH, "", Some(key), body))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(first["data"], again["data"]);
    assert_eq!(first["data"]["status"], "persisted");
    assert_eq!(client.read().unwrap().snapshot().version(), 1);
    assert!(!client.read().unwrap().snapshot().evaluate_disabled());
    let stale = app
        .oneshot(request(Method::PATCH, "", Some(Uuid::new_v4()), body))
        .await
        .unwrap();
    assert_eq!(stale.status(), StatusCode::CONFLICT);
    assert_eq!(stale.headers()["cache-control"], "no-store");
}

#[tokio::test]
async fn safety_http_exact_audit_ack_does_not_allow_holes_or_clear_current_snapshot() {
    let (service, client) = service();
    let app = app(
        service,
        principal(&["admin:safety:read", "admin:safety:write"]).unwrap(),
    );
    let body = r#"{"reason":"first conservative policy"}"#;
    app.clone()
        .oneshot(request(
            Method::POST,
            "/initialize",
            Some(Uuid::new_v4()),
            body,
        ))
        .await
        .unwrap();
    let body = r#"{"expected_version":0,"mutation":{"type":"disable_downloads","value":true},"reason":"contain downloads"}"#;
    app.clone()
        .oneshot(request(Method::PATCH, "", Some(Uuid::new_v4()), body))
        .await
        .unwrap();
    let exported = json(
        app.clone()
            .oneshot(request(Method::GET, "/audits", None, ""))
            .await
            .unwrap(),
    )
    .await;
    let items = exported["data"]["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    let second = items[1]["ack"].to_string();
    let bad = app
        .clone()
        .oneshot(request(Method::POST, "/audit-ack", None, &second))
        .await
        .unwrap();
    assert_eq!(bad.status(), StatusCode::BAD_REQUEST);
    assert_eq!(client.pending_audits(32).unwrap().len(), 2);
    for item in items {
        let ack = item["ack"].to_string();
        let response = app
            .clone()
            .oneshot(request(Method::POST, "/audit-ack", None, &ack))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
    assert!(client.pending_audits(32).unwrap().is_empty());
    assert!(client.read().unwrap().snapshot().downloads_disabled());
}

#[tokio::test]
async fn safety_http_rejects_unknown_fields_duplicate_identity_and_qualification_minting() {
    let (service, client) = service();
    let app = app(
        service,
        principal(&["admin:safety:read", "admin:safety:write"]).unwrap(),
    );
    let invalid = app
        .clone()
        .oneshot(request(
            Method::POST,
            "/initialize",
            Some(Uuid::new_v4()),
            r#"{"reason":"init","extra":true}"#,
        ))
        .await
        .unwrap();
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
    let mut duplicate = request(
        Method::POST,
        "/initialize",
        Some(Uuid::new_v4()),
        r#"{"reason":"init"}"#,
    );
    duplicate.headers_mut().append(
        "idempotency-key",
        HeaderValue::from_str(&Uuid::new_v4().to_string()).unwrap(),
    );
    assert_eq!(
        app.clone().oneshot(duplicate).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        client.read().unwrap_err(),
        SafetyAuthorityError::MissingAuthority
    );
    app.clone()
        .oneshot(request(
            Method::POST,
            "/initialize",
            Some(Uuid::new_v4()),
            r#"{"reason":"init"}"#,
        ))
        .await
        .unwrap();
    let body = r#"{"expected_version":0,"mutation":{"type":"set_shared_admission","value":{"qualified":true,"force_dedicated_process":false,"max_contexts_per_shard":8}},"reason":"caller evidence is insufficient"}"#;
    assert_eq!(
        app.oneshot(request(Method::PATCH, "", Some(Uuid::new_v4()), body))
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(client.read().unwrap().snapshot().version(), 0);
}
