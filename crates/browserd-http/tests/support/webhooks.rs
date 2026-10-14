use super::*;
use browserd_api::{
    ApiRouter, CreateAuthority, RuntimeApiBackend, RuntimeCreateResult, SessionCreateDispatch,
    SessionCreateRequest, WebhookApi, WebhookKeyError, WebhookSigningKeyProvider,
    WebhookSigningSecret,
};
use browserd_coordination::{
    CoordinationActorConfig, MemoryEventOutbox, MemoryWebhookStore, WebhookBlockingClient,
    WebhookSigningKeyRef, WebhookStoreConfig,
};

struct Keys(AtomicBool);
impl WebhookSigningKeyProvider for Keys {
    fn active_master_version_id(&self) -> &str {
        "http-fixture"
    }
    fn derive(
        &self,
        _: &TenantId,
        r: &WebhookSigningKeyRef,
    ) -> Result<WebhookSigningSecret, WebhookKeyError> {
        self.0.store(true, Ordering::SeqCst);
        let mut value = [0; 32];
        value[..16].copy_from_slice(r.key_id().as_bytes());
        Ok(WebhookSigningSecret::new(value))
    }
}
struct NoBrowser;
impl RuntimeApiBackend for NoBrowser {
    fn create_session(
        &self,
        _: &CreateAuthority,
        _: &SessionCreateDispatch,
        _: &SessionCreateRequest,
    ) -> RuntimeCreateResult {
        RuntimeCreateResult::ConfirmedFailure(ApiError::new(ErrorCode::WorkerUnavailable, "unused"))
    }
    fn execute_runtime(
        &self,
        _: &AuthenticatedPrincipal,
        _: ApiRequest,
    ) -> Result<ApiResponse, ApiError> {
        Err(ApiError::new(ErrorCode::WorkerUnavailable, "unused"))
    }
}
fn service() -> (Arc<dyn ApiService>, Arc<Keys>) {
    let keys = Arc::new(Keys(AtomicBool::new(false)));
    let outbox = MemoryEventOutbox::new(Duration::from_secs(86_400)).unwrap();
    let client = WebhookBlockingClient::spawn(
        Arc::new(MemoryWebhookStore::new(outbox, WebhookStoreConfig::default()).unwrap()),
        CoordinationActorConfig::new(16, 4, Duration::from_secs(2), Duration::from_secs(2))
            .unwrap(),
    )
    .unwrap();
    (
        Arc::new(
            ApiRouter::new(Arc::new(NoBrowser))
                .with_webhooks(WebhookApi::new(client, keys.clone())),
        ),
        keys,
    )
}
fn request(method: Method, path: &str, key: Uuid, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", "Bearer valid")
        .header("content-type", "application/json")
        .header("idempotency-key", key.to_string())
        .body(Body::from(body.to_string()))
        .unwrap()
}
async fn json(response: axum::response::Response) -> serde_json::Value {
    serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
}

#[tokio::test]
async fn webhook_http_put_retry_returns_same_key_but_get_and_delete_never_do() {
    let (service, _) = service();
    let app = app(
        service,
        principal(&["webhooks:read", "webhooks:write"]).unwrap(),
    );
    let key = Uuid::new_v4();
    let body = serde_json::json!({"url":"https://receiver.test/hook","expected_revision":null});
    let first = app
        .clone()
        .oneshot(request(
            Method::PUT,
            "/v1/webhook-endpoint",
            key,
            body.clone(),
        ))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(first.headers()["cache-control"], "no-store");
    let first = json(first).await;
    assert!(
        first["data"]["signing_secret"]
            .as_str()
            .is_some_and(|v| v.len() == 43)
    );
    let retry = json(
        app.clone()
            .oneshot(request(Method::PUT, "/v1/webhook-endpoint", key, body))
            .await
            .unwrap(),
    )
    .await;
    assert!(first["data"]["signing_secret"] == retry["data"]["signing_secret"]);
    assert_eq!(
        first["data"]["signing_key_id"],
        retry["data"]["signing_key_id"]
    );
    let get = Request::builder()
        .uri("/v1/webhook-endpoint")
        .header("authorization", "Bearer valid")
        .body(Body::empty())
        .unwrap();
    let get = json(app.clone().oneshot(get).await.unwrap()).await;
    assert!(get["data"].get("signing_secret").is_none());
    assert_eq!(get["data"]["revision"], 1);
    let deleted = json(
        app.oneshot(request(
            Method::DELETE,
            "/v1/webhook-endpoint",
            Uuid::new_v4(),
            serde_json::json!({"expected_revision":1}),
        ))
        .await
        .unwrap(),
    )
    .await;
    assert_eq!(deleted["data"]["status"], "deleted");
    assert!(deleted["data"].get("signing_secret").is_none());
}

#[tokio::test]
async fn webhook_http_rejects_missing_scope_duplicate_headers_and_unknown_fields_before_key_use() {
    let (service, keys) = service();
    let read_only = app(service.clone(), principal(&["webhooks:read"]).unwrap());
    let body = serde_json::json!({"url":"https://receiver.test/hook","expected_revision":null});
    assert_eq!(
        read_only
            .oneshot(request(
                Method::PUT,
                "/v1/webhook-endpoint",
                Uuid::new_v4(),
                body.clone()
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert!(!keys.0.load(Ordering::SeqCst));
    let app = app(service, principal(&["webhooks:write"]).unwrap());
    let mut duplicate = request(
        Method::PUT,
        "/v1/webhook-endpoint",
        Uuid::new_v4(),
        body.clone(),
    );
    duplicate.headers_mut().append(
        "idempotency-key",
        Uuid::new_v4().to_string().parse().unwrap(),
    );
    assert_eq!(
        app.clone().oneshot(duplicate).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
    for body in [
        serde_json::json!({"url":"https://receiver.test/hook","expected_revision":0}),
        serde_json::json!({"url":"https://receiver.test/hook","signing_secret":"caller-secret"}),
        serde_json::json!({"url":"http://receiver.test/hook"}),
    ] {
        assert_eq!(
            app.clone()
                .oneshot(request(
                    Method::PUT,
                    "/v1/webhook-endpoint",
                    Uuid::new_v4(),
                    body
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::BAD_REQUEST
        );
    }
    assert_eq!(
        app.clone()
            .oneshot(request(
                Method::PUT,
                "/v1/webhook-endpoint?unknown=true",
                Uuid::new_v4(),
                body
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert!(!keys.0.load(Ordering::SeqCst));
    assert_eq!(
        app.oneshot(request(
            Method::POST,
            "/v1/webhook-endpoint/resume",
            Uuid::new_v4(),
            serde_json::json!({"expected_revision":1,"mode":{"type":"accept_gap_to_tail"}})
        ))
        .await
        .unwrap()
        .status(),
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn event_http_includes_resource_and_revision_with_webhooks_unconfigured() {
    let principal = principal(&["events:read"]).unwrap();
    let session = SessionId::new();
    let service = Arc::new(InMemoryApiService::default());
    service
        .publish_event(
            principal.tenant_id().clone(),
            browserd_api::EventKind::BrowserControlChanged,
            browserd_api::EventResource::Session(session.clone()),
            Utc::now(),
        )
        .unwrap();
    let response = app(service, principal)
        .oneshot(
            Request::builder()
                .uri("/v1/events")
                .header("authorization", "Bearer valid")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let value = json(response).await;
    let event = &value["data"]["events"][0];
    assert_eq!(event["kind"], "browser.control.changed");
    assert_eq!(
        event["resource"],
        serde_json::json!({"type":"session","id":session})
    );
    assert_eq!(event["aggregate_revision"], 0);
    assert!(event.get("summary").is_none());
}
