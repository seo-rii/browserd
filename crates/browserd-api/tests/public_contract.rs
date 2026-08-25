#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::error::Error;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Instant;

use browserd_actions::{
    AcceptDecision, ActionLedger, DurableActionJournal, JournalEntry, JournalError, LedgerSession,
};
use browserd_api::{
    ActionSubmissionAdapter, ActionSubmitCommand, ApiEnvelope, ApiError, ApiErrorCode, ApiRequest,
    ApiResponse, ApiRouter, ApiService, ApiVersion, EventKind, EventResource, EventStore, GrpcCode,
    InMemoryApiService, PUBLIC_ROUTES, ResponseRepresentation, RuntimeApiBackend,
    SessionCreateRequest, SessionResource, decode_action_resolve, decode_action_submit,
    decode_session_create, decode_viewer_ticket, validate_idempotency_key, validate_last_event_id,
};
use browserd_auth::{
    AuthConfig, RevocationRegistry, ServiceClaims, ServiceTokenSigner, ServiceTokenVerifier,
    VerificationKeySet,
};
use browserd_core::{
    ErrorCode, IsolationProfile, OperationId, PlacementFence, PrincipalId, SessionId,
    SessionLifecycle, TenantId,
};
use chrono::{Duration, TimeZone, Utc};
use jsonwebtoken::Algorithm;
use uuid::{Uuid, Version};

const CREATE_JSON: &str = r#"{
  "isolation":"shared_context",
  "workload_class_hint":"interactive",
  "viewport":{"width":1280,"height":720,"device_scale_factor":1},
  "locale":"ko-KR",
  "timezone":"Asia/Seoul",
  "user_agent":null,
  "network_policy_id":"public-web-default",
  "network_class":"public",
  "checkpoint_ref":null,
  "dialog_policy":"auto_dismiss",
  "feature_profile":"standard",
  "ttl_seconds":1800,
  "idle_timeout_seconds":600,
  "metadata":{"agent_run_id":"run_123"}
}"#;

#[test]
fn v1_request_models_reject_unknown_fields_at_every_level() {
    assert!(decode_session_create(CREATE_JSON).is_ok());
    let top_level = CREATE_JSON.replace(
        "\"metadata\":{\"agent_run_id\":\"run_123\"}",
        "\"metadata\":{},\"tenant_id\":\"forbidden\"",
    );
    assert!(decode_session_create(&top_level).is_err());

    let nested = CREATE_JSON.replace(
        "\"device_scale_factor\":1",
        "\"device_scale_factor\":1,\"physical_width\":1920",
    );
    assert!(decode_session_create(&nested).is_err());

    let action = format!(
        r#"{{"page_id":"{}","if_session_incarnation":1,"execution_timeout_ms":30000,"action":{{"type":"navigate","url":"https://example.com","wait_until":"domcontentloaded","method":"POST"}}}}"#,
        browserd_core::PageId::new()
    );
    assert!(decode_action_submit(&action).is_err());
    assert!(
        decode_action_resolve(
            r#"{"resolution":"confirmed_executed","basis":"verified","unexpected":true}"#
        )
        .is_err()
    );
    assert!(decode_viewer_ticket(
        r#"{"scopes":{"read":true,"control":false,"admin":false},"ttl_seconds":30,"session_id":"forbidden"}"#
    )
    .is_err());
}

#[test]
fn version_and_resume_headers_are_strict() {
    assert_eq!(ApiVersion::parse("/v1"), Ok(ApiVersion::V1));
    assert!(ApiVersion::parse("v1").is_err());
    assert!(ApiVersion::parse("/v1beta").is_err());

    let idempotency = Uuid::new_v4();
    assert_eq!(
        validate_idempotency_key(&idempotency.to_string()),
        Ok(idempotency)
    );
    assert!(validate_idempotency_key("550E8400-E29B-41D4-A716-446655440000").is_err());
    assert!(validate_idempotency_key("not-a-uuid").is_err());
    assert!(validate_idempotency_key(&Uuid::nil().to_string()).is_err());

    let event_id = Uuid::now_v7();
    assert_eq!(validate_last_event_id(&event_id.to_string()), Ok(event_id));
    assert!(validate_last_event_id("01890ABC-DEF0-7ABC-8ABC-ABCDEF012345").is_err());
    assert!(validate_last_event_id(&Uuid::new_v4().to_string()).is_err());
}

#[test]
fn public_route_manifest_contains_the_required_contract() {
    let routes = PUBLIC_ROUTES.iter().copied().collect::<HashSet<_>>();
    for required in [
        "POST /v1/sessions",
        "GET /v1/sessions/{session_id}",
        "DELETE /v1/sessions/{session_id}",
        "POST /v1/sessions/{session_id}/reconnect",
        "POST /v1/sessions/{session_id}/transfer",
        "POST /v1/sessions/{session_id}/actions",
        "GET /v1/sessions/{session_id}/actions/{action_id}",
        "DELETE /v1/sessions/{session_id}/actions/{action_id}",
        "POST /v1/sessions/{session_id}/actions/{action_id}/resolve",
        "GET /v1/events",
        "POST /v1/sessions/{session_id}/viewer-ticket",
        "GET /v1/sessions/{session_id}/artifacts/{artifact_id}",
        "POST /v1/sessions/{session_id}/artifacts/{artifact_id}/download",
    ] {
        assert!(routes.contains(required), "missing route {required}");
    }
}

#[derive(Default)]
struct RecordingRuntime {
    calls: AtomicUsize,
}

impl RuntimeApiBackend for RecordingRuntime {
    fn execute_runtime(
        &self,
        _principal: &browserd_auth::AuthenticatedPrincipal,
        request: ApiRequest,
    ) -> Result<ApiResponse, ApiError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match request {
            ApiRequest::GetSession(session_id) => {
                Ok(ApiResponse::Session(ApiEnvelope::new(SessionResource {
                    id: session_id,
                    lifecycle: SessionLifecycle::Ready,
                    incarnation: 1,
                    requested_isolation: IsolationProfile::SharedContext,
                    effective_isolation: IsolationProfile::SharedContext,
                    metadata: BTreeMap::new(),
                })))
            }
            _ => Err(ApiError::new(ErrorCode::Internal, "unexpected request")),
        }
    }
}

#[test]
fn router_delegates_runtime_endpoints_through_the_typed_backend() -> Result<(), Box<dyn Error>> {
    let tenant = TenantId::new();
    let principal_id = PrincipalId::new();
    let secret = b"browserd-api-router-test-secret";
    let mut keys = VerificationKeySet::new();
    keys.insert_hmac("test", Algorithm::HS256, secret)?;
    let verifier = ServiceTokenVerifier::new(
        AuthConfig::new("issuer", "audience", [Algorithm::HS256], 0, false),
        keys,
        RevocationRegistry::new(),
    );
    let signer = ServiceTokenSigner::new("test", Algorithm::HS256, secret);
    let token = signer.sign(&ServiceClaims::new(
        "issuer",
        "audience",
        principal_id.clone(),
        tenant.clone(),
        BTreeSet::new(),
        "router-test",
        1,
        100,
        None,
    ))?;
    let principal = verifier.verify_at(&token, None, 10)?;
    let backend = Arc::new(RecordingRuntime::default());
    let router = ApiRouter::new(Arc::clone(&backend));
    let session_id = SessionId::new();

    let denied = router
        .execute(&principal, ApiRequest::GetSession(session_id.clone()))
        .expect_err("session read must require its explicit scope");
    assert_eq!(denied.code(), ErrorCode::PermissionDenied);
    assert_eq!(backend.calls.load(Ordering::SeqCst), 0);

    let scoped_token = signer.sign(&ServiceClaims::new(
        "issuer",
        "audience",
        principal_id,
        tenant,
        BTreeSet::from(["session:read".to_owned()]),
        "router-test-scoped",
        1,
        100,
        None,
    ))?;
    let scoped_principal = verifier.verify_at(&scoped_token, None, 10)?;
    let response = router.execute(
        &scoped_principal,
        ApiRequest::GetSession(session_id.clone()),
    )?;
    assert!(matches!(
        response,
        ApiResponse::Session(envelope) if envelope.data().id == session_id
    ));
    assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn error_mapping_reuses_core_codes_and_preserves_unknown_as_terminal_200() {
    let invalid = ApiErrorCode::from(ErrorCode::InvalidRequest).mapping();
    assert_eq!(invalid.http_status(), 400);
    assert_eq!(invalid.grpc_code(), GrpcCode::InvalidArgument);

    let quota = ApiErrorCode::from(ErrorCode::TenantQuotaExceeded).mapping();
    assert_eq!(quota.http_status(), 429);
    assert_eq!(quota.grpc_code(), GrpcCode::ResourceExhausted);

    let unknown = ApiErrorCode::from(ErrorCode::ActionOutcomeUnknown).mapping();
    assert_eq!(unknown.http_status(), 200);
    assert_eq!(unknown.grpc_code(), GrpcCode::Ok);
    assert_eq!(
        unknown.representation(),
        ResponseRepresentation::ActionTerminalStatus
    );
}

#[test]
fn concurrent_session_retries_return_one_canonical_operation() -> Result<(), Box<dyn Error>> {
    const CALLERS: usize = 32;
    let service = Arc::new(InMemoryApiService::default());
    let request: SessionCreateRequest = decode_session_create(CREATE_JSON)?;
    let tenant = TenantId::new();
    let key = Uuid::new_v4().to_string();
    let now = Instant::now();
    let barrier = Arc::new(Barrier::new(CALLERS));
    let mut handles = Vec::new();

    for _ in 0..CALLERS {
        let service = Arc::clone(&service);
        let request = request.clone();
        let tenant = tenant.clone();
        let key = key.clone();
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            service.create_session_for_tenant(tenant, request, &key, now)
        }));
    }

    let mut operation_ids = HashSet::new();
    for handle in handles {
        let response = handle
            .join()
            .map_err(|_| std::io::Error::other("create thread panicked"))??;
        operation_ids.insert(response.data().operation().id().clone());
        assert_eq!(
            response.data().operation().poll_url(),
            format!("/v1/operations/{}", response.data().operation().id())
        );
    }
    assert_eq!(operation_ids.len(), 1);
    assert_eq!(service.operation_count()?, 1);
    Ok(())
}

#[test]
fn same_session_key_with_a_different_body_maps_to_idempotency_conflict()
-> Result<(), Box<dyn Error>> {
    let service = InMemoryApiService::default();
    let tenant = TenantId::new();
    let key = Uuid::new_v4().to_string();
    let now = Instant::now();
    let original = decode_session_create(CREATE_JSON)?;
    let mut changed = original.clone();
    changed.locale = "en-US".to_owned();

    service.create_session_for_tenant(tenant.clone(), original, &key, now)?;
    let conflict = service
        .create_session_for_tenant(tenant, changed, &key, now)
        .expect_err("different body must conflict");
    assert_eq!(conflict.code(), ErrorCode::IdempotencyConflict);
    assert_eq!(conflict.mapping().http_status(), 409);
    Ok(())
}

#[derive(Default)]
struct MemoryJournal {
    entries: std::sync::Mutex<Vec<JournalEntry>>,
}

impl DurableActionJournal for MemoryJournal {
    fn append(&self, entry: &JournalEntry) -> Result<(), JournalError> {
        self.entries
            .lock()
            .map_err(|_| JournalError::new("journal poisoned"))?
            .push(entry.clone());
        Ok(())
    }
}

#[test]
fn concurrent_action_retries_return_one_existing_action() -> Result<(), Box<dyn Error>> {
    const CALLERS: usize = 32;
    let tenant = TenantId::new();
    let session = SessionId::new();
    let fence = PlacementFence::new(3, 5, 7);
    let ledger = Arc::new(ActionLedger::new(
        LedgerSession::new(tenant, session.clone(), fence),
        Arc::new(MemoryJournal::default()),
    ));
    let adapter = Arc::new(ActionSubmissionAdapter::new(ledger));
    let body = decode_action_submit(&format!(
        r#"{{"page_id":"{}","if_session_incarnation":7,"execution_timeout_ms":30000,"action":{{"type":"navigate","url":"https://example.com","wait_until":"domcontentloaded"}}}}"#,
        browserd_core::PageId::new()
    ))?;
    let command = ActionSubmitCommand {
        session_id: session,
        idempotency_key: Uuid::new_v4(),
        body,
    };
    let barrier = Arc::new(Barrier::new(CALLERS));
    let mut handles = Vec::new();

    for _ in 0..CALLERS {
        let adapter = Arc::clone(&adapter);
        let command = command.clone();
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            adapter.submit(fence, command)
        }));
    }

    let mut created = 0;
    let mut action_ids = HashSet::new();
    for handle in handles {
        let decision = handle
            .join()
            .map_err(|_| std::io::Error::other("action thread panicked"))??;
        if matches!(decision, AcceptDecision::Created(_)) {
            created += 1;
        }
        action_ids.insert(decision.snapshot().action_id().clone());
    }
    assert_eq!(created, 1);
    assert_eq!(action_ids.len(), 1);
    Ok(())
}

#[test]
fn event_resume_linearizes_with_concurrent_publish_without_loss_or_duplicate()
-> Result<(), Box<dyn Error>> {
    let store = Arc::new(EventStore::default());
    let tenant = TenantId::new();
    let now = Utc.timestamp_millis_opt(1_000_000).single().ok_or("time")?;
    let first = store.publish(
        tenant.clone(),
        EventKind::OperationStateChanged,
        EventResource::Operation(OperationId::new()),
        now,
    )?;
    let barrier = Arc::new(Barrier::new(2));

    let publisher_store = Arc::clone(&store);
    let publisher_tenant = tenant.clone();
    let publisher_barrier = Arc::clone(&barrier);
    let publisher = thread::spawn(move || {
        publisher_barrier.wait();
        publisher_store.publish(
            publisher_tenant,
            EventKind::SessionLifecycleChanged,
            EventResource::Session(SessionId::new()),
            now + Duration::milliseconds(1),
        )
    });
    let reader_store = Arc::clone(&store);
    let reader_tenant = tenant.clone();
    let first_id = first.event_id();
    let reader = thread::spawn(move || {
        barrier.wait();
        reader_store.resume(
            &reader_tenant,
            Some(first_id),
            10,
            now + Duration::milliseconds(1),
        )
    });

    let published = publisher
        .join()
        .map_err(|_| std::io::Error::other("publisher panicked"))??;
    let page = reader
        .join()
        .map_err(|_| std::io::Error::other("reader panicked"))??;
    let cursor = page.next_cursor().unwrap_or(first.event_id());
    let tail = store.resume(&tenant, Some(cursor), 10, now + Duration::milliseconds(2))?;
    let observed = page
        .events()
        .iter()
        .chain(tail.events())
        .map(|event| event.event_id())
        .collect::<Vec<_>>();
    assert_eq!(observed, vec![published.event_id()]);
    Ok(())
}

#[test]
fn expired_event_cursor_returns_explicit_gap_and_latest_cursor() -> Result<(), Box<dyn Error>> {
    let store = EventStore::default();
    let tenant = TenantId::new();
    let start = Utc.timestamp_millis_opt(1_000_000).single().ok_or("time")?;
    let old = store.publish(
        tenant.clone(),
        EventKind::OperationStateChanged,
        EventResource::Operation(OperationId::new()),
        start,
    )?;
    let latest = store.publish(
        tenant.clone(),
        EventKind::SessionLifecycleChanged,
        EventResource::Session(SessionId::new()),
        start + Duration::hours(25),
    )?;

    let page = store.resume(
        &tenant,
        Some(old.event_id()),
        50,
        start + Duration::hours(25),
    )?;
    assert!(page.gap());
    assert!(page.events().is_empty());
    assert_eq!(page.next_cursor(), Some(latest.event_id()));
    Ok(())
}

#[test]
fn generated_ids_used_by_headers_have_the_expected_versions() {
    assert_eq!(Uuid::new_v4().get_version(), Some(Version::Random));
    assert_eq!(Uuid::now_v7().get_version(), Some(Version::SortRand));
}
