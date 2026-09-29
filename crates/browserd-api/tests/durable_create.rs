#![allow(clippy::expect_used, clippy::panic)]

use std::error::Error;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use browserd_api::{
    ApiError, ApiRequest, ApiResponse, ApiService, CreateAuthority, DurableApiRouter, EventKind,
    EventResource, RuntimeApiBackend, RuntimeCreateResult, SessionCreateDispatch,
    SessionCreateRequest, SessionResource, decode_session_create,
};
use browserd_auth::{
    AuthConfig, AuthenticatedPrincipal, RevocationRegistry, ServiceClaims, ServiceTokenSigner,
    ServiceTokenVerifier, VerificationKeySet,
};
use browserd_coordination::{
    CanonicalRequestHash, ClaimCreateOperation, ClaimOutcome, CoordinationActorConfig,
    CoordinationBlockingClient, CoordinationError, CreateOperationSnapshot,
    CreateSessionCoordination, EventOutbox, EventOutboxBlockingClient, MemoryCoordinationDatabase,
    MemoryCreateSessionStore, MemoryEventOutbox, OperationMutation, OutboxAppend,
    RecoverableCreateIntent, StoreConfig,
};
use browserd_core::{
    ActionId, CreateOperationState, ErrorCode, OperationId, PrincipalId, SessionId,
    SessionLifecycle, TenantId,
};
use chrono::{DateTime, Utc};
use jsonwebtoken::Algorithm;
use uuid::Uuid;

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
  "metadata":{"agent_run_id":"run_durable"}
}"#;

type DispatchRecord = (OperationId, [u8; 32], [u8; 32]);
type RecoveryDispatchRecord = (
    OperationId,
    [u8; 32],
    [u8; 32],
    PrincipalId,
    DateTime<Utc>,
    DateTime<Utc>,
    u64,
);

struct RecordingRuntime {
    calls: AtomicUsize,
}

impl RecordingRuntime {
    fn new() -> Self {
        Self {
            calls: AtomicUsize::new(0),
        }
    }
}

impl RuntimeApiBackend for RecordingRuntime {
    fn create_session(
        &self,
        _principal: &CreateAuthority,
        _dispatch: &SessionCreateDispatch,
        request: &SessionCreateRequest,
    ) -> RuntimeCreateResult {
        self.calls.fetch_add(1, Ordering::SeqCst);
        RuntimeCreateResult::Succeeded(SessionResource {
            id: SessionId::new(),
            lifecycle: SessionLifecycle::Ready,
            incarnation: 1,
            requested_isolation: request.isolation.into(),
            effective_isolation: request.isolation.into(),
            metadata: request.metadata.clone(),
        })
    }

    fn execute_runtime(
        &self,
        _principal: &AuthenticatedPrincipal,
        _request: ApiRequest,
    ) -> Result<ApiResponse, ApiError> {
        Err(ApiError::new(ErrorCode::WorkerUnavailable, "not used"))
    }
}

fn principal(
    tenant_id: TenantId,
    scopes: &[&str],
) -> Result<AuthenticatedPrincipal, Box<dyn Error>> {
    let secret = b"browserd-durable-api-test-secret";
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
        PrincipalId::new(),
        tenant_id,
        scopes.iter().map(|scope| (*scope).to_owned()).collect(),
        Uuid::new_v4().to_string(),
        1,
        100,
        None,
    ))?;
    Ok(verifier.verify_at(&token, None, 10)?)
}

fn actor(database: MemoryCoordinationDatabase) -> CoordinationBlockingClient {
    CoordinationBlockingClient::spawn(
        Arc::new(MemoryCreateSessionStore::attach(
            database,
            StoreConfig::default(),
        )),
        CoordinationActorConfig::new(32, 8, Duration::from_secs(2), Duration::from_secs(2))
            .expect("actor config should be valid"),
    )
    .expect("coordination actor should start")
}

fn create_request(body: SessionCreateRequest, key: String) -> ApiRequest {
    ApiRequest::CreateSession {
        body,
        idempotency_key: key,
        received_at: Instant::now(),
    }
}

fn create_response(response: ApiResponse) -> browserd_api::OperationEnvelope {
    match response {
        ApiResponse::SessionCreate(envelope) => envelope.data().operation().clone(),
        _ => panic!("response should be a create operation"),
    }
}

#[test]
fn concurrent_retries_dispatch_the_runtime_exactly_once() -> Result<(), Box<dyn Error>> {
    const CALLERS: usize = 16;
    let database = MemoryCoordinationDatabase::default();
    let runtime = Arc::new(RecordingRuntime::new());
    let router = Arc::new(DurableApiRouter::new(Arc::clone(&runtime), actor(database)));
    let tenant_id = TenantId::new();
    let principal = Arc::new(principal(
        tenant_id.clone(),
        &["session:create", "session:read"],
    )?);
    let body = decode_session_create(CREATE_JSON)?;
    let key = Uuid::new_v4().to_string();
    let barrier = Arc::new(Barrier::new(CALLERS));
    let mut callers = Vec::new();
    for _ in 0..CALLERS {
        let router = router.clone();
        let principal = principal.clone();
        let body = body.clone();
        let key = key.clone();
        let barrier = barrier.clone();
        callers.push(thread::spawn(move || {
            barrier.wait();
            router
                .execute(&principal, create_request(body, key))
                .map(create_response)
        }));
    }
    let mut operation_id = None;
    for caller in callers {
        let operation = caller.join().map_err(|_| "caller panicked")??;
        operation_id.get_or_insert_with(|| operation.id().clone());
        assert_eq!(
            operation.id(),
            operation_id.as_ref().expect("ID should exist")
        );
    }
    assert_eq!(runtime.calls.load(Ordering::SeqCst), 1);
    let ApiResponse::Operation(terminal) = router.execute(
        &principal,
        ApiRequest::GetOperation(operation_id.expect("operation ID should exist")),
    )?
    else {
        return Err("get should return an operation".into());
    };
    assert_eq!(terminal.data().state(), CreateOperationState::Succeeded);
    assert!(terminal.data().session().is_some());
    Ok(())
}

#[test]
fn resume_events_are_served_from_the_durable_outbox() -> Result<(), Box<dyn Error>> {
    // BRD-017 read path: with a durable outbox attached, ResumeEvents is served from the events
    // connected to durable terminal transitions, mapped to the public event taxonomy, rather than
    // from the disconnected in-memory auxiliary store.
    let database = MemoryCoordinationDatabase::default();
    let runtime = Arc::new(RecordingRuntime::new());
    let outbox: Arc<dyn EventOutbox> = Arc::new(MemoryEventOutbox::default());
    let client = EventOutboxBlockingClient::spawn(outbox, 2)?;
    let router = DurableApiRouter::new(Arc::clone(&runtime), actor(database))
        .with_event_outbox(client.clone());

    let tenant_id = TenantId::new();
    let principal = principal(tenant_id.clone(), &["events:read"])?;
    let session_id = SessionId::new();
    let action_id = ActionId::new();

    // A terminal transition recorded to the outbox (as the runtime would on completion).
    let recorded = client.append(
        OutboxAppend::action_terminal(tenant_id.clone(), session_id, action_id.clone(), 3),
        Utc::now(),
    )?;

    let ApiResponse::Events(page) = router.execute(
        &principal,
        ApiRequest::ResumeEvents {
            last_event_id: None,
            limit: 10,
            now: Utc::now(),
        },
    )?
    else {
        return Err("resume should return events".into());
    };
    let page = page.data();
    assert_eq!(page.events().len(), 1);
    let event = &page.events()[0];
    assert_eq!(event.event_id(), recorded.event_id());
    assert_eq!(event.kind(), EventKind::ActionStateChanged);
    assert_eq!(event.resource(), &EventResource::Action(action_id));
    assert!(!page.gap());
    assert_eq!(page.next_cursor(), Some(recorded.event_id()));

    // Resuming after the last delivered event yields an empty, non-gapped page.
    let ApiResponse::Events(tail) = router.execute(
        &principal,
        ApiRequest::ResumeEvents {
            last_event_id: Some(recorded.event_id()),
            limit: 10,
            now: Utc::now(),
        },
    )?
    else {
        return Err("resume should return events".into());
    };
    assert!(tail.data().events().is_empty());
    assert!(!tail.data().gap());
    Ok(())
}

#[test]
fn terminal_result_survives_router_and_store_reattachment() -> Result<(), Box<dyn Error>> {
    let database = MemoryCoordinationDatabase::default();
    let runtime = Arc::new(RecordingRuntime::new());
    let principal = principal(TenantId::new(), &["session:create", "session:read"])?;
    let body = decode_session_create(CREATE_JSON)?;
    let key = Uuid::new_v4().to_string();
    let first = DurableApiRouter::new(Arc::clone(&runtime), actor(database.clone()));
    let lost_response =
        create_response(first.execute(&principal, create_request(body.clone(), key.clone()))?);
    let original_operation_id = lost_response.id().clone();
    let original_session = lost_response
        .session()
        .expect("session should exist")
        .clone();
    drop(first);

    let restarted = DurableApiRouter::new(Arc::clone(&runtime), actor(database));
    let retry = create_response(restarted.execute(&principal, create_request(body, key))?);
    assert_eq!(retry.id(), &original_operation_id);
    assert_eq!(retry.session(), Some(&original_session));
    let json = retry.public_value();
    assert_eq!(json["session"]["requested_isolation"], "shared_context");
    assert_eq!(json["session"]["effective_isolation"], "shared_context");
    assert_eq!(runtime.calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn conflicting_body_and_cross_tenant_lookup_are_rejected() -> Result<(), Box<dyn Error>> {
    let runtime = Arc::new(RecordingRuntime::new());
    let router = DurableApiRouter::new(
        Arc::clone(&runtime),
        actor(MemoryCoordinationDatabase::default()),
    );
    let first_principal = principal(TenantId::new(), &["session:create", "session:read"])?;
    let second_principal = principal(TenantId::new(), &["session:read"])?;
    let body = decode_session_create(CREATE_JSON)?;
    let key = Uuid::new_v4().to_string();
    let created = create_response(
        router.execute(&first_principal, create_request(body.clone(), key.clone()))?,
    );
    let mut changed = body;
    changed.locale = "en-US".to_owned();
    let conflict = router
        .execute(&first_principal, create_request(changed, key))
        .expect_err("different canonical body should conflict");
    assert_eq!(conflict.code(), ErrorCode::IdempotencyConflict);
    assert_eq!(conflict.mapping().http_status(), 409);
    let hidden = router
        .execute(
            &second_principal,
            ApiRequest::GetOperation(created.id().clone()),
        )
        .expect_err("another tenant must not see the operation");
    assert_eq!(hidden.code(), ErrorCode::OperationNotFound);
    Ok(())
}

#[test]
fn concurrent_cancel_returns_one_cancelled_winner_and_creating_is_irreversible()
-> Result<(), Box<dyn Error>> {
    let database = MemoryCoordinationDatabase::default();
    let coordination = actor(database);
    let tenant_id = TenantId::new();
    let principal = Arc::new(principal(
        tenant_id.clone(),
        &["session:create", "session:read"],
    )?);
    let runtime = Arc::new(RecordingRuntime::new());
    let router = Arc::new(DurableApiRouter::new(runtime, coordination.clone()));
    let now = Utc::now();
    let operation_id = OperationId::new();
    let claim = ClaimCreateOperation::new(
        tenant_id.clone(),
        principal.principal_id().clone(),
        operation_id.clone(),
        Uuid::new_v4().to_string(),
        CanonicalRequestHash::new([9; 32]),
        RecoverableCreateIntent::new(
            &operation_id,
            serde_json::json!({}),
            now,
            now + chrono::Duration::seconds(30),
            serde_json::json!({}),
        )?,
    )?;
    let ClaimOutcome::Created(queued) = coordination.claim_create(claim, now)? else {
        return Err("claim should be created".into());
    };
    let queued = coordination.compare_and_set(
        &tenant_id,
        queued.operation_id(),
        queued.revision(),
        queued.state(),
        OperationMutation::transition(CreateOperationState::Queued),
        now,
    )?;
    let barrier = Arc::new(Barrier::new(2));
    let mut callers = Vec::new();
    for _ in 0..2 {
        let router = router.clone();
        let principal = principal.clone();
        let operation_id = queued.operation_id().clone();
        let barrier = barrier.clone();
        callers.push(thread::spawn(move || {
            barrier.wait();
            router.execute(&principal, ApiRequest::CancelOperation(operation_id))
        }));
    }
    for caller in callers {
        let ApiResponse::Operation(response) = caller.join().map_err(|_| "cancel panicked")??
        else {
            return Err("cancel should return an operation".into());
        };
        assert_eq!(response.data().state(), CreateOperationState::Cancelled);
    }

    let operation_id = OperationId::new();
    let claim = ClaimCreateOperation::new(
        tenant_id.clone(),
        principal.principal_id().clone(),
        operation_id.clone(),
        Uuid::new_v4().to_string(),
        CanonicalRequestHash::new([10; 32]),
        RecoverableCreateIntent::new(
            &operation_id,
            serde_json::json!({}),
            now,
            now + chrono::Duration::seconds(30),
            serde_json::json!({}),
        )?,
    )?;
    let ClaimOutcome::Created(mut creating) = coordination.claim_create(claim, now)? else {
        return Err("claim should be created".into());
    };
    for state in [
        CreateOperationState::Queued,
        CreateOperationState::Reserving,
    ] {
        creating = coordination.compare_and_set(
            &tenant_id,
            creating.operation_id(),
            creating.revision(),
            creating.state(),
            OperationMutation::transition(state),
            now,
        )?;
    }
    creating = coordination.acquire_dispatch_lease(
        &tenant_id,
        creating.operation_id(),
        creating.revision(),
        browserd_coordination::DispatchLeaseToken::new(),
        Duration::from_secs(30),
        now,
    )?;
    let ApiResponse::Operation(response) = router.execute(
        &principal,
        ApiRequest::CancelOperation(creating.operation_id().clone()),
    )?
    else {
        return Err("cancel should return an operation".into());
    };
    assert_eq!(response.data().state(), CreateOperationState::Creating);
    Ok(())
}

struct FailingStore;

#[async_trait]
impl CreateSessionCoordination for FailingStore {
    async fn claim_create(
        &self,
        _claim: ClaimCreateOperation,
        _now: DateTime<Utc>,
    ) -> Result<ClaimOutcome, CoordinationError> {
        Err(CoordinationError::LockUnavailable)
    }

    async fn get(
        &self,
        _tenant_id: &TenantId,
        _operation_id: &OperationId,
    ) -> Result<Option<CreateOperationSnapshot>, CoordinationError> {
        Err(CoordinationError::LockUnavailable)
    }

    async fn compare_and_set(
        &self,
        _tenant_id: &TenantId,
        _operation_id: &OperationId,
        _expected_revision: u64,
        _expected_state: CreateOperationState,
        _mutation: OperationMutation,
        _now: DateTime<Utc>,
    ) -> Result<CreateOperationSnapshot, CoordinationError> {
        Err(CoordinationError::LockUnavailable)
    }

    async fn purge_expired(&self, _now: DateTime<Utc>) -> Result<u64, CoordinationError> {
        Err(CoordinationError::LockUnavailable)
    }
}

#[test]
fn coordination_failure_is_fail_closed_before_runtime_dispatch() -> Result<(), Box<dyn Error>> {
    let runtime = Arc::new(RecordingRuntime::new());
    let coordination = CoordinationBlockingClient::spawn(
        Arc::new(FailingStore),
        CoordinationActorConfig::new(1, 1, Duration::from_secs(1), Duration::from_secs(1))?,
    )?;
    let router = DurableApiRouter::new(Arc::clone(&runtime), coordination);
    let principal = principal(TenantId::new(), &["session:create"])?;
    let error = router
        .execute(
            &principal,
            create_request(
                decode_session_create(CREATE_JSON)?,
                Uuid::new_v4().to_string(),
            ),
        )
        .expect_err("coordination failure must reject creation");
    assert_eq!(error.code(), ErrorCode::WorkerUnavailable);
    assert_eq!(runtime.calls.load(Ordering::SeqCst), 0);
    Ok(())
}

struct FailFirstCompletionStore {
    inner: MemoryCreateSessionStore,
    failed: AtomicBool,
}

#[async_trait]
impl CreateSessionCoordination for FailFirstCompletionStore {
    async fn claim_create(
        &self,
        claim: ClaimCreateOperation,
        now: DateTime<Utc>,
    ) -> Result<ClaimOutcome, CoordinationError> {
        self.inner.claim_create(claim, now).await
    }

    async fn get(
        &self,
        tenant_id: &TenantId,
        operation_id: &OperationId,
    ) -> Result<Option<CreateOperationSnapshot>, CoordinationError> {
        self.inner.get(tenant_id, operation_id).await
    }

    async fn compare_and_set(
        &self,
        tenant_id: &TenantId,
        operation_id: &OperationId,
        expected_revision: u64,
        expected_state: CreateOperationState,
        mutation: OperationMutation,
        now: DateTime<Utc>,
    ) -> Result<CreateOperationSnapshot, CoordinationError> {
        if mutation.next_state() == CreateOperationState::Succeeded
            && !self.failed.swap(true, Ordering::SeqCst)
        {
            return Err(CoordinationError::LockUnavailable);
        }
        self.inner
            .compare_and_set(
                tenant_id,
                operation_id,
                expected_revision,
                expected_state,
                mutation,
                now,
            )
            .await
    }

    async fn purge_expired(&self, now: DateTime<Utc>) -> Result<u64, CoordinationError> {
        self.inner.purge_expired(now).await
    }

    async fn acquire_dispatch_lease(
        &self,
        tenant_id: &TenantId,
        operation_id: &OperationId,
        expected_revision: u64,
        token: browserd_coordination::DispatchLeaseToken,
        ttl: Duration,
        now: DateTime<Utc>,
    ) -> Result<CreateOperationSnapshot, CoordinationError> {
        self.inner
            .acquire_dispatch_lease(tenant_id, operation_id, expected_revision, token, ttl, now)
            .await
    }

    async fn scan_reconcilable(
        &self,
        limit: usize,
        now: DateTime<Utc>,
    ) -> Result<Vec<CreateOperationSnapshot>, CoordinationError> {
        self.inner.scan_reconcilable(limit, now).await
    }
}

struct RecoveryRuntime {
    calls: Mutex<Vec<DispatchRecord>>,
    session: SessionResource,
}

impl RuntimeApiBackend for RecoveryRuntime {
    fn create_session(
        &self,
        _principal: &CreateAuthority,
        dispatch: &SessionCreateDispatch,
        _request: &SessionCreateRequest,
    ) -> RuntimeCreateResult {
        self.calls.lock().expect("test calls lock").push((
            dispatch.operation_id().clone(),
            dispatch.downstream_dedupe_key().as_bytes(),
            *dispatch.canonical_request_hash(),
        ));
        RuntimeCreateResult::Succeeded(self.session.clone())
    }

    fn execute_runtime(
        &self,
        _principal: &AuthenticatedPrincipal,
        _request: ApiRequest,
    ) -> Result<ApiResponse, ApiError> {
        Err(ApiError::new(ErrorCode::WorkerUnavailable, "not used"))
    }
}

#[test]
fn expired_dispatch_lease_has_one_recovery_owner_and_persists_the_terminal_result()
-> Result<(), Box<dyn Error>> {
    const RECOVERY_CALLERS: usize = 8;
    let database = MemoryCoordinationDatabase::default();
    let store = Arc::new(FailFirstCompletionStore {
        inner: MemoryCreateSessionStore::attach(database, StoreConfig::default()),
        failed: AtomicBool::new(false),
    });
    let coordination = CoordinationBlockingClient::spawn(
        store,
        CoordinationActorConfig::new(32, 8, Duration::from_secs(1), Duration::from_secs(1))?,
    )?;
    let recovered_session = SessionResource {
        id: SessionId::new(),
        lifecycle: SessionLifecycle::Ready,
        incarnation: 1,
        requested_isolation: browserd_core::IsolationProfile::SharedContext,
        effective_isolation: browserd_core::IsolationProfile::SharedContext,
        metadata: Default::default(),
    };
    let runtime = Arc::new(RecoveryRuntime {
        calls: Mutex::new(Vec::new()),
        session: recovered_session.clone(),
    });
    let router = Arc::new(DurableApiRouter::with_dispatch_lease_duration(
        Arc::clone(&runtime),
        coordination,
        Duration::from_millis(250),
    )?);
    let tenant_id = TenantId::new();
    let principal = Arc::new(principal(
        tenant_id.clone(),
        &["session:create", "session:read"],
    )?);
    let body = decode_session_create(CREATE_JSON)?;
    let key = Uuid::new_v4().to_string();

    let first = router.execute(&principal, create_request(body.clone(), key.clone()));
    assert!(matches!(first, Err(error) if error.code() == ErrorCode::WorkerUnavailable));
    assert_eq!(runtime.calls.lock().map_err(|_| "calls poisoned")?.len(), 1);

    let before_expiry =
        create_response(router.execute(&principal, create_request(body.clone(), key.clone()))?);
    assert_eq!(before_expiry.state(), CreateOperationState::Creating);
    assert_eq!(runtime.calls.lock().map_err(|_| "calls poisoned")?.len(), 1);
    let operation_id = before_expiry.id().clone();

    thread::sleep(Duration::from_millis(300));
    let barrier = Arc::new(Barrier::new(RECOVERY_CALLERS));
    let mut callers = Vec::new();
    for _ in 0..RECOVERY_CALLERS {
        let router = router.clone();
        let principal = principal.clone();
        let body = body.clone();
        let key = key.clone();
        let barrier = barrier.clone();
        callers.push(thread::spawn(move || {
            barrier.wait();
            router
                .execute(&principal, create_request(body, key))
                .map(create_response)
        }));
    }
    for caller in callers {
        let response = caller.join().map_err(|_| "recovery caller panicked")??;
        assert_eq!(response.id(), &operation_id);
    }

    let calls = runtime.calls.lock().map_err(|_| "calls poisoned")?;
    assert_eq!(calls.len(), 2);
    assert!(calls.iter().all(|(id, retry_key, hash)| {
        id == &operation_id && retry_key == &calls[0].1 && hash == &calls[0].2
    }));
    drop(calls);
    let ApiResponse::Operation(terminal) =
        router.execute(&principal, ApiRequest::GetOperation(operation_id))?
    else {
        return Err("get should return an operation".into());
    };
    assert_eq!(terminal.data().state(), CreateOperationState::Succeeded);
    assert_eq!(terminal.data().session(), Some(&recovered_session));
    Ok(())
}

struct AmbiguousOnceRuntime {
    calls: Mutex<Vec<RecoveryDispatchRecord>>,
    first: AtomicBool,
    session: SessionResource,
}

impl RuntimeApiBackend for AmbiguousOnceRuntime {
    fn create_session(
        &self,
        authority: &CreateAuthority,
        dispatch: &SessionCreateDispatch,
        _request: &SessionCreateRequest,
    ) -> RuntimeCreateResult {
        self.calls.lock().expect("test calls lock").push((
            dispatch.operation_id().clone(),
            dispatch.downstream_dedupe_key().as_bytes(),
            *dispatch.canonical_request_hash(),
            authority.principal_id().clone(),
            dispatch.accepted_at(),
            dispatch.admission_deadline(),
            dispatch.dispatch_generation(),
        ));
        if self.first.swap(false, Ordering::SeqCst) {
            return RuntimeCreateResult::OutcomeUnknown(ApiError::new(
                ErrorCode::WorkerUnavailable,
                "response lost after worker side effect",
            ));
        }
        RuntimeCreateResult::Succeeded(self.session.clone())
    }

    fn execute_runtime(
        &self,
        _principal: &AuthenticatedPrincipal,
        _request: ApiRequest,
    ) -> Result<ApiResponse, ApiError> {
        Err(ApiError::new(ErrorCode::WorkerUnavailable, "not used"))
    }
}

#[test]
fn ambiguous_worker_error_preserves_the_dispatch_lease_for_one_expiry_recovery()
-> Result<(), Box<dyn Error>> {
    const RECOVERY_CALLERS: usize = 8;
    let database = MemoryCoordinationDatabase::default();
    let coordination = actor(database.clone());
    let session = SessionResource {
        id: SessionId::new(),
        lifecycle: SessionLifecycle::Ready,
        incarnation: 1,
        requested_isolation: browserd_core::IsolationProfile::SharedContext,
        effective_isolation: browserd_core::IsolationProfile::SharedContext,
        metadata: Default::default(),
    };
    let runtime = Arc::new(AmbiguousOnceRuntime {
        calls: Mutex::new(Vec::new()),
        first: AtomicBool::new(true),
        session: session.clone(),
    });
    let router = Arc::new(DurableApiRouter::with_dispatch_lease_duration(
        Arc::clone(&runtime),
        coordination,
        Duration::from_millis(250),
    )?);
    let tenant_id = TenantId::new();
    let original_principal = Arc::new(principal(
        tenant_id.clone(),
        &["session:create", "session:read"],
    )?);
    let body = decode_session_create(CREATE_JSON)?;
    let key = Uuid::new_v4().to_string();

    let ambiguous = router.execute(
        &original_principal,
        create_request(body.clone(), key.clone()),
    );
    assert!(matches!(
        ambiguous,
        Err(error) if error.code() == ErrorCode::WorkerUnavailable
    ));
    let before_expiry = create_response(router.execute(
        &original_principal,
        create_request(body.clone(), key.clone()),
    )?);
    assert_eq!(before_expiry.state(), CreateOperationState::Creating);
    assert_eq!(runtime.calls.lock().map_err(|_| "calls poisoned")?.len(), 1);
    let operation_id = before_expiry.id().clone();
    drop(router);

    thread::sleep(Duration::from_millis(300));
    let recovery_principal = Arc::new(principal(tenant_id, &["session:read"])?);
    let router = Arc::new(DurableApiRouter::with_dispatch_lease_duration(
        Arc::clone(&runtime),
        actor(database),
        Duration::from_millis(250),
    )?);
    let barrier = Arc::new(Barrier::new(RECOVERY_CALLERS));
    let mut callers = Vec::new();
    for _ in 0..RECOVERY_CALLERS {
        let router = router.clone();
        let principal = recovery_principal.clone();
        let operation_id = operation_id.clone();
        let barrier = barrier.clone();
        callers.push(thread::spawn(move || {
            barrier.wait();
            let ApiResponse::Operation(response) =
                router.execute(&principal, ApiRequest::GetOperation(operation_id))?
            else {
                return Err(ApiError::new(ErrorCode::Internal, "expected operation"));
            };
            Ok(response.data().clone())
        }));
    }
    for caller in callers {
        assert_eq!(
            caller.join().map_err(|_| "recovery caller panicked")??.id(),
            &operation_id
        );
    }
    let calls = runtime.calls.lock().map_err(|_| "calls poisoned")?;
    assert_eq!(calls.len(), 2);
    assert!(calls.iter().all(|call| {
        call.0 == operation_id
            && call.1 == calls[0].1
            && call.2 == calls[0].2
            && call.3 == calls[0].3
            && call.4 == calls[0].4
            && call.5 == calls[0].5
    }));
    assert_eq!(calls[0].6, 1);
    assert_eq!(calls[1].6, 2);
    drop(calls);
    let ApiResponse::Operation(terminal) =
        router.execute(&recovery_principal, ApiRequest::GetOperation(operation_id))?
    else {
        return Err("get should return an operation".into());
    };
    assert_eq!(terminal.data().state(), CreateOperationState::Succeeded);
    assert_eq!(terminal.data().session(), Some(&session));
    Ok(())
}

struct ConfirmedFailureRuntime;

impl RuntimeApiBackend for ConfirmedFailureRuntime {
    fn create_session(
        &self,
        _authority: &CreateAuthority,
        _dispatch: &SessionCreateDispatch,
        _request: &SessionCreateRequest,
    ) -> RuntimeCreateResult {
        RuntimeCreateResult::ConfirmedFailure(
            ApiError::new(ErrorCode::InvalidRequest, "policy rejected exact message")
                .with_failure_metadata(true, [("policy".to_owned(), "blocked".to_owned())].into()),
        )
    }

    fn execute_runtime(
        &self,
        _principal: &AuthenticatedPrincipal,
        _request: ApiRequest,
    ) -> Result<ApiResponse, ApiError> {
        Err(ApiError::new(ErrorCode::WorkerUnavailable, "not used"))
    }
}

struct SlowRuntime {
    active: AtomicUsize,
    max_active: AtomicUsize,
}

impl RuntimeApiBackend for SlowRuntime {
    fn create_session(
        &self,
        _authority: &CreateAuthority,
        _dispatch: &SessionCreateDispatch,
        request: &SessionCreateRequest,
    ) -> RuntimeCreateResult {
        let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.max_active.fetch_max(active, Ordering::SeqCst);
        thread::sleep(Duration::from_millis(500));
        self.active.fetch_sub(1, Ordering::SeqCst);
        RuntimeCreateResult::Succeeded(SessionResource {
            id: SessionId::new(),
            lifecycle: SessionLifecycle::Ready,
            incarnation: 1,
            requested_isolation: request.isolation.into(),
            effective_isolation: request.isolation.into(),
            metadata: request.metadata.clone(),
        })
    }
    fn execute_runtime(
        &self,
        _principal: &AuthenticatedPrincipal,
        _request: ApiRequest,
    ) -> Result<ApiResponse, ApiError> {
        Err(ApiError::new(ErrorCode::WorkerUnavailable, "not used"))
    }
}

#[test]
fn lease_is_renewed_while_a_slow_create_prevents_overlap() -> Result<(), Box<dyn Error>> {
    let runtime = Arc::new(SlowRuntime {
        active: AtomicUsize::new(0),
        max_active: AtomicUsize::new(0),
    });
    let router = Arc::new(DurableApiRouter::with_dispatch_lease_duration(
        Arc::clone(&runtime),
        actor(MemoryCoordinationDatabase::default()),
        Duration::from_millis(250),
    )?);
    let principal = Arc::new(principal(
        TenantId::new(),
        &["session:create", "session:read"],
    )?);
    let key = Uuid::new_v4().to_string();
    let body = decode_session_create(CREATE_JSON)?;
    let first_router = router.clone();
    let first_principal = principal.clone();
    let first_body = body.clone();
    let first_key = key.clone();
    let first = thread::spawn(move || {
        first_router.execute(&first_principal, create_request(first_body, first_key))
    });
    thread::sleep(Duration::from_millis(300));
    let retry = router.execute(&principal, create_request(body, key))?;
    assert_eq!(
        create_response(retry).state(),
        CreateOperationState::Creating
    );
    assert!(matches!(
        first.join().map_err(|_| "slow create panicked")??,
        ApiResponse::SessionCreate(_)
    ));
    assert_eq!(runtime.max_active.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn get_enforces_persisted_admission_deadline_without_dispatch() -> Result<(), Box<dyn Error>> {
    let coordination = actor(MemoryCoordinationDatabase::default());
    let tenant = TenantId::new();
    let principal = principal(tenant.clone(), &["session:read"])?;
    let operation_id = OperationId::new();
    let accepted = Utc::now() - chrono::Duration::seconds(2);
    let body = decode_session_create(CREATE_JSON)?;
    let intent = RecoverableCreateIntent::new(
        &operation_id,
        serde_json::to_value(body)?,
        accepted,
        accepted + chrono::Duration::seconds(1),
        serde_json::json!({}),
    )?;
    coordination.claim_create(
        ClaimCreateOperation::new(
            tenant,
            principal.principal_id().clone(),
            operation_id.clone(),
            Uuid::new_v4().to_string(),
            CanonicalRequestHash::new([44; 32]),
            intent,
        )?,
        Utc::now(),
    )?;
    let runtime = Arc::new(RecordingRuntime::new());
    let router = DurableApiRouter::new(Arc::clone(&runtime), coordination);
    let ApiResponse::Operation(response) =
        router.execute(&principal, ApiRequest::GetOperation(operation_id))?
    else {
        return Err("expected operation".into());
    };
    assert_eq!(response.data().state(), CreateOperationState::TimedOut);
    assert_eq!(
        response
            .data()
            .failure()
            .map(|failure| failure.code.as_str()),
        Some("admission_timeout")
    );
    assert_eq!(runtime.calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn confirmed_failure_details_survive_restart_and_are_http_serializable()
-> Result<(), Box<dyn Error>> {
    let database = MemoryCoordinationDatabase::default();
    let tenant = TenantId::new();
    let principal = principal(tenant.clone(), &["session:create", "session:read"])?;
    let router = DurableApiRouter::new(Arc::new(ConfirmedFailureRuntime), actor(database.clone()));
    let operation = create_response(router.execute(
        &principal,
        create_request(
            decode_session_create(CREATE_JSON)?,
            Uuid::new_v4().to_string(),
        ),
    )?);
    assert_eq!(operation.state(), CreateOperationState::Failed);
    let operation_id = operation.id().clone();
    drop(router);
    let restarted = DurableApiRouter::new(Arc::new(ConfirmedFailureRuntime), actor(database));
    let ApiResponse::Operation(response) =
        restarted.execute(&principal, ApiRequest::GetOperation(operation_id))?
    else {
        return Err("expected operation".into());
    };
    let failure = response.data().failure().ok_or("missing failure")?;
    assert_eq!(failure.code, "invalid_request");
    assert_eq!(failure.message, "policy rejected exact message");
    assert!(failure.retryable);
    assert_eq!(
        failure.details.get("policy").map(String::as_str),
        Some("blocked")
    );
    let json = response.data().public_value();
    assert_eq!(json["failure"]["details"]["policy"], "blocked");
    Ok(())
}
