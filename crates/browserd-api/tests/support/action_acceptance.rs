use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use browserd_actions::{
    ActionKind, ActionSequence, ActionSnapshot, ActionSnapshotFacts, CanonicalRequestHash,
    IdempotencyKey,
};
use browserd_api::{
    ApiEnvelope, ApiError, ApiResponse, ApiRouter, ApiService, CreateAuthority, DurableApiRouter,
    RuntimeApiBackend, RuntimeCreateResult, SessionCreateDispatch, SessionCreateRequest,
};
use browserd_coordination::{
    CoordinationActorConfig, CoordinationBlockingClient, MemoryCoordinationDatabase,
    MemoryCreateSessionStore, StoreConfig,
};
use browserd_core::{ActionId, ActionState, ErrorCode};

use super::{
    ActionPayload, ActionSubmitCommand, ActionSubmitRequest, ApiRequest, AuthenticatedPrincipal,
    PageId, SessionId, TenantId, Uuid, principal_with_scopes,
};

#[derive(Default)]
struct ObservedRuntime {
    observed_calls: AtomicUsize,
    ordinary_calls: AtomicUsize,
}

fn receipt(command: &ActionSubmitCommand) -> ApiEnvelope<ActionSnapshot> {
    ApiEnvelope::new(
        ActionSnapshot::from_facts(ActionSnapshotFacts {
            action_id: ActionId::new(),
            action_sequence: ActionSequence::new(1),
            idempotency_key: IdempotencyKey::new(command.idempotency_key.to_string()),
            canonical_request_hash: CanonicalRequestHash::new([1; 32]),
            kind: ActionKind::ReadOnly,
            state: ActionState::MayHaveExecuted,
            dispatch_acknowledged: false,
            approval_decision: None,
            terminal_detail: None,
            resolution: None,
            result_content: None,
        })
        .expect("valid acceptance snapshot"),
    )
}

impl RuntimeApiBackend for ObservedRuntime {
    fn create_session(
        &self,
        _: &CreateAuthority,
        _: &SessionCreateDispatch,
        _: &SessionCreateRequest,
    ) -> RuntimeCreateResult {
        RuntimeCreateResult::ConfirmedFailure(ApiError::invalid_request("not a create fixture"))
    }

    fn execute_runtime(
        &self,
        _: &AuthenticatedPrincipal,
        _: ApiRequest,
    ) -> Result<ApiResponse, ApiError> {
        self.ordinary_calls.fetch_add(1, Ordering::SeqCst);
        Err(ApiError::invalid_request(
            "ordinary request reached runtime",
        ))
    }

    fn execute_runtime_with_action_acceptance(
        &self,
        _: &AuthenticatedPrincipal,
        request: ApiRequest,
        accepted: &mut (dyn FnMut(ApiEnvelope<ActionSnapshot>) + Send),
    ) -> Result<ApiResponse, ApiError> {
        self.observed_calls.fetch_add(1, Ordering::SeqCst);
        let ApiRequest::SubmitAction(command) = request else {
            return Err(ApiError::invalid_request("unexpected observed request"));
        };
        let envelope = receipt(&command);
        accepted(envelope.clone());
        Ok(ApiResponse::Action(envelope))
    }
}

fn routers(runtime: &Arc<ObservedRuntime>) -> Vec<Box<dyn ApiService>> {
    let coordination = CoordinationBlockingClient::spawn(
        Arc::new(MemoryCreateSessionStore::attach(
            MemoryCoordinationDatabase::default(),
            StoreConfig::default(),
        )),
        CoordinationActorConfig::new(8, 2, Duration::from_secs(1), Duration::from_secs(1)).unwrap(),
    )
    .unwrap();
    vec![
        Box::new(ApiRouter::new(runtime.clone())),
        Box::new(DurableApiRouter::new(runtime.clone(), coordination)),
    ]
}

fn command() -> ActionSubmitCommand {
    ActionSubmitCommand {
        session_id: SessionId::new(),
        idempotency_key: Uuid::new_v4(),
        body: ActionSubmitRequest {
            page_id: PageId::new(),
            if_session_incarnation: 1,
            execution_timeout_ms: 1000,
            action: ActionPayload::GetTitle,
        },
    }
}

#[test]
fn both_api_routers_forward_the_exact_submit_acceptance_envelope() {
    let runtime = Arc::new(ObservedRuntime::default());
    let principal = principal_with_scopes(TenantId::new(), &["browser:act"]).unwrap();
    for router in routers(&runtime) {
        let mut accepted = Vec::new();
        let result = router
            .execute_with_action_acceptance(
                &principal,
                ApiRequest::SubmitAction(command()),
                &mut |receipt| accepted.push(receipt),
            )
            .unwrap();
        let final_receipt = match result {
            ApiResponse::Action(receipt) => Some(receipt),
            _ => None,
        }
        .expect("fixture returns an action");
        assert_eq!(accepted.len(), 1);
        assert_eq!(accepted[0].trace_id(), final_receipt.trace_id());
        assert_eq!(accepted[0].data(), final_receipt.data());
    }
    assert_eq!(runtime.observed_calls.load(Ordering::SeqCst), 2);
    assert_eq!(runtime.ordinary_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn unauthorized_and_invalid_submits_never_reach_acceptance_or_runtime() {
    let runtime = Arc::new(ObservedRuntime::default());
    let tenant = TenantId::new();
    let authorized = principal_with_scopes(tenant.clone(), &["browser:act"]).unwrap();
    let unauthorized = principal_with_scopes(tenant, &["session:read"]).unwrap();
    let mut nil_key = command();
    nil_key.idempotency_key = Uuid::nil();
    let mut invalid_body = command();
    invalid_body.body.if_session_incarnation = 0;
    let mut evaluate = command();
    evaluate.body.action = ActionPayload::Evaluate {
        expression: "1".to_owned(),
    };
    for router in routers(&runtime) {
        for (principal, command, code) in [
            (&unauthorized, command(), ErrorCode::PermissionDenied),
            (&authorized, nil_key.clone(), ErrorCode::InvalidRequest),
            (&authorized, invalid_body.clone(), ErrorCode::InvalidRequest),
            (&authorized, evaluate.clone(), ErrorCode::PermissionDenied),
        ] {
            let mut observations = 0;
            let error = router
                .execute_with_action_acceptance(
                    principal,
                    ApiRequest::SubmitAction(command),
                    &mut |_| observations += 1,
                )
                .unwrap_err();
            assert_eq!(error.code(), code);
            assert_eq!(observations, 0);
        }
    }
    assert_eq!(runtime.observed_calls.load(Ordering::SeqCst), 0);
    assert_eq!(runtime.ordinary_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn non_submit_requests_keep_the_ordinary_router_path() {
    let runtime = Arc::new(ObservedRuntime::default());
    let principal = principal_with_scopes(TenantId::new(), &["session:read"]).unwrap();
    for router in routers(&runtime) {
        let mut observed = 0;
        let result = router.execute_with_action_acceptance(
            &principal,
            ApiRequest::GetSession(SessionId::new()),
            &mut |_| observed += 1,
        );
        assert!(result.is_err());
        assert_eq!(observed, 0);
    }
    assert_eq!(runtime.observed_calls.load(Ordering::SeqCst), 0);
    assert_eq!(runtime.ordinary_calls.load(Ordering::SeqCst), 2);
}

#[derive(Default)]
struct LegacyBackend(AtomicUsize);

impl ApiService for LegacyBackend {
    fn execute(&self, _: &AuthenticatedPrincipal, _: ApiRequest) -> Result<ApiResponse, ApiError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(ApiError::invalid_request("legacy service called"))
    }
}

impl RuntimeApiBackend for LegacyBackend {
    fn create_session(
        &self,
        _: &CreateAuthority,
        _: &SessionCreateDispatch,
        _: &SessionCreateRequest,
    ) -> RuntimeCreateResult {
        RuntimeCreateResult::ConfirmedFailure(ApiError::invalid_request("unused create"))
    }
    fn execute_runtime(
        &self,
        principal: &AuthenticatedPrincipal,
        request: ApiRequest,
    ) -> Result<ApiResponse, ApiError> {
        self.execute(principal, request)
    }
}

#[test]
fn default_observer_methods_preserve_legacy_service_and_runtime_implementations() {
    let backend = LegacyBackend::default();
    let principal = principal_with_scopes(TenantId::new(), &["browser:act"]).unwrap();
    let mut calls = 0;
    assert!(
        backend
            .execute_with_action_acceptance(
                &principal,
                ApiRequest::SubmitAction(command()),
                &mut |_| calls += 1
            )
            .is_err()
    );
    assert!(
        backend
            .execute_runtime_with_action_acceptance(
                &principal,
                ApiRequest::SubmitAction(command()),
                &mut |_| calls += 1
            )
            .is_err()
    );
    assert_eq!(calls, 0);
    assert_eq!(backend.0.load(Ordering::SeqCst), 2);
}
