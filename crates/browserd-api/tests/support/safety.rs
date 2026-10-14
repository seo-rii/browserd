#![allow(clippy::panic)]

use std::sync::Arc;
use std::time::Duration;

use browserd_api::*;
use browserd_coordination::*;
use browserd_core::{ErrorCode, SafetySwitchMutation, TenantId};
use serde_json::Value;
use uuid::Uuid;

use super::principal_with_scopes;

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
            "unavailable browser",
        ))
    }
    fn execute_runtime(
        &self,
        _: &browserd_auth::AuthenticatedPrincipal,
        _: ApiRequest,
    ) -> Result<ApiResponse, ApiError> {
        Err(ApiError::new(
            ErrorCode::WorkerUnavailable,
            "browser cannot serve operator safety requests",
        ))
    }
}
fn fixture() -> (SafetyAuthorityBlockingClient, ApiRouter<NoBrowser>) {
    let client = SafetyAuthorityBlockingClient::spawn(
        Arc::new(MemorySafetyAuthority::default()),
        CoordinationActorConfig::new(16, 4, Duration::from_secs(2), Duration::from_secs(2))
            .unwrap(),
    )
    .unwrap();
    let router = ApiRouter::new(Arc::new(NoBrowser)).with_safety(SafetyApi::new(client.clone()));
    (client, router)
}
fn initialize(key: Uuid) -> ApiRequest {
    ApiRequest::Safety(SafetyRequest::Initialize {
        body: SafetyInitializeBody {
            reason: "initial conservative policy".into(),
        },
        idempotency_key: key,
    })
}
fn mutation(key: Uuid, version: u64, mutation: SafetySwitchMutation) -> ApiRequest {
    ApiRequest::Safety(SafetyRequest::Mutate {
        body: SafetyMutationBody {
            expected_version: version,
            mutation,
            reason: "runtime containment".into(),
        },
        idempotency_key: key,
    })
}
fn value(response: ApiResponse) -> Value {
    let ApiResponse::Safety(envelope) = response else {
        panic!("expected safety response")
    };
    envelope.data().clone()
}

#[test]
fn operator_scope_precedes_validation_and_never_initializes_on_ordinary_read() {
    let (client, router) = fixture();
    let reader = principal_with_scopes(TenantId::new(), &["admin:safety:read"]).unwrap();
    assert_eq!(
        router
            .execute(&reader, initialize(Uuid::nil()))
            .unwrap_err()
            .code(),
        ErrorCode::PermissionDenied
    );
    assert_eq!(
        client.read().unwrap_err(),
        SafetyAuthorityError::MissingAuthority
    );
    assert_eq!(
        router
            .execute(&reader, ApiRequest::Safety(SafetyRequest::Get))
            .unwrap_err()
            .code(),
        ErrorCode::WorkerUnavailable
    );
    assert_eq!(
        client.read().unwrap_err(),
        SafetyAuthorityError::MissingAuthority
    );
}

#[test]
fn safety_initialize_and_update_retry_exact_receipts_without_browser_readiness() {
    let (client, router) = fixture();
    let tenant = TenantId::new();
    let writer =
        principal_with_scopes(tenant.clone(), &["admin:safety:read", "admin:safety:write"])
            .unwrap();
    let key = Uuid::new_v4();
    let first = value(router.execute(&writer, initialize(key)).unwrap());
    assert_eq!(first["status"], "persisted");
    assert_eq!(first["receipt"]["version"], 0);
    assert_eq!(
        value(router.execute(&writer, initialize(key)).unwrap()),
        first
    );
    assert_eq!(
        router
            .execute(&writer, initialize(Uuid::new_v4()))
            .unwrap_err()
            .code(),
        ErrorCode::IdempotencyConflict
    );
    let key = Uuid::new_v4();
    let first = value(
        router
            .execute(
                &writer,
                mutation(key, 0, SafetySwitchMutation::DisableDownloads(true)),
            )
            .unwrap(),
    );
    assert_eq!(first["receipt"]["version"], 1);
    let restarted = ApiRouter::new(Arc::new(NoBrowser)).with_safety(SafetyApi::new(client.clone()));
    assert_eq!(
        value(
            restarted
                .execute(
                    &writer,
                    mutation(key, 0, SafetySwitchMutation::DisableDownloads(true))
                )
                .unwrap()
        ),
        first
    );
    assert_eq!(
        restarted
            .execute(
                &writer,
                mutation(key, 0, SafetySwitchMutation::DisableDownloads(false))
            )
            .unwrap_err()
            .code(),
        ErrorCode::IdempotencyConflict
    );
    let other = principal_with_scopes(tenant, &["admin:safety:write"]).unwrap();
    assert_eq!(
        restarted
            .execute(
                &other,
                mutation(key, 0, SafetySwitchMutation::DisableDownloads(true))
            )
            .unwrap_err()
            .code(),
        ErrorCode::IdempotencyConflict
    );
    assert!(client.read().unwrap().snapshot().downloads_disabled());
    assert_eq!(client.pending_audits(32).unwrap().len(), 2);
}

#[test]
fn runtime_updates_cannot_grant_qualification_and_stale_versions_do_not_mutate() {
    let (client, router) = fixture();
    let writer = principal_with_scopes(TenantId::new(), &["admin:safety:write"]).unwrap();
    router.execute(&writer, initialize(Uuid::new_v4())).unwrap();
    let initial = client.read().unwrap();
    assert_eq!(
        router
            .execute(
                &writer,
                mutation(
                    Uuid::new_v4(),
                    0,
                    SafetySwitchMutation::SetSharedAdmission {
                        qualified: true,
                        force_dedicated_process: false,
                        max_contexts_per_shard: 8
                    }
                )
            )
            .unwrap_err()
            .code(),
        ErrorCode::InvalidRequest
    );
    assert_eq!(client.read().unwrap(), initial);
    assert_eq!(
        router
            .execute(
                &writer,
                mutation(
                    Uuid::new_v4(),
                    7,
                    SafetySwitchMutation::DisableEvaluate(false)
                )
            )
            .unwrap_err()
            .code(),
        ErrorCode::IdempotencyConflict
    );
    assert_eq!(client.read().unwrap(), initial);
    assert_eq!(client.pending_audits(32).unwrap().len(), 1);
}

#[test]
fn operator_audit_export_and_ack_preserve_exact_oldest_order_and_current_policy() {
    let (client, router) = fixture();
    let writer = principal_with_scopes(
        TenantId::new(),
        &["admin:safety:read", "admin:safety:write"],
    )
    .unwrap();
    router.execute(&writer, initialize(Uuid::new_v4())).unwrap();
    router
        .execute(
            &writer,
            mutation(
                Uuid::new_v4(),
                0,
                SafetySwitchMutation::DisableCheckpoint(true),
            ),
        )
        .unwrap();
    let before = client.read().unwrap();
    let exported = value(
        router
            .execute(&writer, ApiRequest::Safety(SafetyRequest::Audits))
            .unwrap(),
    );
    let rows = exported["items"].as_array().unwrap();
    let first: SafetyAuditAck = serde_json::from_value(rows[0]["ack"].clone()).unwrap();
    let second: SafetyAuditAck = serde_json::from_value(rows[1]["ack"].clone()).unwrap();
    assert_eq!(
        router
            .execute(
                &writer,
                ApiRequest::Safety(SafetyRequest::AckAudit(second.clone()))
            )
            .unwrap_err()
            .code(),
        ErrorCode::InvalidRequest
    );
    router
        .execute(
            &writer,
            ApiRequest::Safety(SafetyRequest::AckAudit(first.clone())),
        )
        .unwrap();
    router
        .execute(&writer, ApiRequest::Safety(SafetyRequest::AckAudit(first)))
        .unwrap();
    router
        .execute(&writer, ApiRequest::Safety(SafetyRequest::AckAudit(second)))
        .unwrap();
    assert!(client.pending_audits(32).unwrap().is_empty());
    assert_eq!(client.read().unwrap(), before);
}
