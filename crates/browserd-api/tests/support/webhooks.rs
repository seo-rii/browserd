use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use browserd_api::*;
use browserd_coordination::*;
use browserd_core::{ErrorCode, TenantId};
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
        RuntimeCreateResult::ConfirmedFailure(ApiError::new(ErrorCode::WorkerUnavailable, "unused"))
    }
    fn execute_runtime(
        &self,
        _: &browserd_auth::AuthenticatedPrincipal,
        _: ApiRequest,
    ) -> Result<ApiResponse, ApiError> {
        Err(ApiError::new(
            ErrorCode::WorkerUnavailable,
            "browser must not be consulted",
        ))
    }
}
#[derive(Default)]
struct Keys {
    fail: AtomicBool,
    calls: AtomicUsize,
}
impl WebhookSigningKeyProvider for Keys {
    fn active_master_version_id(&self) -> &str {
        "test-master"
    }
    fn derive(
        &self,
        _: &TenantId,
        reference: &WebhookSigningKeyRef,
    ) -> Result<WebhookSigningSecret, WebhookKeyError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail.load(Ordering::SeqCst) {
            return Err(WebhookKeyError::Unavailable);
        }
        let mut bytes = [0; 32];
        bytes[..16].copy_from_slice(reference.key_id().as_bytes());
        bytes[16..].copy_from_slice(reference.key_id().as_bytes());
        Ok(WebhookSigningSecret::new(bytes))
    }
}
fn actor_config() -> CoordinationActorConfig {
    CoordinationActorConfig::new(16, 4, Duration::from_secs(2), Duration::from_secs(2)).unwrap()
}
fn fixture() -> (WebhookBlockingClient, Arc<Keys>) {
    let outbox = MemoryEventOutbox::new(Duration::from_secs(86_400)).unwrap();
    let store = MemoryWebhookStore::new(outbox, WebhookStoreConfig::default()).unwrap();
    (
        WebhookBlockingClient::spawn(Arc::new(store), actor_config()).unwrap(),
        Arc::new(Keys::default()),
    )
}
fn put(key: Uuid, revision: Option<u64>, url: &str) -> ApiRequest {
    ApiRequest::Webhook(WebhookRequest::Put {
        body: WebhookPutBody {
            url: url.to_owned(),
            expected_revision: revision,
        },
        idempotency_key: key,
    })
}
fn response(value: ApiResponse) -> ApiEnvelope<WebhookEndpointResponse> {
    let ApiResponse::WebhookEndpoint(value) = value else {
        unreachable!()
    };
    value
}

#[test]
fn webhook_scope_validation_precedes_storage_and_key_derivation() {
    let (store, keys) = fixture();
    let tenant = TenantId::new();
    let principal = principal_with_scopes(tenant.clone(), &["webhooks:read"]).unwrap();
    let router = ApiRouter::new(Arc::new(NoBrowser))
        .with_webhooks(WebhookApi::new(store.clone(), keys.clone()));
    assert_eq!(
        router
            .execute(
                &principal,
                put(Uuid::new_v4(), None, "https://receiver.test/hook")
            )
            .unwrap_err()
            .code(),
        ErrorCode::PermissionDenied
    );
    assert!(store.get_endpoint(&tenant).unwrap().is_none());
    assert_eq!(keys.calls.load(Ordering::SeqCst), 0);
    let writer = principal_with_scopes(tenant.clone(), &["webhooks:write"]).unwrap();
    assert!(
        router
            .execute(
                &writer,
                put(Uuid::new_v4(), None, "http://receiver.test/hook")
            )
            .is_err()
    );
    assert!(store.get_endpoint(&tenant).unwrap().is_none());
    assert_eq!(keys.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn webhook_lost_key_reply_replays_committed_key_and_get_never_reveals_secret() {
    let (store, keys) = fixture();
    let tenant = TenantId::new();
    let principal =
        principal_with_scopes(tenant.clone(), &["webhooks:write", "webhooks:read"]).unwrap();
    let key = Uuid::new_v4();
    keys.fail.store(true, Ordering::SeqCst);
    let router = ApiRouter::new(Arc::new(NoBrowser))
        .with_webhooks(WebhookApi::new(store.clone(), keys.clone()));
    assert!(
        router
            .execute(&principal, put(key, None, "https://receiver.test/hook"))
            .is_err()
    );
    let committed = store.get_endpoint(&tenant).unwrap().unwrap();
    assert_eq!(committed.endpoint_ref().revision(), 1);
    drop(router);
    keys.fail.store(false, Ordering::SeqCst);
    let restarted = ApiRouter::new(Arc::new(NoBrowser))
        .with_webhooks(WebhookApi::new(store.clone(), keys.clone()));
    let retried = response(
        restarted
            .execute(&principal, put(key, None, "https://receiver.test/hook"))
            .unwrap(),
    );
    assert_eq!(retried.data().endpoint, committed);
    let again = response(
        restarted
            .execute(&principal, put(key, None, "https://receiver.test/hook"))
            .unwrap(),
    );
    assert!(
        retried.data().signing_secret.as_ref().unwrap().as_bytes()
            == again.data().signing_secret.as_ref().unwrap().as_bytes()
    );
    assert!(!format!("{retried:?}").contains("receiver.test"));
    let calls = keys.calls.load(Ordering::SeqCst);
    let get = response(
        restarted
            .execute(&principal, ApiRequest::Webhook(WebhookRequest::Get))
            .unwrap(),
    );
    assert!(get.data().signing_secret.is_none());
    assert_eq!(keys.calls.load(Ordering::SeqCst), calls);
    assert_eq!(
        restarted
            .execute(&principal, put(key, None, "https://other.test/hook"))
            .unwrap_err()
            .code(),
        ErrorCode::IdempotencyConflict
    );
    assert_eq!(keys.calls.load(Ordering::SeqCst), calls);
    let foreign = principal_with_scopes(TenantId::new(), &["webhooks:read"]).unwrap();
    assert_eq!(
        restarted
            .execute(&foreign, ApiRequest::Webhook(WebhookRequest::Get))
            .unwrap_err()
            .code(),
        ErrorCode::OperationNotFound
    );
}

#[test]
fn webhook_mutation_retries_preserve_revision_after_replacement_and_never_return_key() {
    let (store, keys) = fixture();
    let principal =
        principal_with_scopes(TenantId::new(), &["webhooks:read", "webhooks:write"]).unwrap();
    let router =
        ApiRouter::new(Arc::new(NoBrowser)).with_webhooks(WebhookApi::new(store.clone(), keys));
    let first = response(
        router
            .execute(
                &principal,
                put(Uuid::new_v4(), None, "https://receiver.test/hook"),
            )
            .unwrap(),
    );
    let delete_key = Uuid::new_v4();
    let delete = || {
        ApiRequest::Webhook(WebhookRequest::Delete {
            body: WebhookDeleteBody {
                expected_revision: 1,
            },
            idempotency_key: delete_key,
        })
    };
    let deleted = response(router.execute(&principal, delete()).unwrap());
    assert!(deleted.data().signing_secret.is_none());
    assert_eq!(
        deleted.data().endpoint.status(),
        WebhookEndpointStatus::Deleted
    );
    let replacement = response(
        router
            .execute(
                &principal,
                put(Uuid::new_v4(), Some(2), "https://receiver.test/new"),
            )
            .unwrap(),
    );
    assert_eq!(
        replacement.data().endpoint.endpoint_ref().endpoint_id(),
        first.data().endpoint.endpoint_ref().endpoint_id()
    );
    let old_replay = response(router.execute(&principal, delete()).unwrap());
    assert_eq!(old_replay.data().endpoint, deleted.data().endpoint);
    assert_eq!(
        store.get_endpoint(principal.tenant_id()).unwrap().unwrap(),
        replacement.data().endpoint
    );
    assert!(
        router
            .execute(
                &principal,
                put(Uuid::new_v4(), Some(1), "https://receiver.test/stale")
            )
            .is_err()
    );
}

#[test]
fn webhook_resume_uses_exact_revision_and_replays_without_key_derivation() {
    let (store, keys) = fixture();
    let principal =
        principal_with_scopes(TenantId::new(), &["webhooks:read", "webhooks:write"]).unwrap();
    let router = ApiRouter::new(Arc::new(NoBrowser))
        .with_webhooks(WebhookApi::new(store.clone(), keys.clone()));
    let endpoint = response(
        router
            .execute(
                &principal,
                put(Uuid::new_v4(), None, "https://receiver.test/hook"),
            )
            .unwrap(),
    );
    let suspended = store
        .suspend_endpoint(
            endpoint.data().endpoint.endpoint_ref(),
            WebhookMutationBinding::new(
                principal.tenant_id().clone(),
                principal.principal_id().clone(),
                Uuid::new_v4().to_string(),
                [7; 32],
            )
            .unwrap(),
        )
        .unwrap();
    let key = Uuid::new_v4();
    let resume = |revision| {
        ApiRequest::Webhook(WebhookRequest::Resume {
            body: WebhookResumeBody {
                expected_revision: revision,
                mode: browserd_api::WebhookResumeMode::Continue,
            },
            idempotency_key: key,
        })
    };
    let calls = keys.calls.load(Ordering::SeqCst);
    assert_eq!(
        router.execute(&principal, resume(1)).unwrap_err().code(),
        ErrorCode::IdempotencyConflict
    );
    let resumed = response(
        router
            .execute(&principal, resume(suspended.endpoint_ref().revision()))
            .unwrap(),
    );
    assert_eq!(
        resumed.data().endpoint.status(),
        WebhookEndpointStatus::Active
    );
    assert!(resumed.data().signing_secret.is_none());
    let replay = response(
        router
            .execute(&principal, resume(suspended.endpoint_ref().revision()))
            .unwrap(),
    );
    assert_eq!(replay.data().endpoint, resumed.data().endpoint);
    assert_eq!(keys.calls.load(Ordering::SeqCst), calls);
}

#[test]
fn durable_polling_preserves_the_exact_shared_wire_for_all_nine_kinds() {
    use browserd_core::{ActionId, ApprovalId, ArtifactId, OperationId, SessionId};
    use chrono::Utc;
    let tenant = TenantId::new();
    let session = SessionId::new();
    let action = ActionId::new();
    let outbox = Arc::new(MemoryEventOutbox::new(Duration::from_secs(86_400)).unwrap());
    let client = EventOutboxBlockingClient::spawn(outbox, 1).unwrap();
    let session_aggregate = OutboxAggregate::Session {
        session_id: session.clone(),
    };
    let action_aggregate = OutboxAggregate::Action {
        session_id: session.clone(),
        action_id: action.clone(),
    };
    let artifact_aggregate = OutboxAggregate::Artifact {
        session_id: session.clone(),
        artifact_id: ArtifactId::new(),
    };
    let cases = [
        (
            OutboxAggregate::Operation {
                operation_id: OperationId::new(),
            },
            OutboxEventKind::OperationStateChanged,
            EventStateSummary::Operation {
                state: EventOperationState::Queued,
            },
        ),
        (
            session_aggregate.clone(),
            OutboxEventKind::SessionLifecycleChanged,
            EventStateSummary::SessionLifecycle {
                state: EventSessionLifecycleState::Ready,
            },
        ),
        (
            session_aggregate.clone(),
            OutboxEventKind::SessionExecutionChanged,
            EventStateSummary::SessionExecution {
                state: EventSessionExecutionState::Running,
                action_id: Some(action.clone()),
            },
        ),
        (
            action_aggregate.clone(),
            OutboxEventKind::ActionStateChanged,
            EventStateSummary::Action {
                state: EventActionState::Succeeded,
                resolution: None,
            },
        ),
        (
            action_aggregate,
            OutboxEventKind::ActionApprovalRequired,
            EventStateSummary::ApprovalRequired {
                approval_id: ApprovalId::new(),
            },
        ),
        (
            OutboxAggregate::Approval {
                session_id: session,
                action_id: action,
                approval_id: ApprovalId::new(),
            },
            OutboxEventKind::ApprovalDecided,
            EventStateSummary::Approval {
                state: EventApprovalDecision::Approved,
            },
        ),
        (
            session_aggregate,
            OutboxEventKind::BrowserControlChanged,
            EventStateSummary::Control {
                state: EventControlState::Human,
            },
        ),
        (
            artifact_aggregate.clone(),
            OutboxEventKind::DownloadCompleted,
            EventStateSummary::Download {
                state: EventDownloadState::Completed,
            },
        ),
        (
            artifact_aggregate,
            OutboxEventKind::ArtifactStateChanged,
            EventStateSummary::Artifact {
                state: EventArtifactState::Available,
            },
        ),
    ];
    let mut expected = Vec::new();
    for (aggregate, kind, summary) in cases {
        let event = client
            .append(
                OutboxAppend::state_changed(tenant.clone(), aggregate, 1, kind, summary).unwrap(),
                Utc::now(),
            )
            .unwrap();
        expected.push(encode_outbox_event(&event).unwrap());
    }
    let creates = CoordinationBlockingClient::spawn(
        Arc::new(MemoryCreateSessionStore::attach(
            MemoryCoordinationDatabase::default(),
            StoreConfig::default(),
        )),
        actor_config(),
    )
    .unwrap();
    let router = DurableApiRouter::new(Arc::new(NoBrowser), creates).with_event_outbox(client);
    let principal = principal_with_scopes(tenant, &["events:read"]).unwrap();
    let ApiResponse::Events(page) = router
        .execute(
            &principal,
            ApiRequest::ResumeEvents {
                last_event_id: None,
                limit: 100,
                now: Utc::now(),
            },
        )
        .unwrap()
    else {
        unreachable!()
    };
    assert_eq!(page.data().events().len(), 9);
    for (event, expected) in page.data().events().iter().zip(expected) {
        assert_eq!(serde_json::to_vec(&event.public_wire()).unwrap(), expected);
    }
}
