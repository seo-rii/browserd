#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use browser_gateway::{
    GatewayWorkerClient, GatewayWorkerPending, GatewayWorkerPlacement, GatewayWorkerRuntime,
};
use browserd_actions::{ResultDigest, TerminalDetail};
use browserd_api::{
    ActionPayload, ActionSubmitCommand, ActionSubmitRequest, ApiRequest, ApiResponse, ApiRouter,
    ApiService, decode_session_create,
};
use browserd_auth::{
    AuthConfig, AuthenticatedPrincipal, RevocationRegistry, ServiceClaims, ServiceTokenSigner,
    ServiceTokenVerifier, VerificationKeySet,
};
use browserd_coordination::{
    CoordinationActorConfig, MemoryCoordinationDatabase, MemoryGatewayActionStore, StoreConfig,
};
use browserd_core::{ErrorCode, PageId, PrincipalId, SessionId, TenantId, WorkerId};
use browserd_worker::{
    WorkerActionReceipt, WorkerActionStatus, WorkerCreateSessionReceipt,
    WorkerCreateSessionRequest, WorkerIsolationProfile, WorkerRpcCompletionError,
    WorkerRpcEnqueueError, WorkerRpcError, WorkerRpcRequest, WorkerRpcResponse,
    WorkerSessionLifecycle, WorkerSessionOwnershipReceipt, WorkerSessionReceipt,
};
use jsonwebtoken::Algorithm;
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use uuid::Uuid;

const BODY: &str = r#"{"isolation":"dedicated_process","workload_class_hint":"interactive","viewport":{"width":1280,"height":720,"device_scale_factor":1},"locale":"ko-KR","timezone":"Asia/Seoul","user_agent":null,"network_policy_id":"public-web-default","network_class":"public","checkpoint_ref":null,"dialog_policy":"auto_dismiss","feature_profile":"standard","ttl_seconds":1800,"idle_timeout_seconds":600,"metadata":{"test":"directory"}}"#;
const RESULT: &[u8] = br#"{"title":"one effect"}"#;

struct Pending(WorkerActionReceipt);
impl GatewayWorkerPending for Pending {
    fn wait(self) -> Result<WorkerRpcResponse, WorkerRpcCompletionError> {
        Ok(WorkerRpcResponse::Action(self.0))
    }
}
struct Worker {
    id: WorkerId,
    session: SessionId,
    page: PageId,
    creates: AtomicUsize,
    dispatches: AtomicUsize,
    reads: AtomicUsize,
    wrong_fence: Mutex<bool>,
    lifecycle: Mutex<WorkerSessionLifecycle>,
    ready: Mutex<bool>,
}
impl GatewayWorkerClient for Worker {
    type PendingAction = Pending;
    fn create_session(
        &self,
        request: WorkerCreateSessionRequest,
    ) -> Result<WorkerCreateSessionReceipt, WorkerRpcError> {
        self.creates.fetch_add(1, Ordering::SeqCst);
        Ok(WorkerCreateSessionReceipt {
            operation_id: request.operation_id,
            tenant_id: request.tenant_id,
            session_id: self.session.clone(),
            session_incarnation: request.session_incarnation,
            effective_isolation: WorkerIsolationProfile::DedicatedProcess,
            primary_page_id: self.page.clone(),
            worker_epoch: request.expected_worker_epoch,
            placement_version: request.placement_version,
            existing: false,
            restored_checkpoint: None,
        })
    }
    fn request(&self, request: WorkerRpcRequest) -> Result<WorkerRpcResponse, WorkerRpcError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        if let WorkerRpcRequest::Probe {
            expected_worker_epoch,
        } = &request
        {
            return Ok(WorkerRpcResponse::Probe(
                browserd_worker::WorkerProbeReceipt {
                    worker_id: self.id.clone(),
                    worker_epoch: *expected_worker_epoch,
                    ready: *self.ready.lock().unwrap(),
                },
            ));
        }
        let (mut fence, inspect) = match request {
            WorkerRpcRequest::GetSession { fence } => (fence, false),
            WorkerRpcRequest::InspectSession {
                expected_worker_id,
                fence,
            } if expected_worker_id == self.id => (fence, true),
            _ => return Err(WorkerRpcError::InvalidRequest),
        };
        if *self.wrong_fence.lock().unwrap() {
            fence.session_incarnation += 1;
        }
        let session = WorkerSessionReceipt {
            fence,
            lifecycle: *self.lifecycle.lock().unwrap(),
            primary_page_id: self.page.clone(),
        };
        Ok(if inspect {
            WorkerRpcResponse::SessionOwnership(WorkerSessionOwnershipReceipt {
                worker_id: self.id.clone(),
                session,
            })
        } else {
            WorkerRpcResponse::Session(session)
        })
    }
    fn enqueue_action(&self, request: WorkerRpcRequest) -> Result<Pending, WorkerRpcEnqueueError> {
        let WorkerRpcRequest::SubmitAction {
            fence,
            action_id,
            action_sequence,
            idempotency_key,
            canonical_request_hash,
            kind,
            ..
        } = request
        else {
            return Err(WorkerRpcEnqueueError::Closed(Box::new(request)));
        };
        self.dispatches.fetch_add(1, Ordering::SeqCst);
        Ok(Pending(WorkerActionReceipt {
            fence,
            action_id,
            action_sequence,
            idempotency_key,
            canonical_request_hash,
            kind,
            status: WorkerActionStatus::Succeeded,
            dispatch_acknowledged: true,
            approval_decision: None,
            terminal_detail: Some(TerminalDetail::Succeeded(ResultDigest::new(
                Sha256::digest(RESULT).into(),
            ))),
            result: Some(RESULT.to_vec()),
            resolution: None,
            custody: None,
            custody_requirement: None,
        }))
    }
}
type Runtime = GatewayWorkerRuntime<Worker>;
struct Fixture {
    worker: Arc<Worker>,
    store: Arc<MemoryGatewayActionStore>,
    database: MemoryCoordinationDatabase,
    principal: AuthenticatedPrincipal,
}
impl Fixture {
    fn new() -> Self {
        let tenant = TenantId::new();
        let secret = [17u8; 32];
        let mut keys = VerificationKeySet::new();
        keys.insert_hmac("directory", Algorithm::HS256, &secret)
            .unwrap();
        let verifier = ServiceTokenVerifier::new(
            AuthConfig::new("issuer", "audience", [Algorithm::HS256], 0, false),
            keys,
            RevocationRegistry::new(),
        );
        let claims = ServiceClaims::new(
            "issuer",
            "audience",
            PrincipalId::new(),
            tenant,
            [
                "session:create",
                "session:read",
                "session:list",
                "session:close",
                "browser:act",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
            "directory",
            100,
            400,
            None,
        );
        let token = ServiceTokenSigner::new("directory", Algorithm::HS256, &secret)
            .sign(&claims)
            .unwrap();
        let principal = verifier.verify_at(&token, None, 200).unwrap();
        let database = MemoryCoordinationDatabase::default();
        Self {
            worker: Arc::new(Worker {
                id: WorkerId::new("directory-worker").unwrap(),
                session: SessionId::new(),
                page: PageId::new(),
                creates: AtomicUsize::new(0),
                dispatches: AtomicUsize::new(0),
                reads: AtomicUsize::new(0),
                wrong_fence: Mutex::new(false),
                lifecycle: Mutex::new(WorkerSessionLifecycle::Ready),
                ready: Mutex::new(true),
            }),
            store: Arc::new(MemoryGatewayActionStore::attach(
                database.clone(),
                StoreConfig::default(),
            )),
            database,
            principal,
        }
    }
    fn gateway(&self) -> Arc<Runtime> {
        self.gateway_with_store(self.store.clone(), 7)
    }
    fn gateway_with_store(&self, store: Arc<MemoryGatewayActionStore>, epoch: u64) -> Arc<Runtime> {
        Arc::new(
            GatewayWorkerRuntime::with_action_coordination(
                self.worker.clone(),
                GatewayWorkerPlacement::new(self.worker.id.clone(), epoch, 3, 5).unwrap(),
                store,
                CoordinationActorConfig::default(),
            )
            .unwrap()
            .with_durable_session_directory(),
        )
    }
    fn create(&self, runtime: Arc<Runtime>) {
        let response = ApiRouter::new(runtime)
            .execute(
                &self.principal,
                ApiRequest::CreateSession {
                    body: decode_session_create(BODY).unwrap(),
                    idempotency_key: Uuid::new_v4().to_string(),
                    received_at: Instant::now(),
                },
            )
            .unwrap();
        assert!(matches!(response, ApiResponse::SessionCreate(_)));
    }
    fn command(&self, key: Uuid) -> ActionSubmitCommand {
        ActionSubmitCommand {
            session_id: self.worker.session.clone(),
            idempotency_key: key,
            body: ActionSubmitRequest {
                page_id: self.worker.page.clone(),
                if_session_incarnation: 1,
                execution_timeout_ms: 1000,
                action: ActionPayload::GetTitle,
            },
        }
    }
}
#[test]
fn second_gateway_rehydrates_exact_single_host_session_without_creating_browser() {
    let f = Fixture::new();
    f.create(f.gateway());
    let response = ApiRouter::new(f.gateway())
        .execute(
            &f.principal,
            ApiRequest::GetSession(f.worker.session.clone()),
        )
        .expect("durable session lookup after gateway replacement");
    assert!(matches!(response, ApiResponse::Session(_)));
    assert_eq!(f.worker.creates.load(Ordering::SeqCst), 1);
}
#[test]
fn restart_terminal_same_key_replays_original_body_without_dispatch() {
    let f = Fixture::new();
    let first = f.gateway();
    f.create(first.clone());
    let key = Uuid::new_v4();
    let ApiResponse::Action(original) = ApiRouter::new(first)
        .execute(&f.principal, ApiRequest::SubmitAction(f.command(key)))
        .unwrap()
    else {
        panic!("action expected");
    };
    let ApiResponse::Action(replayed) = ApiRouter::new(f.gateway())
        .execute(&f.principal, ApiRequest::SubmitAction(f.command(key)))
        .expect("same-key terminal replay without a memory session")
    else {
        panic!("action expected");
    };
    assert_eq!(replayed.data(), original.data());
    assert_eq!(replayed.data().result_content(), Some(RESULT));
    assert_eq!(f.worker.dispatches.load(Ordering::SeqCst), 1);
    assert_eq!(f.worker.creates.load(Ordering::SeqCst), 1);
}
#[test]
fn rehydrated_session_requires_exact_live_worker_fence_before_new_dispatch() {
    let f = Fixture::new();
    f.create(f.gateway());
    *f.worker.wrong_fence.lock().unwrap() = true;
    let error = ApiRouter::new(f.gateway())
        .execute(
            &f.principal,
            ApiRequest::SubmitAction(f.command(Uuid::new_v4())),
        )
        .expect_err("changed incarnation cannot admit an effect");
    assert_eq!(error.code(), ErrorCode::PlacementMismatch);
    assert_eq!(f.worker.dispatches.load(Ordering::SeqCst), 0);
}

#[test]
fn replaced_coordination_client_recovers_directory_and_terminal_same_key_body() {
    let f = Fixture::new();
    let original = f.gateway();
    f.create(original.clone());
    let key = Uuid::new_v4();
    ApiRouter::new(original)
        .execute(&f.principal, ApiRequest::SubmitAction(f.command(key)))
        .unwrap();
    let replacement = Arc::new(MemoryGatewayActionStore::attach(
        f.database.clone(),
        StoreConfig::default(),
    ));
    let restored = f.gateway_with_store(replacement, 7);
    let ApiResponse::Action(receipt) = ApiRouter::new(restored.clone())
        .execute(&f.principal, ApiRequest::SubmitAction(f.command(key)))
        .unwrap()
    else {
        panic!("action expected");
    };
    assert_eq!(receipt.data().result_content(), Some(RESULT));
    assert!(matches!(
        ApiRouter::new(restored)
            .execute(
                &f.principal,
                ApiRequest::GetSession(f.worker.session.clone())
            )
            .unwrap(),
        ApiResponse::Session(_)
    ));
    assert_eq!(f.worker.creates.load(Ordering::SeqCst), 1);
    assert_eq!(f.worker.dispatches.load(Ordering::SeqCst), 1);
}

#[test]
fn two_gateways_concurrently_submit_one_effect_for_the_same_key() {
    let f = Fixture::new();
    f.create(f.gateway());
    let first = f.gateway();
    let second = f.gateway_with_store(
        Arc::new(MemoryGatewayActionStore::attach(
            f.database.clone(),
            StoreConfig::default(),
        )),
        7,
    );
    let barrier = Arc::new(std::sync::Barrier::new(3));
    let key = Uuid::new_v4();
    let mut tasks = Vec::new();
    for gateway in [first, second] {
        let principal = f.principal.clone();
        let command = f.command(key);
        let barrier = barrier.clone();
        tasks.push(std::thread::spawn(move || {
            barrier.wait();
            ApiRouter::new(gateway).execute(&principal, ApiRequest::SubmitAction(command))
        }));
    }
    barrier.wait();
    let ids = tasks
        .into_iter()
        .map(|task| {
            let ApiResponse::Action(receipt) = task.join().unwrap().unwrap() else {
                panic!("action expected");
            };
            receipt.data().action_id().clone()
        })
        .collect::<Vec<_>>();
    assert_eq!(ids[0], ids[1]);
    assert_eq!(f.worker.dispatches.load(Ordering::SeqCst), 1);
    assert_eq!(f.worker.creates.load(Ordering::SeqCst), 1);
}

#[test]
fn completed_same_key_replay_needs_no_live_fence_but_new_effect_does() {
    let f = Fixture::new();
    let original = f.gateway();
    f.create(original.clone());
    let key = Uuid::new_v4();
    ApiRouter::new(original)
        .execute(&f.principal, ApiRequest::SubmitAction(f.command(key)))
        .unwrap();
    *f.worker.wrong_fence.lock().unwrap() = true;
    *f.worker.lifecycle.lock().unwrap() = WorkerSessionLifecycle::Closed;
    let reads = f.worker.reads.load(Ordering::SeqCst);
    let replacement = f.gateway();
    let ApiResponse::Action(replay) = ApiRouter::new(replacement.clone())
        .execute(&f.principal, ApiRequest::SubmitAction(f.command(key)))
        .unwrap()
    else {
        panic!("action expected");
    };
    assert_eq!(replay.data().result_content(), Some(RESULT));
    assert_eq!(f.worker.reads.load(Ordering::SeqCst), reads);
    let error = ApiRouter::new(replacement)
        .execute(
            &f.principal,
            ApiRequest::SubmitAction(f.command(Uuid::new_v4())),
        )
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::PlacementMismatch);
    assert_eq!(f.worker.dispatches.load(Ordering::SeqCst), 1);
}

#[test]
fn changed_epoch_or_body_cannot_dispatch_against_old_directory_or_key() {
    let f = Fixture::new();
    let original = f.gateway();
    f.create(original.clone());
    let key = Uuid::new_v4();
    ApiRouter::new(original)
        .execute(&f.principal, ApiRequest::SubmitAction(f.command(key)))
        .unwrap();
    let stale = f.gateway_with_store(f.store.clone(), 8);
    let error = ApiRouter::new(stale)
        .execute(
            &f.principal,
            ApiRequest::SubmitAction(f.command(Uuid::new_v4())),
        )
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::PlacementMismatch);
    let mut changed = f.command(key);
    changed.body.execution_timeout_ms += 1;
    let error = ApiRouter::new(f.gateway())
        .execute(&f.principal, ApiRequest::SubmitAction(changed))
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::IdempotencyConflict);
    assert_eq!(f.worker.dispatches.load(Ordering::SeqCst), 1);
}

#[test]
fn current_session_fence_without_live_ready_worker_does_not_admit_an_effect() {
    let f = Fixture::new();
    f.create(f.gateway());
    *f.worker.ready.lock().unwrap() = false;
    let runtime = f.gateway();
    assert!(matches!(
        ApiRouter::new(runtime.clone())
            .execute(
                &f.principal,
                ApiRequest::GetSession(f.worker.session.clone())
            )
            .unwrap(),
        ApiResponse::Session(_)
    ));
    let error = ApiRouter::new(runtime)
        .execute(
            &f.principal,
            ApiRequest::SubmitAction(f.command(Uuid::new_v4())),
        )
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::WorkerUnavailable);
    assert_eq!(f.worker.dispatches.load(Ordering::SeqCst), 0);
}

#[test]
fn replaced_gateway_lists_durable_tenant_sessions_without_worker_calls_or_prior_get() {
    let f = Fixture::new();
    let original = f.gateway();
    f.create(original.clone());
    let ApiResponse::Sessions(before) = ApiRouter::new(original)
        .execute(
            &f.principal,
            ApiRequest::ListSessions(browserd_api::SessionListQuery::default()),
        )
        .unwrap()
    else {
        panic!("session page");
    };
    assert_eq!(before.data().items().len(), 1);
    let reads = f.worker.reads.load(Ordering::SeqCst);
    let replacement = f.gateway_with_store(
        Arc::new(MemoryGatewayActionStore::attach(
            f.database.clone(),
            StoreConfig::default(),
        )),
        7,
    );
    let ApiResponse::Sessions(after) = ApiRouter::new(replacement)
        .execute(
            &f.principal,
            ApiRequest::ListSessions(browserd_api::SessionListQuery::default()),
        )
        .unwrap()
    else {
        panic!("session page");
    };
    assert_eq!(
        after.data().items().len(),
        1,
        "durable listing cannot be empty until GET hydrates a local cache"
    );
    assert_eq!(after.data().items()[0].id, f.worker.session);
    assert_eq!(
        f.worker.reads.load(Ordering::SeqCst),
        reads,
        "listing does not issue a Worker RPC for every record"
    );
    assert_eq!(f.worker.creates.load(Ordering::SeqCst), 1);
}

#[test]
fn durable_sparse_listing_preserves_bounded_progress_without_worker_reads() {
    use browserd_coordination::{
        DirectoryFence, GatewayActionCoordination, GatewayActionPlacement,
        GatewayDirectoryLifecycle, GatewaySessionDirectoryRecord, GatewaySessionIsolation,
    };
    let f = Fixture::new();
    let actor = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    actor.block_on(async {
        for index in 1..=600 {
            let session = SessionId::from_uuid(Uuid::from_u128(
                0x0000_0000_0000_7000_8000_0000_0000_0000 | index,
            ))
            .unwrap();
            let mut metadata = std::collections::BTreeMap::new();
            if index == 600 {
                metadata.insert("needle".to_owned(), "present".to_owned());
            }
            let placement = GatewayActionPlacement::new(
                DirectoryFence::new(f.worker.id.clone(), 7, 3, 1).unwrap(),
                5,
            )
            .unwrap();
            let record = GatewaySessionDirectoryRecord::new(
                f.principal.tenant_id().clone(),
                session,
                placement,
                GatewayDirectoryLifecycle::Ready,
                GatewaySessionIsolation::DedicatedProcess,
                GatewaySessionIsolation::DedicatedProcess,
                metadata,
            )
            .unwrap();
            f.store
                .commit_single_host_directory(record, None)
                .await
                .unwrap();
        }
    });
    let gateway = f.gateway();
    let mut query = browserd_api::SessionListQuery {
        metadata_key: Some("needle".to_owned()),
        limit: 10,
        ..browserd_api::SessionListQuery::default()
    };
    let mut found = 0;
    for index in 0..3 {
        let ApiResponse::Sessions(page) = ApiRouter::new(gateway.clone())
            .execute(&f.principal, ApiRequest::ListSessions(query.clone()))
            .unwrap()
        else {
            panic!("session page");
        };
        found += page.data().items().len();
        if index < 2 {
            assert!(page.data().items().is_empty());
            assert!(page.data().next_page_token().is_some());
        }
        query.page_token = page.data().next_page_token().map(str::to_owned);
    }
    assert_eq!(found, 1);
    assert!(query.page_token.is_none());
    assert_eq!(f.worker.reads.load(Ordering::SeqCst), 0);
    assert_eq!(f.worker.creates.load(Ordering::SeqCst), 0);
}

#[test]
fn positively_confirmed_terminal_directory_survives_gateway_replacement_and_never_readmits() {
    let f = Fixture::new();
    f.create(f.gateway());
    *f.worker.lifecycle.lock().unwrap() = WorkerSessionLifecycle::Closed;
    let ApiResponse::Session(first) = ApiRouter::new(f.gateway())
        .execute(
            &f.principal,
            ApiRequest::GetSession(f.worker.session.clone()),
        )
        .unwrap()
    else {
        panic!("session");
    };
    assert_eq!(
        first.data().lifecycle,
        browserd_core::SessionLifecycle::Closed
    );
    let reads = f.worker.reads.load(Ordering::SeqCst);
    *f.worker.wrong_fence.lock().unwrap() = true;
    let ApiResponse::Session(restored) = ApiRouter::new(f.gateway())
        .execute(
            &f.principal,
            ApiRequest::GetSession(f.worker.session.clone()),
        )
        .unwrap()
    else {
        panic!("session");
    };
    assert_eq!(
        restored.data().lifecycle,
        browserd_core::SessionLifecycle::Closed
    );
    assert_eq!(f.worker.reads.load(Ordering::SeqCst), reads);
    let error = ApiRouter::new(f.gateway())
        .execute(
            &f.principal,
            ApiRequest::SubmitAction(f.command(Uuid::new_v4())),
        )
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::SessionNotFound);
    assert_eq!(f.worker.dispatches.load(Ordering::SeqCst), 0);
}
