#![allow(clippy::too_many_lines)]

use std::collections::BTreeSet;
use std::error::Error;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use browser_gateway::{
    GatewayWorkerClient, GatewayWorkerPending, GatewayWorkerPlacement, GatewayWorkerRuntime,
};
use browserd_actions::{
    ActionSequence, BrowserResult, DispatchId, ResolutionAnnotation, TerminalDetail, TransportLoss,
};
use browserd_api::{
    ActionPayload, ActionSubmitCommand, ActionSubmitRequest, ApiRequest, ApiResponse, ApiRouter,
    ApiService, decode_session_create,
};
use browserd_auth::{
    AuthConfig, AuthenticatedPrincipal, RevocationRegistry, ServiceClaims, ServiceTokenSigner,
    ServiceTokenVerifier, VerificationKeySet,
};
use browserd_coordination::{
    ClaimGatewayAction, CoordinationActorConfig, GatewayActionClaimOutcome,
    GatewayActionCoordination, GatewayActionCoordinationError, GatewayActionPlacement,
    GatewayActionSnapshot, SessionLossClaim, SessionLossOutcome,
};
use browserd_core::{
    ActionId, ErrorCode, PageId, PrincipalId, SessionId, SessionLifecycle, TenantId, WorkerId,
};
use browserd_worker::{
    WorkerCreateSessionReceipt, WorkerCreateSessionRequest, WorkerIsolationProfile,
    WorkerRpcCompletionError, WorkerRpcEnqueueError, WorkerRpcError, WorkerRpcRequest,
    WorkerRpcResponse, WorkerSessionLifecycle, WorkerSessionReceipt,
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
  "metadata":{"agent_run_id":"closing-action-race"}
}"#;

#[derive(Default)]
struct ReleaseGate {
    released: Mutex<bool>,
    condition: Condvar,
}

impl ReleaseGate {
    fn wait(&self) -> Result<(), WorkerRpcError> {
        let mut released = self.released.lock().map_err(|_| WorkerRpcError::Runtime)?;
        while !*released {
            released = self
                .condition
                .wait(released)
                .map_err(|_| WorkerRpcError::Runtime)?;
        }
        Ok(())
    }

    fn release(&self) -> Result<(), &'static str> {
        let mut released = self.released.lock().map_err(|_| "gate lock poisoned")?;
        *released = true;
        self.condition.notify_all();
        Ok(())
    }
}

struct RejectedPending;

impl GatewayWorkerPending for RejectedPending {
    fn wait(self) -> Result<WorkerRpcResponse, WorkerRpcCompletionError> {
        Err(WorkerRpcCompletionError::Disconnected)
    }
}

struct BlockingCloseWorker {
    tenant_id: TenantId,
    session_id: SessionId,
    page_id: PageId,
    close_entered: mpsc::Sender<()>,
    close_gate: Arc<ReleaseGate>,
    enqueue_calls: AtomicUsize,
}

impl GatewayWorkerClient for BlockingCloseWorker {
    type PendingAction = RejectedPending;

    fn create_session(
        &self,
        request: WorkerCreateSessionRequest,
    ) -> Result<WorkerCreateSessionReceipt, WorkerRpcError> {
        if request.tenant_id != self.tenant_id {
            return Err(WorkerRpcError::Protocol);
        }
        Ok(WorkerCreateSessionReceipt {
            operation_id: request.operation_id,
            tenant_id: request.tenant_id,
            session_id: self.session_id.clone(),
            session_incarnation: request.session_incarnation,
            effective_isolation: WorkerIsolationProfile::SharedContext,
            primary_page_id: self.page_id.clone(),
            worker_epoch: request.expected_worker_epoch,
            placement_version: request.placement_version,
            existing: false,
        })
    }

    fn request(&self, request: WorkerRpcRequest) -> Result<WorkerRpcResponse, WorkerRpcError> {
        let WorkerRpcRequest::CloseSession { fence, .. } = request else {
            return Err(WorkerRpcError::InvalidRequest);
        };
        if fence.tenant_id != self.tenant_id || fence.session_id != self.session_id {
            return Err(WorkerRpcError::Protocol);
        }
        self.close_entered
            .send(())
            .map_err(|_| WorkerRpcError::Runtime)?;
        self.close_gate.wait()?;
        Ok(WorkerRpcResponse::SessionClosed(WorkerSessionReceipt {
            fence,
            lifecycle: WorkerSessionLifecycle::Closed,
            primary_page_id: self.page_id.clone(),
        }))
    }

    fn enqueue_action(
        &self,
        request: WorkerRpcRequest,
    ) -> Result<Self::PendingAction, WorkerRpcEnqueueError> {
        self.enqueue_calls.fetch_add(1, Ordering::AcqRel);
        Err(WorkerRpcEnqueueError::Full(Box::new(request)))
    }
}

#[derive(Default)]
struct ClaimProbeStore {
    claim_calls: AtomicUsize,
}

impl ClaimProbeStore {
    fn reject<T>(&self) -> Result<T, GatewayActionCoordinationError> {
        Err(GatewayActionCoordinationError::CorruptState)
    }
}

#[async_trait]
impl GatewayActionCoordination for ClaimProbeStore {
    async fn claim_action(
        &self,
        _claim: ClaimGatewayAction,
        _now: DateTime<Utc>,
    ) -> Result<GatewayActionClaimOutcome, GatewayActionCoordinationError> {
        self.claim_calls.fetch_add(1, Ordering::AcqRel);
        self.reject()
    }

    async fn get_effective_action(
        &self,
        _tenant_id: &TenantId,
        _session_id: &SessionId,
        _action_id: &ActionId,
    ) -> Result<Option<GatewayActionSnapshot>, GatewayActionCoordinationError> {
        self.reject()
    }

    async fn arm_dispatch(
        &self,
        _tenant_id: &TenantId,
        _session_id: &SessionId,
        _action_id: &ActionId,
        _expected_revision: u64,
        _placement: &GatewayActionPlacement,
        _dispatch_id: DispatchId,
        _now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        self.reject()
    }

    async fn mark_exposure_possible(
        &self,
        _tenant_id: &TenantId,
        _session_id: &SessionId,
        _action_id: &ActionId,
        _expected_revision: u64,
        _placement: &GatewayActionPlacement,
        _dispatch_id: &DispatchId,
        _now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        self.reject()
    }

    async fn record_worker_result(
        &self,
        _tenant_id: &TenantId,
        _session_id: &SessionId,
        _action_id: &ActionId,
        _expected_revision: u64,
        _placement: &GatewayActionPlacement,
        _dispatch_id: &DispatchId,
        _action_sequence: ActionSequence,
        _result: BrowserResult,
        _now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        self.reject()
    }

    async fn record_worker_terminal(
        &self,
        _tenant_id: &TenantId,
        _session_id: &SessionId,
        _action_id: &ActionId,
        _expected_revision: u64,
        _placement: &GatewayActionPlacement,
        _dispatch_id: &DispatchId,
        _action_sequence: ActionSequence,
        _detail: TerminalDetail,
        _now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        self.reject()
    }

    async fn record_transport_loss(
        &self,
        _tenant_id: &TenantId,
        _session_id: &SessionId,
        _action_id: &ActionId,
        _expected_revision: u64,
        _placement: &GatewayActionPlacement,
        _dispatch_id: &DispatchId,
        _loss: TransportLoss,
        _now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        self.reject()
    }

    async fn cancel_before_dispatch(
        &self,
        _tenant_id: &TenantId,
        _session_id: &SessionId,
        _action_id: &ActionId,
        _expected_revision: u64,
        _placement: &GatewayActionPlacement,
        _now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        self.reject()
    }

    async fn resolve_unknown(
        &self,
        _tenant_id: &TenantId,
        _session_id: &SessionId,
        _action_id: &ActionId,
        _expected_revision: u64,
        _placement: &GatewayActionPlacement,
        _annotation: ResolutionAnnotation,
        _now: DateTime<Utc>,
    ) -> Result<GatewayActionSnapshot, GatewayActionCoordinationError> {
        self.reject()
    }

    async fn mark_session_lost(
        &self,
        _claim: &SessionLossClaim,
        _now: DateTime<Utc>,
    ) -> Result<SessionLossOutcome, GatewayActionCoordinationError> {
        self.reject()
    }

    async fn materialize_session_loss(
        &self,
        _claim: &SessionLossClaim,
        _limit: usize,
        _now: DateTime<Utc>,
    ) -> Result<usize, GatewayActionCoordinationError> {
        self.reject()
    }
}

fn authenticated_principal(tenant_id: TenantId) -> Result<AuthenticatedPrincipal, Box<dyn Error>> {
    let secret = [29_u8; 32];
    let mut keys = VerificationKeySet::new();
    keys.insert_hmac("closing-action-race", Algorithm::HS256, &secret)?;
    let verifier = ServiceTokenVerifier::new(
        AuthConfig::new("issuer", "audience", [Algorithm::HS256], 0, false),
        keys,
        RevocationRegistry::new(),
    );
    let signer = ServiceTokenSigner::new("closing-action-race", Algorithm::HS256, &secret);
    let token = signer.sign(&ServiceClaims::new(
        "issuer",
        "audience",
        PrincipalId::new(),
        tenant_id,
        BTreeSet::from([
            "session:create".to_owned(),
            "session:close".to_owned(),
            "browser:act".to_owned(),
        ]),
        "closing-action-race",
        1,
        100,
        None,
    ))?;
    Ok(verifier.verify_at(&token, None, 10)?)
}

#[test]
fn close_linearizes_before_action_claim_and_worker_enqueue() -> Result<(), Box<dyn Error>> {
    let tenant_id = TenantId::new();
    let principal = authenticated_principal(tenant_id.clone())?;
    let (close_entered_sender, close_entered) = mpsc::channel();
    let close_gate = Arc::new(ReleaseGate::default());
    let worker = Arc::new(BlockingCloseWorker {
        tenant_id,
        session_id: SessionId::new(),
        page_id: PageId::new(),
        close_entered: close_entered_sender,
        close_gate: Arc::clone(&close_gate),
        enqueue_calls: AtomicUsize::new(0),
    });
    let action_store = Arc::new(ClaimProbeStore::default());
    let placement = GatewayWorkerPlacement::new(WorkerId::new("closing-race-worker")?, 41, 7, 29)?;
    let actor_config =
        CoordinationActorConfig::new(8, 2, Duration::from_secs(1), Duration::from_secs(2))?;
    let runtime = Arc::new(GatewayWorkerRuntime::with_action_coordination(
        Arc::clone(&worker),
        placement,
        Arc::clone(&action_store),
        actor_config,
    )?);
    let router = Arc::new(ApiRouter::new(runtime));

    let created = router.execute(
        &principal,
        ApiRequest::CreateSession {
            body: decode_session_create(CREATE_JSON)?,
            idempotency_key: Uuid::new_v4().to_string(),
            received_at: Instant::now(),
        },
    )?;
    let ApiResponse::SessionCreate(created) = created else {
        return Err("unexpected create-session response".into());
    };
    let session_id = created
        .data()
        .operation()
        .session()
        .map(|session| session.id.clone())
        .ok_or("created session is missing")?;

    let close_router = Arc::clone(&router);
    let close_principal = principal.clone();
    let close_session_id = session_id.clone();
    let close = thread::spawn(move || {
        close_router
            .execute(
                &close_principal,
                ApiRequest::DeleteSession(close_session_id),
            )
            .map_err(|error| error.to_string())
    });
    close_entered
        .recv_timeout(Duration::from_secs(5))
        .map_err(|_| "close request did not reach the worker")?;

    let action_result = router.execute(
        &principal,
        ApiRequest::SubmitAction(ActionSubmitCommand {
            session_id: session_id.clone(),
            idempotency_key: Uuid::new_v4(),
            body: ActionSubmitRequest {
                page_id: worker.page_id.clone(),
                if_session_incarnation: 1,
                execution_timeout_ms: 1_000,
                action: ActionPayload::GetTitle,
            },
        }),
    );

    close_gate.release()?;
    let close_response = close.join().map_err(|_| "close caller panicked")??;
    assert!(matches!(
        close_response,
        ApiResponse::SessionClosed(response)
            if response.data().id == session_id
                && response.data().lifecycle == SessionLifecycle::Closed
    ));

    let Err(action_error) = action_result else {
        return Err("action was admitted after close started".into());
    };
    assert_eq!(action_error.code(), ErrorCode::SessionNotFound);
    assert_eq!(action_store.claim_calls.load(Ordering::Acquire), 0);
    assert_eq!(worker.enqueue_calls.load(Ordering::Acquire), 0);
    Ok(())
}
