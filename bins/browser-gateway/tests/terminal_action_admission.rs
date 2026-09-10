#![allow(clippy::expect_used)]

use std::collections::BTreeSet;
use std::error::Error;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
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
  "metadata":{"agent_run_id":"terminal-action-admission"}
}"#;

struct RejectedPending;

impl GatewayWorkerPending for RejectedPending {
    fn wait(self) -> Result<WorkerRpcResponse, WorkerRpcCompletionError> {
        Err(WorkerRpcCompletionError::Disconnected)
    }
}

struct LifecycleWorker {
    tenant_id: TenantId,
    session_id: SessionId,
    page_id: PageId,
    lifecycle: WorkerSessionLifecycle,
    enqueue_calls: AtomicUsize,
}

impl GatewayWorkerClient for LifecycleWorker {
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
        let WorkerRpcRequest::GetSession { fence } = request else {
            return Err(WorkerRpcError::InvalidRequest);
        };
        if fence.tenant_id != self.tenant_id || fence.session_id != self.session_id {
            return Err(WorkerRpcError::Protocol);
        }
        Ok(WorkerRpcResponse::Session(WorkerSessionReceipt {
            fence,
            lifecycle: self.lifecycle,
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
        _result_body: Option<Vec<u8>>,
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

fn assert_terminal_session_rejects_action(
    worker_lifecycle: WorkerSessionLifecycle,
    expected_lifecycle: SessionLifecycle,
) -> Result<(), Box<dyn Error>> {
    let tenant_id = TenantId::new();
    let secret = [23_u8; 32];
    let mut keys = VerificationKeySet::new();
    keys.insert_hmac("terminal-action-admission", Algorithm::HS256, &secret)?;
    let verifier = ServiceTokenVerifier::new(
        AuthConfig::new("issuer", "audience", [Algorithm::HS256], 0, false),
        keys,
        RevocationRegistry::new(),
    );
    let signer = ServiceTokenSigner::new("terminal-action-admission", Algorithm::HS256, &secret);
    let token = signer.sign(&ServiceClaims::new(
        "issuer",
        "audience",
        PrincipalId::new(),
        tenant_id.clone(),
        BTreeSet::from([
            "session:create".to_owned(),
            "session:read".to_owned(),
            "browser:act".to_owned(),
        ]),
        "terminal-action-admission",
        1,
        100,
        None,
    ))?;
    let principal: AuthenticatedPrincipal = verifier.verify_at(&token, None, 10)?;
    let worker = Arc::new(LifecycleWorker {
        tenant_id,
        session_id: SessionId::new(),
        page_id: PageId::new(),
        lifecycle: worker_lifecycle,
        enqueue_calls: AtomicUsize::new(0),
    });
    let action_store = Arc::new(ClaimProbeStore::default());
    let placement =
        GatewayWorkerPlacement::new(WorkerId::new("terminal-action-worker")?, 41, 7, 29)?;
    let actor_config =
        CoordinationActorConfig::new(8, 2, Duration::from_secs(1), Duration::from_secs(2))?;
    let runtime = Arc::new(GatewayWorkerRuntime::with_action_coordination(
        Arc::clone(&worker),
        placement,
        Arc::clone(&action_store),
        actor_config,
    )?);
    let router = ApiRouter::new(runtime);

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

    let refreshed = router.execute(&principal, ApiRequest::GetSession(session_id.clone()))?;
    let ApiResponse::Session(refreshed) = refreshed else {
        return Err("unexpected get-session response".into());
    };
    assert_eq!(refreshed.data().lifecycle, expected_lifecycle);

    let result = router.execute(
        &principal,
        ApiRequest::SubmitAction(ActionSubmitCommand {
            session_id,
            idempotency_key: Uuid::new_v4(),
            body: ActionSubmitRequest {
                page_id: worker.page_id.clone(),
                if_session_incarnation: 1,
                execution_timeout_ms: 1_000,
                action: ActionPayload::GetTitle,
            },
        }),
    );
    let Err(error) = result else {
        return Err("terminal session unexpectedly admitted an action".into());
    };
    assert_eq!(error.code(), ErrorCode::SessionNotFound);
    assert_eq!(action_store.claim_calls.load(Ordering::Acquire), 0);
    assert_eq!(worker.enqueue_calls.load(Ordering::Acquire), 0);
    Ok(())
}

#[test]
fn closing_session_rejects_submit_before_durable_claim_or_worker_enqueue()
-> Result<(), Box<dyn Error>> {
    assert_terminal_session_rejects_action(
        WorkerSessionLifecycle::Closing,
        SessionLifecycle::Closing,
    )
}

#[test]
fn closed_session_rejects_submit_before_durable_claim_or_worker_enqueue()
-> Result<(), Box<dyn Error>> {
    assert_terminal_session_rejects_action(WorkerSessionLifecycle::Closed, SessionLifecycle::Closed)
}

#[test]
fn failed_session_rejects_submit_before_durable_claim_or_worker_enqueue()
-> Result<(), Box<dyn Error>> {
    assert_terminal_session_rejects_action(WorkerSessionLifecycle::Failed, SessionLifecycle::Failed)
}
