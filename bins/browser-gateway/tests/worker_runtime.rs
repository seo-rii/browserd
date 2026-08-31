#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::error::Error;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use browser_gateway::{
    GatewayWorkerClient, GatewayWorkerPending, GatewayWorkerPlacement, GatewayWorkerRuntime,
};
use browserd_actions::{
    ActionKind, ActionSequence, OutcomeUnknownReason, ResolutionAnnotation, ResolutionKind,
    TerminalDetail,
};
use browserd_api::{
    ActionGetRequest, ActionPayload, ActionResolveBody, ActionResolveRequest, ActionSubmitCommand,
    ActionSubmitRequest, ApiRequest, ApiResponse, ApiRouter, ApiService, ApprovalDecisionBody,
    ApprovalDecisionRequest, ApprovalListQuery, ArtifactRequest, PageActivateRequest,
    PageCreateBody, PageCreateRequest, PageDeleteRequest, PageListRequest, ResolutionRequestKind,
    decode_session_create,
};
use browserd_auth::{
    AuthConfig, AuthenticatedPrincipal, RevocationRegistry, ServiceClaims, ServiceTokenSigner,
    ServiceTokenVerifier, VerificationKeySet,
};
use browserd_core::{
    ActionId, ActionState, ApprovalId, ArtifactId, CreateOperationState, PageId, PrincipalId,
    SessionId, TenantId, WorkerId,
};
use browserd_worker::{
    WorkerActionReceipt, WorkerActionStatus, WorkerApprovalActionType, WorkerApprovalDecision,
    WorkerApprovalReceipt, WorkerApprovalState, WorkerArtifactReceipt, WorkerArtifactSource,
    WorkerArtifactState, WorkerCanonicalActionProposal, WorkerCreateSessionReceipt,
    WorkerCreateSessionRequest, WorkerIsolationProfile, WorkerPageReceipt,
    WorkerRpcCompletionError, WorkerRpcEnqueueError, WorkerRpcError, WorkerRpcFailure,
    WorkerRpcFailureCode, WorkerRpcRequest, WorkerRpcResponse, WorkerSessionFence,
    WorkerSessionLifecycle, WorkerSessionReceipt,
};
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
  "metadata":{"agent_run_id":"run_123"}
}"#;

struct ImmediatePending(Result<WorkerRpcResponse, WorkerRpcError>);

impl GatewayWorkerPending for ImmediatePending {
    fn wait(self) -> Result<WorkerRpcResponse, WorkerRpcCompletionError> {
        self.0.map_err(WorkerRpcCompletionError::Exchange)
    }
}

fn gateway_placement() -> Result<GatewayWorkerPlacement, Box<dyn Error>> {
    Ok(GatewayWorkerPlacement::new(
        WorkerId::new("gateway-worker-test")?,
        41,
        7,
        11,
    )?)
}

struct RecordingWorker {
    request: Mutex<Option<WorkerCreateSessionRequest>>,
    session_id: SessionId,
    corrupt_epoch: bool,
}

impl GatewayWorkerClient for RecordingWorker {
    type PendingAction = ImmediatePending;

    fn create_session(
        &self,
        request: WorkerCreateSessionRequest,
    ) -> Result<WorkerCreateSessionReceipt, WorkerRpcError> {
        let mut recorded = self.request.lock().map_err(|_| WorkerRpcError::Runtime)?;
        *recorded = Some(request.clone());
        Ok(WorkerCreateSessionReceipt {
            operation_id: request.operation_id,
            tenant_id: request.tenant_id,
            session_id: self.session_id.clone(),
            session_incarnation: request.session_incarnation,
            effective_isolation: WorkerIsolationProfile::SharedContext,
            primary_page_id: PageId::new(),
            worker_epoch: if self.corrupt_epoch {
                request.expected_worker_epoch.saturating_add(1)
            } else {
                request.expected_worker_epoch
            },
            placement_version: request.placement_version,
            existing: false,
        })
    }

    fn request(&self, request: WorkerRpcRequest) -> Result<WorkerRpcResponse, WorkerRpcError> {
        let recorded = self.request.lock().map_err(|_| WorkerRpcError::Runtime)?;
        let created = recorded.as_ref().ok_or(WorkerRpcError::Protocol)?;
        let (fence, lifecycle, closed) = match request {
            WorkerRpcRequest::GetSession { fence } => (fence, WorkerSessionLifecycle::Ready, false),
            WorkerRpcRequest::CloseSession { fence, .. } => {
                (fence, WorkerSessionLifecycle::Closed, true)
            }
            _ => return Err(WorkerRpcError::InvalidRequest),
        };
        if fence.session_id != self.session_id
            || fence.tenant_id != created.tenant_id
            || fence.worker_epoch != created.expected_worker_epoch
            || fence.placement_version != created.placement_version
            || fence.session_incarnation != created.session_incarnation
        {
            return Err(WorkerRpcError::Protocol);
        }
        let receipt = WorkerSessionReceipt {
            fence,
            lifecycle,
            primary_page_id: PageId::new(),
        };
        Ok(if closed {
            WorkerRpcResponse::SessionClosed(receipt)
        } else {
            WorkerRpcResponse::Session(receipt)
        })
    }

    fn enqueue_action(
        &self,
        request: WorkerRpcRequest,
    ) -> Result<Self::PendingAction, WorkerRpcEnqueueError> {
        Ok(ImmediatePending(self.request(request)))
    }
}

struct RacingWorker {
    create: Mutex<Option<WorkerCreateSessionRequest>>,
    session_id: SessionId,
    block_first_get: AtomicBool,
    get_entered: mpsc::Sender<()>,
    get_release: Mutex<mpsc::Receiver<()>>,
}

struct PageWorker {
    tenant_id: TenantId,
    session_id: SessionId,
    page_id: PageId,
    requests: Mutex<Vec<WorkerRpcRequest>>,
    corrupt_response_tenant: bool,
    failure: Option<WorkerRpcFailureCode>,
}

impl GatewayWorkerClient for PageWorker {
    type PendingAction = ImmediatePending;

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
        self.requests
            .lock()
            .map_err(|_| WorkerRpcError::Runtime)?
            .push(request.clone());
        if let Some(code) = self.failure {
            return Ok(WorkerRpcResponse::Failure(WorkerRpcFailure::new(
                code,
                "injected page failure",
            )));
        }
        let (mut fence, response) = match request {
            WorkerRpcRequest::ListPages { fence } => (fence, 0_u8),
            WorkerRpcRequest::CreatePage { fence, .. } => (fence, 1),
            WorkerRpcRequest::ActivatePage { fence, page_id, .. } if page_id == self.page_id => {
                (fence, 2)
            }
            WorkerRpcRequest::ClosePage { fence, page_id, .. } if page_id == self.page_id => {
                (fence, 3)
            }
            _ => return Err(WorkerRpcError::InvalidRequest),
        };
        if fence.tenant_id != self.tenant_id || fence.session_id != self.session_id {
            return Err(WorkerRpcError::Protocol);
        }
        if self.corrupt_response_tenant {
            fence.tenant_id = TenantId::new();
        }
        let receipt = WorkerPageReceipt {
            fence,
            page_id: self.page_id.clone(),
            active: response == 2,
            target_incarnation: 3,
            document_epoch: 5,
            url_revision: 8,
        };
        Ok(match response {
            0 => WorkerRpcResponse::Pages(vec![receipt]),
            1 | 2 => WorkerRpcResponse::Page(receipt),
            3 => WorkerRpcResponse::PageClosed(receipt),
            _ => return Err(WorkerRpcError::Protocol),
        })
    }

    fn enqueue_action(
        &self,
        request: WorkerRpcRequest,
    ) -> Result<Self::PendingAction, WorkerRpcEnqueueError> {
        Ok(ImmediatePending(self.request(request)))
    }
}

#[derive(Clone)]
struct RecordedActionIdentity {
    action_id: ActionId,
    action_sequence: ActionSequence,
    idempotency_key: String,
    canonical_request_hash: [u8; 32],
    kind: ActionKind,
}

struct ResourceWorker {
    tenant_id: TenantId,
    session_id: SessionId,
    page_id: PageId,
    approval_action_id: ActionId,
    artifact_id: ArtifactId,
    approval_id: ApprovalId,
    requester_principal_id: PrincipalId,
    create_count: AtomicUsize,
    corrupt_action_hash_on_get: AtomicBool,
    action_identity: Mutex<Option<RecordedActionIdentity>>,
    requests: Mutex<Vec<WorkerRpcRequest>>,
}

impl GatewayWorkerClient for ResourceWorker {
    type PendingAction = ImmediatePending;

    fn create_session(
        &self,
        request: WorkerCreateSessionRequest,
    ) -> Result<WorkerCreateSessionReceipt, WorkerRpcError> {
        if request.tenant_id != self.tenant_id {
            return Err(WorkerRpcError::Protocol);
        }
        let session_id = if self.create_count.fetch_add(1, Ordering::AcqRel) == 0 {
            self.session_id.clone()
        } else {
            SessionId::new()
        };
        Ok(WorkerCreateSessionReceipt {
            operation_id: request.operation_id,
            tenant_id: request.tenant_id,
            session_id,
            session_incarnation: request.session_incarnation,
            effective_isolation: WorkerIsolationProfile::SharedContext,
            primary_page_id: self.page_id.clone(),
            worker_epoch: request.expected_worker_epoch,
            placement_version: request.placement_version,
            existing: false,
        })
    }

    fn request(&self, request: WorkerRpcRequest) -> Result<WorkerRpcResponse, WorkerRpcError> {
        self.requests
            .lock()
            .map_err(|_| WorkerRpcError::Runtime)?
            .push(request.clone());
        let action_receipt = |fence: WorkerSessionFence,
                              status: WorkerActionStatus,
                              terminal_detail: Option<TerminalDetail>,
                              resolution: Option<ResolutionAnnotation>|
         -> Result<WorkerActionReceipt, WorkerRpcError> {
            let identity = self
                .action_identity
                .lock()
                .map_err(|_| WorkerRpcError::Runtime)?
                .clone()
                .unwrap_or_else(|| RecordedActionIdentity {
                    action_id: self.approval_action_id.clone(),
                    action_sequence: ActionSequence::new(1),
                    idempotency_key: "action-fallback".to_owned(),
                    canonical_request_hash: [7; 32],
                    kind: ActionKind::ReadOnly,
                });
            Ok(WorkerActionReceipt {
                fence,
                action_id: identity.action_id,
                action_sequence: identity.action_sequence,
                idempotency_key: identity.idempotency_key,
                canonical_request_hash: identity.canonical_request_hash,
                kind: identity.kind,
                status,
                dispatch_acknowledged: matches!(
                    status,
                    WorkerActionStatus::Running
                        | WorkerActionStatus::Succeeded
                        | WorkerActionStatus::CancelledConfirmed
                        | WorkerActionStatus::OutcomeUnknown
                ),
                approval_decision: None,
                terminal_detail,
                result: None,
                resolution,
            })
        };
        let approval_receipt = |fence: WorkerSessionFence,
                                state: WorkerApprovalState|
         -> Result<WorkerApprovalReceipt, WorkerRpcError> {
            let proposal = WorkerCanonicalActionProposal {
                tenant_id: fence.tenant_id.clone(),
                requester_principal_id: self.requester_principal_id.clone(),
                session_id: fence.session_id.clone(),
                session_incarnation: fence.session_incarnation,
                page_id: self.page_id.clone(),
                target_incarnation: 3,
                frame_document_epoch: 5,
                current_origin: "https://example.test".to_owned(),
                url_revision: 8,
                action_type: WorkerApprovalActionType::Click,
                canonical_arguments_hash: [2; 32],
                node_ref: Some("node-opaque".to_owned()),
                credential_refs_hash: [3; 32],
                expires_at_unix_millis: 10_000,
            };
            let proposal_hash = *proposal.to_canonical()?.hash().as_bytes();
            Ok(WorkerApprovalReceipt {
                fence,
                approval_id: self.approval_id.clone(),
                action_id: self.approval_action_id.clone(),
                state,
                proposal,
                proposal_hash,
            })
        };
        match request {
            WorkerRpcRequest::SubmitAction {
                fence,
                action_id,
                action_sequence,
                idempotency_key,
                canonical_request_hash,
                kind,
                page_id,
                ..
            } => {
                if page_id.as_ref() != Some(&self.page_id) {
                    return Err(WorkerRpcError::Protocol);
                }
                *self
                    .action_identity
                    .lock()
                    .map_err(|_| WorkerRpcError::Runtime)? = Some(RecordedActionIdentity {
                    action_id,
                    action_sequence,
                    idempotency_key,
                    canonical_request_hash,
                    kind,
                });
                action_receipt(fence, WorkerActionStatus::Queued, None, None)
                    .map(WorkerRpcResponse::Action)
            }
            WorkerRpcRequest::GetAction { fence, action_id } => {
                let known_action = self
                    .action_identity
                    .lock()
                    .map_err(|_| WorkerRpcError::Runtime)?
                    .as_ref()
                    .is_some_and(|identity| identity.action_id == action_id);
                if !known_action {
                    return Err(WorkerRpcError::InvalidRequest);
                }
                let mut receipt = action_receipt(
                    fence,
                    WorkerActionStatus::OutcomeUnknown,
                    Some(TerminalDetail::OutcomeUnknown(
                        OutcomeUnknownReason::AmbiguousTransportLoss,
                    )),
                    None,
                )?;
                if self.corrupt_action_hash_on_get.load(Ordering::Acquire) {
                    receipt.canonical_request_hash[0] ^= u8::MAX;
                }
                Ok(WorkerRpcResponse::Action(receipt))
            }
            WorkerRpcRequest::CancelAction {
                fence, action_id, ..
            } => {
                let known_action = self
                    .action_identity
                    .lock()
                    .map_err(|_| WorkerRpcError::Runtime)?
                    .as_ref()
                    .is_some_and(|identity| identity.action_id == action_id);
                if !known_action {
                    return Err(WorkerRpcError::InvalidRequest);
                }
                action_receipt(
                    fence,
                    WorkerActionStatus::CancelledBeforeDispatch,
                    Some(TerminalDetail::CancelledBeforeDispatch),
                    None,
                )
                .map(WorkerRpcResponse::Action)
            }
            WorkerRpcRequest::ResolveAction {
                fence,
                action_id,
                resolution,
                resolved_by,
                basis,
                now_unix_millis,
            } => {
                let known_action = self
                    .action_identity
                    .lock()
                    .map_err(|_| WorkerRpcError::Runtime)?
                    .as_ref()
                    .is_some_and(|identity| identity.action_id == action_id);
                if !known_action {
                    return Err(WorkerRpcError::InvalidRequest);
                }
                action_receipt(
                    fence,
                    WorkerActionStatus::OutcomeUnknown,
                    Some(TerminalDetail::OutcomeUnknown(
                        OutcomeUnknownReason::AmbiguousTransportLoss,
                    )),
                    Some(ResolutionAnnotation::new(
                        resolution,
                        resolved_by,
                        now_unix_millis,
                        basis,
                    )),
                )
                .map(WorkerRpcResponse::Action)
            }
            WorkerRpcRequest::GetArtifact { fence, artifact_id }
                if artifact_id == self.artifact_id =>
            {
                Ok(WorkerRpcResponse::Artifact(WorkerArtifactReceipt {
                    fence,
                    artifact_id,
                    state: WorkerArtifactState::Available,
                    size_bytes: 4,
                    checksum_sha256: [8; 32],
                    content_type: "application/octet-stream".to_owned(),
                    source: WorkerArtifactSource::ClientUpload,
                    origin: "gateway-test-upload".to_owned(),
                    object_generation: [9; 32],
                }))
            }
            WorkerRpcRequest::ListApprovals { fence } => {
                approval_receipt(fence, WorkerApprovalState::Pending)
                    .map(|approval| WorkerRpcResponse::Approvals(vec![approval]))
            }
            WorkerRpcRequest::GetApproval { fence, approval_id }
                if approval_id == self.approval_id =>
            {
                approval_receipt(fence, WorkerApprovalState::Pending)
                    .map(WorkerRpcResponse::Approval)
            }
            WorkerRpcRequest::DecideApproval {
                fence,
                approval_id,
                decision,
                principal_id,
                ..
            } if approval_id == self.approval_id => {
                let state = match decision {
                    WorkerApprovalDecision::Approve => {
                        WorkerApprovalState::Approved { by: principal_id }
                    }
                    WorkerApprovalDecision::Deny => {
                        WorkerApprovalState::Denied { by: principal_id }
                    }
                };
                approval_receipt(fence, state).map(WorkerRpcResponse::Approval)
            }
            _ => Err(WorkerRpcError::InvalidRequest),
        }
    }

    fn enqueue_action(
        &self,
        request: WorkerRpcRequest,
    ) -> Result<Self::PendingAction, WorkerRpcEnqueueError> {
        Ok(ImmediatePending(self.request(request)))
    }
}

impl GatewayWorkerClient for RacingWorker {
    type PendingAction = ImmediatePending;

    fn create_session(
        &self,
        request: WorkerCreateSessionRequest,
    ) -> Result<WorkerCreateSessionReceipt, WorkerRpcError> {
        *self.create.lock().map_err(|_| WorkerRpcError::Runtime)? = Some(request.clone());
        Ok(WorkerCreateSessionReceipt {
            operation_id: request.operation_id,
            tenant_id: request.tenant_id,
            session_id: self.session_id.clone(),
            session_incarnation: request.session_incarnation,
            effective_isolation: WorkerIsolationProfile::SharedContext,
            primary_page_id: PageId::new(),
            worker_epoch: request.expected_worker_epoch,
            placement_version: request.placement_version,
            existing: false,
        })
    }

    fn request(&self, request: WorkerRpcRequest) -> Result<WorkerRpcResponse, WorkerRpcError> {
        let (tenant_id, expected_worker_epoch, placement_version, session_incarnation) = {
            let created = self.create.lock().map_err(|_| WorkerRpcError::Runtime)?;
            let created = created.as_ref().ok_or(WorkerRpcError::Protocol)?;
            (
                created.tenant_id.clone(),
                created.expected_worker_epoch,
                created.placement_version,
                created.session_incarnation,
            )
        };
        let (fence, lifecycle, closed) = match request {
            WorkerRpcRequest::GetSession { fence } => {
                if self.block_first_get.swap(false, Ordering::AcqRel) {
                    self.get_entered
                        .send(())
                        .map_err(|_| WorkerRpcError::Runtime)?;
                    self.get_release
                        .lock()
                        .map_err(|_| WorkerRpcError::Runtime)?
                        .recv()
                        .map_err(|_| WorkerRpcError::Runtime)?;
                }
                (fence, WorkerSessionLifecycle::Ready, false)
            }
            WorkerRpcRequest::CloseSession { fence, .. } => {
                (fence, WorkerSessionLifecycle::Closed, true)
            }
            _ => return Err(WorkerRpcError::InvalidRequest),
        };
        if fence.session_id != self.session_id
            || fence.tenant_id != tenant_id
            || fence.worker_epoch != expected_worker_epoch
            || fence.placement_version != placement_version
            || fence.session_incarnation != session_incarnation
        {
            return Err(WorkerRpcError::Protocol);
        }
        let receipt = WorkerSessionReceipt {
            fence,
            lifecycle,
            primary_page_id: PageId::new(),
        };
        Ok(if closed {
            WorkerRpcResponse::SessionClosed(receipt)
        } else {
            WorkerRpcResponse::Session(receipt)
        })
    }

    fn enqueue_action(
        &self,
        request: WorkerRpcRequest,
    ) -> Result<Self::PendingAction, WorkerRpcEnqueueError> {
        Ok(ImmediatePending(self.request(request)))
    }
}

fn authenticated_principal(tenant_id: TenantId) -> Result<AuthenticatedPrincipal, Box<dyn Error>> {
    let secret = [9_u8; 32];
    let mut keys = VerificationKeySet::new();
    keys.insert_hmac("gateway-worker-test", Algorithm::HS256, &secret)?;
    let verifier = ServiceTokenVerifier::new(
        AuthConfig::new("issuer", "audience", [Algorithm::HS256], 0, false),
        keys,
        RevocationRegistry::new(),
    );
    let signer = ServiceTokenSigner::new("gateway-worker-test", Algorithm::HS256, &secret);
    let token = signer.sign(&ServiceClaims::new(
        "issuer",
        "audience",
        PrincipalId::new(),
        tenant_id,
        BTreeSet::from([
            "session:create".to_owned(),
            "session:read".to_owned(),
            "session:close".to_owned(),
            "browser:act".to_owned(),
            "artifact:read".to_owned(),
            "approval:read".to_owned(),
            "approval:decide".to_owned(),
        ]),
        "gateway-worker-runtime",
        1,
        100,
        None,
    ))?;
    Ok(verifier.verify_at(&token, None, 10)?)
}

type ResourceRouter = ApiRouter<GatewayWorkerRuntime<ResourceWorker>>;
type ResourceFixture = (
    AuthenticatedPrincipal,
    Arc<ResourceWorker>,
    ResourceRouter,
    SessionId,
);

fn resource_worker(
    tenant_id: TenantId,
    requester_principal_id: PrincipalId,
) -> Arc<ResourceWorker> {
    Arc::new(ResourceWorker {
        tenant_id,
        session_id: SessionId::new(),
        page_id: PageId::new(),
        approval_action_id: ActionId::new(),
        artifact_id: ArtifactId::new(),
        approval_id: ApprovalId::new(),
        requester_principal_id,
        create_count: AtomicUsize::new(0),
        corrupt_action_hash_on_get: AtomicBool::new(false),
        action_identity: Mutex::new(None),
        requests: Mutex::new(Vec::new()),
    })
}

fn resource_fixture() -> Result<ResourceFixture, Box<dyn Error>> {
    let tenant_id = TenantId::new();
    let principal = authenticated_principal(tenant_id.clone())?;
    let worker = resource_worker(tenant_id, principal.principal_id().clone());
    let runtime = Arc::new(GatewayWorkerRuntime::new(
        Arc::clone(&worker),
        gateway_placement()?,
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
        return Err("unexpected create response".into());
    };
    let session_id = created
        .data()
        .operation()
        .session()
        .map(|session| session.id.clone())
        .ok_or("created session missing")?;
    Ok((principal, worker, router, session_id))
}

#[test]
fn create_dispatch_preserves_idempotency_and_exact_worker_fences() -> Result<(), Box<dyn Error>> {
    let tenant_id = TenantId::new();
    let principal = authenticated_principal(tenant_id.clone())?;
    let worker = Arc::new(RecordingWorker {
        request: Mutex::new(None),
        session_id: SessionId::new(),
        corrupt_epoch: false,
    });
    let placement = gateway_placement()?;
    let runtime = Arc::new(GatewayWorkerRuntime::new(Arc::clone(&worker), placement)?);
    let router = ApiRouter::new(runtime);
    let idempotency_key = Uuid::new_v4().to_string();

    let response = router.execute(
        &principal,
        ApiRequest::CreateSession {
            body: decode_session_create(CREATE_JSON)?,
            idempotency_key: idempotency_key.clone(),
            received_at: Instant::now(),
        },
    )?;
    let ApiResponse::SessionCreate(response) = response else {
        return Err("unexpected create response".into());
    };
    assert_eq!(
        response.data().operation().state(),
        CreateOperationState::Succeeded
    );
    let session = response
        .data()
        .operation()
        .session()
        .ok_or("created session missing")?;
    assert_eq!(
        session.metadata.get("agent_run_id").map(String::as_str),
        Some("run_123")
    );

    let recorded = worker
        .request
        .lock()
        .map_err(|_| "recorded request lock poisoned")?
        .clone()
        .ok_or("worker request missing")?;
    assert_eq!(recorded.tenant_id, tenant_id);
    assert_ne!(recorded.idempotency_key, idempotency_key);
    assert_eq!(recorded.idempotency_key.len(), 64);
    assert!(
        recorded
            .idempotency_key
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    );
    assert_ne!(recorded.canonical_request_hash, [0; 32]);
    assert_eq!(recorded.expected_worker_epoch, 41);
    assert_eq!(recorded.placement_version, 7);
    assert_eq!(recorded.session_incarnation, 1);
    Ok(())
}

#[test]
fn a_mismatched_worker_receipt_cannot_complete_the_create_operation() -> Result<(), Box<dyn Error>>
{
    let tenant_id = TenantId::new();
    let principal = authenticated_principal(tenant_id)?;
    let worker = Arc::new(RecordingWorker {
        request: Mutex::new(None),
        session_id: SessionId::new(),
        corrupt_epoch: true,
    });
    let placement = gateway_placement()?;
    let runtime = Arc::new(GatewayWorkerRuntime::new(worker, placement)?);
    let router = ApiRouter::new(runtime);

    let response = router.execute(
        &principal,
        ApiRequest::CreateSession {
            body: decode_session_create(CREATE_JSON)?,
            idempotency_key: Uuid::new_v4().to_string(),
            received_at: Instant::now(),
        },
    )?;
    let ApiResponse::SessionCreate(response) = response else {
        return Err("unexpected create response".into());
    };
    assert_eq!(
        response.data().operation().state(),
        CreateOperationState::Failed
    );
    assert!(response.data().operation().session().is_none());
    Ok(())
}

#[test]
fn created_sessions_are_read_and_closed_through_the_same_exact_worker_fence()
-> Result<(), Box<dyn Error>> {
    let tenant_id = TenantId::new();
    let principal = authenticated_principal(tenant_id)?;
    let worker = Arc::new(RecordingWorker {
        request: Mutex::new(None),
        session_id: SessionId::new(),
        corrupt_epoch: false,
    });
    let placement = gateway_placement()?;
    let runtime = Arc::new(GatewayWorkerRuntime::new(worker, placement)?);
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
        return Err("unexpected create response".into());
    };
    let session_id = created
        .data()
        .operation()
        .session()
        .map(|session| session.id.clone())
        .ok_or("created session missing")?;

    let fetched = router.execute(&principal, ApiRequest::GetSession(session_id.clone()))?;
    assert!(matches!(
        fetched,
        ApiResponse::Session(response) if response.data().id == session_id
    ));
    let closed = router.execute(&principal, ApiRequest::DeleteSession(session_id.clone()))?;
    assert!(matches!(
        closed,
        ApiResponse::SessionClosed(response)
            if response.data().id == session_id
                && response.data().lifecycle == browserd_core::SessionLifecycle::Closed
    ));
    Ok(())
}

#[test]
fn a_delayed_read_cannot_regress_a_concurrently_closed_session() -> Result<(), Box<dyn Error>> {
    let tenant_id = TenantId::new();
    let principal = Arc::new(authenticated_principal(tenant_id)?);
    let (get_entered_tx, get_entered_rx) = mpsc::channel();
    let (get_release_tx, get_release_rx) = mpsc::channel();
    let worker = Arc::new(RacingWorker {
        create: Mutex::new(None),
        session_id: SessionId::new(),
        block_first_get: AtomicBool::new(true),
        get_entered: get_entered_tx,
        get_release: Mutex::new(get_release_rx),
    });
    let placement = gateway_placement()?;
    let runtime = Arc::new(GatewayWorkerRuntime::new(worker, placement)?);
    let router = Arc::new(ApiRouter::new(runtime));

    let created = router.execute(
        principal.as_ref(),
        ApiRequest::CreateSession {
            body: decode_session_create(CREATE_JSON)?,
            idempotency_key: Uuid::new_v4().to_string(),
            received_at: Instant::now(),
        },
    )?;
    let ApiResponse::SessionCreate(created) = created else {
        return Err("unexpected create response".into());
    };
    let session_id = created
        .data()
        .operation()
        .session()
        .map(|session| session.id.clone())
        .ok_or("created session missing")?;

    let read_router = Arc::clone(&router);
    let read_principal = Arc::clone(&principal);
    let read_session_id = session_id.clone();
    let read = thread::spawn(move || {
        read_router.execute(
            read_principal.as_ref(),
            ApiRequest::GetSession(read_session_id),
        )
    });
    get_entered_rx.recv_timeout(Duration::from_secs(1))?;
    let closed = router.execute(
        principal.as_ref(),
        ApiRequest::DeleteSession(session_id.clone()),
    )?;
    assert!(matches!(
        closed,
        ApiResponse::SessionClosed(response)
            if response.data().lifecycle == browserd_core::SessionLifecycle::Closed
    ));
    get_release_tx.send(())?;

    let delayed = read.join().map_err(|_| "delayed read panicked")??;
    assert!(matches!(
        delayed,
        ApiResponse::Session(response)
            if response.data().id == session_id
                && response.data().lifecycle == browserd_core::SessionLifecycle::Closed
    ));
    Ok(())
}

#[test]
fn page_endpoints_use_the_exact_tenant_session_and_placement_fence() -> Result<(), Box<dyn Error>> {
    let tenant_id = TenantId::new();
    let principal = authenticated_principal(tenant_id.clone())?;
    let worker = Arc::new(PageWorker {
        tenant_id,
        session_id: SessionId::new(),
        page_id: PageId::new(),
        requests: Mutex::new(Vec::new()),
        corrupt_response_tenant: false,
        failure: None,
    });
    let runtime = Arc::new(GatewayWorkerRuntime::new(
        Arc::clone(&worker),
        gateway_placement()?,
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
        return Err("unexpected create response".into());
    };
    let session_id = created
        .data()
        .operation()
        .session()
        .map(|session| session.id.clone())
        .ok_or("created session missing")?;

    let listed = router.execute(
        &principal,
        ApiRequest::ListPages(PageListRequest {
            session_id: session_id.clone(),
        }),
    )?;
    assert!(matches!(
        listed,
        ApiResponse::Pages(response)
            if response.data().len() == 1
                && response.data()[0].session_id == session_id
                && response.data()[0].page_id == worker.page_id
    ));
    let created_page = router.execute(
        &principal,
        ApiRequest::CreatePage(PageCreateRequest {
            session_id: session_id.clone(),
            body: PageCreateBody { url: None },
        }),
    )?;
    assert!(matches!(created_page, ApiResponse::Page(_)));
    let activated = router.execute(
        &principal,
        ApiRequest::ActivatePage(PageActivateRequest {
            session_id: session_id.clone(),
            page_id: worker.page_id.clone(),
        }),
    )?;
    assert!(matches!(
        activated,
        ApiResponse::Page(response) if response.data().active
    ));
    let deleted = router.execute(
        &principal,
        ApiRequest::DeletePage(PageDeleteRequest {
            session_id,
            page_id: worker.page_id.clone(),
        }),
    )?;
    assert!(matches!(deleted, ApiResponse::PageDeleted(_)));

    let requests = worker
        .requests
        .lock()
        .map_err(|_| "request lock poisoned")?;
    assert_eq!(requests.len(), 4);
    assert!(requests.iter().all(|request| match request {
        WorkerRpcRequest::ListPages { fence }
        | WorkerRpcRequest::CreatePage { fence, .. }
        | WorkerRpcRequest::ActivatePage { fence, .. }
        | WorkerRpcRequest::ClosePage { fence, .. } => {
            fence.tenant_id == worker.tenant_id
                && fence.session_id == worker.session_id
                && fence.worker_epoch == 41
                && fence.placement_version == 7
                && fence.session_incarnation == 1
        }
        _ => false,
    }));
    Ok(())
}

#[test]
fn a_cross_tenant_page_receipt_is_rejected_fail_closed() -> Result<(), Box<dyn Error>> {
    let tenant_id = TenantId::new();
    let principal = authenticated_principal(tenant_id.clone())?;
    let worker = Arc::new(PageWorker {
        tenant_id,
        session_id: SessionId::new(),
        page_id: PageId::new(),
        requests: Mutex::new(Vec::new()),
        corrupt_response_tenant: true,
        failure: None,
    });
    let runtime = Arc::new(GatewayWorkerRuntime::new(worker, gateway_placement()?)?);
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
        return Err("unexpected create response".into());
    };
    let session_id = created
        .data()
        .operation()
        .session()
        .map(|session| session.id.clone())
        .ok_or("created session missing")?;

    let Err(error) = router.execute(
        &principal,
        ApiRequest::ListPages(PageListRequest { session_id }),
    ) else {
        return Err("cross-tenant receipt must fail closed".into());
    };
    assert_eq!(error.code(), browserd_core::ErrorCode::PlacementMismatch);
    Ok(())
}

#[test]
fn worker_page_not_found_is_mapped_to_the_public_page_error() -> Result<(), Box<dyn Error>> {
    let tenant_id = TenantId::new();
    let principal = authenticated_principal(tenant_id.clone())?;
    let worker = Arc::new(PageWorker {
        tenant_id,
        session_id: SessionId::new(),
        page_id: PageId::new(),
        requests: Mutex::new(Vec::new()),
        corrupt_response_tenant: false,
        failure: Some(WorkerRpcFailureCode::NotFound),
    });
    let runtime = Arc::new(GatewayWorkerRuntime::new(worker, gateway_placement()?)?);
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
        return Err("unexpected create response".into());
    };
    let session_id = created
        .data()
        .operation()
        .session()
        .map(|session| session.id.clone())
        .ok_or("created session missing")?;

    let Err(error) = router.execute(
        &principal,
        ApiRequest::ActivatePage(PageActivateRequest {
            session_id,
            page_id: PageId::new(),
        }),
    ) else {
        return Err("worker page miss must remain an error".into());
    };
    assert_eq!(error.code(), browserd_core::ErrorCode::PageNotFound);
    Ok(())
}

#[test]
fn page_create_rejects_an_initial_url_the_worker_cannot_apply_atomically()
-> Result<(), Box<dyn Error>> {
    let tenant_id = TenantId::new();
    let principal = authenticated_principal(tenant_id.clone())?;
    let worker = Arc::new(PageWorker {
        tenant_id,
        session_id: SessionId::new(),
        page_id: PageId::new(),
        requests: Mutex::new(Vec::new()),
        corrupt_response_tenant: false,
        failure: None,
    });
    let runtime = Arc::new(GatewayWorkerRuntime::new(
        Arc::clone(&worker),
        gateway_placement()?,
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
        return Err("unexpected create response".into());
    };
    let session_id = created
        .data()
        .operation()
        .session()
        .map(|session| session.id.clone())
        .ok_or("created session missing")?;

    let Err(error) = router.execute(
        &principal,
        ApiRequest::CreatePage(PageCreateRequest {
            session_id,
            body: PageCreateBody {
                url: Some("https://example.test".to_owned()),
            },
        }),
    ) else {
        return Err("an unsupported initial URL must fail closed".into());
    };
    assert_eq!(error.code(), browserd_core::ErrorCode::InvalidRequest);
    assert!(
        worker
            .requests
            .lock()
            .map_err(|_| "request lock poisoned")?
            .is_empty()
    );
    Ok(())
}

#[test]
fn action_endpoints_preserve_request_identity_and_complete_worker_status()
-> Result<(), Box<dyn Error>> {
    let (principal, worker, router, session_id) = resource_fixture()?;
    let idempotency_key = Uuid::new_v4();
    let submitted = router.execute(
        &principal,
        ApiRequest::SubmitAction(ActionSubmitCommand {
            session_id: session_id.clone(),
            idempotency_key,
            body: ActionSubmitRequest {
                page_id: worker.page_id.clone(),
                if_session_incarnation: 1,
                execution_timeout_ms: 1_000,
                action: ActionPayload::GetTitle,
            },
        }),
    )?;
    let ApiResponse::Action(submitted) = submitted else {
        return Err("unexpected action submit response".into());
    };
    let action_id = submitted.data().action_id().clone();
    let action_sequence = submitted.data().action_sequence();
    assert!(action_sequence.get() > 0);
    assert_eq!(submitted.data().state(), ActionState::ReadyToDispatch);
    assert_eq!(submitted.data().request().kind(), ActionKind::ReadOnly);
    let requests = worker
        .requests
        .lock()
        .map_err(|_| "request lock poisoned")?;
    let submit = requests.iter().find_map(|request| match request {
        WorkerRpcRequest::SubmitAction {
            fence,
            action_id,
            action_sequence,
            requester_principal_id,
            idempotency_key,
            canonical_request_hash,
            kind,
            page_id,
            payload,
            ..
        } => Some((
            fence,
            action_id,
            action_sequence,
            requester_principal_id,
            idempotency_key,
            canonical_request_hash,
            kind,
            page_id,
            payload,
        )),
        _ => None,
    });
    let Some((
        fence,
        wire_action_id,
        wire_action_sequence,
        requester,
        key,
        hash,
        kind,
        page_id,
        payload,
    )) = submit
    else {
        return Err("submit RPC not recorded".into());
    };
    assert_eq!(fence.tenant_id, worker.tenant_id);
    assert_eq!(fence.session_id, session_id);
    assert_eq!(wire_action_id, &action_id);
    assert_eq!(*wire_action_sequence, action_sequence);
    assert_eq!(requester, principal.principal_id());
    assert_eq!(key, &idempotency_key.to_string());
    assert_ne!(hash, &[0; 32]);
    assert_eq!(*kind, ActionKind::ReadOnly);
    assert_eq!(page_id.as_ref(), Some(&worker.page_id));
    let wire_payload = serde_json::from_slice::<serde_json::Value>(payload)?;
    assert_eq!(wire_payload, serde_json::json!({"type": "get_title"}));
    drop(requests);

    let fetched = router.execute(
        &principal,
        ApiRequest::GetAction(ActionGetRequest {
            session_id: session_id.clone(),
            action_id: action_id.clone(),
        }),
    )?;
    assert!(matches!(
        fetched,
        ApiResponse::Action(response)
            if response.data().state() == ActionState::OutcomeUnknown
                && matches!(
                    response.data().terminal_detail(),
                    Some(TerminalDetail::OutcomeUnknown(
                        OutcomeUnknownReason::AmbiguousTransportLoss
                    ))
                )
    ));
    let cancelled = router.execute(
        &principal,
        ApiRequest::CancelAction(ActionGetRequest {
            session_id: session_id.clone(),
            action_id: action_id.clone(),
        }),
    )?;
    assert!(matches!(
        cancelled,
        ApiResponse::Action(response)
            if response.data().state() == ActionState::OutcomeUnknown
                && response.data().terminal_detail()
                    == Some(TerminalDetail::OutcomeUnknown(
                        OutcomeUnknownReason::AmbiguousTransportLoss
                    ))
    ));
    let resolved = router.execute(
        &principal,
        ApiRequest::ResolveAction(ActionResolveRequest {
            session_id,
            action_id,
            body: ActionResolveBody {
                resolution: ResolutionRequestKind::ConfirmedNotExecuted,
                basis: "operator verified no effect".to_owned(),
                note: None,
            },
        }),
    )?;
    assert!(matches!(
        resolved,
        ApiResponse::Action(response)
            if response.data().resolution().is_some_and(|annotation| {
                annotation.kind() == ResolutionKind::ConfirmedNotExecuted
                    && annotation.resolved_by() == principal.principal_id()
            })
    ));
    Ok(())
}

#[test]
fn action_lookup_treats_worker_identity_drift_as_ambiguous_after_dispatch()
-> Result<(), Box<dyn Error>> {
    let (principal, worker, router, session_id) = resource_fixture()?;
    let submitted = router.execute(
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
    )?;
    let ApiResponse::Action(submitted) = submitted else {
        return Err("unexpected action submit response".into());
    };
    let action_id = submitted.data().action_id().clone();
    worker
        .corrupt_action_hash_on_get
        .store(true, Ordering::Release);

    let response = router.execute(
        &principal,
        ApiRequest::GetAction(ActionGetRequest {
            session_id,
            action_id,
        }),
    )?;
    assert!(matches!(
        response,
        ApiResponse::Action(response)
            if response.data().state() == ActionState::OutcomeUnknown
                && response.data().terminal_detail()
                    == Some(TerminalDetail::OutcomeUnknown(
                        OutcomeUnknownReason::AmbiguousTransportLoss
                    ))
    ));
    Ok(())
}

#[test]
fn artifact_metadata_is_read_through_the_exact_worker_fence() -> Result<(), Box<dyn Error>> {
    let (principal, worker, router, session_id) = resource_fixture()?;
    let response = router.execute(
        &principal,
        ApiRequest::GetArtifact(ArtifactRequest {
            session_id: session_id.clone(),
            artifact_id: worker.artifact_id.clone(),
        }),
    )?;
    assert!(matches!(
        response,
        ApiResponse::Artifact(response)
            if response.data().key.tenant_id() == &worker.tenant_id
                && response.data().key.session_id() == &session_id
                && response.data().key.artifact_id() == &worker.artifact_id
                && response.data().state == browserd_artifacts::ArtifactState::Available
                && response.data().checksum_sha256 == Some([8; 32])
                && response.data().size_bytes == Some(4)
    ));
    Ok(())
}

#[test]
fn approval_endpoints_route_uuidv7_ids_without_exposing_raw_credentials()
-> Result<(), Box<dyn Error>> {
    let (principal, worker, router, session_id) = resource_fixture()?;
    let listed = router.execute(
        &principal,
        ApiRequest::ListApprovals(ApprovalListQuery {
            state: None,
            session_id: Some(session_id),
            limit: 10,
            page_token: None,
        }),
    )?;
    assert!(matches!(
        listed,
        ApiResponse::Approvals(response)
            if response.data().items().len() == 1
                && response.data().items()[0].approval_id == *worker.approval_id.as_uuid()
                && response.data().items()[0].proposal.credential_refs_hash().as_bytes()
                    == &[3; 32]
    ));
    let approval_uuid = *worker.approval_id.as_uuid();
    let fetched = router.execute(&principal, ApiRequest::GetApproval(approval_uuid))?;
    assert!(matches!(
        fetched,
        ApiResponse::Approval(response)
            if response.data().approval_id == approval_uuid
                && response.data().tenant_id == worker.tenant_id
    ));
    let decided = router.execute(
        &principal,
        ApiRequest::DecideApproval {
            approval_id: approval_uuid,
            body: ApprovalDecisionBody {
                decision: ApprovalDecisionRequest::Approve,
                reason: "reviewed by an operator".to_owned(),
            },
        },
    )?;
    assert!(matches!(
        decided,
        ApiResponse::Approval(response)
            if matches!(
                response.data().state,
                browserd_policy::ApprovalState::Approved { .. }
            )
    ));
    Ok(())
}

#[test]
fn approval_route_preflight_rejects_duplicate_active_bindings() -> Result<(), Box<dyn Error>> {
    let tenant_id = TenantId::new();
    let principal = authenticated_principal(tenant_id.clone())?;
    let worker = resource_worker(tenant_id, principal.principal_id().clone());
    let runtime = Arc::new(GatewayWorkerRuntime::new(
        Arc::clone(&worker),
        gateway_placement()?,
    )?);
    let router = ApiRouter::new(runtime);
    for _ in 0..2 {
        let response = router.execute(
            &principal,
            ApiRequest::CreateSession {
                body: decode_session_create(CREATE_JSON)?,
                idempotency_key: Uuid::new_v4().to_string(),
                received_at: Instant::now(),
            },
        )?;
        assert!(matches!(response, ApiResponse::SessionCreate(_)));
    }

    let Err(error) = router.execute(
        &principal,
        ApiRequest::GetApproval(*worker.approval_id.as_uuid()),
    ) else {
        return Err("duplicate approval bindings must fail closed".into());
    };
    assert_eq!(error.code(), browserd_core::ErrorCode::PlacementMismatch);
    let requests = worker
        .requests
        .lock()
        .map_err(|_| "request lock poisoned")?;
    assert_eq!(
        requests
            .iter()
            .filter(|request| matches!(request, WorkerRpcRequest::GetApproval { .. }))
            .count(),
        2
    );
    Ok(())
}

#[test]
fn approval_route_preflight_fails_closed_when_the_active_route_bound_is_exceeded()
-> Result<(), Box<dyn Error>> {
    let tenant_id = TenantId::new();
    let principal = authenticated_principal(tenant_id.clone())?;
    let worker = resource_worker(tenant_id, principal.principal_id().clone());
    let runtime = Arc::new(GatewayWorkerRuntime::new(
        Arc::clone(&worker),
        gateway_placement()?,
    )?);
    let router = ApiRouter::new(runtime);
    for _ in 0..257 {
        let response = router.execute(
            &principal,
            ApiRequest::CreateSession {
                body: decode_session_create(CREATE_JSON)?,
                idempotency_key: Uuid::new_v4().to_string(),
                received_at: Instant::now(),
            },
        )?;
        assert!(matches!(response, ApiResponse::SessionCreate(_)));
    }

    let Err(error) = router.execute(
        &principal,
        ApiRequest::GetApproval(*worker.approval_id.as_uuid()),
    ) else {
        return Err("an over-bound approval route scan must fail closed".into());
    };
    assert_eq!(error.code(), browserd_core::ErrorCode::WorkerUnavailable);
    assert!(
        worker
            .requests
            .lock()
            .map_err(|_| "request lock poisoned")?
            .iter()
            .all(|request| !matches!(request, WorkerRpcRequest::GetApproval { .. }))
    );
    Ok(())
}
