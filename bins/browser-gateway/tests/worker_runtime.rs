#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

#[path = "support/singlehost_safety.rs"]
mod singlehost_safety;

use std::collections::BTreeMap;
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
    ApprovalDecisionRequest, ApprovalListQuery, ArtifactRequest, ArtifactUploadBody,
    ArtifactUploadRequest, PageActivateRequest, PageCreateBody, PageCreateRequest,
    PageDeleteRequest, PageListRequest, ResolutionRequestKind, WaitCondition, WaitUntil,
    decode_session_create,
};
use browserd_auth::{
    AuthConfig, AuthenticatedPrincipal, RevocationRegistry, ServiceClaims, ServiceTokenSigner,
    ServiceTokenVerifier, VerificationKeySet,
};
use browserd_core::{
    ActionId, ActionState, ApprovalId, ArtifactId, CreateOperationState, ErrorCode, PageId,
    PrincipalId, SessionId, TenantId, WorkerId,
};
use browserd_worker::{
    WorkerActionCommand, WorkerActionReceipt, WorkerActionStatus, WorkerApprovalActionType,
    WorkerApprovalDecision, WorkerApprovalReceipt, WorkerApprovalState, WorkerArtifactReceipt,
    WorkerArtifactSource, WorkerArtifactState, WorkerCanonicalActionProposal,
    WorkerCreateSessionReceipt, WorkerCreateSessionRequest, WorkerIsolationProfile,
    WorkerNavigateWaitUntil, WorkerPageReceipt, WorkerRpcCompletionError, WorkerRpcEnqueueError,
    WorkerRpcError, WorkerRpcFailure, WorkerRpcFailureCode, WorkerRpcRequest, WorkerRpcResponse,
    WorkerSessionFence, WorkerSessionLifecycle, WorkerSessionOptionsV1,
    WorkerSessionOwnershipReceipt, WorkerSessionReceipt, WorkerViewport, WorkerWaitCondition,
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
    closed: AtomicBool,
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
            restored_checkpoint: None,
        })
    }

    fn request(&self, request: WorkerRpcRequest) -> Result<WorkerRpcResponse, WorkerRpcError> {
        let recorded = self.request.lock().map_err(|_| WorkerRpcError::Runtime)?;
        let created = recorded.as_ref().ok_or(WorkerRpcError::Protocol)?;
        let (fence, lifecycle, closed, inspected_worker) = match request {
            WorkerRpcRequest::GetSession { fence } => (
                fence,
                if self.closed.load(Ordering::Acquire) {
                    WorkerSessionLifecycle::Closed
                } else {
                    WorkerSessionLifecycle::Ready
                },
                false,
                None,
            ),
            WorkerRpcRequest::InspectSession {
                expected_worker_id,
                fence,
            } => (
                fence,
                if self.closed.load(Ordering::Acquire) {
                    WorkerSessionLifecycle::Closed
                } else {
                    WorkerSessionLifecycle::Ready
                },
                false,
                Some(expected_worker_id),
            ),
            WorkerRpcRequest::CloseSession { fence, .. } => {
                (fence, WorkerSessionLifecycle::Closed, true, None)
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
        if closed {
            self.closed.store(true, Ordering::Release);
        }
        let receipt = WorkerSessionReceipt {
            fence,
            lifecycle,
            primary_page_id: PageId::new(),
        };
        Ok(if let Some(worker_id) = inspected_worker {
            WorkerRpcResponse::SessionOwnership(WorkerSessionOwnershipReceipt {
                worker_id,
                session: receipt,
            })
        } else if closed {
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

struct CheckpointWorker {
    inner: RecordingWorker,
    restored_checkpoint: Option<browserd_worker::WorkerCheckpointRestoreReceipt>,
}

impl GatewayWorkerClient for CheckpointWorker {
    type PendingAction = ImmediatePending;

    fn create_session(
        &self,
        request: WorkerCreateSessionRequest,
    ) -> Result<WorkerCreateSessionReceipt, WorkerRpcError> {
        let mut receipt = self.inner.create_session(request)?;
        receipt.restored_checkpoint = self.restored_checkpoint.clone();
        Ok(receipt)
    }

    fn request(&self, request: WorkerRpcRequest) -> Result<WorkerRpcResponse, WorkerRpcError> {
        self.inner.request(request)
    }

    fn enqueue_action(
        &self,
        request: WorkerRpcRequest,
    ) -> Result<Self::PendingAction, WorkerRpcEnqueueError> {
        self.inner.enqueue_action(request)
    }
}

struct RacingWorker {
    create: Mutex<Option<WorkerCreateSessionRequest>>,
    session_id: SessionId,
    block_first_get: AtomicBool,
    closed: AtomicBool,
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
            restored_checkpoint: None,
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
    artifact_list_ids: Vec<ArtifactId>,
    artifact_list_fault: AtomicUsize,
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
            restored_checkpoint: None,
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
                custody: None,
                custody_requirement: None,
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
                typed_binding: None,
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
            WorkerRpcRequest::UploadNamedArtifact {
                fence,
                bytes,
                content_type,
                display_filename,
                ..
            } => Ok(WorkerRpcResponse::ArtifactStored(WorkerArtifactReceipt {
                fence,
                artifact_id: self.artifact_id.clone(),
                state: WorkerArtifactState::Available,
                size_bytes: bytes.len() as u64,
                checksum_sha256: [8; 32],
                content_type,
                source: WorkerArtifactSource::ClientUpload,
                display_filename: Some(display_filename.clone()),
                origin: display_filename,
                object_generation: [9; 32],
            })),
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
                    display_filename: None,
                    origin: "gateway-test-upload".to_owned(),
                    object_generation: [9; 32],
                }))
            }
            WorkerRpcRequest::ListArtifacts {
                fence,
                after,
                limit,
            } => {
                let mut receipts = self
                    .artifact_list_ids
                    .iter()
                    .filter(|id| after.as_ref().is_none_or(|after| *id > after))
                    .take(limit)
                    .map(|id| WorkerArtifactReceipt {
                        fence: fence.clone(),
                        artifact_id: id.clone(),
                        state: WorkerArtifactState::Available,
                        size_bytes: 4,
                        checksum_sha256: [8; 32],
                        content_type: "application/octet-stream".to_owned(),
                        source: WorkerArtifactSource::BrowserDownload,
                        display_filename: None,
                        origin: "browserd-worker-download".to_owned(),
                        object_generation: [9; 32],
                    })
                    .collect::<Vec<_>>();
                if let Some(last) = receipts.last_mut() {
                    match self.artifact_list_fault.load(Ordering::Acquire) {
                        1 => last.fence.tenant_id = TenantId::new(),
                        2 => last.fence.session_id = SessionId::new(),
                        3 => last.fence.worker_epoch += 1,
                        4 => last.artifact_id = self.artifact_list_ids[0].clone(),
                        6 => {
                            last.artifact_id =
                                after.unwrap_or_else(|| self.artifact_list_ids[0].clone())
                        }
                        7 => last.content_type = "invalid\ncontent-type".to_owned(),
                        8 => last.object_generation = [0; 32],
                        _ => {}
                    }
                }
                if self.artifact_list_fault.load(Ordering::Acquire) == 5 {
                    receipts.reverse();
                }
                if self.artifact_list_fault.load(Ordering::Acquire) == 9 {
                    receipts.extend(receipts.clone());
                }
                Ok(WorkerRpcResponse::Artifacts(receipts))
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
            restored_checkpoint: None,
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
        let (fence, lifecycle, closed, inspected_worker) = match request {
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
                (fence, WorkerSessionLifecycle::Ready, false, None)
            }
            WorkerRpcRequest::InspectSession {
                expected_worker_id,
                fence,
            } => (
                fence,
                if self.closed.load(Ordering::Acquire) {
                    WorkerSessionLifecycle::Closed
                } else {
                    WorkerSessionLifecycle::Ready
                },
                false,
                Some(expected_worker_id),
            ),
            WorkerRpcRequest::CloseSession { fence, .. } => {
                (fence, WorkerSessionLifecycle::Closed, true, None)
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
        if closed {
            self.closed.store(true, Ordering::Release);
        }
        let receipt = WorkerSessionReceipt {
            fence,
            lifecycle,
            primary_page_id: PageId::new(),
        };
        Ok(if let Some(worker_id) = inspected_worker {
            WorkerRpcResponse::SessionOwnership(WorkerSessionOwnershipReceipt {
                worker_id,
                session: receipt,
            })
        } else if closed {
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
    authenticated_principal_with_scopes(
        tenant_id,
        &[
            "session:create",
            "session:read",
            "session:close",
            "browser:act",
            "browser:evaluate",
            "artifact:read",
            "artifact:upload",
            "approval:read",
            "approval:decide",
        ],
    )
}

fn authenticated_principal_with_scopes(
    tenant_id: TenantId,
    scopes: &[&str],
) -> Result<AuthenticatedPrincipal, Box<dyn Error>> {
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
        scopes.iter().map(|scope| (*scope).to_owned()).collect(),
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
        artifact_list_ids: [
            "01900000-0000-7000-8000-000000000001",
            "01900000-0000-7000-8000-000000000002",
            "01900000-0000-7000-8000-000000000003",
        ]
        .into_iter()
        .map(|id| id.parse().expect("typed artifact ID"))
        .collect(),
        artifact_list_fault: AtomicUsize::new(0),
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
        closed: AtomicBool::new(false),
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
fn create_dispatch_forwards_every_v1_session_option_to_the_worker() -> Result<(), Box<dyn Error>> {
    let tenant_id = TenantId::new();
    let principal = authenticated_principal(tenant_id)?;
    let worker = Arc::new(RecordingWorker {
        request: Mutex::new(None),
        session_id: SessionId::new(),
        corrupt_epoch: false,
        closed: AtomicBool::new(false),
    });
    let runtime = Arc::new(GatewayWorkerRuntime::new(
        Arc::clone(&worker),
        gateway_placement()?,
    )?);
    let router = ApiRouter::new(runtime);

    let response = router.execute(
        &principal,
        ApiRequest::CreateSession {
            body: decode_session_create(CREATE_JSON)?,
            idempotency_key: Uuid::new_v4().to_string(),
            received_at: Instant::now(),
        },
    )?;
    assert!(matches!(response, ApiResponse::SessionCreate(_)));

    let recorded = worker
        .request
        .lock()
        .map_err(|_| "recorded request lock poisoned")?
        .clone()
        .ok_or("worker request missing")?;
    assert_eq!(
        recorded.requested_isolation,
        WorkerIsolationProfile::SharedContext
    );
    assert_eq!(recorded.options_version, 1);
    assert_eq!(
        recorded.canonical_request_hash,
        recorded
            .options
            .canonical_request_hash(recorded.requested_isolation),
        "gateway canonicalization and the worker option commitment must agree",
    );
    assert_eq!(
        recorded.options,
        WorkerSessionOptionsV1 {
            workload_class_hint: "interactive".to_owned(),
            viewport: WorkerViewport {
                width: 1280,
                height: 720,
                device_scale_factor: 1,
            },
            locale: "ko-KR".to_owned(),
            timezone: "Asia/Seoul".to_owned(),
            user_agent: None,
            network_policy_id: "public-web-default".to_owned(),
            network_class: "public".to_owned(),
            checkpoint_ref: None,
            dialog_policy: "auto_dismiss".to_owned(),
            feature_profile: "standard".to_owned(),
            ttl_seconds: 1_800,
            idle_timeout_seconds: 600,
            metadata: BTreeMap::from([("agent_run_id".to_owned(), "run_123".to_owned())]),
        }
    );
    Ok(())
}

#[test]
fn checkpoint_restore_requires_scope_and_preserves_the_reference_into_a_new_session()
-> Result<(), Box<dyn Error>> {
    let tenant = TenantId::new();
    let source_session = SessionId::new();
    let destination = SessionId::new();
    let checkpoint_ref = "opaque-checkpoint";
    let worker = Arc::new(CheckpointWorker {
        inner: RecordingWorker {
            request: Mutex::new(None),
            session_id: destination.clone(),
            corrupt_epoch: false,
            closed: AtomicBool::new(false),
        },
        restored_checkpoint: Some(browserd_worker::WorkerCheckpointRestoreReceipt {
            checkpoint_ref: checkpoint_ref.to_owned(),
            source_session_id: source_session.clone(),
        }),
    });
    let runtime = Arc::new(GatewayWorkerRuntime::new(
        Arc::clone(&worker),
        gateway_placement()?,
    )?);
    let router = ApiRouter::new(runtime);
    let key = Uuid::new_v4().to_string();
    let mut body = decode_session_create(CREATE_JSON)?;
    body.checkpoint_ref = Some(checkpoint_ref.to_owned());
    body.metadata.insert(
        "restored_from_checkpoint".to_owned(),
        "spoofed-ref".to_owned(),
    );
    body.metadata.insert(
        "recovered_from_session".to_owned(),
        "spoofed-session".to_owned(),
    );
    let request = || ApiRequest::CreateSession {
        body: body.clone(),
        idempotency_key: key.clone(),
        received_at: Instant::now(),
    };
    for scopes in [&["session:create"][..], &["checkpoint:read"][..]] {
        assert!(
            router
                .execute(
                    &authenticated_principal_with_scopes(tenant.clone(), scopes)?,
                    request()
                )
                .is_err()
        );
    }
    assert!(worker.inner.request.lock().unwrap().is_none());
    let principal = authenticated_principal_with_scopes(
        tenant.clone(),
        &["session:create", "checkpoint:read", "session:read"],
    )?;
    let ApiResponse::SessionCreate(created) = router.execute(&principal, request())? else {
        return Err("unexpected restore response".into());
    };
    assert_eq!(
        created.data().operation().state(),
        CreateOperationState::Succeeded
    );
    let session = created
        .data()
        .operation()
        .session()
        .ok_or("restored session missing")?;
    assert_eq!(session.id, destination);
    assert_ne!(session.id, source_session);
    assert_eq!(session.incarnation, 1);
    assert_eq!(
        session
            .metadata
            .get("restored_from_checkpoint")
            .map(String::as_str),
        Some(checkpoint_ref)
    );
    assert_eq!(
        session.metadata.get("recovered_from_session"),
        Some(&source_session.to_string())
    );
    assert_eq!(
        session.metadata.get("agent_run_id").map(String::as_str),
        Some("run_123")
    );
    let recorded = worker
        .inner
        .request
        .lock()
        .unwrap()
        .clone()
        .ok_or("worker create missing")?;
    assert_eq!(recorded.tenant_id, tenant);
    assert_eq!(
        recorded.options.checkpoint_ref.as_deref(),
        Some(checkpoint_ref)
    );
    assert_eq!(
        recorded.canonical_request_hash,
        recorded
            .options
            .canonical_request_hash(recorded.requested_isolation)
    );
    let ApiResponse::Session(fetched) =
        router.execute(&principal, ApiRequest::GetSession(destination))?
    else {
        return Err("unexpected restored session".into());
    };
    assert_eq!(fetched.data().metadata, session.metadata);
    assert!(
        router
            .execute(&principal, ApiRequest::GetSession(source_session))
            .is_err()
    );
    Ok(())
}

#[test]
fn invalid_checkpoint_restore_receipts_never_register_a_session_route_or_catalog_entry()
-> Result<(), Box<dyn Error>> {
    let destination = SessionId::new();
    let restored = browserd_worker::WorkerCheckpointRestoreReceipt {
        checkpoint_ref: "opaque-checkpoint".to_owned(),
        source_session_id: SessionId::new(),
    };
    for (requested, receipt) in [
        (Some("opaque-checkpoint"), None),
        (
            Some("opaque-checkpoint"),
            Some(browserd_worker::WorkerCheckpointRestoreReceipt {
                checkpoint_ref: "different-checkpoint".to_owned(),
                ..restored.clone()
            }),
        ),
        (
            Some("opaque-checkpoint"),
            Some(browserd_worker::WorkerCheckpointRestoreReceipt {
                source_session_id: destination.clone(),
                ..restored.clone()
            }),
        ),
        (None, Some(restored)),
    ] {
        let principal = authenticated_principal_with_scopes(
            TenantId::new(),
            &["session:create", "checkpoint:read", "session:read"],
        )?;
        let worker = Arc::new(CheckpointWorker {
            inner: RecordingWorker {
                request: Mutex::new(None),
                session_id: destination.clone(),
                corrupt_epoch: false,
                closed: AtomicBool::new(false),
            },
            restored_checkpoint: receipt,
        });
        let runtime = Arc::new(GatewayWorkerRuntime::new(worker, gateway_placement()?)?);
        let router = ApiRouter::new(runtime);
        let mut body = decode_session_create(CREATE_JSON)?;
        body.checkpoint_ref = requested.map(str::to_owned);
        let ApiResponse::SessionCreate(created) = router.execute(
            &principal,
            ApiRequest::CreateSession {
                body,
                idempotency_key: Uuid::new_v4().to_string(),
                received_at: Instant::now(),
            },
        )?
        else {
            return Err("unexpected restore response".into());
        };
        assert_eq!(
            created.data().operation().state(),
            CreateOperationState::Failed
        );
        assert!(created.data().operation().session().is_none());
        assert!(
            router
                .execute(&principal, ApiRequest::GetSession(destination.clone()))
                .is_err()
        );
        let ApiResponse::Sessions(sessions) = router.execute(
            &principal,
            ApiRequest::ListSessions(browserd_api::SessionListQuery::default()),
        )?
        else {
            return Err("unexpected session catalog response".into());
        };
        assert!(sessions.data().items().is_empty());
    }
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
        closed: AtomicBool::new(false),
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
        closed: AtomicBool::new(false),
    });
    let placement = gateway_placement()?;
    let runtime = Arc::new(GatewayWorkerRuntime::new(worker, placement)?);
    let router = ApiRouter::new(runtime);
    let mut body = decode_session_create(CREATE_JSON)?;
    body.metadata.insert(
        "restored_from_checkpoint".to_owned(),
        "spoofed-ref".to_owned(),
    );
    body.metadata.insert(
        "recovered_from_session".to_owned(),
        "spoofed-session".to_owned(),
    );

    let created = router.execute(
        &principal,
        ApiRequest::CreateSession {
            body,
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
            && !response.data().metadata.contains_key("restored_from_checkpoint")
            && !response.data().metadata.contains_key("recovered_from_session")
            && response.data().metadata.get("agent_run_id").map(String::as_str)==Some("run_123")
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
        closed: AtomicBool::new(false),
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
            action,
            execution_timeout_ms,
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
            action,
            execution_timeout_ms,
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
        action,
        execution_timeout_ms,
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
    assert_eq!(action, &WorkerActionCommand::GetTitle);
    assert_eq!(execution_timeout_ms.get(), 1_000);
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
fn unsupported_public_actions_are_rejected_before_durable_claim_or_worker_enqueue()
-> Result<(), Box<dyn Error>> {
    let (principal, worker, router, session_id) = resource_fixture()?;
    let idempotency_key = Uuid::new_v4();
    let requests_before = worker
        .requests
        .lock()
        .map_err(|_| "request lock poisoned")?
        .len();
    let unsupported = router.execute(
        &principal,
        ApiRequest::SubmitAction(ActionSubmitCommand {
            session_id: session_id.clone(),
            idempotency_key,
            body: ActionSubmitRequest {
                page_id: worker.page_id.clone(),
                if_session_incarnation: 1,
                execution_timeout_ms: 1_000,
                action: ActionPayload::NewPage { url: None },
            },
        }),
    );
    let error = unsupported
        .err()
        .ok_or("unsupported action unexpectedly reached the worker")?;
    assert_eq!(error.code(), browserd_core::ErrorCode::InvalidRequest);
    assert_eq!(
        worker
            .requests
            .lock()
            .map_err(|_| "request lock poisoned")?
            .len(),
        requests_before
    );

    let supported = router.execute(
        &principal,
        ApiRequest::SubmitAction(ActionSubmitCommand {
            session_id,
            idempotency_key,
            body: ActionSubmitRequest {
                page_id: worker.page_id.clone(),
                if_session_incarnation: 1,
                execution_timeout_ms: 1_000,
                action: ActionPayload::GetTitle,
            },
        }),
    )?;
    assert!(matches!(supported, ApiResponse::Action(_)));
    Ok(())
}

#[test]
fn navigate_actions_reach_the_worker_with_a_typed_wait_until_lifecycle()
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
                execution_timeout_ms: 30_000,
                action: ActionPayload::Navigate {
                    url: "https://example.test/path".to_owned(),
                    wait_until: WaitUntil::Domcontentloaded,
                },
            },
        }),
    )?;
    let ApiResponse::Action(submitted) = submitted else {
        return Err("unexpected navigate submit response".into());
    };
    assert_eq!(submitted.data().request().kind(), ActionKind::Mutating);

    let requests = worker
        .requests
        .lock()
        .map_err(|_| "request lock poisoned")?;
    let action = requests
        .iter()
        .find_map(|request| match request {
            WorkerRpcRequest::SubmitAction { action, kind, .. } => Some((action, kind)),
            _ => None,
        })
        .ok_or("navigate submit RPC not recorded")?;
    assert_eq!(*action.1, ActionKind::Mutating);
    assert_eq!(
        action.0,
        &WorkerActionCommand::Navigate {
            url: "https://example.test/path".to_owned(),
            wait_until: WorkerNavigateWaitUntil::Domcontentloaded,
        }
    );
    Ok(())
}

#[test]
fn history_traversal_actions_reach_the_worker_as_typed_mutations() -> Result<(), Box<dyn Error>> {
    let (principal, worker, router, session_id) = resource_fixture()?;
    let submitted = router.execute(
        &principal,
        ApiRequest::SubmitAction(ActionSubmitCommand {
            session_id: session_id.clone(),
            idempotency_key: Uuid::new_v4(),
            body: ActionSubmitRequest {
                page_id: worker.page_id.clone(),
                if_session_incarnation: 1,
                execution_timeout_ms: 30_000,
                action: ActionPayload::GoBack,
            },
        }),
    )?;
    let ApiResponse::Action(submitted) = submitted else {
        return Err("unexpected go_back submit response".into());
    };
    assert_eq!(submitted.data().request().kind(), ActionKind::Mutating);

    let requests = worker
        .requests
        .lock()
        .map_err(|_| "request lock poisoned")?;
    let action = requests
        .iter()
        .find_map(|request| match request {
            WorkerRpcRequest::SubmitAction { action, kind, .. } => Some((action, kind)),
            _ => None,
        })
        .ok_or("go_back submit RPC not recorded")?;
    assert_eq!(*action.1, ActionKind::Mutating);
    assert_eq!(action.0, &WorkerActionCommand::GoBack);
    Ok(())
}

#[test]
fn raw_input_actions_reach_the_worker_as_typed_mutations() -> Result<(), Box<dyn Error>> {
    // Each mutating action gets a fresh session so it owns its own admission lane.
    for (payload, expected) in [
        (
            ActionPayload::PressKey {
                key: "Enter".to_owned(),
            },
            WorkerActionCommand::PressKey {
                key: "Enter".to_owned(),
            },
        ),
        (
            ActionPayload::Scroll {
                delta_x: 0,
                delta_y: 240,
            },
            WorkerActionCommand::Scroll {
                delta_x: 0,
                delta_y: 240,
            },
        ),
    ] {
        let (principal, worker, router, session_id) = resource_fixture()?;
        let submitted = router.execute(
            &principal,
            ApiRequest::SubmitAction(ActionSubmitCommand {
                session_id: session_id.clone(),
                idempotency_key: Uuid::new_v4(),
                body: ActionSubmitRequest {
                    page_id: worker.page_id.clone(),
                    if_session_incarnation: 1,
                    execution_timeout_ms: 30_000,
                    action: payload,
                },
            }),
        )?;
        let ApiResponse::Action(submitted) = submitted else {
            return Err("unexpected raw-input submit response".into());
        };
        assert_eq!(submitted.data().request().kind(), ActionKind::Mutating);

        let requests = worker
            .requests
            .lock()
            .map_err(|_| "request lock poisoned")?;
        let found = requests.iter().any(|request| {
            matches!(
                request,
                WorkerRpcRequest::SubmitAction { action, .. } if action == &expected
            )
        });
        assert!(
            found,
            "raw-input action {expected:?} did not reach the worker"
        );
    }
    Ok(())
}

#[test]
fn query_all_reaches_the_worker_as_a_read_only_selector() -> Result<(), Box<dyn Error>> {
    for frame_path in [
        vec![],
        vec!["iframe#outer".to_owned(), "iframe#inner".to_owned()],
    ] {
        let (principal, worker, router, session_id) = resource_fixture()?;
        let idempotency_key = Uuid::new_v4();
        let body = ActionSubmitRequest {
            page_id: worker.page_id.clone(),
            if_session_incarnation: 1,
            execution_timeout_ms: 30_000,
            action: ActionPayload::QueryAll {
                selector: "a.link".to_owned(),
                frame_path: frame_path.clone(),
            },
        };
        let expected_hash =
            *browserd_operations::CanonicalRequestHash::from_json(&serde_json::to_value(&body)?)
                .as_bytes();
        let request = |body| {
            ApiRequest::SubmitAction(ActionSubmitCommand {
                session_id: session_id.clone(),
                idempotency_key,
                body,
            })
        };
        let ApiResponse::Action(submitted) = router.execute(&principal, request(body.clone()))?
        else {
            return Err("unexpected query_all submit response".into());
        };
        assert_eq!(submitted.data().request().kind(), ActionKind::ReadOnly);
        {
            let requests = worker
                .requests
                .lock()
                .map_err(|_| "request lock poisoned")?;
            let (action, kind, hash) = requests
                .iter()
                .rev()
                .find_map(|request| match request {
                    WorkerRpcRequest::SubmitAction {
                        action,
                        kind,
                        canonical_request_hash,
                        ..
                    } => Some((action, kind, canonical_request_hash)),
                    _ => None,
                })
                .ok_or("query_all submit RPC not recorded")?;
            assert_eq!(*kind, ActionKind::ReadOnly);
            assert_eq!(*hash, expected_hash);
            assert_eq!(
                action,
                &WorkerActionCommand::QueryAll {
                    selector: "a.link".to_owned(),
                    frame_path: frame_path.clone(),
                }
            );
        }
        let before = worker
            .requests
            .lock()
            .map_err(|_| "request lock poisoned")?
            .len();
        let mut different = body;
        different.action = ActionPayload::QueryAll {
            selector: "a.link".to_owned(),
            frame_path: vec!["iframe#different".to_owned()],
        };
        let error = router
            .execute(&principal, request(different))
            .err()
            .ok_or("changed frame path must conflict with the original idempotency key")?;
        assert_eq!(error.code(), ErrorCode::IdempotencyConflict);
        assert_eq!(
            worker
                .requests
                .lock()
                .map_err(|_| "request lock poisoned")?
                .len(),
            before
        );
    }
    Ok(())
}

#[test]
fn get_text_reaches_the_worker_as_a_read_only_node_reference() -> Result<(), Box<dyn Error>> {
    let (principal, worker, router, session_id) = resource_fixture()?;
    let submitted = router.execute(
        &principal,
        ApiRequest::SubmitAction(ActionSubmitCommand {
            session_id: session_id.clone(),
            idempotency_key: Uuid::new_v4(),
            body: ActionSubmitRequest {
                page_id: worker.page_id.clone(),
                if_session_incarnation: 1,
                execution_timeout_ms: 30_000,
                action: ActionPayload::GetText {
                    node_ref: "0000000000000001".to_owned(),
                },
            },
        }),
    )?;
    let ApiResponse::Action(submitted) = submitted else {
        return Err("unexpected get_text submit response".into());
    };
    assert_eq!(submitted.data().request().kind(), ActionKind::ReadOnly);

    let requests = worker
        .requests
        .lock()
        .map_err(|_| "request lock poisoned")?;
    let action = requests
        .iter()
        .find_map(|request| match request {
            WorkerRpcRequest::SubmitAction { action, kind, .. } => Some((action, kind)),
            _ => None,
        })
        .ok_or("get_text submit RPC not recorded")?;
    assert_eq!(*action.1, ActionKind::ReadOnly);
    assert_eq!(
        action.0,
        &WorkerActionCommand::GetText {
            node_ref: "0000000000000001".to_owned(),
        }
    );
    Ok(())
}

#[test]
fn node_read_actions_reach_the_worker_as_read_only() -> Result<(), Box<dyn Error>> {
    for (payload, expected) in [
        (
            ActionPayload::GetHtml { node_ref: None },
            WorkerActionCommand::GetHtml { node_ref: None },
        ),
        (
            ActionPayload::GetAttribute {
                node_ref: "0000000000000001".to_owned(),
                name: "href".to_owned(),
            },
            WorkerActionCommand::GetAttribute {
                node_ref: "0000000000000001".to_owned(),
                name: "href".to_owned(),
            },
        ),
        (
            ActionPayload::GetProperties {
                node_ref: "0000000000000001".to_owned(),
            },
            WorkerActionCommand::GetProperties {
                node_ref: "0000000000000001".to_owned(),
            },
        ),
        (
            ActionPayload::GetComputedStyle {
                node_ref: "0000000000000001".to_owned(),
            },
            WorkerActionCommand::GetComputedStyle {
                node_ref: "0000000000000001".to_owned(),
            },
        ),
        (
            ActionPayload::ExtractTable {
                node_ref: "0000000000000001".to_owned(),
            },
            WorkerActionCommand::ExtractTable {
                node_ref: "0000000000000001".to_owned(),
            },
        ),
    ] {
        let (principal, worker, router, session_id) = resource_fixture()?;
        let submitted = router.execute(
            &principal,
            ApiRequest::SubmitAction(ActionSubmitCommand {
                session_id: session_id.clone(),
                idempotency_key: Uuid::new_v4(),
                body: ActionSubmitRequest {
                    page_id: worker.page_id.clone(),
                    if_session_incarnation: 1,
                    execution_timeout_ms: 30_000,
                    action: payload,
                },
            }),
        )?;
        let ApiResponse::Action(submitted) = submitted else {
            return Err("unexpected node-read submit response".into());
        };
        assert_eq!(submitted.data().request().kind(), ActionKind::ReadOnly);

        let requests = worker
            .requests
            .lock()
            .map_err(|_| "request lock poisoned")?;
        let found = requests.iter().any(|request| {
            matches!(
                request,
                WorkerRpcRequest::SubmitAction { action, kind, .. }
                    if *kind == ActionKind::ReadOnly && action == &expected
            )
        });
        assert!(
            found,
            "node-read action {expected:?} did not reach the worker"
        );
    }
    Ok(())
}

#[test]
fn click_reaches_the_worker_as_a_mutating_node_reference() -> Result<(), Box<dyn Error>> {
    let (principal, worker, router, session_id) = resource_fixture()?;
    let submitted = router.execute(
        &principal,
        ApiRequest::SubmitAction(ActionSubmitCommand {
            session_id: session_id.clone(),
            idempotency_key: Uuid::new_v4(),
            body: ActionSubmitRequest {
                page_id: worker.page_id.clone(),
                if_session_incarnation: 1,
                execution_timeout_ms: 30_000,
                action: ActionPayload::Click {
                    node_ref: "0000000000000001".to_owned(),
                },
            },
        }),
    )?;
    let ApiResponse::Action(submitted) = submitted else {
        return Err("unexpected click submit response".into());
    };
    assert_eq!(submitted.data().request().kind(), ActionKind::Mutating);

    let requests = worker
        .requests
        .lock()
        .map_err(|_| "request lock poisoned")?;
    let action = requests
        .iter()
        .find_map(|request| match request {
            WorkerRpcRequest::SubmitAction { action, kind, .. } => Some((action, kind)),
            _ => None,
        })
        .ok_or("click submit RPC not recorded")?;
    assert_eq!(*action.1, ActionKind::Mutating);
    assert_eq!(
        action.0,
        &WorkerActionCommand::Click {
            node_ref: "0000000000000001".to_owned(),
        }
    );
    Ok(())
}

#[test]
fn wait_for_reaches_the_worker_with_a_typed_condition() -> Result<(), Box<dyn Error>> {
    let (principal, worker, router, session_id) = resource_fixture()?;
    let submitted = router.execute(
        &principal,
        ApiRequest::SubmitAction(ActionSubmitCommand {
            session_id: session_id.clone(),
            idempotency_key: Uuid::new_v4(),
            body: ActionSubmitRequest {
                page_id: worker.page_id.clone(),
                if_session_incarnation: 1,
                execution_timeout_ms: 30_000,
                action: ActionPayload::WaitFor {
                    condition: WaitCondition::SelectorVisible {
                        selector: "#ready".to_owned(),
                    },
                },
            },
        }),
    )?;
    let ApiResponse::Action(submitted) = submitted else {
        return Err("unexpected wait_for submit response".into());
    };
    assert_eq!(submitted.data().request().kind(), ActionKind::Mutating);

    let requests = worker
        .requests
        .lock()
        .map_err(|_| "request lock poisoned")?;
    let found = requests.iter().any(|request| {
        matches!(
            request,
            WorkerRpcRequest::SubmitAction { action, .. }
                if action == &WorkerActionCommand::WaitFor {
                    condition: WorkerWaitCondition::SelectorVisible {
                        selector: "#ready".to_owned(),
                    },
                }
        )
    });
    assert!(found, "wait_for did not reach the worker");
    Ok(())
}

#[test]
fn handle_dialog_reaches_the_worker_as_a_mutation() -> Result<(), Box<dyn Error>> {
    let (principal, worker, router, session_id) = resource_fixture()?;
    let submitted = router.execute(
        &principal,
        ApiRequest::SubmitAction(ActionSubmitCommand {
            session_id: session_id.clone(),
            idempotency_key: Uuid::new_v4(),
            body: ActionSubmitRequest {
                page_id: worker.page_id.clone(),
                if_session_incarnation: 1,
                execution_timeout_ms: 30_000,
                action: ActionPayload::HandleDialog {
                    accept: true,
                    prompt_text: None,
                },
            },
        }),
    )?;
    let ApiResponse::Action(submitted) = submitted else {
        return Err("unexpected handle_dialog submit response".into());
    };
    assert_eq!(submitted.data().request().kind(), ActionKind::Mutating);

    let requests = worker
        .requests
        .lock()
        .map_err(|_| "request lock poisoned")?;
    let found = requests.iter().any(|request| {
        matches!(
            request,
            WorkerRpcRequest::SubmitAction { action, .. }
                if action == &WorkerActionCommand::HandleDialog {
                    accept: true,
                    prompt_text: None,
                }
        )
    });
    assert!(found, "handle_dialog did not reach the worker");
    Ok(())
}

#[test]
fn snapshot_reaches_the_worker_as_a_read() -> Result<(), Box<dyn Error>> {
    let (principal, worker, router, session_id) = resource_fixture()?;
    let submitted = router.execute(
        &principal,
        ApiRequest::SubmitAction(ActionSubmitCommand {
            session_id: session_id.clone(),
            idempotency_key: Uuid::new_v4(),
            body: ActionSubmitRequest {
                page_id: worker.page_id.clone(),
                if_session_incarnation: 1,
                execution_timeout_ms: 30_000,
                action: ActionPayload::Snapshot,
            },
        }),
    )?;
    let ApiResponse::Action(submitted) = submitted else {
        return Err("unexpected snapshot submit response".into());
    };
    assert_eq!(submitted.data().request().kind(), ActionKind::ReadOnly);

    let requests = worker
        .requests
        .lock()
        .map_err(|_| "request lock poisoned")?;
    let found = requests.iter().any(|request| {
        matches!(
            request,
            WorkerRpcRequest::SubmitAction { action, .. }
                if action == &WorkerActionCommand::Snapshot
        )
    });
    assert!(found, "snapshot did not reach the worker");
    Ok(())
}

#[test]
fn evaluate_reaches_the_worker_as_a_mutation() -> Result<(), Box<dyn Error>> {
    let (principal, worker, router, session_id) = resource_fixture()?;
    let submitted = router.execute(
        &principal,
        ApiRequest::SubmitAction(ActionSubmitCommand {
            session_id: session_id.clone(),
            idempotency_key: Uuid::new_v4(),
            body: ActionSubmitRequest {
                page_id: worker.page_id.clone(),
                if_session_incarnation: 1,
                execution_timeout_ms: 30_000,
                action: ActionPayload::Evaluate {
                    expression: "document.title".to_owned(),
                },
            },
        }),
    )?;
    let ApiResponse::Action(submitted) = submitted else {
        return Err("unexpected evaluate submit response".into());
    };
    assert_eq!(submitted.data().request().kind(), ActionKind::Mutating);

    let requests = worker
        .requests
        .lock()
        .map_err(|_| "request lock poisoned")?;
    let found = requests.iter().any(|request| {
        matches!(
            request,
            WorkerRpcRequest::SubmitAction { action, .. }
                if action == &WorkerActionCommand::Evaluate {
                    expression: "document.title".to_owned(),
                }
        )
    });
    assert!(found, "evaluate did not reach the worker");
    Ok(())
}

#[test]
fn pointer_mutations_reach_the_worker_as_typed_node_references() -> Result<(), Box<dyn Error>> {
    let node = || "0000000000000001".to_owned();
    for (payload, expected) in [
        (
            ActionPayload::DoubleClick { node_ref: node() },
            WorkerActionCommand::DoubleClick { node_ref: node() },
        ),
        (
            ActionPayload::Hover { node_ref: node() },
            WorkerActionCommand::Hover { node_ref: node() },
        ),
        (
            ActionPayload::Focus { node_ref: node() },
            WorkerActionCommand::Focus { node_ref: node() },
        ),
        (
            ActionPayload::Blur { node_ref: node() },
            WorkerActionCommand::Blur { node_ref: node() },
        ),
        (
            ActionPayload::Check { node_ref: node() },
            WorkerActionCommand::Check { node_ref: node() },
        ),
        (
            ActionPayload::Uncheck { node_ref: node() },
            WorkerActionCommand::Uncheck { node_ref: node() },
        ),
        (
            ActionPayload::Fill {
                node_ref: node(),
                value: "hi".to_owned(),
            },
            WorkerActionCommand::Fill {
                node_ref: node(),
                value: "hi".to_owned(),
            },
        ),
        (
            ActionPayload::SelectOption {
                node_ref: node(),
                values: vec!["a".to_owned()],
            },
            WorkerActionCommand::SelectOption {
                node_ref: node(),
                values: vec!["a".to_owned()],
            },
        ),
    ] {
        let (principal, worker, router, session_id) = resource_fixture()?;
        let submitted = router.execute(
            &principal,
            ApiRequest::SubmitAction(ActionSubmitCommand {
                session_id: session_id.clone(),
                idempotency_key: Uuid::new_v4(),
                body: ActionSubmitRequest {
                    page_id: worker.page_id.clone(),
                    if_session_incarnation: 1,
                    execution_timeout_ms: 30_000,
                    action: payload,
                },
            }),
        )?;
        let ApiResponse::Action(submitted) = submitted else {
            return Err("unexpected pointer-mutation submit response".into());
        };
        assert_eq!(submitted.data().request().kind(), ActionKind::Mutating);

        let requests = worker
            .requests
            .lock()
            .map_err(|_| "request lock poisoned")?;
        let found = requests.iter().any(|request| {
            matches!(
                request,
                WorkerRpcRequest::SubmitAction { action, kind, .. }
                    if *kind == ActionKind::Mutating && action == &expected
            )
        });
        assert!(
            found,
            "pointer mutation {expected:?} did not reach the worker"
        );
    }
    Ok(())
}

#[test]
fn set_files_reaches_worker_with_exact_ids_and_rejects_duplicates_before_dispatch()
-> Result<(), Box<dyn Error>> {
    let (principal, worker, router, session_id) = resource_fixture()?;
    let ids = vec![ArtifactId::new(), ArtifactId::new()];
    let command = |ids| {
        ApiRequest::SubmitAction(ActionSubmitCommand {
            session_id: session_id.clone(),
            idempotency_key: Uuid::new_v4(),
            body: ActionSubmitRequest {
                page_id: worker.page_id.clone(),
                if_session_incarnation: 1,
                execution_timeout_ms: 30_000,
                action: ActionPayload::SetFiles {
                    node_ref: "0000000000000001".to_owned(),
                    artifact_ids: ids,
                },
            },
        })
    };
    assert!(
        router
            .execute(&principal, command(vec![ids[0].clone(), ids[0].clone()]))
            .is_err()
    );
    assert!(
        !worker
            .requests
            .lock()
            .unwrap()
            .iter()
            .any(|request| matches!(request, WorkerRpcRequest::SubmitAction { .. }))
    );
    assert!(matches!(
        router.execute(&principal, command(ids.clone()))?,
        ApiResponse::Action(_)
    ));
    assert!(worker.requests.lock().unwrap().iter().any(|request| matches!(request,
        WorkerRpcRequest::SubmitAction { action:WorkerActionCommand::SetFiles { node_ref, artifact_ids }, kind:ActionKind::Mutating, page_id, .. }
        if node_ref == "0000000000000001" && artifact_ids == &ids && page_id.as_ref() == Some(&worker.page_id))));
    Ok(())
}

#[test]
fn checkpoint_actions_preserve_origins_and_require_create_scope_before_worker_dispatch()
-> Result<(), Box<dyn Error>> {
    for origins in [
        vec![],
        vec![
            "https://example.test".to_owned(),
            "http://example.test:8080".to_owned(),
        ],
    ] {
        let (base, worker, router, session_id) = resource_fixture()?;
        let checkpoint_only =
            authenticated_principal_with_scopes(base.tenant_id().clone(), &["checkpoint:create"])?;
        let authorized = authenticated_principal_with_scopes(
            base.tenant_id().clone(),
            &["browser:act", "checkpoint:create"],
        )?;
        let key = Uuid::new_v4();
        let body = ActionSubmitRequest {
            page_id: worker.page_id.clone(),
            if_session_incarnation: 1,
            execution_timeout_ms: 30000,
            action: ActionPayload::Checkpoint {
                origins: origins.clone(),
            },
        };
        let request = |body| {
            ApiRequest::SubmitAction(ActionSubmitCommand {
                session_id: session_id.clone(),
                idempotency_key: key,
                body,
            })
        };
        let before = worker.requests.lock().unwrap().len();
        for denied in [&base, &checkpoint_only] {
            assert!(router.execute(denied, request(body.clone())).is_err());
        }
        let mut invalid = body.clone();
        invalid.action = ActionPayload::Checkpoint {
            origins: vec!["https://example.test/path".to_owned()],
        };
        assert!(router.execute(&authorized, request(invalid)).is_err());
        assert_eq!(worker.requests.lock().unwrap().len(), before);
        let expected_hash =
            *browserd_operations::CanonicalRequestHash::from_json(&serde_json::to_value(&body)?)
                .as_bytes();
        let ApiResponse::Action(submitted) = router.execute(&authorized, request(body))? else {
            return Err("unexpected checkpoint action response".into());
        };
        assert_eq!(submitted.data().request().kind(), ActionKind::ReadOnly);
        assert!(worker.requests.lock().unwrap().iter().any(|request|matches!(request,
            WorkerRpcRequest::SubmitAction { action:WorkerActionCommand::Checkpoint { origins:actual },kind:ActionKind::ReadOnly,canonical_request_hash,.. }
                if actual==&origins && *canonical_request_hash==expected_hash)));
    }
    Ok(())
}

#[test]
fn fill_secret_requires_both_scopes_and_dispatches_only_the_reference() -> Result<(), Box<dyn Error>>
{
    let (principal, worker, router, session_id) = resource_fixture()?;
    let secret_only =
        authenticated_principal_with_scopes(principal.tenant_id().clone(), &["secret:use"])?;
    let authorized = authenticated_principal_with_scopes(
        principal.tenant_id().clone(),
        &["browser:act", "secret:use"],
    )?;
    let idempotency_key = Uuid::new_v4();
    let body = ActionSubmitRequest {
        page_id: worker.page_id.clone(),
        if_session_incarnation: 1,
        execution_timeout_ms: 30_000,
        action: ActionPayload::FillSecret {
            node_ref: "0000000000000001".to_owned(),
            secret_ref: "credential.login".to_owned(),
        },
    };
    let request = |body| {
        ApiRequest::SubmitAction(ActionSubmitCommand {
            session_id: session_id.clone(),
            idempotency_key,
            body,
        })
    };
    let before = worker.requests.lock().unwrap().len();
    for denied in [&principal, &secret_only] {
        assert!(router.execute(denied, request(body.clone())).is_err());
    }
    let mut invalid = body.clone();
    invalid.action = ActionPayload::FillSecret {
        node_ref: "0000000000000001".to_owned(),
        secret_ref: " invalid ".to_owned(),
    };
    assert!(router.execute(&authorized, request(invalid)).is_err());
    assert_eq!(worker.requests.lock().unwrap().len(), before);
    let expected_hash =
        *browserd_operations::CanonicalRequestHash::from_json(&serde_json::to_value(&body)?)
            .as_bytes();
    assert!(matches!(
        router.execute(&authorized, request(body))?,
        ApiResponse::Action(_)
    ));
    let requests = worker.requests.lock().unwrap();
    let sent = requests
        .iter()
        .find_map(|request| match request {
            WorkerRpcRequest::SubmitAction {
                action,
                kind,
                canonical_request_hash,
                requester_principal_id,
                ..
            } => Some((action, kind, canonical_request_hash, requester_principal_id)),
            _ => None,
        })
        .ok_or("secret reference dispatch missing")?;
    assert_eq!(*sent.1, ActionKind::Mutating);
    assert_eq!(*sent.2, expected_hash);
    assert_eq!(sent.3, authorized.principal_id());
    assert_eq!(
        serde_json::to_value(sent.0)?,
        serde_json::json!({"type":"fill_secret","node_ref":"0000000000000001","secret_ref":"credential.login"})
    );
    Ok(())
}

#[test]
fn upload_preserves_safe_filename_and_rejects_paths_before_worker_dispatch()
-> Result<(), Box<dyn Error>> {
    let (principal, worker, router, session_id) = resource_fixture()?;
    let command = |display_filename: &str| {
        ApiRequest::UploadArtifact(ArtifactUploadRequest {
            session_id: session_id.clone(),
            body: ArtifactUploadBody {
                display_filename: display_filename.to_owned(),
                declared_content_type: Some("text/plain".to_owned()),
                expected_size_bytes: 5,
                data_base64: Some("aGVsbG8=".to_owned()),
            },
        })
    };
    for name in ["../file", "/file", "a\\b", ".", "..", "a\nb"] {
        assert!(router.execute(&principal, command(name)).is_err());
    }
    assert!(
        !worker
            .requests
            .lock()
            .unwrap()
            .iter()
            .any(|request| matches!(
                request,
                WorkerRpcRequest::StoreArtifact { .. }
                    | WorkerRpcRequest::UploadNamedArtifact { .. }
            ))
    );
    assert!(matches!(
        router.execute(&principal, command("첨부 문서.txt"))?,
        ApiResponse::ArtifactUpload(_)
    ));
    assert!(worker.requests.lock().unwrap().iter().any(|request| matches!(request,
        WorkerRpcRequest::UploadNamedArtifact { fence, bytes, content_type, display_filename, .. }
        if fence.session_id == session_id && bytes == b"hello" && content_type == "text/plain" && display_filename == "첨부 문서.txt")));
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
fn artifact_discovery_paginates_typed_ids_and_requests_one_extra_result()
-> Result<(), Box<dyn Error>> {
    let (principal, worker, router, session_id) = resource_fixture()?;
    let first = router.execute(
        &principal,
        ApiRequest::ListArtifacts(browserd_api::ArtifactListRequest {
            session_id: session_id.clone(),
            after: None,
            limit: 2,
        }),
    )?;
    let ApiResponse::Artifacts(first) = first else {
        return Err("expected artifact list".into());
    };
    assert_eq!(
        first
            .data()
            .items
            .iter()
            .map(|item| item.key.artifact_id().clone())
            .collect::<Vec<_>>(),
        worker.artifact_list_ids[..2]
    );
    assert_eq!(
        first.data().next_cursor.as_ref(),
        Some(&worker.artifact_list_ids[1])
    );
    assert!(
        first
            .data()
            .items
            .iter()
            .all(|item| item.key.tenant_id() == principal.tenant_id()
                && item.key.session_id() == &session_id)
    );
    let second = router.execute(
        &principal,
        ApiRequest::ListArtifacts(browserd_api::ArtifactListRequest {
            session_id: session_id.clone(),
            after: first.data().next_cursor.clone(),
            limit: 2,
        }),
    )?;
    let ApiResponse::Artifacts(second) = second else {
        return Err("expected artifact list".into());
    };
    assert_eq!(second.data().items.len(), 1);
    assert_eq!(
        second.data().items[0].key.artifact_id(),
        &worker.artifact_list_ids[2]
    );
    assert_eq!(second.data().next_cursor, None);
    let requests = worker.requests.lock().unwrap();
    let lists = requests
        .iter()
        .filter_map(|request| match request {
            WorkerRpcRequest::ListArtifacts {
                fence,
                after,
                limit,
            } => Some((fence, after, limit)),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(lists.len(), 2);
    assert_eq!(lists[0].0.tenant_id, *principal.tenant_id());
    assert_eq!(lists[0].0.session_id, session_id);
    assert_eq!(lists[0].1, &None);
    assert_eq!(*lists[0].2, 3);
    assert_eq!(lists[1].1.as_ref(), Some(&worker.artifact_list_ids[1]));
    Ok(())
}

#[test]
fn artifact_discovery_checks_cross_fence_and_metadata_on_hidden_extra_item()
-> Result<(), Box<dyn Error>> {
    for fault in [1, 2, 3, 7, 8] {
        let (principal, worker, router, session_id) = resource_fixture()?;
        worker.artifact_list_fault.store(fault, Ordering::Release);
        assert!(
            router
                .execute(
                    &principal,
                    ApiRequest::ListArtifacts(browserd_api::ArtifactListRequest {
                        session_id,
                        after: None,
                        limit: 2,
                    })
                )
                .is_err(),
            "fault {fault} on extra item must fail the whole page"
        );
    }
    Ok(())
}

#[test]
fn artifact_discovery_rejects_duplicate_unsorted_and_unbounded_worker_lists()
-> Result<(), Box<dyn Error>> {
    for fault in [4, 5, 9] {
        let (principal, worker, router, session_id) = resource_fixture()?;
        worker.artifact_list_fault.store(fault, Ordering::Release);
        assert!(
            router
                .execute(
                    &principal,
                    ApiRequest::ListArtifacts(browserd_api::ArtifactListRequest {
                        session_id,
                        after: None,
                        limit: 2,
                    })
                )
                .is_err(),
            "fault {fault} must fail closed"
        );
    }
    let (principal, worker, router, session_id) = resource_fixture()?;
    worker.artifact_list_fault.store(6, Ordering::Release);
    assert!(
        router
            .execute(
                &principal,
                ApiRequest::ListArtifacts(browserd_api::ArtifactListRequest {
                    session_id,
                    after: Some(worker.artifact_list_ids[0].clone()),
                    limit: 2,
                })
            )
            .is_err(),
        "worker cannot return a cursor or earlier artifact"
    );
    Ok(())
}

#[test]
fn artifact_discovery_rejects_invalid_limits_and_another_tenants_session_before_dispatch()
-> Result<(), Box<dyn Error>> {
    let (principal, worker, router, session_id) = resource_fixture()?;
    for limit in [0, 101, usize::MAX] {
        assert!(
            router
                .execute(
                    &principal,
                    ApiRequest::ListArtifacts(browserd_api::ArtifactListRequest {
                        session_id: session_id.clone(),
                        after: None,
                        limit,
                    })
                )
                .is_err()
        );
    }
    let stranger = authenticated_principal(TenantId::new())?;
    assert!(
        router
            .execute(
                &stranger,
                ApiRequest::ListArtifacts(browserd_api::ArtifactListRequest {
                    session_id,
                    after: None,
                    limit: 2,
                })
            )
            .is_err()
    );
    assert!(
        !worker
            .requests
            .lock()
            .unwrap()
            .iter()
            .any(|request| matches!(request, WorkerRpcRequest::ListArtifacts { .. }))
    );
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
