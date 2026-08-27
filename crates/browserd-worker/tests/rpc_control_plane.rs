use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use browserd_actions::{ActionJournalLimits, ActionKind};
use browserd_core::{
    ActionId, IsolationProfile, OperationId, PageId, PrincipalId, SessionId, TenantId, WorkerId,
};
use browserd_policy::{CanonicalActionProposal, Origin};
use browserd_sandbox::CleanupReason;
use browserd_session::{LeasePolicy, OwnershipFence, SessionTime, SessionTimeoutPolicy};
use browserd_worker::{
    ActionExecutionResult, ActionJournalConfig, ApprovedActionError, ArtifactStoreReceipt,
    ArtifactStoreRequest, AuthenticatedPeer, ChromiumDriver, DependencyError, InternalEndpoint,
    LiveApprovalContext, SandboxClient, UnavailableChromiumDriver, UnavailableSandboxClient,
    WorkerActionApprovalRequirement, WorkerActionStatus, WorkerApprovalActionType, WorkerClock,
    WorkerConfig, WorkerControlPlane, WorkerControlPlaneRpcHandler, WorkerCreateSessionRequest,
    WorkerError, WorkerIsolationProfile, WorkerRpcFailureCode, WorkerRpcHandler, WorkerRpcRequest,
    WorkerRpcResponse, WorkerSessionFence,
};

struct FrozenClock;

impl WorkerClock for FrozenClock {
    fn now(&self) -> Result<SessionTime, WorkerError> {
        Ok(SessionTime::new(0))
    }
}

struct ReadyDriver;

impl ChromiumDriver for ReadyDriver {
    fn qualify(&self) -> Result<(), DependencyError> {
        Ok(())
    }

    fn create_context(&self, _session_id: &SessionId) -> Result<PageId, DependencyError> {
        Ok(PageId::new())
    }

    fn close_context(&self, _session_id: &SessionId) -> Result<(), DependencyError> {
        Ok(())
    }

    fn create_page(&self, _session_id: &SessionId) -> Result<PageId, DependencyError> {
        Ok(PageId::new())
    }

    fn close_page(
        &self,
        _session_id: &SessionId,
        _page_id: &PageId,
    ) -> Result<(), DependencyError> {
        Ok(())
    }

    fn activate_page(
        &self,
        _session_id: &SessionId,
        _page_id: &PageId,
    ) -> Result<(), DependencyError> {
        Ok(())
    }

    fn execute_action(
        &self,
        _session_id: &SessionId,
        _page_id: Option<&PageId>,
        _payload: &[u8],
    ) -> ActionExecutionResult {
        ActionExecutionResult::Succeeded(Vec::new())
    }

    fn inspect_approval_context(
        &self,
        _session_id: &SessionId,
        _page_id: &PageId,
        _proposal: &CanonicalActionProposal,
    ) -> Result<LiveApprovalContext, DependencyError> {
        Ok(LiveApprovalContext {
            target_incarnation: 1,
            frame_document_epoch: 1,
            current_origin: Origin::parse("https://example.test")
                .map_err(|_| DependencyError::Rejected)?,
            url_revision: 1,
            node_ref: None,
            node_valid: true,
            resolved_ips: Vec::new(),
            credential_refs: Vec::new(),
            chromium_build: "sha256:rpc-test".to_owned(),
            effective_isolation: IsolationProfile::SharedContext,
        })
    }

    fn execute_approved_action(
        &self,
        _session_id: &SessionId,
        _page_id: &PageId,
        _payload: &[u8],
        _proposal: &CanonicalActionProposal,
        inspected: &LiveApprovalContext,
        authorize_and_commit: &mut dyn FnMut(
            &LiveApprovalContext,
        ) -> Result<(), ApprovedActionError>,
    ) -> Result<ActionExecutionResult, ApprovedActionError> {
        authorize_and_commit(inspected)?;
        Ok(ActionExecutionResult::Succeeded(Vec::new()))
    }

    fn cancel_action(
        &self,
        _session_id: &SessionId,
        _action_id: &ActionId,
    ) -> Result<bool, DependencyError> {
        Ok(true)
    }
}

struct ReadySandbox;

impl SandboxClient for ReadySandbox {
    fn qualify(&self) -> Result<(), DependencyError> {
        Ok(())
    }

    fn provision(
        &self,
        _session_id: &SessionId,
        _fence: &OwnershipFence,
    ) -> Result<(), DependencyError> {
        Ok(())
    }

    fn cleanup(
        &self,
        _session_id: &SessionId,
        _reason: CleanupReason,
    ) -> Result<(), DependencyError> {
        Ok(())
    }

    fn heartbeat(&self, _worker_id: &WorkerId, _worker_epoch: u64) -> Result<(), DependencyError> {
        Ok(())
    }

    fn store_artifact(
        &self,
        _request: &ArtifactStoreRequest,
    ) -> Result<ArtifactStoreReceipt, DependencyError> {
        Err(DependencyError::Unavailable)
    }
}

#[tokio::test]
async fn control_plane_rpc_rejects_stale_worker_epoch_before_dependency_effects() {
    let directory = tempfile::tempdir();
    assert!(directory.is_ok());
    let Some(directory) = directory.ok() else {
        return;
    };
    let worker_id = WorkerId::new("worker-rpc-test");
    assert!(worker_id.is_ok());
    let Some(worker_id) = worker_id.ok() else {
        return;
    };
    let peer = AuthenticatedPeer::new("gateway-rpc-test");
    assert!(peer.is_ok());
    let Some(peer) = peer.ok() else {
        return;
    };
    let lease = LeasePolicy::new(Duration::from_secs(15), Duration::from_secs(3));
    let timeout = SessionTimeoutPolicy::new(Duration::from_secs(60), Duration::from_secs(30));
    assert!(lease.is_ok() && timeout.is_ok());
    let (Some(lease), Some(timeout)) = (lease.ok(), timeout.ok()) else {
        return;
    };
    let journal = ActionJournalConfig::new(directory.path(), ActionJournalLimits::default());
    assert!(journal.is_ok());
    let Some(journal) = journal.ok() else {
        return;
    };
    let config = WorkerConfig::new(
        worker_id,
        7,
        InternalEndpoint::Loopback(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 19011)),
        peer.clone(),
        4,
        8,
        lease,
        timeout,
        Duration::from_secs(60),
        journal,
    );
    assert!(config.is_ok());
    let Some(config) = config.ok() else {
        return;
    };
    let worker = Arc::new(WorkerControlPlane::new(
        config,
        Arc::new(UnavailableChromiumDriver),
        Arc::new(UnavailableSandboxClient),
    ));
    let handler = WorkerControlPlaneRpcHandler::new(worker, peer);
    let mismatched_probe = handler
        .handle(WorkerRpcRequest::Probe {
            expected_worker_epoch: 6,
        })
        .await;
    assert!(matches!(
        mismatched_probe,
        WorkerRpcResponse::Failure(failure)
            if failure.code == WorkerRpcFailureCode::FenceMismatch
    ));
    let not_ready_probe = handler
        .handle(WorkerRpcRequest::Probe {
            expected_worker_epoch: 7,
        })
        .await;
    assert!(matches!(
        not_ready_probe,
        WorkerRpcResponse::Failure(failure)
            if failure.code == WorkerRpcFailureCode::NotReady
    ));
    let response = handler
        .handle(WorkerRpcRequest::CreateSession(
            WorkerCreateSessionRequest {
                operation_id: OperationId::new(),
                tenant_id: TenantId::new(),
                idempotency_key: "create-stale".to_owned(),
                canonical_request_hash: [9; 32],
                expected_worker_epoch: 6,
                placement_version: 1,
                session_incarnation: 1,
                requested_isolation: WorkerIsolationProfile::SharedContext,
                now_unix_millis: 1,
            },
        ))
        .await;
    assert!(matches!(
        response,
        WorkerRpcResponse::Failure(failure)
            if failure.code == WorkerRpcFailureCode::FenceMismatch
    ));
}

#[tokio::test]
async fn control_plane_rpc_bounds_create_bindings_and_rejects_cross_tenant_fences() {
    let directory = tempfile::tempdir();
    assert!(directory.is_ok());
    let Some(directory) = directory.ok() else {
        return;
    };
    let worker_id = WorkerId::new("worker-rpc-tenant-test");
    assert!(worker_id.is_ok());
    let Some(worker_id) = worker_id.ok() else {
        return;
    };
    let peer = AuthenticatedPeer::new("gateway-rpc-tenant-test");
    assert!(peer.is_ok());
    let Some(peer) = peer.ok() else {
        return;
    };
    let lease = LeasePolicy::new(Duration::from_secs(15), Duration::from_secs(3));
    let timeout = SessionTimeoutPolicy::new(Duration::from_secs(60), Duration::from_secs(30));
    assert!(lease.is_ok() && timeout.is_ok());
    let (Some(lease), Some(timeout)) = (lease.ok(), timeout.ok()) else {
        return;
    };
    let journal = ActionJournalConfig::new(directory.path(), ActionJournalLimits::default());
    assert!(journal.is_ok());
    let Some(journal) = journal.ok() else {
        return;
    };
    let config = WorkerConfig::new(
        worker_id,
        7,
        InternalEndpoint::Loopback(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 19012)),
        peer.clone(),
        4,
        8,
        lease,
        timeout,
        Duration::from_secs(60),
        journal,
    );
    assert!(config.is_ok());
    let Some(config) = config.ok() else {
        return;
    };
    let tenant_id = TenantId::new();
    let worker = Arc::new(WorkerControlPlane::new_with_clock(
        config,
        Arc::new(ReadyDriver),
        Arc::new(ReadySandbox),
        Arc::new(FrozenClock),
    ));
    let handler = WorkerControlPlaneRpcHandler::new_with_binding_capacity(worker, peer, 1);
    assert!(handler.is_ok());
    let Some(handler) = handler.ok() else {
        return;
    };
    let probe = handler
        .handle(WorkerRpcRequest::Probe {
            expected_worker_epoch: 7,
        })
        .await;
    assert!(matches!(
        probe,
        WorkerRpcResponse::Probe(receipt)
            if receipt.worker_epoch == 7 && receipt.ready
    ));
    let created = handler
        .handle(WorkerRpcRequest::CreateSession(
            WorkerCreateSessionRequest {
                operation_id: OperationId::new(),
                tenant_id: tenant_id.clone(),
                idempotency_key: "create-tenant-fence".to_owned(),
                canonical_request_hash: [4; 32],
                expected_worker_epoch: 7,
                placement_version: 1,
                session_incarnation: 1,
                requested_isolation: WorkerIsolationProfile::SharedContext,
                now_unix_millis: 1,
            },
        ))
        .await;
    assert!(matches!(&created, WorkerRpcResponse::SessionCreated(_)));
    let WorkerRpcResponse::SessionCreated(created) = created else {
        return;
    };
    assert_eq!(created.tenant_id, tenant_id);
    assert_eq!(
        created.effective_isolation,
        WorkerIsolationProfile::SharedContext
    );

    let retry = handler
        .handle(WorkerRpcRequest::CreateSession(
            WorkerCreateSessionRequest {
                operation_id: created.operation_id.clone(),
                tenant_id: tenant_id.clone(),
                idempotency_key: "create-tenant-fence".to_owned(),
                canonical_request_hash: [4; 32],
                expected_worker_epoch: 7,
                placement_version: 1,
                session_incarnation: 1,
                requested_isolation: WorkerIsolationProfile::SharedContext,
                now_unix_millis: 2,
            },
        ))
        .await;
    assert!(matches!(&retry, WorkerRpcResponse::SessionCreated(_)));
    let WorkerRpcResponse::SessionCreated(retry) = retry else {
        return;
    };
    assert_eq!(retry.operation_id, created.operation_id);
    assert_eq!(retry.session_id, created.session_id);
    assert!(retry.existing);

    let refenced_retry = handler
        .handle(WorkerRpcRequest::CreateSession(
            WorkerCreateSessionRequest {
                operation_id: created.operation_id.clone(),
                tenant_id: tenant_id.clone(),
                idempotency_key: "create-tenant-fence".to_owned(),
                canonical_request_hash: [4; 32],
                expected_worker_epoch: 7,
                placement_version: 2,
                session_incarnation: 1,
                requested_isolation: WorkerIsolationProfile::SharedContext,
                now_unix_millis: 2,
            },
        ))
        .await;
    assert!(matches!(
        refenced_retry,
        WorkerRpcResponse::Failure(failure)
            if failure.code == WorkerRpcFailureCode::Conflict
    ));

    let overloaded = handler
        .handle(WorkerRpcRequest::CreateSession(
            WorkerCreateSessionRequest {
                operation_id: OperationId::new(),
                tenant_id: tenant_id.clone(),
                idempotency_key: "create-over-capacity".to_owned(),
                canonical_request_hash: [7; 32],
                expected_worker_epoch: 7,
                placement_version: 2,
                session_incarnation: 1,
                requested_isolation: WorkerIsolationProfile::SharedContext,
                now_unix_millis: 3,
            },
        ))
        .await;
    assert!(matches!(
        overloaded,
        WorkerRpcResponse::Failure(failure)
            if failure.code == WorkerRpcFailureCode::Capacity
    ));

    let unsupported_isolation = handler
        .handle(WorkerRpcRequest::CreateSession(
            WorkerCreateSessionRequest {
                operation_id: OperationId::new(),
                tenant_id: tenant_id.clone(),
                idempotency_key: "create-dedicated".to_owned(),
                canonical_request_hash: [8; 32],
                expected_worker_epoch: 7,
                placement_version: 2,
                session_incarnation: 1,
                requested_isolation: WorkerIsolationProfile::DedicatedProcess,
                now_unix_millis: 3,
            },
        ))
        .await;
    assert!(matches!(
        unsupported_isolation,
        WorkerRpcResponse::Failure(failure)
            if failure.code == WorkerRpcFailureCode::InvalidRequest
    ));

    let response = handler
        .handle(WorkerRpcRequest::GetSession {
            fence: WorkerSessionFence {
                tenant_id: TenantId::new(),
                session_id: created.session_id,
                worker_epoch: created.worker_epoch,
                placement_version: created.placement_version,
                session_incarnation: created.session_incarnation,
            },
        })
        .await;
    assert!(matches!(
        response,
        WorkerRpcResponse::Failure(failure)
            if failure.code == WorkerRpcFailureCode::FenceMismatch
    ));
}

#[tokio::test]
async fn accepted_pending_approval_action_is_returned_without_dispatching_it() {
    let directory = tempfile::tempdir();
    assert!(directory.is_ok());
    let Some(directory) = directory.ok() else {
        return;
    };
    let worker_id = WorkerId::new("worker-rpc-approval-test");
    assert!(worker_id.is_ok());
    let Some(worker_id) = worker_id.ok() else {
        return;
    };
    let peer = AuthenticatedPeer::new("gateway-rpc-approval-test");
    assert!(peer.is_ok());
    let Some(peer) = peer.ok() else {
        return;
    };
    let lease = LeasePolicy::new(Duration::from_secs(15), Duration::from_secs(3));
    let timeout = SessionTimeoutPolicy::new(Duration::from_secs(60), Duration::from_secs(30));
    assert!(lease.is_ok() && timeout.is_ok());
    let (Some(lease), Some(timeout)) = (lease.ok(), timeout.ok()) else {
        return;
    };
    let journal = ActionJournalConfig::new(directory.path(), ActionJournalLimits::default());
    assert!(journal.is_ok());
    let Some(journal) = journal.ok() else {
        return;
    };
    let config = WorkerConfig::new(
        worker_id,
        7,
        InternalEndpoint::Loopback(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 19013)),
        peer.clone(),
        4,
        8,
        lease,
        timeout,
        Duration::from_secs(60),
        journal,
    );
    assert!(config.is_ok());
    let Some(config) = config.ok() else {
        return;
    };
    let tenant_id = TenantId::new();
    let worker = Arc::new(WorkerControlPlane::new_with_clock(
        config,
        Arc::new(ReadyDriver),
        Arc::new(ReadySandbox),
        Arc::new(FrozenClock),
    ));
    let handler = WorkerControlPlaneRpcHandler::new(worker, peer);
    let created = handler
        .handle(WorkerRpcRequest::CreateSession(
            WorkerCreateSessionRequest {
                operation_id: OperationId::new(),
                tenant_id: tenant_id.clone(),
                idempotency_key: "create-approval".to_owned(),
                canonical_request_hash: [5; 32],
                expected_worker_epoch: 7,
                placement_version: 1,
                session_incarnation: 1,
                requested_isolation: WorkerIsolationProfile::SharedContext,
                now_unix_millis: 1,
            },
        ))
        .await;
    assert!(matches!(&created, WorkerRpcResponse::SessionCreated(_)));
    let WorkerRpcResponse::SessionCreated(created) = created else {
        return;
    };
    let fence = WorkerSessionFence {
        tenant_id,
        session_id: created.session_id,
        worker_epoch: created.worker_epoch,
        placement_version: created.placement_version,
        session_incarnation: created.session_incarnation,
    };
    let submitted = handler
        .handle(WorkerRpcRequest::SubmitAction {
            fence: fence.clone(),
            requester_principal_id: PrincipalId::new(),
            idempotency_key: "pending-action".to_owned(),
            canonical_request_hash: [6; 32],
            kind: ActionKind::Mutating,
            page_id: Some(created.primary_page_id),
            payload: b"click".to_vec(),
            approval: Some(WorkerActionApprovalRequirement {
                target_incarnation: 1,
                frame_document_epoch: 1,
                current_origin: "https://example.test".to_owned(),
                url_revision: 1,
                action_type: WorkerApprovalActionType::Click,
                node_ref: None,
                credential_refs: Vec::new(),
                require_four_eyes: true,
            }),
            now_unix_millis: 2,
        })
        .await;
    assert!(matches!(&submitted, WorkerRpcResponse::Action(_)));
    let WorkerRpcResponse::Action(submitted) = submitted else {
        return;
    };
    assert_eq!(submitted.fence, fence);
    assert_eq!(submitted.status, WorkerActionStatus::PendingApproval);
    assert_eq!(submitted.idempotency_key, "pending-action");
    assert_eq!(submitted.canonical_request_hash, [6; 32]);
    assert!(submitted.to_action_snapshot().is_ok());

    let approvals = handler
        .handle(WorkerRpcRequest::ListApprovals {
            fence: fence.clone(),
        })
        .await;
    let WorkerRpcResponse::Approvals(approvals) = approvals else {
        return;
    };
    assert_eq!(approvals.len(), 1);
    let Some(approval) = approvals.first() else {
        return;
    };
    assert_eq!(
        approval.approval_id.as_uuid().get_version(),
        Some(uuid::Version::SortRand)
    );
    let canonical = approval.canonical_proposal();
    assert!(canonical.is_ok());
    assert!(canonical.as_ref().is_ok_and(|proposal| {
        proposal.tenant_id() == &fence.tenant_id
            && proposal.session_id() == &fence.session_id
            && proposal.hash().as_bytes() == &approval.proposal_hash
    }));
    let approver = PrincipalId::new();
    let decision = WorkerRpcRequest::DecideApproval {
        fence: fence.clone(),
        approval_id: approval.approval_id.clone(),
        decision: browserd_worker::WorkerApprovalDecision::Approve,
        principal_id: approver,
        reason: "reviewed by an independent operator".to_owned(),
        now_unix_millis: 3,
    };
    let decided = handler.handle(decision.clone()).await;
    assert!(matches!(
        decided,
        WorkerRpcResponse::Approval(browserd_worker::WorkerApprovalReceipt {
            state: browserd_worker::WorkerApprovalState::Approved { .. },
            ..
        })
    ));
    let retry = handler.handle(decision).await;
    assert!(matches!(
        retry,
        WorkerRpcResponse::Approval(browserd_worker::WorkerApprovalReceipt {
            state: browserd_worker::WorkerApprovalState::Approved { .. },
            ..
        })
    ));
    let action = handler
        .handle(WorkerRpcRequest::GetAction {
            fence,
            action_id: submitted.action_id,
        })
        .await;
    assert!(matches!(
        action,
        WorkerRpcResponse::Action(receipt)
            if receipt.status == WorkerActionStatus::Succeeded
    ));
}
