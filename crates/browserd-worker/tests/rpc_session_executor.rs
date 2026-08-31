use std::collections::BTreeMap;
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::time::Duration;

use browserd_actions::{ActionJournalLimits, ActionKind, ActionSequence};
use browserd_core::{
    ActionId, IsolationProfile, OperationId, PageId, PrincipalId, SessionId, TenantId, WorkerId,
};
use browserd_policy::{CanonicalActionProposal, Origin};
use browserd_sandbox::CleanupReason;
use browserd_session::{LeasePolicy, OwnershipFence, SessionTime, SessionTimeoutPolicy};
use browserd_worker::{
    ActionExecutionResult, ActionJournalConfig, ApprovedActionError, ArtifactStoreReceipt,
    ArtifactStoreRequest, AuthenticatedPeer, ChromiumDriver, DependencyError, InternalEndpoint,
    LiveApprovalContext, SandboxClient, WORKER_SESSION_OPTIONS_VERSION,
    WorkerActionApprovalRequirement, WorkerActionCommand, WorkerActionExecutionTimeout,
    WorkerActionStatus, WorkerApprovalActionType, WorkerApprovalDecision, WorkerClock,
    WorkerConfig, WorkerControlPlane, WorkerControlPlaneRpcHandler, WorkerCreateSessionRequest,
    WorkerError, WorkerIsolationProfile, WorkerRpcFailureCode, WorkerRpcHandler, WorkerRpcRequest,
    WorkerRpcResponse, WorkerSessionFence, WorkerSessionOptionsV1, WorkerViewport,
};

struct FrozenClock;

impl WorkerClock for FrozenClock {
    fn now(&self) -> Result<SessionTime, WorkerError> {
        Ok(SessionTime::new(0))
    }
}

struct ExecutorDriver {
    page_operation_gate: Option<(Arc<Barrier>, Arc<Barrier>)>,
    action_execution_count: AtomicUsize,
    fail_actions: bool,
}

impl ExecutorDriver {
    fn ready() -> Self {
        Self {
            page_operation_gate: None,
            action_execution_count: AtomicUsize::new(0),
            fail_actions: false,
        }
    }

    fn failing() -> Self {
        Self {
            page_operation_gate: None,
            action_execution_count: AtomicUsize::new(0),
            fail_actions: true,
        }
    }

    fn blocking_page(started: Arc<Barrier>, release: Arc<Barrier>) -> Self {
        Self {
            page_operation_gate: Some((started, release)),
            action_execution_count: AtomicUsize::new(0),
            fail_actions: false,
        }
    }
}

impl ChromiumDriver for ExecutorDriver {
    fn qualify(&self) -> Result<(), DependencyError> {
        Ok(())
    }

    fn create_context(&self, _session_id: &SessionId) -> Result<PageId, DependencyError> {
        Ok(PageId::new())
    }

    fn create_context_owned_with_options(
        &self,
        _tenant_id: &TenantId,
        session_id: &SessionId,
        _fence: &OwnershipFence,
        options: &WorkerSessionOptionsV1,
    ) -> Result<PageId, DependencyError> {
        if !options.is_valid() {
            return Err(DependencyError::Rejected);
        }
        self.create_context(session_id)
    }

    fn close_context(&self, _session_id: &SessionId) -> Result<(), DependencyError> {
        Ok(())
    }

    fn create_page(&self, _session_id: &SessionId) -> Result<PageId, DependencyError> {
        if let Some((started, release)) = &self.page_operation_gate {
            let _ = started.wait();
            let _ = release.wait();
        }
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
        payload: &[u8],
    ) -> ActionExecutionResult {
        self.action_execution_count.fetch_add(1, Ordering::AcqRel);
        if self.fail_actions {
            ActionExecutionResult::FailedKnown("driver rejected action".to_owned())
        } else {
            ActionExecutionResult::Succeeded(payload.to_vec())
        }
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
            chromium_build: "sha256:session-executor-test".to_owned(),
            effective_isolation: IsolationProfile::SharedContext,
        })
    }

    fn execute_approved_action(
        &self,
        _session_id: &SessionId,
        _page_id: &PageId,
        payload: &[u8],
        _proposal: &CanonicalActionProposal,
        inspected: &LiveApprovalContext,
        authorize_and_commit: &mut dyn FnMut(
            &LiveApprovalContext,
        ) -> Result<(), ApprovedActionError>,
    ) -> Result<ActionExecutionResult, ApprovedActionError> {
        authorize_and_commit(inspected)?;
        self.action_execution_count.fetch_add(1, Ordering::AcqRel);
        Ok(ActionExecutionResult::Succeeded(payload.to_vec()))
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

struct RpcFixture {
    _directory: tempfile::TempDir,
    driver: Arc<ExecutorDriver>,
    handler: Arc<WorkerControlPlaneRpcHandler<ExecutorDriver, ReadySandbox>>,
    fence: WorkerSessionFence,
    primary_page_id: PageId,
}

async fn rpc_fixture(
    driver: Arc<ExecutorDriver>,
    endpoint_port: u16,
) -> Result<RpcFixture, Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let worker_id = WorkerId::new(format!("worker-session-executor-{endpoint_port}"))?;
    let peer = AuthenticatedPeer::new(format!("gateway-session-executor-{endpoint_port}"))
        .map_err(|error| std::io::Error::other(format!("invalid peer: {error:?}")))?;
    let lease = LeasePolicy::new(Duration::from_secs(15), Duration::from_secs(3))
        .map_err(|error| std::io::Error::other(format!("invalid lease policy: {error:?}")))?;
    let timeout = SessionTimeoutPolicy::new(Duration::from_secs(60), Duration::from_secs(30))
        .map_err(|error| std::io::Error::other(format!("invalid timeout policy: {error:?}")))?;
    let journal = ActionJournalConfig::new(directory.path(), ActionJournalLimits::default())
        .map_err(|error| std::io::Error::other(format!("invalid action journal: {error:?}")))?;
    let config = WorkerConfig::new(
        worker_id,
        7,
        InternalEndpoint::Loopback(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            endpoint_port,
        )),
        peer.clone(),
        4,
        8,
        lease,
        timeout,
        Duration::from_secs(60),
        journal,
    )
    .map_err(|error| std::io::Error::other(format!("invalid worker config: {error:?}")))?;
    let tenant_id = TenantId::new();
    let worker = Arc::new(WorkerControlPlane::new_with_clock(
        config,
        Arc::clone(&driver),
        Arc::new(ReadySandbox),
        Arc::new(FrozenClock),
    ));
    let handler = Arc::new(WorkerControlPlaneRpcHandler::new(worker, peer));
    let options = WorkerSessionOptionsV1 {
        workload_class_hint: "interactive".to_owned(),
        viewport: WorkerViewport {
            width: 1_280,
            height: 720,
            device_scale_factor: 1,
        },
        locale: "en-US".to_owned(),
        timezone: "UTC".to_owned(),
        user_agent: None,
        network_policy_id: "public-web-default".to_owned(),
        network_class: "public".to_owned(),
        checkpoint_ref: None,
        dialog_policy: "auto_dismiss".to_owned(),
        feature_profile: "standard".to_owned(),
        ttl_seconds: 60,
        idle_timeout_seconds: 30,
        metadata: BTreeMap::new(),
    };
    let created = handler
        .handle(WorkerRpcRequest::CreateSession(
            WorkerCreateSessionRequest {
                operation_id: OperationId::new(),
                tenant_id: tenant_id.clone(),
                idempotency_key: format!("create-session-executor-{endpoint_port}"),
                canonical_request_hash: options
                    .canonical_request_hash(WorkerIsolationProfile::SharedContext),
                expected_worker_epoch: 7,
                placement_version: 1,
                session_incarnation: 1,
                requested_isolation: WorkerIsolationProfile::SharedContext,
                options_version: WORKER_SESSION_OPTIONS_VERSION,
                options,
                now_unix_millis: 1,
            },
        ))
        .await;
    let WorkerRpcResponse::SessionCreated(created) = created else {
        return Err(std::io::Error::other("session executor fixture creation failed").into());
    };
    Ok(RpcFixture {
        _directory: directory,
        driver,
        handler,
        fence: WorkerSessionFence {
            tenant_id,
            session_id: created.session_id,
            worker_epoch: created.worker_epoch,
            placement_version: created.placement_version,
            session_incarnation: created.session_incarnation,
        },
        primary_page_id: created.primary_page_id,
    })
}

fn submit_action_request(
    fence: &WorkerSessionFence,
    page_id: &PageId,
    action_id: &ActionId,
    sequence: u64,
    key: &str,
    request_hash_byte: u8,
    approval_required: bool,
) -> WorkerRpcRequest {
    WorkerRpcRequest::SubmitAction {
        fence: fence.clone(),
        action_id: action_id.clone(),
        action_sequence: ActionSequence::new(sequence),
        requester_principal_id: PrincipalId::new(),
        idempotency_key: key.to_owned(),
        canonical_request_hash: [request_hash_byte; 32],
        kind: ActionKind::Mutating,
        page_id: Some(page_id.clone()),
        action: WorkerActionCommand::TypeText {
            text: key.to_owned(),
        },
        execution_timeout_ms: WorkerActionExecutionTimeout::DEFAULT,
        approval: approval_required.then(|| {
            Box::new(WorkerActionApprovalRequirement {
                target_incarnation: 1,
                frame_document_epoch: 1,
                current_origin: "https://example.test".to_owned(),
                url_revision: 1,
                action_type: WorkerApprovalActionType::Click,
                node_ref: None,
                credential_refs: Vec::new(),
                require_four_eyes: true,
            })
        }),
        now_unix_millis: sequence.saturating_add(1),
    }
}

#[tokio::test]
async fn known_driver_failure_produces_a_protocol_valid_receipt() -> Result<(), Box<dyn Error>> {
    let fixture = rpc_fixture(Arc::new(ExecutorDriver::failing()), 19032).await?;
    let action_id = ActionId::new();
    let response = fixture
        .handler
        .handle(submit_action_request(
            &fixture.fence,
            &fixture.primary_page_id,
            &action_id,
            1,
            "known-driver-failure",
            31,
            false,
        ))
        .await;
    let WorkerRpcResponse::Action(receipt) = response else {
        return Err("known driver failure did not return an action receipt".into());
    };
    assert_eq!(receipt.action_id, action_id);
    assert_eq!(receipt.status, WorkerActionStatus::FailedKnown);
    assert!(receipt.result.is_none());
    assert!(receipt.to_action_snapshot().is_ok());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn submit_action_rejected_while_session_owner_is_busy_is_not_durably_accepted()
-> Result<(), Box<dyn Error>> {
    let page_operation_started = Arc::new(Barrier::new(2));
    let release_page_operation = Arc::new(Barrier::new(2));
    let fixture = rpc_fixture(
        Arc::new(ExecutorDriver::blocking_page(
            Arc::clone(&page_operation_started),
            Arc::clone(&release_page_operation),
        )),
        19030,
    )
    .await?;

    let page_handler = Arc::clone(&fixture.handler);
    let page_fence = fixture.fence.clone();
    let page_task = tokio::spawn(async move {
        page_handler
            .handle(WorkerRpcRequest::CreatePage {
                fence: page_fence,
                now_unix_millis: 2,
            })
            .await
    });
    let _ = page_operation_started.wait();

    let action_id = ActionId::new();
    let request = submit_action_request(
        &fixture.fence,
        &fixture.primary_page_id,
        &action_id,
        1,
        "busy-owner-action",
        11,
        false,
    );
    let rejected = fixture.handler.handle(request.clone()).await;
    let while_owner_busy = fixture
        .handler
        .handle(WorkerRpcRequest::GetAction {
            fence: fixture.fence.clone(),
            action_id: action_id.clone(),
        })
        .await;
    let executions_while_busy = fixture
        .driver
        .action_execution_count
        .load(Ordering::Acquire);

    let _ = release_page_operation.wait();
    let page_response = page_task.await?;
    let after_owner_release = fixture
        .handler
        .handle(WorkerRpcRequest::GetAction {
            fence: fixture.fence.clone(),
            action_id: action_id.clone(),
        })
        .await;
    let executions_after_release = fixture
        .driver
        .action_execution_count
        .load(Ordering::Acquire);
    let retry = fixture.handler.handle(request).await;

    assert!(matches!(page_response, WorkerRpcResponse::Page(_)));
    assert!(matches!(
        rejected,
        WorkerRpcResponse::Failure(failure)
            if failure.code == WorkerRpcFailureCode::Capacity
    ));
    assert!(matches!(
        while_owner_busy,
        WorkerRpcResponse::Failure(failure)
            if failure.code == WorkerRpcFailureCode::NotFound
    ));
    assert!(matches!(
        after_owner_release,
        WorkerRpcResponse::Failure(failure)
            if failure.code == WorkerRpcFailureCode::NotFound
    ));
    assert_eq!(executions_while_busy, 0);
    assert_eq!(executions_after_release, 0);
    assert!(matches!(
        retry,
        WorkerRpcResponse::Action(receipt)
            if receipt.action_id == action_id
                && receipt.action_sequence == ActionSequence::new(1)
                && receipt.status == WorkerActionStatus::Succeeded
    ));
    assert_eq!(
        fixture
            .driver
            .action_execution_count
            .load(Ordering::Acquire),
        1
    );
    Ok(())
}

#[tokio::test]
async fn approving_queue_head_drains_ready_actions_until_the_next_pending_approval()
-> Result<(), Box<dyn Error>> {
    let fixture = rpc_fixture(Arc::new(ExecutorDriver::ready()), 19031).await?;
    let approval_head_id = ActionId::new();
    let first_ready_id = ActionId::new();
    let second_ready_id = ActionId::new();
    let next_approval_id = ActionId::new();
    let behind_next_approval_id = ActionId::new();
    let requests = [
        submit_action_request(
            &fixture.fence,
            &fixture.primary_page_id,
            &approval_head_id,
            1,
            "approval-head",
            21,
            true,
        ),
        submit_action_request(
            &fixture.fence,
            &fixture.primary_page_id,
            &first_ready_id,
            2,
            "ready-after-head-one",
            22,
            false,
        ),
        submit_action_request(
            &fixture.fence,
            &fixture.primary_page_id,
            &second_ready_id,
            3,
            "ready-after-head-two",
            23,
            false,
        ),
        submit_action_request(
            &fixture.fence,
            &fixture.primary_page_id,
            &next_approval_id,
            4,
            "next-approval",
            24,
            true,
        ),
        submit_action_request(
            &fixture.fence,
            &fixture.primary_page_id,
            &behind_next_approval_id,
            5,
            "ready-behind-next-approval",
            25,
            false,
        ),
    ];
    let mut submitted = Vec::new();
    for request in requests {
        submitted.push(fixture.handler.handle(request).await);
    }

    let approvals = fixture
        .handler
        .handle(WorkerRpcRequest::ListApprovals {
            fence: fixture.fence.clone(),
        })
        .await;
    let WorkerRpcResponse::Approvals(approvals) = approvals else {
        return Err(std::io::Error::other("approval queue was not returned").into());
    };
    let approval_id = approvals
        .iter()
        .find(|approval| approval.action_id == approval_head_id)
        .map(|approval| approval.approval_id.clone())
        .ok_or_else(|| std::io::Error::other("head approval was not found"))?;
    let decided = fixture
        .handler
        .handle(WorkerRpcRequest::DecideApproval {
            fence: fixture.fence.clone(),
            approval_id,
            decision: WorkerApprovalDecision::Approve,
            principal_id: PrincipalId::new(),
            reason: "approved for queue-drain contract test".to_owned(),
            now_unix_millis: 10,
        })
        .await;

    let action_ids = [
        approval_head_id.clone(),
        first_ready_id.clone(),
        second_ready_id.clone(),
        next_approval_id.clone(),
        behind_next_approval_id.clone(),
    ];
    let mut actions = Vec::new();
    for action_id in action_ids {
        actions.push(
            fixture
                .handler
                .handle(WorkerRpcRequest::GetAction {
                    fence: fixture.fence.clone(),
                    action_id,
                })
                .await,
        );
    }

    assert!(matches!(
        submitted.as_slice(),
        [
            WorkerRpcResponse::Action(first),
            WorkerRpcResponse::Action(second),
            WorkerRpcResponse::Action(third),
            WorkerRpcResponse::Action(fourth),
            WorkerRpcResponse::Action(fifth),
        ] if first.status == WorkerActionStatus::PendingApproval
            && second.status == WorkerActionStatus::Queued
            && third.status == WorkerActionStatus::Queued
            && fourth.status == WorkerActionStatus::PendingApproval
            && fifth.status == WorkerActionStatus::Queued
    ));
    assert!(matches!(decided, WorkerRpcResponse::Approval(_)));
    assert!(matches!(
        actions.as_slice(),
        [
            WorkerRpcResponse::Action(first),
            WorkerRpcResponse::Action(second),
            WorkerRpcResponse::Action(third),
            WorkerRpcResponse::Action(fourth),
            WorkerRpcResponse::Action(fifth),
        ] if first.status == WorkerActionStatus::Succeeded
            && second.status == WorkerActionStatus::Succeeded
            && third.status == WorkerActionStatus::Succeeded
            && fourth.status == WorkerActionStatus::PendingApproval
            && fifth.status == WorkerActionStatus::Queued
    ));
    assert_eq!(
        fixture
            .driver
            .action_execution_count
            .load(Ordering::Acquire),
        3
    );
    Ok(())
}
