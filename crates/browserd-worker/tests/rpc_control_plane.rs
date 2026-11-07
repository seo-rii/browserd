use std::collections::BTreeMap;
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::time::{Duration, Instant};

use browserd_actions::{
    ActionJournalLimits, ActionKind, ActionSequence, JournalSessionScope,
    TerminalCustodyRequirement,
};
use browserd_core::{
    ActionId, IsolationProfile, OperationId, PageId, PrincipalId, SessionId, TenantId, WorkerId,
};
use browserd_policy::{CanonicalActionProposal, Origin};
use browserd_sandbox::CleanupReason;
use browserd_session::{LeasePolicy, OwnershipFence, SessionTime, SessionTimeoutPolicy};
use browserd_worker::{
    ActionExecutionResult, ActionJournalConfig, ActionJournalPool, ActionJournalPoolConfig,
    ApprovedActionError, ArtifactStoreReceipt, ArtifactStoreRequest, AuthenticatedPeer,
    ChromiumDriver, DependencyError, InternalEndpoint, LiveApprovalContext, SandboxClient,
    SessionOptionSupport, UnavailableChromiumDriver, UnavailableSandboxClient,
    WORKER_SESSION_OPTIONS_VERSION, WorkerActionApprovalRequirement, WorkerActionCommand,
    WorkerActionExecutionTimeout, WorkerActionStatus, WorkerApprovalActionType, WorkerClock,
    WorkerConfig, WorkerControlPlane, WorkerControlPlaneRpcHandler, WorkerCreateSessionRequest,
    WorkerError, WorkerIsolationProfile, WorkerRpcFailureCode, WorkerRpcHandler, WorkerRpcRequest,
    WorkerRpcResponse, WorkerSessionFence, WorkerSessionOptionsV1, WorkerViewport,
};

#[path = "support/fleet_worker_admission.rs"]
mod fleet_worker_admission;

fn session_options() -> WorkerSessionOptionsV1 {
    WorkerSessionOptionsV1 {
        workload_class_hint: "interactive".to_owned(),
        viewport: WorkerViewport {
            width: 1_280,
            height: 720,
            device_scale_factor: 1,
        },
        locale: "ko-KR".to_owned(),
        timezone: "Asia/Seoul".to_owned(),
        user_agent: Some("browserd-rpc-options-test".to_owned()),
        network_policy_id: "public-web-default".to_owned(),
        network_class: "public".to_owned(),
        checkpoint_ref: None,
        dialog_policy: "auto_dismiss".to_owned(),
        feature_profile: "standard".to_owned(),
        ttl_seconds: 60,
        idle_timeout_seconds: 30,
        metadata: BTreeMap::from([("suite".to_owned(), "rpc-control-plane".to_owned())]),
    }
}

#[test]
fn options_aware_create_does_not_fall_back_to_the_legacy_driver_method() {
    let Some(worker_id) = WorkerId::new("worker-options-fail-closed").ok() else {
        return;
    };
    let tenant_id = TenantId::new();
    let session_id = SessionId::new();
    let fence = OwnershipFence::new(worker_id, 1, 1, 1);
    let driver = UnavailableChromiumDriver;

    assert_eq!(
        driver.create_context_owned(&tenant_id, &session_id, &fence),
        Err(DependencyError::Unavailable)
    );
    assert_eq!(
        driver.create_context_owned_with_options(
            &tenant_id,
            &session_id,
            &fence,
            &session_options(),
        ),
        Err(DependencyError::Rejected)
    );
}

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

struct OptionsRecordingDriver {
    calls: AtomicUsize,
    observed: Mutex<Option<WorkerSessionOptionsV1>>,
    page_id: PageId,
    placement: Option<WorkerIsolationProfile>,
    closed: AtomicUsize,
}

impl OptionsRecordingDriver {
    fn new(page_id: PageId) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            observed: Mutex::new(None),
            page_id,
            placement: None,
            closed: AtomicUsize::new(0),
        }
    }
}

impl ChromiumDriver for OptionsRecordingDriver {
    fn supports_requested_isolation(&self, requested: WorkerIsolationProfile) -> bool {
        self.placement.is_some() || requested.satisfied_by(self.effective_isolation())
    }

    fn create_context_owned_with_placement(
        &self,
        tenant: &TenantId,
        session: &SessionId,
        fence: &OwnershipFence,
        options: Option<&WorkerSessionOptionsV1>,
        _requested: WorkerIsolationProfile,
    ) -> Result<browserd_worker::CreatedSessionContext, DependencyError> {
        let options = options.ok_or(DependencyError::Rejected)?;
        Ok(browserd_worker::CreatedSessionContext {
            primary_page_id: self
                .create_context_owned_with_options(tenant, session, fence, options)?,
            effective_isolation: self.placement.unwrap_or(self.effective_isolation()),
        })
    }

    fn qualify(&self) -> Result<(), DependencyError> {
        Ok(())
    }

    fn create_context(&self, _session_id: &SessionId) -> Result<PageId, DependencyError> {
        Err(DependencyError::Rejected)
    }

    fn create_context_owned_with_options(
        &self,
        _tenant_id: &TenantId,
        _session_id: &SessionId,
        _fence: &OwnershipFence,
        options: &WorkerSessionOptionsV1,
    ) -> Result<PageId, DependencyError> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        let mut observed = self
            .observed
            .lock()
            .map_err(|_| DependencyError::Unavailable)?;
        *observed = Some(options.clone());
        Ok(self.page_id.clone())
    }

    fn close_context(&self, _session_id: &SessionId) -> Result<(), DependencyError> {
        self.closed.fetch_add(1, Ordering::SeqCst);
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
        session_id: &SessionId,
        page_id: &PageId,
        proposal: &CanonicalActionProposal,
    ) -> Result<LiveApprovalContext, DependencyError> {
        ReadyDriver.inspect_approval_context(session_id, page_id, proposal)
    }

    fn execute_approved_action(
        &self,
        session_id: &SessionId,
        page_id: &PageId,
        payload: &[u8],
        proposal: &CanonicalActionProposal,
        inspected: &LiveApprovalContext,
        authorize_and_commit: &mut dyn FnMut(
            &LiveApprovalContext,
        ) -> Result<(), ApprovedActionError>,
    ) -> Result<ActionExecutionResult, ApprovedActionError> {
        ReadyDriver.execute_approved_action(
            session_id,
            page_id,
            payload,
            proposal,
            inspected,
            authorize_and_commit,
        )
    }

    fn cancel_action(
        &self,
        _session_id: &SessionId,
        _action_id: &ActionId,
    ) -> Result<bool, DependencyError> {
        Ok(true)
    }
}

struct BlockingActionDriver {
    execution_started: Arc<Barrier>,
    release_execution: Arc<Barrier>,
    execution_count: AtomicUsize,
}

impl BlockingActionDriver {
    fn new(execution_started: Arc<Barrier>, release_execution: Arc<Barrier>) -> Self {
        Self {
            execution_started,
            release_execution,
            execution_count: AtomicUsize::new(0),
        }
    }
}

impl ChromiumDriver for BlockingActionDriver {
    fn qualify(&self) -> Result<(), DependencyError> {
        ReadyDriver.qualify()
    }

    fn create_context(&self, session_id: &SessionId) -> Result<PageId, DependencyError> {
        ReadyDriver.create_context(session_id)
    }

    fn create_context_owned_with_options(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        fence: &OwnershipFence,
        options: &WorkerSessionOptionsV1,
    ) -> Result<PageId, DependencyError> {
        ReadyDriver.create_context_owned_with_options(tenant_id, session_id, fence, options)
    }

    fn close_context(&self, session_id: &SessionId) -> Result<(), DependencyError> {
        ReadyDriver.close_context(session_id)
    }

    fn create_page(&self, session_id: &SessionId) -> Result<PageId, DependencyError> {
        ReadyDriver.create_page(session_id)
    }

    fn close_page(&self, session_id: &SessionId, page_id: &PageId) -> Result<(), DependencyError> {
        ReadyDriver.close_page(session_id, page_id)
    }

    fn activate_page(
        &self,
        session_id: &SessionId,
        page_id: &PageId,
    ) -> Result<(), DependencyError> {
        ReadyDriver.activate_page(session_id, page_id)
    }

    fn execute_action(
        &self,
        _session_id: &SessionId,
        _page_id: Option<&PageId>,
        payload: &[u8],
    ) -> ActionExecutionResult {
        if self.execution_count.fetch_add(1, Ordering::AcqRel) == 0 {
            let _ = self.execution_started.wait();
            let _ = self.release_execution.wait();
        }
        ActionExecutionResult::Succeeded(payload.to_vec())
    }

    fn inspect_approval_context(
        &self,
        session_id: &SessionId,
        page_id: &PageId,
        proposal: &CanonicalActionProposal,
    ) -> Result<LiveApprovalContext, DependencyError> {
        ReadyDriver.inspect_approval_context(session_id, page_id, proposal)
    }

    fn execute_approved_action(
        &self,
        session_id: &SessionId,
        page_id: &PageId,
        payload: &[u8],
        proposal: &CanonicalActionProposal,
        inspected: &LiveApprovalContext,
        authorize_and_commit: &mut dyn FnMut(
            &LiveApprovalContext,
        ) -> Result<(), ApprovedActionError>,
    ) -> Result<ActionExecutionResult, ApprovedActionError> {
        ReadyDriver.execute_approved_action(
            session_id,
            page_id,
            payload,
            proposal,
            inspected,
            authorize_and_commit,
        )
    }

    fn cancel_action(
        &self,
        session_id: &SessionId,
        action_id: &ActionId,
    ) -> Result<bool, DependencyError> {
        ReadyDriver.cancel_action(session_id, action_id)
    }
}

/// A ready driver whose effective isolation is `DedicatedProcess`, used to exercise isolation
/// negotiation (BRD-001) against a worker that provides stronger isolation than `SharedContext`.
struct DedicatedProcessDriver;

impl ChromiumDriver for DedicatedProcessDriver {
    fn qualify(&self) -> Result<(), DependencyError> {
        ReadyDriver.qualify()
    }

    fn effective_isolation(&self) -> WorkerIsolationProfile {
        WorkerIsolationProfile::DedicatedProcess
    }

    fn create_context(&self, session_id: &SessionId) -> Result<PageId, DependencyError> {
        ReadyDriver.create_context(session_id)
    }

    fn create_context_owned_with_options(
        &self,
        tenant_id: &TenantId,
        session_id: &SessionId,
        fence: &OwnershipFence,
        options: &WorkerSessionOptionsV1,
    ) -> Result<PageId, DependencyError> {
        ReadyDriver.create_context_owned_with_options(tenant_id, session_id, fence, options)
    }

    fn close_context(&self, session_id: &SessionId) -> Result<(), DependencyError> {
        ReadyDriver.close_context(session_id)
    }

    fn create_page(&self, session_id: &SessionId) -> Result<PageId, DependencyError> {
        ReadyDriver.create_page(session_id)
    }

    fn close_page(&self, session_id: &SessionId, page_id: &PageId) -> Result<(), DependencyError> {
        ReadyDriver.close_page(session_id, page_id)
    }

    fn activate_page(
        &self,
        session_id: &SessionId,
        page_id: &PageId,
    ) -> Result<(), DependencyError> {
        ReadyDriver.activate_page(session_id, page_id)
    }

    fn execute_action(
        &self,
        session_id: &SessionId,
        page_id: Option<&PageId>,
        payload: &[u8],
    ) -> ActionExecutionResult {
        ReadyDriver.execute_action(session_id, page_id, payload)
    }

    fn inspect_approval_context(
        &self,
        session_id: &SessionId,
        page_id: &PageId,
        proposal: &CanonicalActionProposal,
    ) -> Result<LiveApprovalContext, DependencyError> {
        ReadyDriver.inspect_approval_context(session_id, page_id, proposal)
    }

    fn execute_approved_action(
        &self,
        session_id: &SessionId,
        page_id: &PageId,
        payload: &[u8],
        proposal: &CanonicalActionProposal,
        inspected: &LiveApprovalContext,
        authorize_and_commit: &mut dyn FnMut(
            &LiveApprovalContext,
        ) -> Result<(), ApprovedActionError>,
    ) -> Result<ActionExecutionResult, ApprovedActionError> {
        ReadyDriver.execute_approved_action(
            session_id,
            page_id,
            payload,
            proposal,
            inspected,
            authorize_and_commit,
        )
    }

    fn cancel_action(
        &self,
        session_id: &SessionId,
        action_id: &ActionId,
    ) -> Result<bool, DependencyError> {
        ReadyDriver.cancel_action(session_id, action_id)
    }
}

struct ReadySandbox;

#[tokio::test]
async fn named_upload_rpc_rejects_unsafe_filenames_before_storage() -> Result<(), Box<dyn Error>> {
    let fixture = action_rpc_fixture(Arc::new(ReadyDriver), Arc::new(ReadySandbox), 19082).await?;
    for display_filename in [
        "".to_owned(),
        ".".to_owned(),
        "..".to_owned(),
        "/tmp/file".to_owned(),
        "a\\b".to_owned(),
        "a\nb".to_owned(),
        "a".repeat(256),
        "한".repeat(86),
    ] {
        let response = fixture
            .handler
            .handle(WorkerRpcRequest::UploadNamedArtifact {
                fence: fixture.fence.clone(),
                bytes: b"hello".to_vec(),
                content_type: "text/plain".to_owned(),
                display_filename,
                now_unix_millis: 2,
            })
            .await;
        assert!(
            matches!(response, WorkerRpcResponse::Failure(failure) if failure.code == WorkerRpcFailureCode::InvalidRequest)
        );
    }
    // The valid Unicode basename crosses validation and reaches this fixture's unavailable
    // storage adapter. A filename validation failure would instead be InvalidRequest.
    let response = fixture
        .handler
        .handle(WorkerRpcRequest::UploadNamedArtifact {
            fence: fixture.fence.clone(),
            bytes: b"hello".to_vec(),
            content_type: "text/plain".to_owned(),
            display_filename: "첨부 문서.txt".to_owned(),
            now_unix_millis: 2,
        })
        .await;
    assert!(
        matches!(response, WorkerRpcResponse::Failure(failure) if failure.code == WorkerRpcFailureCode::Dependency)
    );
    Ok(())
}

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

struct ActionRpcFixture<D, S> {
    _directory: tempfile::TempDir,
    worker: Arc<WorkerControlPlane<D, S>>,
    handler: Arc<WorkerControlPlaneRpcHandler<D, S>>,
    peer: AuthenticatedPeer,
    ownership: OwnershipFence,
    fence: WorkerSessionFence,
    primary_page_id: PageId,
}

fn action_rpc_config(
    directory: &std::path::Path,
    worker_id: &WorkerId,
    epoch: u64,
    peer: &AuthenticatedPeer,
    endpoint_port: u16,
) -> Result<WorkerConfig, Box<dyn Error>> {
    let lease = LeasePolicy::new(Duration::from_secs(15), Duration::from_secs(3))
        .map_err(|error| std::io::Error::other(format!("invalid lease policy: {error:?}")))?;
    let timeout = SessionTimeoutPolicy::new(Duration::from_secs(60), Duration::from_secs(30))
        .map_err(|error| std::io::Error::other(format!("invalid timeout policy: {error:?}")))?;
    let journal = ActionJournalConfig::new(directory, ActionJournalLimits::default())
        .map_err(|error| std::io::Error::other(format!("invalid action journal: {error:?}")))?;
    Ok(WorkerConfig::new(
        worker_id.clone(),
        epoch,
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
    .map_err(|error| std::io::Error::other(format!("invalid worker config: {error:?}")))?
    .with_session_option_support(SessionOptionSupport::single_host_default()))
}

async fn action_rpc_fixture<D: ChromiumDriver, S: SandboxClient>(
    driver: Arc<D>,
    sandbox: Arc<S>,
    endpoint_port: u16,
) -> Result<ActionRpcFixture<D, S>, Box<dyn Error>> {
    action_rpc_fixture_with_pool(driver, sandbox, endpoint_port, false).await
}

async fn action_rpc_fixture_with_pool<D: ChromiumDriver, S: SandboxClient>(
    driver: Arc<D>,
    sandbox: Arc<S>,
    endpoint_port: u16,
    pooled: bool,
) -> Result<ActionRpcFixture<D, S>, Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let worker_id = WorkerId::new(format!("worker-rpc-action-{endpoint_port}"))?;
    let peer = AuthenticatedPeer::new(format!("gateway-rpc-action-{endpoint_port}"))
        .map_err(|error| std::io::Error::other(format!("invalid action peer: {error:?}")))?;
    let config = action_rpc_config(directory.path(), &worker_id, 7, &peer, endpoint_port)?;
    let tenant_id = TenantId::new();
    let mut worker =
        WorkerControlPlane::new_with_clock(config, driver, sandbox, Arc::new(FrozenClock));
    if pooled {
        let pool = ActionJournalPool::open(
            ActionJournalPoolConfig::new(
                directory.path().to_path_buf(),
                ActionJournalLimits::default(),
            )?,
            worker_id.clone(),
        )?;
        worker = worker.with_action_journal_pool(pool);
    }
    let worker = Arc::new(worker);
    let handler = Arc::new(WorkerControlPlaneRpcHandler::new(
        Arc::clone(&worker),
        peer.clone(),
    ));
    let options = session_options();
    let created = handler
        .handle(WorkerRpcRequest::CreateSession(
            WorkerCreateSessionRequest {
                operation_id: OperationId::new(),
                tenant_id: tenant_id.clone(),
                idempotency_key: format!("create-action-{endpoint_port}"),
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
        return Err(std::io::Error::other("action RPC fixture session creation failed").into());
    };
    let ownership = OwnershipFence::new(
        worker_id,
        created.worker_epoch,
        created.placement_version,
        created.session_incarnation,
    );
    let fence = WorkerSessionFence {
        tenant_id,
        session_id: created.session_id,
        worker_epoch: created.worker_epoch,
        placement_version: created.placement_version,
        session_incarnation: created.session_incarnation,
    };
    Ok(ActionRpcFixture {
        _directory: directory,
        worker,
        handler,
        peer,
        ownership,
        fence,
        primary_page_id: created.primary_page_id,
    })
}

#[tokio::test]
async fn create_session_rpc_forwards_valid_v1_options_to_the_owned_driver_boundary()
-> Result<(), Box<dyn Error>> {
    let expected_page_id = PageId::new();
    let driver = Arc::new(OptionsRecordingDriver::new(expected_page_id.clone()));
    let fixture = action_rpc_fixture(Arc::clone(&driver), Arc::new(ReadySandbox), 19031).await?;

    assert_eq!(fixture.primary_page_id, expected_page_id);
    assert_eq!(driver.calls.load(Ordering::Acquire), 1);
    assert_eq!(
        *driver
            .observed
            .lock()
            .map_err(|_| std::io::Error::other("options observation lock poisoned"))?,
        Some(session_options()),
    );
    Ok(())
}

#[tokio::test]
async fn create_session_rpc_rejects_options_hash_mismatch_before_browser_effect()
-> Result<(), Box<dyn Error>> {
    let driver = Arc::new(OptionsRecordingDriver::new(PageId::new()));
    let fixture = action_rpc_fixture(Arc::clone(&driver), Arc::new(ReadySandbox), 19032).await?;
    let options = WorkerSessionOptionsV1 {
        locale: "en-US".to_owned(),
        ..session_options()
    };
    let response = fixture
        .handler
        .handle(WorkerRpcRequest::CreateSession(
            WorkerCreateSessionRequest {
                operation_id: OperationId::new(),
                tenant_id: fixture.fence.tenant_id.clone(),
                idempotency_key: "create-options-hash-mismatch".to_owned(),
                canonical_request_hash: session_options()
                    .canonical_request_hash(WorkerIsolationProfile::SharedContext),
                expected_worker_epoch: fixture.fence.worker_epoch,
                placement_version: 2,
                session_incarnation: 1,
                requested_isolation: WorkerIsolationProfile::SharedContext,
                options_version: WORKER_SESSION_OPTIONS_VERSION,
                options,
                now_unix_millis: 2,
            },
        ))
        .await;

    assert!(matches!(
        response,
        WorkerRpcResponse::Failure(failure)
            if failure.code == WorkerRpcFailureCode::InvalidRequest
    ));
    assert_eq!(driver.calls.load(Ordering::Acquire), 1);
    Ok(())
}

fn submit_action_request(
    fence: &WorkerSessionFence,
    page_id: &PageId,
    action_id: &ActionId,
    action_sequence: u64,
    idempotency_key: &str,
    request_hash_byte: u8,
) -> WorkerRpcRequest {
    WorkerRpcRequest::SubmitAction {
        fence: fence.clone(),
        action_id: action_id.clone(),
        action_sequence: ActionSequence::new(action_sequence),
        requester_principal_id: PrincipalId::new(),
        idempotency_key: idempotency_key.to_owned(),
        canonical_request_hash: [request_hash_byte; 32],
        kind: ActionKind::Mutating,
        page_id: Some(page_id.clone()),
        action: WorkerActionCommand::TypeText {
            text: idempotency_key.to_owned(),
        },
        execution_timeout_ms: WorkerActionExecutionTimeout::DEFAULT,
        approval: None,
        now_unix_millis: action_sequence.saturating_add(1),
    }
}

#[tokio::test]
async fn transient_terminal_projection_preserves_known_result_and_historical_rpc_recovers_after_restart()
-> Result<(), Box<dyn Error>> {
    let driver = Arc::new(BlockingActionDriver::new(
        Arc::new(Barrier::new(1)),
        Arc::new(Barrier::new(1)),
    ));
    let fixture =
        action_rpc_fixture_with_pool(Arc::clone(&driver), Arc::new(ReadySandbox), 19117, true)
            .await?;
    let action_id = ActionId::new();
    let WorkerRpcResponse::Action(original) = fixture
        .handler
        .handle(submit_action_request(
            &fixture.fence,
            &fixture.primary_page_id,
            &action_id,
            1,
            "projection-recovery",
            93,
        ))
        .await
    else {
        return Err(std::io::Error::other("projection action was not accepted").into());
    };
    original.to_action_snapshot()?;
    assert_eq!(original.status, WorkerActionStatus::Succeeded);
    assert_eq!(
        original.custody_requirement,
        Some(TerminalCustodyRequirement::Required)
    );
    let custody = original
        .custody
        .as_ref()
        .ok_or_else(|| std::io::Error::other("original custody missing"))?
        .clone();
    let wal = fixture
        ._directory
        .path()
        .join(format!("{}.wal", fixture.fence.session_id));
    let durable_bytes = std::fs::read(&wal)?;
    let mut unreadable = durable_bytes.clone();
    let last = unreadable
        .last_mut()
        .ok_or_else(|| std::io::Error::other("empty action WAL"))?;
    *last ^= 1;
    // Fail the optional projection's real replay read while the durable terminal result is
    // already in the live action ledger. Restore the same inode before reopening the pool.
    std::fs::write(&wal, unreadable)?;
    let observed = fixture
        .handler
        .handle(WorkerRpcRequest::GetAction {
            fence: fixture.fence.clone(),
            action_id: action_id.clone(),
        })
        .await;
    std::fs::write(&wal, durable_bytes)?;
    let WorkerRpcResponse::Action(observed) = observed else {
        return Err(std::io::Error::other("known result was lost on projection failure").into());
    };
    observed.to_action_snapshot()?;
    assert_eq!(observed.status, original.status);
    assert_eq!(observed.terminal_detail, original.terminal_detail);
    assert_eq!(observed.result, original.result);
    assert_eq!(
        observed.custody_requirement,
        Some(TerminalCustodyRequirement::Required)
    );
    assert!(observed.custody.is_none());
    assert!(matches!(
        fixture
            .handler
            .handle(WorkerRpcRequest::CloseSession {
                fence: fixture.fence.clone(),
                now_unix_millis: 3,
            })
            .await,
        WorkerRpcResponse::SessionClosed(_)
    ));
    let worker_id = fixture.ownership.worker_id().clone();
    let scope = custody.scope().clone();
    let ActionRpcFixture {
        _directory: directory,
        worker,
        handler,
        peer,
        ..
    } = fixture;
    drop(handler);
    drop(worker);
    let pool = ActionJournalPool::open(
        ActionJournalPoolConfig::new(
            directory.path().to_path_buf(),
            ActionJournalLimits::default(),
        )?,
        worker_id.clone(),
    )?;
    let worker = Arc::new(
        WorkerControlPlane::new_with_clock(
            action_rpc_config(directory.path(), &worker_id, 8, &peer, 19117)?,
            Arc::new(UnavailableChromiumDriver),
            Arc::new(UnavailableSandboxClient),
            Arc::new(FrozenClock),
        )
        .with_action_journal_pool(pool),
    );
    let handler = WorkerControlPlaneRpcHandler::new(Arc::clone(&worker), peer.clone());
    assert!(
        matches!(handler.handle(WorkerRpcRequest::Probe { expected_worker_epoch: 8 }).await,
        WorkerRpcResponse::Failure(f) if f.code == WorkerRpcFailureCode::NotReady)
    );
    let query = WorkerRpcRequest::GetTerminalCustody {
        expected_serving_worker_id: worker_id.clone(),
        expected_serving_worker_epoch: 8,
        scope: scope.clone(),
        action_id: action_id.clone(),
        action_sequence: original.action_sequence,
        kind: original.kind,
    };
    for _ in 0..2 {
        let WorkerRpcResponse::TerminalCustody(proof) = handler.handle(query.clone()).await else {
            return Err(std::io::Error::other("historical custody could not be recovered").into());
        };
        proof.validate_for(
            &worker_id,
            8,
            &scope,
            &action_id,
            original.action_sequence,
            original.kind,
        )?;
        assert_eq!(*proof.receipt, *custody);
    }
    let invalid_scopes = [
        JournalSessionScope::new(
            TenantId::new(),
            scope.session_id().clone(),
            worker_id.clone(),
            scope.fence(),
        )?,
        JournalSessionScope::new(
            scope.tenant_id().clone(),
            SessionId::new(),
            worker_id.clone(),
            scope.fence(),
        )?,
        JournalSessionScope::new(
            scope.tenant_id().clone(),
            scope.session_id().clone(),
            worker_id.clone(),
            browserd_core::PlacementFence::new(
                scope.fence().worker_epoch,
                scope.fence().placement_version + 1,
                scope.fence().session_incarnation,
            ),
        )?,
    ];
    for wrong_scope in invalid_scopes {
        assert!(matches!(
            handler
                .handle(WorkerRpcRequest::GetTerminalCustody {
                    expected_serving_worker_id: worker_id.clone(),
                    expected_serving_worker_epoch: 8,
                    scope: wrong_scope,
                    action_id: action_id.clone(),
                    action_sequence: original.action_sequence,
                    kind: original.kind,
                })
                .await,
            WorkerRpcResponse::Failure(_)
        ));
    }
    for (epoch, sequence, kind) in [
        (7, original.action_sequence, original.kind),
        (8, ActionSequence::new(2), original.kind),
        (8, original.action_sequence, ActionKind::ReadOnly),
    ] {
        assert!(matches!(
            handler
                .handle(WorkerRpcRequest::GetTerminalCustody {
                    expected_serving_worker_id: worker_id.clone(),
                    expected_serving_worker_epoch: epoch,
                    scope: scope.clone(),
                    action_id: action_id.clone(),
                    action_sequence: sequence,
                    kind,
                })
                .await,
            WorkerRpcResponse::Failure(_)
        ));
    }
    let foreign = WorkerControlPlaneRpcHandler::new(
        worker,
        AuthenticatedPeer::new("foreign-custody-peer")
            .map_err(|_| std::io::Error::other("invalid test peer"))?,
    );
    assert!(matches!(
        foreign.handle(query).await,
        WorkerRpcResponse::Failure(_)
    ));
    assert_eq!(driver.execution_count.load(Ordering::Acquire), 1);
    Ok(())
}

#[tokio::test]
async fn unmanaged_origin_is_explicit_but_historical_pool_absence_is_unavailable()
-> Result<(), Box<dyn Error>> {
    let driver = Arc::new(BlockingActionDriver::new(
        Arc::new(Barrier::new(1)),
        Arc::new(Barrier::new(1)),
    ));
    let fixture = action_rpc_fixture(Arc::clone(&driver), Arc::new(ReadySandbox), 19118).await?;
    let action_id = ActionId::new();
    let WorkerRpcResponse::Action(receipt) = fixture
        .handler
        .handle(submit_action_request(
            &fixture.fence,
            &fixture.primary_page_id,
            &action_id,
            1,
            "unmanaged-origin",
            94,
        ))
        .await
    else {
        return Err(std::io::Error::other("unmanaged action was not accepted").into());
    };
    receipt.to_action_snapshot()?;
    assert_eq!(receipt.status, WorkerActionStatus::Succeeded);
    assert_eq!(
        receipt.custody_requirement,
        Some(TerminalCustodyRequirement::Unsupported)
    );
    assert!(receipt.custody.is_none());
    let scope = JournalSessionScope::new(
        fixture.fence.tenant_id.clone(),
        fixture.fence.session_id.clone(),
        fixture.ownership.worker_id().clone(),
        fixture.ownership.as_placement_fence(),
    )?;
    assert!(
        matches!(fixture.handler.handle(WorkerRpcRequest::GetTerminalCustody {
        expected_serving_worker_id: fixture.ownership.worker_id().clone(), expected_serving_worker_epoch: 7,
        scope, action_id, action_sequence: receipt.action_sequence, kind: receipt.kind,
    }).await, WorkerRpcResponse::Failure(f) if f.code == WorkerRpcFailureCode::Durability)
    );
    assert_eq!(driver.execution_count.load(Ordering::Acquire), 1);
    Ok(())
}

#[tokio::test]
async fn terminal_custody_survives_lost_ack_restart_and_unready_release()
-> Result<(), Box<dyn Error>> {
    const DAY: u64 = 24 * 60 * 60 * 1000;
    let driver = Arc::new(BlockingActionDriver::new(
        Arc::new(Barrier::new(1)),
        Arc::new(Barrier::new(1)),
    ));
    let fixture =
        action_rpc_fixture_with_pool(Arc::clone(&driver), Arc::new(ReadySandbox), 19115, true)
            .await?;
    let action_id = ActionId::new();
    let submitted = fixture
        .handler
        .handle(submit_action_request(
            &fixture.fence,
            &fixture.primary_page_id,
            &action_id,
            1,
            "custody-once",
            91,
        ))
        .await;
    let WorkerRpcResponse::Action(submitted) = submitted else {
        return Err(std::io::Error::other("custody action was not accepted").into());
    };
    assert_eq!(submitted.status, WorkerActionStatus::Succeeded);
    submitted.to_action_snapshot()?;
    let custody = submitted
        .custody
        .ok_or_else(|| std::io::Error::other("terminal custody missing"))?;
    assert_ne!(custody.request_hash().as_bytes(), &[91; 32]);
    assert_eq!(custody.action_id(), &action_id);
    let worker_id = fixture.ownership.worker_id().clone();
    let ack_request = WorkerRpcRequest::AckTerminalCustody {
        expected_serving_worker_id: worker_id.clone(),
        expected_serving_worker_epoch: 7,
        receipt: custody.clone(),
    };
    // The caller loses this successful response before persisting its positive ACK.
    assert!(matches!(
        fixture.handler.handle(ack_request).await,
        WorkerRpcResponse::TerminalCustodyAck(_)
    ));
    assert!(matches!(
        fixture
            .handler
            .handle(WorkerRpcRequest::CloseSession {
                fence: fixture.fence.clone(),
                now_unix_millis: 3,
            })
            .await,
        WorkerRpcResponse::SessionClosed(_)
    ));
    assert_eq!(driver.execution_count.load(Ordering::Acquire), 1);
    let ActionRpcFixture {
        _directory: directory,
        worker,
        handler,
        peer,
        fence,
        ..
    } = fixture;
    drop(handler);
    drop(worker);
    let pool = ActionJournalPool::open(
        ActionJournalPoolConfig::new(
            directory.path().to_path_buf(),
            ActionJournalLimits::default(),
        )?,
        worker_id.clone(),
    )?;
    // An ACK alone never allows deletion, even after its retention horizon.
    assert_eq!(
        pool.maintain(30 * DAY, 32, Instant::now() + Duration::from_secs(2))?,
        0
    );
    let config = action_rpc_config(directory.path(), &worker_id, 8, &peer, 19115)?;
    let worker = Arc::new(
        WorkerControlPlane::new_with_clock(
            config,
            Arc::new(UnavailableChromiumDriver),
            Arc::new(UnavailableSandboxClient),
            Arc::new(FrozenClock),
        )
        .with_action_journal_pool(Arc::clone(&pool)),
    );
    let handler = WorkerControlPlaneRpcHandler::new(Arc::clone(&worker), peer.clone());
    assert!(
        matches!(handler.handle(WorkerRpcRequest::Probe { expected_worker_epoch: 8 }).await,
        WorkerRpcResponse::Failure(f) if f.code == WorkerRpcFailureCode::NotReady)
    );
    assert!(
        matches!(handler.handle(WorkerRpcRequest::AckTerminalCustody {
        expected_serving_worker_id: worker_id.clone(), expected_serving_worker_epoch: 7, receipt: custody.clone(),
    }).await, WorkerRpcResponse::Failure(f) if f.code == WorkerRpcFailureCode::FenceMismatch)
    );
    for _ in 0..2 {
        let response = handler
            .handle(WorkerRpcRequest::AckTerminalCustody {
                expected_serving_worker_id: worker_id.clone(),
                expected_serving_worker_epoch: 8,
                receipt: custody.clone(),
            })
            .await;
        assert!(
            matches!(response, WorkerRpcResponse::TerminalCustodyAck(ack)
            if ack.worker_id == worker_id && ack.worker_epoch == 8 && ack.receipt_sha256 == custody.digest())
        );
    }
    assert!(
        matches!(handler.handle(WorkerRpcRequest::GetSession { fence }).await,
        WorkerRpcResponse::Failure(f) if matches!(f.code, WorkerRpcFailureCode::NotFound | WorkerRpcFailureCode::FenceMismatch))
    );
    assert_eq!(
        pool.maintain(30 * DAY, 32, Instant::now() + Duration::from_secs(2))?,
        0
    );
    let release = WorkerRpcRequest::ReleaseTerminalCustody {
        expected_serving_worker_id: worker_id.clone(),
        expected_serving_worker_epoch: 8,
        receipt: custody.clone(),
    };
    assert!(matches!(
        handler.handle(release.clone()).await,
        WorkerRpcResponse::TerminalCustodyRelease(_)
    ));
    assert_eq!(
        pool.maintain(30 * DAY, 32, Instant::now() + Duration::from_secs(2))?,
        1
    );
    // A lost release response converges after physical deletion; it cannot fabricate a copy ACK.
    assert!(
        matches!(handler.handle(release).await, WorkerRpcResponse::TerminalCustodyRelease(ack)
        if ack.receipt_sha256 == custody.digest())
    );
    assert!(matches!(
        handler
            .handle(WorkerRpcRequest::AckTerminalCustody {
                expected_serving_worker_id: worker_id,
                expected_serving_worker_epoch: 8,
                receipt: custody,
            })
            .await,
        WorkerRpcResponse::Failure(_)
    ));
    assert_eq!(driver.execution_count.load(Ordering::Acquire), 1);
    Ok(())
}

#[tokio::test]
async fn terminal_custody_remains_queryable_after_closed_session_memory_is_reclaimed()
-> Result<(), Box<dyn Error>> {
    const DAY: u64 = 24 * 60 * 60 * 1000;
    let driver = Arc::new(BlockingActionDriver::new(
        Arc::new(Barrier::new(1)),
        Arc::new(Barrier::new(1)),
    ));
    let fixture =
        action_rpc_fixture_with_pool(Arc::clone(&driver), Arc::new(ReadySandbox), 19116, true)
            .await?;
    let action_id = ActionId::new();
    let WorkerRpcResponse::Action(receipt) = fixture
        .handler
        .handle(submit_action_request(
            &fixture.fence,
            &fixture.primary_page_id,
            &action_id,
            1,
            "custody-retired",
            92,
        ))
        .await
    else {
        return Err(std::io::Error::other("retained action missing").into());
    };
    let custody = receipt
        .custody
        .ok_or_else(|| std::io::Error::other("retained custody missing"))?;
    fixture
        .worker
        .close_session(
            &fixture.peer,
            &fixture.fence.session_id,
            &fixture.ownership,
            SessionTime::new(3),
        )
        .map_err(|error| std::io::Error::other(format!("close failed: {error:?}")))?;
    assert_eq!(
        fixture
            .worker
            .reclaim_retired_sessions(&fixture.peer, SessionTime::new(4))
            .map_err(|error| std::io::Error::other(format!("reclamation failed: {error:?}")))?,
        0
    );
    assert_eq!(
        fixture
            .worker
            .reclaim_retired_sessions(&fixture.peer, SessionTime::new(DAY + 4))
            .map_err(|error| std::io::Error::other(format!("reclamation failed: {error:?}")))?,
        1
    );
    assert_eq!(
        fixture
            .worker
            .terminal_custody_receipt(
                &fixture.peer,
                &fixture.fence.tenant_id,
                &fixture.fence.session_id,
                &action_id,
                &fixture.ownership,
            )
            .map_err(|error| std::io::Error::other(format!("custody read failed: {error:?}")))?,
        Some(*custody.clone())
    );
    let foreign = AuthenticatedPeer::new("untrusted-custody-peer")
        .map_err(|error| std::io::Error::other(format!("peer failed: {error:?}")))?;
    assert_eq!(
        fixture
            .worker
            .ack_terminal_custody(&foreign, fixture.ownership.worker_id(), 7, &custody),
        Err(WorkerError::UnauthorizedPeer)
    );
    let mut wrong_scope = fixture.fence.clone();
    wrong_scope.tenant_id = TenantId::new();
    assert!(
        fixture
            .worker
            .terminal_custody_receipt(
                &fixture.peer,
                &wrong_scope.tenant_id,
                &wrong_scope.session_id,
                &action_id,
                &fixture.ownership,
            )
            .is_err()
    );
    let scope = JournalSessionScope::new(
        fixture.fence.tenant_id,
        fixture.fence.session_id,
        fixture.ownership.worker_id().clone(),
        fixture.ownership.as_placement_fence(),
    )?;
    assert_eq!(custody.scope(), &scope);
    assert_eq!(driver.execution_count.load(Ordering::Acquire), 1);
    Ok(())
}

#[tokio::test]
async fn invalid_checkpoint_origins_are_rejected_before_action_registration()
-> Result<(), Box<dyn Error>> {
    let fixture = action_rpc_fixture(Arc::new(ReadyDriver), Arc::new(ReadySandbox), 19084).await?;
    for origins in [
        vec!["https://example.test/path".to_owned()],
        vec!["https://example.test".to_owned(); 2],
        (0..17)
            .map(|i| format!("https://origin-{i}.test"))
            .collect(),
    ] {
        let id = ActionId::new();
        let mut request = submit_action_request(
            &fixture.fence,
            &fixture.primary_page_id,
            &id,
            1,
            "invalid-checkpoint",
            3,
        );
        if let WorkerRpcRequest::SubmitAction { action, kind, .. } = &mut request {
            *action = WorkerActionCommand::Checkpoint { origins };
            *kind = ActionKind::ReadOnly;
        }
        assert!(
            matches!(fixture.handler.handle(request).await,WorkerRpcResponse::Failure(failure) if failure.code==WorkerRpcFailureCode::InvalidRequest)
        );
        assert!(
            matches!(fixture.handler.handle(WorkerRpcRequest::GetAction { fence:fixture.fence.clone(),action_id:id }).await,WorkerRpcResponse::Failure(failure) if failure.code==WorkerRpcFailureCode::NotFound)
        );
    }
    Ok(())
}

#[tokio::test]
async fn checkpoint_restore_rejects_unbound_or_unsupported_reference_before_context_allocation()
-> Result<(), Box<dyn Error>> {
    let driver = Arc::new(OptionsRecordingDriver::new(PageId::new()));
    let fixture = action_rpc_fixture(Arc::clone(&driver), Arc::new(ReadySandbox), 19085).await?;
    let calls = driver.calls.load(Ordering::Acquire);
    for bind_reference in [false, true] {
        let options = WorkerSessionOptionsV1 {
            checkpoint_ref: Some("opaque-checkpoint".to_owned()),
            ..session_options()
        };
        let hash = if bind_reference {
            options.canonical_request_hash(WorkerIsolationProfile::SharedContext)
        } else {
            session_options().canonical_request_hash(WorkerIsolationProfile::SharedContext)
        };
        let response = fixture
            .handler
            .handle(WorkerRpcRequest::CreateSession(
                WorkerCreateSessionRequest {
                    operation_id: OperationId::new(),
                    tenant_id: fixture.fence.tenant_id.clone(),
                    idempotency_key: format!("checkpoint-restore-{bind_reference}"),
                    canonical_request_hash: hash,
                    expected_worker_epoch: fixture.fence.worker_epoch,
                    placement_version: 1,
                    session_incarnation: 1,
                    requested_isolation: WorkerIsolationProfile::SharedContext,
                    options_version: WORKER_SESSION_OPTIONS_VERSION,
                    options,
                    now_unix_millis: 2,
                },
            ))
            .await;
        assert!(
            matches!(response,WorkerRpcResponse::Failure(failure) if failure.code==WorkerRpcFailureCode::InvalidRequest)
        );
        assert_eq!(driver.calls.load(Ordering::Acquire), calls);
    }
    Ok(())
}

#[tokio::test]
async fn invalid_secret_reference_is_rejected_before_action_registration()
-> Result<(), Box<dyn Error>> {
    let fixture = action_rpc_fixture(Arc::new(ReadyDriver), Arc::new(ReadySandbox), 19083).await?;
    for secret_ref in ["", " reference", "reference ", "ref\nerence"] {
        let id = ActionId::new();
        let mut request = submit_action_request(
            &fixture.fence,
            &fixture.primary_page_id,
            &id,
            1,
            "invalid-secret",
            3,
        );
        if let WorkerRpcRequest::SubmitAction { action, .. } = &mut request {
            *action = WorkerActionCommand::FillSecret {
                node_ref: "0000000000000001".to_owned(),
                secret_ref: secret_ref.to_owned(),
            };
        }
        assert!(
            matches!(fixture.handler.handle(request).await, WorkerRpcResponse::Failure(failure) if failure.code == WorkerRpcFailureCode::InvalidRequest)
        );
        assert!(
            matches!(fixture.handler.handle(WorkerRpcRequest::GetAction { fence:fixture.fence.clone(), action_id:id }).await, WorkerRpcResponse::Failure(failure) if failure.code == WorkerRpcFailureCode::NotFound)
        );
    }
    Ok(())
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
    let options = session_options();
    let response = handler
        .handle(WorkerRpcRequest::CreateSession(
            WorkerCreateSessionRequest {
                operation_id: OperationId::new(),
                tenant_id: TenantId::new(),
                idempotency_key: "create-stale".to_owned(),
                canonical_request_hash: options
                    .canonical_request_hash(WorkerIsolationProfile::SharedContext),
                expected_worker_epoch: 6,
                placement_version: 1,
                session_incarnation: 1,
                requested_isolation: WorkerIsolationProfile::SharedContext,
                options_version: WORKER_SESSION_OPTIONS_VERSION,
                options,
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
    let options = session_options();
    let created = handler
        .handle(WorkerRpcRequest::CreateSession(
            WorkerCreateSessionRequest {
                operation_id: OperationId::new(),
                tenant_id: tenant_id.clone(),
                idempotency_key: "create-tenant-fence".to_owned(),
                canonical_request_hash: options
                    .canonical_request_hash(WorkerIsolationProfile::SharedContext),
                expected_worker_epoch: 7,
                placement_version: 1,
                session_incarnation: 1,
                requested_isolation: WorkerIsolationProfile::SharedContext,
                options_version: WORKER_SESSION_OPTIONS_VERSION,
                options: options.clone(),
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
                canonical_request_hash: options
                    .canonical_request_hash(WorkerIsolationProfile::SharedContext),
                expected_worker_epoch: 7,
                placement_version: 1,
                session_incarnation: 1,
                requested_isolation: WorkerIsolationProfile::SharedContext,
                options_version: WORKER_SESSION_OPTIONS_VERSION,
                options: options.clone(),
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
                canonical_request_hash: options
                    .canonical_request_hash(WorkerIsolationProfile::SharedContext),
                expected_worker_epoch: 7,
                placement_version: 2,
                session_incarnation: 1,
                requested_isolation: WorkerIsolationProfile::SharedContext,
                options_version: WORKER_SESSION_OPTIONS_VERSION,
                options: options.clone(),
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
                canonical_request_hash: options
                    .canonical_request_hash(WorkerIsolationProfile::SharedContext),
                expected_worker_epoch: 7,
                placement_version: 2,
                session_incarnation: 1,
                requested_isolation: WorkerIsolationProfile::SharedContext,
                options_version: WORKER_SESSION_OPTIONS_VERSION,
                options: options.clone(),
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
                canonical_request_hash: options
                    .canonical_request_hash(WorkerIsolationProfile::DedicatedProcess),
                expected_worker_epoch: 7,
                placement_version: 2,
                session_incarnation: 1,
                requested_isolation: WorkerIsolationProfile::DedicatedProcess,
                options_version: WORKER_SESSION_OPTIONS_VERSION,
                options,
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
    let options = session_options();
    let created = handler
        .handle(WorkerRpcRequest::CreateSession(
            WorkerCreateSessionRequest {
                operation_id: OperationId::new(),
                tenant_id: tenant_id.clone(),
                idempotency_key: "create-approval".to_owned(),
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
    let requested_action_id = ActionId::new();
    let requested_action_sequence = ActionSequence::new(1);
    let submitted = handler
        .handle(WorkerRpcRequest::SubmitAction {
            fence: fence.clone(),
            action_id: requested_action_id.clone(),
            action_sequence: requested_action_sequence,
            requester_principal_id: PrincipalId::new(),
            idempotency_key: "pending-action".to_owned(),
            canonical_request_hash: [6; 32],
            kind: ActionKind::Mutating,
            page_id: Some(created.primary_page_id),
            action: WorkerActionCommand::Click {
                node_ref: "0000000000000001".to_owned(),
            },
            execution_timeout_ms: WorkerActionExecutionTimeout::DEFAULT,
            approval: Some(Box::new(WorkerActionApprovalRequirement {
                target_incarnation: 1,
                frame_document_epoch: 1,
                current_origin: "https://example.test".to_owned(),
                url_revision: 1,
                action_type: WorkerApprovalActionType::Click,
                node_ref: None,
                credential_refs: Vec::new(),
                require_four_eyes: true,
            })),
            now_unix_millis: 2,
        })
        .await;
    assert!(matches!(&submitted, WorkerRpcResponse::Action(_)));
    let WorkerRpcResponse::Action(submitted) = submitted else {
        return;
    };
    assert_eq!(submitted.fence, fence);
    assert_eq!(submitted.action_id, requested_action_id);
    assert_eq!(submitted.action_sequence, requested_action_sequence);
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_submit_action_rpc_rejects_before_accept_and_exact_retry_dispatches_once()
-> Result<(), Box<dyn Error>> {
    let execution_started = Arc::new(Barrier::new(2));
    let release_execution = Arc::new(Barrier::new(2));
    let driver = Arc::new(BlockingActionDriver::new(
        Arc::clone(&execution_started),
        Arc::clone(&release_execution),
    ));
    let fixture = action_rpc_fixture(Arc::clone(&driver), Arc::new(ReadySandbox), 19014).await?;
    let first_action_id = ActionId::new();
    let second_action_id = ActionId::new();
    let first_request = submit_action_request(
        &fixture.fence,
        &fixture.primary_page_id,
        &first_action_id,
        1,
        "serialized-first",
        11,
    );
    let second_request = submit_action_request(
        &fixture.fence,
        &fixture.primary_page_id,
        &second_action_id,
        2,
        "serialized-second",
        12,
    );

    let first_handler = Arc::clone(&fixture.handler);
    let first_task = tokio::spawn(async move { first_handler.handle(first_request).await });
    let _ = execution_started.wait();

    let second_call_started = Arc::new(Barrier::new(2));
    let (second_completed_tx, second_completed_rx) = std::sync::mpsc::channel();
    let second_handler = Arc::clone(&fixture.handler);
    let second_started = Arc::clone(&second_call_started);
    let retry_request = second_request.clone();
    let second_task = tokio::spawn(async move {
        let _ = second_started.wait();
        let response = second_handler.handle(second_request).await;
        let _ = second_completed_tx.send(response.clone());
        response
    });
    let _ = second_call_started.wait();
    let early_second = second_completed_rx.recv_timeout(Duration::from_millis(250));
    let prematurely_admitted = fixture.worker.get_action(
        &fixture.peer,
        &fixture.fence.session_id,
        &second_action_id,
        &fixture.ownership,
    );

    let _ = release_execution.wait();
    let first_response = first_task.await?;
    let second_response = second_task.await?;

    assert!(matches!(
        early_second,
        Ok(WorkerRpcResponse::Failure(failure))
            if failure.code == WorkerRpcFailureCode::Capacity
    ));
    assert!(matches!(
        prematurely_admitted,
        Err(WorkerError::ActionNotFound)
    ));
    let WorkerRpcResponse::Action(first_receipt) = first_response else {
        return Err(std::io::Error::other("first concurrent action RPC did not succeed").into());
    };
    assert!(matches!(
        second_response,
        WorkerRpcResponse::Failure(failure)
            if failure.code == WorkerRpcFailureCode::Capacity
    ));
    assert_eq!(first_receipt.action_id, first_action_id);
    assert_eq!(first_receipt.action_sequence, ActionSequence::new(1));
    assert_eq!(first_receipt.status, WorkerActionStatus::Succeeded);
    let retry = fixture.handler.handle(retry_request).await;
    assert!(matches!(
        retry,
        WorkerRpcResponse::Action(receipt)
            if receipt.action_id == second_action_id
                && receipt.action_sequence == ActionSequence::new(2)
                && receipt.status == WorkerActionStatus::Succeeded
    ));
    assert_eq!(driver.execution_count.load(Ordering::Acquire), 2);
    Ok(())
}

#[tokio::test]
async fn gateway_forward_action_sequence_gap_is_accepted_without_poisoning_the_session_lane()
-> Result<(), Box<dyn Error>> {
    let fixture = action_rpc_fixture(Arc::new(ReadyDriver), Arc::new(ReadySandbox), 19015).await?;
    let first_action_id = ActionId::new();
    let second_action_id = ActionId::new();
    let first_request = submit_action_request(
        &fixture.fence,
        &fixture.primary_page_id,
        &first_action_id,
        2,
        "gateway-forward-gap",
        21,
    );
    let second_request = submit_action_request(
        &fixture.fence,
        &fixture.primary_page_id,
        &second_action_id,
        3,
        "gateway-after-gap",
        22,
    );

    let first = fixture.handler.handle(first_request.clone()).await;
    let second = fixture.handler.handle(second_request).await;
    let retry = fixture.handler.handle(first_request).await;

    assert!(matches!(
        first,
        WorkerRpcResponse::Action(receipt)
            if receipt.action_id == first_action_id
                && receipt.action_sequence == ActionSequence::new(2)
                && receipt.status == WorkerActionStatus::Succeeded
    ));
    assert!(matches!(
        second,
        WorkerRpcResponse::Action(receipt)
            if receipt.action_id == second_action_id
                && receipt.action_sequence == ActionSequence::new(3)
                && receipt.status == WorkerActionStatus::Succeeded
    ));
    assert!(matches!(
        retry,
        WorkerRpcResponse::Action(receipt)
            if receipt.action_id == first_action_id
                && receipt.action_sequence == ActionSequence::new(2)
                && receipt.status == WorkerActionStatus::Succeeded
    ));
    Ok(())
}

#[tokio::test]
async fn create_session_rpc_negotiates_isolation_against_worker_capability()
-> Result<(), Box<dyn Error>> {
    let fixture = action_rpc_fixture(
        Arc::new(DedicatedProcessDriver),
        Arc::new(ReadySandbox),
        19071,
    )
    .await?;
    let tenant_id = fixture.fence.tenant_id.clone();
    let options = session_options();

    // A request for exactly the isolation the worker provides is accepted, and the effective
    // placement is reported back (BRD-001) rather than rejected as "not implemented".
    let accepted = fixture
        .handler
        .handle(WorkerRpcRequest::CreateSession(
            WorkerCreateSessionRequest {
                operation_id: OperationId::new(),
                tenant_id: tenant_id.clone(),
                idempotency_key: "isolation-dedicated-process".to_owned(),
                canonical_request_hash: options
                    .canonical_request_hash(WorkerIsolationProfile::DedicatedProcess),
                expected_worker_epoch: fixture.fence.worker_epoch,
                placement_version: 1,
                session_incarnation: 1,
                requested_isolation: WorkerIsolationProfile::DedicatedProcess,
                options_version: WORKER_SESSION_OPTIONS_VERSION,
                options: options.clone(),
                now_unix_millis: 10,
            },
        ))
        .await;
    let WorkerRpcResponse::SessionCreated(receipt) = accepted else {
        return Err("a request matching the worker's isolation must be accepted".into());
    };
    assert_eq!(
        receipt.effective_isolation,
        WorkerIsolationProfile::DedicatedProcess
    );

    // A request for isolation stronger than the worker can deliver is rejected before any effect.
    let rejected = fixture
        .handler
        .handle(WorkerRpcRequest::CreateSession(
            WorkerCreateSessionRequest {
                operation_id: OperationId::new(),
                tenant_id,
                idempotency_key: "isolation-dedicated-worker".to_owned(),
                canonical_request_hash: options
                    .canonical_request_hash(WorkerIsolationProfile::DedicatedWorker),
                expected_worker_epoch: fixture.fence.worker_epoch,
                placement_version: 1,
                session_incarnation: 1,
                requested_isolation: WorkerIsolationProfile::DedicatedWorker,
                options_version: WORKER_SESSION_OPTIONS_VERSION,
                options,
                now_unix_millis: 11,
            },
        ))
        .await;
    assert!(matches!(
        rejected,
        WorkerRpcResponse::Failure(failure)
            if failure.code == WorkerRpcFailureCode::InvalidRequest
    ));
    Ok(())
}

#[tokio::test]
async fn create_receipt_uses_per_session_placement_and_exact_retry_preserves_it()
-> Result<(), Box<dyn Error>> {
    let mut driver = OptionsRecordingDriver::new(PageId::new());
    driver.placement = Some(WorkerIsolationProfile::TenantDedicatedShard);
    let driver = Arc::new(driver);
    let fixture = action_rpc_fixture(Arc::clone(&driver), Arc::new(ReadySandbox), 19074).await?;
    assert_eq!(
        fixture
            .worker
            .session_effective_isolation(
                &fixture.peer,
                &fixture.fence.session_id,
                &fixture.ownership,
            )
            .map_err(|_| "effective session isolation lookup failed")?,
        WorkerIsolationProfile::TenantDedicatedShard
    );
    let options = session_options();
    let request = WorkerCreateSessionRequest {
        operation_id: OperationId::new(),
        tenant_id: fixture.fence.tenant_id.clone(),
        idempotency_key: "session-placement-retry".to_owned(),
        canonical_request_hash: options
            .canonical_request_hash(WorkerIsolationProfile::SharedContext),
        expected_worker_epoch: 7,
        placement_version: 2,
        session_incarnation: 1,
        requested_isolation: WorkerIsolationProfile::SharedContext,
        options_version: WORKER_SESSION_OPTIONS_VERSION,
        options,
        now_unix_millis: 2,
    };
    let first = fixture
        .handler
        .handle(WorkerRpcRequest::CreateSession(request.clone()))
        .await;
    let second = fixture
        .handler
        .handle(WorkerRpcRequest::CreateSession(request))
        .await;
    let (WorkerRpcResponse::SessionCreated(first), WorkerRpcResponse::SessionCreated(second)) =
        (first, second)
    else {
        return Err("per-session placement must be returned".into());
    };
    assert_eq!(first.session_id, second.session_id);
    assert_eq!(
        first.effective_isolation,
        WorkerIsolationProfile::TenantDedicatedShard
    );
    assert_eq!(first.effective_isolation, second.effective_isolation);
    assert_eq!(driver.calls.load(Ordering::SeqCst), 2);
    let foreign = OwnershipFence::new(fixture.ownership.worker_id().clone(), 7, 99, 1);
    assert!(
        fixture
            .worker
            .session_effective_isolation(&fixture.peer, &fixture.fence.session_id, &foreign)
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn weaker_actual_placement_is_cleaned_before_ready_and_never_reported()
-> Result<(), Box<dyn Error>> {
    let mut driver = OptionsRecordingDriver::new(PageId::new());
    driver.placement = Some(WorkerIsolationProfile::SharedContext);
    let driver = Arc::new(driver);
    let fixture = action_rpc_fixture(Arc::clone(&driver), Arc::new(ReadySandbox), 19075).await?;
    let options = session_options();
    let response = fixture
        .handler
        .handle(WorkerRpcRequest::CreateSession(
            WorkerCreateSessionRequest {
                operation_id: OperationId::new(),
                tenant_id: fixture.fence.tenant_id.clone(),
                idempotency_key: "weaker-placement".to_owned(),
                canonical_request_hash: options
                    .canonical_request_hash(WorkerIsolationProfile::DedicatedProcess),
                expected_worker_epoch: 7,
                placement_version: 2,
                session_incarnation: 1,
                requested_isolation: WorkerIsolationProfile::DedicatedProcess,
                options_version: WORKER_SESSION_OPTIONS_VERSION,
                options,
                now_unix_millis: 2,
            },
        ))
        .await;
    assert!(matches!(response, WorkerRpcResponse::Failure(_)));
    assert_eq!(driver.calls.load(Ordering::SeqCst), 2);
    assert_eq!(driver.closed.load(Ordering::SeqCst), 1);
    assert_eq!(
        fixture
            .worker
            .session_effective_isolation(
                &fixture.peer,
                &fixture.fence.session_id,
                &fixture.ownership
            )
            .map_err(|_| "effective session isolation lookup failed")?,
        WorkerIsolationProfile::SharedContext
    );
    Ok(())
}

#[tokio::test]
async fn create_session_rpc_rejects_unsupported_options_before_allocation()
-> Result<(), Box<dyn Error>> {
    // A worker that supports only the single-host option set must reject a create carrying an
    // unsupported option with a precise, non-opaque failure before touching any resource
    // (BRD-022). The fixture already declares single-host option support.
    let driver = Arc::new(OptionsRecordingDriver::new(PageId::new()));
    let fixture = action_rpc_fixture(Arc::clone(&driver), Arc::new(ReadySandbox), 19081).await?;
    let calls_after_fixture = driver.calls.load(Ordering::Acquire);

    let unsupported = WorkerSessionOptionsV1 {
        feature_profile: "privileged".to_owned(),
        ..session_options()
    };
    let response = fixture
        .handler
        .handle(WorkerRpcRequest::CreateSession(
            WorkerCreateSessionRequest {
                operation_id: OperationId::new(),
                tenant_id: fixture.fence.tenant_id.clone(),
                idempotency_key: "unsupported-feature-profile".to_owned(),
                canonical_request_hash: unsupported
                    .canonical_request_hash(WorkerIsolationProfile::SharedContext),
                expected_worker_epoch: fixture.fence.worker_epoch,
                placement_version: 1,
                session_incarnation: 1,
                requested_isolation: WorkerIsolationProfile::SharedContext,
                options_version: WORKER_SESSION_OPTIONS_VERSION,
                options: unsupported,
                now_unix_millis: 5,
            },
        ))
        .await;

    assert!(matches!(
        response,
        WorkerRpcResponse::Failure(failure)
            if failure.code == WorkerRpcFailureCode::InvalidRequest
    ));
    // The unsupported request was rejected before the driver was asked to allocate a context.
    assert_eq!(driver.calls.load(Ordering::Acquire), calls_after_fixture);
    Ok(())
}
