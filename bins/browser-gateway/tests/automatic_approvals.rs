#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};

use browser_gateway::{
    GatewayWorkerClient, GatewayWorkerPending, GatewayWorkerPlacement, GatewayWorkerRuntime,
};
use browserd_actions::{ActionJournalLimits, ActionSnapshot};
use browserd_api::{
    ActionGetRequest, ActionPayload, ActionSubmitCommand, ActionSubmitRequest, ApiRequest,
    ApiResponse, ApiRouter, ApiService, ApprovalDecisionBody, ApprovalDecisionRequest,
    ApprovalListQuery, ApprovalResource, decode_session_create,
};
use browserd_auth::{
    AuthConfig, AuthenticatedPrincipal, RevocationRegistry, ServiceClaims, ServiceTokenSigner,
    ServiceTokenVerifier, VerificationKeySet,
};
use browserd_core::{
    ActionId, ActionState, IsolationProfile, PageId, PrincipalId, SessionId, TenantId, WorkerId,
};
use browserd_observability::{AuditWal, AuditWalPolicy};
use browserd_policy::{
    ActionApprovalGrant, ActionApprovalOutcome, ActionApprovalPolicy, ApprovalActionKind,
    ApprovalContextScope, ApprovalNodeBinding, CanonicalActionProposal, Origin,
};
use browserd_sandbox::CleanupReason;
use browserd_session::{LeasePolicy, OwnershipFence, SessionTimeoutPolicy};
use browserd_worker::{
    ActionExecutionResult, ActionJournalConfig, ApprovedActionError, ArtifactStoreReceipt,
    ArtifactStoreRequest, AuthenticatedPeer, ChromiumDriver, DependencyError, InternalEndpoint,
    LiveApprovalContext, SandboxClient, TypedApprovalObservation, WorkerActionCommand,
    WorkerControlPlane, WorkerControlPlaneRpcHandler, WorkerCreateSessionReceipt,
    WorkerCreateSessionRequest, WorkerRpcCompletionError, WorkerRpcEnqueueError, WorkerRpcError,
    WorkerRpcHandler, WorkerRpcRequest, WorkerRpcResponse,
};
use jsonwebtoken::Algorithm;
use uuid::Uuid;

struct Driver {
    page: PageId,
    effects: AtomicUsize,
}
impl ChromiumDriver for Driver {
    fn qualify(&self) -> Result<(), DependencyError> {
        Ok(())
    }
    fn create_context(&self, _: &SessionId) -> Result<PageId, DependencyError> {
        Ok(self.page.clone())
    }
    fn create_context_owned_with_options(
        &self,
        _: &TenantId,
        session: &SessionId,
        _: &OwnershipFence,
        _: &browserd_worker::WorkerSessionOptionsV1,
    ) -> Result<PageId, DependencyError> {
        self.create_context(session)
    }
    fn close_context(&self, _: &SessionId) -> Result<(), DependencyError> {
        Ok(())
    }
    fn create_page(&self, _: &SessionId) -> Result<PageId, DependencyError> {
        Ok(PageId::new())
    }
    fn close_page(&self, _: &SessionId, _: &PageId) -> Result<(), DependencyError> {
        Ok(())
    }
    fn activate_page(&self, _: &SessionId, _: &PageId) -> Result<(), DependencyError> {
        Ok(())
    }
    fn execute_action(&self, _: &SessionId, _: Option<&PageId>, _: &[u8]) -> ActionExecutionResult {
        panic!("policy must use guarded typed dispatch")
    }
    fn inspect_approval_context(
        &self,
        _: &SessionId,
        _: &PageId,
        _: &CanonicalActionProposal,
    ) -> Result<LiveApprovalContext, DependencyError> {
        panic!("typed inspection required")
    }
    fn execute_approved_action(
        &self,
        _: &SessionId,
        _: &PageId,
        _: &[u8],
        _: &CanonicalActionProposal,
        _: &LiveApprovalContext,
        _: &mut dyn FnMut(&LiveApprovalContext) -> Result<(), ApprovedActionError>,
    ) -> Result<ActionExecutionResult, ApprovedActionError> {
        panic!("typed dispatch required")
    }
    fn cancel_action(&self, _: &SessionId, _: &ActionId) -> Result<bool, DependencyError> {
        Ok(true)
    }
    fn inspect_typed_approval_until(
        &self,
        tenant: &TenantId,
        session: &SessionId,
        page: Option<&PageId>,
        fence: &OwnershipFence,
        action: &WorkerActionCommand,
        _: Instant,
    ) -> Result<TypedApprovalObservation, ApprovedActionError> {
        assert_eq!(page, Some(&self.page));
        let WorkerActionCommand::Fill { node_ref, .. } = action else {
            panic!("unexpected command")
        };
        Ok(TypedApprovalObservation {
            tenant_id: tenant.clone(),
            session_id: session.clone(),
            page_id: page.cloned(),
            fence: fence.clone(),
            context_scope: ApprovalContextScope::HttpOrigin {
                origin: "https://review.test".to_owned(),
            },
            target_binding_sha256: [2; 32],
            node_binding: Some(ApprovalNodeBinding {
                node_ref: node_ref.clone(),
                binding_sha256: [3; 32],
                role: None,
                name: None,
            }),
            build_identity_sha256: [4; 32],
            live: LiveApprovalContext {
                target_incarnation: 2,
                frame_document_epoch: 3,
                current_origin: Origin::parse("https://review.test").unwrap(),
                url_revision: 4,
                node_ref: Some(browserd_policy::NodeReference::new(node_ref).unwrap()),
                node_valid: true,
                resolved_ips: vec![],
                credential_refs: vec![],
                chromium_build: "sha256:fixture".to_owned(),
                effective_isolation: IsolationProfile::SharedContext,
            },
        })
    }
    fn execute_typed_browser_until(
        &self,
        expected: &TypedApprovalObservation,
        _: &[u8],
        _: Instant,
        authorize: &mut dyn FnMut(&TypedApprovalObservation) -> Result<(), ApprovedActionError>,
    ) -> Result<ActionExecutionResult, ApprovedActionError> {
        authorize(expected)?;
        self.effects.fetch_add(1, Ordering::SeqCst);
        Ok(ActionExecutionResult::Succeeded(b"ok".to_vec()))
    }
}
struct Sandbox;
impl SandboxClient for Sandbox {
    fn qualify(&self) -> Result<(), DependencyError> {
        Ok(())
    }
    fn provision(&self, _: &SessionId, _: &OwnershipFence) -> Result<(), DependencyError> {
        Ok(())
    }
    fn cleanup(&self, _: &SessionId, _: CleanupReason) -> Result<(), DependencyError> {
        Ok(())
    }
    fn heartbeat(&self, _: &WorkerId, _: u64) -> Result<(), DependencyError> {
        Ok(())
    }
    fn store_artifact(
        &self,
        _: &ArtifactStoreRequest,
    ) -> Result<ArtifactStoreReceipt, DependencyError> {
        Err(DependencyError::Rejected)
    }
}
struct Pending(Result<WorkerRpcResponse, WorkerRpcError>);
impl GatewayWorkerPending for Pending {
    fn wait(self) -> Result<WorkerRpcResponse, WorkerRpcCompletionError> {
        self.0.map_err(WorkerRpcCompletionError::Exchange)
    }
}
struct Client {
    runtime: tokio::runtime::Runtime,
    handler: Arc<dyn WorkerRpcHandler>,
    submissions: AtomicUsize,
    decisions: AtomicUsize,
    corrupt_worker: AtomicBool,
}
impl GatewayWorkerClient for Client {
    type PendingAction = Pending;
    fn create_session(
        &self,
        request: WorkerCreateSessionRequest,
    ) -> Result<WorkerCreateSessionReceipt, WorkerRpcError> {
        match self.request(WorkerRpcRequest::CreateSession(request))? {
            WorkerRpcResponse::SessionCreated(receipt) => Ok(receipt),
            WorkerRpcResponse::Failure(failure) => Err(WorkerRpcError::Remote(failure)),
            _ => Err(WorkerRpcError::Protocol),
        }
    }
    fn enqueue_action(&self, request: WorkerRpcRequest) -> Result<Pending, WorkerRpcEnqueueError> {
        Ok(Pending(self.request(request)))
    }
    fn request(&self, request: WorkerRpcRequest) -> Result<WorkerRpcResponse, WorkerRpcError> {
        if let WorkerRpcRequest::SubmitAction { approval, .. } = &request {
            assert!(
                approval.is_none(),
                "the public caller must not author the policy proposal"
            );
            self.submissions.fetch_add(1, Ordering::SeqCst);
        }
        if matches!(request, WorkerRpcRequest::DecideApproval { .. }) {
            self.decisions.fetch_add(1, Ordering::SeqCst);
        }
        let request = serde_json::from_slice(&serde_json::to_vec(&request).unwrap()).unwrap();
        let mut response = self.runtime.block_on(self.handler.handle(request));
        if self.corrupt_worker.load(Ordering::SeqCst)
            && let WorkerRpcResponse::Approval(receipt) = &mut response
        {
            receipt
                .proposal
                .typed_binding
                .as_mut()
                .unwrap()
                .fence
                .worker_id = WorkerId::new("foreign-worker").unwrap();
            receipt.proposal_hash = *receipt.proposal.to_canonical().unwrap().hash().as_bytes();
        }
        Ok(serde_json::from_slice(&serde_json::to_vec(&response).unwrap()).unwrap())
    }
}

fn principal(tenant: &TenantId, id: PrincipalId, scopes: &[&str]) -> AuthenticatedPrincipal {
    let mut keys = VerificationKeySet::new();
    keys.insert_hmac("test", Algorithm::HS256, b"public-approval-test")
        .unwrap();
    let verifier = ServiceTokenVerifier::new(
        AuthConfig::new("issuer", "audience", [Algorithm::HS256], 0, false),
        keys,
        RevocationRegistry::new(),
    );
    let claims = ServiceClaims::new(
        "issuer",
        "audience",
        id,
        tenant.clone(),
        scopes.iter().map(|v| (*v).to_owned()).collect(),
        Uuid::new_v4().to_string(),
        1,
        100,
        None,
    );
    let signed = ServiceTokenSigner::new("test", Algorithm::HS256, b"public-approval-test")
        .sign(&claims)
        .unwrap();
    verifier.verify_at(&signed, None, 10).unwrap()
}
struct Fixture {
    requester: AuthenticatedPrincipal,
    decider: AuthenticatedPrincipal,
    router: ApiRouter<GatewayWorkerRuntime<Client>>,
    driver: Arc<Driver>,
    client: Arc<Client>,
    session: SessionId,
    key: Uuid,
    _journal: tempfile::TempDir,
}
impl Fixture {
    fn new(grant: Option<(ActionApprovalOutcome, &str)>) -> Self {
        let tenant = TenantId::new();
        let requester = principal(
            &tenant,
            PrincipalId::new(),
            &[
                "session:create",
                "session:read",
                "browser:act",
                "approval:read",
                "approval:decide",
            ],
        );
        let decider = principal(
            &tenant,
            PrincipalId::new(),
            &["approval:read", "approval:decide"],
        );
        let policy = match grant {
            None => ActionApprovalPolicy::default(),
            Some((outcome, origin)) => ActionApprovalPolicy::new(vec![ActionApprovalGrant {
                tenant_id: tenant.clone(),
                principal_id: requester.principal_id().clone(),
                action: ApprovalActionKind::Fill,
                context_scope: ApprovalContextScope::HttpOrigin {
                    origin: origin.to_owned(),
                },
                navigation_destination: None,
                outcome,
                require_four_eyes: true,
            }])
            .unwrap(),
        };
        let journal = tempfile::tempdir().unwrap();
        std::fs::create_dir(journal.path().join("actions")).unwrap();
        let peer = AuthenticatedPeer::new("approval-gateway").unwrap();
        let worker_id = WorkerId::new("approval-worker").unwrap();
        let config = browserd_worker::WorkerConfig::new(
            worker_id.clone(),
            7,
            InternalEndpoint::loopback("127.0.0.1:9022".parse().unwrap()).unwrap(),
            peer.clone(),
            2,
            8,
            LeasePolicy::new(Duration::from_secs(30), Duration::from_secs(1)).unwrap(),
            SessionTimeoutPolicy::new(Duration::from_secs(60), Duration::from_secs(30)).unwrap(),
            Duration::from_secs(5),
            ActionJournalConfig::new(
                journal.path().join("actions"),
                ActionJournalLimits::default(),
            )
            .unwrap(),
        )
        .unwrap();
        let audit = Arc::new(
            AuditWal::open(
                journal.path().join("audit.wal"),
                AuditWalPolicy::new(1 << 20, 16 * 1024).unwrap(),
            )
            .unwrap(),
        );
        let driver = Arc::new(Driver {
            page: PageId::new(),
            effects: AtomicUsize::new(0),
        });
        let worker = Arc::new(
            WorkerControlPlane::new(config, driver.clone(), Arc::new(Sandbox))
                .with_audit_wal(audit)
                .with_action_approval_policy(policy),
        );
        let client = Arc::new(Client {
            runtime: tokio::runtime::Runtime::new().unwrap(),
            handler: Arc::new(WorkerControlPlaneRpcHandler::new(worker, peer)),
            submissions: AtomicUsize::new(0),
            decisions: AtomicUsize::new(0),
            corrupt_worker: AtomicBool::new(false),
        });
        let router = ApiRouter::new(Arc::new(
            GatewayWorkerRuntime::new(
                client.clone(),
                GatewayWorkerPlacement::new(worker_id, 7, 3, 1).unwrap(),
            )
            .unwrap(),
        ));
        let response = router.execute(&requester, ApiRequest::CreateSession {
            body: decode_session_create(r#"{"isolation":"shared_context","workload_class_hint":"interactive","viewport":{"width":1280,"height":720,"device_scale_factor":1},"locale":"en-US","timezone":"UTC","user_agent":null,"network_policy_id":"public-web-default","network_class":"public","checkpoint_ref":null,"dialog_policy":"auto_dismiss","feature_profile":"standard","ttl_seconds":60,"idle_timeout_seconds":30,"metadata":{}}"#).unwrap(),
            idempotency_key: Uuid::new_v4().to_string(), received_at: Instant::now(),
        }).unwrap();
        let ApiResponse::SessionCreate(response) = response else {
            panic!("create response")
        };
        let session = response.data().operation().session().unwrap().id.clone();
        Self {
            requester,
            decider,
            router,
            driver,
            client,
            session,
            key: Uuid::new_v4(),
            _journal: journal,
        }
    }
    fn submit(&self) -> ActionSnapshot {
        let response = self
            .router
            .execute(
                &self.requester,
                ApiRequest::SubmitAction(ActionSubmitCommand {
                    session_id: self.session.clone(),
                    idempotency_key: self.key,
                    body: ActionSubmitRequest {
                        page_id: self.driver.page.clone(),
                        if_session_incarnation: 1,
                        execution_timeout_ms: 30_000,
                        action: ActionPayload::Fill {
                            node_ref: "opaque-node".to_owned(),
                            value: "private-fill-value".to_owned(),
                        },
                    },
                }),
            )
            .unwrap();
        let ApiResponse::Action(response) = response else {
            panic!("action response")
        };
        response.data().clone()
    }
    fn approvals(&self) -> Vec<ApprovalResource> {
        let response = self
            .router
            .execute(
                &self.requester,
                ApiRequest::ListApprovals(ApprovalListQuery {
                    session_id: Some(self.session.clone()),
                    ..ApprovalListQuery::default()
                }),
            )
            .unwrap();
        let ApiResponse::Approvals(response) = response else {
            panic!("approval list")
        };
        response.data().items().to_vec()
    }
    fn decide(
        &self,
        by: &AuthenticatedPrincipal,
        id: Uuid,
        decision: ApprovalDecisionRequest,
    ) -> Result<ApiResponse, browserd_api::ApiError> {
        self.router.execute(
            by,
            ApiRequest::DecideApproval {
                approval_id: id,
                body: ApprovalDecisionBody {
                    decision,
                    reason: "operator reviewed safe summary".to_owned(),
                },
            },
        )
    }
    fn action(&self, id: &ActionId) -> ActionSnapshot {
        let ApiResponse::Action(response) = self
            .router
            .execute(
                &self.requester,
                ApiRequest::GetAction(ActionGetRequest {
                    session_id: self.session.clone(),
                    action_id: id.clone(),
                }),
            )
            .unwrap()
        else {
            panic!("action read")
        };
        response.data().clone()
    }
}

#[test]
fn public_submit_generates_reviewable_policy_approval_then_executes_once() {
    let f = Fixture::new(None);
    let pending = f.submit();
    assert_eq!(pending.state(), ActionState::PendingApproval);
    assert_eq!(f.driver.effects.load(Ordering::SeqCst), 0);
    let approvals = f.approvals();
    assert_eq!(approvals.len(), 1);
    let approval = &approvals[0];
    assert_eq!(&approval.action_id, pending.action_id());
    let ApiResponse::Approval(read) = f
        .router
        .execute(&f.decider, ApiRequest::GetApproval(approval.approval_id))
        .unwrap()
    else {
        panic!("approval read")
    };
    let summary = serde_json::to_value(read.data().summary()).unwrap();
    assert_eq!(summary["action_kind"], "fill");
    assert_eq!(summary["context"]["origin"], "https://review.test");
    assert_eq!(summary["node_ref"], "opaque-node");
    assert!(summary["policy_digest"].is_string());
    assert!(!summary.to_string().contains("private-fill-value"));
    assert!(
        f.decide(
            &f.requester,
            approval.approval_id,
            ApprovalDecisionRequest::Approve
        )
        .is_err(),
        "four-eyes rule remains enforced"
    );
    assert_eq!(f.driver.effects.load(Ordering::SeqCst), 0);
    let no_scope = principal(
        f.requester.tenant_id(),
        PrincipalId::new(),
        &["approval:read"],
    );
    let before = f.client.decisions.load(Ordering::SeqCst);
    assert!(
        f.decide(
            &no_scope,
            approval.approval_id,
            ApprovalDecisionRequest::Approve
        )
        .is_err()
    );
    assert_eq!(
        f.client.decisions.load(Ordering::SeqCst),
        before,
        "scope rejected before RPC"
    );
    f.decide(
        &f.decider,
        approval.approval_id,
        ApprovalDecisionRequest::Approve,
    )
    .unwrap();
    assert_eq!(
        f.action(pending.action_id()).state(),
        ActionState::Succeeded
    );
    assert_eq!(f.submit().action_id(), pending.action_id());
    assert_eq!(f.driver.effects.load(Ordering::SeqCst), 1);
    assert_eq!(f.client.submissions.load(Ordering::SeqCst), 1);
}

#[test]
fn denying_public_policy_approval_prevents_effect_and_replay() {
    let f = Fixture::new(None);
    let pending = f.submit();
    let approval = f.approvals().remove(0);
    f.decide(
        &f.decider,
        approval.approval_id,
        ApprovalDecisionRequest::Deny,
    )
    .unwrap();
    assert_eq!(
        f.action(pending.action_id()).state(),
        ActionState::FailedKnown
    );
    assert_eq!(f.submit().action_id(), pending.action_id());
    assert_eq!(f.driver.effects.load(Ordering::SeqCst), 0);
    assert_eq!(f.client.submissions.load(Ordering::SeqCst), 1);
}

#[test]
fn public_policy_grants_are_exact_and_deny_never_dispatches() {
    for (outcome, origin, expected, effects) in [
        (
            ActionApprovalOutcome::Allow,
            "https://review.test",
            ActionState::Succeeded,
            1,
        ),
        (
            ActionApprovalOutcome::Allow,
            "https://other.test",
            ActionState::PendingApproval,
            0,
        ),
        (
            ActionApprovalOutcome::Deny,
            "https://review.test",
            ActionState::FailedKnown,
            0,
        ),
    ] {
        let f = Fixture::new(Some((outcome, origin)));
        let action = f.submit();
        assert_eq!(action.state(), expected);
        assert_eq!(f.driver.effects.load(Ordering::SeqCst), effects);
        assert_eq!(
            f.approvals().len(),
            usize::from(expected == ActionState::PendingApproval)
        );
    }
}

#[test]
fn approval_read_rejects_a_validly_hashed_proposal_from_another_worker() {
    let f = Fixture::new(None);
    f.submit();
    let approval = f.approvals().remove(0);
    f.client.corrupt_worker.store(true, Ordering::SeqCst);
    assert!(
        f.router
            .execute(&f.decider, ApiRequest::GetApproval(approval.approval_id))
            .is_err()
    );
    assert_eq!(f.driver.effects.load(Ordering::SeqCst), 0);
}
