use super::*;
use browserd_api::{DurableApiRouter, SessionCreateRequest};
use browserd_coordination::{
    CoordinationActorConfig, CoordinationBlockingClient, MemoryCreateSessionStore,
    MemorySafetyAuthority, SafetyActorIdentity, SafetyAuthorityBlockingClient,
    SafetyInitializeRequest, SafetyMutationRequest,
};
use browserd_core::{IsolationProfile, SafetySwitchMutation};

#[derive(Clone)]
struct AcceptedCreate {
    request: WorkerCreateSessionRequest,
    receipt: WorkerCreateSessionReceipt,
}

impl AcceptedCreate {
    fn matches(&self, request: &WorkerCreateSessionRequest) -> bool {
        self.request.operation_id == request.operation_id
            && self.request.tenant_id == request.tenant_id
            && self.request.idempotency_key == request.idempotency_key
            && self.request.canonical_request_hash == request.canonical_request_hash
            && self.request.expected_worker_epoch == request.expected_worker_epoch
            && self.request.placement_version == request.placement_version
            && self.request.session_incarnation == request.session_incarnation
            && self.request.requested_isolation == request.requested_isolation
            && self.request.options_version == request.options_version
            && self.request.options == request.options
        // now_unix_millis is the attempt clock, not part of the immutable operation binding.
    }
}

/// Exercises the worker's immutable receipt recovery without starting Chromium.
struct NoBrowser {
    safety: SafetyAuthorityBlockingClient,
    accepted: Mutex<Option<AcceptedCreate>>,
    attempts: Mutex<Vec<WorkerCreateSessionRequest>>,
    creates: AtomicUsize,
    action_effects: AtomicUsize,
}

fn rejected(code: WorkerRpcFailureCode) -> WorkerRpcError {
    WorkerRpcError::Remote(WorkerRpcFailure::new(
        code,
        "no-browser worker rejected create",
    ))
}

impl GatewayWorkerClient for NoBrowser {
    type PendingAction = ImmediatePending;

    fn create_session(
        &self,
        request: WorkerCreateSessionRequest,
    ) -> Result<WorkerCreateSessionReceipt, WorkerRpcError> {
        self.attempts.lock().unwrap().push(request.clone());
        if !request.is_valid() {
            return Err(rejected(WorkerRpcFailureCode::InvalidRequest));
        }
        let mut accepted = self.accepted.lock().unwrap();
        if let Some(original) = accepted.as_ref()
            && original.request.tenant_id == request.tenant_id
            && original.request.idempotency_key == request.idempotency_key
        {
            if !original.matches(&request) {
                return Err(rejected(WorkerRpcFailureCode::Conflict));
            }
            let mut receipt = original.receipt.clone();
            receipt.existing = true;
            return Ok(receipt);
        }
        // As in Worker RPC, an exact completed binding is recovered before new effect admission.
        let authority = self
            .safety
            .read()
            .map_err(|_| rejected(WorkerRpcFailureCode::NotReady))?;
        let snapshot = authority.snapshot();
        if snapshot.network_class_stopped(&request.options.network_class)
            || (request.options.checkpoint_ref.is_some() && snapshot.checkpoint_disabled())
        {
            return Err(rejected(WorkerRpcFailureCode::NotReady));
        }
        let requested = match request.requested_isolation {
            WorkerIsolationProfile::SharedContext => IsolationProfile::SharedContext,
            WorkerIsolationProfile::TenantDedicatedShard => IsolationProfile::TenantDedicatedShard,
            WorkerIsolationProfile::DedicatedProcess => IsolationProfile::DedicatedProcess,
            WorkerIsolationProfile::DedicatedWorker => IsolationProfile::DedicatedWorker,
        };
        let effective_isolation = match snapshot.effective_isolation(requested) {
            IsolationProfile::SharedContext => WorkerIsolationProfile::SharedContext,
            IsolationProfile::TenantDedicatedShard => WorkerIsolationProfile::TenantDedicatedShard,
            IsolationProfile::DedicatedProcess => WorkerIsolationProfile::DedicatedProcess,
            IsolationProfile::DedicatedWorker => WorkerIsolationProfile::DedicatedWorker,
        };
        let receipt =
            WorkerCreateSessionReceipt {
                operation_id: request.operation_id.clone(),
                tenant_id: request.tenant_id.clone(),
                session_id: SessionId::new(),
                session_incarnation: request.session_incarnation,
                effective_isolation,
                primary_page_id: PageId::new(),
                worker_epoch: request.expected_worker_epoch,
                placement_version: request.placement_version,
                existing: false,
                restored_checkpoint: request.options.checkpoint_ref.as_ref().map(
                    |checkpoint_ref| browserd_worker::WorkerCheckpointRestoreReceipt {
                        checkpoint_ref: checkpoint_ref.clone(),
                        source_session_id: SessionId::new(),
                    },
                ),
            };
        assert_eq!(self.creates.fetch_add(1, Ordering::SeqCst), 0);
        *accepted = Some(AcceptedCreate { request, receipt });
        // The effect and immutable receipt have committed, but the first response is lost.
        Err(WorkerRpcError::Timeout)
    }

    fn request(&self, _: WorkerRpcRequest) -> Result<WorkerRpcResponse, WorkerRpcError> {
        self.action_effects.fetch_add(1, Ordering::SeqCst);
        Err(WorkerRpcError::InvalidRequest)
    }

    fn enqueue_action(
        &self,
        request: WorkerRpcRequest,
    ) -> Result<Self::PendingAction, WorkerRpcEnqueueError> {
        Ok(ImmediatePending(self.request(request)))
    }
}

struct Fixture {
    principal: AuthenticatedPrincipal,
    safety: SafetyAuthorityBlockingClient,
    coordination: CoordinationBlockingClient,
    worker: Arc<NoBrowser>,
    body: SessionCreateRequest,
    key: String,
}

impl Fixture {
    fn new(checkpoint: bool) -> Result<Self, Box<dyn Error>> {
        let principal = authenticated_principal_with_scopes(
            TenantId::new(),
            &["session:create", "session:read", "checkpoint:read"],
        )?;
        let safety = SafetyAuthorityBlockingClient::spawn(
            Arc::new(MemorySafetyAuthority::default()),
            Self::actor_config(),
        )?;
        safety.initialize(SafetyInitializeRequest::new(
            SafetyActorIdentity::new(principal.tenant_id().clone(), "singlehost-safety-operator")?,
            Uuid::new_v4(),
            "initialize conservative singlehost safety",
        )?)?;
        let mut body = decode_session_create(CREATE_JSON)?;
        if checkpoint {
            body.checkpoint_ref = Some("opaque-checkpoint".to_owned());
        }
        Ok(Self {
            principal,
            coordination: CoordinationBlockingClient::spawn(
                Arc::new(MemoryCreateSessionStore::default()),
                Self::actor_config(),
            )?,
            worker: Arc::new(NoBrowser {
                safety: safety.clone(),
                accepted: Mutex::new(None),
                attempts: Mutex::new(Vec::new()),
                creates: AtomicUsize::new(0),
                action_effects: AtomicUsize::new(0),
            }),
            safety,
            body,
            key: Uuid::new_v4().to_string(),
        })
    }

    fn actor_config() -> CoordinationActorConfig {
        CoordinationActorConfig::new(64, 8, Duration::from_secs(2), Duration::from_secs(2)).unwrap()
    }

    fn router(&self) -> Result<DurableApiRouter<GatewayWorkerRuntime<NoBrowser>>, Box<dyn Error>> {
        Ok(DurableApiRouter::with_dispatch_lease_duration(
            Arc::new(
                GatewayWorkerRuntime::new(Arc::clone(&self.worker), gateway_placement()?)?
                    .with_runtime_safety(self.safety.clone()),
            ),
            self.coordination.clone(),
            Duration::from_millis(150),
        )?)
    }

    fn request(&self, key: &str) -> ApiRequest {
        ApiRequest::CreateSession {
            body: self.body.clone(),
            idempotency_key: key.to_owned(),
            received_at: Instant::now(),
        }
    }

    fn lose_reply(&self) -> Result<AcceptedCreate, Box<dyn Error>> {
        let error = self
            .router()?
            .execute(&self.principal, self.request(&self.key))
            .expect_err("the committed worker receipt's first response is lost");
        assert_eq!(error.code(), ErrorCode::WorkerUnavailable);
        let original = self.worker.accepted.lock().unwrap().clone().unwrap();
        assert!(original.request.is_valid());
        assert_eq!(
            original.request.requested_isolation,
            WorkerIsolationProfile::SharedContext
        );
        assert_eq!(
            original.receipt.effective_isolation,
            WorkerIsolationProfile::DedicatedProcess
        );
        let persisted = self
            .coordination
            .get(self.principal.tenant_id(), &original.request.operation_id)?
            .unwrap();
        assert_eq!(persisted.state(), CreateOperationState::Creating);
        assert_eq!(
            persisted.intent().canonical_request(),
            &serde_json::to_value(&self.body)?
        );
        assert_eq!(
            persisted.request_hash().as_bytes(),
            original.request.canonical_request_hash
        );
        assert_eq!(self.worker.creates.load(Ordering::SeqCst), 1);
        Ok(original)
    }

    fn mutate(&self, mutation: SafetySwitchMutation) -> Result<(), Box<dyn Error>> {
        self.safety.mutate(SafetyMutationRequest::new(
            SafetyActorIdentity::new(
                self.principal.tenant_id().clone(),
                "singlehost-safety-operator",
            )?,
            Uuid::new_v4(),
            self.safety.read()?.snapshot().version(),
            mutation,
            "change runtime safety after the create response was lost",
        )?)?;
        Ok(())
    }

    fn recover(&self, original: &AcceptedCreate) -> Result<(), Box<dyn Error>> {
        thread::sleep(Duration::from_millis(200));
        // A fresh Gateway recovers the same durable operation and worker receipt.
        let ApiResponse::SessionCreate(recovered) = self
            .router()?
            .execute(&self.principal, self.request(&self.key))?
        else {
            return Err("unexpected recovered create response".into());
        };
        let operation = recovered.data().operation();
        assert_eq!(operation.id(), &original.request.operation_id);
        assert_eq!(operation.state(), CreateOperationState::Succeeded);
        let session = operation.session().unwrap();
        assert_eq!(session.id, original.receipt.session_id);
        assert_eq!(session.requested_isolation, IsolationProfile::SharedContext);
        assert_eq!(
            session.effective_isolation,
            IsolationProfile::DedicatedProcess
        );
        if let Some(restored) = &original.receipt.restored_checkpoint {
            assert_eq!(
                session.metadata.get("restored_from_checkpoint"),
                Some(&restored.checkpoint_ref)
            );
            assert_eq!(
                session.metadata.get("recovered_from_session"),
                Some(&restored.source_session_id.to_string())
            );
        }
        let attempts = self.worker.attempts.lock().unwrap();
        assert_eq!(attempts.len(), 2);
        assert!(attempts.iter().all(|request| original.matches(request)));
        assert_eq!(self.worker.creates.load(Ordering::SeqCst), 1);
        assert_eq!(self.worker.action_effects.load(Ordering::SeqCst), 0);
        Ok(())
    }

    fn assert_new_create_denied(&self) -> Result<(), Box<dyn Error>> {
        let ApiResponse::SessionCreate(denied) = self
            .router()?
            .execute(&self.principal, self.request(&Uuid::new_v4().to_string()))?
        else {
            return Err("unexpected denied create response".into());
        };
        assert_eq!(
            denied.data().operation().state(),
            CreateOperationState::Failed
        );
        assert!(denied.data().operation().session().is_none());
        assert_eq!(self.worker.attempts.lock().unwrap().len(), 3);
        assert_eq!(self.worker.creates.load(Ordering::SeqCst), 1);
        assert_eq!(self.worker.action_effects.load(Ordering::SeqCst), 0);
        Ok(())
    }
}

#[test]
fn singlehost_lost_create_reply_recovers_immutable_request_after_safety_floor_relaxes()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new(false)?;
    let original = fixture.lose_reply()?;
    fixture.mutate(SafetySwitchMutation::SetForceDedicatedProcess(false))?;
    fixture.mutate(SafetySwitchMutation::SetMaxContextsPerShard(8))?;
    assert_eq!(
        fixture
            .safety
            .read()?
            .snapshot()
            .effective_isolation(IsolationProfile::SharedContext),
        IsolationProfile::SharedContext
    );
    fixture.recover(&original)
}

#[test]
fn singlehost_lost_create_reply_recovers_before_current_network_class_denial()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new(false)?;
    let original = fixture.lose_reply()?;
    fixture.mutate(SafetySwitchMutation::SetStoppedNetworkClass {
        network_class: "public".to_owned(),
        stopped: true,
    })?;
    fixture.recover(&original)?;
    fixture.assert_new_create_denied()
}

#[test]
fn singlehost_lost_checkpoint_restore_reply_recovers_before_current_checkpoint_denial()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new(true)?;
    let original = fixture.lose_reply()?;
    fixture.mutate(SafetySwitchMutation::DisableCheckpoint(true))?;
    fixture.recover(&original)?;
    fixture.assert_new_create_denied()
}
