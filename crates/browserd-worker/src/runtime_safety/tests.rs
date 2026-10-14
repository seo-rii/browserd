use super::*;
use crate::*;
use browserd_core::{PageId, PrincipalId, SafetySwitchMutation, SessionId};
use browserd_policy::{CanonicalActionProposal, Origin};
use browserd_sandbox::CleanupReason;
use browserd_session::{LeasePolicy, SessionTime, SessionTimeoutPolicy};
use std::os::unix::fs::PermissionsExt;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

type Hook = Arc<dyn Fn() + Send + Sync>;
#[derive(Default)]
struct Driver {
    creates: AtomicUsize,
    closes: AtomicUsize,
    weak: AtomicBool,
    requested: Mutex<Vec<WorkerIsolationProfile>>,
    created_hook: Mutex<Option<Hook>>,
}
impl ChromiumDriver for Driver {
    fn qualify(&self) -> Result<(), DependencyError> {
        Ok(())
    }
    fn supports_requested_isolation(&self, requested: WorkerIsolationProfile) -> bool {
        requested != WorkerIsolationProfile::DedicatedWorker
    }
    fn create_context(&self, _: &SessionId) -> Result<PageId, DependencyError> {
        Err(DependencyError::Rejected)
    }
    fn create_context_owned_with_placement(
        &self,
        _: &TenantId,
        _: &SessionId,
        _: &OwnershipFence,
        _: Option<&WorkerSessionOptionsV1>,
        requested: WorkerIsolationProfile,
    ) -> Result<CreatedSessionContext, DependencyError> {
        self.creates.fetch_add(1, Ordering::AcqRel);
        self.requested.lock().expect("requested").push(requested);
        if let Some(hook) = self.created_hook.lock().expect("hook").take() {
            hook();
        }
        Ok(CreatedSessionContext {
            primary_page_id: PageId::new(),
            effective_isolation: if self.weak.load(Ordering::Acquire) {
                WorkerIsolationProfile::SharedContext
            } else {
                requested
            },
        })
    }
    fn close_context(&self, _: &SessionId) -> Result<(), DependencyError> {
        self.closes.fetch_add(1, Ordering::AcqRel);
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
        ActionExecutionResult::OutcomeUnknown
    }
    fn inspect_approval_context(
        &self,
        _: &SessionId,
        _: &PageId,
        _: &CanonicalActionProposal,
    ) -> Result<LiveApprovalContext, DependencyError> {
        Ok(LiveApprovalContext {
            target_incarnation: 1,
            frame_document_epoch: 1,
            current_origin: Origin::parse("https://example.test").expect("origin"),
            url_revision: 1,
            node_ref: None,
            node_valid: true,
            resolved_ips: vec![],
            credential_refs: vec![],
            chromium_build: "17".repeat(32),
            effective_isolation: browserd_core::IsolationProfile::DedicatedProcess,
        })
    }
    fn execute_approved_action(
        &self,
        session: &SessionId,
        page: &PageId,
        payload: &[u8],
        proposal: &CanonicalActionProposal,
        inspected: &LiveApprovalContext,
        callback: &mut dyn FnMut(&LiveApprovalContext) -> Result<(), ApprovedActionError>,
    ) -> Result<ActionExecutionResult, ApprovedActionError> {
        let current = self
            .inspect_approval_context(session, page, proposal)
            .map_err(|_| ApprovedActionError::Unavailable)?;
        if let Some(reason) = inspected.stale_reason(&current) {
            return Err(ApprovedActionError::ApprovalStale(reason));
        }
        callback(&current)?;
        Ok(self.execute_action(session, Some(page), payload))
    }
    fn cancel_action(&self, _: &SessionId, _: &ActionId) -> Result<bool, DependencyError> {
        Ok(true)
    }
}
#[derive(Default)]
struct Sandbox {
    provisions: AtomicUsize,
    cleanups: AtomicUsize,
}
impl SandboxClient for Sandbox {
    fn qualify(&self) -> Result<(), DependencyError> {
        Ok(())
    }
    fn provision(&self, _: &SessionId, _: &OwnershipFence) -> Result<(), DependencyError> {
        self.provisions.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }
    fn cleanup(&self, _: &SessionId, _: CleanupReason) -> Result<(), DependencyError> {
        self.cleanups.fetch_add(1, Ordering::AcqRel);
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
struct Clock;
impl WorkerClock for Clock {
    fn now(&self) -> Result<SessionTime, WorkerError> {
        Ok(SessionTime::new(0))
    }
}
struct Fixture {
    worker: WorkerControlPlane<Driver, Sandbox>,
    driver: Arc<Driver>,
    sandbox: Arc<Sandbox>,
    peer: AuthenticatedPeer,
    _directory: tempfile::TempDir,
}
fn fixture(cache: Arc<RuntimeSafetyCache>) -> Fixture {
    fixture_with_admission(cache, None)
}
fn fixture_with_admission(
    cache: Arc<RuntimeSafetyCache>,
    admission: Option<WorkerAdmissionPolicy>,
) -> Fixture {
    let directory = tempfile::tempdir().expect("directory");
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
        .expect("private");
    let driver = Arc::new(Driver::default());
    let sandbox = Arc::new(Sandbox::default());
    let peer = AuthenticatedPeer::new("runtime-gateway").expect("peer");
    let mut config = WorkerConfig::new(
        WorkerId::new("runtime-worker").expect("worker"),
        3,
        InternalEndpoint::loopback("127.0.0.1:9105".parse().expect("address")).expect("endpoint"),
        peer.clone(),
        4,
        8,
        LeasePolicy::new(Duration::from_secs(30), Duration::from_secs(1)).expect("lease"),
        SessionTimeoutPolicy::new(Duration::from_secs(60), Duration::from_secs(30))
            .expect("timeouts"),
        Duration::from_secs(5),
        ActionJournalConfig::with_default_limits(directory.path()).expect("journal"),
    )
    .expect("config");
    if let Some(admission) = admission {
        config = config
            .with_fleet_admission_policy(admission)
            .expect("fleet admission");
    }
    let worker = WorkerControlPlane::new_with_clock(
        config,
        driver.clone(),
        sandbox.clone(),
        Arc::new(Clock),
    )
    .with_runtime_safety_cache(cache, "17".repeat(32))
    .expect("runtime builder");
    Fixture {
        worker,
        driver,
        sandbox,
        peer,
        _directory: directory,
    }
}
fn create(f: &Fixture) -> Result<CreateSessionOutcome, WorkerError> {
    f.worker.create_session(
        &f.peer,
        CreateSessionCommand {
            tenant_id: TenantId::new(),
            idempotency_key: PrincipalId::new().to_string(),
            canonical_request_hash: [1; 32],
            placement_version: 1,
            session_incarnation: 1,
        },
        SessionTime::new(0),
    )
}

fn runtime_options() -> WorkerSessionOptionsV1 {
    serde_json::from_value(serde_json::json!({
        "workload_class_hint": "interactive",
        "viewport": { "width": 1280, "height": 720, "device_scale_factor": 1 },
        "locale": "ko-KR",
        "timezone": "Asia/Seoul",
        "user_agent": null,
        "network_policy_id": "public-web-default",
        "network_class": "public",
        "checkpoint_ref": null,
        "dialog_policy": "auto_dismiss",
        "feature_profile": "standard",
        "ttl_seconds": 60,
        "idle_timeout_seconds": 30,
        "metadata": {}
    }))
    .expect("options")
}

#[test]
fn uninitialized_runtime_keeps_control_plane_bootstrap_and_positive_cleanup_available() {
    let cache = Arc::new(RuntimeSafetyCache::new());
    let f = fixture(cache.clone());
    assert!(f.worker.control_plane_qualified());
    assert!(!f.worker.is_ready());
    assert!(create(&f).is_err());
    assert_eq!(f.driver.creates.load(Ordering::Acquire), 0);
    assert_eq!(f.sandbox.provisions.load(Ordering::Acquire), 0);
    cache
        .install(
            uuid::Uuid::new_v4(),
            SafetySwitchSnapshot::default(),
            Duration::from_secs(30),
        )
        .expect("explicit authority init observed");
    assert!(f.worker.is_ready());
    let created = create(&f).expect("create");
    cache.invalidate().expect("observer unavailable");
    assert!(!f.worker.is_ready());
    f.worker
        .close_session(
            &f.peer,
            &created.session_id,
            &created.fence,
            SessionTime::new(1),
        )
        .expect("cleanup");
    assert_eq!(f.driver.closes.load(Ordering::Acquire), 1);
    assert_eq!(f.sandbox.cleanups.load(Ordering::Acquire), 1);
}
#[test]
fn cap_one_strengthens_real_driver_request_and_rejects_weaker_actual_placement() {
    let cache = Arc::new(RuntimeSafetyCache::new());
    cache
        .install(
            uuid::Uuid::new_v4(),
            SafetySwitchSnapshot::default()
                .apply(&SafetySwitchMutation::SetForceDedicatedProcess(false))
                .expect("cap1 intent"),
            Duration::from_secs(30),
        )
        .expect("install");
    let f = fixture(cache);
    f.driver.weak.store(true, Ordering::Release);
    assert!(create(&f).is_err());
    assert_eq!(
        *f.driver.requested.lock().expect("request"),
        vec![WorkerIsolationProfile::DedicatedProcess]
    );
    assert_eq!(f.driver.closes.load(Ordering::Acquire), 1);
    assert_eq!(f.sandbox.cleanups.load(Ordering::Acquire), 1);
    assert!(
        f.worker.is_ready(),
        "positively disposed rejected placement does not taint worker"
    );
}
#[test]
fn stopped_network_blocks_create_and_post_start_build_kill_prevents_ready_exposure() {
    let cache = Arc::new(RuntimeSafetyCache::new());
    let namespace = uuid::Uuid::new_v4();
    let initial = SafetySwitchSnapshot::default()
        .apply(&SafetySwitchMutation::SetStoppedNetworkClass {
            network_class: "public".to_owned(),
            stopped: true,
        })
        .expect("stop");
    cache
        .install(namespace, initial.clone(), Duration::from_secs(30))
        .expect("install");
    let f = fixture(cache.clone());
    assert!(create(&f).is_err());
    assert_eq!(f.driver.creates.load(Ordering::Acquire), 0);
    let enabled = initial
        .apply(&SafetySwitchMutation::SetStoppedNetworkClass {
            network_class: "public".to_owned(),
            stopped: false,
        })
        .expect("reopen");
    cache
        .install(namespace, enabled.clone(), Duration::from_secs(30))
        .expect("update");
    *f.driver.created_hook.lock().expect("hook") = Some(Arc::new(move || {
        cache
            .install(
                namespace,
                enabled
                    .apply(&SafetySwitchMutation::SetChromiumBuildDisabled {
                        digest: "17".repeat(32),
                        disabled: true,
                    })
                    .expect("kill build"),
                Duration::from_secs(30),
            )
            .expect("update during create");
    }));
    assert!(create(&f).is_err());
    assert_eq!(f.driver.creates.load(Ordering::Acquire), 1);
    assert_eq!(f.driver.closes.load(Ordering::Acquire), 1);
    assert_eq!(f.sandbox.cleanups.load(Ordering::Acquire), 1);
    assert!(!f.worker.is_ready());
}

#[tokio::test]
async fn bootstrap_capacity_rpc_serves_unready_and_old_shared_grant_cannot_upgrade_after_switch() {
    let cache = Arc::new(RuntimeSafetyCache::new());
    let namespace = uuid::Uuid::new_v4();
    let resources = ResourceVector::new(1, 1, 1, 1, 1, 1);
    let admission = WorkerAdmissionPolicy::new(
        [1; 32],
        resources,
        vec![WorkerAdmissionBudget {
            profile_digest: [2; 32],
            isolation: WorkerIsolationProfile::SharedContext,
            resources,
        }],
        8,
        None,
    )
    .expect("admission");
    let f = fixture_with_admission(cache.clone(), Some(admission));
    let worker = Arc::new(f.worker);
    let handler = WorkerControlPlaneRpcHandler::new(worker.clone(), f.peer.clone());
    let WorkerRpcResponse::Probe(unready_probe) = handler
        .handle(WorkerRpcRequest::Probe {
            expected_worker_epoch: 3,
        })
        .await
    else {
        panic!("authenticated structural probe before initialization");
    };
    assert!(!unready_probe.ready);
    assert_eq!(unready_probe.worker_epoch, 3);
    assert_eq!(
        unready_probe.worker_id,
        WorkerId::new("runtime-worker").expect("worker")
    );
    let WorkerRpcResponse::Capacity(unready) = handler
        .handle(WorkerRpcRequest::CapacityStatus {
            expected_worker_epoch: 3,
        })
        .await
    else {
        panic!("authenticated capacity metadata before initialization");
    };
    assert!(!unready.ready);
    assert_eq!(unready.worker_epoch, 3);
    assert!(worker.control_plane_qualified());
    let enabled = SafetySwitchSnapshot::default()
        .apply(&SafetySwitchMutation::SetForceDedicatedProcess(false))
        .expect("intent")
        .apply(&SafetySwitchMutation::SetMaxContextsPerShard(4))
        .expect("density");
    cache
        .install(namespace, enabled.clone(), Duration::from_secs(30))
        .expect("observe init");
    let WorkerRpcResponse::Probe(ready_probe) = handler
        .handle(WorkerRpcRequest::Probe {
            expected_worker_epoch: 3,
        })
        .await
    else {
        panic!("authenticated probe after observation");
    };
    assert!(ready_probe.ready);
    assert_eq!(ready_probe.worker_id, unready_probe.worker_id);
    assert_eq!(ready_probe.worker_epoch, unready_probe.worker_epoch);
    let options = runtime_options();
    let request = WorkerReservationRequest {
        request: WorkerCreateSessionRequest {
            operation_id: browserd_core::OperationId::new(),
            tenant_id: TenantId::new(),
            idempotency_key: "stored-shared-grant".to_owned(),
            canonical_request_hash: options
                .canonical_request_hash(WorkerIsolationProfile::SharedContext),
            expected_worker_epoch: 3,
            placement_version: 1,
            session_incarnation: 1,
            requested_isolation: WorkerIsolationProfile::SharedContext,
            options_version: WORKER_SESSION_OPTIONS_VERSION,
            options,
            now_unix_millis: 0,
        },
        reservation_id: browserd_core::LeaseId::new(),
        expected_worker_boot_nonce: unready.worker_boot_nonce,
        compatibility_digest: [1; 32],
        profile_digest: [2; 32],
        resources,
        ttl_millis: 30_000,
    };
    let reserved = worker
        .reserve_session(&f.peer, request.clone())
        .expect("original shared grant");
    cache
        .install(
            namespace,
            enabled
                .apply(&SafetySwitchMutation::SetForceDedicatedProcess(true))
                .expect("force"),
            Duration::from_secs(30),
        )
        .expect("update");
    let cancelled = worker
        .commit_reserved_session(&f.peer, &reserved.token)
        .expect("known no-exposure receipt");
    assert_eq!(cancelled.phase, WorkerReservationPhase::Cancelled);
    assert!(cancelled.session.is_none());
    assert_eq!(cancelled.token.request, request);
    assert_eq!(cancelled.capacity.raw_free, resources);
    assert_eq!(f.driver.creates.load(Ordering::Acquire), 0);
    assert_eq!(f.sandbox.provisions.load(Ordering::Acquire), 0);
}

#[tokio::test]
async fn canonical_shared_request_retains_dedicated_grant_across_relaxation_and_rpc_retries() {
    let cache = Arc::new(RuntimeSafetyCache::new());
    let namespace = uuid::Uuid::new_v4();
    let initial = SafetySwitchSnapshot::default();
    cache
        .install(namespace, initial.clone(), Duration::from_secs(30))
        .expect("dedicated safety floor");
    let shared_resources = ResourceVector::new(1, 1, 1, 1, 1, 1);
    let dedicated_resources = ResourceVector::new(3, 3, 3, 3, 1, 3);
    let admission = WorkerAdmissionPolicy::new(
        [1; 32],
        dedicated_resources,
        vec![
            WorkerAdmissionBudget {
                profile_digest: [2; 32],
                isolation: WorkerIsolationProfile::SharedContext,
                resources: shared_resources,
            },
            WorkerAdmissionBudget {
                profile_digest: [3; 32],
                isolation: WorkerIsolationProfile::DedicatedProcess,
                resources: dedicated_resources,
            },
        ],
        8,
        None,
    )
    .expect("immutable budgets");
    let f = fixture_with_admission(cache.clone(), Some(admission));
    let worker = Arc::new(f.worker);
    let handler = WorkerControlPlaneRpcHandler::new(worker, f.peer.clone());
    let WorkerRpcResponse::Capacity(capacity) = handler
        .handle(WorkerRpcRequest::CapacityStatus {
            expected_worker_epoch: 3,
        })
        .await
    else {
        panic!("capacity");
    };
    let options = runtime_options();
    let request = WorkerReservationRequest {
        request: WorkerCreateSessionRequest {
            operation_id: browserd_core::OperationId::new(),
            tenant_id: TenantId::new(),
            idempotency_key: "canonical-shared-dedicated-grant".to_owned(),
            canonical_request_hash: options
                .canonical_request_hash(WorkerIsolationProfile::SharedContext),
            expected_worker_epoch: 3,
            placement_version: 1,
            session_incarnation: 1,
            requested_isolation: WorkerIsolationProfile::SharedContext,
            options_version: WORKER_SESSION_OPTIONS_VERSION,
            options,
            now_unix_millis: 0,
        },
        reservation_id: browserd_core::LeaseId::new(),
        expected_worker_boot_nonce: capacity.worker_boot_nonce,
        compatibility_digest: [1; 32],
        profile_digest: [3; 32],
        resources: dedicated_resources,
        ttl_millis: 30_000,
    };
    let request: WorkerReservationRequest =
        serde_json::from_slice(&serde_json::to_vec(&request).expect("wire encoding"))
            .expect("wire decoding");
    assert!(request.request.is_valid());
    let mut undercharged = request.clone();
    undercharged.profile_digest = [2; 32];
    undercharged.resources = shared_resources;
    assert!(matches!(
        handler
            .handle(WorkerRpcRequest::ReserveSession(undercharged))
            .await,
        WorkerRpcResponse::Failure(WorkerRpcFailure {
            code: WorkerRpcFailureCode::InvalidRequest,
            ..
        })
    ));
    let WorkerRpcResponse::SessionReservation(reserved) = handler
        .handle(WorkerRpcRequest::ReserveSession(request.clone()))
        .await
    else {
        panic!("canonical original request admits its dedicated grant");
    };
    assert_eq!(reserved.token.request, request);
    assert_eq!(reserved.phase, WorkerReservationPhase::Reserved);
    assert_eq!(reserved.capacity.raw_free, ResourceVector::ZERO);
    let relaxed = initial
        .apply(&SafetySwitchMutation::SetForceDedicatedProcess(false))
        .expect("relax force")
        .apply(&SafetySwitchMutation::SetMaxContextsPerShard(4))
        .expect("relax floor");
    cache
        .install(namespace, relaxed, Duration::from_secs(30))
        .expect("observe relaxation before actual effect");
    let WorkerRpcResponse::SessionReservation(recovered) = handler
        .handle(WorkerRpcRequest::ReserveSession(request.clone()))
        .await
    else {
        panic!("exact reservation retry preserves accepted grant after relaxation");
    };
    assert_eq!(recovered.token, reserved.token);
    let WorkerRpcResponse::SessionReservation(created) = handler
        .handle(WorkerRpcRequest::CommitReservedSession(
            reserved.token.clone(),
        ))
        .await
    else {
        panic!("reserved create");
    };
    assert_eq!(created.phase, WorkerReservationPhase::Active);
    assert_eq!(created.token, reserved.token);
    let session = created.session.as_ref().expect("created session");
    assert_eq!(
        session.effective_isolation,
        WorkerIsolationProfile::DedicatedProcess
    );
    assert_eq!(
        *f.driver.requested.lock().expect("actual request"),
        vec![WorkerIsolationProfile::DedicatedProcess]
    );
    let WorkerRpcResponse::SessionReservation(retry) = handler
        .handle(WorkerRpcRequest::CommitReservedSession(
            reserved.token.clone(),
        ))
        .await
    else {
        panic!("lost response retry returns known receipt");
    };
    assert_eq!(retry.token.request, request);
    assert_eq!(retry.session, created.session);
    assert_eq!(retry.capacity.raw_free, ResourceVector::ZERO);
    assert_eq!(f.driver.creates.load(Ordering::Acquire), 1);
    assert_eq!(f.sandbox.provisions.load(Ordering::Acquire), 1);
}
