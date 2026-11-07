#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use super::*;
use browserd_core::{ActionId, SessionId};
use browserd_policy::EmergencyPolicy;
use browserd_worker::{PrivilegedEvaluateGrant, PrivilegedEvaluatePolicy, WorkerActionSnapshot};
use std::sync::atomic::AtomicU64;
use std::time::Instant;

const PAYLOAD: &[u8] = br#"{"type":"evaluate","expression":"globalThis.fixtureValue = 1"}"#;

pub(super) fn execute(
    driver: &FakeDriver,
    session_id: &SessionId,
    page_id: &PageId,
    payload: &[u8],
    deadline: Instant,
    authorize_and_commit: &mut dyn FnMut(&LiveApprovalContext) -> Result<(), ApprovedActionError>,
) -> Result<ActionExecutionResult, ApprovedActionError> {
    let hook = driver
        .evaluate_boundary
        .lock()
        .map_err(|_| ApprovedActionError::Unavailable)?
        .clone();
    if let Some(hook) = hook {
        hook();
    }
    let _gate = driver
        .approved_effect_gate
        .lock()
        .map_err(|_| ApprovedActionError::Unavailable)?;
    if Instant::now() >= deadline {
        return Err(ApprovedActionError::DeadlineBeforeDispatch);
    }
    let live = LiveApprovalContext {
        target_incarnation: 1,
        frame_document_epoch: 1,
        current_origin: Origin::parse("https://example.test").unwrap(),
        url_revision: 1,
        node_ref: None,
        node_valid: true,
        resolved_ips: vec![],
        credential_refs: vec![],
        chromium_build: "sha256:test".to_owned(),
        effective_isolation: IsolationProfile::SharedContext,
    };
    driver.evaluate_callbacks.fetch_add(1, Ordering::SeqCst);
    authorize_and_commit(&live)?;
    Ok(driver.execute_action(session_id, Some(page_id), payload))
}

#[derive(Default)]
struct Clock(AtomicU64);

impl WorkerClock for Clock {
    fn now(&self) -> Result<SessionTime, WorkerError> {
        Ok(SessionTime::new(self.0.load(Ordering::SeqCst)))
    }
}

#[derive(Clone, Copy)]
enum AuditMode {
    Missing,
    Healthy,
    Full,
}

struct Fixture {
    worker: Arc<WorkerControlPlane<FakeDriver, FakeSandbox>>,
    peer: AuthenticatedPeer,
    driver: Arc<FakeDriver>,
    tenant: TenantId,
    requester: PrincipalId,
    created: CreateSessionOutcome,
    clock: Arc<Clock>,
    emergency: Arc<EmergencyPolicy>,
    audit: Option<Arc<AuditWal>>,
    _audit_directory: tempfile::TempDir,
}

impl Fixture {
    fn new(profile: &str, requester_granted: bool, audit_mode: AuditMode) -> Self {
        Self::new_with_runtime(profile, requester_granted, audit_mode, None)
    }
    fn new_with_runtime(
        profile: &str,
        requester_granted: bool,
        audit_mode: AuditMode,
        runtime: Option<Arc<browserd_core::RuntimeSafetyCache>>,
    ) -> Self {
        let tenant = TenantId::new();
        let requester = PrincipalId::new();
        let policy = PrivilegedEvaluatePolicy::new(vec![PrivilegedEvaluateGrant {
            tenant_id: tenant.clone(),
            principal_id: if requester_granted {
                requester.clone()
            } else {
                PrincipalId::new()
            },
        }])
        .unwrap();
        let driver = Arc::new(FakeDriver {
            qualified: true,
            ..FakeDriver::default()
        });
        let sandbox = Arc::new(FakeSandbox {
            qualified: true,
            ..FakeSandbox::default()
        });
        let peer = AuthenticatedPeer::new("gateway-internal").unwrap();
        let clock = Arc::new(Clock::default());
        let emergency = Arc::new(EmergencyPolicy::default());
        let directory = tempfile::tempdir().unwrap();
        let audit = match audit_mode {
            AuditMode::Missing => None,
            AuditMode::Healthy | AuditMode::Full => {
                let capacity = if matches!(audit_mode, AuditMode::Full) {
                    512
                } else {
                    1 << 20
                };
                let record_limit = if matches!(audit_mode, AuditMode::Full) {
                    512
                } else {
                    4096
                };
                let audit = Arc::new(
                    AuditWal::open(
                        directory.path().join("audit.wal"),
                        AuditWalPolicy::new(capacity, record_limit).unwrap(),
                    )
                    .unwrap(),
                );
                if matches!(audit_mode, AuditMode::Full) {
                    let mut full = false;
                    for index in 0..100 {
                        match audit.append(AuditEvent::new(
                            AuditEventId::new(format!("fill-{index}")).unwrap(),
                            "filler",
                            vec![],
                            true,
                        )) {
                            Ok(_) => {}
                            Err(AuditWalError::FullCritical) => {
                                full = true;
                                break;
                            }
                            Err(error) => panic!("unexpected audit failure: {error:?}"),
                        }
                    }
                    assert!(full, "bounded audit fixture must reach capacity");
                }
                Some(audit)
            }
        };
        let mut worker = WorkerControlPlane::new_with_emergency_policy_and_clock(
            config(4).unwrap(),
            driver.clone(),
            sandbox,
            emergency.clone(),
            clock.clone(),
        )
        .with_privileged_evaluate_policy(policy);
        if let Some(audit) = &audit {
            worker = worker.with_audit_wal(audit.clone());
        }
        if let Some(runtime) = runtime {
            worker = worker
                .with_runtime_safety_cache(runtime, "17".repeat(32))
                .expect("runtime");
        }
        let created = worker
            .create_session_with_options(
                &peer,
                create_command(tenant.clone(), "privileged-fixture", 91),
                &session_options(profile),
                SessionTime::new(0),
            )
            .unwrap();
        Self {
            worker: Arc::new(worker),
            peer,
            driver,
            tenant,
            requester,
            created,
            clock,
            emergency,
            audit,
            _audit_directory: directory,
        }
    }

    fn submit(
        &self,
        key: &str,
        feature: Option<BuiltinFeature>,
        kind: ActionKind,
        approved: bool,
    ) -> Result<ActionId, WorkerError> {
        let submitted_at = SessionTime::new(1);
        let approval = approved.then(|| {
            ActionApprovalRequirement::new(
                CanonicalActionProposal::new(
                    self.tenant.clone(),
                    self.requester.clone(),
                    self.created.session_id.clone(),
                    self.created.fence.session_incarnation(),
                    self.created.primary_page_id.clone(),
                    1,
                    1,
                    Origin::parse("https://example.test").unwrap(),
                    1,
                    ActionType::Evaluate,
                    ActionArgumentsHash::digest(PAYLOAD),
                    None,
                    CredentialRefsHash::digest(std::iter::empty()),
                    submitted_at.get() + 100,
                ),
                ActionType::Evaluate,
                true,
            )
        });
        self.worker.submit_action(
            &self.peer,
            self.requester.clone(),
            &self.created.session_id,
            &self.created.fence,
            key,
            [92; 32],
            kind,
            feature,
            Some(self.created.primary_page_id.clone()),
            PAYLOAD.to_vec(),
            approval,
            submitted_at,
        )
    }

    fn queue(&self, key: &str) -> ActionId {
        self.submit(
            key,
            Some(BuiltinFeature::PrivilegedEvaluate),
            ActionKind::Mutating,
            false,
        )
        .unwrap()
    }

    fn run(&self, action: &ActionId) -> WorkerActionSnapshot {
        // Rejection may be returned as a policy error; the durable action snapshot is authoritative.
        let _ = self.worker.run_next_action(
            &self.peer,
            &self.created.session_id,
            &self.created.fence,
            SessionTime::new(3),
        );
        self.snapshot(action)
    }

    fn snapshot(&self, action: &ActionId) -> WorkerActionSnapshot {
        self.worker
            .get_action(
                &self.peer,
                &self.created.session_id,
                action,
                &self.created.fence,
            )
            .unwrap()
    }

    fn assert_no_effect(&self) {
        assert_eq!(self.driver.action_effects.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn privileged_creation_requires_enabled_policy_and_exact_tenant_before_provision() {
    for policy in [
        None,
        Some(PrivilegedEvaluatePolicy::new(vec![]).unwrap()),
        Some(
            PrivilegedEvaluatePolicy::new(vec![PrivilegedEvaluateGrant {
                tenant_id: TenantId::new(),
                principal_id: PrincipalId::new(),
            }])
            .unwrap(),
        ),
    ] {
        let (worker, peer, driver, sandbox) = ready_worker(1).unwrap();
        let worker = if let Some(policy) = policy {
            worker.with_privileged_evaluate_policy(policy)
        } else {
            worker
        };
        assert!(
            worker
                .create_session_with_options(
                    &peer,
                    create_command(TenantId::new(), "privileged-denied", 93),
                    &session_options("privileged"),
                    SessionTime::new(0),
                )
                .is_err()
        );
        assert_eq!(*sandbox.provision_count.lock().unwrap(), 0);
        assert_eq!(driver.action_effects.load(Ordering::SeqCst), 0);
        assert!(create_ready_session(&worker, &peer, "standard-remains-supported").is_some());
    }
}

#[test]
fn evaluate_denies_another_principal_in_the_same_tenant_and_standard_profile() {
    for (profile, grant) in [("privileged", false), ("standard", true)] {
        let fixture = Fixture::new(profile, grant, AuditMode::Healthy);
        let action = fixture.queue("denied");
        assert_eq!(fixture.run(&action).status, ActionStatus::FailedKnown);
        fixture.assert_no_effect();
        assert_eq!(fixture.driver.evaluate_callbacks.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn evaluate_cannot_bypass_admission_using_missing_or_wrong_feature_or_read_only_kind() {
    for (feature, kind) in [
        (None, ActionKind::Mutating),
        (Some(BuiltinFeature::CoreInput), ActionKind::Mutating),
        (
            Some(BuiltinFeature::PrivilegedEvaluate),
            ActionKind::ReadOnly,
        ),
    ] {
        let fixture = Fixture::new("privileged", true, AuditMode::Healthy);
        if let Ok(action) = fixture.submit("mismatched", feature, kind, false) {
            assert_eq!(fixture.run(&action).status, ActionStatus::FailedKnown);
        }
        fixture.assert_no_effect();
    }
}

#[test]
fn evaluate_requires_a_present_and_writable_audit_wal() {
    for mode in [AuditMode::Missing, AuditMode::Full] {
        let fixture = Fixture::new("privileged", true, mode);
        let action = fixture.queue("audit-denied");
        assert_eq!(fixture.run(&action).status, ActionStatus::FailedKnown);
        fixture.assert_no_effect();
        assert_eq!(fixture.driver.evaluate_callbacks.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn manual_approval_cannot_override_evaluate_policy_profile_or_missing_audit() {
    for (profile, grant, mode) in [
        ("privileged", false, AuditMode::Healthy),
        ("standard", true, AuditMode::Healthy),
        ("privileged", true, AuditMode::Missing),
        ("privileged", true, AuditMode::Full),
    ] {
        let fixture = Fixture::new(profile, grant, mode);
        let action = fixture
            .submit(
                "manual-denied",
                Some(BuiltinFeature::PrivilegedEvaluate),
                ActionKind::Mutating,
                true,
            )
            .unwrap();
        let approval_id = fixture
            .worker
            .approval_for_action(
                &fixture.peer,
                &fixture.created.session_id,
                &action,
                &fixture.created.fence,
            )
            .unwrap();
        let approved = fixture
            .worker
            .decide_approval(
                &fixture.peer,
                &fixture.created.session_id,
                &approval_id,
                &fixture.created.fence,
                ApprovalDecision::Approve,
                PrincipalId::new(),
                SessionTime::new(2),
            )
            .unwrap();
        assert_eq!(fixture.run(&action).status, ActionStatus::FailedKnown);
        assert_eq!(
            fixture
                .worker
                .get_approval(
                    &fixture.peer,
                    &fixture.created.session_id,
                    &approval_id,
                    &fixture.created.fence,
                )
                .unwrap(),
            approved
        );
        assert_eq!(fixture.driver.approved_callbacks.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.driver.evaluate_callbacks.load(Ordering::SeqCst), 0);
        fixture.assert_no_effect();
    }
}

#[test]
fn evaluate_waits_for_manual_approval_and_then_consumes_it_once() {
    let fixture = Fixture::new("privileged", true, AuditMode::Healthy);
    let action = fixture
        .submit(
            "pending",
            Some(BuiltinFeature::PrivilegedEvaluate),
            ActionKind::Mutating,
            true,
        )
        .unwrap();
    assert_eq!(fixture.run(&action).status, ActionStatus::PendingApproval);
    fixture.assert_no_effect();
    assert_eq!(fixture.driver.approved_callbacks.load(Ordering::SeqCst), 0);
    let approval = fixture
        .worker
        .approval_for_action(
            &fixture.peer,
            &fixture.created.session_id,
            &action,
            &fixture.created.fence,
        )
        .unwrap();
    fixture
        .worker
        .decide_approval(
            &fixture.peer,
            &fixture.created.session_id,
            &approval,
            &fixture.created.fence,
            ApprovalDecision::Approve,
            PrincipalId::new(),
            SessionTime::new(2),
        )
        .unwrap();
    assert_eq!(fixture.run(&action).status, ActionStatus::Succeeded);
    assert_eq!(fixture.run(&action).status, ActionStatus::Succeeded);
    assert_eq!(fixture.driver.approved_callbacks.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.driver.action_effects.load(Ordering::SeqCst), 1);
}

#[test]
fn evaluate_requires_the_complete_current_ownership_fence() {
    let fixture = Fixture::new("privileged", true, AuditMode::Healthy);
    let action = fixture.queue("fenced");
    let current = &fixture.created.fence;
    for fence in [
        OwnershipFence::new(
            WorkerId::new("another-worker").unwrap(),
            current.worker_epoch(),
            current.placement_version(),
            current.session_incarnation(),
        ),
        OwnershipFence::new(
            current.worker_id().clone(),
            current.worker_epoch() + 1,
            current.placement_version(),
            current.session_incarnation(),
        ),
        OwnershipFence::new(
            current.worker_id().clone(),
            current.worker_epoch(),
            current.placement_version() + 1,
            current.session_incarnation(),
        ),
        OwnershipFence::new(
            current.worker_id().clone(),
            current.worker_epoch(),
            current.placement_version(),
            current.session_incarnation() + 1,
        ),
    ] {
        assert_eq!(
            fixture.worker.run_next_action(
                &fixture.peer,
                &fixture.created.session_id,
                &fence,
                SessionTime::new(2),
            ),
            Err(WorkerError::StaleFence)
        );
        assert_eq!(fixture.snapshot(&action).status, ActionStatus::Queued);
        fixture.assert_no_effect();
    }
    assert_eq!(fixture.driver.evaluate_callbacks.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.run(&action).status, ActionStatus::Succeeded);
}

pub(super) fn assert_success_and_idempotency() {
    let fixture = Fixture::new("privileged", true, AuditMode::Healthy);
    let audit = fixture.audit.clone().unwrap();
    *fixture.driver.evaluate_boundary.lock().unwrap() = Some(Arc::new(move || {
        assert!(
            audit
                .pending()
                .unwrap()
                .iter()
                .any(|pending| pending.event().kind() == "browser.evaluate.dispatch"),
            "privileged audit must be durable before the effect"
        );
    }));
    fixture
        .driver
        .executions
        .lock()
        .unwrap()
        .push_back(ActionExecutionResult::Succeeded(br#"{"value":1}"#.to_vec()));
    let action = fixture.queue("success");
    let result = fixture.run(&action);
    assert_eq!(result.status, ActionStatus::Succeeded);
    assert_eq!(result.result.as_deref(), Some(br#"{"value":1}"#.as_slice()));
    assert_eq!(fixture.queue("success"), action);
    assert_eq!(fixture.run(&action), result);
    assert_eq!(fixture.driver.action_effects.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.driver.evaluate_callbacks.load(Ordering::SeqCst), 1);
}

#[test]
fn evaluate_rechecks_lease_at_the_last_dispatch_boundary() {
    let fixture = Fixture::new("privileged", true, AuditMode::Healthy);
    let clock = fixture.clock.clone();
    *fixture.driver.evaluate_boundary.lock().unwrap() = Some(Arc::new(move || {
        clock.0.store(100, Ordering::SeqCst);
    }));
    let action = fixture.queue("expired");
    assert_eq!(fixture.run(&action).status, ActionStatus::FailedKnown);
    assert_eq!(fixture.driver.evaluate_callbacks.load(Ordering::SeqCst), 1);
    fixture.assert_no_effect();
}

#[test]
fn evaluate_rechecks_emergency_denials_at_the_last_dispatch_boundary() {
    for mode in 0..4 {
        let fixture = Fixture::new("privileged", true, AuditMode::Healthy);
        let emergency = fixture.emergency.clone();
        let tenant = fixture.tenant.clone();
        let session = fixture.created.session_id.clone();
        *fixture.driver.evaluate_boundary.lock().unwrap() = Some(Arc::new(move || {
            match mode {
                0 => emergency.disable_tenant(tenant.clone()),
                1 => emergency.disable_session(session.clone()),
                2 => emergency.deny_feature("browser:evaluate"),
                _ => emergency.deny_domain("example.test"),
            }
            .unwrap();
        }));
        let action = fixture.queue("emergency");
        assert_eq!(fixture.run(&action).status, ActionStatus::FailedKnown);
        assert_eq!(fixture.driver.evaluate_callbacks.load(Ordering::SeqCst), 1);
        fixture.assert_no_effect();
    }
}

#[test]
fn evaluate_cancel_before_authorization_never_reaches_the_browser() {
    let fixture = Fixture::new("privileged", true, AuditMode::Healthy);
    let action = fixture.queue("cancel");
    let worker = Arc::downgrade(&fixture.worker);
    let peer = fixture.peer.clone();
    let session = fixture.created.session_id.clone();
    let fence = fixture.created.fence.clone();
    let cancelled_action = action.clone();
    let (cancel_observed_tx, cancel_observed_rx) = std::sync::mpsc::channel();
    *fixture.driver.evaluate_cancel_observed.lock().unwrap() = Some(cancel_observed_tx);
    let cancel_observed_rx = Mutex::new(cancel_observed_rx);
    let cancellation = Arc::new(Mutex::new(None));
    let cancellation_handle = cancellation.clone();
    *fixture.driver.evaluate_boundary.lock().unwrap() = Some(Arc::new(move || {
        let worker = worker.upgrade().unwrap();
        let peer = peer.clone();
        let session = session.clone();
        let action = cancelled_action.clone();
        let fence = fence.clone();
        *cancellation_handle.lock().unwrap() = Some(thread::spawn(move || {
            worker.cancel_action(&peer, &session, &action, &fence, SessionTime::new(4))
        }));
        cancel_observed_rx
            .lock()
            .unwrap()
            .recv_timeout(Duration::from_secs(5))
            .expect("cancellation must reach the driver before evaluate admission resumes");
    }));
    let _ = fixture.run(&action);
    let cancelled = cancellation
        .lock()
        .unwrap()
        .take()
        .unwrap()
        .join()
        .unwrap()
        .unwrap();
    assert!(matches!(
        cancelled.status,
        ActionStatus::FailedKnown | ActionStatus::CancelledConfirmed
    ));
    let result = fixture.snapshot(&action);
    assert!(matches!(
        result.status,
        ActionStatus::FailedKnown | ActionStatus::CancelledConfirmed
    ));
    assert_eq!(fixture.queue("cancel"), action);
    assert_eq!(fixture.run(&action), result);
    fixture.assert_no_effect();
}

#[test]
fn evaluate_unknown_outcome_is_not_replayed_on_idempotent_retry() {
    let fixture = Fixture::new("privileged", true, AuditMode::Healthy);
    fixture
        .driver
        .executions
        .lock()
        .unwrap()
        .push_back(ActionExecutionResult::OutcomeUnknown);
    let action = fixture.queue("unknown");
    assert_eq!(fixture.run(&action).status, ActionStatus::OutcomeUnknown);
    assert_eq!(fixture.queue("unknown"), action);
    assert_eq!(fixture.run(&action).status, ActionStatus::OutcomeUnknown);
    assert_eq!(fixture.driver.action_effects.load(Ordering::SeqCst), 1);
}

#[test]
fn runtime_evaluate_switch_is_rechecked_at_real_driver_effect_boundary() {
    use browserd_core::{RuntimeSafetyCache, SafetySwitchMutation, SafetySwitchSnapshot};
    let cache = Arc::new(RuntimeSafetyCache::new());
    let namespace = *browserd_core::SessionId::new().as_uuid();
    let snapshot = SafetySwitchSnapshot::default()
        .apply(&SafetySwitchMutation::SetForceDedicatedProcess(false))
        .expect("intent")
        .apply(&SafetySwitchMutation::SetMaxContextsPerShard(4))
        .expect("density")
        .apply(&SafetySwitchMutation::DisableEvaluate(false))
        .expect("enable evaluate");
    cache
        .install(namespace, snapshot.clone(), Duration::from_secs(30))
        .expect("authority");
    let fixture =
        Fixture::new_with_runtime("privileged", true, AuditMode::Healthy, Some(cache.clone()));
    let action = fixture.queue("runtime-evaluate");
    *fixture.driver.evaluate_boundary.lock().expect("hook") = Some(Arc::new(move || {
        cache
            .install(
                namespace,
                snapshot
                    .apply(&SafetySwitchMutation::DisableEvaluate(true))
                    .expect("disable"),
                Duration::from_secs(30),
            )
            .expect("before callback");
    }));
    assert_eq!(fixture.run(&action).status, ActionStatus::FailedKnown);
    assert_eq!(fixture.driver.evaluate_callbacks.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.driver.action_effects.load(Ordering::SeqCst), 0);
}
