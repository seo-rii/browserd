#![allow(clippy::expect_used)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use browserd_actions::{
    ActionJournalLimits, ActionKind, ActionLedger, FileActionJournal, LedgerSession,
};
use browserd_core::{
    ActionId, ActionState, IsolationProfile, PageId, PrincipalId, SessionId, TenantId, WorkerId,
};
use browserd_policy::{
    ActionArgumentsHash, ActionType, ApprovalDecision, ApprovalError, CanonicalActionProposal,
    CredentialRefsHash, EmergencyDenyReason, EmergencyPolicy, Origin, StaleApprovalReason,
};
use browserd_sandbox::CleanupReason;
use browserd_session::{LeasePolicy, OwnershipFence, SessionTime, SessionTimeoutPolicy};
use browserd_worker::{
    ActionApprovalRequirement, ActionExecutionResult, ActionJournalConfig, ApprovedActionError,
    ArtifactUpload, AuthenticatedPeer, ChromiumDriver, CreateSessionCommand, DependencyError,
    InternalEndpoint, LiveApprovalContext, SandboxClient, WorkerClock, WorkerConfig,
    WorkerControlPlane, WorkerError,
};
use sha2::{Digest, Sha256};

#[derive(Default)]
struct Driver {
    executions: AtomicUsize,
    cancellation_attempts: AtomicUsize,
    approved_effect_occurred: AtomicBool,
    skip_authorization_callback: AtomicBool,
    invoke_authorization_callback_twice: AtomicBool,
    ignore_authorization_error: AtomicBool,
    confirm_cancellation_without_driver_serialization: AtomicBool,
    live_context: Mutex<Option<LiveApprovalContext>>,
    invalidate_after_inspection: std::sync::atomic::AtomicBool,
    pre_authorization_failure: Mutex<Option<ApprovedActionError>>,
    approved_failure: Mutex<Option<ApprovedActionError>>,
    inspection_barriers: Mutex<Option<(Arc<Barrier>, Arc<Barrier>)>>,
    authorization_barriers: Mutex<Option<(Arc<Barrier>, Arc<Barrier>)>>,
    effect_start_barriers: Mutex<Option<(Arc<Barrier>, Arc<Barrier>)>>,
    page_create_barriers: Mutex<Option<(Arc<Barrier>, Arc<Barrier>)>>,
    page_activation_barriers: Mutex<Option<(Arc<Barrier>, Arc<Barrier>)>>,
    page_close_barriers: Mutex<Option<(Arc<Barrier>, Arc<Barrier>)>>,
    approved_effect_gate: Mutex<()>,
}

impl ChromiumDriver for Driver {
    fn qualify(&self) -> Result<(), DependencyError> {
        Ok(())
    }

    fn create_context(&self, _session_id: &SessionId) -> Result<PageId, DependencyError> {
        Ok(PageId::new())
    }

    fn close_context(&self, _session_id: &SessionId) -> Result<(), DependencyError> {
        let _gate = self
            .approved_effect_gate
            .lock()
            .map_err(|_| DependencyError::Unavailable)?;
        Ok(())
    }

    fn create_page(&self, _session_id: &SessionId) -> Result<PageId, DependencyError> {
        let barriers = self
            .page_create_barriers
            .lock()
            .map_err(|_| DependencyError::Unavailable)?
            .clone();
        if let Some((started, release)) = barriers {
            started.wait();
            release.wait();
        }
        Ok(PageId::new())
    }

    fn close_page(
        &self,
        _session_id: &SessionId,
        _page_id: &PageId,
    ) -> Result<(), DependencyError> {
        let barriers = self
            .page_close_barriers
            .lock()
            .map_err(|_| DependencyError::Unavailable)?
            .clone();
        if let Some((started, release)) = barriers {
            started.wait();
            release.wait();
        }
        let _gate = self
            .approved_effect_gate
            .lock()
            .map_err(|_| DependencyError::Unavailable)?;
        Ok(())
    }

    fn activate_page(
        &self,
        _session_id: &SessionId,
        _page_id: &PageId,
    ) -> Result<(), DependencyError> {
        let barriers = self
            .page_activation_barriers
            .lock()
            .map_err(|_| DependencyError::Unavailable)?
            .clone();
        if let Some((started, release)) = barriers {
            started.wait();
            release.wait();
        }
        Ok(())
    }

    fn execute_action(
        &self,
        _session_id: &SessionId,
        _page_id: Option<&PageId>,
        payload: &[u8],
    ) -> ActionExecutionResult {
        self.executions.fetch_add(1, Ordering::AcqRel);
        ActionExecutionResult::Succeeded(payload.to_vec())
    }

    fn inspect_approval_context(
        &self,
        _session_id: &SessionId,
        _page_id: &PageId,
        _proposal: &CanonicalActionProposal,
    ) -> Result<LiveApprovalContext, DependencyError> {
        let barriers = self
            .inspection_barriers
            .lock()
            .map_err(|_| DependencyError::Unavailable)?
            .clone();
        if let Some((started, release)) = barriers {
            started.wait();
            release.wait();
        }
        let mut context = self
            .live_context
            .lock()
            .map_err(|_| DependencyError::Unavailable)?;
        let inspected = context.clone().ok_or(DependencyError::Unavailable)?;
        if self
            .invalidate_after_inspection
            .swap(false, Ordering::AcqRel)
            && let Some(context) = context.as_mut()
        {
            context.current_origin =
                Origin::parse("https://raced.test/").map_err(|_| DependencyError::Rejected)?;
        }
        Ok(inspected)
    }

    fn execute_approved_action(
        &self,
        session_id: &SessionId,
        page_id: &PageId,
        payload: &[u8],
        _proposal: &CanonicalActionProposal,
        inspected: &LiveApprovalContext,
        authorize_and_commit: &mut dyn FnMut(
            &LiveApprovalContext,
        ) -> Result<(), ApprovedActionError>,
    ) -> Result<ActionExecutionResult, ApprovedActionError> {
        let _gate = self
            .approved_effect_gate
            .lock()
            .map_err(|_| ApprovedActionError::Unavailable)?;
        let context = self
            .live_context
            .lock()
            .map_err(|_| ApprovedActionError::Unavailable)?;
        let observed = context.as_ref().ok_or(ApprovedActionError::Unavailable)?;
        if let Some(reason) = inspected.stale_reason(observed) {
            return Err(ApprovedActionError::ApprovalStale(reason));
        }
        let barriers = self
            .authorization_barriers
            .lock()
            .map_err(|_| ApprovedActionError::Unavailable)?
            .clone();
        if let Some((started, release)) = barriers {
            started.wait();
            release.wait();
        }
        if let Some(error) = self
            .pre_authorization_failure
            .lock()
            .map_err(|_| ApprovedActionError::Unavailable)?
            .take()
        {
            return Err(error);
        }
        if self
            .skip_authorization_callback
            .swap(false, Ordering::AcqRel)
        {
            self.approved_effect_occurred.store(true, Ordering::Release);
            return Ok(self.execute_action(session_id, Some(page_id), payload));
        }
        if let Err(error) = authorize_and_commit(observed)
            && !self
                .ignore_authorization_error
                .swap(false, Ordering::AcqRel)
        {
            return Err(error);
        }
        if self
            .invoke_authorization_callback_twice
            .swap(false, Ordering::AcqRel)
        {
            authorize_and_commit(observed)?;
        }
        let barriers = self
            .effect_start_barriers
            .lock()
            .map_err(|_| ApprovedActionError::Unavailable)?
            .clone();
        if let Some((started, release)) = barriers {
            started.wait();
            release.wait();
        }
        if let Some(error) = self
            .approved_failure
            .lock()
            .map_err(|_| ApprovedActionError::Unavailable)?
            .take()
        {
            return Err(error);
        }
        self.approved_effect_occurred.store(true, Ordering::Release);
        Ok(self.execute_action(session_id, Some(page_id), payload))
    }

    fn cancel_action(
        &self,
        _session_id: &SessionId,
        _action_id: &ActionId,
    ) -> Result<bool, DependencyError> {
        self.cancellation_attempts.fetch_add(1, Ordering::AcqRel);
        if self
            .confirm_cancellation_without_driver_serialization
            .swap(false, Ordering::AcqRel)
        {
            return Ok(true);
        }
        let _gate = self
            .approved_effect_gate
            .lock()
            .map_err(|_| DependencyError::Unavailable)?;
        Ok(!self.approved_effect_occurred.load(Ordering::Acquire))
    }
}

struct Sandbox;

impl SandboxClient for Sandbox {
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
        _session_id: &SessionId,
        _upload: &ArtifactUpload,
    ) -> Result<(), DependencyError> {
        Ok(())
    }
}

#[derive(Default)]
struct Clock {
    now: AtomicUsize,
    fail: AtomicBool,
}

impl Clock {
    fn set(&self, now: u64) {
        self.now.store(
            usize::try_from(now).expect("test clock value should fit usize"),
            Ordering::Release,
        );
    }

    fn set_failing(&self, fail: bool) {
        self.fail.store(fail, Ordering::Release);
    }
}

impl WorkerClock for Clock {
    fn now(&self) -> Result<SessionTime, WorkerError> {
        if self.fail.load(Ordering::Acquire) {
            return Err(WorkerError::StateUnavailable);
        }
        Ok(SessionTime::new(
            u64::try_from(self.now.load(Ordering::Acquire))
                .expect("test clock value should fit u64"),
        ))
    }
}

type TestWorker = WorkerControlPlane<Driver, Sandbox>;

struct Fixture {
    worker: Arc<TestWorker>,
    peer: AuthenticatedPeer,
    driver: Arc<Driver>,
    emergency_policy: Arc<EmergencyPolicy>,
    clock: Arc<Clock>,
    tenant_id: TenantId,
    requester: PrincipalId,
    session_id: SessionId,
    page_id: PageId,
    fence: OwnershipFence,
    journal: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        Self::with_journal_limits(ActionJournalLimits::default())
    }

    fn with_journal_limits(limits: ActionJournalLimits) -> Self {
        Self::with_journal_limits_and_terminalization_hook(limits, Arc::new(|| Ok(())))
    }

    fn with_journal_limits_and_terminalization_hook<F>(
        limits: ActionJournalLimits,
        terminalization_hook: Arc<F>,
    ) -> Self
    where
        F: Fn() -> Result<(), WorkerError> + Send + Sync + 'static,
    {
        Self::with_lease_policy_and_terminalization_hook(
            limits,
            LeasePolicy::new(Duration::from_secs(30), Duration::from_secs(1))
                .expect("lease policy should be valid"),
            SessionTimeoutPolicy::new(Duration::from_secs(60), Duration::from_secs(30))
                .expect("timeout policy should be valid"),
            terminalization_hook,
        )
    }

    fn with_deadline_policies(
        lease_policy: LeasePolicy,
        timeout_policy: SessionTimeoutPolicy,
    ) -> Self {
        Self::with_lease_policy_and_terminalization_hook(
            ActionJournalLimits::default(),
            lease_policy,
            timeout_policy,
            Arc::new(|| Ok(())),
        )
    }

    fn with_lease_policy_and_terminalization_hook<F>(
        limits: ActionJournalLimits,
        lease_policy: LeasePolicy,
        timeout_policy: SessionTimeoutPolicy,
        terminalization_hook: Arc<F>,
    ) -> Self
    where
        F: Fn() -> Result<(), WorkerError> + Send + Sync + 'static,
    {
        let journal = tempfile::tempdir().expect("journal directory should be created");
        let peer = AuthenticatedPeer::new("gateway-internal").expect("peer should be valid");
        let config = WorkerConfig::new(
            WorkerId::new("approval-worker").expect("worker id should be valid"),
            7,
            InternalEndpoint::loopback(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9017))
                .expect("endpoint should be valid"),
            peer.clone(),
            2,
            8,
            lease_policy,
            timeout_policy,
            Duration::from_millis(10),
            ActionJournalConfig::new(journal.path(), limits).expect("journal should be valid"),
        )
        .expect("worker config should be valid");
        let tenant_id = TenantId::new();
        let driver = Arc::new(Driver::default());
        *driver
            .live_context
            .lock()
            .expect("live context lock should work") = Some(LiveApprovalContext {
            target_incarnation: 9,
            frame_document_epoch: 11,
            current_origin: Origin::parse("https://example.test/after")
                .expect("origin should be valid"),
            url_revision: 13,
            node_ref: None,
            node_valid: true,
            resolved_ips: vec![],
            credential_refs: vec![],
            chromium_build: "sha256:test".to_owned(),
            effective_isolation: IsolationProfile::SharedContext,
        });
        let emergency_policy = Arc::new(EmergencyPolicy::default());
        let clock = Arc::new(Clock::default());
        let worker = Arc::new(
            WorkerControlPlane::new_with_emergency_policy_and_clock_and_terminalization_hook(
                config,
                Arc::clone(&driver),
                Arc::new(Sandbox),
                Arc::clone(&emergency_policy),
                Arc::clone(&clock),
                terminalization_hook,
            ),
        );
        let created = worker
            .create_session(
                &peer,
                CreateSessionCommand {
                    tenant_id: tenant_id.clone(),
                    idempotency_key: "create".to_owned(),
                    canonical_request_hash: [1; 32],
                    placement_version: 3,
                    session_incarnation: 5,
                },
                SessionTime::new(0),
            )
            .expect("session should be created");
        Self {
            worker,
            peer,
            driver,
            emergency_policy,
            clock,
            tenant_id,
            requester: PrincipalId::new(),
            session_id: created.session_id,
            page_id: created.primary_page_id,
            fence: created.fence,
            journal,
        }
    }

    fn proposal(&self, payload: &[u8]) -> CanonicalActionProposal {
        CanonicalActionProposal::new(
            self.tenant_id.clone(),
            self.requester.clone(),
            self.session_id.clone(),
            5,
            self.page_id.clone(),
            9,
            11,
            Origin::parse("https://example.test/path").expect("origin should be valid"),
            13,
            ActionType::Click,
            ActionArgumentsHash::digest(payload),
            None,
            CredentialRefsHash::digest(std::iter::empty()),
            11,
        )
    }

    fn submit(&self, key: &str, payload: &[u8], proposal: CanonicalActionProposal) -> ActionId {
        self.worker
            .submit_action(
                &self.peer,
                self.requester.clone(),
                &self.session_id,
                &self.fence,
                key,
                [7; 32],
                ActionKind::Mutating,
                None,
                Some(self.page_id.clone()),
                payload.to_vec(),
                Some(ActionApprovalRequirement::new(
                    proposal,
                    ActionType::Click,
                    true,
                )),
                SessionTime::new(1),
            )
            .expect("action should be accepted")
    }
}

#[test]
fn proposal_requester_must_match_the_trusted_requester_before_any_durable_mutation() {
    let fixture = Fixture::new();
    let payload = b"click-submit";
    let mismatched = CanonicalActionProposal::new(
        fixture.tenant_id.clone(),
        PrincipalId::new(),
        fixture.session_id.clone(),
        5,
        fixture.page_id.clone(),
        9,
        11,
        Origin::parse("https://example.test/").expect("origin should be valid"),
        13,
        ActionType::Click,
        ActionArgumentsHash::digest(payload),
        None,
        CredentialRefsHash::digest(std::iter::empty()),
        11,
    );

    assert_eq!(
        fixture.worker.submit_action(
            &fixture.peer,
            fixture.requester.clone(),
            &fixture.session_id,
            &fixture.fence,
            "requester-mismatch",
            [7; 32],
            ActionKind::Mutating,
            None,
            Some(fixture.page_id.clone()),
            payload.to_vec(),
            Some(ActionApprovalRequirement::new(
                mismatched,
                ActionType::Click,
                true,
            )),
            SessionTime::new(1),
        ),
        Err(WorkerError::ApprovalEvidenceMismatch)
    );
    let action_id = fixture.submit("requester-mismatch", payload, fixture.proposal(payload));
    assert_eq!(
        fixture
            .worker
            .get_action(
                &fixture.peer,
                &fixture.session_id,
                &action_id,
                &fixture.fence,
            )
            .expect("valid retry should be accepted")
            .action_sequence
            .get(),
        1
    );
}

#[test]
fn changed_live_origin_consumes_approval_without_dispatch_and_fails_known() {
    let fixture = Fixture::new();
    let payload = b"click-submit";
    let action_id = fixture.submit("origin-change", payload, fixture.proposal(payload));
    let approval_id = fixture
        .worker
        .approval_for_action(
            &fixture.peer,
            &fixture.session_id,
            &action_id,
            &fixture.fence,
        )
        .expect("approval should exist");
    fixture
        .worker
        .decide_approval(
            &fixture.peer,
            &fixture.session_id,
            &approval_id,
            &fixture.fence,
            ApprovalDecision::Approve,
            PrincipalId::new(),
            SessionTime::new(2),
        )
        .expect("approval should be recorded");
    fixture
        .driver
        .live_context
        .lock()
        .expect("live context lock should work")
        .as_mut()
        .expect("live context should exist")
        .current_origin =
        Origin::parse("https://attacker.test/").expect("changed origin should be valid");

    assert_eq!(
        fixture.worker.run_next_action(
            &fixture.peer,
            &fixture.session_id,
            &fixture.fence,
            SessionTime::new(3),
        ),
        Err(WorkerError::ApprovalPolicy(ApprovalError::ApprovalStale(
            StaleApprovalReason::Origin,
        )))
    );
    assert_eq!(fixture.driver.executions.load(Ordering::Acquire), 0);
    assert_eq!(
        fixture
            .worker
            .get_action(
                &fixture.peer,
                &fixture.session_id,
                &action_id,
                &fixture.fence,
            )
            .expect("action should remain queryable")
            .status,
        browserd_worker::ActionStatus::FailedKnown
    );
    assert_eq!(
        fixture.worker.run_next_action(
            &fixture.peer,
            &fixture.session_id,
            &fixture.fence,
            SessionTime::new(4),
        ),
        Ok(None)
    );
}

#[test]
fn changed_proposal_cannot_reuse_idempotent_action_or_approval() {
    let fixture = Fixture::new();
    let payload = b"click-submit";
    let first = fixture.proposal(payload);
    fixture.submit("same-key", payload, first.clone());
    let changed = first.with_url_revision(14);

    assert_eq!(
        fixture.worker.submit_action(
            &fixture.peer,
            fixture.requester.clone(),
            &fixture.session_id,
            &fixture.fence,
            "same-key",
            [7; 32],
            ActionKind::Mutating,
            None,
            Some(fixture.page_id.clone()),
            payload.to_vec(),
            Some(ActionApprovalRequirement::new(
                changed,
                ActionType::Click,
                true,
            )),
            SessionTime::new(1),
        ),
        Err(WorkerError::IdempotencyConflict)
    );
}

#[test]
fn changed_four_eyes_policy_cannot_reuse_idempotent_approval() {
    let fixture = Fixture::new();
    let payload = b"click-submit";
    let proposal = fixture.proposal(payload);
    let first = fixture.worker.submit_action(
        &fixture.peer,
        fixture.requester.clone(),
        &fixture.session_id,
        &fixture.fence,
        "same-policy-key",
        [9; 32],
        ActionKind::Mutating,
        None,
        Some(fixture.page_id.clone()),
        payload.to_vec(),
        Some(ActionApprovalRequirement::new(
            proposal.clone(),
            ActionType::Click,
            false,
        )),
        SessionTime::new(1),
    );
    assert!(first.is_ok());

    assert_eq!(
        fixture.worker.submit_action(
            &fixture.peer,
            fixture.requester.clone(),
            &fixture.session_id,
            &fixture.fence,
            "same-policy-key",
            [9; 32],
            ActionKind::Mutating,
            None,
            Some(fixture.page_id.clone()),
            payload.to_vec(),
            Some(ActionApprovalRequirement::new(
                proposal,
                ActionType::Click,
                true,
            )),
            SessionTime::new(1),
        ),
        Err(WorkerError::IdempotencyConflict)
    );
}

#[test]
fn durable_action_request_hash_commits_to_approval_evidence() {
    let fixture = Fixture::new();
    let payload = b"click-submit";
    let proposal = fixture.proposal(payload);
    let proposal_hash = proposal.hash();
    let action_id = fixture.submit("durable-binding", payload, proposal);
    let journal_path = fixture
        .journal
        .path()
        .join(format!("{}.wal", fixture.session_id));
    let ledger_session = LedgerSession::new(
        fixture.tenant_id.clone(),
        fixture.session_id.clone(),
        fixture.fence.as_placement_fence(),
    );
    drop(fixture.worker);

    let mut expected = Sha256::new();
    expected.update(b"browserd-worker-action-request-v2\0");
    expected.update([7; 32]);
    expected.update(fixture.requester.as_bytes());
    expected.update([1]);
    expected.update(proposal_hash.as_bytes());
    expected.update([1]);
    let expected: [u8; 32] = expected.finalize().into();
    let journal = FileActionJournal::open(journal_path, ActionJournalLimits::default())
        .expect("journal should reopen");
    let ledger =
        ActionLedger::recover(ledger_session, Arc::new(journal)).expect("ledger should recover");

    assert_eq!(
        ledger
            .snapshot(fixture.fence.as_placement_fence(), &action_id)
            .expect("action should recover")
            .request()
            .canonical_request_hash()
            .as_bytes(),
        &expected
    );
}

#[test]
fn proposal_arguments_must_match_the_dispatched_payload() {
    let fixture = Fixture::new();
    let proposal = fixture.proposal(b"approved-payload");

    assert_eq!(
        fixture.worker.submit_action(
            &fixture.peer,
            fixture.requester.clone(),
            &fixture.session_id,
            &fixture.fence,
            "changed-payload",
            [8; 32],
            ActionKind::Mutating,
            None,
            Some(fixture.page_id.clone()),
            b"different-payload".to_vec(),
            Some(ActionApprovalRequirement::new(
                proposal,
                ActionType::Click,
                true,
            )),
            SessionTime::new(1),
        ),
        Err(WorkerError::ApprovalEvidenceMismatch)
    );
    assert_eq!(fixture.driver.executions.load(Ordering::Acquire), 0);
}

#[test]
fn failed_durable_grant_does_not_poison_the_pending_policy_decision() {
    let fixture =
        Fixture::with_journal_limits(ActionJournalLimits::new(4 * 1024, 4, 4 * 1024 * 1024));
    let payload = b"click-submit";
    let action_id = fixture.submit("durable-decision", payload, fixture.proposal(payload));
    let approval_id = fixture
        .worker
        .approval_for_action(
            &fixture.peer,
            &fixture.session_id,
            &action_id,
            &fixture.fence,
        )
        .expect("approval should exist");

    assert_eq!(
        fixture.worker.decide_approval(
            &fixture.peer,
            &fixture.session_id,
            &approval_id,
            &fixture.fence,
            ApprovalDecision::Approve,
            PrincipalId::new(),
            SessionTime::new(2),
        ),
        Err(WorkerError::DurabilityUnavailable)
    );
    assert!(matches!(
        fixture.worker.decide_approval(
            &fixture.peer,
            &fixture.session_id,
            &approval_id,
            &fixture.fence,
            ApprovalDecision::Deny,
            PrincipalId::new(),
            SessionTime::new(2),
        ),
        Ok(browserd_worker::WorkerApprovalSnapshot {
            state: browserd_policy::ApprovalState::Denied { .. },
            ..
        })
    ));
    assert_eq!(fixture.driver.executions.load(Ordering::Acquire), 0);
}

#[test]
fn requester_cannot_self_approve_and_a_distinct_principal_can_still_decide() {
    let fixture = Fixture::new();
    let payload = b"click-submit";
    let action_id = fixture.submit("four-eyes", payload, fixture.proposal(payload));
    let approval_id = fixture
        .worker
        .approval_for_action(
            &fixture.peer,
            &fixture.session_id,
            &action_id,
            &fixture.fence,
        )
        .expect("approval should exist");

    assert_eq!(
        fixture.worker.decide_approval(
            &fixture.peer,
            &fixture.session_id,
            &approval_id,
            &fixture.fence,
            ApprovalDecision::Approve,
            fixture.requester.clone(),
            SessionTime::new(2),
        ),
        Err(WorkerError::ApprovalPolicy(
            ApprovalError::FourEyesViolation,
        ))
    );
    assert!(
        fixture
            .worker
            .decide_approval(
                &fixture.peer,
                &fixture.session_id,
                &approval_id,
                &fixture.fence,
                ApprovalDecision::Approve,
                PrincipalId::new(),
                SessionTime::new(2),
            )
            .is_ok()
    );
}

#[test]
fn stale_fence_cannot_mutate_the_one_time_approval() {
    let fixture = Fixture::new();
    let payload = b"click-submit";
    let action_id = fixture.submit("stale-fence", payload, fixture.proposal(payload));
    let approval_id = fixture
        .worker
        .approval_for_action(
            &fixture.peer,
            &fixture.session_id,
            &action_id,
            &fixture.fence,
        )
        .expect("approval should exist");
    let stale = OwnershipFence::new(
        fixture.fence.worker_id().clone(),
        fixture.fence.worker_epoch(),
        fixture.fence.placement_version() + 1,
        fixture.fence.session_incarnation(),
    );

    assert_eq!(
        fixture.worker.decide_approval(
            &fixture.peer,
            &fixture.session_id,
            &approval_id,
            &stale,
            ApprovalDecision::Approve,
            PrincipalId::new(),
            SessionTime::new(2),
        ),
        Err(WorkerError::StaleFence)
    );
    assert!(
        fixture
            .worker
            .decide_approval(
                &fixture.peer,
                &fixture.session_id,
                &approval_id,
                &fixture.fence,
                ApprovalDecision::Approve,
                PrincipalId::new(),
                SessionTime::new(2),
            )
            .is_ok()
    );
}

#[test]
fn emergency_policy_change_after_approval_prevents_dispatch() {
    let fixture = Fixture::new();
    let payload = b"click-submit";
    let action_id = fixture.submit("emergency-policy", payload, fixture.proposal(payload));
    let approval_id = fixture
        .worker
        .approval_for_action(
            &fixture.peer,
            &fixture.session_id,
            &action_id,
            &fixture.fence,
        )
        .expect("approval should exist");
    fixture
        .worker
        .decide_approval(
            &fixture.peer,
            &fixture.session_id,
            &approval_id,
            &fixture.fence,
            ApprovalDecision::Approve,
            PrincipalId::new(),
            SessionTime::new(2),
        )
        .expect("approval should succeed");
    fixture
        .emergency_policy
        .disable_session(fixture.session_id.clone())
        .expect("emergency policy should update");

    assert_eq!(
        fixture.worker.run_next_action(
            &fixture.peer,
            &fixture.session_id,
            &fixture.fence,
            SessionTime::new(3),
        ),
        Err(WorkerError::ApprovalPolicy(ApprovalError::ApprovalStale(
            StaleApprovalReason::EmergencyDenied(EmergencyDenyReason::SessionDisabled),
        )))
    );
    assert_eq!(fixture.driver.executions.load(Ordering::Acquire), 0);
}

#[test]
fn context_change_after_inspection_is_rechecked_before_browser_effect() {
    let fixture = Fixture::new();
    let payload = b"click-submit";
    let action_id = fixture.submit("inspection-race", payload, fixture.proposal(payload));
    let approval_id = fixture
        .worker
        .approval_for_action(
            &fixture.peer,
            &fixture.session_id,
            &action_id,
            &fixture.fence,
        )
        .expect("approval should exist");
    fixture
        .worker
        .decide_approval(
            &fixture.peer,
            &fixture.session_id,
            &approval_id,
            &fixture.fence,
            ApprovalDecision::Approve,
            PrincipalId::new(),
            SessionTime::new(2),
        )
        .expect("approval should succeed");
    fixture
        .driver
        .invalidate_after_inspection
        .store(true, Ordering::Release);

    assert_eq!(
        fixture.worker.run_next_action(
            &fixture.peer,
            &fixture.session_id,
            &fixture.fence,
            SessionTime::new(3),
        ),
        Err(WorkerError::ApprovalPolicy(ApprovalError::ApprovalStale(
            StaleApprovalReason::Origin,
        )))
    );
    assert_eq!(fixture.driver.executions.load(Ordering::Acquire), 0);
    assert_eq!(
        fixture
            .worker
            .get_action(
                &fixture.peer,
                &fixture.session_id,
                &action_id,
                &fixture.fence,
            )
            .expect("action should remain queryable")
            .status,
        browserd_worker::ActionStatus::FailedKnown
    );
}

#[test]
fn uncertain_approved_dispatch_is_never_downgraded_to_failed_known() {
    let fixture = Fixture::new();
    let payload = b"click-submit";
    let action_id = fixture.submit("uncertain-dispatch", payload, fixture.proposal(payload));
    let approval_id = fixture
        .worker
        .approval_for_action(
            &fixture.peer,
            &fixture.session_id,
            &action_id,
            &fixture.fence,
        )
        .expect("approval should exist");
    fixture
        .worker
        .decide_approval(
            &fixture.peer,
            &fixture.session_id,
            &approval_id,
            &fixture.fence,
            ApprovalDecision::Approve,
            PrincipalId::new(),
            SessionTime::new(2),
        )
        .expect("approval should succeed");
    *fixture
        .driver
        .approved_failure
        .lock()
        .expect("failure lock should work") = Some(ApprovedActionError::OutcomeUncertain);

    let outcome = fixture
        .worker
        .run_next_action(
            &fixture.peer,
            &fixture.session_id,
            &fixture.fence,
            SessionTime::new(3),
        )
        .expect("outcome unknown is a terminal action result")
        .expect("action should be returned");
    assert_eq!(
        outcome.status,
        browserd_worker::ActionStatus::OutcomeUnknown
    );
    assert_eq!(fixture.driver.executions.load(Ordering::Acquire), 0);
    assert_eq!(
        fixture
            .worker
            .get_action(
                &fixture.peer,
                &fixture.session_id,
                &action_id,
                &fixture.fence,
            )
            .expect("action should remain queryable")
            .status,
        browserd_worker::ActionStatus::OutcomeUnknown
    );
}

#[test]
fn unavailable_approved_dispatch_is_a_terminal_outcome_unknown_snapshot() {
    let fixture = Fixture::new();
    let payload = b"click-submit";
    let action_id = fixture.submit("unavailable-dispatch", payload, fixture.proposal(payload));
    let approval_id = fixture
        .worker
        .approval_for_action(
            &fixture.peer,
            &fixture.session_id,
            &action_id,
            &fixture.fence,
        )
        .expect("approval should exist");
    fixture
        .worker
        .decide_approval(
            &fixture.peer,
            &fixture.session_id,
            &approval_id,
            &fixture.fence,
            ApprovalDecision::Approve,
            PrincipalId::new(),
            SessionTime::new(2),
        )
        .expect("approval should succeed");
    *fixture
        .driver
        .approved_failure
        .lock()
        .expect("failure lock should work") = Some(ApprovedActionError::Unavailable);

    let outcome = fixture
        .worker
        .run_next_action(
            &fixture.peer,
            &fixture.session_id,
            &fixture.fence,
            SessionTime::new(3),
        )
        .expect("unavailable dispatch has an ambiguous durable terminal result")
        .expect("action should be returned");
    assert_eq!(
        outcome.status,
        browserd_worker::ActionStatus::OutcomeUnknown
    );
    assert_eq!(fixture.driver.executions.load(Ordering::Acquire), 0);
    assert_eq!(
        fixture
            .worker
            .get_action(
                &fixture.peer,
                &fixture.session_id,
                &action_id,
                &fixture.fence,
            )
            .expect("action should remain queryable")
            .status,
        browserd_worker::ActionStatus::OutcomeUnknown
    );
}

#[test]
fn driver_success_without_an_authorization_callback_is_never_exposed_as_success() {
    let fixture = Fixture::new();
    let payload = b"click-submit";
    let action_id = fixture.submit("missing-callback", payload, fixture.proposal(payload));
    let approval_id = fixture
        .worker
        .approval_for_action(
            &fixture.peer,
            &fixture.session_id,
            &action_id,
            &fixture.fence,
        )
        .expect("approval should exist");
    fixture
        .worker
        .decide_approval(
            &fixture.peer,
            &fixture.session_id,
            &approval_id,
            &fixture.fence,
            ApprovalDecision::Approve,
            PrincipalId::new(),
            SessionTime::new(2),
        )
        .expect("approval should succeed");
    fixture
        .driver
        .skip_authorization_callback
        .store(true, Ordering::Release);
    let later_action_id = fixture
        .worker
        .submit_action(
            &fixture.peer,
            fixture.requester.clone(),
            &fixture.session_id,
            &fixture.fence,
            "after-missing-callback",
            [29; 32],
            ActionKind::Mutating,
            None,
            None,
            b"later".to_vec(),
            None,
            SessionTime::new(2),
        )
        .expect("a later mutation should be queued until reconciliation");

    let outcome = fixture
        .worker
        .run_next_action(
            &fixture.peer,
            &fixture.session_id,
            &fixture.fence,
            SessionTime::new(3),
        )
        .expect("the unproven effect boundary must be durably terminal")
        .expect("the action should be returned");
    assert_eq!(
        outcome.status,
        browserd_worker::ActionStatus::OutcomeUnknown
    );
    assert_eq!(fixture.driver.executions.load(Ordering::Acquire), 1);
    assert_eq!(
        fixture
            .worker
            .get_action(
                &fixture.peer,
                &fixture.session_id,
                &action_id,
                &fixture.fence,
            )
            .expect("the action should remain queryable")
            .status,
        browserd_worker::ActionStatus::OutcomeUnknown
    );
    assert_eq!(
        fixture.worker.run_next_action(
            &fixture.peer,
            &fixture.session_id,
            &fixture.fence,
            SessionTime::new(4),
        ),
        Err(WorkerError::InvalidActionTransition)
    );
    assert_eq!(fixture.driver.executions.load(Ordering::Acquire), 1);
    assert_eq!(
        fixture
            .worker
            .get_action(
                &fixture.peer,
                &fixture.session_id,
                &later_action_id,
                &fixture.fence,
            )
            .expect("the blocked later action should remain queryable")
            .status,
        browserd_worker::ActionStatus::Queued
    );
}

#[test]
fn callbackless_dispatch_revocation_is_durably_terminal_before_the_error_is_returned() {
    let fixture = Fixture::new();
    let payload = b"click-submit";
    let action_id = fixture.submit(
        "callbackless-revocation",
        payload,
        fixture.proposal(payload),
    );
    let approval_id = fixture
        .worker
        .approval_for_action(
            &fixture.peer,
            &fixture.session_id,
            &action_id,
            &fixture.fence,
        )
        .expect("approval should exist");
    fixture
        .worker
        .decide_approval(
            &fixture.peer,
            &fixture.session_id,
            &approval_id,
            &fixture.fence,
            ApprovalDecision::Approve,
            PrincipalId::new(),
            SessionTime::new(2),
        )
        .expect("approval should succeed");
    *fixture
        .driver
        .pre_authorization_failure
        .lock()
        .expect("failure lock should work") = Some(ApprovedActionError::DispatchRevoked);

    assert_eq!(
        fixture.worker.run_next_action(
            &fixture.peer,
            &fixture.session_id,
            &fixture.fence,
            SessionTime::new(3),
        ),
        Err(WorkerError::InvalidActionTransition)
    );
    assert_eq!(fixture.driver.executions.load(Ordering::Acquire), 0);
    assert_eq!(
        fixture
            .worker
            .get_action(
                &fixture.peer,
                &fixture.session_id,
                &action_id,
                &fixture.fence,
            )
            .expect("the revoked action must remain queryable")
            .status,
        browserd_worker::ActionStatus::FailedKnown
    );
}

#[test]
fn approved_driver_phase_and_result_matrix_always_reaches_a_durable_terminal_state() {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum DispatchPhase {
        Pending,
        Stopped,
        Started,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum DriverResult {
        Ok,
        ApprovalStale,
        DispatchRevoked,
        Transport,
    }

    let cases = [
        (DispatchPhase::Pending, DriverResult::Ok),
        (DispatchPhase::Pending, DriverResult::ApprovalStale),
        (DispatchPhase::Pending, DriverResult::DispatchRevoked),
        (DispatchPhase::Pending, DriverResult::Transport),
        (DispatchPhase::Stopped, DriverResult::Ok),
        (DispatchPhase::Stopped, DriverResult::ApprovalStale),
        (DispatchPhase::Stopped, DriverResult::DispatchRevoked),
        (DispatchPhase::Stopped, DriverResult::Transport),
        (DispatchPhase::Started, DriverResult::Ok),
        (DispatchPhase::Started, DriverResult::ApprovalStale),
        (DispatchPhase::Started, DriverResult::DispatchRevoked),
        (DispatchPhase::Started, DriverResult::Transport),
    ];

    for (phase, driver_result) in cases {
        let fixture = Fixture::new();
        let payload = b"click-submit";
        let key = format!("matrix-{phase:?}-{driver_result:?}");
        let action_id = fixture.submit(&key, payload, fixture.proposal(payload));
        let approval_id = fixture
            .worker
            .approval_for_action(
                &fixture.peer,
                &fixture.session_id,
                &action_id,
                &fixture.fence,
            )
            .expect("approval should exist");
        fixture
            .worker
            .decide_approval(
                &fixture.peer,
                &fixture.session_id,
                &approval_id,
                &fixture.fence,
                ApprovalDecision::Approve,
                PrincipalId::new(),
                SessionTime::new(2),
            )
            .expect("approval should succeed");

        match phase {
            DispatchPhase::Pending => match driver_result {
                DriverResult::Ok => fixture
                    .driver
                    .skip_authorization_callback
                    .store(true, Ordering::Release),
                DriverResult::ApprovalStale => {
                    *fixture
                        .driver
                        .pre_authorization_failure
                        .lock()
                        .expect("failure lock should work") = Some(
                        ApprovedActionError::ApprovalStale(StaleApprovalReason::Origin),
                    );
                }
                DriverResult::DispatchRevoked => {
                    *fixture
                        .driver
                        .pre_authorization_failure
                        .lock()
                        .expect("failure lock should work") =
                        Some(ApprovedActionError::DispatchRevoked);
                }
                DriverResult::Transport => {
                    *fixture
                        .driver
                        .pre_authorization_failure
                        .lock()
                        .expect("failure lock should work") =
                        Some(ApprovedActionError::OutcomeUncertain);
                }
            },
            DispatchPhase::Stopped => {
                fixture
                    .emergency_policy
                    .disable_session(fixture.session_id.clone())
                    .expect("session should be disabled");
                if driver_result != DriverResult::DispatchRevoked {
                    fixture
                        .driver
                        .ignore_authorization_error
                        .store(true, Ordering::Release);
                }
                let failure = match driver_result {
                    DriverResult::ApprovalStale => Some(ApprovedActionError::ApprovalStale(
                        StaleApprovalReason::Origin,
                    )),
                    DriverResult::Transport => Some(ApprovedActionError::OutcomeUncertain),
                    DriverResult::Ok | DriverResult::DispatchRevoked => None,
                };
                *fixture
                    .driver
                    .approved_failure
                    .lock()
                    .expect("failure lock should work") = failure;
            }
            DispatchPhase::Started => {
                let failure = match driver_result {
                    DriverResult::ApprovalStale => Some(ApprovedActionError::ApprovalStale(
                        StaleApprovalReason::Origin,
                    )),
                    DriverResult::DispatchRevoked => Some(ApprovedActionError::DispatchRevoked),
                    DriverResult::Transport => Some(ApprovedActionError::OutcomeUncertain),
                    DriverResult::Ok => None,
                };
                *fixture
                    .driver
                    .approved_failure
                    .lock()
                    .expect("failure lock should work") = failure;
            }
        }

        let response = fixture.worker.run_next_action(
            &fixture.peer,
            &fixture.session_id,
            &fixture.fence,
            SessionTime::new(3),
        );
        let expected_status = match (phase, driver_result) {
            (DispatchPhase::Started, DriverResult::Ok) => browserd_worker::ActionStatus::Succeeded,
            (
                DispatchPhase::Pending | DispatchPhase::Stopped,
                DriverResult::ApprovalStale | DriverResult::DispatchRevoked,
            ) => browserd_worker::ActionStatus::FailedKnown,
            _ => browserd_worker::ActionStatus::OutcomeUnknown,
        };
        let durable = fixture
            .worker
            .get_action(
                &fixture.peer,
                &fixture.session_id,
                &action_id,
                &fixture.fence,
            )
            .expect("every driver result must leave a queryable action");
        assert_eq!(
            durable.status, expected_status,
            "phase={phase:?}, result={driver_result:?}, response={response:?}"
        );
        if let Ok(Some(returned)) = response {
            assert_eq!(returned.status, expected_status);
        }
        assert_ne!(
            durable.status,
            browserd_worker::ActionStatus::Running,
            "phase={phase:?}, result={driver_result:?}"
        );

        let executions = fixture.driver.executions.load(Ordering::Acquire);
        assert_eq!(
            fixture.submit(&key, payload, fixture.proposal(payload)),
            action_id,
            "the idempotent retry must resolve to the original terminal action"
        );
        assert_eq!(
            fixture.worker.run_next_action(
                &fixture.peer,
                &fixture.session_id,
                &fixture.fence,
                SessionTime::new(4),
            ),
            Ok(None),
            "a terminal action must never be replayed for phase={phase:?}, result={driver_result:?}"
        );
        assert_eq!(
            fixture.driver.executions.load(Ordering::Acquire),
            executions
        );
    }
}

#[test]
fn driver_stale_error_after_effect_admission_is_durable_outcome_unknown() {
    let fixture = Fixture::new();
    let payload = b"click-submit";
    let action_id = fixture.submit("stale-after-admission", payload, fixture.proposal(payload));
    let approval_id = fixture
        .worker
        .approval_for_action(
            &fixture.peer,
            &fixture.session_id,
            &action_id,
            &fixture.fence,
        )
        .expect("approval should exist");
    fixture
        .worker
        .decide_approval(
            &fixture.peer,
            &fixture.session_id,
            &approval_id,
            &fixture.fence,
            ApprovalDecision::Approve,
            PrincipalId::new(),
            SessionTime::new(2),
        )
        .expect("approval should succeed");
    *fixture
        .driver
        .approved_failure
        .lock()
        .expect("failure lock should work") = Some(ApprovedActionError::ApprovalStale(
        StaleApprovalReason::Origin,
    ));

    let outcome = fixture
        .worker
        .run_next_action(
            &fixture.peer,
            &fixture.session_id,
            &fixture.fence,
            SessionTime::new(3),
        )
        .expect("an error after admission has an ambiguous durable terminal result")
        .expect("the action should be returned");
    assert_eq!(
        outcome.status,
        browserd_worker::ActionStatus::OutcomeUnknown
    );
    assert_eq!(fixture.driver.executions.load(Ordering::Acquire), 0);
    assert_eq!(
        fixture
            .worker
            .get_action(
                &fixture.peer,
                &fixture.session_id,
                &action_id,
                &fixture.fence,
            )
            .expect("the action should remain queryable")
            .status,
        browserd_worker::ActionStatus::OutcomeUnknown
    );
}

#[test]
fn second_authorization_callback_after_admission_cannot_leave_the_action_running() {
    let fixture = Fixture::new();
    let payload = b"click-submit";
    let action_id = fixture.submit("double-callback", payload, fixture.proposal(payload));
    let approval_id = fixture
        .worker
        .approval_for_action(
            &fixture.peer,
            &fixture.session_id,
            &action_id,
            &fixture.fence,
        )
        .expect("approval should exist");
    fixture
        .worker
        .decide_approval(
            &fixture.peer,
            &fixture.session_id,
            &approval_id,
            &fixture.fence,
            ApprovalDecision::Approve,
            PrincipalId::new(),
            SessionTime::new(2),
        )
        .expect("approval should succeed");
    fixture
        .driver
        .invoke_authorization_callback_twice
        .store(true, Ordering::Release);

    let outcome = fixture
        .worker
        .run_next_action(
            &fixture.peer,
            &fixture.session_id,
            &fixture.fence,
            SessionTime::new(3),
        )
        .expect("a contract error after admission must still terminalize")
        .expect("the action should be returned");
    assert_eq!(
        outcome.status,
        browserd_worker::ActionStatus::OutcomeUnknown
    );
    assert_eq!(fixture.driver.executions.load(Ordering::Acquire), 0);
    assert_eq!(
        fixture
            .worker
            .get_action(
                &fixture.peer,
                &fixture.session_id,
                &action_id,
                &fixture.fence,
            )
            .expect("the action should remain queryable")
            .status,
        browserd_worker::ActionStatus::OutcomeUnknown
    );
}

#[test]
fn approval_expiring_while_live_inspection_blocks_never_dispatches() {
    let fixture = Fixture::new();
    let payload = b"click-submit";
    let action_id = fixture.submit("inspection-expiry", payload, fixture.proposal(payload));
    let approval_id = fixture
        .worker
        .approval_for_action(
            &fixture.peer,
            &fixture.session_id,
            &action_id,
            &fixture.fence,
        )
        .expect("approval should exist");
    fixture
        .worker
        .decide_approval(
            &fixture.peer,
            &fixture.session_id,
            &approval_id,
            &fixture.fence,
            ApprovalDecision::Approve,
            PrincipalId::new(),
            SessionTime::new(2),
        )
        .expect("approval should succeed");
    let started = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    *fixture
        .driver
        .inspection_barriers
        .lock()
        .expect("inspection barrier lock should work") =
        Some((Arc::clone(&started), Arc::clone(&release)));
    let worker = Arc::clone(&fixture.worker);
    let peer = fixture.peer.clone();
    let session_id = fixture.session_id.clone();
    let fence = fixture.fence.clone();
    let runner = thread::spawn(move || {
        worker.run_next_action(&peer, &session_id, &fence, SessionTime::new(3))
    });
    started.wait();
    fixture
        .worker
        .heartbeat(&fixture.peer, SessionTime::new(12))
        .expect("trusted session clock should advance past approval expiry");
    release.wait();

    assert_eq!(
        runner.join().expect("runner should not panic"),
        Err(WorkerError::ApprovalPolicy(ApprovalError::ApprovalStale(
            StaleApprovalReason::Expired,
        )))
    );
    assert_eq!(fixture.driver.executions.load(Ordering::Acquire), 0);
    assert_eq!(
        fixture
            .worker
            .get_action(
                &fixture.peer,
                &fixture.session_id,
                &action_id,
                &fixture.fence,
            )
            .expect("expired action should remain queryable")
            .status,
        browserd_worker::ActionStatus::FailedKnown
    );
}

#[test]
fn trusted_clock_expiry_at_driver_authorization_boundary_never_dispatches() {
    let fixture = Fixture::new();
    let payload = b"click-submit";
    let action_id = fixture.submit("boundary-clock-expiry", payload, fixture.proposal(payload));
    let approval_id = fixture
        .worker
        .approval_for_action(
            &fixture.peer,
            &fixture.session_id,
            &action_id,
            &fixture.fence,
        )
        .expect("approval should exist");
    fixture
        .worker
        .decide_approval(
            &fixture.peer,
            &fixture.session_id,
            &approval_id,
            &fixture.fence,
            ApprovalDecision::Approve,
            PrincipalId::new(),
            SessionTime::new(2),
        )
        .expect("approval should succeed");
    let started = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    *fixture
        .driver
        .authorization_barriers
        .lock()
        .expect("authorization barrier lock should work") =
        Some((Arc::clone(&started), Arc::clone(&release)));
    let worker = Arc::clone(&fixture.worker);
    let peer = fixture.peer.clone();
    let session_id = fixture.session_id.clone();
    let fence = fixture.fence.clone();
    let runner = thread::spawn(move || {
        worker.run_next_action(&peer, &session_id, &fence, SessionTime::new(3))
    });
    started.wait();
    fixture.clock.set(12);
    release.wait();

    assert_eq!(
        runner.join().expect("runner should not panic"),
        Err(WorkerError::ApprovalPolicy(ApprovalError::ApprovalStale(
            StaleApprovalReason::Expired,
        )))
    );
    assert_eq!(fixture.driver.executions.load(Ordering::Acquire), 0);
    assert_eq!(
        fixture
            .worker
            .get_action(
                &fixture.peer,
                &fixture.session_id,
                &action_id,
                &fixture.fence,
            )
            .expect("expired action should remain queryable")
            .status,
        browserd_worker::ActionStatus::FailedKnown
    );
}

fn assert_trusted_clock_session_deadline_never_dispatches(
    key: &str,
    lease_policy: LeasePolicy,
    timeout_policy: SessionTimeoutPolicy,
    deadline: u64,
) {
    let fixture = Fixture::with_deadline_policies(lease_policy, timeout_policy);
    let payload = b"click-submit";
    let action_id = fixture.submit(key, payload, fixture.proposal(payload));
    let approval_id = fixture
        .worker
        .approval_for_action(
            &fixture.peer,
            &fixture.session_id,
            &action_id,
            &fixture.fence,
        )
        .expect("approval should exist");
    fixture
        .worker
        .decide_approval(
            &fixture.peer,
            &fixture.session_id,
            &approval_id,
            &fixture.fence,
            ApprovalDecision::Approve,
            PrincipalId::new(),
            SessionTime::new(2),
        )
        .expect("approval should succeed before the active session deadline");
    let started = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    *fixture
        .driver
        .inspection_barriers
        .lock()
        .expect("inspection barrier lock should work") =
        Some((Arc::clone(&started), Arc::clone(&release)));
    let worker = Arc::clone(&fixture.worker);
    let peer = fixture.peer.clone();
    let session_id = fixture.session_id.clone();
    let fence = fixture.fence.clone();
    let runner = thread::spawn(move || {
        worker.run_next_action(&peer, &session_id, &fence, SessionTime::new(3))
    });
    started.wait();
    fixture.clock.set(deadline);
    release.wait();

    assert_eq!(
        runner.join().expect("runner should not panic"),
        Err(WorkerError::ApprovalPolicy(ApprovalError::ApprovalStale(
            StaleApprovalReason::PlacementOwnership,
        )))
    );
    assert_eq!(fixture.driver.executions.load(Ordering::Acquire), 0);
    assert_eq!(
        fixture
            .worker
            .get_action(
                &fixture.peer,
                &fixture.session_id,
                &action_id,
                &fixture.fence,
            )
            .expect("stale-ownership action should remain queryable")
            .status,
        browserd_worker::ActionStatus::FailedKnown
    );

    let journal_path = fixture
        .journal
        .path()
        .join(format!("{}.wal", fixture.session_id));
    let ledger_session = LedgerSession::new(
        fixture.tenant_id.clone(),
        fixture.session_id.clone(),
        fixture.fence.as_placement_fence(),
    );
    drop(fixture.worker);
    let journal = FileActionJournal::open(journal_path, ActionJournalLimits::default())
        .expect("journal should reopen");
    let ledger =
        ActionLedger::recover(ledger_session, Arc::new(journal)).expect("ledger should recover");
    assert_eq!(
        ledger
            .snapshot(fixture.fence.as_placement_fence(), &action_id)
            .expect("stale-ownership action should recover")
            .state(),
        ActionState::FailedKnown
    );
}

#[test]
fn trusted_clock_lease_expiry_during_live_inspection_never_dispatches() {
    assert_trusted_clock_session_deadline_never_dispatches(
        "inspection-lease-expiry",
        LeasePolicy::new(Duration::from_millis(5), Duration::from_millis(1))
            .expect("short lease policy should be valid"),
        SessionTimeoutPolicy::new(Duration::from_secs(60), Duration::from_secs(30))
            .expect("timeout policy should be valid"),
        5,
    );
}

#[test]
fn trusted_clock_session_expiry_during_live_inspection_never_dispatches() {
    assert_trusted_clock_session_deadline_never_dispatches(
        "inspection-session-expiry",
        LeasePolicy::new(Duration::from_secs(30), Duration::from_secs(1))
            .expect("lease policy should be valid"),
        SessionTimeoutPolicy::new(Duration::from_millis(5), Duration::from_secs(30))
            .expect("short session policy should be valid"),
        5,
    );
}

#[test]
fn trusted_clock_idle_expiry_during_live_inspection_never_dispatches() {
    assert_trusted_clock_session_deadline_never_dispatches(
        "inspection-idle-expiry",
        LeasePolicy::new(Duration::from_secs(30), Duration::from_secs(1))
            .expect("lease policy should be valid"),
        SessionTimeoutPolicy::new(Duration::from_secs(60), Duration::from_millis(5))
            .expect("short idle policy should be valid"),
        7,
    );
}

#[test]
fn failed_authorization_clock_terminalizes_without_effect_and_unblocks_the_queue() {
    let fixture = Fixture::new();
    let payload = b"click-submit";
    let action_id = fixture.submit("failed-clock", payload, fixture.proposal(payload));
    let approval_id = fixture
        .worker
        .approval_for_action(
            &fixture.peer,
            &fixture.session_id,
            &action_id,
            &fixture.fence,
        )
        .expect("approval should exist");
    fixture
        .worker
        .decide_approval(
            &fixture.peer,
            &fixture.session_id,
            &approval_id,
            &fixture.fence,
            ApprovalDecision::Approve,
            PrincipalId::new(),
            SessionTime::new(2),
        )
        .expect("approval should succeed");
    let next_action_id = fixture
        .worker
        .submit_action(
            &fixture.peer,
            fixture.requester.clone(),
            &fixture.session_id,
            &fixture.fence,
            "after-failed-clock",
            [19; 32],
            ActionKind::Mutating,
            None,
            None,
            b"next".to_vec(),
            None,
            SessionTime::new(2),
        )
        .expect("a later action should be queued");
    fixture.clock.set_failing(true);

    assert_eq!(
        fixture.worker.run_next_action(
            &fixture.peer,
            &fixture.session_id,
            &fixture.fence,
            SessionTime::new(3),
        ),
        Err(WorkerError::StateUnavailable)
    );
    assert_eq!(fixture.driver.executions.load(Ordering::Acquire), 0);
    assert_eq!(
        fixture
            .worker
            .get_action(
                &fixture.peer,
                &fixture.session_id,
                &action_id,
                &fixture.fence,
            )
            .expect("failed admission should remain queryable")
            .status,
        browserd_worker::ActionStatus::FailedKnown
    );

    fixture.clock.set_failing(false);
    let next = fixture
        .worker
        .run_next_action(
            &fixture.peer,
            &fixture.session_id,
            &fixture.fence,
            SessionTime::new(4),
        )
        .expect("the session should be quiescent after terminalization")
        .expect("the next queued action should run");
    assert_eq!(next.action_id, next_action_id);
    assert_eq!(next.status, browserd_worker::ActionStatus::Succeeded);
}

#[test]
fn approval_decision_uses_the_trusted_clock_for_deadline_enforcement() {
    let fixture = Fixture::new();
    let payload = b"click-submit";
    let action_id = fixture.submit("decision-clock-expiry", payload, fixture.proposal(payload));
    let approval_id = fixture
        .worker
        .approval_for_action(
            &fixture.peer,
            &fixture.session_id,
            &action_id,
            &fixture.fence,
        )
        .expect("approval should exist");
    fixture.clock.set(12);

    assert_eq!(
        fixture.worker.decide_approval(
            &fixture.peer,
            &fixture.session_id,
            &approval_id,
            &fixture.fence,
            ApprovalDecision::Approve,
            PrincipalId::new(),
            SessionTime::new(2),
        ),
        Err(WorkerError::ApprovalPolicy(ApprovalError::ApprovalExpired))
    );
    assert_eq!(fixture.driver.executions.load(Ordering::Acquire), 0);
    assert_eq!(
        fixture
            .worker
            .get_action(
                &fixture.peer,
                &fixture.session_id,
                &action_id,
                &fixture.fence,
            )
            .expect("timed-out approval action should remain queryable")
            .status,
        browserd_worker::ActionStatus::FailedKnown
    );
    assert_eq!(
        fixture.worker.run_next_action(
            &fixture.peer,
            &fixture.session_id,
            &fixture.fence,
            SessionTime::new(13),
        ),
        Ok(None)
    );
}

#[test]
fn confirmed_cancel_while_live_inspection_blocks_wins_before_browser_effect() {
    let fixture = Fixture::new();
    let payload = b"click-submit";
    let action_id = fixture.submit("inspection-cancel", payload, fixture.proposal(payload));
    let approval_id = fixture
        .worker
        .approval_for_action(
            &fixture.peer,
            &fixture.session_id,
            &action_id,
            &fixture.fence,
        )
        .expect("approval should exist");
    fixture
        .worker
        .decide_approval(
            &fixture.peer,
            &fixture.session_id,
            &approval_id,
            &fixture.fence,
            ApprovalDecision::Approve,
            PrincipalId::new(),
            SessionTime::new(2),
        )
        .expect("approval should succeed");
    let started = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    *fixture
        .driver
        .inspection_barriers
        .lock()
        .expect("inspection barrier lock should work") =
        Some((Arc::clone(&started), Arc::clone(&release)));
    let worker = Arc::clone(&fixture.worker);
    let peer = fixture.peer.clone();
    let session_id = fixture.session_id.clone();
    let fence = fixture.fence.clone();
    let runner = thread::spawn(move || {
        worker.run_next_action(&peer, &session_id, &fence, SessionTime::new(3))
    });
    started.wait();
    let cancelled = fixture
        .worker
        .cancel_action(
            &fixture.peer,
            &fixture.session_id,
            &action_id,
            &fixture.fence,
            SessionTime::new(4),
        )
        .expect("driver-confirmed cancellation should win while inspection is blocked");
    assert_eq!(
        cancelled.status,
        browserd_worker::ActionStatus::CancelledConfirmed
    );
    release.wait();

    let run_result = runner.join().expect("runner should not panic");
    assert_eq!(fixture.driver.executions.load(Ordering::Acquire), 0);
    assert_eq!(
        run_result,
        Err(WorkerError::InvalidActionTransition),
        "the cancellation winner remains queryable through the action resource"
    );
    assert_eq!(
        fixture
            .worker
            .get_action(
                &fixture.peer,
                &fixture.session_id,
                &action_id,
                &fixture.fence,
            )
            .expect("cancelled action should remain queryable")
            .status,
        browserd_worker::ActionStatus::CancelledConfirmed
    );
}

#[test]
fn cancel_at_driver_authorization_boundary_never_inverts_worker_and_driver_locks() {
    let fixture = Fixture::new();
    let payload = b"click-submit";
    let action_id = fixture.submit(
        "authorization-boundary-cancel",
        payload,
        fixture.proposal(payload),
    );
    let approval_id = fixture
        .worker
        .approval_for_action(
            &fixture.peer,
            &fixture.session_id,
            &action_id,
            &fixture.fence,
        )
        .expect("approval should exist");
    fixture
        .worker
        .decide_approval(
            &fixture.peer,
            &fixture.session_id,
            &approval_id,
            &fixture.fence,
            ApprovalDecision::Approve,
            PrincipalId::new(),
            SessionTime::new(2),
        )
        .expect("approval should succeed");
    let started = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    *fixture
        .driver
        .authorization_barriers
        .lock()
        .expect("authorization barrier lock should work") =
        Some((Arc::clone(&started), Arc::clone(&release)));
    let worker = Arc::clone(&fixture.worker);
    let peer = fixture.peer.clone();
    let session_id = fixture.session_id.clone();
    let fence = fixture.fence.clone();
    let runner = thread::spawn(move || {
        worker.run_next_action(&peer, &session_id, &fence, SessionTime::new(3))
    });
    started.wait();

    let (cancelled_tx, cancelled_rx) = mpsc::channel();
    let worker = Arc::clone(&fixture.worker);
    let peer = fixture.peer.clone();
    let session_id = fixture.session_id.clone();
    let fence = fixture.fence.clone();
    let cancel_action_id = action_id.clone();
    let canceller = thread::spawn(move || {
        cancelled_tx
            .send(worker.cancel_action(
                &peer,
                &session_id,
                &cancel_action_id,
                &fence,
                SessionTime::new(4),
            ))
            .expect("test receiver remains");
    });
    assert!(
        cancelled_rx
            .recv_timeout(Duration::from_millis(100))
            .is_err(),
        "cancellation cannot claim a known result until the entered driver boundary resolves"
    );
    assert_eq!(
        fixture
            .worker
            .get_action(
                &fixture.peer,
                &fixture.session_id,
                &action_id,
                &fixture.fence,
            )
            .expect("action queries must not wait on the driver gate")
            .status,
        browserd_worker::ActionStatus::Running
    );
    release.wait();

    let cancelled = cancelled_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("cancellation should finish after the driver boundary resolves")
        .expect("pre-start cancellation should have a known result");
    assert!(matches!(
        cancelled.status,
        browserd_worker::ActionStatus::CancelledConfirmed
            | browserd_worker::ActionStatus::FailedKnown
    ));
    assert_eq!(
        fixture.driver.cancellation_attempts.load(Ordering::Acquire),
        1
    );

    canceller.join().expect("canceller should not panic");
    assert_eq!(
        runner.join().expect("runner should not panic"),
        Err(WorkerError::InvalidActionTransition)
    );
    assert_eq!(fixture.driver.executions.load(Ordering::Acquire), 0);
}

#[test]
fn rejected_callback_ignored_by_driver_is_never_downgraded_to_confirmed_cancellation() {
    let fixture = Fixture::new();
    let payload = b"click-submit";
    let action_id = fixture.submit(
        "ignored-rejection-cancel-race",
        payload,
        fixture.proposal(payload),
    );
    let approval_id = fixture
        .worker
        .approval_for_action(
            &fixture.peer,
            &fixture.session_id,
            &action_id,
            &fixture.fence,
        )
        .expect("approval should exist");
    fixture
        .worker
        .decide_approval(
            &fixture.peer,
            &fixture.session_id,
            &approval_id,
            &fixture.fence,
            ApprovalDecision::Approve,
            PrincipalId::new(),
            SessionTime::new(2),
        )
        .expect("approval should succeed");
    fixture
        .driver
        .ignore_authorization_error
        .store(true, Ordering::Release);
    fixture
        .driver
        .confirm_cancellation_without_driver_serialization
        .store(true, Ordering::Release);
    let authorization_started = Arc::new(Barrier::new(2));
    let release_authorization = Arc::new(Barrier::new(2));
    *fixture
        .driver
        .authorization_barriers
        .lock()
        .expect("authorization barrier lock should work") = Some((
        Arc::clone(&authorization_started),
        Arc::clone(&release_authorization),
    ));

    let worker = Arc::clone(&fixture.worker);
    let peer = fixture.peer.clone();
    let session_id = fixture.session_id.clone();
    let fence = fixture.fence.clone();
    let runner = thread::spawn(move || {
        worker.run_next_action(&peer, &session_id, &fence, SessionTime::new(3))
    });
    authorization_started.wait();

    let cancel_entered = Arc::new(Barrier::new(2));
    let (cancelled_tx, cancelled_rx) = mpsc::channel();
    let worker = Arc::clone(&fixture.worker);
    let peer = fixture.peer.clone();
    let session_id = fixture.session_id.clone();
    let fence = fixture.fence.clone();
    let cancel_action_id = action_id.clone();
    let cancel_entered_thread = Arc::clone(&cancel_entered);
    let canceller = thread::spawn(move || {
        cancel_entered_thread.wait();
        cancelled_tx
            .send(worker.cancel_action(
                &peer,
                &session_id,
                &cancel_action_id,
                &fence,
                SessionTime::new(4),
            ))
            .expect("test receiver remains");
    });
    cancel_entered.wait();
    let early_cancellation = cancelled_rx.recv_timeout(Duration::from_millis(100));

    release_authorization.wait();
    let run_result = runner.join().expect("runner should not panic");
    let cancellation_completed_before_driver = early_cancellation.is_ok();
    let cancellation = match early_cancellation {
        Ok(result) => Some(result),
        Err(mpsc::RecvTimeoutError::Timeout) => {
            cancelled_rx.recv_timeout(Duration::from_secs(1)).ok()
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => None,
    };
    canceller.join().expect("canceller should not panic");

    assert!(
        !cancellation_completed_before_driver,
        "a callback rejection is not proof of no effect until the driver boundary resolves"
    );
    assert!(
        cancellation.is_some(),
        "cancellation should finish after the driver boundary resolves"
    );
    let Some(cancellation) = cancellation else {
        return;
    };
    assert!(
        !matches!(
            cancellation,
            Ok(ref snapshot)
                if snapshot.status == browserd_worker::ActionStatus::CancelledConfirmed
        ),
        "an ignored callback rejection must never become confirmed cancellation"
    );
    assert_eq!(fixture.driver.executions.load(Ordering::Acquire), 1);
    assert_eq!(
        fixture
            .worker
            .get_action(
                &fixture.peer,
                &fixture.session_id,
                &action_id,
                &fixture.fence,
            )
            .expect("the uncertain action should remain queryable")
            .status,
        browserd_worker::ActionStatus::OutcomeUnknown,
        "driver effect after a rejected callback is conservatively terminal"
    );
    assert!(
        run_result.is_ok() || run_result == Err(WorkerError::InvalidActionTransition),
        "the runner may lose finalization to cancellation but must terminate"
    );
}

#[test]
fn admitted_effect_start_wins_before_driver_confirmed_cancellation() {
    let fixture = Fixture::new();
    let payload = b"click-submit";
    let action_id = fixture.submit("effect-start-cancel", payload, fixture.proposal(payload));
    let approval_id = fixture
        .worker
        .approval_for_action(
            &fixture.peer,
            &fixture.session_id,
            &action_id,
            &fixture.fence,
        )
        .expect("approval should exist");
    fixture
        .worker
        .decide_approval(
            &fixture.peer,
            &fixture.session_id,
            &approval_id,
            &fixture.fence,
            ApprovalDecision::Approve,
            PrincipalId::new(),
            SessionTime::new(2),
        )
        .expect("approval should succeed");
    let started = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    *fixture
        .driver
        .effect_start_barriers
        .lock()
        .expect("effect-start barrier lock should work") =
        Some((Arc::clone(&started), Arc::clone(&release)));
    let worker = Arc::clone(&fixture.worker);
    let peer = fixture.peer.clone();
    let session_id = fixture.session_id.clone();
    let fence = fixture.fence.clone();
    let runner = thread::spawn(move || {
        worker.run_next_action(&peer, &session_id, &fence, SessionTime::new(3))
    });
    started.wait();

    let (cancelled_tx, cancelled_rx) = mpsc::channel();
    let worker = Arc::clone(&fixture.worker);
    let peer = fixture.peer.clone();
    let session_id = fixture.session_id.clone();
    let fence = fixture.fence.clone();
    let cancel_action_id = action_id.clone();
    let canceller = thread::spawn(move || {
        let result = worker.cancel_action(
            &peer,
            &session_id,
            &cancel_action_id,
            &fence,
            SessionTime::new(4),
        );
        cancelled_tx.send(result).expect("test receiver remains");
    });
    let cancellation_deadline = Instant::now() + Duration::from_secs(1);
    while fixture.driver.cancellation_attempts.load(Ordering::Acquire) == 0
        && Instant::now() < cancellation_deadline
    {
        thread::yield_now();
    }
    assert_eq!(
        fixture.driver.cancellation_attempts.load(Ordering::Acquire),
        1,
        "canceller should reach the driver gate"
    );
    assert!(
        cancelled_rx
            .recv_timeout(Duration::from_millis(50))
            .is_err(),
        "cancellation must not complete ahead of an already-admitted effect start"
    );
    let (queried_tx, queried_rx) = mpsc::channel();
    let worker = Arc::clone(&fixture.worker);
    let peer = fixture.peer.clone();
    let session_id = fixture.session_id.clone();
    let fence = fixture.fence.clone();
    let query_action_id = action_id.clone();
    let query = thread::spawn(move || {
        queried_tx
            .send(worker.get_action(&peer, &session_id, &query_action_id, &fence))
            .expect("test receiver remains");
    });
    let query_while_effect_blocked = queried_rx.recv_timeout(Duration::from_millis(50)).ok();
    let query_completed_while_effect_blocked = query_while_effect_blocked.is_some();
    release.wait();

    let queried = match query_while_effect_blocked {
        Some(queried) => queried,
        None => queried_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("query should finish after the effect gate is released"),
    };
    query.join().expect("query should not panic");
    let cancellation = cancelled_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("cancellation should complete after effect start");
    canceller.join().expect("canceller should not panic");
    assert!(
        match &cancellation {
            Err(WorkerError::InvalidActionTransition) => true,
            Ok(snapshot) => snapshot.status == browserd_worker::ActionStatus::Succeeded,
            Err(_) => false,
        },
        "unexpected cancellation outcome: {cancellation:?}"
    );
    let completed = runner
        .join()
        .expect("runner should not panic")
        .expect("admitted driver result should remain authoritative")
        .expect("action should be returned");
    assert!(
        query_completed_while_effect_blocked,
        "driver cancellation must not hold the session state lock while it waits"
    );
    assert_eq!(
        queried.expect("action query should succeed").status,
        browserd_worker::ActionStatus::Running
    );
    assert_eq!(fixture.driver.executions.load(Ordering::Acquire), 1);
    assert_eq!(completed.status, browserd_worker::ActionStatus::Succeeded);
    assert_eq!(
        fixture
            .worker
            .get_action(
                &fixture.peer,
                &fixture.session_id,
                &action_id,
                &fixture.fence,
            )
            .expect("completed action should remain queryable")
            .status,
        browserd_worker::ActionStatus::Succeeded
    );
}

#[test]
fn session_close_while_live_inspection_blocks_wins_before_browser_effect() {
    let fixture = Fixture::new();
    let payload = b"click-submit";
    let action_id = fixture.submit("inspection-close", payload, fixture.proposal(payload));
    let approval_id = fixture
        .worker
        .approval_for_action(
            &fixture.peer,
            &fixture.session_id,
            &action_id,
            &fixture.fence,
        )
        .expect("approval should exist");
    fixture
        .worker
        .decide_approval(
            &fixture.peer,
            &fixture.session_id,
            &approval_id,
            &fixture.fence,
            ApprovalDecision::Approve,
            PrincipalId::new(),
            SessionTime::new(2),
        )
        .expect("approval should succeed");
    let started = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    *fixture
        .driver
        .inspection_barriers
        .lock()
        .expect("inspection barrier lock should work") =
        Some((Arc::clone(&started), Arc::clone(&release)));
    let worker = Arc::clone(&fixture.worker);
    let peer = fixture.peer.clone();
    let session_id = fixture.session_id.clone();
    let fence = fixture.fence.clone();
    let runner = thread::spawn(move || {
        worker.run_next_action(&peer, &session_id, &fence, SessionTime::new(3))
    });
    started.wait();
    fixture
        .worker
        .close_session(
            &fixture.peer,
            &fixture.session_id,
            &fixture.fence,
            SessionTime::new(4),
        )
        .expect("close should win while inspection is blocked");
    release.wait();

    assert!(runner.join().expect("runner should not panic").is_err());
    assert_eq!(fixture.driver.executions.load(Ordering::Acquire), 0);
    assert_eq!(
        fixture
            .worker
            .get_action(
                &fixture.peer,
                &fixture.session_id,
                &action_id,
                &fixture.fence,
            )
            .expect("closed action should remain queryable")
            .status,
        browserd_worker::ActionStatus::FailedKnown
    );
}

#[test]
fn close_attempts_later_queue_terminalization_after_stopped_dispatch_wal_failure() {
    let fail_stopped_terminal = Arc::new(AtomicBool::new(true));
    let hook_flag = Arc::clone(&fail_stopped_terminal);
    let fixture = Fixture::with_journal_limits_and_terminalization_hook(
        ActionJournalLimits::default(),
        Arc::new(move || {
            if hook_flag.swap(false, Ordering::AcqRel) {
                Err(WorkerError::DurabilityUnavailable)
            } else {
                Ok(())
            }
        }),
    );
    let payload = b"click-submit";
    let stopped_action_id = fixture.submit(
        "stopped-terminal-failure",
        payload,
        fixture.proposal(payload),
    );
    let approval_id = fixture
        .worker
        .approval_for_action(
            &fixture.peer,
            &fixture.session_id,
            &stopped_action_id,
            &fixture.fence,
        )
        .expect("approval should exist");
    fixture
        .worker
        .decide_approval(
            &fixture.peer,
            &fixture.session_id,
            &approval_id,
            &fixture.fence,
            ApprovalDecision::Approve,
            PrincipalId::new(),
            SessionTime::new(2),
        )
        .expect("approval should succeed");
    let queued_action_id = fixture
        .worker
        .submit_action(
            &fixture.peer,
            fixture.requester.clone(),
            &fixture.session_id,
            &fixture.fence,
            "queued-after-stopped-terminal",
            [23; 32],
            ActionKind::Mutating,
            None,
            None,
            b"queued".to_vec(),
            None,
            SessionTime::new(2),
        )
        .expect("a later action should be queued");
    let started = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    *fixture
        .driver
        .inspection_barriers
        .lock()
        .expect("inspection barrier lock should work") =
        Some((Arc::clone(&started), Arc::clone(&release)));
    let worker = Arc::clone(&fixture.worker);
    let peer = fixture.peer.clone();
    let session_id = fixture.session_id.clone();
    let fence = fixture.fence.clone();
    let runner = thread::spawn(move || {
        worker.run_next_action(&peer, &session_id, &fence, SessionTime::new(3))
    });
    started.wait();

    assert_eq!(
        fixture.worker.close_session(
            &fixture.peer,
            &fixture.session_id,
            &fixture.fence,
            SessionTime::new(4),
        ),
        Err(WorkerError::DurabilityUnavailable)
    );
    release.wait();
    assert!(runner.join().expect("runner should not panic").is_err());
    assert_eq!(fixture.driver.executions.load(Ordering::Acquire), 0);
    assert_eq!(
        fixture
            .worker
            .get_action(
                &fixture.peer,
                &fixture.session_id,
                &stopped_action_id,
                &fixture.fence,
            )
            .expect("the stopped dispatch should be recoverably terminal")
            .status,
        browserd_worker::ActionStatus::OutcomeUnknown
    );
    assert_eq!(
        fixture
            .worker
            .get_action(
                &fixture.peer,
                &fixture.session_id,
                &queued_action_id,
                &fixture.fence,
            )
            .expect("the later queued action should remain queryable")
            .status,
        browserd_worker::ActionStatus::CancelledBeforeDispatch
    );
}

#[test]
fn close_waiting_on_an_admitted_effect_does_not_block_action_queries() {
    let fixture = Fixture::new();
    let payload = b"click-submit";
    let action_id = fixture.submit("effect-start-close", payload, fixture.proposal(payload));
    let approval_id = fixture
        .worker
        .approval_for_action(
            &fixture.peer,
            &fixture.session_id,
            &action_id,
            &fixture.fence,
        )
        .expect("approval should exist");
    fixture
        .worker
        .decide_approval(
            &fixture.peer,
            &fixture.session_id,
            &approval_id,
            &fixture.fence,
            ApprovalDecision::Approve,
            PrincipalId::new(),
            SessionTime::new(2),
        )
        .expect("approval should succeed");
    let started = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    *fixture
        .driver
        .effect_start_barriers
        .lock()
        .expect("effect-start barrier lock should work") =
        Some((Arc::clone(&started), Arc::clone(&release)));
    let worker = Arc::clone(&fixture.worker);
    let peer = fixture.peer.clone();
    let session_id = fixture.session_id.clone();
    let fence = fixture.fence.clone();
    let runner = thread::spawn(move || {
        worker.run_next_action(&peer, &session_id, &fence, SessionTime::new(3))
    });
    started.wait();

    let (closed_tx, closed_rx) = mpsc::channel();
    let worker = Arc::clone(&fixture.worker);
    let peer = fixture.peer.clone();
    let session_id = fixture.session_id.clone();
    let fence = fixture.fence.clone();
    let closer = thread::spawn(move || {
        closed_tx
            .send(worker.close_session(&peer, &session_id, &fence, SessionTime::new(4)))
            .expect("test receiver remains");
    });
    assert!(
        closed_rx.recv_timeout(Duration::from_millis(50)).is_err(),
        "close should wait for the admitted effect gate"
    );
    let (queried_tx, queried_rx) = mpsc::channel();
    let worker = Arc::clone(&fixture.worker);
    let peer = fixture.peer.clone();
    let session_id = fixture.session_id.clone();
    let fence = fixture.fence.clone();
    let query_action_id = action_id.clone();
    let query = thread::spawn(move || {
        queried_tx
            .send(worker.get_action(&peer, &session_id, &query_action_id, &fence))
            .expect("test receiver remains");
    });
    let query_while_effect_blocked = queried_rx.recv_timeout(Duration::from_millis(50)).ok();
    let query_completed_while_effect_blocked = query_while_effect_blocked.is_some();
    release.wait();

    let queried = match query_while_effect_blocked {
        Some(queried) => queried,
        None => queried_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("query should finish after the effect gate is released"),
    };
    query.join().expect("query should not panic");
    closer.join().expect("closer should not panic");
    closed_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("close should finish after effect completion")
        .expect("close should succeed");
    assert!(runner.join().expect("runner should not panic").is_err());
    assert!(
        query_completed_while_effect_blocked,
        "cleanup must not hold the session state lock while it waits on the driver"
    );
    assert_eq!(
        queried.expect("action query should succeed").status,
        browserd_worker::ActionStatus::OutcomeUnknown
    );
}

#[test]
fn expiry_waiting_on_an_admitted_effect_does_not_block_action_queries() {
    let fixture = Fixture::new();
    let payload = b"click-submit";
    let action_id = fixture.submit("effect-start-expiry", payload, fixture.proposal(payload));
    let approval_id = fixture
        .worker
        .approval_for_action(
            &fixture.peer,
            &fixture.session_id,
            &action_id,
            &fixture.fence,
        )
        .expect("approval should exist");
    fixture
        .worker
        .decide_approval(
            &fixture.peer,
            &fixture.session_id,
            &approval_id,
            &fixture.fence,
            ApprovalDecision::Approve,
            PrincipalId::new(),
            SessionTime::new(2),
        )
        .expect("approval should succeed");
    let started = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    *fixture
        .driver
        .effect_start_barriers
        .lock()
        .expect("effect-start barrier lock should work") =
        Some((Arc::clone(&started), Arc::clone(&release)));
    let worker = Arc::clone(&fixture.worker);
    let peer = fixture.peer.clone();
    let session_id = fixture.session_id.clone();
    let fence = fixture.fence.clone();
    let runner = thread::spawn(move || {
        worker.run_next_action(&peer, &session_id, &fence, SessionTime::new(3))
    });
    started.wait();
    for (key, request_hash, now) in [
        ("expiry-keepalive-1", [41; 32], 29_000),
        ("expiry-keepalive-2", [42; 32], 58_000),
    ] {
        fixture
            .worker
            .submit_action(
                &fixture.peer,
                fixture.requester.clone(),
                &fixture.session_id,
                &fixture.fence,
                key,
                request_hash,
                ActionKind::Mutating,
                None,
                None,
                Vec::new(),
                None,
                SessionTime::new(now),
            )
            .expect("activity should renew the idle deadline");
        fixture
            .worker
            .heartbeat(&fixture.peer, SessionTime::new(now))
            .expect("lease should be renewed beyond the absolute session deadline");
    }

    let (expired_tx, expired_rx) = mpsc::channel();
    let worker = Arc::clone(&fixture.worker);
    let peer = fixture.peer.clone();
    let expirer = thread::spawn(move || {
        expired_tx
            .send(worker.expire_due(&peer, SessionTime::new(60_001)))
            .expect("test receiver remains");
    });
    assert!(
        expired_rx.recv_timeout(Duration::from_millis(50)).is_err(),
        "expiry cleanup should wait for the admitted effect gate"
    );
    let (queried_tx, queried_rx) = mpsc::channel();
    let worker = Arc::clone(&fixture.worker);
    let peer = fixture.peer.clone();
    let session_id = fixture.session_id.clone();
    let fence = fixture.fence.clone();
    let query_action_id = action_id.clone();
    let query = thread::spawn(move || {
        queried_tx
            .send(worker.get_action(&peer, &session_id, &query_action_id, &fence))
            .expect("test receiver remains");
    });
    let query_while_effect_blocked = queried_rx.recv_timeout(Duration::from_millis(50)).ok();
    let query_completed_while_effect_blocked = query_while_effect_blocked.is_some();
    release.wait();

    let queried = match query_while_effect_blocked {
        Some(queried) => queried,
        None => queried_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("query should finish after the effect gate is released"),
    };
    query.join().expect("query should not panic");
    expirer.join().expect("expirer should not panic");
    assert_eq!(
        expired_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("expiry should finish after effect completion"),
        Ok(1)
    );
    assert!(runner.join().expect("runner should not panic").is_err());
    assert!(
        query_completed_while_effect_blocked,
        "expiry cleanup must not hold the session state lock while it waits on the driver"
    );
    assert_eq!(
        queried.expect("action query should succeed").status,
        browserd_worker::ActionStatus::OutcomeUnknown
    );
}

#[test]
fn stale_fence_close_during_inspection_does_not_revoke_the_valid_dispatch() {
    let fixture = Fixture::new();
    let payload = b"click-submit";
    let action_id = fixture.submit("inspection-stale-close", payload, fixture.proposal(payload));
    let approval_id = fixture
        .worker
        .approval_for_action(
            &fixture.peer,
            &fixture.session_id,
            &action_id,
            &fixture.fence,
        )
        .expect("approval should exist");
    fixture
        .worker
        .decide_approval(
            &fixture.peer,
            &fixture.session_id,
            &approval_id,
            &fixture.fence,
            ApprovalDecision::Approve,
            PrincipalId::new(),
            SessionTime::new(2),
        )
        .expect("approval should succeed");
    let started = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    *fixture
        .driver
        .inspection_barriers
        .lock()
        .expect("inspection barrier lock should work") =
        Some((Arc::clone(&started), Arc::clone(&release)));
    let worker = Arc::clone(&fixture.worker);
    let peer = fixture.peer.clone();
    let session_id = fixture.session_id.clone();
    let fence = fixture.fence.clone();
    let runner = thread::spawn(move || {
        worker.run_next_action(&peer, &session_id, &fence, SessionTime::new(3))
    });
    started.wait();
    let stale = OwnershipFence::new(
        fixture.fence.worker_id().clone(),
        fixture.fence.worker_epoch(),
        fixture.fence.placement_version() + 1,
        fixture.fence.session_incarnation(),
    );
    assert_eq!(
        fixture.worker.close_session(
            &fixture.peer,
            &fixture.session_id,
            &stale,
            SessionTime::new(4),
        ),
        Err(WorkerError::StaleFence)
    );
    release.wait();

    let completed = runner
        .join()
        .expect("runner should not panic")
        .expect("stale close must not revoke valid action ownership")
        .expect("action should be returned");
    assert_eq!(completed.status, browserd_worker::ActionStatus::Succeeded);
    assert_eq!(fixture.driver.executions.load(Ordering::Acquire), 1);
    assert_eq!(
        fixture
            .worker
            .get_action(
                &fixture.peer,
                &fixture.session_id,
                &action_id,
                &fixture.fence,
            )
            .expect("completed action should remain queryable")
            .status,
        browserd_worker::ActionStatus::Succeeded
    );
}

#[test]
fn blocked_page_driver_call_does_not_hold_the_session_state_mutex() {
    let fixture = Fixture::new();
    let close_started = Arc::new(Barrier::new(2));
    let release_close = Arc::new(Barrier::new(2));
    *fixture
        .driver
        .page_close_barriers
        .lock()
        .expect("page close barrier lock should work") =
        Some((Arc::clone(&close_started), Arc::clone(&release_close)));

    let close_worker = Arc::clone(&fixture.worker);
    let close_peer = fixture.peer.clone();
    let close_session_id = fixture.session_id.clone();
    let close_page_id = fixture.page_id.clone();
    let close_fence = fixture.fence.clone();
    let close_handle = thread::spawn(move || {
        close_worker.close_page(
            &close_peer,
            &close_session_id,
            &close_page_id,
            &close_fence,
            SessionTime::new(2),
        )
    });
    close_started.wait();

    let query_worker = Arc::clone(&fixture.worker);
    let query_peer = fixture.peer.clone();
    let query_session_id = fixture.session_id.clone();
    let query_fence = fixture.fence.clone();
    let (query_tx, query_rx) = mpsc::channel();
    let query_handle = thread::spawn(move || {
        query_tx
            .send(query_worker.get_session(&query_peer, &query_session_id, &query_fence))
            .expect("query receiver should remain available");
    });

    let query_while_driver_blocked = query_rx
        .recv_timeout(Duration::from_millis(100))
        .expect("session query must not wait for a blocked page driver call");
    assert!(query_while_driver_blocked.is_ok());
    assert_eq!(
        fixture.worker.submit_action(
            &fixture.peer,
            fixture.requester.clone(),
            &fixture.session_id,
            &fixture.fence,
            "closing-page-action",
            [51; 32],
            ActionKind::Mutating,
            None,
            Some(fixture.page_id.clone()),
            b"must-not-bind-closing-page".to_vec(),
            None,
            SessionTime::new(3),
        ),
        Err(WorkerError::InvalidActionTransition),
        "a short in-memory reservation must replace the released session mutex"
    );

    release_close.wait();
    close_handle
        .join()
        .expect("close thread should not panic")
        .expect("page should close");
    query_handle.join().expect("query thread should not panic");
}

#[test]
fn blocked_page_creation_and_activation_do_not_hold_the_session_state_mutex() {
    {
        let fixture = Fixture::new();
        let call_started = Arc::new(Barrier::new(2));
        let release_call = Arc::new(Barrier::new(2));
        *fixture
            .driver
            .page_create_barriers
            .lock()
            .expect("page create barrier lock should work") =
            Some((Arc::clone(&call_started), Arc::clone(&release_call)));

        let call_worker = Arc::clone(&fixture.worker);
        let call_peer = fixture.peer.clone();
        let call_session_id = fixture.session_id.clone();
        let call_fence = fixture.fence.clone();
        let call_handle = thread::spawn(move || {
            call_worker.create_page(
                &call_peer,
                &call_session_id,
                &call_fence,
                SessionTime::new(2),
            )
        });
        call_started.wait();

        let query_worker = Arc::clone(&fixture.worker);
        let query_peer = fixture.peer.clone();
        let query_session_id = fixture.session_id.clone();
        let query_fence = fixture.fence.clone();
        let (query_tx, query_rx) = mpsc::channel();
        let query_handle = thread::spawn(move || {
            query_tx
                .send(query_worker.get_session(&query_peer, &query_session_id, &query_fence))
                .expect("query receiver should remain available");
        });
        let query_completed = query_rx.recv_timeout(Duration::from_millis(100)).is_ok();
        release_call.wait();
        call_handle
            .join()
            .expect("create thread should not panic")
            .expect("page should be created");
        query_handle.join().expect("query thread should not panic");
        assert!(
            query_completed,
            "session query must not wait for a blocked page create call"
        );
    }

    {
        let fixture = Fixture::new();
        let call_started = Arc::new(Barrier::new(2));
        let release_call = Arc::new(Barrier::new(2));
        *fixture
            .driver
            .page_activation_barriers
            .lock()
            .expect("page activation barrier lock should work") =
            Some((Arc::clone(&call_started), Arc::clone(&release_call)));

        let call_worker = Arc::clone(&fixture.worker);
        let call_peer = fixture.peer.clone();
        let call_session_id = fixture.session_id.clone();
        let call_page_id = fixture.page_id.clone();
        let call_fence = fixture.fence.clone();
        let call_handle = thread::spawn(move || {
            call_worker.activate_page(
                &call_peer,
                &call_session_id,
                &call_page_id,
                &call_fence,
                SessionTime::new(2),
            )
        });
        call_started.wait();

        let query_worker = Arc::clone(&fixture.worker);
        let query_peer = fixture.peer.clone();
        let query_session_id = fixture.session_id.clone();
        let query_fence = fixture.fence.clone();
        let (query_tx, query_rx) = mpsc::channel();
        let query_handle = thread::spawn(move || {
            query_tx
                .send(query_worker.get_session(&query_peer, &query_session_id, &query_fence))
                .expect("query receiver should remain available");
        });
        let query_completed = query_rx.recv_timeout(Duration::from_millis(100)).is_ok();
        release_call.wait();
        call_handle
            .join()
            .expect("activation thread should not panic")
            .expect("page should be activated");
        query_handle.join().expect("query thread should not panic");
        assert!(
            query_completed,
            "session query must not wait for a blocked page activation call"
        );
    }
}
