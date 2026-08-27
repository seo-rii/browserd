#![allow(clippy::expect_used)]

use std::collections::VecDeque;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::Duration;

use browserd_actions::{
    ActionJournalLimits, ActionKind, ActionLedger, FileActionJournal, LedgerSession,
};
use browserd_core::{
    ActionId, ActionState, IsolationProfile, PageId, PrincipalId, SessionId, TenantId, WorkerId,
};
use browserd_policy::{
    ActionArgumentsHash, ActionType, ApprovalDecision, ApprovalError, CanonicalActionProposal,
    CredentialRefsHash, Origin,
};
use browserd_session::{
    LeasePolicy, OwnershipFence, SessionExecution, SessionTime, SessionTimeoutPolicy,
};
use browserd_worker::{
    ActionApprovalRequirement, ActionExecutionResult, ActionJournalConfig, ApprovedActionError,
    ArtifactStoreReceipt, ArtifactStoreRequest, AuthenticatedPeer, ChromiumDriver,
    CreateSessionCommand, CreateSessionOutcome, DependencyError, InternalEndpoint,
    LiveApprovalContext, SandboxClient, WorkerClock, WorkerConfig, WorkerControlPlane, WorkerError,
};
use tempfile::TempDir;

#[derive(Default)]
struct RecordingDriver {
    executions: AtomicUsize,
    payloads: Mutex<Vec<Vec<u8>>>,
    results: Mutex<VecDeque<ActionExecutionResult>>,
    execution_barriers: Mutex<Option<(Arc<Barrier>, Arc<Barrier>)>>,
    approved_effect_gate: Mutex<()>,
}

impl ChromiumDriver for RecordingDriver {
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
        Ok(PageId::new())
    }

    fn close_page(
        &self,
        _session_id: &SessionId,
        _page_id: &PageId,
    ) -> Result<(), DependencyError> {
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
        Ok(())
    }

    fn execute_action(
        &self,
        _session_id: &SessionId,
        _page_id: Option<&PageId>,
        payload: &[u8],
    ) -> ActionExecutionResult {
        self.executions.fetch_add(1, Ordering::AcqRel);
        self.payloads
            .lock()
            .expect("payload lock should work")
            .push(payload.to_vec());
        let barriers = self
            .execution_barriers
            .lock()
            .expect("barrier lock should work")
            .clone();
        if let Some((started, release)) = barriers {
            started.wait();
            release.wait();
        }
        self.results
            .lock()
            .expect("result lock should work")
            .pop_front()
            .unwrap_or_else(|| ActionExecutionResult::Succeeded(payload.to_vec()))
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
            current_origin: Origin::parse("https://example.test/").expect("origin should be valid"),
            url_revision: 1,
            node_ref: None,
            node_valid: true,
            resolved_ips: vec![],
            credential_refs: vec![],
            chromium_build: "sha256:test".to_owned(),
            effective_isolation: IsolationProfile::SharedContext,
        })
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
        let _gate = self
            .approved_effect_gate
            .lock()
            .map_err(|_| ApprovedActionError::Unavailable)?;
        let observed = self
            .inspect_approval_context(session_id, page_id, proposal)
            .map_err(|_| ApprovedActionError::Unavailable)?;
        if let Some(reason) = inspected.stale_reason(&observed) {
            return Err(ApprovedActionError::ApprovalStale(reason));
        }
        authorize_and_commit(&observed)?;
        Ok(self.execute_action(session_id, Some(page_id), payload))
    }

    fn cancel_action(
        &self,
        _session_id: &SessionId,
        _action_id: &ActionId,
    ) -> Result<bool, DependencyError> {
        let _gate = self
            .approved_effect_gate
            .lock()
            .map_err(|_| DependencyError::Unavailable)?;
        Ok(true)
    }
}

struct JournalCheckingSandbox {
    journal_root: PathBuf,
    saw_journal_before_provision: AtomicBool,
    fail_provision: AtomicBool,
}

impl SandboxClient for JournalCheckingSandbox {
    fn qualify(&self) -> Result<(), DependencyError> {
        Ok(())
    }

    fn provision(
        &self,
        session_id: &SessionId,
        _fence: &OwnershipFence,
    ) -> Result<(), DependencyError> {
        let path = self.journal_root.join(format!("{session_id}.wal"));
        let initialized = fs::metadata(path).is_ok_and(|metadata| metadata.len() > 0);
        self.saw_journal_before_provision
            .store(initialized, Ordering::Release);
        if initialized && !self.fail_provision.load(Ordering::Acquire) {
            Ok(())
        } else {
            Err(DependencyError::Unavailable)
        }
    }

    fn cleanup(
        &self,
        _session_id: &SessionId,
        _reason: browserd_sandbox::CleanupReason,
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

type TestWorker = WorkerControlPlane<RecordingDriver, JournalCheckingSandbox>;

struct TestClock;

impl WorkerClock for TestClock {
    fn now(&self) -> Result<SessionTime, WorkerError> {
        Ok(SessionTime::new(0))
    }
}

fn worker(
    max_records: usize,
    queue_capacity: usize,
) -> (
    Arc<TestWorker>,
    AuthenticatedPeer,
    Arc<RecordingDriver>,
    Arc<JournalCheckingSandbox>,
    TempDir,
) {
    let journal_root = tempfile::tempdir().expect("journal directory should be created");
    let journal = ActionJournalConfig::new(
        journal_root.path(),
        ActionJournalLimits::new(4 * 1024, max_records, 4 * 1024 * 1024),
    )
    .expect("journal configuration should be valid");
    let peer = AuthenticatedPeer::new("gateway-internal").expect("peer should be valid");
    let config = WorkerConfig::new(
        WorkerId::new("worker-durable-test").expect("worker ID should be valid"),
        9,
        InternalEndpoint::loopback(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9123))
            .expect("endpoint should be valid"),
        peer.clone(),
        4,
        queue_capacity,
        LeasePolicy::new(Duration::from_secs(30), Duration::from_secs(1))
            .expect("lease policy should be valid"),
        SessionTimeoutPolicy::new(Duration::from_secs(60), Duration::from_secs(30))
            .expect("timeout policy should be valid"),
        Duration::from_millis(5),
        journal,
    )
    .expect("worker configuration should be valid");
    let driver = Arc::new(RecordingDriver::default());
    let sandbox = Arc::new(JournalCheckingSandbox {
        journal_root: journal_root.path().to_path_buf(),
        saw_journal_before_provision: AtomicBool::new(false),
        fail_provision: AtomicBool::new(false),
    });
    let worker = Arc::new(WorkerControlPlane::new_with_clock(
        config,
        Arc::clone(&driver),
        Arc::clone(&sandbox),
        Arc::new(TestClock),
    ));
    (worker, peer, driver, sandbox, journal_root)
}

struct TestSession {
    outcome: CreateSessionOutcome,
    tenant_id: TenantId,
    requester: PrincipalId,
}

impl std::ops::Deref for TestSession {
    type Target = CreateSessionOutcome;

    fn deref(&self) -> &Self::Target {
        &self.outcome
    }
}

fn create_session(worker: &TestWorker, peer: &AuthenticatedPeer) -> TestSession {
    let tenant_id = TenantId::new();
    let outcome = worker
        .create_session(
            peer,
            CreateSessionCommand {
                tenant_id: tenant_id.clone(),
                idempotency_key: "create".to_owned(),
                canonical_request_hash: [1; 32],
                placement_version: 1,
                session_incarnation: 1,
            },
            SessionTime::new(0),
        )
        .expect("session should be created");
    TestSession {
        outcome,
        tenant_id,
        requester: PrincipalId::new(),
    }
}

fn submit(
    worker: &TestWorker,
    peer: &AuthenticatedPeer,
    session: &TestSession,
    key: &str,
    payload: &[u8],
    requires_approval: bool,
) -> ActionId {
    let approval = requires_approval.then(|| {
        ActionApprovalRequirement::new(
            CanonicalActionProposal::new(
                session.tenant_id.clone(),
                session.requester.clone(),
                session.session_id.clone(),
                session.fence.session_incarnation(),
                session.primary_page_id.clone(),
                1,
                1,
                Origin::parse("https://example.test/").expect("origin should be valid"),
                1,
                ActionType::Click,
                ActionArgumentsHash::digest(payload),
                None,
                CredentialRefsHash::digest(std::iter::empty()),
                6,
            ),
            ActionType::Click,
            true,
        )
    });
    worker
        .submit_action(
            peer,
            session.requester.clone(),
            &session.session_id,
            &session.fence,
            key,
            [payload.len() as u8; 32],
            ActionKind::Mutating,
            None,
            requires_approval.then(|| session.primary_page_id.clone()),
            payload.to_vec(),
            approval,
            SessionTime::new(1),
        )
        .expect("action should be submitted")
}

#[test]
fn session_journal_exists_before_sandbox_provisioning() {
    let (worker, peer, _driver, sandbox, _journal_root) = worker(64, 8);

    create_session(&worker, &peer);

    assert!(sandbox.saw_journal_before_provision.load(Ordering::Acquire));
}

#[test]
fn action_journal_configuration_rejects_missing_storage_and_invalid_limits() {
    let root = tempfile::tempdir().expect("temporary root should be created");
    assert!(matches!(
        ActionJournalConfig::new(root.path().join("missing"), ActionJournalLimits::default()),
        Err(WorkerError::InvalidConfiguration)
    ));
    assert!(matches!(
        ActionJournalConfig::new(root.path(), ActionJournalLimits::new(0, 1, 4 * 1024)),
        Err(WorkerError::InvalidConfiguration)
    ));
}

#[test]
fn readiness_drops_when_action_journal_storage_disappears() {
    let (worker, _peer, _driver, _sandbox, journal_root) = worker(64, 8);
    assert!(worker.is_ready());
    fs::remove_dir(journal_root.path()).expect("empty journal directory should be removable");

    assert!(!worker.is_ready());
}

#[test]
fn failed_session_provisioning_removes_the_unused_journal() {
    let (worker, peer, _driver, sandbox, journal_root) = worker(64, 8);
    sandbox.fail_provision.store(true, Ordering::Release);

    assert_eq!(
        worker.create_session(
            &peer,
            CreateSessionCommand {
                tenant_id: TenantId::new(),
                idempotency_key: "failed-provision".to_owned(),
                canonical_request_hash: [10; 32],
                placement_version: 1,
                session_incarnation: 1,
            },
            SessionTime::new(0),
        ),
        Err(WorkerError::DependencyUnavailable)
    );
    assert_eq!(
        fs::read_dir(journal_root.path())
            .expect("journal directory should remain readable")
            .count(),
        0
    );
}

#[test]
fn failed_dispatch_intent_never_calls_the_browser_driver() {
    let (worker, peer, driver, _sandbox, _journal_root) = worker(4, 8);
    let session = create_session(&worker, &peer);
    let action_id = submit(&worker, &peer, &session, "intent-full", b"click", false);

    assert_eq!(
        worker.run_next_action(
            &peer,
            &session.session_id,
            &session.fence,
            SessionTime::new(2),
        ),
        Err(WorkerError::DurabilityUnavailable)
    );
    assert_eq!(driver.executions.load(Ordering::Acquire), 0);
    assert_eq!(
        worker
            .get_action(&peer, &session.session_id, &action_id, &session.fence)
            .expect("action should remain queryable")
            .status,
        browserd_worker::ActionStatus::Queued
    );
    assert_eq!(
        worker
            .cancel_action(
                &peer,
                &session.session_id,
                &action_id,
                &session.fence,
                SessionTime::new(3),
            )
            .expect("the reserved terminal slot should remain available")
            .status,
        browserd_worker::ActionStatus::CancelledBeforeDispatch
    );
}

#[test]
fn partial_submission_is_compensated_and_remains_idempotently_queryable() {
    let (worker, peer, driver, _sandbox, _journal_root) = worker(2, 8);
    let session = create_session(&worker, &peer);
    let submit = || {
        worker.submit_action(
            &peer,
            session.requester.clone(),
            &session.session_id,
            &session.fence,
            "partial",
            [4; 32],
            ActionKind::Mutating,
            None,
            None,
            b"partial".to_vec(),
            None,
            SessionTime::new(1),
        )
    };

    assert_eq!(submit(), Err(WorkerError::DurabilityUnavailable));
    let action_id = submit().expect("retry should return the durably compensated action");
    assert_eq!(
        worker
            .get_action(&peer, &session.session_id, &action_id, &session.fence)
            .expect("compensated action should remain queryable")
            .status,
        browserd_worker::ActionStatus::CancelledBeforeDispatch
    );
    assert_eq!(driver.executions.load(Ordering::Acquire), 0);
}

#[test]
fn pending_approval_at_queue_head_blocks_later_sequence() {
    let (worker, peer, driver, _sandbox, _journal_root) = worker(64, 8);
    let session = create_session(&worker, &peer);
    let first = submit(&worker, &peer, &session, "first", b"first", true);
    let second = submit(&worker, &peer, &session, "second", b"second", false);
    assert_eq!(
        worker
            .get_action(&peer, &session.session_id, &first, &session.fence)
            .expect("first action should be queryable")
            .action_sequence
            .get(),
        1
    );
    assert_eq!(
        worker
            .get_action(&peer, &session.session_id, &second, &session.fence)
            .expect("second action should be queryable")
            .action_sequence
            .get(),
        2
    );

    assert_eq!(
        worker
            .run_next_action(
                &peer,
                &session.session_id,
                &session.fence,
                SessionTime::new(2),
            )
            .expect("blocked queue should be a normal condition"),
        None
    );
    assert_eq!(driver.executions.load(Ordering::Acquire), 0);

    let approval_id = worker
        .approval_for_action(&peer, &session.session_id, &first, &session.fence)
        .expect("approval should exist");
    worker
        .decide_approval(
            &peer,
            &session.session_id,
            &approval_id,
            &session.fence,
            ApprovalDecision::Approve,
            PrincipalId::new(),
            SessionTime::new(3),
        )
        .expect("approval should succeed");
    for now in [4, 5] {
        assert!(
            worker
                .run_next_action(
                    &peer,
                    &session.session_id,
                    &session.fence,
                    SessionTime::new(now),
                )
                .expect("queued action should run")
                .is_some()
        );
    }
    assert_eq!(
        driver
            .payloads
            .lock()
            .expect("payload lock should work")
            .as_slice(),
        [b"first".to_vec(), b"second".to_vec()]
    );
}

#[test]
fn pending_approval_expires_on_its_own_deadline_without_dispatch() {
    let (worker, peer, driver, _sandbox, _journal_root) = worker(64, 8);
    let session = create_session(&worker, &peer);
    let action_id = submit(&worker, &peer, &session, "approval-timeout", b"click", true);
    let approval_id = worker
        .approval_for_action(&peer, &session.session_id, &action_id, &session.fence)
        .expect("approval should exist");

    assert_eq!(worker.expire_due(&peer, SessionTime::new(5)), Ok(0));
    assert_eq!(
        worker
            .get_action(&peer, &session.session_id, &action_id, &session.fence,)
            .expect("pending action should remain queryable")
            .status,
        browserd_worker::ActionStatus::PendingApproval
    );
    assert_eq!(worker.expire_due(&peer, SessionTime::new(6)), Ok(0));
    assert_eq!(
        worker
            .get_action(&peer, &session.session_id, &action_id, &session.fence,)
            .expect("expired action should remain queryable")
            .status,
        browserd_worker::ActionStatus::FailedKnown
    );
    assert_eq!(driver.executions.load(Ordering::Acquire), 0);
    assert_eq!(
        worker.decide_approval(
            &peer,
            &session.session_id,
            &approval_id,
            &session.fence,
            ApprovalDecision::Approve,
            PrincipalId::new(),
            SessionTime::new(7),
        ),
        Err(WorkerError::ApprovalPolicy(ApprovalError::ApprovalExpired))
    );
}

#[test]
fn concurrent_runners_dispatch_one_action_exactly_once() {
    let (worker, peer, driver, _sandbox, _journal_root) = worker(64, 8);
    let session = create_session(&worker, &peer);
    submit(&worker, &peer, &session, "once", b"once", false);
    let mut runners = Vec::new();
    for now in [2, 3] {
        let worker = Arc::clone(&worker);
        let peer = peer.clone();
        let session_id = session.session_id.clone();
        let fence = session.fence.clone();
        runners.push(thread::spawn(move || {
            worker.run_next_action(&peer, &session_id, &fence, SessionTime::new(now))
        }));
    }
    let results = runners
        .into_iter()
        .map(|runner| runner.join().expect("runner should not panic"))
        .collect::<Vec<_>>();

    assert_eq!(driver.executions.load(Ordering::Acquire), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| result.as_ref().is_ok_and(Option::is_some))
            .count(),
        1
    );
}

#[test]
fn confirmed_cancellation_wins_a_race_with_the_driver_result() {
    let (worker, peer, driver, _sandbox, _journal_root) = worker(64, 8);
    let session = create_session(&worker, &peer);
    let action_id = submit(&worker, &peer, &session, "cancel-race", b"click", false);
    let started = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    *driver
        .execution_barriers
        .lock()
        .expect("barrier lock should work") = Some((Arc::clone(&started), Arc::clone(&release)));
    let runner = {
        let worker = Arc::clone(&worker);
        let peer = peer.clone();
        let session_id = session.session_id.clone();
        let fence = session.fence.clone();
        thread::spawn(move || {
            worker.run_next_action(&peer, &session_id, &fence, SessionTime::new(2))
        })
    };
    started.wait();

    let cancelled = worker
        .cancel_action(
            &peer,
            &session.session_id,
            &action_id,
            &session.fence,
            SessionTime::new(3),
        )
        .expect("driver should confirm cancellation");
    assert_eq!(
        cancelled.status,
        browserd_worker::ActionStatus::CancelledConfirmed
    );
    release.wait();
    assert!(runner.join().is_ok_and(|result| result.is_err()));

    assert_eq!(
        worker
            .get_action(&peer, &session.session_id, &action_id, &session.fence,)
            .expect("cancelled action should remain queryable")
            .status,
        browserd_worker::ActionStatus::CancelledConfirmed
    );
}

#[test]
fn confirmed_cancellation_after_newer_heartbeat_commits_consistently() {
    let (worker, peer, driver, _sandbox, _journal_root) = worker(64, 8);
    let session = create_session(&worker, &peer);
    let action_id = submit(
        &worker,
        &peer,
        &session,
        "cancel-clock-race",
        b"click",
        false,
    );
    let started = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    *driver
        .execution_barriers
        .lock()
        .expect("barrier lock should work") = Some((Arc::clone(&started), Arc::clone(&release)));
    let runner = {
        let worker = Arc::clone(&worker);
        let peer = peer.clone();
        let session_id = session.session_id.clone();
        let fence = session.fence.clone();
        thread::spawn(move || {
            worker.run_next_action(&peer, &session_id, &fence, SessionTime::new(2))
        })
    };
    started.wait();
    worker
        .heartbeat(&peer, SessionTime::new(90))
        .expect("heartbeat should advance session time");

    assert_eq!(
        worker
            .cancel_action(
                &peer,
                &session.session_id,
                &action_id,
                &session.fence,
                SessionTime::new(3),
            )
            .expect("confirmed cancellation should use current session time")
            .status,
        browserd_worker::ActionStatus::CancelledConfirmed
    );
    release.wait();
    assert!(runner.join().is_ok_and(|result| result.is_err()));
    assert_eq!(
        worker
            .get_action(&peer, &session.session_id, &action_id, &session.fence,)
            .expect("cancelled action should remain queryable")
            .status,
        browserd_worker::ActionStatus::CancelledConfirmed
    );
}

#[test]
fn driver_result_after_newer_heartbeat_commits_consistently() {
    let (worker, peer, driver, _sandbox, _journal_root) = worker(64, 8);
    let session = create_session(&worker, &peer);
    let action_id = submit(&worker, &peer, &session, "clock-race", b"click", false);
    let started = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    *driver
        .execution_barriers
        .lock()
        .expect("barrier lock should work") = Some((Arc::clone(&started), Arc::clone(&release)));
    let runner = {
        let worker = Arc::clone(&worker);
        let peer = peer.clone();
        let session_id = session.session_id.clone();
        let fence = session.fence.clone();
        thread::spawn(move || {
            worker.run_next_action(&peer, &session_id, &fence, SessionTime::new(2))
        })
    };
    started.wait();
    worker
        .heartbeat(&peer, SessionTime::new(90))
        .expect("heartbeat should advance session time");
    release.wait();

    assert_eq!(
        runner
            .join()
            .expect("runner should not panic")
            .expect("driver result should commit")
            .expect("one action should complete")
            .status,
        browserd_worker::ActionStatus::Succeeded
    );
    assert_eq!(
        worker
            .get_action(&peer, &session.session_id, &action_id, &session.fence,)
            .expect("completed action should be queryable")
            .status,
        browserd_worker::ActionStatus::Succeeded
    );
    assert_eq!(
        worker
            .get_session(&peer, &session.session_id, &session.fence)
            .expect("session should remain queryable")
            .execution,
        SessionExecution::Idle
    );
}

#[test]
fn stale_cancel_time_is_rejected_before_durable_mutation() {
    let (worker, peer, _driver, _sandbox, journal_root) = worker(64, 8);
    let tenant_id = TenantId::new();
    let outcome = worker
        .create_session(
            &peer,
            CreateSessionCommand {
                tenant_id: tenant_id.clone(),
                idempotency_key: "stale-cancel-session".to_owned(),
                canonical_request_hash: [8; 32],
                placement_version: 1,
                session_incarnation: 1,
            },
            SessionTime::new(0),
        )
        .expect("session should be created");
    let session = TestSession {
        outcome,
        tenant_id: tenant_id.clone(),
        requester: PrincipalId::new(),
    };
    let action_id = submit(&worker, &peer, &session, "stale-cancel", b"click", false);
    worker
        .heartbeat(&peer, SessionTime::new(90))
        .expect("heartbeat should advance session time");

    assert!(
        worker
            .cancel_action(
                &peer,
                &session.session_id,
                &action_id,
                &session.fence,
                SessionTime::new(3),
            )
            .is_err()
    );
    drop(worker);

    let journal = FileActionJournal::open(
        journal_root
            .path()
            .join(format!("{}.wal", session.session_id)),
        ActionJournalLimits::new(4 * 1024, 64, 4 * 1024 * 1024),
    )
    .expect("session journal should reopen");
    let ledger = ActionLedger::recover(
        LedgerSession::new(
            tenant_id,
            session.session_id.clone(),
            session.fence.as_placement_fence(),
        ),
        Arc::new(journal),
    )
    .expect("session journal should recover");
    assert_eq!(
        ledger
            .snapshot(session.fence.as_placement_fence(), &action_id)
            .expect("action should recover")
            .state(),
        ActionState::ReadyToDispatch
    );
}

#[test]
fn stale_resolution_time_cannot_replace_durable_audit_evidence() {
    let (worker, peer, driver, _sandbox, journal_root) = worker(64, 8);
    let tenant_id = TenantId::new();
    let outcome = worker
        .create_session(
            &peer,
            CreateSessionCommand {
                tenant_id: tenant_id.clone(),
                idempotency_key: "stale-resolution-session".to_owned(),
                canonical_request_hash: [9; 32],
                placement_version: 1,
                session_incarnation: 1,
            },
            SessionTime::new(0),
        )
        .expect("session should be created");
    let session = TestSession {
        outcome,
        tenant_id: tenant_id.clone(),
        requester: PrincipalId::new(),
    };
    driver
        .results
        .lock()
        .expect("result lock should work")
        .push_back(ActionExecutionResult::OutcomeUnknown);
    let action_id = submit(
        &worker,
        &peer,
        &session,
        "stale-resolution",
        b"click",
        false,
    );
    worker
        .run_next_action(
            &peer,
            &session.session_id,
            &session.fence,
            SessionTime::new(2),
        )
        .expect("action should run")
        .expect("action should complete as unknown");
    worker
        .heartbeat(&peer, SessionTime::new(90))
        .expect("heartbeat should advance session time");
    let stale_principal = PrincipalId::new();
    assert!(
        worker
            .resolve_action(
                &peer,
                &session.session_id,
                &action_id,
                &session.fence,
                browserd_actions::ResolutionKind::ConfirmedExecuted,
                stale_principal,
                "stale evidence",
                SessionTime::new(3),
            )
            .is_err()
    );
    let accepted_principal = PrincipalId::new();
    let resolved = worker
        .resolve_action(
            &peer,
            &session.session_id,
            &action_id,
            &session.fence,
            browserd_actions::ResolutionKind::ConfirmedExecuted,
            accepted_principal.clone(),
            "fresh evidence",
            SessionTime::new(91),
        )
        .expect("fresh resolution should succeed");
    assert_eq!(
        resolved
            .resolution
            .as_ref()
            .map(browserd_actions::ResolutionAnnotation::resolved_by),
        Some(&accepted_principal)
    );
    drop(worker);

    let journal = FileActionJournal::open(
        journal_root
            .path()
            .join(format!("{}.wal", session.session_id)),
        ActionJournalLimits::new(4 * 1024, 64, 4 * 1024 * 1024),
    )
    .expect("session journal should reopen");
    let ledger = ActionLedger::recover(
        LedgerSession::new(
            tenant_id,
            session.session_id.clone(),
            session.fence.as_placement_fence(),
        ),
        Arc::new(journal),
    )
    .expect("session journal should recover");
    let durable = ledger
        .snapshot(session.fence.as_placement_fence(), &action_id)
        .expect("resolved action should recover");
    assert_eq!(
        durable
            .resolution()
            .map(browserd_actions::ResolutionAnnotation::resolved_by),
        Some(&accepted_principal)
    );
    assert_eq!(
        durable
            .resolution()
            .map(browserd_actions::ResolutionAnnotation::basis),
        Some("fresh evidence")
    );
}

#[test]
fn browser_mutations_cannot_bypass_the_running_action_owner() {
    let (worker, peer, driver, _sandbox, _journal_root) = worker(64, 8);
    let session = create_session(&worker, &peer);
    submit(&worker, &peer, &session, "mutation-owner", b"click", false);
    let started = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    *driver
        .execution_barriers
        .lock()
        .expect("barrier lock should work") = Some((Arc::clone(&started), Arc::clone(&release)));
    let runner = {
        let worker = Arc::clone(&worker);
        let peer = peer.clone();
        let session_id = session.session_id.clone();
        let fence = session.fence.clone();
        thread::spawn(move || {
            worker.run_next_action(&peer, &session_id, &fence, SessionTime::new(2))
        })
    };
    started.wait();

    let activate = worker.activate_page(
        &peer,
        &session.session_id,
        &session.primary_page_id,
        &session.fence,
        SessionTime::new(3),
    );
    let create = worker.create_page(
        &peer,
        &session.session_id,
        &session.fence,
        SessionTime::new(3),
    );
    let close = worker.close_page(
        &peer,
        &session.session_id,
        &session.primary_page_id,
        &session.fence,
        SessionTime::new(3),
    );
    release.wait();
    assert!(
        runner
            .join()
            .is_ok_and(|result| result.is_ok_and(|snapshot| snapshot.is_some()))
    );

    assert_eq!(activate, Err(WorkerError::QueueFull));
    assert_eq!(create, Err(WorkerError::QueueFull));
    assert_eq!(close, Err(WorkerError::QueueFull));
}

#[test]
fn close_durably_terminalizes_every_action_that_never_dispatched() {
    let (worker, peer, _driver, _sandbox, journal_root) = worker(64, 8);
    let tenant_id = TenantId::new();
    let outcome = worker
        .create_session(
            &peer,
            CreateSessionCommand {
                tenant_id: tenant_id.clone(),
                idempotency_key: "durable-close".to_owned(),
                canonical_request_hash: [7; 32],
                placement_version: 1,
                session_incarnation: 1,
            },
            SessionTime::new(0),
        )
        .expect("session should be created");
    let session = TestSession {
        outcome,
        tenant_id: tenant_id.clone(),
        requester: PrincipalId::new(),
    };
    let queued = submit(&worker, &peer, &session, "queued", b"queued", false);
    let pending = submit(&worker, &peer, &session, "pending", b"pending", true);

    worker
        .close_session(
            &peer,
            &session.session_id,
            &session.fence,
            SessionTime::new(2),
        )
        .expect("session should close");
    drop(worker);

    let journal = FileActionJournal::open(
        journal_root
            .path()
            .join(format!("{}.wal", session.session_id)),
        ActionJournalLimits::new(4 * 1024, 64, 4 * 1024 * 1024),
    )
    .expect("closed session journal should reopen");
    let ledger = ActionLedger::recover(
        LedgerSession::new(
            tenant_id,
            session.session_id.clone(),
            session.fence.as_placement_fence(),
        ),
        Arc::new(journal),
    )
    .expect("closed session journal should recover");

    assert_eq!(
        ledger
            .snapshot(session.fence.as_placement_fence(), &queued)
            .expect("queued action should recover")
            .state(),
        ActionState::CancelledBeforeDispatch
    );
    assert_eq!(
        ledger
            .snapshot(session.fence.as_placement_fence(), &pending)
            .expect("pending action should recover")
            .state(),
        ActionState::FailedKnown
    );
}
