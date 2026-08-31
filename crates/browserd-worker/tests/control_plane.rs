use std::collections::VecDeque;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex, OnceLock};
use std::thread;
use std::time::Duration;

use browserd_actions::{ActionJournalLimits, ActionKind, ResolutionKind};
use browserd_artifacts::{ArtifactChecksum, ArtifactContentSource, ArtifactObjectGeneration};
use browserd_core::{
    ArtifactId, IsolationProfile, LeaseId, PageId, PrincipalId, TenantId, WorkerId,
};
use browserd_features::BuiltinFeature;
use browserd_policy::{
    ActionArgumentsHash, ActionType, ApprovalDecision, CanonicalActionProposal, CredentialRefsHash,
    Origin,
};
use browserd_session::{LeasePolicy, SessionLifecycle, SessionTime, SessionTimeoutPolicy};
use browserd_viewer::ViewerScopes;
use browserd_worker::{
    ActionApprovalRequirement, ActionExecutionResult, ActionJournalConfig, ActionStatus,
    ApprovedActionError, ArtifactScanVerdict, ArtifactStoreReceipt, ArtifactStoreRequest,
    ArtifactUpload, AuthenticatedPeer, ChromiumDriver, CreateSessionCommand, CreateSessionOutcome,
    DependencyError, InternalEndpoint, LiveApprovalContext, SandboxClient, WorkerArtifactLimits,
    WorkerClock, WorkerConfig, WorkerControlPlane, WorkerError,
};
use sha2::{Digest, Sha256};

struct TestClock;

impl WorkerClock for TestClock {
    fn now(&self) -> Result<SessionTime, WorkerError> {
        Ok(SessionTime::new(0))
    }
}

#[derive(Default)]
struct FakeDriver {
    qualified: bool,
    executions: Mutex<VecDeque<ActionExecutionResult>>,
    cleanup_count: Mutex<usize>,
    qualification_barriers: Mutex<Option<(Arc<Barrier>, Arc<Barrier>)>>,
    execution_barriers: Mutex<Option<(Arc<Barrier>, Arc<Barrier>)>>,
    approved_effect_gate: Mutex<()>,
}

impl ChromiumDriver for FakeDriver {
    fn qualify(&self) -> Result<(), DependencyError> {
        let barriers = self
            .qualification_barriers
            .lock()
            .map_err(|_| DependencyError::Unavailable)?
            .clone();
        if let Some((started, release)) = barriers {
            started.wait();
            release.wait();
        }
        if self.qualified {
            Ok(())
        } else {
            Err(DependencyError::Unavailable)
        }
    }

    fn create_context(
        &self,
        _session_id: &browserd_core::SessionId,
    ) -> Result<PageId, DependencyError> {
        Ok(PageId::new())
    }

    fn close_context(&self, _session_id: &browserd_core::SessionId) -> Result<(), DependencyError> {
        let _gate = self
            .approved_effect_gate
            .lock()
            .map_err(|_| DependencyError::Unavailable)?;
        let Ok(mut count) = self.cleanup_count.lock() else {
            return Err(DependencyError::Unavailable);
        };
        *count += 1;
        Ok(())
    }

    fn create_page(
        &self,
        _session_id: &browserd_core::SessionId,
    ) -> Result<PageId, DependencyError> {
        Ok(PageId::new())
    }

    fn close_page(
        &self,
        _session_id: &browserd_core::SessionId,
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
        _session_id: &browserd_core::SessionId,
        _page_id: &PageId,
    ) -> Result<(), DependencyError> {
        Ok(())
    }

    fn execute_action(
        &self,
        _session_id: &browserd_core::SessionId,
        _page_id: Option<&PageId>,
        _payload: &[u8],
    ) -> ActionExecutionResult {
        let barriers = self
            .execution_barriers
            .lock()
            .ok()
            .and_then(|barriers| barriers.clone());
        if let Some((started, release)) = barriers {
            started.wait();
            release.wait();
        }
        self.executions
            .lock()
            .ok()
            .and_then(|mut executions| executions.pop_front())
            .unwrap_or(ActionExecutionResult::Succeeded(Vec::new()))
    }

    fn inspect_approval_context(
        &self,
        _session_id: &browserd_core::SessionId,
        _page_id: &PageId,
        _proposal: &CanonicalActionProposal,
    ) -> Result<LiveApprovalContext, DependencyError> {
        Ok(LiveApprovalContext {
            target_incarnation: 1,
            frame_document_epoch: 1,
            current_origin: Origin::parse("https://example.test/")
                .map_err(|_| DependencyError::Rejected)?,
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
        session_id: &browserd_core::SessionId,
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
        _session_id: &browserd_core::SessionId,
        _action_id: &browserd_core::ActionId,
    ) -> Result<bool, DependencyError> {
        let _gate = self
            .approved_effect_gate
            .lock()
            .map_err(|_| DependencyError::Unavailable)?;
        Ok(true)
    }
}

#[derive(Default)]
struct FakeSandbox {
    qualified: bool,
    fail_provision: bool,
    fail_cleanup: bool,
    provision_count: Mutex<usize>,
    cleanup_count: Mutex<usize>,
    provision_barriers: Mutex<Option<(Arc<Barrier>, Arc<Barrier>)>>,
    artifact_barriers: Mutex<Option<(Arc<Barrier>, Arc<Barrier>)>>,
    artifact_store_count: AtomicUsize,
    corrupt_artifact_receipt: AtomicBool,
    wrong_artifact_key: AtomicBool,
    quarantine_artifact: AtomicBool,
}

impl SandboxClient for FakeSandbox {
    fn qualify(&self) -> Result<(), DependencyError> {
        if self.qualified {
            Ok(())
        } else {
            Err(DependencyError::Unavailable)
        }
    }

    fn provision(
        &self,
        _session_id: &browserd_core::SessionId,
        _fence: &browserd_session::OwnershipFence,
    ) -> Result<(), DependencyError> {
        let invocation = {
            let Ok(mut count) = self.provision_count.lock() else {
                return Err(DependencyError::Unavailable);
            };
            *count += 1;
            *count
        };
        if invocation == 1 {
            let barriers = self
                .provision_barriers
                .lock()
                .map_err(|_| DependencyError::Unavailable)?
                .clone();
            if let Some((started, release)) = barriers {
                started.wait();
                release.wait();
            }
        }
        if self.fail_provision {
            Err(DependencyError::Unavailable)
        } else {
            Ok(())
        }
    }

    fn cleanup(
        &self,
        _session_id: &browserd_core::SessionId,
        _reason: browserd_sandbox::CleanupReason,
    ) -> Result<(), DependencyError> {
        let Ok(mut count) = self.cleanup_count.lock() else {
            return Err(DependencyError::Unavailable);
        };
        *count += 1;
        if self.fail_cleanup {
            Err(DependencyError::Unavailable)
        } else {
            Ok(())
        }
    }

    fn heartbeat(&self, _worker_id: &WorkerId, _worker_epoch: u64) -> Result<(), DependencyError> {
        Ok(())
    }

    fn store_artifact(
        &self,
        request: &ArtifactStoreRequest,
    ) -> Result<ArtifactStoreReceipt, DependencyError> {
        self.artifact_store_count.fetch_add(1, Ordering::SeqCst);
        let barriers = self
            .artifact_barriers
            .lock()
            .map_err(|_| DependencyError::Unavailable)?
            .clone();
        if let Some((started, release)) = barriers {
            started.wait();
            release.wait();
        }
        let mut checksum: [u8; 32] = Sha256::digest(request.bytes()).into();
        if self.corrupt_artifact_receipt.load(Ordering::SeqCst) {
            checksum[0] ^= 0xff;
        }
        let key = if self.wrong_artifact_key.load(Ordering::SeqCst) {
            browserd_artifacts::ArtifactKey::new(
                request.key().tenant_id().clone(),
                request.key().session_id().clone(),
                ArtifactId::new(),
            )
        } else {
            request.key().clone()
        };
        let verdict = if self.quarantine_artifact.load(Ordering::SeqCst) {
            ArtifactScanVerdict::Quarantined
        } else {
            ArtifactScanVerdict::Clean
        };
        ArtifactStoreReceipt::new(
            key,
            u64::try_from(request.bytes().len()).map_err(|_| DependencyError::Rejected)?,
            ArtifactChecksum::new(checksum),
            request.declared_content_type(),
            ArtifactObjectGeneration::new([1; ArtifactObjectGeneration::LENGTH]),
            verdict,
        )
        .map_err(|_| DependencyError::Rejected)
    }
}

fn config(queue_capacity: usize) -> Option<WorkerConfig> {
    config_with_max_sessions(queue_capacity, 16)
}

fn config_with_max_sessions(queue_capacity: usize, max_sessions: usize) -> Option<WorkerConfig> {
    static JOURNAL_ROOT: OnceLock<Option<tempfile::TempDir>> = OnceLock::new();

    let worker_id = WorkerId::new("worker-test").ok()?;
    let endpoint =
        InternalEndpoint::loopback(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9010)).ok()?;
    let peer = AuthenticatedPeer::new("gateway-internal").ok()?;
    let lease = LeasePolicy::new(Duration::from_millis(100), Duration::from_millis(20)).ok()?;
    let timeout =
        SessionTimeoutPolicy::new(Duration::from_millis(1_000), Duration::from_millis(500)).ok()?;
    let root = JOURNAL_ROOT
        .get_or_init(|| tempfile::tempdir().ok())
        .as_ref()?;
    let journal_directory = root.path().join(LeaseId::new().to_string());
    fs::create_dir(&journal_directory).ok()?;
    let journal =
        ActionJournalConfig::new(journal_directory, ActionJournalLimits::default()).ok()?;
    WorkerConfig::new(
        worker_id,
        7,
        endpoint,
        peer,
        max_sessions,
        queue_capacity,
        lease,
        timeout,
        Duration::from_millis(100),
        journal,
    )
    .ok()
}

type ReadyWorker = (
    WorkerControlPlane<FakeDriver, FakeSandbox>,
    AuthenticatedPeer,
    Arc<FakeDriver>,
    Arc<FakeSandbox>,
);

fn ready_worker(queue_capacity: usize) -> Option<ReadyWorker> {
    let driver = Arc::new(FakeDriver {
        qualified: true,
        ..FakeDriver::default()
    });
    let sandbox = Arc::new(FakeSandbox {
        qualified: true,
        ..FakeSandbox::default()
    });
    let peer = AuthenticatedPeer::new("gateway-internal").ok()?;
    let worker = WorkerControlPlane::new_with_clock(
        config(queue_capacity)?,
        driver.clone(),
        sandbox.clone(),
        Arc::new(TestClock),
    );
    Some((worker, peer, driver, sandbox))
}

fn ready_worker_with_artifact_limits(limits: WorkerArtifactLimits) -> Option<ReadyWorker> {
    let driver = Arc::new(FakeDriver {
        qualified: true,
        ..FakeDriver::default()
    });
    let sandbox = Arc::new(FakeSandbox {
        qualified: true,
        ..FakeSandbox::default()
    });
    let peer = AuthenticatedPeer::new("gateway-internal").ok()?;
    let worker = WorkerControlPlane::new_with_clock(
        config(2)?.with_artifact_limits(limits),
        driver.clone(),
        sandbox.clone(),
        Arc::new(TestClock),
    );
    Some((worker, peer, driver, sandbox))
}

fn create_command(tenant_id: TenantId, key: &str, hash_byte: u8) -> CreateSessionCommand {
    CreateSessionCommand {
        tenant_id,
        idempotency_key: key.to_owned(),
        canonical_request_hash: [hash_byte; 32],
        placement_version: 1,
        session_incarnation: 1,
    }
}

fn create_ready_session(
    worker: &WorkerControlPlane<FakeDriver, FakeSandbox>,
    peer: &AuthenticatedPeer,
    key: &str,
) -> Option<CreateSessionOutcome> {
    worker
        .create_session(
            peer,
            create_command(TenantId::new(), key, 1),
            SessionTime::new(0),
        )
        .ok()
}

fn approval_requirement(
    tenant_id: &TenantId,
    requester: &PrincipalId,
    session: &CreateSessionOutcome,
    payload: &[u8],
    submitted_at: SessionTime,
) -> Option<ActionApprovalRequirement> {
    Some(ActionApprovalRequirement::new(
        CanonicalActionProposal::new(
            tenant_id.clone(),
            requester.clone(),
            session.session_id.clone(),
            session.fence.session_incarnation(),
            session.primary_page_id.clone(),
            1,
            1,
            Origin::parse("https://example.test/").ok()?,
            1,
            ActionType::Click,
            ActionArgumentsHash::digest(payload),
            None,
            CredentialRefsHash::digest(std::iter::empty()),
            submitted_at.get() + 100,
        ),
        ActionType::Click,
        true,
    ))
}

#[test]
fn readiness_and_internal_transport_fail_closed() {
    assert!(
        InternalEndpoint::loopback(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 9010,))
            .is_err()
    );
    assert!(InternalEndpoint::unix("relative.sock").is_err());
    let Some(config) = config(1) else {
        return;
    };
    let driver = Arc::new(FakeDriver::default());
    let sandbox = Arc::new(FakeSandbox::default());
    let worker = WorkerControlPlane::new_with_clock(config, driver, sandbox, Arc::new(TestClock));
    assert!(!worker.is_ready());
    let peer = AuthenticatedPeer::new("gateway-internal");
    assert!(peer.is_ok());
    let Some(peer) = peer.ok() else {
        return;
    };
    assert_eq!(
        worker.create_session(
            &peer,
            create_command(TenantId::new(), "key", 1),
            SessionTime::new(0)
        ),
        Err(WorkerError::NotReady)
    );
}

#[test]
fn create_is_idempotent_fenced_and_page_lifecycle_is_serialized() {
    let Some((worker, peer, _driver, _sandbox)) = ready_worker(2) else {
        return;
    };
    let tenant_id = TenantId::new();
    let first = worker.create_session(
        &peer,
        create_command(tenant_id.clone(), "create-key", 1),
        SessionTime::new(0),
    );
    assert!(first.is_ok());
    let Some(first) = first.ok() else {
        return;
    };
    let repeated = worker.create_session(
        &peer,
        create_command(tenant_id.clone(), "create-key", 1),
        SessionTime::new(0),
    );
    assert!(repeated.is_ok());
    let Some(repeated) = repeated.ok() else {
        return;
    };
    assert_eq!(first.session_id, repeated.session_id);
    assert!(repeated.existing);
    assert_eq!(
        worker.create_session(
            &peer,
            create_command(tenant_id, "create-key", 2),
            SessionTime::new(0)
        ),
        Err(WorkerError::IdempotencyConflict)
    );

    let page = worker.create_page(&peer, &first.session_id, &first.fence, SessionTime::new(2));
    assert!(page.is_ok());
    let Some(page) = page.ok() else {
        return;
    };
    assert!(
        worker
            .activate_page(
                &peer,
                &first.session_id,
                &page,
                &first.fence,
                SessionTime::new(3)
            )
            .is_ok()
    );
    assert!(
        worker
            .close_page(
                &peer,
                &first.session_id,
                &page,
                &first.fence,
                SessionTime::new(4)
            )
            .is_ok()
    );
    assert_eq!(
        worker
            .get_session(&peer, &first.session_id, &first.fence)
            .ok()
            .map(|snapshot| snapshot.active_targets),
        Some(1)
    );
    assert!(
        worker
            .close_page(
                &peer,
                &first.session_id,
                &page,
                &first.fence,
                SessionTime::new(5),
            )
            .is_ok()
    );
    let stale = browserd_session::OwnershipFence::new(
        first.fence.worker_id().clone(),
        first.fence.worker_epoch(),
        first.fence.placement_version().saturating_add(1),
        first.fence.session_incarnation(),
    );
    assert_eq!(
        worker.create_page(&peer, &first.session_id, &stale, SessionTime::new(6)),
        Err(WorkerError::StaleFence)
    );
}

#[test]
fn page_snapshots_are_opaque_ordered_and_track_activation() {
    let Some((worker, peer, _driver, _sandbox)) = ready_worker(4) else {
        return;
    };
    let Some(session) = create_ready_session(&worker, &peer, "page-snapshots") else {
        return;
    };

    let initial = worker.list_pages(&peer, &session.session_id, &session.fence);
    assert!(initial.is_ok());
    let Some(initial) = initial.ok() else {
        return;
    };
    assert_eq!(initial.len(), 1);
    assert_eq!(initial[0].page_id, session.primary_page_id);
    assert!(initial[0].active);
    assert_eq!(initial[0].target_incarnation, 1);
    assert_eq!(initial[0].document_epoch, 1);
    assert_eq!(initial[0].url_revision, 0);

    let second = worker.create_page(
        &peer,
        &session.session_id,
        &session.fence,
        SessionTime::new(1),
    );
    assert!(second.is_ok());
    let Some(second) = second.ok() else {
        return;
    };
    assert!(
        worker
            .activate_page(
                &peer,
                &session.session_id,
                &second,
                &session.fence,
                SessionTime::new(2),
            )
            .is_ok()
    );
    let activated = worker.list_pages(&peer, &session.session_id, &session.fence);
    assert!(activated.is_ok());
    let Some(activated) = activated.ok() else {
        return;
    };
    assert_eq!(activated.len(), 2);
    assert!(
        activated
            .iter()
            .find(|page| page.page_id == second)
            .is_some_and(|page| page.active && page.target_incarnation == 1)
    );
    assert!(
        activated
            .iter()
            .find(|page| page.page_id == session.primary_page_id)
            .is_some_and(|page| !page.active)
    );
}

#[test]
fn blocked_session_provisioning_does_not_hold_the_global_worker_mutex() {
    let Some((worker, peer, _driver, sandbox)) = ready_worker(4) else {
        return;
    };
    let worker = Arc::new(worker);
    let provision_started = Arc::new(Barrier::new(2));
    let release_provision = Arc::new(Barrier::new(2));
    let Ok(mut provision_barriers) = sandbox.provision_barriers.lock() else {
        return;
    };
    *provision_barriers = Some((
        Arc::clone(&provision_started),
        Arc::clone(&release_provision),
    ));
    drop(provision_barriers);

    let create_worker = Arc::clone(&worker);
    let create_peer = peer.clone();
    let create_handle = thread::spawn(move || {
        create_worker.create_session(
            &create_peer,
            create_command(TenantId::new(), "blocked-create", 41),
            SessionTime::new(0),
        )
    });
    provision_started.wait();

    let readiness_worker = Arc::clone(&worker);
    let (readiness_tx, readiness_rx) = std::sync::mpsc::channel();
    let readiness_handle = thread::spawn(move || {
        let _ = readiness_tx.send(readiness_worker.is_ready());
    });
    let readiness_completed = readiness_rx
        .recv_timeout(Duration::from_millis(100))
        .is_ok();

    release_provision.wait();
    assert!(create_handle.join().is_ok_and(|result| result.is_ok()));
    assert!(readiness_handle.join().is_ok());
    assert!(
        readiness_completed,
        "readiness must not wait for an unrelated external provision call"
    );
}

#[test]
fn concurrent_identical_create_waits_for_and_reuses_the_single_inflight_operation() {
    let Some((worker, peer, _driver, sandbox)) = ready_worker(4) else {
        return;
    };
    let worker = Arc::new(worker);
    let provision_started = Arc::new(Barrier::new(2));
    let release_provision = Arc::new(Barrier::new(2));
    let Ok(mut provision_barriers) = sandbox.provision_barriers.lock() else {
        return;
    };
    *provision_barriers = Some((
        Arc::clone(&provision_started),
        Arc::clone(&release_provision),
    ));
    drop(provision_barriers);
    let command = create_command(TenantId::new(), "concurrent-identical-create", 52);

    let first_worker = Arc::clone(&worker);
    let first_peer = peer.clone();
    let first_command = command.clone();
    let first_handle = thread::spawn(move || {
        first_worker.create_session(&first_peer, first_command, SessionTime::new(0))
    });
    provision_started.wait();

    let second_worker = Arc::clone(&worker);
    let second_peer = peer.clone();
    let (second_tx, second_rx) = std::sync::mpsc::channel();
    let second_handle = thread::spawn(move || {
        let _ = second_tx.send(second_worker.create_session(
            &second_peer,
            command,
            SessionTime::new(0),
        ));
    });
    let retry_completed_before_original = second_rx.recv_timeout(Duration::from_millis(50)).is_ok();

    release_provision.wait();
    let first = first_handle.join();
    let second = second_rx.recv_timeout(Duration::from_secs(1));
    assert!(second_handle.join().is_ok());
    assert!(first.is_ok());
    assert!(second.is_ok());
    let (Ok(Ok(first)), Ok(Ok(second))) = (first, second) else {
        return;
    };
    assert!(
        !retry_completed_before_original,
        "an identical retry must not observe a partial create result"
    );
    assert_eq!(first.operation_id, second.operation_id);
    assert_eq!(first.session_id, second.session_id);
    assert!(!first.existing);
    assert!(second.existing);
    assert_eq!(
        sandbox.provision_count.lock().ok().map(|count| *count),
        Some(1)
    );
}

#[test]
fn graceful_shutdown_waits_for_an_inflight_create_to_rollback() {
    let Some((worker, peer, driver, sandbox)) = ready_worker(4) else {
        return;
    };
    let worker = Arc::new(worker);
    let provision_started = Arc::new(Barrier::new(2));
    let release_provision = Arc::new(Barrier::new(2));
    let Ok(mut provision_barriers) = sandbox.provision_barriers.lock() else {
        return;
    };
    *provision_barriers = Some((
        Arc::clone(&provision_started),
        Arc::clone(&release_provision),
    ));
    drop(provision_barriers);

    let create_worker = Arc::clone(&worker);
    let create_peer = peer.clone();
    let create_handle = thread::spawn(move || {
        create_worker.create_session(
            &create_peer,
            create_command(TenantId::new(), "shutdown-inflight-create", 53),
            SessionTime::new(0),
        )
    });
    provision_started.wait();
    assert_eq!(worker.begin_drain(&peer), Ok(()));

    let shutdown_entered = Arc::new(Barrier::new(2));
    let shutdown_entered_thread = Arc::clone(&shutdown_entered);
    let shutdown_worker = Arc::clone(&worker);
    let shutdown_peer = peer.clone();
    let (shutdown_tx, shutdown_rx) = std::sync::mpsc::channel();
    let shutdown_handle = thread::spawn(move || {
        shutdown_entered_thread.wait();
        let _ = shutdown_tx
            .send(shutdown_worker.graceful_shutdown(&shutdown_peer, SessionTime::new(1)));
    });
    shutdown_entered.wait();
    let shutdown_before_create_rollback = shutdown_rx.recv_timeout(Duration::from_millis(100));

    release_provision.wait();
    let create_result = create_handle.join();
    let shutdown_completed_early = shutdown_before_create_rollback.is_ok();
    let shutdown_result = match shutdown_before_create_rollback {
        Ok(result) => Some(result),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            shutdown_rx.recv_timeout(Duration::from_secs(1)).ok()
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => None,
    };
    let shutdown_join = shutdown_handle.join();

    assert!(
        !shutdown_completed_early,
        "graceful shutdown must not report success while a provisioned create is still live"
    );
    assert!(create_result.is_ok(), "create thread must not panic");
    let Ok(create_result) = create_result else {
        return;
    };
    assert!(matches!(
        create_result,
        Err(WorkerError::Draining | WorkerError::Stopped)
    ));
    assert!(shutdown_join.is_ok(), "shutdown thread must not panic");
    assert!(
        shutdown_result.is_some(),
        "shutdown must finish after create rollback"
    );
    let Some(shutdown_result) = shutdown_result else {
        return;
    };
    assert_eq!(shutdown_result, Ok(()));
    assert_eq!(
        sandbox.cleanup_count.lock().ok().map(|count| *count),
        Some(1),
        "the rejected create must roll back its sandbox before shutdown returns"
    );
    assert_eq!(
        driver.cleanup_count.lock().ok().map(|count| *count),
        Some(1),
        "the rejected create must close its browser context before shutdown returns"
    );
}

#[test]
fn graceful_shutdown_reports_an_inflight_create_rollback_failure() {
    let driver = Arc::new(FakeDriver {
        qualified: true,
        ..FakeDriver::default()
    });
    let sandbox = Arc::new(FakeSandbox {
        qualified: true,
        fail_cleanup: true,
        ..FakeSandbox::default()
    });
    let Some(config) = config(4) else {
        return;
    };
    let Ok(peer) = AuthenticatedPeer::new("gateway-internal") else {
        return;
    };
    let worker = Arc::new(WorkerControlPlane::new_with_clock(
        config,
        Arc::clone(&driver),
        Arc::clone(&sandbox),
        Arc::new(TestClock),
    ));
    let provision_started = Arc::new(Barrier::new(2));
    let release_provision = Arc::new(Barrier::new(2));
    let Ok(mut provision_barriers) = sandbox.provision_barriers.lock() else {
        return;
    };
    *provision_barriers = Some((
        Arc::clone(&provision_started),
        Arc::clone(&release_provision),
    ));
    drop(provision_barriers);

    let create_worker = Arc::clone(&worker);
    let create_peer = peer.clone();
    let create_handle = thread::spawn(move || {
        create_worker.create_session(
            &create_peer,
            create_command(TenantId::new(), "shutdown-failed-create-rollback", 54),
            SessionTime::new(0),
        )
    });
    provision_started.wait();
    assert_eq!(worker.begin_drain(&peer), Ok(()));

    let shutdown_worker = Arc::clone(&worker);
    let shutdown_peer = peer.clone();
    let (shutdown_tx, shutdown_rx) = std::sync::mpsc::channel();
    let shutdown_handle = thread::spawn(move || {
        let _ = shutdown_tx
            .send(shutdown_worker.graceful_shutdown(&shutdown_peer, SessionTime::new(1)));
    });
    assert!(
        shutdown_rx
            .recv_timeout(Duration::from_millis(100))
            .is_err(),
        "shutdown must wait for the in-flight rollback attempt"
    );

    release_provision.wait();
    let create_result = create_handle.join();
    let shutdown_result = shutdown_rx.recv_timeout(Duration::from_secs(1));
    let shutdown_join = shutdown_handle.join();

    assert!(matches!(create_result, Ok(Err(WorkerError::CleanupFailed))));
    assert_eq!(shutdown_result, Ok(Err(WorkerError::CleanupFailed)));
    assert!(shutdown_join.is_ok(), "shutdown thread must not panic");
    assert_eq!(
        sandbox.cleanup_count.lock().ok().map(|count| *count),
        Some(1),
        "shutdown must observe the failed rollback attempt"
    );
    assert_eq!(
        driver.cleanup_count.lock().ok().map(|count| *count),
        Some(1)
    );
}

#[test]
fn blocked_readiness_probe_does_not_hold_the_global_worker_mutex() {
    let Some((worker, peer, driver, _sandbox)) = ready_worker(4) else {
        return;
    };
    let worker = Arc::new(worker);
    let session = worker.create_session(
        &peer,
        create_command(TenantId::new(), "readiness-session", 42),
        SessionTime::new(0),
    );
    assert!(session.is_ok());
    let Ok(session) = session else {
        return;
    };
    let qualify_started = Arc::new(Barrier::new(2));
    let release_qualify = Arc::new(Barrier::new(2));
    let Ok(mut qualification_barriers) = driver.qualification_barriers.lock() else {
        return;
    };
    *qualification_barriers = Some((Arc::clone(&qualify_started), Arc::clone(&release_qualify)));
    drop(qualification_barriers);

    let readiness_worker = Arc::clone(&worker);
    let readiness_handle = thread::spawn(move || readiness_worker.is_ready());
    qualify_started.wait();

    let query_worker = Arc::clone(&worker);
    let query_peer = peer.clone();
    let query_session_id = session.session_id.clone();
    let query_fence = session.fence.clone();
    let (query_tx, query_rx) = std::sync::mpsc::channel();
    let query_handle = thread::spawn(move || {
        let _ =
            query_tx.send(query_worker.get_session(&query_peer, &query_session_id, &query_fence));
    });
    let query_completed = query_rx.recv_timeout(Duration::from_millis(100)).is_ok();

    release_qualify.wait();
    assert!(readiness_handle.join().is_ok_and(|ready| ready));
    assert!(query_handle.join().is_ok());
    assert!(
        query_completed,
        "session lookup must not wait for an external readiness probe"
    );
}

#[test]
fn blocked_artifact_storage_does_not_hold_the_session_state_mutex() {
    let Some((worker, peer, _driver, sandbox)) = ready_worker(4) else {
        return;
    };
    let worker = Arc::new(worker);
    let session = worker.create_session(
        &peer,
        create_command(TenantId::new(), "artifact-session", 43),
        SessionTime::new(0),
    );
    assert!(session.is_ok());
    let Ok(session) = session else {
        return;
    };
    let storage_started = Arc::new(Barrier::new(2));
    let release_storage = Arc::new(Barrier::new(2));
    let Ok(mut artifact_barriers) = sandbox.artifact_barriers.lock() else {
        return;
    };
    *artifact_barriers = Some((Arc::clone(&storage_started), Arc::clone(&release_storage)));
    drop(artifact_barriers);

    let upload_worker = Arc::clone(&worker);
    let upload_peer = peer.clone();
    let upload_session_id = session.session_id.clone();
    let upload_fence = session.fence.clone();
    let upload_handle = thread::spawn(move || {
        upload_worker.upload_artifact(
            &upload_peer,
            &upload_session_id,
            &upload_fence,
            ArtifactUpload {
                bytes: vec![1, 2, 3],
                content_type: "application/octet-stream".to_owned(),
            },
            SessionTime::new(2),
        )
    });
    storage_started.wait();

    let query_worker = Arc::clone(&worker);
    let query_peer = peer.clone();
    let query_session_id = session.session_id.clone();
    let query_fence = session.fence.clone();
    let (query_tx, query_rx) = std::sync::mpsc::channel();
    let query_handle = thread::spawn(move || {
        let _ =
            query_tx.send(query_worker.get_session(&query_peer, &query_session_id, &query_fence));
    });
    let query_completed = query_rx.recv_timeout(Duration::from_millis(100)).is_ok();

    release_storage.wait();
    assert!(upload_handle.join().is_ok_and(|result| result.is_ok()));
    assert!(query_handle.join().is_ok());
    assert!(
        query_completed,
        "session query must not wait for external artifact storage"
    );
}

#[test]
fn action_queue_is_bounded_idempotent_and_unknown_requires_explicit_resolution() {
    let Some((worker, peer, driver, _sandbox)) = ready_worker(1) else {
        return;
    };
    let created = worker.create_session(
        &peer,
        create_command(TenantId::new(), "create", 1),
        SessionTime::new(0),
    );
    assert!(created.is_ok());
    let Some(created) = created.ok() else {
        return;
    };
    let page = created.primary_page_id.clone();
    let requester = PrincipalId::new();
    let first = worker.submit_action(
        &peer,
        requester.clone(),
        &created.session_id,
        &created.fence,
        "action-key",
        [3; 32],
        ActionKind::Mutating,
        Some(BuiltinFeature::CoreInput),
        Some(page),
        b"click".to_vec(),
        None,
        SessionTime::new(2),
    );
    assert!(first.is_ok());
    let Some(first) = first.ok() else {
        return;
    };
    let duplicate = worker.submit_action(
        &peer,
        requester,
        &created.session_id,
        &created.fence,
        "action-key",
        [3; 32],
        ActionKind::Mutating,
        None,
        None,
        Vec::new(),
        None,
        SessionTime::new(2),
    );
    assert_eq!(duplicate.ok(), Some(first.clone()));
    assert_eq!(
        worker.submit_action(
            &peer,
            PrincipalId::new(),
            &created.session_id,
            &created.fence,
            "second",
            [4; 32],
            ActionKind::ReadOnly,
            None,
            None,
            Vec::new(),
            None,
            SessionTime::new(2),
        ),
        Err(WorkerError::QueueFull)
    );
    if let Ok(mut executions) = driver.executions.lock() {
        executions.push_back(ActionExecutionResult::OutcomeUnknown);
    }
    let result = worker.run_next_action(
        &peer,
        &created.session_id,
        &created.fence,
        SessionTime::new(3),
    );
    assert!(result.is_ok());
    let snapshot = worker.get_action(&peer, &created.session_id, &first, &created.fence);
    assert!(snapshot.is_ok());
    assert_eq!(
        snapshot.ok().map(|action| action.status),
        Some(ActionStatus::OutcomeUnknown)
    );
    let resolver = PrincipalId::new();
    let resolved = worker.resolve_action(
        &peer,
        &created.session_id,
        &first,
        &created.fence,
        ResolutionKind::ConfirmedExecuted,
        resolver.clone(),
        "verified",
        SessionTime::new(4),
    );
    assert!(resolved.is_ok());
    let Some(resolved) = resolved.ok() else {
        return;
    };
    assert_eq!(resolved.status, ActionStatus::OutcomeUnknown);
    assert_eq!(
        resolved
            .resolution
            .as_ref()
            .map(browserd_actions::ResolutionAnnotation::kind),
        Some(ResolutionKind::ConfirmedExecuted)
    );
    assert_eq!(
        resolved
            .resolution
            .as_ref()
            .map(browserd_actions::ResolutionAnnotation::resolved_by),
        Some(&resolver)
    );
    assert_eq!(
        resolved
            .resolution
            .as_ref()
            .map(browserd_actions::ResolutionAnnotation::resolved_at_millis),
        Some(4)
    );
    assert_eq!(
        resolved
            .resolution
            .as_ref()
            .map(browserd_actions::ResolutionAnnotation::basis),
        Some("verified")
    );
}

#[test]
fn artifact_approval_viewer_and_cleanup_commands_remain_fenced() {
    let Some((worker, peer, _driver, sandbox)) = ready_worker(2) else {
        return;
    };
    let tenant_id = TenantId::new();
    let created = worker.create_session(
        &peer,
        create_command(tenant_id.clone(), "create", 1),
        SessionTime::new(0),
    );
    assert!(created.is_ok());
    let Some(created) = created.ok() else {
        return;
    };
    let artifact = worker.upload_artifact(
        &peer,
        &created.session_id,
        &created.fence,
        ArtifactUpload {
            bytes: vec![1, 2, 3],
            content_type: "application/octet-stream".to_owned(),
        },
        SessionTime::new(2),
    );
    assert!(artifact.is_ok());
    let Some(artifact) = artifact.ok() else {
        return;
    };
    let stored = worker.get_artifact(&peer, &created.session_id, &artifact, &created.fence);
    assert!(stored.is_ok());
    let Some(stored) = stored.ok() else {
        return;
    };
    assert_eq!(stored.size_bytes, 3);
    let expected_checksum: [u8; 32] = Sha256::digest([1, 2, 3]).into();
    assert_eq!(stored.checksum_sha256, expected_checksum);
    assert_eq!(stored.source, ArtifactContentSource::ClientUpload);
    assert_eq!(stored.origin, "browserd-worker-upload");
    assert!(
        worker
            .issue_viewer_ticket(
                &peer,
                &created.session_id,
                &created.fence,
                ViewerScopes::new(true, false, false),
                Duration::from_secs(5),
                SessionTime::new(3),
            )
            .is_ok()
    );

    let requester = PrincipalId::new();
    let action = worker.submit_action(
        &peer,
        requester.clone(),
        &created.session_id,
        &created.fence,
        "approval",
        [8; 32],
        ActionKind::Mutating,
        None,
        Some(created.primary_page_id.clone()),
        Vec::new(),
        approval_requirement(&tenant_id, &requester, &created, &[], SessionTime::new(3)),
        SessionTime::new(3),
    );
    assert!(action.is_ok());
    let Some(action) = action.ok() else {
        return;
    };
    let approval = worker.approval_for_action(&peer, &created.session_id, &action, &created.fence);
    assert!(approval.is_ok());
    let Some(approval) = approval.ok() else {
        return;
    };
    let pending = worker.get_approval(&peer, &created.session_id, &approval, &created.fence);
    assert!(pending.is_ok());
    assert!(
        pending
            .as_ref()
            .is_ok_and(|snapshot| snapshot.action_id == action
                && snapshot.proposal_hash.as_bytes() != &[0; 32])
    );
    let approvals = worker.list_approvals(&peer, &created.session_id, &created.fence);
    assert!(approvals.is_ok());
    assert!(
        approvals
            .as_ref()
            .is_ok_and(|snapshots| snapshots.len() == 1 && snapshots[0].approval_id == approval)
    );
    assert!(
        worker
            .decide_approval(
                &peer,
                &created.session_id,
                &approval,
                &created.fence,
                ApprovalDecision::Approve,
                PrincipalId::new(),
                SessionTime::new(4),
            )
            .is_ok()
    );
    let decided = worker.get_approval(&peer, &created.session_id, &approval, &created.fence);
    assert!(decided.is_ok());
    assert!(decided.as_ref().is_ok_and(|snapshot| matches!(
        snapshot.state,
        browserd_policy::ApprovalState::Approved { .. }
    )));
    assert!(
        worker
            .close_session(
                &peer,
                &created.session_id,
                &created.fence,
                SessionTime::new(5)
            )
            .is_ok()
    );
    assert!(
        sandbox
            .cleanup_count
            .lock()
            .ok()
            .is_some_and(|count| *count == 1)
    );
}

#[test]
fn artifact_receipt_checksum_and_key_mismatches_fail_closed() {
    for wrong_key in [false, true] {
        let Some((worker, peer, _driver, sandbox)) = ready_worker(2) else {
            return;
        };
        let Some(created) = create_ready_session(&worker, &peer, "artifact-receipt") else {
            return;
        };
        sandbox
            .corrupt_artifact_receipt
            .store(!wrong_key, Ordering::SeqCst);
        sandbox
            .wrong_artifact_key
            .store(wrong_key, Ordering::SeqCst);

        assert_eq!(
            worker.upload_artifact(
                &peer,
                &created.session_id,
                &created.fence,
                ArtifactUpload {
                    bytes: vec![1, 2, 3],
                    content_type: "application/octet-stream".to_owned(),
                },
                SessionTime::new(1),
            ),
            Err(WorkerError::DependencyUnavailable)
        );
        assert_eq!(sandbox.artifact_store_count.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn artifact_without_clean_scan_receipt_is_never_available() {
    let Some((worker, peer, _driver, sandbox)) = ready_worker(2) else {
        return;
    };
    sandbox.quarantine_artifact.store(true, Ordering::SeqCst);
    let Some(created) = create_ready_session(&worker, &peer, "artifact-quarantine") else {
        return;
    };
    let artifact_id = worker.upload_artifact(
        &peer,
        &created.session_id,
        &created.fence,
        ArtifactUpload {
            bytes: vec![1, 2, 3],
            content_type: "application/octet-stream".to_owned(),
        },
        SessionTime::new(1),
    );
    assert!(artifact_id.is_ok());
    let Some(artifact_id) = artifact_id.ok() else {
        return;
    };
    let snapshot = worker.get_artifact(&peer, &created.session_id, &artifact_id, &created.fence);
    assert!(snapshot.is_ok());
    assert_eq!(
        snapshot.ok().map(|snapshot| snapshot.state),
        Some(browserd_artifacts::ArtifactState::Quarantined)
    );
}

#[test]
fn concurrent_artifact_quota_is_reserved_before_storage_completes() {
    let Some(limits) = WorkerArtifactLimits::new(4, 5, 4).ok() else {
        return;
    };
    let Some((worker, peer, _driver, sandbox)) = ready_worker_with_artifact_limits(limits) else {
        return;
    };
    let worker = Arc::new(worker);
    let Some(created) = create_ready_session(&worker, &peer, "artifact-concurrent-quota") else {
        return;
    };
    let storage_started = Arc::new(Barrier::new(2));
    let release_storage = Arc::new(Barrier::new(2));
    let Ok(mut artifact_barriers) = sandbox.artifact_barriers.lock() else {
        return;
    };
    *artifact_barriers = Some((Arc::clone(&storage_started), Arc::clone(&release_storage)));
    drop(artifact_barriers);

    let first_worker = Arc::clone(&worker);
    let first_peer = peer.clone();
    let first_session_id = created.session_id.clone();
    let first_fence = created.fence.clone();
    let first_handle = thread::spawn(move || {
        first_worker.upload_artifact(
            &first_peer,
            &first_session_id,
            &first_fence,
            ArtifactUpload {
                bytes: vec![1, 2, 3],
                content_type: "application/octet-stream".to_owned(),
            },
            SessionTime::new(1),
        )
    });
    storage_started.wait();

    let second_worker = Arc::clone(&worker);
    let second_peer = peer.clone();
    let second_session_id = created.session_id.clone();
    let second_fence = created.fence.clone();
    let (second_tx, second_rx) = std::sync::mpsc::channel();
    let second_handle = thread::spawn(move || {
        let result = second_worker.upload_artifact(
            &second_peer,
            &second_session_id,
            &second_fence,
            ArtifactUpload {
                bytes: vec![4, 5, 6],
                content_type: "application/octet-stream".to_owned(),
            },
            SessionTime::new(2),
        );
        let _ = second_tx.send(result);
    });
    let second_before_release = second_rx.recv_timeout(Duration::from_millis(100)).ok();
    let stores_before_release = sandbox.artifact_store_count.load(Ordering::SeqCst);

    release_storage.wait();
    assert!(first_handle.join().is_ok_and(|result| result.is_ok()));
    assert!(second_handle.join().is_ok());
    assert_eq!(
        second_before_release,
        Some(Err(WorkerError::CapacityExceeded)),
        "concurrent quota loser must be rejected while the reserved upload is still in storage"
    );
    assert_eq!(stores_before_release, 1);
    assert_eq!(sandbox.artifact_store_count.load(Ordering::SeqCst), 1);
}

#[test]
fn artifact_file_and_committed_quotas_reject_before_storage() {
    let Some(file_limits) = WorkerArtifactLimits::new(2, 8, 4).ok() else {
        return;
    };
    let Some((worker, peer, _driver, sandbox)) = ready_worker_with_artifact_limits(file_limits)
    else {
        return;
    };
    let Some(created) = create_ready_session(&worker, &peer, "artifact-file-limit") else {
        return;
    };
    assert_eq!(
        worker.upload_artifact(
            &peer,
            &created.session_id,
            &created.fence,
            ArtifactUpload {
                bytes: vec![1, 2, 3],
                content_type: "application/octet-stream".to_owned(),
            },
            SessionTime::new(1),
        ),
        Err(WorkerError::CapacityExceeded)
    );
    assert_eq!(sandbox.artifact_store_count.load(Ordering::SeqCst), 0);

    let Some(committed_limits) = WorkerArtifactLimits::new(4, 5, 4).ok() else {
        return;
    };
    let Some((worker, peer, _driver, sandbox)) =
        ready_worker_with_artifact_limits(committed_limits)
    else {
        return;
    };
    let Some(created) = create_ready_session(&worker, &peer, "artifact-committed-limit") else {
        return;
    };
    let first = worker.upload_artifact(
        &peer,
        &created.session_id,
        &created.fence,
        ArtifactUpload {
            bytes: vec![1, 2, 3],
            content_type: "application/octet-stream".to_owned(),
        },
        SessionTime::new(1),
    );
    assert!(first.is_ok());
    assert_eq!(
        worker.upload_artifact(
            &peer,
            &created.session_id,
            &created.fence,
            ArtifactUpload {
                bytes: vec![4, 5, 6],
                content_type: "application/octet-stream".to_owned(),
            },
            SessionTime::new(2),
        ),
        Err(WorkerError::CapacityExceeded)
    );
    assert_eq!(sandbox.artifact_store_count.load(Ordering::SeqCst), 1);
}

#[test]
fn unauthenticated_peer_and_drain_are_rejected() {
    let Some((worker, peer, _driver, _sandbox)) = ready_worker(1) else {
        return;
    };
    let attacker = AuthenticatedPeer::new("attacker");
    assert!(attacker.is_ok());
    let Some(attacker) = attacker.ok() else {
        return;
    };
    assert_eq!(
        worker.create_session(
            &attacker,
            create_command(TenantId::new(), "bad", 1),
            SessionTime::new(0)
        ),
        Err(WorkerError::UnauthorizedPeer)
    );
    assert!(worker.begin_drain(&peer).is_ok());
    assert_eq!(
        worker.create_session(
            &peer,
            create_command(TenantId::new(), "drain", 1),
            SessionTime::new(0)
        ),
        Err(WorkerError::Draining)
    );
}

#[test]
fn heartbeat_renews_ownership_and_expiry_cleans_worker_loss() {
    let Some((worker, peer, driver, sandbox)) = ready_worker(1) else {
        return;
    };
    let created = worker.create_session(
        &peer,
        create_command(TenantId::new(), "heartbeat", 1),
        SessionTime::new(0),
    );
    assert!(created.is_ok());
    assert!(worker.heartbeat(&peer, SessionTime::new(90)).is_ok());
    assert_eq!(
        worker.heartbeat_deadline(&peer),
        Ok(Some(SessionTime::new(190)))
    );
    assert_eq!(worker.expire_due(&peer, SessionTime::new(100)), Ok(0));
    assert_eq!(worker.expire_due(&peer, SessionTime::new(190)), Ok(1));
    assert!(
        driver
            .cleanup_count
            .lock()
            .ok()
            .is_some_and(|count| *count == 0)
    );
    assert!(
        sandbox
            .cleanup_count
            .lock()
            .ok()
            .is_some_and(|count| *count == 1)
    );
    assert_eq!(worker.heartbeat_deadline(&peer), Ok(None));
    assert_eq!(
        worker.create_session(
            &peer,
            create_command(TenantId::new(), "after-worker-loss", 2),
            SessionTime::new(191),
        ),
        Err(WorkerError::Draining)
    );
    assert!(
        worker
            .graceful_shutdown(&peer, SessionTime::new(192))
            .is_ok()
    );
    assert_eq!(
        worker.create_session(
            &peer,
            create_command(TenantId::new(), "after-stop", 3),
            SessionTime::new(193),
        ),
        Err(WorkerError::Stopped)
    );
}

#[test]
fn worker_loss_racing_dispatched_action_derives_outcome_unknown() {
    let Some((worker, peer, driver, _sandbox)) = ready_worker(1) else {
        return;
    };
    let worker = Arc::new(worker);
    let created = worker.create_session(
        &peer,
        create_command(TenantId::new(), "loss", 1),
        SessionTime::new(0),
    );
    assert!(created.is_ok());
    let Some(created) = created.ok() else {
        return;
    };
    let action_id = worker.submit_action(
        &peer,
        PrincipalId::new(),
        &created.session_id,
        &created.fence,
        "running",
        [9; 32],
        ActionKind::Mutating,
        None,
        None,
        Vec::new(),
        None,
        SessionTime::new(1),
    );
    assert!(action_id.is_ok());
    let Some(action_id) = action_id.ok() else {
        return;
    };
    let started = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    if let Ok(mut barriers) = driver.execution_barriers.lock() {
        *barriers = Some((started.clone(), release.clone()));
    }
    let runner = worker.clone();
    let run_peer = peer.clone();
    let run_session = created.session_id.clone();
    let run_fence = created.fence.clone();
    let run = thread::spawn(move || {
        runner.run_next_action(&run_peer, &run_session, &run_fence, SessionTime::new(2))
    });
    started.wait();
    assert_eq!(worker.expire_due(&peer, SessionTime::new(100)), Ok(1));
    release.wait();
    let run_result = run.join();
    assert!(run_result.is_ok());
    assert!(run_result.ok().is_some_and(|result| result.is_err()));
    assert_eq!(
        worker
            .get_action(&peer, &created.session_id, &action_id, &created.fence)
            .ok()
            .map(|snapshot| snapshot.status),
        Some(ActionStatus::OutcomeUnknown)
    );
    assert_eq!(
        worker
            .get_session(&peer, &created.session_id, &created.fence)
            .ok()
            .map(|snapshot| snapshot.lifecycle),
        Some(browserd_session::SessionLifecycle::Failed)
    );
}

#[test]
fn explicit_close_racing_dispatched_action_never_leaves_it_running() {
    let Some((worker, peer, driver, _sandbox)) = ready_worker(2) else {
        return;
    };
    let worker = Arc::new(worker);
    let created = worker.create_session(
        &peer,
        create_command(TenantId::new(), "close-race", 1),
        SessionTime::new(0),
    );
    assert!(created.is_ok());
    let Some(created) = created.ok() else {
        return;
    };
    let action_id = worker.submit_action(
        &peer,
        PrincipalId::new(),
        &created.session_id,
        &created.fence,
        "running-close",
        [10; 32],
        ActionKind::Mutating,
        None,
        None,
        Vec::new(),
        None,
        SessionTime::new(1),
    );
    assert!(action_id.is_ok());
    let Some(action_id) = action_id.ok() else {
        return;
    };
    let started = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    if let Ok(mut barriers) = driver.execution_barriers.lock() {
        *barriers = Some((started.clone(), release.clone()));
    }
    let runner = Arc::clone(&worker);
    let run_peer = peer.clone();
    let run_session = created.session_id.clone();
    let run_fence = created.fence.clone();
    let run = thread::spawn(move || {
        runner.run_next_action(&run_peer, &run_session, &run_fence, SessionTime::new(2))
    });
    started.wait();
    let closed = worker.close_session(
        &peer,
        &created.session_id,
        &created.fence,
        SessionTime::new(3),
    );
    assert!(closed.is_ok());
    release.wait();
    let joined = run.join();
    assert!(joined.is_ok());
    assert!(joined.ok().is_some_and(|result| result.is_err()));
    assert_eq!(
        worker
            .get_action(&peer, &created.session_id, &action_id, &created.fence)
            .ok()
            .map(|snapshot| snapshot.status),
        Some(ActionStatus::OutcomeUnknown)
    );
}

#[test]
fn failed_pre_dispatch_validation_keeps_action_available_for_close_cancellation() {
    let Some((worker, peer, _driver, _sandbox)) = ready_worker(2) else {
        return;
    };
    let created = worker.create_session(
        &peer,
        create_command(TenantId::new(), "expired-dispatch", 1),
        SessionTime::new(0),
    );
    assert!(created.is_ok());
    let Some(created) = created.ok() else {
        return;
    };
    let action_id = worker.submit_action(
        &peer,
        PrincipalId::new(),
        &created.session_id,
        &created.fence,
        "queued-at-expiry",
        [11; 32],
        ActionKind::Mutating,
        None,
        None,
        Vec::new(),
        None,
        SessionTime::new(1),
    );
    assert!(action_id.is_ok());
    let Some(action_id) = action_id.ok() else {
        return;
    };

    assert!(
        worker
            .run_next_action(
                &peer,
                &created.session_id,
                &created.fence,
                SessionTime::new(100),
            )
            .is_err()
    );
    assert!(
        worker
            .close_session(
                &peer,
                &created.session_id,
                &created.fence,
                SessionTime::new(101),
            )
            .is_ok()
    );
    assert_eq!(
        worker
            .get_action(&peer, &created.session_id, &action_id, &created.fence)
            .ok()
            .map(|snapshot| snapshot.status),
        Some(ActionStatus::CancelledBeforeDispatch)
    );
}

#[test]
fn explicit_close_resolves_all_actions_that_never_dispatched() {
    let Some((worker, peer, _driver, _sandbox)) = ready_worker(3) else {
        return;
    };
    let tenant_id = TenantId::new();
    let created = worker.create_session(
        &peer,
        create_command(tenant_id.clone(), "close-pending", 1),
        SessionTime::new(0),
    );
    assert!(created.is_ok());
    let Some(created) = created.ok() else {
        return;
    };
    let queued = worker.submit_action(
        &peer,
        PrincipalId::new(),
        &created.session_id,
        &created.fence,
        "queued",
        [12; 32],
        ActionKind::ReadOnly,
        None,
        None,
        Vec::new(),
        None,
        SessionTime::new(1),
    );
    let pending_requester = PrincipalId::new();
    let pending = worker.submit_action(
        &peer,
        pending_requester.clone(),
        &created.session_id,
        &created.fence,
        "pending",
        [13; 32],
        ActionKind::Mutating,
        None,
        Some(created.primary_page_id.clone()),
        Vec::new(),
        approval_requirement(
            &tenant_id,
            &pending_requester,
            &created,
            &[],
            SessionTime::new(2),
        ),
        SessionTime::new(2),
    );
    assert!(queued.is_ok());
    assert!(pending.is_ok());
    let Some(queued) = queued.ok() else {
        return;
    };
    let Some(pending) = pending.ok() else {
        return;
    };

    assert!(
        worker
            .close_session(
                &peer,
                &created.session_id,
                &created.fence,
                SessionTime::new(3),
            )
            .is_ok()
    );
    assert_eq!(
        worker
            .get_action(&peer, &created.session_id, &queued, &created.fence)
            .ok()
            .map(|snapshot| snapshot.status),
        Some(ActionStatus::CancelledBeforeDispatch)
    );
    assert_eq!(
        worker
            .get_action(&peer, &created.session_id, &pending, &created.fence)
            .ok()
            .map(|snapshot| snapshot.status),
        Some(ActionStatus::FailedKnown)
    );
}

#[test]
fn failed_create_result_is_stable_for_identical_retries() {
    let driver = Arc::new(FakeDriver {
        qualified: true,
        ..FakeDriver::default()
    });
    let sandbox = Arc::new(FakeSandbox {
        qualified: true,
        fail_provision: true,
        ..FakeSandbox::default()
    });
    let peer = AuthenticatedPeer::new("gateway-internal");
    assert!(peer.is_ok());
    let Some(peer) = peer.ok() else {
        return;
    };
    let Some(config) = config(1) else {
        return;
    };
    let worker =
        WorkerControlPlane::new_with_clock(config, driver, sandbox.clone(), Arc::new(TestClock));
    let tenant_id = TenantId::new();

    assert_eq!(
        worker.create_session(
            &peer,
            create_command(tenant_id.clone(), "failed-create", 1),
            SessionTime::new(0),
        ),
        Err(WorkerError::DependencyUnavailable)
    );
    assert_eq!(
        worker.create_session(
            &peer,
            create_command(tenant_id, "failed-create", 1),
            SessionTime::new(1),
        ),
        Err(WorkerError::DependencyUnavailable)
    );
    assert!(
        sandbox
            .provision_count
            .lock()
            .ok()
            .is_some_and(|count| *count == 1)
    );
}

#[test]
fn terminal_sessions_release_worker_capacity_without_losing_query_state() {
    let driver = Arc::new(FakeDriver {
        qualified: true,
        ..FakeDriver::default()
    });
    let sandbox = Arc::new(FakeSandbox {
        qualified: true,
        ..FakeSandbox::default()
    });
    let Some(config) = config_with_max_sessions(1, 1) else {
        return;
    };
    let worker = WorkerControlPlane::new_with_clock(config, driver, sandbox, Arc::new(TestClock));
    let peer = AuthenticatedPeer::new("gateway-internal");
    assert!(peer.is_ok());
    let Some(peer) = peer.ok() else {
        return;
    };
    let first = worker.create_session(
        &peer,
        create_command(TenantId::new(), "first-capacity", 1),
        SessionTime::new(0),
    );
    assert!(first.is_ok());
    let Some(first) = first.ok() else {
        return;
    };
    assert!(
        worker
            .close_session(&peer, &first.session_id, &first.fence, SessionTime::new(1),)
            .is_ok()
    );

    assert!(
        worker
            .create_session(
                &peer,
                create_command(TenantId::new(), "second-capacity", 2),
                SessionTime::new(2),
            )
            .is_ok()
    );
    assert_eq!(
        worker
            .get_session(&peer, &first.session_id, &first.fence)
            .ok()
            .map(|snapshot| snapshot.lifecycle),
        Some(SessionLifecycle::Closed)
    );
}

#[test]
fn timeout_expiry_terminalizes_dispatched_queued_and_pending_actions() {
    let Some((worker, peer, driver, _sandbox)) = ready_worker(3) else {
        return;
    };
    let worker = Arc::new(worker);
    let tenant_id = TenantId::new();
    let created = worker.create_session(
        &peer,
        create_command(tenant_id.clone(), "timeout-actions", 1),
        SessionTime::new(0),
    );
    assert!(created.is_ok());
    let Some(created) = created.ok() else {
        return;
    };
    let running = worker.submit_action(
        &peer,
        PrincipalId::new(),
        &created.session_id,
        &created.fence,
        "timeout-running",
        [14; 32],
        ActionKind::Mutating,
        None,
        None,
        Vec::new(),
        None,
        SessionTime::new(1),
    );
    let queued = worker.submit_action(
        &peer,
        PrincipalId::new(),
        &created.session_id,
        &created.fence,
        "timeout-queued",
        [15; 32],
        ActionKind::ReadOnly,
        None,
        None,
        Vec::new(),
        None,
        SessionTime::new(1),
    );
    let pending_requester = PrincipalId::new();
    let pending = worker.submit_action(
        &peer,
        pending_requester.clone(),
        &created.session_id,
        &created.fence,
        "timeout-pending",
        [16; 32],
        ActionKind::Mutating,
        None,
        Some(created.primary_page_id.clone()),
        Vec::new(),
        approval_requirement(
            &tenant_id,
            &pending_requester,
            &created,
            &[],
            SessionTime::new(1),
        ),
        SessionTime::new(1),
    );
    assert!(running.is_ok());
    assert!(queued.is_ok());
    assert!(pending.is_ok());
    let (Some(running), Some(queued), Some(pending)) = (running.ok(), queued.ok(), pending.ok())
    else {
        return;
    };
    let started = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    if let Ok(mut barriers) = driver.execution_barriers.lock() {
        *barriers = Some((started.clone(), release.clone()));
    }
    let runner = Arc::clone(&worker);
    let run_peer = peer.clone();
    let run_session = created.session_id.clone();
    let run_fence = created.fence.clone();
    let run = thread::spawn(move || {
        runner.run_next_action(&run_peer, &run_session, &run_fence, SessionTime::new(2))
    });
    started.wait();
    for heartbeat_at in [90, 180, 270, 360, 450] {
        assert!(
            worker
                .heartbeat(&peer, SessionTime::new(heartbeat_at))
                .is_ok()
        );
    }
    assert_eq!(worker.expire_due(&peer, SessionTime::new(501)), Ok(1));
    release.wait();
    assert!(run.join().is_ok_and(|result| result.is_err()));

    for (action_id, expected) in [
        (running, ActionStatus::OutcomeUnknown),
        (queued, ActionStatus::CancelledBeforeDispatch),
        (pending, ActionStatus::FailedKnown),
    ] {
        assert_eq!(
            worker
                .get_action(&peer, &created.session_id, &action_id, &created.fence)
                .ok()
                .map(|snapshot| snapshot.status),
            Some(expected)
        );
    }
}

#[test]
fn closing_the_only_primary_page_creates_a_bootstrapped_replacement() {
    let Some((worker, peer, _driver, _sandbox)) = ready_worker(1) else {
        return;
    };
    let created = worker.create_session(
        &peer,
        create_command(TenantId::new(), "replace-primary", 1),
        SessionTime::new(0),
    );
    assert!(created.is_ok());
    let Some(created) = created.ok() else {
        return;
    };

    assert!(
        worker
            .close_page(
                &peer,
                &created.session_id,
                &created.primary_page_id,
                &created.fence,
                SessionTime::new(1),
            )
            .is_ok()
    );
    assert_eq!(
        worker
            .get_session(&peer, &created.session_id, &created.fence)
            .ok()
            .map(|snapshot| snapshot.active_targets),
        Some(1)
    );
}

#[test]
fn page_close_cannot_invalidate_an_admitted_action_target() {
    let Some((worker, peer, _driver, _sandbox)) = ready_worker(1) else {
        return;
    };
    let created = worker.create_session(
        &peer,
        create_command(TenantId::new(), "page-action-fence", 1),
        SessionTime::new(0),
    );
    assert!(created.is_ok());
    let Some(created) = created.ok() else {
        return;
    };
    assert!(
        worker
            .submit_action(
                &peer,
                PrincipalId::new(),
                &created.session_id,
                &created.fence,
                "page-bound-action",
                [17; 32],
                ActionKind::Mutating,
                None,
                Some(created.primary_page_id.clone()),
                Vec::new(),
                None,
                SessionTime::new(1),
            )
            .is_ok()
    );

    assert_eq!(
        worker.close_page(
            &peer,
            &created.session_id,
            &created.primary_page_id,
            &created.fence,
            SessionTime::new(2),
        ),
        Err(WorkerError::InvalidActionTransition)
    );
    assert_eq!(
        worker
            .get_session(&peer, &created.session_id, &created.fence)
            .ok()
            .map(|snapshot| snapshot.active_targets),
        Some(1)
    );
}
